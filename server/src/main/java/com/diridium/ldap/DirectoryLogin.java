// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.normalize;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.NoPermissionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.diridium.ldap.LdapSettings.BindMode;
import com.diridium.ldap.LoginResult.Reason;

/**
 * The directory's part of a sign-in: bind (by DN template, or after a search with
 * the service account), read the entry, check the login filter and the group filter, and collect the
 * user's groups for roles. A connection that fails before any request was sent is
 * tried again; nothing else is.
 */
final class DirectoryLogin {

    /** What the directory said; {@code refusal} is null when the user may go on. */
    record Facts(Reason refusal, DirectoryEntry entry, String username, String entryId, List<DirectoryGroup> groups) {

        static Facts refused(Reason reason) {
            return new Facts(reason, null, null, null, List.of());
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(DirectoryLogin.class);

    private final LdapSettings settings;
    private final DirectoryClient directory;
    private final boolean readGroups;
    private final LoginFlow.Sleeper sleeper;

    DirectoryLogin(LdapSettings settings, DirectoryClient directory, boolean readGroups, LoginFlow.Sleeper sleeper) {
        this.settings = settings;
        this.directory = directory;
        this.readGroups = readGroups;
        this.sleeper = sleeper;
    }

    /** @param name the name to sign in with: the typed name, stripped, or a linked account's directory name */
    Facts read(String name, String password, LoginResult result) {
        int attempts = settings.retries() + 1;
        Exception last = null;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            if (attempt > 1) {
                try {
                    sleeper.sleep(settings.retryIntervalMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            try {
                return settings.bindMode() == BindMode.TEMPLATE ? templateBind(name, password, result)
                        : searchBind(name, password, result);
            } catch (NamingException | IOException | RuntimeException e) {
                if (!Failures.isConnectionFailure(e)) {
                    result.step("Directory", false, Failures.describe(e));
                    return Facts.refused(Failures.isTls(e) ? Reason.TLS : Reason.DIRECTORY_ERROR);
                }
                last = e;
                LOG.debug("LDAP connection attempt " + attempt + " of " + attempts + " failed: " + Failures.describe(e));
                if (!Failures.failedBeforeSending(e)) {
                    LOG.debug("Not tried again: the request may have reached the directory");
                    break;
                }
            }
        }
        result.step("Connect", false, "no answer: " + Failures.describe(last));
        return Facts.refused(Reason.UNREACHABLE);
    }

    private Facts templateBind(String name, String password, LoginResult result) throws NamingException, IOException {
        boolean dn = settings.userDnTemplateIsDn();
        String principal = settings.userDnTemplate().replace("{username}", dn ? LdapEscaping.dnValue(name) : name);
        DirectorySession bound = bindUser(principal, password, result);
        if (bound == null) {
            return Facts.refused(Reason.BIND_REFUSED);
        }
        try (DirectorySession session = bound) {
            DirectoryEntry entry;
            if (dn) {
                try {
                    entry = session.read(principal, entryAttributes());
                } catch (NameNotFoundException | NoPermissionException e) {
                    result.step("Read the entry", false, Failures.describe(e));
                    return Facts.refused(Reason.ENTRY_NOT_FOUND);
                }
            } else {
                // Found by the exact principal that was bound, so the entry is the account that signed in.
                String filter = "(userPrincipalName=" + LdapEscaping.filterValue(principal) + ")";
                List<DirectoryEntry> found = session.search(settings.userSearchBase(), filter, entryAttributes(), 2);
                if (found.size() != 1) {
                    result.step("Find the entry by userPrincipalName", false, found.size() + " entries match " + filter);
                    return Facts.refused(found.isEmpty() ? Reason.ENTRY_NOT_FOUND : Reason.AMBIGUOUS_USER);
                }
                entry = found.get(0);
            }
            return entryFacts(session, entry, name, result);
        }
    }

    private Facts searchBind(String name, String password, LoginResult result) throws NamingException, IOException {
        DirectorySession service;
        try {
            service = directory.bindService();
        } catch (AuthenticationException e) {
            result.step("Bind as the service account", false, Failures.describe(e));
            return Facts.refused(Reason.SERVICE_BIND_REFUSED);
        }
        try (DirectorySession session = service) {
            result.step(settings.serviceDn().isEmpty() ? "Connect anonymously" : "Bind as " + settings.serviceDn(), true, null);
            String filter = Placeholders.fill(settings.userSearchFilter(), name, null);
            List<DirectoryEntry> found = session.search(settings.userSearchBase(), filter, entryAttributes(), 2);
            if (found.size() != 1) {
                result.step("Find the user", false, found.size() + " entries match " + filter);
                return Facts.refused(found.isEmpty() ? Reason.UNKNOWN_USER : Reason.AMBIGUOUS_USER);
            }
            DirectoryEntry entry = found.get(0);
            result.step("Find the user", true, entry.dn());
            DirectorySession user = bindUser(entry.dn(), password, result);
            if (user == null) {
                return Facts.refused(Reason.BIND_REFUSED);
            }
            user.close();
            return entryFacts(session, entry, name, result);
        }
    }

    /** @return the bound session, or null when the directory refused the password */
    private DirectorySession bindUser(String principal, String password, LoginResult result) throws NamingException, IOException {
        try {
            DirectorySession session = directory.bind(principal, password);
            result.step("Bind as " + principal, true, null);
            return session;
        } catch (AuthenticationException e) {
            result.step("Bind as " + principal, false, Failures.describe(e));
            return null;
        }
    }

    private Facts entryFacts(DirectorySession session, DirectoryEntry entry, String name, LoginResult result)
            throws NamingException {
        String entryId = entryId(entry);
        result.entry(entry.dn(), entryId);
        List<String> values = entry.all(settings.usernameAttribute());
        if (values.isEmpty() || values.get(0).isBlank()) {
            result.step("Username attribute", false, settings.usernameAttribute() + " has no value in " + entry.dn());
            return Facts.refused(Reason.NO_USERNAME);
        }
        String username = values.get(0);
        if (values.size() > 1) {
            // Several values: the one the user signed in with, so the choice isn't the directory's order.
            List<String> same = values.stream().filter(value -> normalize(value).equals(normalize(name))).toList();
            if (same.size() != 1) {
                result.step("Username attribute", false, settings.usernameAttribute() + " has " + values.size()
                        + " values and " + same.size() + " of them equal the name signed in with");
                return Facts.refused(Reason.USERNAME_AMBIGUOUS);
            }
            username = same.get(0);
        }
        if (LogText.hasControl(username)) {
            result.step("Username attribute", false, LogText.quote(username) + " contains control characters");
            return Facts.refused(Reason.USERNAME_INVALID);
        }
        if (entryId == null) {
            result.step("Entry id", false, "no " + entryIdAttributes() + " in " + entry.dn());
            return Facts.refused(Reason.NO_ENTRY_ID);
        }
        result.step("Read the entry", true, "username " + LogText.quote(username) + ", id " + LogText.quote(entryId));
        if (!settings.loginFilter().isEmpty()) {
            // The user's own entry, on the connection the group check uses.
            String filter = Placeholders.fill(settings.loginFilter(), username, entry.dn());
            if (!session.matches(entry.dn(), filter)) {
                result.step("Login filter", false, entry.dn() + " doesn't match " + filter);
                return Facts.refused(Reason.NOT_ALLOWED);
            }
            result.step("Login filter", true, filter);
        }
        if (!settings.groupFilter().isEmpty()) {
            String filter = Placeholders.fill(settings.groupFilter(), username, entry.dn());
            List<DirectoryEntry> allowed = session.search(settings.groupSearchBase(), filter, List.of(), 1);
            if (allowed.isEmpty()) {
                result.step("Group filter", false, "nothing matches " + filter);
                return Facts.refused(Reason.NOT_IN_GROUP);
            }
            result.step("Group filter", true, allowed.get(0).dn());
        }
        List<DirectoryGroup> groups = new ArrayList<>();
        if (readGroups) {
            String filter = Placeholders.fill(settings.rolesMemberFilter(), username, entry.dn());
            List<String> shown = new ArrayList<>();
            for (DirectoryEntry group : session.search(settings.groupSearchBase(), filter, List.of(settings.rolesGroupAttribute()), 1000)) {
                groups.add(DirectoryGroup.of(group, settings.rolesGroupAttribute()));
                shown.add(group.dn());
            }
            result.groups(shown);
            result.step("Groups", true, shown.isEmpty() ? "none" : String.join("; ", shown));
        }
        return new Facts(null, entry, username, entryId, groups);
    }

    private List<String> entryAttributes() {
        List<String> attributes = new ArrayList<>();
        attributes.add(settings.usernameAttribute());
        attributes.addAll(entryIdAttributes());
        for (String attribute : new String[] { settings.firstNameAttribute(), settings.lastNameAttribute(),
                settings.emailAttribute(), settings.organizationAttribute() }) {
            if (!attribute.isEmpty()) {
                attributes.add(attribute);
            }
        }
        return attributes;
    }

    private List<String> entryIdAttributes() {
        if (settings.entryIdAttribute().equalsIgnoreCase(LdapSettings.ENTRY_ID_AUTO)) {
            return List.of("entryUUID", "objectGUID");
        }
        return List.of(settings.entryIdAttribute());
    }

    /** The first id attribute with a value, normalized; null when there is none. */
    private String entryId(DirectoryEntry entry) {
        for (String attribute : entryIdAttributes()) {
            String value = entry.first(attribute);
            if (value != null && !value.isBlank()) {
                return normalize(value);
            }
        }
        return null;
    }
}
