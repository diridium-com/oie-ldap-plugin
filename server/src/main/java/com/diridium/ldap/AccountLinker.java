// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.normalize;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.diridium.ldap.LoginResult.Reason;
import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.UserController;

/**
 * Finds, links or creates the engine account for a directory entry.
 *
 * <p>Engine accounts are found the way the engine finds them, with
 * {@code UserController.getUser(null, name)}, so the database's own case and accent
 * rules decide which account a name means. A link ({@link LinkStore}) records the
 * entry's stable id for an engine user id. Accounts this plugin creates are linked
 * when created. An engine account that existed before signs in through the directory
 * only when the {@code linked-accounts} setting pairs it with the directory name; the
 * first such sign-in records the link. Once recorded, a different entry (a directory
 * user deleted and re-created under the same name) is refused.</p>
 */
final class AccountLinker {

    /** The Administrator's first-login dialog and password prompt don't apply to directory accounts. */
    static final String FIRST_LOGIN_PREFERENCE = "firstlogin";

    private static final Logger LOG = LoggerFactory.getLogger(AccountLinker.class);
    // The engine's PERSON columns (engine v4.7.0, server/dbconf/<database>/<database>-database.sql):
    // FIRSTNAME and LASTNAME hold 40, EMAIL and ORGANIZATION 255; NVARCHAR on SQL Server, VARCHAR
    // elsewhere. Oracle's VARCHAR(40) may count bytes, not characters; the end-to-end tests measure it.
    private static final int NAME_COLUMN = 40;
    private static final int WIDE_COLUMN = 255;

    /** The engine account a typed name means; {@code failed} when the engine couldn't be asked. */
    record Lookup(User user, boolean failed) {
    }

    /** The account a sign-in ends up with, the account to create, or why there is none. */
    record Resolution(Reason refusal, String detail, String username, Integer userId, boolean toCreate) {

        static Resolution refuse(Reason reason, String detail) {
            return new Resolution(reason, detail, null, null, false);
        }

        boolean refused() {
            return refusal != null;
        }
    }

    private final LdapSettings settings;
    private final Supplier<UserController> users;
    private final LinkStore links;

    AccountLinker(LdapSettings settings, Supplier<UserController> users, LinkStore links) {
        this.settings = settings;
        this.users = users;
        this.links = links;
    }

    /** The engine account the typed name means, found as the engine finds it. */
    Lookup lookup(String typed) {
        try {
            return new Lookup(users.get().getUser(null, typed), false);
        } catch (ControllerException | RuntimeException e) {
            LOG.warn("Could not read the engine account for " + LogText.quote(typed) + ": " + e);
            return new Lookup(null, true);
        }
    }

    /** Whether the name is on the local-only list: the account's name, or the typed one when there's no account. */
    boolean isLocalOnly(Lookup lookup, String typed) {
        String name = lookup.user() != null ? lookup.user().getUsername() : typed;
        return settings.localOnlyUsernames().contains(normalize(name));
    }

    /**
     * Whether the sign-in is for a directory account: an engine account with a link, an engine
     * account or directory name in {@code linked-accounts}, or one that can't be checked.
     */
    boolean isDirectoryAccount(Lookup lookup, String typed) {
        if (lookup.failed()) {
            return true;
        }
        String key = normalize(typed);
        String name = lookup.user() == null ? null : normalize(lookup.user().getUsername());
        for (NamePair link : settings.linkedAccounts()) {
            String local = normalize(link.left());
            if (local.equals(key) || normalize(link.right()).equals(key) || local.equals(name)) {
                return true;
            }
        }
        if (lookup.user() == null) {
            return false;
        }
        try {
            return links.entryId(lookup.user().getId()) != null;
        } catch (RuntimeException e) {
            LOG.warn("Could not read the account link of engine user id " + lookup.user().getId() + ": " + e);
            return true;
        }
    }

    /** Whether the plugin created the engine account; an account it can't read about counts as created. */
    boolean isCreated(int userId) {
        try {
            return links.created(userId);
        } catch (RuntimeException e) {
            LOG.warn("Could not read the account link of engine user id " + userId + ": " + e);
            return true;
        }
    }

    /**
     * The name to look up in the directory: the linked directory name when the typed name
     * is a linked account's engine name, so either name signs in.
     */
    String directoryName(String typed) {
        String key = normalize(typed);
        for (NamePair link : settings.linkedAccounts()) {
            if (normalize(link.left()).equals(key)) {
                return link.right();
            }
        }
        return typed;
    }

    /**
     * @param typedAccount  the engine account the typed name means; the engine's REST Basic
     *                      sign-in uses it, whatever name this plugin returns
     * @param directoryName the entry's username-attribute value, as stored
     * @param dryRun        for a test login: no link is recorded
     */
    Resolution resolve(Lookup typedAccount, String directoryName, String entryId, boolean dryRun) {
        try {
            return resolveOrThrow(typedAccount, directoryName, entryId, dryRun);
        } catch (ControllerException | RuntimeException e) {
            LOG.warn("Could not read or write the engine account for " + LogText.quote(directoryName) + ": " + e);
            return Resolution.refuse(Reason.ACCOUNT_ERROR, null);
        }
    }

    private Resolution resolveOrThrow(Lookup typedAccount, String directoryName, String entryId, boolean dryRun)
            throws ControllerException {
        if (typedAccount.failed()) {
            return Resolution.refuse(Reason.ACCOUNT_ERROR, null);
        }
        NamePair link = null;
        for (NamePair candidate : settings.linkedAccounts()) {
            if (normalize(candidate.right()).equals(normalize(directoryName))) {
                link = candidate;
            }
        }
        String localName = link != null ? link.left() : directoryName;
        if (localName.length() > LdapSettings.MAX_USERNAME_LENGTH) {
            return Resolution.refuse(Reason.NAME_TOO_LONG, LogText.quote(localName) + " has " + localName.length() + " characters");
        }
        User account = users.get().getUser(null, localName);
        List<Integer> sameName = new ArrayList<>();
        String key = normalize(account != null ? account.getUsername() : localName);
        for (User user : users.get().getAllUsers()) {
            if (normalize(user.getUsername()).equals(key)) {
                sameName.add(user.getId());
            }
        }
        if (sameName.size() > 1) {
            return Resolution.refuse(Reason.DUPLICATE_LOCAL, "engine user ids " + sameName);
        }
        User typed = typedAccount.user();
        if (typed != null && (account == null || !typed.getId().equals(account.getId()))) {
            return Resolution.refuse(Reason.OTHER_ACCOUNT_TYPED, "the typed name is engine user id " + typed.getId()
                    + ", the directory entry belongs to " + LogText.quote(localName));
        }
        if (account == null) {
            return settings.createUsers() ? new Resolution(null, null, localName, null, true)
                    : Resolution.refuse(Reason.NO_LOCAL_ACCOUNT, null);
        }
        String recorded = links.entryId(account.getId());
        if (recorded != null) {
            if (!normalize(recorded).equals(entryId)) {
                return Resolution.refuse(Reason.ENTRY_MISMATCH, "engine user id " + account.getId() + " is linked to entry "
                        + LogText.quote(normalize(recorded)) + ", the directory returned " + LogText.quote(entryId));
            }
            return new Resolution(null, null, account.getUsername(), account.getId(), false);
        }
        if (link == null) {
            return Resolution.refuse(Reason.NOT_LINKED, "engine user id " + account.getId());
        }
        if (!dryRun) {
            links.link(account.getId(), entryId);
            LOG.info("Linked engine user " + LogText.quote(account.getUsername()) + " (id " + account.getId()
                    + ") to directory entry " + LogText.quote(entryId));
        }
        return new Resolution(null, null, account.getUsername(), account.getId(), false);
    }

    /** Creates the engine account, without a password, and links it. */
    Resolution create(String name, String entryId, DirectoryEntry entry) {
        try {
            User user = new User();
            user.setUsername(name);
            // Display details only, so a value too long for its column is cut, not refused.
            user.setFirstName(value(entry, settings.firstNameAttribute(), NAME_COLUMN));
            user.setLastName(value(entry, settings.lastNameAttribute(), NAME_COLUMN));
            user.setEmail(value(entry, settings.emailAttribute(), WIDE_COLUMN));
            user.setOrganization(value(entry, settings.organizationAttribute(), WIDE_COLUMN));
            users.get().updateUser(user);
            // The engine's insert doesn't hand back the new id.
            User stored = users.get().getUser(null, name);
            if (stored == null || stored.getId() == null) {
                throw new ControllerException("the new engine user " + name + " could not be read back");
            }
            links.link(stored.getId(), entryId);
            links.markCreated(stored.getId());
            users.get().setUserPreference(stored.getId(), FIRST_LOGIN_PREFERENCE, "false");
            LOG.info("Created engine user " + LogText.quote(name) + " (id " + stored.getId() + ") for directory entry "
                    + LogText.quote(entryId));
            return new Resolution(null, null, stored.getUsername(), stored.getId(), false);
        } catch (ControllerException | RuntimeException e) {
            LOG.warn("Could not create the engine account " + LogText.quote(name) + ": " + e);
            return Resolution.refuse(Reason.ACCOUNT_ERROR, null);
        }
    }

    /**
     * The attribute's first value cut to the column's size, or null when unset. A value
     * starting with {@code <html} is dropped: the Swing Administrator would render it.
     */
    private static String value(DirectoryEntry entry, String attribute, int column) {
        String value = entry.first(attribute);
        if (value == null || value.isBlank()) {
            return null;
        }
        value = value.strip();
        if (value.toLowerCase(Locale.ROOT).startsWith("<html")) {
            LOG.debug("Dropped the directory's " + attribute + " value: it starts with <html");
            return null;
        }
        if (value.length() > column) {
            LOG.debug("Cut the directory's " + attribute + " value of " + value.length() + " characters to the "
                    + column + " the engine stores");
            return value.substring(0, column);
        }
        return value;
    }
}
