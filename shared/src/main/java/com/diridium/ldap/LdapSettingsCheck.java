// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

/**
 * The checks {@link LdapSettings#parse} runs after reading the values. Values
 * that are set are always checked; values that are needed are required only
 * when the plugin is enabled, so a half-finished configuration can be saved
 * switched off.
 */
final class LdapSettingsCheck {

    /** RFC 4512 descr or numericoid. */
    private static final Pattern ATTRIBUTE = Pattern.compile("[A-Za-z][A-Za-z0-9-]*|[0-9]+(\\.[0-9]+)+");

    private LdapSettingsCheck() {
    }

    static List<String> problems(LdapSettings s) {
        List<String> p = new ArrayList<>();
        attribute(p, USERNAME_ATTRIBUTE, s.usernameAttribute, true);
        if (!ENTRY_ID_AUTO.equalsIgnoreCase(s.entryIdAttribute)) {
            attribute(p, ENTRY_ID_ATTRIBUTE, s.entryIdAttribute, true);
        }
        attribute(p, FIRST_NAME_ATTRIBUTE, s.firstNameAttribute, false);
        attribute(p, LAST_NAME_ATTRIBUTE, s.lastNameAttribute, false);
        attribute(p, EMAIL_ATTRIBUTE, s.emailAttribute, false);
        attribute(p, ORGANIZATION_ATTRIBUTE, s.organizationAttribute, false);
        attribute(p, ROLES_GROUP_ATTRIBUTE, s.rolesGroupAttribute, !s.rolesMap.isEmpty());
        urls(p, s);
        if (!s.caCertificate.isEmpty()) {
            try {
                PemCertificates.parse(s.caCertificate);
            } catch (CertificateException e) {
                p.add(CA_CERTIFICATE + ": not a PEM certificate (" + e.getMessage() + ").");
            }
        }
        if (!s.servicePassword.isEmpty() && !s.servicePassword.startsWith(SEALED_PREFIX)) {
            p.add(SERVICE_PASSWORD + ": stored in clear. Save the settings again so the password is encrypted.");
        }
        dn(p, SERVICE_DN, s.serviceDn);
        dn(p, USER_SEARCH_BASE, s.userSearchBase);
        dn(p, GROUP_SEARCH_BASE, s.groupSearchBase);
        if (!s.userDnTemplate.isEmpty() && !s.userDnTemplate.contains("{username}")) {
            p.add(USER_DN_TEMPLATE + ": must contain {username}.");
        }
        filter(p, USER_SEARCH_FILTER, s.userSearchFilter, "{username}");
        filter(p, GROUP_FILTER, s.groupFilter, "{username}", "{dn}");
        filter(p, LOGIN_FILTER, s.loginFilter);
        filter(p, ROLES_MEMBER_FILTER, s.rolesMemberFilter, "{username}", "{dn}");
        linkedAccounts(p, s);
        roles(p, s);
        if (s.enabled) {
            required(p, s);
        }
        return p;
    }

    /** Settings that work but deserve a second look. */
    static List<String> warnings(LdapSettings s) {
        List<String> w = new ArrayList<>();
        boolean plain = !s.urls.isEmpty() && s.urls.stream().noneMatch(url -> url.toLowerCase(Locale.ROOT).startsWith("ldaps:"));
        if (s.enabled && plain && !s.startTls) {
            w.add(URL + ": ldap:// without starttls sends every password to the directory in clear.");
        }
        if (s.enabled && s.localOnlyUsernames.isEmpty()) {
            w.add(LOCAL_ONLY_USERNAMES + ": empty, so every engine account signs in through the directory. "
                    + "If the directory fails, the kill switch (OIE_LDAP_DISABLED=true) is the way back in.");
        }
        if (s.outageLocalPasswords) {
            w.add(OUTAGE_LOCAL_PASSWORDS + ": on, so directory accounts sign in with their engine passwords "
                    + "while the directory can't be used.");
        }
        for (NamePair mapping : s.rolesMap) {
            if (!mapping.left().contains("=")) {
                w.add(ROLES_MAP + ": \"" + mapping.left() + "\" is a group name, which matches every group of that name under "
                        + GROUP_SEARCH_BASE + ". A group DN matches only that group.");
            }
        }
        return w;
    }

    /** Role sync needs a default role, so someone who leaves every mapped group still gets one. */
    private static void roles(List<String> p, LdapSettings s) {
        for (NamePair mapping : s.rolesMap) {
            if (mapping.left().contains("=")) {
                dn(p, ROLES_MAP, mapping.left());
            }
        }
        boolean syncing = s.rolesSync != RoleSync.NEVER && !s.rolesMap.isEmpty();
        if ((syncing || s.createUsers) && s.rolesDefault.isEmpty()) {
            p.add(ROLES_DEFAULT + ": needed when " + CREATE_USERS + " is on or " + ROLES_MAP
                    + " is set with role sync on, so every account gets at least this role.");
        }
        if (s.createUsers && s.groupFilter.isEmpty() && s.loginFilter.isEmpty()) {
            p.add(CREATE_USERS + ": needs " + LOGIN_FILTER + " or " + GROUP_FILTER
                    + ", so accounts are created only for the users they allow.");
        }
    }

    private static void required(List<String> p, LdapSettings s) {
        if (s.urls.isEmpty()) {
            p.add(URL + ": needed when LDAP is enabled.");
        }
        if (s.bindMode == BindMode.TEMPLATE) {
            if (s.userDnTemplate.isEmpty()) {
                p.add(USER_DN_TEMPLATE + ": needed for the template bind mode.");
            } else if (!isDnTemplate(s.userDnTemplate) && s.userSearchBase.isEmpty()) {
                p.add(USER_SEARCH_BASE + ": needed when " + USER_DN_TEMPLATE
                        + " is not a DN (such as {username}@corp.example.com): the entry is found there by userPrincipalName.");
            }
        } else {
            if (s.userSearchBase.isEmpty()) {
                p.add(USER_SEARCH_BASE + ": needed for the search bind mode.");
            }
            if (s.userSearchFilter.isEmpty()) {
                p.add(USER_SEARCH_FILTER + ": needed for the search bind mode.");
            }
            if (!s.serviceDn.isEmpty() && s.servicePassword.isEmpty()) {
                p.add(SERVICE_PASSWORD + ": needed when " + SERVICE_DN + " is set.");
            }
        }
        if (s.groupFilter.isEmpty() && s.loginFilter.isEmpty()) {
            p.add(LOGIN_FILTER + ": needed when LDAP is enabled and " + GROUP_FILTER
                    + " is empty. Set one or both to say who may sign in.");
        }
        if (!s.groupFilter.isEmpty() && s.groupSearchBase.isEmpty()) {
            p.add(GROUP_SEARCH_BASE + ": needed when " + GROUP_FILTER + " is set.");
        }
        if (!s.rolesMap.isEmpty() && s.rolesSync != RoleSync.NEVER) {
            if (s.groupSearchBase.isEmpty()) {
                p.add(GROUP_SEARCH_BASE + ": needed when " + ROLES_MAP + " is set.");
            }
            if (s.rolesMemberFilter.isEmpty()) {
                p.add(ROLES_MEMBER_FILTER + ": needed when " + ROLES_MAP + " is set.");
            }
        }
    }

    /** Whether the template, with a name put in, is a DN (and not, say, a userPrincipalName). */
    static boolean isDnTemplate(String template) {
        try {
            return new LdapName(template.replace("{username}", "x")).size() > 0;
        } catch (InvalidNameException | IllegalArgumentException e) {
            return false;
        }
    }

    private static void urls(List<String> p, LdapSettings s) {
        Set<String> schemes = new HashSet<>();
        for (String url : s.urls) {
            String scheme = null;
            try {
                URI uri = new URI(url);
                scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
                boolean noPath = uri.getRawPath() == null || uri.getRawPath().isEmpty() || uri.getRawPath().equals("/");
                if (!("ldap".equals(scheme) || "ldaps".equals(scheme)) || uri.getHost() == null || !noPath
                        || uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getRawUserInfo() != null) {
                    scheme = null;
                }
            } catch (URISyntaxException e) {
                scheme = null;
            }
            if (scheme == null) {
                p.add(URL + ": \"" + url + "\" must be ldap://host[:port] or ldaps://host[:port], with no path.");
            } else {
                schemes.add(scheme);
            }
        }
        if (schemes.size() > 1) {
            p.add(URL + ": use either ldap:// or ldaps:// URLs, not both.");
        }
        if (s.startTls && schemes.contains("ldaps")) {
            p.add(STARTTLS + ": StartTLS needs ldap:// URLs; ldaps:// is already encrypted.");
        }
    }

    private static void linkedAccounts(List<String> p, LdapSettings s) {
        Set<String> locals = new HashSet<>();
        Set<String> directories = new HashSet<>();
        for (NamePair pair : s.linkedAccounts) {
            String local = normalize(pair.left());
            if (pair.left().length() > MAX_USERNAME_LENGTH) {
                p.add(LINKED_ACCOUNTS + ": \"" + pair.left() + "\" is longer than " + MAX_USERNAME_LENGTH
                        + " characters, which an engine username can't be.");
            }
            if (!locals.add(local)) {
                p.add(LINKED_ACCOUNTS + ": \"" + pair.left() + "\" is linked more than once.");
            }
            if (!directories.add(normalize(pair.right()))) {
                p.add(LINKED_ACCOUNTS + ": directory user \"" + pair.right() + "\" is linked more than once.");
            }
            if (s.localOnlyUsernames.contains(local)) {
                p.add(LINKED_ACCOUNTS + ": \"" + pair.left() + "\" is also in " + LOCAL_ONLY_USERNAMES + ".");
            }
        }
    }

    private static void attribute(List<String> p, String key, String value, boolean needed) {
        if (value.isEmpty()) {
            if (needed) {
                p.add(key + ": needed.");
            }
        } else if (!ATTRIBUTE.matcher(value).matches()) {
            p.add(key + ": \"" + value + "\" is not an attribute name.");
        }
    }

    private static void dn(List<String> p, String key, String value) {
        if (!value.isEmpty()) {
            try {
                new LdapName(value);
            } catch (InvalidNameException | IllegalArgumentException e) {
                p.add(key + ": \"" + value + "\" is not a DN.");
            }
        }
    }

    private static void filter(List<String> p, String key, String value, String... placeholders) {
        if (value.isEmpty()) {
            return;
        }
        if (!balanced(value)) {
            p.add(key + ": \"" + value + "\" is not an LDAP filter in parentheses.");
            return;
        }
        if (placeholders.length == 0) {
            return;
        }
        for (String placeholder : placeholders) {
            if (value.contains(placeholder)) {
                return;
            }
        }
        p.add(key + ": must contain " + String.join(" or ", placeholders) + ".");
    }

    private static boolean balanced(String filter) {
        if (!filter.startsWith("(") || !filter.endsWith(")")) {
            return false;
        }
        int depth = 0;
        for (int i = 0; i < filter.length(); i++) {
            char c = filter.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth < 0) {
                return false;
            }
        }
        return depth == 0;
    }
}
