// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.junit.jupiter.api.Test;

class LdapSettingsTest {

    private static final String CA = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBszCCAVmgAwIBAgIUAKc1qJQZ3Qb3wDpYQb9Kp9sTnD0wCgYIKoZIzj0EAwIw\n"
            + "-----END CERTIFICATE-----\n";

    private static Properties enabled(String... keysAndValues) {
        Properties p = new Properties();
        p.setProperty(LdapSettings.ENABLED, "true");
        p.setProperty(LdapSettings.URL, "ldap://ldap.example.com:389");
        p.setProperty(LdapSettings.USER_DN_TEMPLATE, "uid={username},ou=people,dc=example,dc=com");
        p.setProperty(LdapSettings.LOGIN_FILTER, "(objectClass=person)");
        for (int i = 0; i + 1 < keysAndValues.length; i += 2) {
            p.setProperty(keysAndValues[i], keysAndValues[i + 1]);
        }
        return p;
    }

    private static List<String> problems(String... keysAndValues) {
        return LdapSettings.parse(enabled(keysAndValues)).problems();
    }

    private static void assertProblem(String expectedKeyAndText, String... keysAndValues) {
        List<String> problems = problems(keysAndValues);
        assertTrue(problems.stream().anyMatch(p -> p.startsWith(expectedKeyAndText.split(":")[0] + ":")
                && p.contains(expectedKeyAndText.substring(expectedKeyAndText.indexOf(':') + 1).trim())),
                "expected \"" + expectedKeyAndText + "\" in " + problems);
    }

    @Test
    void theDefaultsAreValidAndSwitchedOff() {
        LdapSettings defaults = LdapSettings.parse(LdapSettings.defaults());
        assertEquals(List.of(), defaults.problems());
        assertFalse(defaults.enabled());
        assertEquals(LdapSettings.defaults(), defaults.toProperties());
        assertEquals(LdapSettings.defaults(), LdapSettings.parse(null).toProperties());
        assertEquals(2, defaults.retries());
        assertEquals("uid", defaults.usernameAttribute());
        assertEquals(LdapSettings.RoleSync.ALWAYS, defaults.rolesSync());
        assertFalse(defaults.createUsers());
        assertFalse(defaults.outageLocalPasswords());
    }

    @Test
    void settingsRoundTripThroughProperties() {
        Properties p = enabled(LdapSettings.LINKED_ACCOUNTS, "mary = mjones, ops\\,night=nops",
                LdapSettings.ROLES_MAP, "Ops\\, Night=Operator\\=x", LdapSettings.GROUP_SEARCH_BASE, "ou=groups,dc=example,dc=com",
                LdapSettings.ROLES_DEFAULT, "Viewer",
                LdapSettings.LOCAL_ONLY_USERNAMES, " Admin , ROOT");
        LdapSettings once = LdapSettings.parse(p);
        assertEquals(List.of(), once.problems());
        assertEquals(List.of(new NamePair("mary", "mjones"), new NamePair("ops,night", "nops")), once.linkedAccounts());
        assertEquals(List.of(new NamePair("Ops, Night", "Operator=x")), once.rolesMap());
        assertEquals(Set.of("admin", "root"), once.localOnlyUsernames());
        LdapSettings twice = LdapSettings.parse(once.toProperties());
        assertEquals(once.toProperties(), twice.toProperties());
        assertEquals(once.linkedAccounts(), twice.linkedAccounts());
    }

    @Test
    void namesAreComparedTrimmedAndLowerCased() {
        assertEquals("alice", LdapSettings.normalize("  ALICE "));
        assertEquals("", LdapSettings.normalize(null));
        // Locale.ROOT, not the platform locale: a Turkish default would turn "I" into a dotless i.
        assertEquals("i", LdapSettings.normalize("I"));
    }

    @Test
    void numbersBooleansAndChoicesAreChecked() {
        assertProblem("retries: from 0 to 10", LdapSettings.RETRIES, "11");
        assertProblem("retry-interval-ms: whole number", LdapSettings.RETRY_INTERVAL_MS, "fast");
        assertProblem("connect-timeout-ms: from 100", LdapSettings.CONNECT_TIMEOUT_MS, "0");
        assertProblem("starttls: not true or false", LdapSettings.STARTTLS, "yes");
        assertProblem("bind-mode: not one of template, search", LdapSettings.BIND_MODE, "anonymous");
        assertProblem("roles.sync: not one of always, jit-only, never", LdapSettings.ROLES_SYNC, "sometimes");
    }

    @Test
    void urlsMustBeLdapOrLdapsWithoutAPath() {
        assertProblem("url: must be ldap://host[:port]", LdapSettings.URL, "http://ldap.example.com");
        assertProblem("url: with no path", LdapSettings.URL, "ldap://ldap.example.com/dc=example,dc=com");
        assertProblem("url: not both", LdapSettings.URL, "ldap://a.example.com ldaps://b.example.com");
        assertProblem("starttls: needs ldap://", LdapSettings.URL, "ldaps://a.example.com", LdapSettings.STARTTLS, "true");
        assertEquals(List.of(), problems(LdapSettings.URL, "ldaps://a.example.com:636 ldaps://b.example.com"));
        assertEquals(List.of("ldaps://a.example.com:636", "ldaps://b.example.com"),
                LdapSettings.parse(enabled(LdapSettings.URL, " ldaps://a.example.com:636   ldaps://b.example.com ")).urls());
    }

    @Test
    void aServicePasswordStoredInClearIsAProblemEvenWhenSwitchedOff() {
        assertProblem("service-password: stored in clear", LdapSettings.SERVICE_PASSWORD, "hunter2");
        Properties off = LdapSettings.defaults();
        off.setProperty(LdapSettings.SERVICE_PASSWORD, "hunter2");
        assertFalse(LdapSettings.parse(off).isValid());
        assertEquals(List.of(), problems(LdapSettings.SERVICE_PASSWORD, LdapSettings.SEALED_PREFIX + "abc"));
    }

    @Test
    void theCaCertificateMustBePem() {
        assertProblem("ca-certificate: not a PEM certificate", LdapSettings.CA_CERTIFICATE, "not a certificate");
        assertProblem("ca-certificate: not a PEM certificate", LdapSettings.CA_CERTIFICATE, CA);
    }

    @Test
    void templatesAndFiltersNeedTheirPlaceholders() {
        assertProblem("user-dn-template: must contain {username}", LdapSettings.USER_DN_TEMPLATE, "uid=fixed,dc=example,dc=com");
        assertProblem("group-filter: must contain {username} or {dn}", LdapSettings.GROUP_FILTER, "(cn=mirth)",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com");
        assertProblem("group-filter: not an LDAP filter", LdapSettings.GROUP_FILTER, "member={dn}",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com");
        assertProblem("roles.member-filter: not an LDAP filter", LdapSettings.ROLES_MEMBER_FILTER, "(member={dn}");
        assertEquals(List.of(), problems(LdapSettings.GROUP_FILTER, "(&(cn=a\\29b)(member={dn}))",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com"));
    }

    @Test
    void aUpnTemplateNeedsTheSearchBaseItsEntryIsFoundUnder() {
        LdapSettings upn = LdapSettings.parse(enabled(LdapSettings.USER_DN_TEMPLATE, "{username}@corp.example.com"));
        assertFalse(upn.userDnTemplateIsDn());
        assertProblem("user-search-base: userPrincipalName", LdapSettings.USER_DN_TEMPLATE, "{username}@corp.example.com");
        assertEquals(List.of(), problems(LdapSettings.USER_DN_TEMPLATE, "{username}@corp.example.com",
                LdapSettings.USER_SEARCH_BASE, "dc=corp,dc=example,dc=com"));
        assertTrue(LdapSettings.parse(enabled()).userDnTemplateIsDn());
    }

    @Test
    void searchModeNeedsItsBaseAndFilterAndAPasswordForTheServiceAccount() {
        assertProblem("user-search-base: needed for the search bind mode", LdapSettings.BIND_MODE, "search");
        assertProblem("user-search-filter: needed for the search bind mode", LdapSettings.BIND_MODE, "search");
        assertProblem("user-search-filter: must contain {username}", LdapSettings.BIND_MODE, "search",
                LdapSettings.USER_SEARCH_FILTER, "(uid=x)");
        assertProblem("service-password: needed when service-dn is set", LdapSettings.BIND_MODE, "search",
                LdapSettings.SERVICE_DN, "cn=service,dc=example,dc=com");
        assertEquals(List.of(), problems(LdapSettings.BIND_MODE, "search", LdapSettings.USER_SEARCH_BASE, "dc=example,dc=com",
                LdapSettings.USER_SEARCH_FILTER, "(uid={username})"));
    }

    @Test
    void groupAndRoleFiltersNeedTheGroupSearchBase() {
        assertProblem("group-search-base: needed when group-filter is set", LdapSettings.GROUP_FILTER, "(member={dn})");
        assertProblem("group-search-base: needed when roles.map is set", LdapSettings.ROLES_MAP, "admins=Admin",
                LdapSettings.ROLES_DEFAULT, "Viewer");
        assertEquals(List.of(), problems(LdapSettings.ROLES_MAP, "admins=Admin", LdapSettings.ROLES_SYNC, "never"));
    }

    @Test
    void dnsAndAttributeNamesAreChecked() {
        assertProblem("group-search-base: not a DN", LdapSettings.GROUP_SEARCH_BASE, "groups");
        assertProblem("username-attribute: not an attribute name", LdapSettings.USERNAME_ATTRIBUTE, "user name");
        assertProblem("username-attribute: needed", LdapSettings.USERNAME_ATTRIBUTE, "");
        assertProblem("entry-id-attribute: not an attribute name", LdapSettings.ENTRY_ID_ATTRIBUTE, "x y");
        assertEquals(List.of(), problems(LdapSettings.ENTRY_ID_ATTRIBUTE, "objectGUID", LdapSettings.EMAIL_ATTRIBUTE, ""));
    }

    @Test
    void linkedAccountsAreCheckedAgainstEachOtherAndTheLocalOnlyList() {
        assertProblem("linked-accounts: not in the form localUser=directoryUsername", LdapSettings.LINKED_ACCOUNTS, "mary");
        assertProblem("linked-accounts: not in the form", LdapSettings.LINKED_ACCOUNTS, "a=b=c");
        assertProblem("linked-accounts: linked more than once", LdapSettings.LINKED_ACCOUNTS, "mary=a, MARY =b");
        assertProblem("linked-accounts: directory user \"A\" is linked more than once", LdapSettings.LINKED_ACCOUNTS, "mary=a, bob=A");
        assertProblem("linked-accounts: also in local-only-usernames", LdapSettings.LINKED_ACCOUNTS, "admin=jdoe",
                LdapSettings.LOCAL_ONLY_USERNAMES, "ADMIN");
        assertProblem("linked-accounts: longer than 40", LdapSettings.LINKED_ACCOUNTS, "x".repeat(41) + "=jdoe");
        assertProblem("roles.map: not in the form group=RBAC role", LdapSettings.ROLES_MAP, "admins",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com", LdapSettings.ROLES_DEFAULT, "Viewer");
    }

    @Test
    void neededValuesAreRequiredOnlyWhenEnabled() {
        Properties half = new Properties();
        half.setProperty(LdapSettings.BIND_MODE, "search");
        assertEquals(List.of(), LdapSettings.parse(half).problems());
        half.setProperty(LdapSettings.ENABLED, "true");
        assertTrue(LdapSettings.parse(half).problems().contains("url: needed when LDAP is enabled."),
                LdapSettings.parse(half).problems().toString());
    }

    @Test
    void anUnreadableValueKeepsItsDefaultAndIsReported() {
        LdapSettings settings = LdapSettings.parse(enabled(LdapSettings.READ_TIMEOUT_MS, "soon"));
        assertEquals(10_000, settings.readTimeoutMs());
        assertFalse(settings.isValid());
    }

    @Test
    void roleSyncAndAccountCreationNeedADefaultRole() {
        assertProblem("roles.default: needed when create-users is on", LdapSettings.ROLES_MAP, "admins=Admin",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com");
        assertProblem("roles.default: needed when create-users is on", LdapSettings.CREATE_USERS, "true",
                LdapSettings.GROUP_FILTER, "(member={dn})", LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com");
        assertEquals(List.of(), problems(LdapSettings.ROLES_MAP, "admins=Admin", LdapSettings.ROLES_SYNC, "never"));
    }

    @Test
    void accountCreationNeedsAFilterEvenWhileLdapIsOff() {
        Properties off = LdapSettings.defaults();
        off.setProperty(LdapSettings.CREATE_USERS, "true");
        off.setProperty(LdapSettings.ROLES_DEFAULT, "Viewer");
        assertFalse(LdapSettings.parse(off).isValid(), "checked even while LDAP is off");
    }

    @Test
    void aRolesMapKeyWithAnEqualsSignIsAGroupDn() {
        LdapSettings settings = LdapSettings.parse(enabled(LdapSettings.ROLES_MAP, "cn=ops\\,ou=groups\\,dc=example\\,dc=com=Operator",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com", LdapSettings.ROLES_DEFAULT, "Viewer"));
        assertEquals(List.of(), settings.problems());
        assertEquals(List.of(new NamePair("cn=ops,ou=groups,dc=example,dc=com", "Operator")), settings.rolesMap());
        assertEquals(settings.rolesMap(), LdapSettings.parse(settings.toProperties()).rolesMap());
        assertProblem("roles.map: not a DN", LdapSettings.ROLES_MAP, "=ops=Operator",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com", LdapSettings.ROLES_DEFAULT, "Viewer");
    }

    @Test
    void warningsNameSettingsThatWorkButDeserveASecondLook() {
        List<String> plain = LdapSettings.parse(enabled()).warnings();
        assertTrue(plain.stream().anyMatch(w -> w.startsWith("url: ldap:// without starttls")), plain.toString());
        assertTrue(plain.stream().anyMatch(w -> w.startsWith("local-only-usernames: empty")), plain.toString());
        List<String> quiet = LdapSettings.parse(enabled(LdapSettings.URL, "ldaps://ldap.example.com",
                LdapSettings.LOCAL_ONLY_USERNAMES, "admin")).warnings();
        assertEquals(List.of(), quiet);
        List<String> more = LdapSettings.parse(enabled(LdapSettings.URL, "ldaps://ldap.example.com", LdapSettings.LOCAL_ONLY_USERNAMES,
                "admin", LdapSettings.OUTAGE_LOCAL_PASSWORDS, "true", LdapSettings.ROLES_MAP, "ops=Operator",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com", LdapSettings.ROLES_DEFAULT, "Viewer")).warnings();
        assertTrue(more.stream().anyMatch(w -> w.startsWith("outage-local-passwords: on")), more.toString());
        assertTrue(more.stream().anyMatch(w -> w.startsWith("roles.map: \"ops\" is a group name")), more.toString());
    }

    @Test
    void unicodeSpacesAreRemovedBeforeNamesAreCompared() {
        assertEquals("admin", LdapSettings.normalize("\u00a0admin\u3000"));
        assertEquals("admin", LdapSettings.normalize("\u2007ADMIN\u202f"));
        assertEquals(Set.of("admin"), LdapSettings.parse(enabled(LdapSettings.LOCAL_ONLY_USERNAMES, "\u3000Admin")).localOnlyUsernames());
    }

    @Test
    void theTargetFingerprintChangesWithEveryTargetFieldAndNothingElse() {
        String base = LdapSettings.parse(enabled()).targetFingerprint();
        assertEquals(64, base.length());
        String[][] changes = { { LdapSettings.URL, "ldap://other.example.com" }, { LdapSettings.STARTTLS, "true" },
            { LdapSettings.CA_CERTIFICATE, "x" }, { LdapSettings.BIND_MODE, "search" },
            { LdapSettings.SERVICE_DN, "cn=s,dc=example,dc=com" } };
        for (String[] change : changes) {
            assertFalse(base.equals(LdapSettings.parse(enabled(change[0], change[1])).targetFingerprint()), change[0]);
        }
        assertEquals(base, LdapSettings.parse(enabled(LdapSettings.RETRIES, "5", LdapSettings.GROUP_FILTER, "(member={dn})",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com")).targetFingerprint());
        assertEquals(base, LdapSettings.parse(enabled(LdapSettings.URL, "  ldap://ldap.example.com:389 ")).targetFingerprint());
    }

    @Test
    void withLdapOnAtLeastOneSignInFilterIsNeeded() {
        assertProblem("login-filter: needed when LDAP is enabled and group-filter is empty", LdapSettings.LOGIN_FILTER, "");
        assertEquals(List.of(), problems(LdapSettings.LOGIN_FILTER, "", LdapSettings.GROUP_FILTER, "(member={dn})",
                LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com"));
        assertEquals(List.of(), problems(LdapSettings.GROUP_FILTER, "(member={dn})", LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com"));
        Properties off = LdapSettings.defaults();
        assertEquals(List.of(), LdapSettings.parse(off).problems(), "not needed while LDAP is off");
    }

    @Test
    void theLoginFilterIsCheckedLikeTheOtherFiltersAndNeedsNoPlaceholder() {
        assertProblem("login-filter: not an LDAP filter", LdapSettings.LOGIN_FILTER, "objectClass=person");
        assertProblem("login-filter: not an LDAP filter", LdapSettings.LOGIN_FILTER, "(memberOf=x");
        assertEquals(List.of(), problems(LdapSettings.LOGIN_FILTER, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"));
        assertEquals("(objectClass=person)", LdapSettings.parse(enabled()).toProperties().getProperty(LdapSettings.LOGIN_FILTER));
    }

    @Test
    void accountCreationTakesALoginFilterOrAGroupFilter() {
        assertEquals(List.of(), problems(LdapSettings.CREATE_USERS, "true", LdapSettings.ROLES_DEFAULT, "Viewer"));
        assertProblem("create-users: needs login-filter or group-filter", LdapSettings.CREATE_USERS, "true",
                LdapSettings.ROLES_DEFAULT, "Viewer", LdapSettings.LOGIN_FILTER, "");
    }
}
