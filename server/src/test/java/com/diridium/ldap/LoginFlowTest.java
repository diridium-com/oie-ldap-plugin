// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.ldap.LoginResult.Outcome;
import com.diridium.ldap.LoginResult.Reason;
import com.mirth.connect.model.User;

/**
 * Sign-ins against the in-memory directory, one test per probe finding on
 * upstream's code (oie-ldap-plugin 1.0.0 upstream probe) and per behaviour the
 * rewrite changed.
 */
class LoginFlowTest {

    private static TestDirectory directory;
    private StandInUsers users;
    private LogCapture log;

    @BeforeAll
    static void start() throws Exception {
        directory = TestDirectory.start();
    }

    @AfterAll
    static void stop() {
        directory.close();
    }

    @BeforeEach
    void setUp() {
        users = new StandInUsers();
        log = new LogCapture();
        directory.drain();
    }

    @AfterEach
    void tearDown() {
        log.close();
    }

    private LoginResult login(Properties settings, String typed, String password) throws Exception {
        return TestSupport.flow(settings, users).login(typed, password, false);
    }

    private LoginResult login(String typed, String password) throws Exception {
        return login(TestSupport.template(directory), typed, password);
    }

    private static void assertRefused(LoginResult result, Reason reason) {
        assertEquals(Outcome.REFUSED, result.outcome(), () -> "steps: " + result.steps());
        assertEquals(reason, result.reason(), () -> "steps: " + result.steps());
    }

    private static void assertSignedInAs(LoginResult result, String engineUsername) {
        assertEquals(Outcome.SUCCESS, result.outcome(), () -> result.reason() + ", steps: " + result.steps());
        assertEquals(engineUsername, result.engineUsername());
    }

    @Test
    void controlAPlainNameSignsIn() throws Exception {
        assertSignedInAs(login("alice", "alice-pw"), "alice");
    }

    @Test
    void probeFinding1ExtraRdnsInTheTypedNameAreRefused() throws Exception {
        assertRefused(login("eve,ou=contractors", "eve-pw"), Reason.BIND_REFUSED);
        assertRefused(login("carol+cn=Carol", "carol-pw"), Reason.BIND_REFUSED);
        List<String> seen = directory.drain();
        assertTrue(seen.stream().anyMatch(line -> line.contains("dn=\"uid=eve\\\\,ou\\\\=contractors," + TestDirectory.PEOPLE)
                || line.contains("dn=\"uid=eve\\,ou\\=contractors," + TestDirectory.PEOPLE)), "escaped DN sent: " + seen);
        assertEquals(List.of(), users.writes);
    }

    @Test
    void probeFinding2PaddingAndCaseNeverReachTheEngine() throws Exception {
        for (String typed : new String[] { "alice", "alice ", " alice", "ALICE", " Alice " }) {
            assertSignedInAs(login(typed, "alice-pw"), "alice");
        }
        assertEquals(1, users.getAllUsers().size(), "one engine account, named as the directory stores it");
        assertEquals("alice", users.getAllUsers().get(0).getUsername());
    }

    @Test
    void probeFinding3ADirectoryAccountNamedLikeAnUnlinkedEngineAccountIsRefused() throws Exception {
        User admin = users.add("admin");
        assertRefused(login("admin", "dir-admin-pw"), Reason.NOT_LINKED);
        assertNull(users.links.entryId(admin.getId()));
        assertEquals(List.of(), users.writes);
    }

    @Test
    void probeFinding3ALinkedEngineAccountSignsInAndRecordsTheEntry() throws Exception {
        User admin = users.add("admin");
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "admin=admin");
        assertSignedInAs(login(linked, "admin", "dir-admin-pw"), "admin");
        assertNotNull(users.links.entryId(admin.getId()));
        assertEquals(1, users.getAllUsers().size());
    }

    @Test
    void probeFinding4EitherTheEngineNameOrTheDirectoryNameSignsIn() throws Exception {
        // Upstream issue #8: typed mary, mapped to mjones, created mjones while the engine was told mary.
        users.add("mary");
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "mary=mjones");
        assertSignedInAs(login(linked, "mary", "mary-pw"), "mary");
        assertSignedInAs(login(linked, "mjones", "mary-pw"), "mary");
        assertSignedInAs(login(linked, " MARY ", "mary-pw"), "mary");
        assertEquals(1, users.getAllUsers().size(), "no mjones account is created");
        assertRefused(login(linked, "mary", "other-mary-pw"), Reason.BIND_REFUSED);
    }

    @Test
    void probeFinding4AMissingLinkedAccountIsCreatedUnderTheEngineName() throws Exception {
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "mary=mjones");
        assertSignedInAs(login(linked, "mjones", "mary-pw"), "mary");
        assertEquals("mary", users.getAllUsers().get(0).getUsername());
    }

    @Test
    void probeFinding5ARefusedPasswordLogsOneInfoLineAndNoStackTrace() throws Exception {
        assertRefused(login("alice", "wrong-pw-7"), Reason.BIND_REFUSED);
        List<LogEvent> shown = log.infoAndAbove();
        assertEquals(1, shown.size(), () -> "lines: " + shown.stream().map(LogCapture::text).toList());
        assertEquals(Level.INFO, shown.get(0).getLevel());
        assertTrue(LogCapture.text(shown.get(0)).contains("\"alice\""), LogCapture.text(shown.get(0)));
        assertTrue(LogCapture.text(shown.get(0)).contains(Reason.BIND_REFUSED.text), LogCapture.text(shown.get(0)));
        assertTrue(log.at(Level.DEBUG).stream().allMatch(event -> event.getThrown() == null));
        assertNull(shown.get(0).getThrown());
        assertFalse(log.at(Level.DEBUG).isEmpty(), "the details go to DEBUG");
        for (Level level : new Level[] { Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR }) {
            assertTrue(log.at(level).stream().noneMatch(event -> LogCapture.text(event).contains("wrong-pw-7")),
                    "the password is never logged, at " + level);
        }
    }

    @Test
    void probeFinding5AnEmptyPasswordIsRefusedWithoutRetriesOrNetwork() throws Exception {
        Properties patient = TestSupport.with(TestSupport.template(directory), LdapSettings.RETRIES, "10",
                LdapSettings.RETRY_INTERVAL_MS, "10000");
        List<Long> sleeps = new java.util.ArrayList<>();
        LoginFlow flow = TestSupport.flow(TestSupport.settings(patient), users,
                new RbacRoles(TestSupport.settings(patient), "none", () -> null), TestSupport.OFF, sleeps);
        assertRefused(flow.login("alice", "", false), Reason.EMPTY_PASSWORD);
        assertRefused(flow.login("alice", null, false), Reason.EMPTY_PASSWORD);
        assertEquals(List.of(), sleeps);
        assertEquals(List.of(), directory.drain(), "nothing reaches the directory");
        assertEquals(List.of(), log.at(Level.ERROR));
        assertEquals(2, log.at(Level.INFO).size(), "one line per refusal");
    }

    @Test
    void createdUsersGetTheirDetailsNoPasswordAndNoFirstLoginPrompt() throws Exception {
        LoginResult result = login("alice", "alice-pw");
        assertSignedInAs(result, "alice");
        User alice = users.byName("alice");
        assertEquals("Alice", alice.getFirstName());
        assertEquals("Smith", alice.getLastName());
        assertEquals("alice@example.com", alice.getEmail());
        assertEquals("Example Org", alice.getOrganization());
        assertEquals("false", users.preference(alice.getId(), AccountLinker.FIRST_LOGIN_PREFERENCE));
        String id = users.links.entryId(alice.getId());
        assertEquals(result.entryId(), id);
        assertTrue(id.matches("[0-9a-f-]{36}"), "an entryUUID: " + id);
        assertTrue(users.writes.stream().noneMatch(write -> write.contains("password")));
    }

    @Test
    void creatingUsersCanBeTurnedOff() throws Exception {
        Properties off = TestSupport.with(TestSupport.template(directory), LdapSettings.CREATE_USERS, "false");
        assertRefused(login(off, "alice", "alice-pw"), Reason.NO_LOCAL_ACCOUNT);
        assertEquals(List.of(), users.writes);
    }

    @Test
    void aNameLongerThanTheEngineHoldsIsRefusedWithTheLimitAndTheSetting() throws Exception {
        LoginResult result = login(TestDirectory.LONG_NAME, "long-pw");
        assertRefused(result, Reason.NAME_TOO_LONG);
        assertTrue(result.userMessage().contains("40") && result.userMessage().contains("username-attribute"), result.userMessage());
        assertEquals(List.of(), users.writes);
    }

    @Test
    void twoEngineAccountsDifferingOnlyInCaseAreRefusedWithBothIdsLogged() throws Exception {
        User lower = users.add("alice");
        User upper = users.add("Alice");
        assertRefused(login("alice", "alice-pw"), Reason.DUPLICATE_LOCAL);
        String line = LogCapture.text(log.at(Level.INFO).get(0));
        assertTrue(line.contains(String.valueOf(lower.getId())) && line.contains(String.valueOf(upper.getId())), line);
    }

    @Test
    void theGroupFilterDecidesWhoMaySignIn() throws Exception {
        assertRefused(login("bob", "bob-pw"), Reason.NOT_IN_GROUP);
        Properties anyone = TestSupport.with(TestSupport.template(directory), LdapSettings.GROUP_FILTER, "",
                LdapSettings.LOGIN_FILTER, "(objectClass=inetOrgPerson)");
        assertSignedInAs(login(anyone, "bob", "bob-pw"), "bob");
    }

    @Test
    void theEngineUsernameComesFromTheUsernameAttribute() throws Exception {
        Properties byMail = TestSupport.with(TestSupport.template(directory), LdapSettings.USERNAME_ATTRIBUTE, "mail");
        assertSignedInAs(login(byMail, "alice", "alice-pw"), "alice@example.com");
    }

    @Test
    void aReCreatedDirectoryUserWithTheSameNameIsRefused() throws Exception {
        try (TestDirectory own = TestDirectory.start()) {
            Properties settings = TestSupport.template(own);
            assertSignedInAs(login(settings, "alice", "alice-pw"), "alice");
            own.delete("uid=alice," + TestDirectory.PEOPLE);
            own.add("dn: uid=alice," + TestDirectory.PEOPLE, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice",
                    "sn: Again", "userPassword: new-pw");
            assertRefused(login(settings, "alice", "new-pw"), Reason.ENTRY_MISMATCH);
        }
    }

    @Test
    void theTypedNameOfAnotherEngineAccountIsRefused() throws Exception {
        // REST Basic sign-in looks the user up by the typed name, not the name the plugin returns.
        users.add("mary");
        users.add("mjones");
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "mary=mjones");
        assertRefused(login(linked, "mjones", "mary-pw"), Reason.OTHER_ACCOUNT_TYPED);
        assertSignedInAs(login(linked, "mary", "mary-pw"), "mary");
    }

    @Test
    void searchModeFindsTheUserThroughTheServiceAccount() throws Exception {
        Properties search = TestSupport.search(directory);
        assertSignedInAs(login(search, "alice", "alice-pw"), "alice");
        assertRefused(login(search, "alice", "wrong"), Reason.BIND_REFUSED);
        assertRefused(login(search, "*", "alice-pw"), Reason.UNKNOWN_USER);
        assertRefused(login(search, "alice)(uid=*", "alice-pw"), Reason.UNKNOWN_USER);
        assertTrue(directory.drain().stream().anyMatch(line -> line.contains("filter=\"(uid=\\2a)\"")), "escaped filter");
    }

    @Test
    void searchModeRefusesAWrongServicePassword() throws Exception {
        Properties search = TestSupport.search(directory);
        Properties wrong = TestSupport.with(search, LdapSettings.SERVICE_PASSWORD, TestSupport.sealFor(search, "not-it"));
        assertRefused(login(wrong, "alice", "alice-pw"), Reason.SERVICE_BIND_REFUSED);
    }

    @Test
    void aTestLoginCreatesAndRecordsNothing() throws Exception {
        LoginResult created = TestSupport.flow(TestSupport.template(directory), users).login("alice", "alice-pw", true);
        assertEquals(Outcome.SUCCESS, created.outcome(), () -> "steps: " + created.steps());
        assertTrue(created.steps().stream().anyMatch(step -> step.getDetail().startsWith("would create")), created.steps().toString());
        users.add("admin");
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "admin=admin");
        assertEquals(Outcome.SUCCESS, TestSupport.flow(linked, users).login("admin", "dir-admin-pw", true).outcome());
        assertEquals(List.of(), users.writes);
        assertEquals(List.of(), users.links.writes);
        assertEquals(List.of(), log.infoAndAbove());
    }

    @Test
    void withSeveralUsernameValuesTheOneSignedInWithIsUsed() throws Exception {
        try (TestDirectory own = TestDirectory.start()) {
            own.add("dn: uid=pat," + TestDirectory.PEOPLE, "objectClass: inetOrgPerson", "uid: pat", "uid: patricia", "cn: Pat",
                    "sn: P", "mail: pat@example.com", "userPassword: pat-pw");
            own.add("dn: cn=pats," + TestDirectory.GROUPS, "objectClass: groupOfUniqueNames", "cn: pats",
                    "uniqueMember: uid=pat," + TestDirectory.PEOPLE);
            Properties search = TestSupport.with(TestSupport.search(own), LdapSettings.GROUP_FILTER, "(&(cn=pats)(uniqueMember={dn}))");
            assertSignedInAs(login(search, "Patricia", "pat-pw"), "patricia");
            Properties byMail = TestSupport.with(search, LdapSettings.USER_SEARCH_FILTER, "(mail={username})");
            assertRefused(login(byMail, "pat@example.com", "pat-pw"), Reason.USERNAME_AMBIGUOUS);
        }
    }

    @Test
    void aDirectoryUsernameWithAControlCharacterIsRefused() throws Exception {
        try (TestDirectory own = TestDirectory.start()) {
            own.add("dn: uid=ctl," + TestDirectory.PEOPLE, "objectClass: inetOrgPerson", "uid: ctl", "cn: C", "sn: C",
                    "description: bad\u0007name", "userPassword: ctl-pw");
            own.add("dn: cn=ctls," + TestDirectory.GROUPS, "objectClass: groupOfUniqueNames", "cn: ctls",
                    "uniqueMember: uid=ctl," + TestDirectory.PEOPLE);
            Properties p = TestSupport.with(TestSupport.template(own), LdapSettings.USERNAME_ATTRIBUTE, "description",
                    LdapSettings.GROUP_FILTER, "(&(cn=ctls)(uniqueMember={dn}))");
            assertRefused(login(p, "ctl", "ctl-pw"), Reason.USERNAME_INVALID);
            assertEquals(List.of(), users.writes);
        }
    }

    @Test
    void theLoginFilterIsMatchedAgainstTheUsersOwnEntry() throws Exception {
        Properties members = TestSupport.with(TestSupport.template(directory), LdapSettings.GROUP_FILTER, "",
                LdapSettings.LOGIN_FILTER, "(&(objectClass=inetOrgPerson)(o=Example Org))");
        assertSignedInAs(login(members, "alice", "alice-pw"), "alice");
        Properties others = TestSupport.with(members, LdapSettings.LOGIN_FILTER, "(o=Other Org)");
        assertRefused(login(others, "bob", "bob-pw"), Reason.NOT_ALLOWED);
        Properties byName = TestSupport.with(members, LdapSettings.LOGIN_FILTER, "(uid={username})");
        assertSignedInAs(login(byName, "bob", "bob-pw"), "bob");
        List<String> seen = directory.drain();
        assertTrue(seen.stream().anyMatch(line -> line.contains("filter=\"(uid=bob)\"")), "base search on the entry: " + seen);
    }

    @Test
    void withBothFiltersSetBothMustPass() throws Exception {
        Properties both = TestSupport.with(TestSupport.template(directory), LdapSettings.LOGIN_FILTER, "(mail=*@example.com)");
        assertSignedInAs(login(both, "alice", "alice-pw"), "alice");
        assertRefused(login(both, "bob", "bob-pw"), Reason.NOT_IN_GROUP);
        Properties failingLogin = TestSupport.with(both, LdapSettings.LOGIN_FILTER, "(mail=*@elsewhere.example)");
        assertRefused(login(failingLogin, "alice", "alice-pw"), Reason.NOT_ALLOWED);
    }

    @Test
    void searchModeChecksTheLoginFilterOnTheServiceConnection() throws Exception {
        Properties search = TestSupport.with(TestSupport.search(directory), LdapSettings.GROUP_FILTER, "",
                LdapSettings.LOGIN_FILTER, "(o=Example Org)");
        assertSignedInAs(login(search, "bob", "bob-pw"), "bob");
        assertRefused(login(TestSupport.with(search, LdapSettings.LOGIN_FILTER, "(o=Nobody)"), "bob", "bob-pw"), Reason.NOT_ALLOWED);
    }
}
