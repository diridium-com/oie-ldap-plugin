// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.ldap.LoginResult.Outcome;
import com.diridium.ldap.LoginResult.Reason;

/**
 * When the engine's own password check answers instead: the kill switch, the
 * local-only list, and the fallback, which covers only names the directory
 * doesn't know. Accounts the plugin created or linked never fall back.
 * Retries happen only when the connection fails.
 */
class LoginFallbackTest {

    private static TestDirectory directory;
    private static String closedUrl;
    private StandInUsers users;
    private final List<Long> sleeps = new ArrayList<>();

    @BeforeAll
    static void start() throws Exception {
        directory = TestDirectory.start();
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            closedUrl = "ldap://localhost:" + socket.getLocalPort();
        }
    }

    @AfterAll
    static void stop() {
        directory.close();
    }

    @BeforeEach
    void setUp() {
        users = new StandInUsers();
        sleeps.clear();
        directory.drain();
    }

    private LoginResult login(Properties p, KillSwitch killSwitch, String typed, String password) throws Exception {
        LdapSettings settings = TestSupport.settings(p);
        TestSupport.standardRbac();
        return TestSupport.flow(settings, users, TestSupport.roles(settings), killSwitch, sleeps).login(typed, password, false);
    }

    private LoginResult offline(Properties p, String typed) {
        return TestSupport.offline(LdapSettings.parse(p), users).login(typed, "any-pw", false);
    }

    /** Alice signs in once, so her engine account is created and linked. */
    private void aliceIsADirectoryAccount() throws Exception {
        assertEquals(Outcome.SUCCESS, login(TestSupport.template(directory), "alice", "alice-pw").outcome());
    }

    private LoginResult login(Properties p, String typed, String password) throws Exception {
        return login(p, TestSupport.OFF, typed, password);
    }

    private static void assertOutcome(LoginResult result, Outcome outcome, Reason reason) {
        assertEquals(outcome, result.outcome(), () -> result.reason() + ", steps: " + result.steps());
        assertEquals(reason, result.reason(), () -> "steps: " + result.steps());
    }

    @Test
    void theKillSwitchHandsEveryNameToTheEngineWithoutAskingTheDirectory() throws Exception {
        KillSwitch environment = TestSupport.environment(KillSwitch.ENVIRONMENT_VARIABLE, "true");
        assertOutcome(login(TestSupport.template(directory), environment, "alice", "alice-pw"), Outcome.LOCAL, Reason.KILL_SWITCH);
        KillSwitch property = new KillSwitch(name -> null, name -> name.equals(KillSwitch.SYSTEM_PROPERTY) ? "TRUE" : null);
        assertOutcome(login(TestSupport.template(directory), property, "bob", "x"), Outcome.LOCAL, Reason.KILL_SWITCH);
        assertEquals(List.of(), directory.drain());
    }

    @Test
    void theKillSwitchIsOffUnlessSetToTrue() {
        assertEquals(false, TestSupport.environment(KillSwitch.ENVIRONMENT_VARIABLE, "yes").isOn());
        assertEquals(false, TestSupport.environment(KillSwitch.ENVIRONMENT_VARIABLE, "").isOn());
        assertEquals(false, TestSupport.OFF.isOn());
        assertEquals(true, TestSupport.environment(KillSwitch.ENVIRONMENT_VARIABLE, " true ").isOn());
    }

    @Test
    void localOnlyNamesSkipTheDirectoryWhateverTheCaseOrPadding() throws Exception {
        Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.LOCAL_ONLY_USERNAMES, "admin, ops");
        for (String typed : new String[] { "admin", "ADMIN", " admin", "Admin ", "OPS" }) {
            assertOutcome(login(p, typed, "dir-admin-pw"), Outcome.LOCAL, Reason.LOCAL_ONLY);
        }
        assertEquals(List.of(), directory.drain());
    }

    @Test
    void localOnlyNamesStillWorkWhenTheDirectoryIsDown() throws Exception {
        Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.URL, closedUrl,
                LdapSettings.LOCAL_ONLY_USERNAMES, "admin");
        assertOutcome(login(p, "admin", "anything"), Outcome.LOCAL, Reason.LOCAL_ONLY);
    }

    @Test
    void withoutTheFallbackANameTheDirectoryDoesNotKnowIsRefused() throws Exception {
        users.add("localbob");
        assertOutcome(login(TestSupport.search(directory), "localbob", "pw"), Outcome.REFUSED, Reason.UNKNOWN_USER);
    }

    @Test
    void theFallbackCoversANameTheDirectoryDoesNotKnow() throws Exception {
        users.add("localbob");
        Properties search = TestSupport.with(TestSupport.search(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertOutcome(login(search, "localbob", "pw"), Outcome.LOCAL, Reason.FALLBACK);
        Properties template = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertOutcome(login(template, "localbob", "pw"), Outcome.LOCAL, Reason.FALLBACK);
    }

    @Test
    void theFallbackNeverCoversANameTheDirectoryKnows() throws Exception {
        Properties search = TestSupport.with(TestSupport.search(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertOutcome(login(search, "alice", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
    }

    @Test
    void anAccountThePluginCreatedNeverFallsBack() throws Exception {
        Properties template = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertEquals(Outcome.SUCCESS, login(template, "alice", "alice-pw").outcome());
        assertOutcome(login(template, "alice", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
        assertOutcome(login(template, "ALICE", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
        // The engine finds no account under " ALICE " (a leading space counts), so the decision is on
        // no account at all, and the engine's own check then finds nothing to sign in to.
        assertOutcome(login(template, " ALICE ", "wrong"), Outcome.LOCAL, Reason.FALLBACK);
    }

    @Test
    void eitherNameOfALinkedAccountNeverFallsBack() throws Exception {
        users.add("mary");
        Properties template = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true",
                LdapSettings.LINKED_ACCOUNTS, "mary=mjones");
        assertOutcome(login(template, "mary", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
        assertOutcome(login(template, "mjones", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
    }

    @Test
    void whenTheDirectoryIsDownLinkedAccountsAreRefusedAndOthersMayFallBack() throws Exception {
        Properties up = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertEquals(Outcome.SUCCESS, login(up, "alice", "alice-pw").outcome());
        users.add("ops");
        Properties down = TestSupport.with(up, LdapSettings.URL, closedUrl);
        assertOutcome(login(down, "alice", "alice-pw"), Outcome.REFUSED, Reason.UNREACHABLE);
        assertOutcome(login(down, "ops", "pw"), Outcome.LOCAL, Reason.FALLBACK);
        Properties noFallback = TestSupport.with(down, LdapSettings.FALLBACK_TO_LOCAL, "false");
        assertOutcome(login(noFallback, "ops", "pw"), Outcome.REFUSED, Reason.UNREACHABLE);
    }

    @Test
    void aConnectionFailureIsRetriedWithThePauseBetween() throws Exception {
        Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.URL, closedUrl,
                LdapSettings.RETRIES, "2", LdapSettings.RETRY_INTERVAL_MS, "750");
        assertOutcome(login(p, "alice", "alice-pw"), Outcome.REFUSED, Reason.UNREACHABLE);
        assertEquals(List.of(750L, 750L), sleeps);
    }

    @Test
    void aRefusedPasswordIsNeverRetried() throws Exception {
        Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.RETRIES, "5", LdapSettings.RETRY_INTERVAL_MS, "750");
        assertOutcome(login(p, "alice", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
        assertEquals(List.of(), sleeps);
        assertEquals(1, directory.drain().stream().filter(line -> line.startsWith("BIND REQUEST")).count());
    }

    @Test
    void aDirectoryErrorFromBadSettingsIsNeverRetried() throws Exception {
        Properties p = TestSupport.with(TestSupport.search(directory), LdapSettings.USER_SEARCH_BASE, "ou=missing," + TestDirectory.BASE,
                LdapSettings.RETRIES, "5", LdapSettings.RETRY_INTERVAL_MS, "750");
        assertOutcome(login(p, "alice", "alice-pw"), Outcome.REFUSED, Reason.DIRECTORY_ERROR);
        assertEquals(List.of(), sleeps);
    }

    @Test
    void aServerThatNeverAnswersIsNotAskedAgain() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))) {
            List<java.net.Socket> held = new ArrayList<>();
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        held.add(silent.accept());
                    }
                } catch (Exception closed) {
                    // the test is over
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.URL, "ldap://localhost:" + silent.getLocalPort(),
                    LdapSettings.CONNECT_TIMEOUT_MS, "300", LdapSettings.RETRIES, "3", LdapSettings.RETRY_INTERVAL_MS, "750");
            assertOutcome(login(p, "alice", "alice-pw"), Outcome.REFUSED, Reason.UNREACHABLE);
            assertEquals(List.of(), sleeps, "the bind may have reached the directory, so it isn't sent again");
            for (java.net.Socket socket : held) {
                socket.close();
            }
        }
    }

    @Test
    void withLdapOffADirectoryAccountIsRefusedAndOthersUseTheirEnginePassword() throws Exception {
        aliceIsADirectoryAccount();
        users.add("ops");
        Properties off = TestSupport.with(TestSupport.template(directory), LdapSettings.ENABLED, "false");
        assertOutcome(offline(off, "alice"), Outcome.REFUSED, Reason.DIRECTORY_OFF);
        assertOutcome(offline(off, "ALICE"), Outcome.REFUSED, Reason.DIRECTORY_OFF);
        assertOutcome(offline(off, "ops"), Outcome.LOCAL, Reason.TURNED_OFF);
        assertOutcome(offline(off, "nobody"), Outcome.LOCAL, Reason.TURNED_OFF);
        Properties localOnly = TestSupport.with(off, LdapSettings.LOCAL_ONLY_USERNAMES, "alice");
        assertOutcome(offline(localOnly, "alice"), Outcome.LOCAL, Reason.LOCAL_ONLY);
    }

    @Test
    void withSettingsThatHaveAProblemADirectoryAccountIsRefused() throws Exception {
        aliceIsADirectoryAccount();
        users.add("ops");
        Properties broken = TestSupport.with(TestSupport.template(directory), LdapSettings.URL, "http://wrong");
        assertOutcome(offline(broken, "alice"), Outcome.REFUSED, Reason.DIRECTORY_OFF);
        assertOutcome(offline(broken, "ops"), Outcome.LOCAL, Reason.INVALID_SETTINGS);
    }

    @Test
    void theOutageSettingLetsDirectoryAccountsUseTheirEnginePasswordWhileTheDirectoryCantBeUsed() throws Exception {
        aliceIsADirectoryAccount();
        Properties outage = TestSupport.with(TestSupport.template(directory), LdapSettings.OUTAGE_LOCAL_PASSWORDS, "true");
        assertOutcome(offline(TestSupport.with(outage, LdapSettings.ENABLED, "false"), "alice"), Outcome.LOCAL, Reason.OUTAGE);
        assertOutcome(offline(TestSupport.with(outage, LdapSettings.URL, "http://wrong"), "alice"), Outcome.LOCAL, Reason.OUTAGE);
        assertOutcome(login(TestSupport.with(outage, LdapSettings.URL, closedUrl), "alice", "x"), Outcome.LOCAL, Reason.OUTAGE);
    }

    @Test
    void theOutageSettingNeverCoversAWrongPassword() throws Exception {
        aliceIsADirectoryAccount();
        Properties both = TestSupport.with(TestSupport.template(directory), LdapSettings.OUTAGE_LOCAL_PASSWORDS, "true",
                LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertOutcome(login(both, "alice", "wrong"), Outcome.REFUSED, Reason.BIND_REFUSED);
    }

    @Test
    void unicodeWhitespaceCantSlipPastTheLocalOnlyList() throws Exception {
        Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.LOCAL_ONLY_USERNAMES, "admin");
        for (String typed : new String[] { "admin\u3000", "\u00a0admin", "admin\u2007", "\u202fADMIN" }) {
            assertOutcome(login(p, typed, "dir-admin-pw"), Outcome.LOCAL, Reason.LOCAL_ONLY);
        }
        assertEquals(List.of(), directory.drain());
    }

    @Test
    void theDecisionUsesTheAccountTheDatabaseFinds() throws Exception {
        // MySQL's default collation ignores accents: "alic\u00e9" finds alice. The decision must follow it.
        StandInUsers accentBlind = new StandInUsers() {
            @Override
            public com.mirth.connect.model.User getUser(Integer userId, String userName) throws com.mirth.connect.client.core.ControllerException {
                return super.getUser(userId, userName == null ? null
                        : java.text.Normalizer.normalize(userName, java.text.Normalizer.Form.NFD).replaceAll("\\p{M}", ""));
            }
        };
        users = accentBlind;
        aliceIsADirectoryAccount();
        Properties fallback = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        assertOutcome(login(fallback, "alic\u00e9", "alice-old-local-pw"), Outcome.REFUSED, Reason.BIND_REFUSED);
    }

    @Test
    void whenTheEngineAccountCantBeReadTheFallbackRefuses() throws Exception {
        users = new StandInUsers() {
            @Override
            public com.mirth.connect.model.User getUser(Integer userId, String userName) throws com.mirth.connect.client.core.ControllerException {
                throw new com.mirth.connect.client.core.ControllerException("database down");
            }
        };
        Properties fallback = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        LoginResult result = login(fallback, "ops", "wrong");
        assertOutcome(result, Outcome.REFUSED, Reason.BIND_REFUSED);
        assertTrue(result.steps().stream().anyMatch(step -> step.getName().equals("Fallback") && !step.isPassed()), result.steps().toString());
    }
}
