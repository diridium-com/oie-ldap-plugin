// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.ldap.LoginResult.Outcome;
import com.diridium.ldap.LoginResult.Reason;
import com.diridium.rbac.RbacRepository;

/**
 * Accounts the plugin created sign in only while Role-Based Access Control is installed
 * and running; without it the engine lets every signed-in user do everything. Accounts
 * an administrator made and linked through linked-accounts aren't affected.
 */
class CreatedAccountsNeedRbacTest {

    private static TestDirectory directory;
    private StandInUsers users;

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
    }

    @AfterEach
    void tearDown() {
        RbacRepository.instance = null;
    }

    private LoginResult login(Properties p, String typed, String password, Runnable rbac) throws Exception {
        LoginFlow flow = TestSupport.flow(p, users);
        rbac.run();
        return flow.login(typed, password, false);
    }

    private void aliceIsCreated() throws Exception {
        assertEquals(Outcome.SUCCESS, login(TestSupport.template(directory), "alice", "alice-pw", () -> { }).outcome());
        assertTrue(users.links.created(users.byName("alice").getId()));
    }

    @Test
    void aCreatedAccountSignsInWhileRbacRuns() throws Exception {
        aliceIsCreated();
        assertEquals(Outcome.SUCCESS, login(TestSupport.template(directory), "alice", "alice-pw", () -> { }).outcome());
    }

    @Test
    void aCreatedAccountIsRefusedWhenRbacIsntInstalled() throws Exception {
        aliceIsCreated();
        LdapSettings settings = TestSupport.settings(TestSupport.template(directory));
        RbacRoles absent = new RbacRoles(settings, "com.diridium.rbac.NotInstalled", TestSupport.Authorization::new);
        try (LogCapture log = new LogCapture()) {
            LoginResult result = TestSupport.flow(settings, users, absent, TestSupport.OFF, new ArrayList<>())
                    .login("alice", "alice-pw", false);
            assertEquals(Reason.CREATED_NEEDS_RBAC, result.reason(), () -> "steps: " + result.steps());
            assertEquals(1, log.at(Level.INFO).stream().filter(e -> LogCapture.text(e).contains("Role-Based Access Control")).count());
        }
    }

    @Test
    void aCreatedAccountIsRefusedWhenRbacFailedToStart() throws Exception {
        aliceIsCreated();
        // rbac's getInstance() throws until it has started.
        LoginResult result = login(TestSupport.template(directory), "alice", "alice-pw", () -> RbacRepository.instance = null);
        assertEquals(Reason.CREATED_NEEDS_RBAC, result.reason(), () -> "steps: " + result.steps());
    }

    @Test
    void theOutageSettingDoesntLetACreatedAccountInWithoutRbac() throws Exception {
        aliceIsCreated();
        Properties outage = TestSupport.with(TestSupport.template(directory), LdapSettings.ENABLED, "false",
                LdapSettings.OUTAGE_LOCAL_PASSWORDS, "true");
        RbacRepository.instance = null;
        LoginResult result = TestSupport.offline(LdapSettings.parse(outage), users).login("alice", "any-pw", false);
        assertEquals(Reason.CREATED_NEEDS_RBAC, result.reason(), () -> "steps: " + result.steps());
    }

    @Test
    void typingTheDirectoryNameOfACreatedLinkedAccountIsCheckedToo() throws Exception {
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "mary=mjones");
        assertEquals("mary", login(linked, "mjones", "mary-pw", () -> { }).engineUsername(), "created under the engine name");
        LoginResult result = login(linked, "mjones", "mary-pw", () -> RbacRepository.instance = null);
        assertEquals(Reason.CREATED_NEEDS_RBAC, result.reason(), () -> "steps: " + result.steps());
    }

    @Test
    void aLinkedAccountAnAdministratorMadeSignsInWithOrWithoutRbac() throws Exception {
        users.add("admin");
        Properties linked = TestSupport.with(TestSupport.template(directory), LdapSettings.LINKED_ACCOUNTS, "admin=admin");
        assertEquals(Outcome.SUCCESS, login(linked, "admin", "dir-admin-pw", () -> { }).outcome());
        assertFalse(users.links.created(users.byName("admin").getId()));
        LoginResult without = login(linked, "admin", "dir-admin-pw", () -> RbacRepository.instance = null);
        assertEquals(Outcome.SUCCESS, without.outcome(), () -> without.reason() + ", steps: " + without.steps());
    }
}
