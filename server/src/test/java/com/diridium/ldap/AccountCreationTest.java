// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
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
 * Accounts are created only with Role-Based Access Control started and a default role
 * that exists and isn't the admin role, and a new account always gets a role.
 */
class AccountCreationTest {

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

    private LoginResult alice(Properties p, Runnable afterBuild) throws Exception {
        LoginFlow flow = TestSupport.flow(p, users);
        afterBuild.run();
        return flow.login("alice", "alice-pw", false);
    }

    @Test
    void aNewAccountGetsTheDefaultRole() throws Exception {
        LoginResult result = alice(TestSupport.template(directory), () -> { });
        assertEquals(Outcome.SUCCESS, result.outcome(), () -> "steps: " + result.steps());
        assertEquals(TestSupport.VIEWER, RbacRepository.instance.userRoles.get(users.byName("alice").getId()));
    }

    @Test
    void withoutRbacNoAccountIsCreated() throws Exception {
        LoginResult result = alice(TestSupport.template(directory), () -> RbacRepository.instance = null);
        assertEquals(Reason.CREATION_NOT_ALLOWED, result.reason(), () -> "steps: " + result.steps());
        assertEquals(List.of(), users.writes);
    }

    @Test
    void aDefaultRoleRbacDoesntHaveStopsCreation() throws Exception {
        Properties missing = TestSupport.with(TestSupport.template(directory), LdapSettings.ROLES_DEFAULT, "Missing");
        assertEquals(Reason.CREATION_NOT_ALLOWED, alice(missing, () -> { }).reason());
        assertEquals(List.of(), users.writes);
    }

    @Test
    void theAdminRoleAsTheDefaultStopsCreation() throws Exception {
        Properties admin = TestSupport.with(TestSupport.template(directory), LdapSettings.ROLES_DEFAULT, "Admin");
        assertEquals(Reason.CREATION_NOT_ALLOWED, alice(admin, () -> { }).reason());
        assertEquals(List.of(), users.writes);
    }

    @Test
    void aNewAccountWhoseRoleCantBeAssignedIsRefusedItsFirstSignIn() throws Exception {
        try (LogCapture log = new LogCapture()) {
            LoginResult result = alice(TestSupport.template(directory), () -> {
                RbacRepository failing = new RbacRepository() {
                    @Override
                    public void assignUserRole(int userId, int roleId) {
                        throw new IllegalStateException("database down");
                    }
                };
                failing.roles.putAll(RbacRepository.instance.roles);
                failing.adminRoleId = TestSupport.ADMIN;
                RbacRepository.instance = failing;
            });
            assertEquals(Reason.ROLE_NOT_ASSIGNED, result.reason(), () -> "steps: " + result.steps());
            assertNotNull(users.byName("alice"), "the account exists");
            assertTrue(log.at(Level.WARN).stream().anyMatch(e -> LogCapture.text(e).contains("got no role")));
        }
    }

    @Test
    void anExistingAccountSignsInWhenItsRoleCantBeChanged() throws Exception {
        assertEquals(Outcome.SUCCESS, alice(TestSupport.template(directory), () -> { }).outcome());
        LoginResult again = alice(TestSupport.with(TestSupport.template(directory), LdapSettings.ROLES_MAP, "mirth-admins=Admin"),
                () -> RbacRepository.instance.failure = new IllegalStateException("database down"));
        assertEquals(Outcome.SUCCESS, again.outcome(), () -> "steps: " + again.steps());
        assertTrue(again.role().startsWith("not assigned"), again.role());
    }
}
