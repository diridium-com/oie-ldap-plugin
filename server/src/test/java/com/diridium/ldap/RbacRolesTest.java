// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.TestSupport.ADMIN;
import static com.diridium.ldap.TestSupport.OPERATOR;
import static com.diridium.ldap.TestSupport.VIEWER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.rbac.RbacRepository;

/**
 * Role assignment through the stand-in for rbac's repository (the real class's
 * name and signatures, reached by reflection as in production).
 */
class RbacRolesTest {

    private static final String OPS_DN = "cn=Night Ops,ou=groups,dc=example,dc=com";

    private final TestSupport.Authorization authorization = new TestSupport.Authorization();
    private RbacRepository repository;

    @BeforeEach
    void installRbac() {
        repository = TestSupport.standardRbac();
    }

    @AfterEach
    void removeRbac() {
        RbacRepository.instance = null;
    }

    private static LdapSettings settings(String... keysAndValues) {
        Properties p = new Properties();
        p.setProperty(LdapSettings.URL, "ldap://localhost:1");
        p.setProperty(LdapSettings.USER_DN_TEMPLATE, "uid={username},dc=x");
        p.setProperty(LdapSettings.GROUP_SEARCH_BASE, "ou=groups,dc=example,dc=com");
        p.setProperty(LdapSettings.GROUP_FILTER, "(member={dn})");
        p.setProperty(LdapSettings.ROLES_MAP, "Night Ops=Operator, mirth-admins=Admin");
        p.setProperty(LdapSettings.ROLES_DEFAULT, "Viewer");
        return TestSupport.settings(TestSupport.with(p, keysAndValues));
    }

    private RbacRoles roles(String... keysAndValues) {
        return new RbacRoles(settings(keysAndValues), RbacRoles.REPOSITORY_CLASS, () -> authorization);
    }

    private static DirectoryGroup group(String dn, String... names) {
        Set<String> normalized = new LinkedHashSet<>();
        for (String name : names) {
            normalized.add(LdapSettings.normalize(name));
        }
        return new DirectoryGroup(DirectoryGroup.normalizeDn(dn), Collections.unmodifiableSet(normalized));
    }

    private static List<DirectoryGroup> nightOps() {
        return List.of(group(OPS_DN, "Night Ops"));
    }

    @Test
    void theFirstMatchingMappingWinsInTheOrderListedIgnoringCaseAndPadding() {
        assertEquals("Operator", roles().roleFor(List.of(group("cn=mirth-admins,dc=x", "MIRTH-ADMINS"), group("cn=n,dc=x", " night ops "))));
        assertEquals("Admin", roles().roleFor(List.of(group("cn=mirth-admins,dc=x", "mirth-admins"))));
    }

    @Test
    void aKeyWithAnEqualsSignIsAGroupDnAndMatchesOnlyThatGroup() {
        RbacRoles byDn = roles(LdapSettings.ROLES_MAP, "CN=Night Ops\\,OU=Groups\\,DC=Example\\,DC=com=Operator");
        assertEquals("Operator", byDn.roleFor(nightOps()));
        assertEquals("Viewer", byDn.roleFor(List.of(group("cn=Night Ops,ou=elsewhere,dc=example,dc=com", "Night Ops"))));
    }

    @Test
    void someoneInNoMappedGroupGetsTheDefault() {
        assertEquals("Viewer", roles().roleFor(List.of(group("cn=other,dc=x", "other"))));
        repository.userRoles.put(7, OPERATOR);
        assertEquals("Viewer", roles().apply(7, List.of(), false));
        assertEquals(VIEWER, repository.userRoles.get(7));
    }

    @Test
    void theRoleIsAssignedAndTheUsersCachedPermissionsDropped() {
        assertEquals("Operator", roles().apply(7, nightOps(), false));
        assertEquals(List.of("7->" + OPERATOR), repository.assignments);
        assertEquals(List.of(7), authorization.invalidated);
    }

    @Test
    void anAlreadyAssignedRoleIsLeftAlone() {
        repository.userRoles.put(7, OPERATOR);
        roles().apply(7, nightOps(), false);
        assertEquals(List.of(), repository.assignments);
    }

    @Test
    void theLastAdminIsNeverMovedOffTheAdminRole() {
        repository.userRoles.put(7, ADMIN);
        String what = roles().apply(7, nightOps(), false);
        assertTrue(what.contains("last user with the admin role"), what);
        assertEquals(List.of(), repository.assignments);
        roles().apply(7, List.of(), false);
        assertEquals(ADMIN, repository.userRoles.get(7), "leaving every mapped group doesn't demote the last admin either");
    }

    @Test
    void anAdminIsMovedWhenAnotherAdminRemains() {
        repository.userRoles.put(7, ADMIN);
        repository.userRoles.put(8, ADMIN);
        roles().apply(7, nightOps(), false);
        assertEquals(List.of("7->" + OPERATOR), repository.assignments);
    }

    @Test
    void twoSignInsAtOnceNeverLeaveTheEngineWithoutAnAdmin() throws Exception {
        CyclicBarrier bothCounted = new CyclicBarrier(2);
        RbacRepository racing = new RbacRepository() {
            @Override
            public int countUsersByRoleId(int roleId) {
                int count = super.countUsersByRoleId(roleId);
                try {
                    // Without the plugin's lock both sign-ins count two admins here, then both move.
                    bothCounted.await(300, TimeUnit.MILLISECONDS);
                } catch (InterruptedException | BrokenBarrierException | TimeoutException e) {
                    // the other sign-in is waiting for the lock
                }
                return count;
            }
        };
        racing.roles.putAll(repository.roles);
        racing.adminRoleId = ADMIN;
        racing.userRoles.put(7, ADMIN);
        racing.userRoles.put(8, ADMIN);
        RbacRepository.instance = racing;
        RbacRoles roles = roles();
        List<String> results = Collections.synchronizedList(new ArrayList<>());
        Thread a = new Thread(() -> results.add(roles.apply(7, nightOps(), false)));
        Thread b = new Thread(() -> results.add(roles.apply(8, nightOps(), false)));
        a.start();
        b.start();
        a.join();
        b.join();
        assertEquals(1, racing.userRoles.values().stream().filter(role -> role == ADMIN).count(), results.toString());
    }

    @Test
    void anAdminLeftWithoutAnotherAfterTheMoveGetsTheAdminRoleBack() {
        RbacRepository meanwhile = new RbacRepository() {
            @Override
            public void assignUserRole(int userId, int roleId) {
                super.assignUserRole(userId, roleId);
                if (userId == 7 && roleId == OPERATOR) {
                    userRoles.put(8, OPERATOR); // someone else demotes the other admin at the same moment
                }
            }
        };
        meanwhile.roles.putAll(repository.roles);
        meanwhile.adminRoleId = ADMIN;
        meanwhile.userRoles.put(7, ADMIN);
        meanwhile.userRoles.put(8, ADMIN);
        RbacRepository.instance = meanwhile;
        try (LogCapture log = new LogCapture()) {
            String what = roles().apply(7, nightOps(), false);
            assertTrue(what.contains("admin role"), what);
            assertEquals(ADMIN, meanwhile.userRoles.get(7));
            assertTrue(log.at(org.apache.logging.log4j.Level.WARN).stream()
                    .anyMatch(e -> LogCapture.text(e).contains("the admin role was given back")));
        }
    }

    @Test
    void jitOnlyAndNeverLeaveExistingAccountsAlone() {
        assertTrue(roles(LdapSettings.ROLES_SYNC, "jit-only").apply(7, nightOps(), false).startsWith("left as it is"));
        assertTrue(roles(LdapSettings.ROLES_SYNC, "never").apply(7, nightOps(), false).startsWith("left as it is"));
        assertEquals(List.of(), repository.assignments);
    }

    @Test
    void theAdminRoleIsNeverGivenAsTheDefault() {
        RbacRoles adminDefault = roles(LdapSettings.ROLES_DEFAULT, "Admin");
        assertTrue(adminDefault.defaultRoleProblem().contains("admin role"));
        assertTrue(adminDefault.creationProblem().contains("admin role"));
        assertTrue(adminDefault.apply(7, List.of(), false).startsWith("left as it is"));
        assertNull(adminDefault.assignNew(7, List.of(), false));
        assertEquals(List.of(), repository.assignments);
        assertEquals("Admin", adminDefault.apply(7, List.of(group("cn=a,dc=x", "mirth-admins")), false), "a mapped group may give it");
    }

    @Test
    void creatingAccountsNeedsRbacAndAnExistingDefaultRole() {
        assertNull(roles().creationProblem());
        assertTrue(roles(LdapSettings.ROLES_DEFAULT, "Missing").creationProblem().contains("names no"));
        RbacRepository.instance = null;
        assertTrue(roles().creationProblem().contains("not installed or not started"));
        RbacRoles absent = new RbacRoles(settings(), "com.diridium.rbac.NotInstalled", () -> authorization);
        assertTrue(absent.creationProblem().contains("not installed or not started"));
    }

    @Test
    void aNewAccountGetsTheMappedRoleOrTheDefault() {
        assertEquals("Operator", roles().assignNew(7, nightOps(), false));
        assertEquals("Viewer", roles().assignNew(8, List.of(), false));
        assertEquals("Viewer", roles(LdapSettings.ROLES_SYNC, "never").assignNew(9, nightOps(), false));
        assertEquals(List.of("7->" + OPERATOR, "8->" + VIEWER, "9->" + VIEWER), repository.assignments);
    }

    @Test
    void aNewAccountWhoseRoleCantBeAssignedGetsNull() {
        repository.failure = new IllegalStateException("database down");
        assertNull(roles().assignNew(7, nightOps(), false));
    }

    @Test
    void aFailureInsideRbacNeverReachesAnExistingAccountsSignIn() {
        repository.failure = new IllegalStateException("database down");
        assertTrue(roles().apply(7, nightOps(), false).startsWith("not assigned"));
    }

    @Test
    void aControllerWithoutTheCacheMethodStillGetsTheRole() {
        RbacRoles roles = new RbacRoles(settings(), RbacRoles.REPOSITORY_CLASS, Object::new);
        assertEquals("Operator", roles.apply(7, nightOps(), false));
    }

    @Test
    void aDryRunSaysWhatItWouldDoAndAssignsNothing() {
        assertEquals("would assign Operator", roles().apply(7, nightOps(), true));
        assertEquals("would assign Operator", roles().assignNew(null, nightOps(), true));
        assertEquals(List.of(), repository.assignments);
        assertEquals(List.of(), authorization.invalidated);
    }

    @Test
    void aSignInGetsTheRoleItsDirectoryGroupsMapTo() throws Exception {
        try (TestDirectory directory = TestDirectory.start()) {
            Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.ROLES_MAP,
                    "cn=mirth-admins\\," + TestDirectory.GROUPS.replace(",", "\\,") + "=Admin");
            LdapSettings settings = TestSupport.settings(p);
            StandInUsers users = new StandInUsers();
            RbacRoles roles = new RbacRoles(settings, RbacRoles.REPOSITORY_CLASS, () -> authorization);
            LoginResult alice = TestSupport.flow(settings, users, roles, TestSupport.OFF, new ArrayList<>()).login("alice", "alice-pw", false);
            assertEquals(LoginResult.Outcome.SUCCESS, alice.outcome(), () -> "steps: " + alice.steps());
            assertEquals("Admin", alice.role());
            assertTrue(alice.groups().stream().anyMatch(dn -> dn.startsWith("cn=mirth-admins")), alice.groups().toString());
            LoginResult mary = TestSupport.flow(settings, users, roles, TestSupport.OFF, new ArrayList<>()).login("mjones", "mary-pw", false);
            assertEquals("Viewer", mary.role());
            int aliceId = users.byName("alice").getId();
            int maryId = users.byName("mjones").getId();
            assertEquals(List.of(aliceId + "->" + ADMIN, maryId + "->" + VIEWER), repository.assignments);
        }
    }
}
