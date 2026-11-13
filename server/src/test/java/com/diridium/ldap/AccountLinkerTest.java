// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.Test;

import com.diridium.ldap.AccountLinker.Lookup;
import com.diridium.ldap.AccountLinker.Resolution;
import com.diridium.ldap.LoginResult.Reason;
import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.model.User;

/** The linking rules on their own, without a directory. */
class AccountLinkerTest {

    private final StandInUsers users = new StandInUsers();

    private AccountLinker linker(String... keysAndValues) {
        return linker(users, keysAndValues);
    }

    private static AccountLinker linker(StandInUsers users, String... keysAndValues) {
        Properties p = new Properties();
        p.setProperty(LdapSettings.URL, "ldap://localhost:1");
        p.setProperty(LdapSettings.USER_DN_TEMPLATE, "uid={username},ou=people,dc=example,dc=com");
        p.setProperty(LdapSettings.CREATE_USERS, "true");
        p.setProperty(LdapSettings.GROUP_FILTER, "(member={dn})");
        p.setProperty(LdapSettings.GROUP_SEARCH_BASE, "dc=example,dc=com");
        p.setProperty(LdapSettings.ROLES_DEFAULT, "Viewer");
        return new AccountLinker(TestSupport.settings(TestSupport.with(p, keysAndValues)), () -> users, users.links);
    }

    private Resolution resolve(AccountLinker linker, String typed, String directoryName, String entryId, boolean dryRun) {
        return linker.resolve(linker.lookup(typed), directoryName, entryId, dryRun);
    }

    private static DirectoryEntry entry(Map<String, List<String>> values) {
        return new DirectoryEntry("uid=alice,ou=people,dc=example,dc=com", values);
    }

    @Test
    void aRecordedEntryIdMatchesIgnoringCaseAndPadding() {
        User alice = users.add("alice");
        users.links.links.put(alice.getId(), " ABC-123 ");
        Resolution resolution = resolve(linker(), "alice", "alice", "abc-123", false);
        assertFalse(resolution.refused(), String.valueOf(resolution.refusal()));
        assertEquals("alice", resolution.username());
    }

    @Test
    void aDifferentEntryIdIsRefused() {
        User alice = users.add("alice");
        users.links.links.put(alice.getId(), "abc-123");
        assertEquals(Reason.ENTRY_MISMATCH, resolve(linker(), "alice", "alice", "def-456", false).refusal());
    }

    @Test
    void anUnlinkedAccountIsRefusedAndALinkedOneRecordedOnce() {
        User admin = users.add("Admin");
        assertEquals(Reason.NOT_LINKED, resolve(linker(), "admin", "admin", "id-1", false).refusal());
        AccountLinker linked = linker(LdapSettings.LINKED_ACCOUNTS, "ADMIN = Admin");
        assertFalse(resolve(linked, "admin", "admin", "id-1", false).refused());
        assertEquals("id-1", users.links.entryId(admin.getId()));
        assertFalse(users.links.created(admin.getId()), "an account linked through linked-accounts isn't marked");
        assertEquals(Reason.ENTRY_MISMATCH, resolve(linked, "admin", "admin", "id-2", false).refusal());
    }

    @Test
    void theEngineSignsInAsTheStoredNameNotTheTypedOne() {
        users.add("Alice");
        AccountLinker linked = linker(LdapSettings.LINKED_ACCOUNTS, "alice=alice");
        assertEquals("Alice", resolve(linked, "ALICE", "alice", "id-1", false).username());
    }

    @Test
    void anAccountToCreateIsOnlyPlannedAndADryRunRecordsNothing() {
        Resolution plan = resolve(linker(), "alice", "alice", "id-1", true);
        assertTrue(plan.toCreate());
        assertNull(plan.userId());
        users.add("admin");
        assertFalse(resolve(linker(LdapSettings.LINKED_ACCOUNTS, "admin=admin"), "admin", "admin", "id-2", true).refused());
        assertEquals(List.of(), users.writes);
        assertEquals(List.of(), users.links.writes);
    }

    @Test
    void creatingLinksTheAccountAndTurnsOffTheFirstLoginPrompt() {
        Resolution created = linker().create("alice", "id-1", entry(Map.of("givenname", List.of("Alice"))));
        assertFalse(created.refused());
        User alice = users.byName("alice");
        assertEquals("id-1", users.links.entryId(alice.getId()));
        assertTrue(users.links.created(alice.getId()), "marked as created by the plugin");
        assertEquals("false", users.preference(alice.getId(), AccountLinker.FIRST_LOGIN_PREFERENCE));
        assertEquals("Alice", alice.getFirstName());
    }

    @Test
    void directoryDetailsAreCutToTheEnginesColumnsWithOnlyADebugLine() {
        DirectoryEntry entry = entry(Map.of("givenname", List.of("g".repeat(41)), "sn", List.of("s".repeat(60)),
                "mail", List.of("m".repeat(256)), "o", List.of("o".repeat(300))));
        try (LogCapture log = new LogCapture()) {
            assertFalse(linker(LdapSettings.ORGANIZATION_ATTRIBUTE, "o").create("alice", "id-1", entry).refused());
            User alice = users.byName("alice");
            assertEquals("g".repeat(40), alice.getFirstName());
            assertEquals("s".repeat(40), alice.getLastName());
            assertEquals("m".repeat(255), alice.getEmail());
            assertEquals("o".repeat(255), alice.getOrganization());
            assertEquals(4, log.at(Level.DEBUG).stream().filter(e -> LogCapture.text(e).startsWith("Cut the directory's")).count());
            assertTrue(log.infoAndAbove().stream().noneMatch(e -> LogCapture.text(e).startsWith("Cut")));
        }
    }

    @Test
    void aDisplayValueStartingWithHtmlIsDropped() {
        try (LogCapture log = new LogCapture()) {
            linker().create("alice", "id-1", entry(Map.of("givenname", List.of(" <HTML><b>Alice</b>"), "sn", List.of("Smith"))));
            User alice = users.byName("alice");
            assertNull(alice.getFirstName());
            assertEquals("Smith", alice.getLastName());
            assertEquals(1, log.at(Level.DEBUG).stream().filter(e -> LogCapture.text(e).contains("<html")).count());
        }
    }

    @Test
    void localOnlyIsDecidedOnTheAccountTheEngineFinds() {
        users.add("Admin");
        AccountLinker linker = linker(LdapSettings.LOCAL_ONLY_USERNAMES, "admin");
        assertTrue(linker.isLocalOnly(linker.lookup("ADMIN"), "ADMIN"));
        assertTrue(linker.isLocalOnly(linker.lookup("nobody-but-admin"), " admin "));
        assertFalse(linker.isLocalOnly(linker.lookup("alice"), "alice"));
    }

    @Test
    void directoryAccountsAreLinkedOrNamedInLinkedAccounts() {
        AccountLinker linked = linker(LdapSettings.LINKED_ACCOUNTS, "mary=mjones");
        assertTrue(linked.isDirectoryAccount(linked.lookup("MARY"), "MARY"));
        assertTrue(linked.isDirectoryAccount(linked.lookup(" mjones "), " mjones "));
        User created = users.add("alice");
        users.links.links.put(created.getId(), "id-1");
        assertTrue(linked.isDirectoryAccount(linked.lookup("Alice"), "Alice"));
        users.add("ops");
        assertFalse(linked.isDirectoryAccount(linked.lookup("ops"), "ops"));
        assertFalse(linked.isDirectoryAccount(linked.lookup("nobody"), "nobody"));
        assertTrue(linked.isDirectoryAccount(new Lookup(null, true), "ops"), "an account that can't be read counts as one");
    }

    @Test
    void whenTheEngineAccountsCantBeReadTheSignInIsRefused() {
        StandInUsers broken = new StandInUsers() {
            @Override
            public List<User> getAllUsers() {
                throw new IllegalStateException("database down");
            }
        };
        AccountLinker linker = linker(broken);
        assertEquals(Reason.ACCOUNT_ERROR, linker.resolve(linker.lookup("alice"), "alice", "id-1", false).refusal());
        assertEquals(Reason.ACCOUNT_ERROR, linker.resolve(new Lookup(null, true), "alice", "id-1", false).refusal());
    }

    @Test
    void aCreateThatCantBeReadBackIsAnAccountError() {
        StandInUsers forgetful = new StandInUsers() {
            @Override
            public void updateUser(User user) throws ControllerException {
                writes.add("insert lost");
            }
        };
        assertEquals(Reason.ACCOUNT_ERROR, linker(forgetful).create("alice", "id-1", entry(Map.of())).refusal());
        assertEquals(List.of(), forgetful.links.writes);
    }

    @Test
    void directoryValuesInTheRefusalDetailAreEscaped() {
        User alice = users.add("alice");
        users.links.links.put(alice.getId(), "abc\n123");
        Resolution refused = resolve(linker(), "alice", "alice", "def\r456", false);
        assertEquals(Reason.ENTRY_MISMATCH, refused.refusal());
        assertTrue(refused.detail().contains("abc\\x0a123") && refused.detail().contains("def\\x0d456"), refused.detail());
        assertFalse(refused.detail().contains("\n") || refused.detail().indexOf(10) >= 0 || refused.detail().indexOf(13) >= 0);
    }
}
