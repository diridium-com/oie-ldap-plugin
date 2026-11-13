// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.diridium.ldap.LoginResult.Outcome;
import com.diridium.ldap.LoginResult.Reason;

/**
 * A directory shaped like Active Directory (binds by userPrincipalName, a
 * binary objectGUID, sAMAccountName, no entryUUID), on the in-memory server.
 * Samba's AD domain controller is measured separately in the end-to-end tests.
 */
class ActiveDirectoryLoginTest {

    private static TestDirectory directory;

    @BeforeAll
    static void start() throws Exception {
        directory = TestDirectory.startActiveDirectory();
    }

    @AfterAll
    static void stop() {
        directory.close();
    }

    private static Properties upn() {
        Properties p = new Properties();
        p.setProperty(LdapSettings.ENABLED, "true");
        p.setProperty(LdapSettings.URL, directory.url());
        p.setProperty(LdapSettings.USER_DN_TEMPLATE, "{username}@corp.example.com");
        p.setProperty(LdapSettings.USER_SEARCH_BASE, TestDirectory.PEOPLE);
        p.setProperty(LdapSettings.USERNAME_ATTRIBUTE, "sAMAccountName");
        p.setProperty(LdapSettings.GROUP_SEARCH_BASE, TestDirectory.GROUPS);
        p.setProperty(LdapSettings.GROUP_FILTER, "(&(objectClass=group)(member={dn}))");
        p.setProperty(LdapSettings.RETRIES, "0");
        p.setProperty(LdapSettings.CREATE_USERS, "true");
        p.setProperty(LdapSettings.ROLES_DEFAULT, "Viewer");
        return p;
    }

    private static LoginResult login(Properties p, StandInUsers users, String typed, String password) throws Exception {
        return TestSupport.flow(p, users).login(typed, password, false);
    }

    @Test
    void aUpnTemplateBindsAsThePrincipalAndFindsTheEntryByIt() throws Exception {
        StandInUsers users = new StandInUsers();
        LoginResult result = login(upn(), users, "alice", "alice-pw");
        assertEquals(Outcome.SUCCESS, result.outcome(), () -> result.reason() + ", steps: " + result.steps());
        assertEquals("alice", result.engineUsername());
        assertEquals("cn=alice," + TestDirectory.PEOPLE, result.dn());
    }

    @Test
    void theEntryIdFallsBackToObjectGuidAsHex() throws Exception {
        StandInUsers users = new StandInUsers();
        LoginResult result = login(upn(), users, "alice", "alice-pw");
        assertEquals("ff111111111111111111111111111111", result.entryId());
        assertEquals("ff111111111111111111111111111111",
                users.links.entryId(users.byName("alice").getId()));
    }

    @Test
    void aWrongPasswordAndANonMemberAreRefused() throws Exception {
        StandInUsers users = new StandInUsers();
        assertEquals(Reason.BIND_REFUSED, login(upn(), users, "alice", "wrong").reason());
        assertEquals(Reason.NOT_IN_GROUP, login(upn(), users, "bob", "bob-pw").reason());
    }

    @Test
    void theEntryMustCarryTheExactPrincipalThatWasBound() throws Exception {
        // Binds as alice@corp.example.com, then finds no entry under a base that doesn't hold it.
        Properties elsewhere = TestSupport.with(upn(), LdapSettings.USER_SEARCH_BASE, TestDirectory.GROUPS);
        assertEquals(Reason.ENTRY_NOT_FOUND, login(elsewhere, new StandInUsers(), "alice", "alice-pw").reason());
    }

    @Test
    void searchModeWorksWithSamAccountName() throws Exception {
        Properties search = TestSupport.with(upn(), LdapSettings.BIND_MODE, "search", LdapSettings.USER_DN_TEMPLATE, "",
                LdapSettings.SERVICE_DN, TestDirectory.SERVICE_DN, LdapSettings.USER_SEARCH_FILTER, "(sAMAccountName={username})");
        search.setProperty(LdapSettings.SERVICE_PASSWORD, TestSupport.sealFor(search, TestDirectory.SERVICE_PASSWORD));
        LoginResult result = login(search, new StandInUsers(), "alice", "alice-pw");
        assertEquals(Outcome.SUCCESS, result.outcome(), () -> result.reason() + ", steps: " + result.steps());
        assertEquals("alice", result.engineUsername());
    }

    private static Properties loginFilter(String filter) {
        return TestSupport.with(upn(), LdapSettings.GROUP_FILTER, "", LdapSettings.LOGIN_FILTER, filter);
    }

    @Test
    void aMemberOfLoginFilterLetsInOnlyMembers() throws Exception {
        Properties members = loginFilter("(memberOf=" + TestDirectory.AD_USERS_GROUP + ")");
        LoginResult alice = login(members, new StandInUsers(), "alice", "alice-pw");
        assertEquals(Outcome.SUCCESS, alice.outcome(), () -> alice.reason() + ", steps: " + alice.steps());
        assertEquals(Reason.NOT_ALLOWED, login(members, new StandInUsers(), "bob", "bob-pw").reason());
    }

    @Test
    void aFilterTheDirectoryCantEvaluateRefusesTheSignIn() throws Exception {
        // Active Directory's disabled-account test. The in-memory server answers
        // "does not support extensible-match filters"; the sign-in is refused, not let through.
        Properties enabledOnly = loginFilter("(!(userAccountControl:1.2.840.113556.1.4.803:=2))");
        LoginResult alice = login(enabledOnly, new StandInUsers(), "alice", "alice-pw");
        assertEquals(Reason.DIRECTORY_ERROR, alice.reason(), () -> "steps: " + alice.steps());
        assertTrue(alice.steps().toString().contains("extensible-match"), alice.steps().toString());
    }
}
