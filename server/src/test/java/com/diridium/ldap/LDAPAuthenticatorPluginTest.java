// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LDAPAuthenticatorPluginTest {

    @Test
    void escapesAsterisk() {
        assertEquals("\\2a", LDAPAuthenticatorPlugin.escapeFilterValue("*"));
    }

    @Test
    void escapesOpenParenthesis() {
        assertEquals("\\28", LDAPAuthenticatorPlugin.escapeFilterValue("("));
    }

    @Test
    void escapesCloseParenthesis() {
        assertEquals("\\29", LDAPAuthenticatorPlugin.escapeFilterValue(")"));
    }

    @Test
    void escapesBackslash() {
        assertEquals("\\5c", LDAPAuthenticatorPlugin.escapeFilterValue("\\"));
    }

    @Test
    void escapesNul() {
        assertEquals("\\00", LDAPAuthenticatorPlugin.escapeFilterValue("\u0000"));
    }

    @Test
    void escapesNonAsciiAsUtf8Bytes() {
        assertEquals("\\c3\\a9", LDAPAuthenticatorPlugin.escapeFilterValue("\u00e9"));
    }

    @Test
    void leavesPlainAsciiUnchanged() {
        assertEquals("jdoe.Smith-42", LDAPAuthenticatorPlugin.escapeFilterValue("jdoe.Smith-42"));
    }

    @Test
    void nullBecomesEmptyString() {
        assertEquals("", LDAPAuthenticatorPlugin.escapeFilterValue(null));
    }
}
