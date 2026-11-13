// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.junit.jupiter.api.Test;

class LdapEscapingTest {

    @Test
    void dnValueEscapesTheRfc4514Specials() {
        assertEquals("a\\,b\\+c\\\"d\\\\e\\<f\\>g\\;h\\=i", LdapEscaping.dnValue("a,b+c\"d\\e<f>g;h=i"));
    }

    @Test
    void dnValueEscapesLeadingSpaceOrHashAndTrailingSpace() {
        assertEquals("\\ alice", LdapEscaping.dnValue(" alice"));
        assertEquals("alice\\ ", LdapEscaping.dnValue("alice "));
        assertEquals("\\#alice", LdapEscaping.dnValue("#alice"));
        assertEquals("a#b c", LdapEscaping.dnValue("a#b c"));
        assertEquals("\\ ", LdapEscaping.dnValue(" "));
    }

    @Test
    void dnValueWritesNulAndControlCharactersAsHex() {
        assertEquals("a\\00b\\0ac", LdapEscaping.dnValue("a\u0000b\nc"));
    }

    @Test
    void dnValueLeavesNonAsciiAsIs() {
        assertEquals("jos\u00e9", LdapEscaping.dnValue("jos\u00e9"));
    }

    @Test
    void anEscapedValueParsesBackAsOneAttributeValue() throws Exception {
        for (String typed : new String[] { "eve,ou=contractors", "carol+cn=Carol", " alice ", "#x", "a\\b", "a\"b;c<d>" }) {
            LdapName dn = new LdapName("uid=" + LdapEscaping.dnValue(typed) + ",ou=people,dc=example,dc=com");
            assertEquals(4, dn.size(), typed);
            Rdn rdn = dn.getRdn(3);
            assertEquals(1, rdn.size(), typed);
            assertEquals(typed, rdn.getValue(), typed);
        }
    }

    @Test
    void filterValueEscapesTheRfc4515Specials() {
        assertEquals("\\2a\\28\\29\\5c\\00", LdapEscaping.filterValue("*()\\\u0000"));
    }

    @Test
    void filterValueLeavesDnCharactersAndNonAsciiAlone() {
        assertEquals("uid=a,ou=b+c", LdapEscaping.filterValue("uid=a,ou=b+c"));
        assertEquals("jos\u00e9", LdapEscaping.filterValue("jos\u00e9"));
    }

    @Test
    void filterValueWritesControlCharactersAsHex() {
        assertEquals("a\\0ab\\7f", LdapEscaping.filterValue("a\nb\u007f"));
    }

    @Test
    void placeholdersAreFilledInOnePass() {
        assertEquals("(|(uid=x{dn})(member=cn=a))", Placeholders.fill("(|(uid={username})(member={dn}))", "x{dn}", "cn=a"));
        assertEquals("(uid=\\2a)", Placeholders.fill("(uid={username})", "*", null));
    }
}
