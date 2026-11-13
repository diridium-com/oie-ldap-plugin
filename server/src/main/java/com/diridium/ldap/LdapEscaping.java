// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

/**
 * Escaping for values the plugin puts into DNs and search filters, written from
 * the RFCs. A typed username goes through one of these before it reaches the
 * directory, so it can only ever be one attribute value: never an extra RDN, a
 * second AVA or a filter clause.
 */
final class LdapEscaping {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private LdapEscaping() {
    }

    /**
     * RFC 4514 section 2.4, an attribute value in a DN string: a backslash before
     * {@code " + , ; < > \}, before a leading space or {@code #} and before a
     * trailing space; NUL as {@code \00}. {@code =} and the other control
     * characters are escaped too, which the RFC allows.
     */
    static String dnValue(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        int last = value.length() - 1;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((i == 0 && (c == ' ' || c == '#')) || (i == last && c == ' ')) {
                out.append('\\').append(c);
            } else if (c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\' || c == '=') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c == 0x7f) {
                hex(out, c);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * RFC 4515 section 3, an assertion value in a search filter: {@code * ( ) \}
     * and NUL as {@code \2a \28 \29 \5c \00}. The other control characters are
     * escaped too, which the RFC allows; other characters go as UTF-8.
     */
    static String filterValue(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '*' || c == '(' || c == ')' || c == '\\' || c < 0x20 || c == 0x7f) {
                hex(out, c);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static void hex(StringBuilder out, char c) {
        out.append('\\').append(HEX[(c >> 4) & 0x0f]).append(HEX[c & 0x0f]);
    }
}
