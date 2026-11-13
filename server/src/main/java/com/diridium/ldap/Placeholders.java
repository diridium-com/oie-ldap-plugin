// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

/**
 * Fills {@code {username}} and {@code {dn}} in a filter setting, each value
 * escaped for a filter. One pass: a value that itself contains {@code {dn}} is
 * not filled again.
 */
final class Placeholders {

    private static final String USERNAME = "{username}";
    private static final String DN = "{dn}";

    private Placeholders() {
    }

    static String fill(String filter, String username, String dn) {
        StringBuilder out = new StringBuilder(filter.length() + 32);
        int i = 0;
        while (i < filter.length()) {
            if (filter.startsWith(USERNAME, i) && username != null) {
                out.append(LdapEscaping.filterValue(username));
                i += USERNAME.length();
            } else if (filter.startsWith(DN, i) && dn != null) {
                out.append(LdapEscaping.filterValue(dn));
                i += DN.length();
            } else {
                out.append(filter.charAt(i++));
            }
        }
        return out.toString();
    }
}
