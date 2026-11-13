// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

/** Puts a typed name into a log line without letting it start a line of its own. */
final class LogText {

    private LogText() {
    }

    /** The name in double quotes, control characters written as {@code \xNN}. */
    static String quote(String text) {
        return text == null ? "(none)" : '"' + clean(text) + '"';
    }

    /** The text with control characters written as {@code \xNN}. */
    static String clean(String text) {
        if (text == null) {
            return "(none)";
        }
        StringBuilder out = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            if (c < 0x20 || c == 0x7f) {
                out.append(String.format("\\x%02x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** Whether the text holds a control character. */
    static boolean hasControl(String text) {
        for (char c : text.toCharArray()) {
            if (c < 0x20 || c == 0x7f) {
                return true;
            }
        }
        return false;
    }
}
