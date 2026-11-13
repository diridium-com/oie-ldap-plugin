// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The comma-separated lists in the settings: {@code a, b} for names and
 * {@code a=b, c=d} for pairs. A backslash makes the next {@code ,}, {@code =} or
 * {@code \} part of the name, so a group called {@code Ops, Night} is written
 * {@code Ops\, Night=Operator}.
 */
final class NameLists {

    private NameLists() {
    }

    static List<String> parseNames(String raw) {
        List<String> names = new ArrayList<>();
        for (String item : split(raw, ',')) {
            String name = unescape(item).trim();
            if (!name.isEmpty()) {
                names.add(name);
            }
        }
        return List.copyOf(names);
    }

    /**
     * @param lastSeparator split each entry at its last unescaped {@code =}, so the left side
     *                      may hold more (a group DN); otherwise an entry has exactly one
     */
    static List<NamePair> parsePairs(String raw, String key, String form, List<String> problems, boolean lastSeparator) {
        List<NamePair> pairs = new ArrayList<>();
        for (String item : split(raw, ',')) {
            if (item.trim().isEmpty()) {
                continue;
            }
            List<String> sides = split(item, '=');
            if (lastSeparator && sides.size() > 2) {
                sides = List.of(String.join("=", sides.subList(0, sides.size() - 1)), sides.get(sides.size() - 1));
            }
            String left = sides.size() == 2 ? unescape(sides.get(0)).trim() : "";
            String right = sides.size() == 2 ? unescape(sides.get(1)).trim() : "";
            if (left.isEmpty() || right.isEmpty()) {
                problems.add(key + ": \"" + item.trim() + "\" is not in the form " + form + ".");
            } else {
                pairs.add(new NamePair(left, right));
            }
        }
        return List.copyOf(pairs);
    }

    static String formatNames(Collection<String> names) {
        List<String> escaped = new ArrayList<>();
        for (String name : names) {
            escaped.add(escape(name));
        }
        return String.join(", ", escaped);
    }

    static String formatPairs(List<NamePair> pairs) {
        List<String> escaped = new ArrayList<>();
        for (NamePair pair : pairs) {
            escaped.add(escape(pair.left()) + "=" + escape(pair.right()));
        }
        return String.join(", ", escaped);
    }

    /** Splits on every separator not preceded by a backslash; escapes stay in the parts. */
    private static List<String> split(String raw, char separator) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                current.append(c).append(raw.charAt(++i));
            } else if (c == separator) {
                parts.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts;
    }

    private static String unescape(String part) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < part.length(); i++) {
            char c = part.charAt(i);
            if (c == '\\' && i + 1 < part.length()) {
                out.append(part.charAt(++i));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String escape(String name) {
        StringBuilder out = new StringBuilder();
        for (char c : name.toCharArray()) {
            if (c == '\\' || c == ',' || c == '=') {
                out.append('\\');
            }
            out.append(c);
        }
        return out.toString();
    }
}
