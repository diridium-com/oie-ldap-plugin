// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

/**
 * A directory entry as read: its DN and the attributes asked for. Attribute
 * names are matched ignoring case; binary values (objectGUID) are held as
 * lower-case hex of their bytes.
 */
final class DirectoryEntry {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final String dn;
    private final Map<String, List<String>> values;

    DirectoryEntry(String dn, Map<String, List<String>> values) {
        this.dn = dn;
        this.values = values;
    }

    static DirectoryEntry from(String dn, Attributes attributes) throws NamingException {
        Map<String, List<String>> values = new HashMap<>();
        if (attributes != null) {
            NamingEnumeration<? extends Attribute> all = attributes.getAll();
            while (all.hasMore()) {
                Attribute attribute = all.next();
                List<String> list = new ArrayList<>();
                for (int i = 0; i < attribute.size(); i++) {
                    Object value = attribute.get(i);
                    list.add(value instanceof byte[] ? hex((byte[]) value) : String.valueOf(value));
                }
                values.put(attribute.getID().toLowerCase(Locale.ROOT), Collections.unmodifiableList(list));
            }
        }
        return new DirectoryEntry(dn, values);
    }

    String dn() {
        return dn;
    }

    /** @return the first value, or null when the attribute is absent or the name is empty */
    String first(String attribute) {
        List<String> list = all(attribute);
        return list.isEmpty() ? null : list.get(0);
    }

    List<String> all(String attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return List.of();
        }
        return values.getOrDefault(attribute.toLowerCase(Locale.ROOT), List.of());
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(HEX[(b >> 4) & 0x0f]).append(HEX[b & 0x0f]);
        }
        return out.toString();
    }
}
