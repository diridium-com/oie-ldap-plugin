// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.normalize;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * A group the user is a member of: its DN and its names (the {@code roles.group-attribute}
 * values), both normalized, so a {@code roles.map} key can name a group either way.
 */
record DirectoryGroup(String dn, Set<String> names) {

    static DirectoryGroup of(DirectoryEntry entry, String nameAttribute) {
        Set<String> names = new LinkedHashSet<>();
        for (String name : entry.all(nameAttribute)) {
            names.add(normalize(name));
        }
        return new DirectoryGroup(normalizeDn(entry.dn()), Collections.unmodifiableSet(names));
    }

    /**
     * A DN in one spelling: attribute types and values lower-cased and normalized, values
     * unescaped, the values of a multi-valued RDN sorted. Two spellings of one DN give the same
     * text; text that isn't a DN is only normalized.
     */
    static String normalizeDn(String dn) {
        try {
            LdapName name = new LdapName(dn);
            List<String> rdns = new ArrayList<>();
            for (int i = name.size() - 1; i >= 0; i--) {
                rdns.add(rdn(name.getRdn(i)));
            }
            return String.join(",", rdns);
        } catch (NamingException | IllegalArgumentException e) {
            return normalize(dn);
        }
    }

    private static String rdn(Rdn rdn) throws NamingException {
        List<String> values = new ArrayList<>();
        NamingEnumeration<? extends Attribute> attributes = rdn.toAttributes().getAll();
        while (attributes.hasMore()) {
            Attribute attribute = attributes.next();
            for (int i = 0; i < attribute.size(); i++) {
                values.add(attribute.getID().toLowerCase(Locale.ROOT) + "=" + normalize(String.valueOf(attribute.get(i))));
            }
        }
        Collections.sort(values);
        return String.join("+", values);
    }
}
