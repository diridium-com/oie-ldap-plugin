// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.List;

import com.mirth.connect.model.converters.ObjectXMLSerializer;

/**
 * Lets the engine's serializer read and write the plugin's REST types, which it
 * refuses by default. The server calls this on start; a client plugin does the same.
 */
public final class LdapSerialization {

    static final Class<?>[] TYPES = { LdapTestResult.class, LdapTestStep.class, LdapTestLoginRequest.class, LdapSaveResult.class };

    private LdapSerialization() {
    }

    public static void register() {
        List<String> names = new ArrayList<>();
        for (Class<?> type : TYPES) {
            names.add(type.getName());
        }
        ObjectXMLSerializer.getInstance().allowTypes(names, List.of(), List.of());
    }
}
