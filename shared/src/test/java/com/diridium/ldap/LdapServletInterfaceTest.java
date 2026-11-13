// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Map;
import java.util.TreeMap;

import javax.ws.rs.Path;

import org.junit.jupiter.api.Test;

import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

/**
 * The REST contract: every operation needs the plugin's permission, the
 * changes are audited, and nothing that can hold a password goes into the
 * engine's audit event.
 */
class LdapServletInterfaceTest {

    private static Map<String, Method> operations() {
        Map<String, Method> operations = new TreeMap<>();
        for (Method method : LdapServletInterface.class.getDeclaredMethods()) {
            MirthOperation operation = method.getAnnotation(MirthOperation.class);
            if (operation != null) {
                operations.put(operation.name(), method);
            }
        }
        return operations;
    }

    @Test
    void everyOperationNeedsThePluginsPermission() {
        assertEquals(4, operations().size(), operations().keySet().toString());
        for (Method method : operations().values()) {
            assertEquals(LdapPermissions.MANAGE, method.getAnnotation(MirthOperation.class).permission(), method.getName());
        }
    }

    @Test
    void readingIsNotAuditedAndEverythingElseIs() {
        Map<String, Method> operations = operations();
        assertEquals(false, operations.get("getLdapSettings").getAnnotation(MirthOperation.class).auditable());
        for (String name : new String[] { "setLdapSettings", "testLdapConnection", "testLdapLogin" }) {
            assertTrue(operations.get(name).getAnnotation(MirthOperation.class).auditable(), name);
        }
    }

    @Test
    void parametersThatCanHoldAPasswordStayOutOfTheEnginesAudit() {
        for (Method method : operations().values()) {
            for (Parameter parameter : method.getParameters()) {
                Param param = parameter.getAnnotation(Param.class);
                assertNotNull(param, method.getName() + " " + parameter.getName());
                assertTrue(param.excludeFromAudit(), method.getName() + " " + param.value());
            }
        }
    }

    @Test
    void theApiLivesUnderThePluginId() {
        assertEquals("/extensions/oie-ldap-plugin", LdapServletInterface.class.getAnnotation(Path.class).value());
        assertEquals("settings_LDAP Authentication", LdapPermissions.SETTINGS_TASK_GROUP);
    }
}
