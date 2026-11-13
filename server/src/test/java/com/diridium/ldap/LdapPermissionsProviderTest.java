// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.server.api.DontCheckAuthorized;

/**
 * Every operation of the plugin's REST API, and the engine's own plugin
 * properties operations for this plugin, are registered under the plugin's
 * permission, and the engine checks it before every servlet method.
 */
class LdapPermissionsProviderTest {

    private static Set<String> servletOperations() {
        Set<String> names = new TreeSet<>();
        for (Method method : LdapServletInterface.class.getMethods()) {
            MirthOperation operation = method.getAnnotation(MirthOperation.class);
            if (operation != null) {
                names.add(operation.name());
            }
        }
        return names;
    }

    @Test
    void everyServletOperationIsRegisteredUnderThePluginsPermission() {
        ExtensionPermission[] permissions = LdapPermissionsProvider.permissions();
        assertEquals(1, permissions.length);
        ExtensionPermission permission = permissions[0];
        assertEquals(LdapServletInterface.PLUGIN_NAME, permission.getExtensionName());
        assertEquals(LdapPermissions.MANAGE, permission.getDisplayName());
        assertTrue(permission.getDescription().contains("admin rights"), permission.getDescription());
        Set<String> expected = new TreeSet<>(servletOperations());
        assertEquals(4, expected.size(), expected.toString());
        expected.add("getPluginProperties");
        expected.add("setPluginProperties");
        assertEquals(expected, new TreeSet<>(Set.of(permission.getOperationNames())));
    }

    @Test
    void theSettingsTabIsGatedByThePermission() {
        assertEquals(Set.of("settings_LDAP Authentication/doRefresh"), Set.of(LdapPermissionsProvider.permissions()[0].getTaskNames()));
    }

    @Test
    void noServletMethodSkipsTheEnginesAuthorizationCheck() {
        assertTrue(LdapServletInterface.class.isAssignableFrom(LdapServlet.class));
        for (Method method : LdapServlet.class.getDeclaredMethods()) {
            assertNull(method.getAnnotation(DontCheckAuthorized.class), method.getName());
        }
    }
}
