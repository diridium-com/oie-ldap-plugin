// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import com.mirth.connect.client.core.TaskConstants;
import com.mirth.connect.client.core.api.servlets.ExtensionServletInterface;
import com.mirth.connect.client.core.api.util.OperationUtil;
import com.mirth.connect.model.ExtensionPermission;

/**
 * The permission the plugin registers with the engine, which Role-Based Access
 * Control enforces. The operation names are read off the servlet interface, so
 * an operation added later can't ship unregistered. The engine's own
 * get and set plugin properties operations are claimed too (as the engine's
 * Data Pruner does for its own), since they reach the same stored settings.
 */
final class LdapPermissionsProvider {

    private LdapPermissionsProvider() {
    }

    static ExtensionPermission[] permissions() {
        String[] operations = OperationUtil.getOperationNamesForPermission(LdapPermissions.MANAGE, LdapServletInterface.class,
                ExtensionServletInterface.OPERATION_PLUGIN_PROPERTIES_GET, ExtensionServletInterface.OPERATION_PLUGIN_PROPERTIES_SET);
        return new ExtensionPermission[] {
            new ExtensionPermission(LdapServletInterface.PLUGIN_NAME, LdapPermissions.MANAGE,
                    "Change the LDAP sign-in settings and run the connection and login tests. The holder can link any "
                            + "engine account to a directory account and map directory groups to roles, which amounts to "
                            + "admin rights.", operations,
                    new String[] { LdapPermissions.SETTINGS_TASK_GROUP + "/" + TaskConstants.SETTINGS_REFRESH })
        };
    }
}
