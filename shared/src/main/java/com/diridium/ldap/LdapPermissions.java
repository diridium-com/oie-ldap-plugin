// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import com.mirth.connect.client.core.TaskConstants;

/**
 * The plugin's one permission. It lets the holder link any engine account to a
 * directory account and map directory groups to roles, so it amounts to admin
 * rights. Every operation of {@link LdapServletInterface}
 * needs it, and so do the engine's own {@code getPluginProperties} and
 * {@code setPluginProperties} for this plugin, which read and write the same
 * stored settings. Role-Based Access Control allows any operation that no
 * permission claims, so leaving those two unclaimed would let any role rewrite
 * the linked accounts.
 */
public final class LdapPermissions {

    public static final String MANAGE = "Manage LDAP Authentication";

    /** The settings tab's task group; its refresh task needs {@link #MANAGE}. */
    public static final String SETTINGS_TASK_GROUP = TaskConstants.SETTINGS_KEY_PREFIX + LdapServletInterface.PLUGIN_NAME;

    private LdapPermissions() {
    }
}
