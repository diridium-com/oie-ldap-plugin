// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import com.mirth.connect.server.controllers.ConfigurationController;

/**
 * The links between engine accounts and directory entries: engine user id to the
 * entry's stable id. In the engine they are kept in the CONFIGURATION table under
 * {@value #CATEGORY}, a category that is no plugin's name. Role-Based Access Control
 * 1.3.0 and later refuse the engine's generic plugin properties API for a name that
 * isn't an installed plugin's, so only the admin role can reach the links that way,
 * and users can't change them the way they can change their own preferences.
 * An account the plugin created carries a second key, {@code <id>.created}.
 */
interface LinkStore {

    String CATEGORY = "LDAP Authentication account links";
    String CREATED = ".created";

    /** @return the linked entry id, or null when the account has no link */
    String entryId(int userId);

    void link(int userId, String entryId);

    /** Records that the plugin created the account; accounts linked through linked-accounts aren't marked. */
    void markCreated(int userId);

    boolean created(int userId);

    /** Removes the link and the created mark. */
    void unlink(int userId);

    /** Every link, engine user id to entry id. */
    Map<Integer, String> all();

    static LinkStore engine() {
        return new LinkStore() {
            @Override
            public String entryId(int userId) {
                String value = ConfigurationController.getInstance().getProperty(CATEGORY, String.valueOf(userId));
                return value == null || value.isBlank() ? null : value;
            }

            @Override
            public void link(int userId, String entryId) {
                ConfigurationController.getInstance().saveProperty(CATEGORY, String.valueOf(userId), entryId);
            }

            @Override
            public void markCreated(int userId) {
                ConfigurationController.getInstance().saveProperty(CATEGORY, userId + CREATED, "true");
            }

            @Override
            public boolean created(int userId) {
                return "true".equals(ConfigurationController.getInstance().getProperty(CATEGORY, userId + CREATED));
            }

            @Override
            public void unlink(int userId) {
                ConfigurationController.getInstance().removeProperty(CATEGORY, String.valueOf(userId));
                ConfigurationController.getInstance().removeProperty(CATEGORY, userId + CREATED);
            }

            @Override
            public Map<Integer, String> all() {
                Properties stored = ConfigurationController.getInstance().getPropertiesForGroup(CATEGORY);
                Map<Integer, String> links = new HashMap<>();
                for (String key : stored.stringPropertyNames()) {
                    try {
                        links.put(Integer.valueOf(key), stored.getProperty(key));
                    } catch (NumberFormatException e) {
                        // a created mark, or not something this plugin wrote
                    }
                }
                return links;
            }
        };
    }
}
