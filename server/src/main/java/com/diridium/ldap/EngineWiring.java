// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.ExtensionController;
import com.mirth.connect.server.controllers.UserController;

/** Builds the plugin's parts on the engine's controllers. Tests build them on stand-ins instead. */
final class EngineWiring {

    private EngineWiring() {
    }

    static LoginFlow flow(LdapSettings settings, boolean directoryUsable) {
        AccountLinker accounts = new AccountLinker(settings, EngineWiring::users, LinkStore.engine());
        RbacRoles roles = RbacRoles.engine(settings);
        DirectoryLogin directory = null;
        if (directoryUsable) {
            try {
                directory = new DirectoryLogin(settings, new DirectoryClient(settings, SecretCipher.engine()), roles.needsGroups(),
                        Thread::sleep);
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("The TLS trust could not be set up: " + e.getMessage(), e);
            }
        }
        return new LoginFlow(settings, directory, accounts, roles, KillSwitch.system());
    }

    /** The settings as stored, read back after a save. */
    static Properties storedSettings() {
        try {
            return extensions().getPluginProperties(LdapServletInterface.PLUGIN_NAME);
        } catch (ControllerException e) {
            throw new IllegalStateException(e);
        }
    }

    static void sweepLinks() {
        LinkSweep.run(LinkStore.engine(), () -> users().getAllUsers());
    }

    static SettingsService settingsService(SettingsService.Audit audit) {
        return new SettingsService(new SettingsService.Store() {
            @Override
            public Properties load() throws Exception {
                return extensions().getPluginProperties(LdapServletInterface.PLUGIN_NAME);
            }

            @Override
            public void save(Properties properties) throws Exception {
                extensions().setPluginProperties(LdapServletInterface.PLUGIN_NAME, properties, false);
            }

            @Override
            public void apply(Properties properties) {
                extensions().updatePluginProperties(LdapServletInterface.PLUGIN_NAME, properties);
            }
        }, SecretCipher.engine(), EngineWiring::flow, audit, new SaveGuard(EngineWiring::users, LinkStore.engine(), RbacRoles::engine));
    }

    private static UserController users() {
        return ControllerFactory.getFactory().createUserController();
    }

    private static ExtensionController extensions() {
        return ControllerFactory.getFactory().createExtensionController();
    }
}
