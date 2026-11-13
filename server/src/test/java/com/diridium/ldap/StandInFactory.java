// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.lang.reflect.Field;

import com.mirth.connect.server.controllers.AlertController;
import com.mirth.connect.server.controllers.AuthorizationController;
import com.mirth.connect.server.controllers.ChannelController;
import com.mirth.connect.server.controllers.CodeTemplateController;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ContextFactoryController;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.DatabaseTaskController;
import com.mirth.connect.server.controllers.DebugUsageController;
import com.mirth.connect.server.controllers.EngineController;
import com.mirth.connect.server.controllers.EventController;
import com.mirth.connect.server.controllers.ExtensionController;
import com.mirth.connect.server.controllers.MessageController;
import com.mirth.connect.server.controllers.MigrationController;
import com.mirth.connect.server.controllers.ScriptController;
import com.mirth.connect.server.controllers.UsageController;
import com.mirth.connect.server.controllers.UserController;

/**
 * The engine's controller factory with only the user controller, set as the
 * factory through reflection on its private static field, as the upstream probe did.
 */
final class StandInFactory extends ControllerFactory {

    private final UserController users;

    private StandInFactory(UserController users) {
        this.users = users;
    }

    static void install(UserController users) throws Exception {
        set(new StandInFactory(users));
    }

    static void uninstall() throws Exception {
        set(null);
    }

    private static void set(ControllerFactory factory) throws Exception {
        Field field = ControllerFactory.class.getDeclaredField("factory");
        field.setAccessible(true);
        field.set(null, factory);
    }

    @Override public UserController createUserController() { return users; }
    @Override public AuthorizationController createAuthorizationController() { return null; }
    @Override public AlertController createAlertController() { return null; }
    @Override public ChannelController createChannelController() { return null; }
    @Override public CodeTemplateController createCodeTemplateController() { return null; }
    @Override public ConfigurationController createConfigurationController() { return null; }
    @Override public DebugUsageController createDebugUsageController() { return null; }
    @Override public EngineController createEngineController() { return null; }
    @Override public EventController createEventController() { return null; }
    @Override public ExtensionController createExtensionController() { return null; }
    @Override public MessageController createMessageController() { return null; }
    @Override public MigrationController createMigrationController() { return null; }
    @Override public ScriptController createScriptController() { return null; }
    @Override public UsageController createUsageController() { return null; }
    @Override public DatabaseTaskController createDatabaseTaskController() { return null; }
    @Override public ContextFactoryController createContextFactoryController() { return null; }
}
