// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.server.api.MirthServlet;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * The REST API. No method skips the engine's authorization check
 * ({@code @DontCheckAuthorized}), so the engine checks {@link LdapPermissions#MANAGE}
 * before each one runs. Parameters that can hold a password are left out of the
 * engine's audit event, and {@link SettingsService} writes a second event with the
 * details, the service password masked.
 */
public class LdapServlet extends MirthServlet implements LdapServletInterface {

    private static final Logger LOG = LoggerFactory.getLogger(LdapServlet.class);

    private final SettingsService service;

    public LdapServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        super(request, sc, PLUGIN_NAME);
        this.service = EngineWiring.settingsService(this::audit);
    }

    @Override
    public Properties getSettings() {
        try {
            return service.getMasked();
        } catch (Exception e) {
            LOG.error("Could not read the LDAP settings", e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public LdapSaveResult setSettings(Properties settings) {
        try {
            return new LdapSaveResult(service.save(settings, getCurrentUserId()));
        } catch (SettingsService.Rejected e) {
            throw new MirthApiException(Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build());
        } catch (Exception e) {
            LOG.error("Could not save the LDAP settings", e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public LdapTestResult testConnection(Properties settings) {
        return service.testConnection(settings);
    }

    @Override
    public LdapTestResult testLogin(LdapTestLoginRequest request) {
        return service.testLogin(request);
    }

    private void audit(String action, Map<String, String> attributes, boolean success) {
        ServerEvent event = new ServerEvent(ConfigurationController.getInstance().getServerId(), PLUGIN_NAME + ": " + action,
                ServerEvent.Level.INFORMATION, success ? ServerEvent.Outcome.SUCCESS : ServerEvent.Outcome.FAILURE, attributes);
        event.setUserId(getCurrentUserId());
        event.setIpAddress(getRequestIpAddress());
        ControllerFactory.getFactory().createEventController().dispatchEvent(event);
    }
}
