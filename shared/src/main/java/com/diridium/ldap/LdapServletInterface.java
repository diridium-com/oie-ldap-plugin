// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.Properties;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.Operation.ExecuteType;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST API for the LDAP settings, mounted at {@code /extensions/oie-ldap-plugin}.
 * Every operation needs {@link LdapPermissions#MANAGE}. Parameters that can hold a
 * password are kept out of the engine's audit; the server writes its own audit
 * event with the service password masked.
 */
@Path("/extensions/oie-ldap-plugin")
@Tag(name = "LDAP Authentication")
@Consumes({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
@Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
public interface LdapServletInterface extends BaseServletInterface {

    /** The plugin.xml name: the key of the stored settings and of the plugin's permission. */
    String PLUGIN_NAME = "LDAP Authentication";

    @GET
    @Path("/settings")
    @Operation(summary = "Returns the LDAP settings, with the service password masked")
    @MirthOperation(name = "getLdapSettings", display = "Get LDAP settings", permission = LdapPermissions.MANAGE,
            type = ExecuteType.ASYNC, auditable = false)
    Properties getSettings() throws ClientException;

    @PUT
    @Path("/settings")
    @Operation(summary = "Checks and saves the LDAP settings, applies them without a restart, and returns warnings")
    @MirthOperation(name = "setLdapSettings", display = "Save LDAP settings", permission = LdapPermissions.MANAGE,
            type = ExecuteType.SYNC)
    LdapSaveResult setSettings(
            @Param(value = "settings", excludeFromAudit = true)
            @Parameter(description = "The settings; a masked service password keeps the stored one unless url, starttls, "
                    + "ca-certificate, bind-mode or service-dn changed", required = true)
            Properties settings) throws ClientException;

    @POST
    @Path("/_testConnection")
    @Operation(summary = "Connects with the given (unsaved) settings and binds as the service account")
    @MirthOperation(name = "testLdapConnection", display = "Test LDAP connection", permission = LdapPermissions.MANAGE,
            type = ExecuteType.SYNC)
    LdapTestResult testConnection(
            @Param(value = "settings", excludeFromAudit = true)
            @Parameter(description = "The settings to test; a masked service password uses the stored one unless url, "
                    + "starttls, ca-certificate, bind-mode or service-dn changed", required = true)
            Properties settings) throws ClientException;

    @POST
    @Path("/_testLogin")
    @Operation(summary = "Runs a sign-in with the given (unsaved) settings without creating or changing anything")
    @MirthOperation(name = "testLdapLogin", display = "Test LDAP login", permission = LdapPermissions.MANAGE,
            type = ExecuteType.SYNC)
    LdapTestResult testLogin(
            @Param(value = "request", excludeFromAudit = true)
            @Parameter(description = "The settings, username and password to test", required = true)
            LdapTestLoginRequest request) throws ClientException;
}
