// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.mirth.connect.server.api.MirthServlet;

/**
 * The servlet gives the engine the plugin's name as its extension name. The engine
 * then checks each operation as "LDAP Authentication#&lt;operation&gt;", the name the
 * plugin's permission registers; without it rbac finds no mapping and allows every
 * operation to every role.
 */
class LdapServletTest {

    @BeforeEach
    void install() throws Exception {
        StandInFactory.install(new StandInUsers());
    }

    @AfterEach
    void uninstall() throws Exception {
        StandInFactory.uninstall();
    }

    /** A request from a signed-in engine user with id 1. */
    private static HttpServletRequest signedIn() {
        HttpSession session = (HttpSession) Proxy.newProxyInstance(LdapServletTest.class.getClassLoader(),
                new Class<?>[] { HttpSession.class }, (proxy, method, arguments) -> {
                    if (method.getName().equals("getAttribute")) {
                        return "authorized".equals(arguments[0]) ? Boolean.TRUE : "user".equals(arguments[0]) ? 1 : null;
                    }
                    return null;
                });
        return (HttpServletRequest) Proxy.newProxyInstance(LdapServletTest.class.getClassLoader(),
                new Class<?>[] { HttpServletRequest.class }, (proxy, method, arguments) -> {
                    if (method.getName().equals("getSession")) {
                        return session;
                    }
                    return method.getName().equals("getRemoteAddr") ? "127.0.0.1" : null;
                });
    }

    @Test
    void theServletPassesThePluginNameAsItsExtensionName() throws Exception {
        LdapServlet servlet = new LdapServlet(signedIn(), null);
        Field extensionName = MirthServlet.class.getDeclaredField("extensionName");
        extensionName.setAccessible(true);
        assertEquals(LdapServletInterface.PLUGIN_NAME, extensionName.get(servlet));
    }
}
