// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * plugin.xml names classes the compiler can't check. A server class that doesn't
 * exist, or isn't a ServicePlugin, never starts and never registers its
 * permission; a name that differs from the one the settings are stored under
 * loses the settings on uninstall and breaks saving them.
 */
class PluginXmlWiringTest {

    private static Document pluginXml() throws Exception {
        File file = new File("resources/plugin.xml");
        assertTrue(file.exists(), "plugin.xml not found at " + file.getAbsolutePath());
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(file);
    }

    private static List<String> strings(Document doc, String parent) {
        List<String> values = new ArrayList<>();
        NodeList parents = doc.getElementsByTagName(parent);
        for (int i = 0; i < parents.getLength(); i++) {
            NodeList strings = ((Element) parents.item(i)).getElementsByTagName("string");
            for (int j = 0; j < strings.getLength(); j++) {
                values.add(strings.item(j).getTextContent().trim());
            }
        }
        return values;
    }

    @Test
    void theServerClassExistsAndIsTheServiceAndAuthorizationPlugin() throws Exception {
        List<String> serverClasses = strings(pluginXml(), "serverClasses");
        assertEquals(List.of("com.diridium.ldap.LdapAuthorizationPlugin"), serverClasses);
        Class<?> plugin = Class.forName(serverClasses.get(0), false, getClass().getClassLoader());
        assertTrue(Class.forName("com.mirth.connect.plugins.ServicePlugin").isAssignableFrom(plugin));
        assertTrue(Class.forName("com.mirth.connect.plugins.AuthorizationPlugin").isAssignableFrom(plugin));
    }

    @Test
    void theApiProvidersAreTheServletInterfaceAndItsServlet() throws Exception {
        NodeList providers = pluginXml().getElementsByTagName("apiProvider");
        assertEquals(2, providers.getLength());
        for (int i = 0; i < providers.getLength(); i++) {
            Element provider = (Element) providers.item(i);
            Class<?> type = Class.forName(provider.getAttribute("name"), false, getClass().getClassLoader());
            if (provider.getAttribute("type").equals("SERVLET_INTERFACE")) {
                assertEquals(LdapServletInterface.class, type);
            } else {
                assertEquals("SERVER_CLASS", provider.getAttribute("type"));
                assertEquals("com.diridium.ldap.LdapServlet", type.getName());
                assertTrue(LdapServletInterface.class.isAssignableFrom(type));
            }
        }
    }

    @Test
    void theServerAndSharedJarsAreListed() throws Exception {
        NodeList libraries = pluginXml().getElementsByTagName("library");
        List<String> listed = new ArrayList<>();
        for (int i = 0; i < libraries.getLength(); i++) {
            Element library = (Element) libraries.item(i);
            listed.add(library.getAttribute("type") + " " + library.getAttribute("path"));
        }
        assertEquals(List.of("SERVER oie-ldap-plugin-server-${project.version}.jar",
                "SHARED oie-ldap-plugin-shared-${project.version}.jar"), listed);
    }

    @Test
    void thePluginNameIsTheNameTheSettingsAndPermissionUse() throws Exception {
        String name = pluginXml().getElementsByTagName("name").item(0).getTextContent().trim();
        assertEquals(LdapServletInterface.PLUGIN_NAME, name);
        assertEquals("oie-ldap-plugin", pluginXml().getDocumentElement().getAttribute("path"));
    }
}
