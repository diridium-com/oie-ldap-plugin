// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.Serializable;
import java.util.Properties;

/** Body of a test login: the (unsaved) settings and the credentials to try. */
public class LdapTestLoginRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private Properties settings = new Properties();
    private String username = "";
    private String password = "";

    public LdapTestLoginRequest() {
    }

    public LdapTestLoginRequest(Properties settings, String username, String password) {
        this.settings = settings;
        this.username = username;
        this.password = password;
    }

    public Properties getSettings() {
        return settings;
    }

    public void setSettings(Properties settings) {
        this.settings = settings;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
