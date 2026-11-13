// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * What a connection or login test found. A login test fills in the entry it
 * reached and what a real sign-in would do with it; nothing is created or
 * changed by a test.
 */
public class LdapTestResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean success;
    private String message = "";
    private List<LdapTestStep> steps = new ArrayList<>();
    private String dn = "";
    private String entryId = "";
    private String engineUsername = "";
    private List<String> groups = new ArrayList<>();
    private String role = "";

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message == null ? "" : message;
    }

    public List<LdapTestStep> getSteps() {
        return steps;
    }

    public void setSteps(List<LdapTestStep> steps) {
        this.steps = steps;
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String dn) {
        this.dn = dn == null ? "" : dn;
    }

    public String getEntryId() {
        return entryId;
    }

    public void setEntryId(String entryId) {
        this.entryId = entryId == null ? "" : entryId;
    }

    public String getEngineUsername() {
        return engineUsername;
    }

    public void setEngineUsername(String engineUsername) {
        this.engineUsername = engineUsername == null ? "" : engineUsername;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role == null ? "" : role;
    }
}
