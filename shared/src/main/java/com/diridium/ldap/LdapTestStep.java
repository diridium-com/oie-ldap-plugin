// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.Serializable;

/** One check of a connection or login test: what was checked, whether it passed, and what was seen. */
public class LdapTestStep implements Serializable {

    private static final long serialVersionUID = 1L;

    private String name = "";
    private boolean passed;
    private String detail = "";

    public LdapTestStep() {
    }

    public LdapTestStep(String name, boolean passed, String detail) {
        this.name = name;
        this.passed = passed;
        this.detail = detail == null ? "" : detail;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    @Override
    public String toString() {
        return (passed ? "PASS " : "FAIL ") + name + (detail.isEmpty() ? "" : ": " + detail);
    }
}
