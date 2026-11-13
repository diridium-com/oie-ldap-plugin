// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** What a successful save returns: the warnings about settings that work but deserve a second look. */
public class LdapSaveResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<String> warnings = new ArrayList<>();

    public LdapSaveResult() {
    }

    public LdapSaveResult(List<String> warnings) {
        this.warnings = new ArrayList<>(warnings);
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }
}
