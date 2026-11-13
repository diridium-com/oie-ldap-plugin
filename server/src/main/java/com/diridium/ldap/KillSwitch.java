// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.function.UnaryOperator;

/**
 * Turns LDAP sign-in off without touching the stored settings, for when a bad
 * setting locks everyone out: environment variable {@code OIE_LDAP_DISABLED=true}
 * or system property {@code com.diridium.ldap.disabled=true}. While it is on,
 * every name signs in with the engine's own password check.
 */
final class KillSwitch {

    static final String ENVIRONMENT_VARIABLE = "OIE_LDAP_DISABLED";
    static final String SYSTEM_PROPERTY = "com.diridium.ldap.disabled";

    private final UnaryOperator<String> environment;
    private final UnaryOperator<String> systemProperties;

    KillSwitch(UnaryOperator<String> environment, UnaryOperator<String> systemProperties) {
        this.environment = environment;
        this.systemProperties = systemProperties;
    }

    static KillSwitch system() {
        return new KillSwitch(System::getenv, System::getProperty);
    }

    boolean isOn() {
        return source() != null;
    }

    /** @return what turned it on, or null when it is off */
    String source() {
        if ("true".equalsIgnoreCase(trim(environment.apply(ENVIRONMENT_VARIABLE)))) {
            return "environment variable " + ENVIRONMENT_VARIABLE;
        }
        if ("true".equalsIgnoreCase(trim(systemProperties.apply(SYSTEM_PROPERTY)))) {
            return "system property " + SYSTEM_PROPERTY;
        }
        return null;
    }

    private static String trim(String value) {
        return value == null ? null : value.trim();
    }
}
