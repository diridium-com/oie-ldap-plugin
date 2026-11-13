// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.SECRET_MASK;
import static com.diridium.ldap.LdapSettings.SERVICE_PASSWORD;

import java.util.Properties;

import com.diridium.ldap.LdapSettings.BindMode;

/**
 * What becomes of the service password in settings a client sends. The mask, or
 * no password at all, keeps the stored one, but only while the connection target
 * is the same: when url, starttls, ca-certificate, bind-mode or service-dn
 * differs from the stored settings, the stored password is dropped and has to be
 * typed again. Any other value is a new password, sealed for the new target.
 * Settings changed some other way (the engine's generic plugin properties API, a
 * restored backup) keep a sealed password that no longer opens; {@link #unusable}
 * says so.
 */
final class ServicePassword {

    static final String RETYPE = "service-password: enter it again. The stored password is not kept when url, starttls, "
            + "ca-certificate, bind-mode or service-dn changes.";

    static final String WRONG_TARGET = "service-password: stored for a different url, starttls, ca-certificate, "
            + "bind-mode or service-dn, so it can't be used. Enter it again.";

    /** The settings with the password resolved, and whether a stored password was dropped. */
    record Resolved(Properties settings, boolean dropped) {
    }

    private ServicePassword() {
    }

    static Resolved resolve(Properties incoming, Properties stored, SecretCipher cipher) {
        Properties resolved = new Properties();
        if (incoming != null) {
            resolved.putAll(incoming);
        }
        String value = resolved.getProperty(SERVICE_PASSWORD);
        if (value != null && !SECRET_MASK.equals(value)) {
            // Sealed even when it starts with the marker: whatever a client sends is clear text.
            resolved.setProperty(SERVICE_PASSWORD, cipher.seal(value, LdapSettings.parse(resolved).targetFingerprint()));
            return new Resolved(resolved, false);
        }
        String kept = stored == null ? "" : stored.getProperty(SERVICE_PASSWORD, "");
        boolean dropped = !kept.isEmpty() && targetChanged(LdapSettings.parse(stored), LdapSettings.parse(resolved));
        resolved.setProperty(SERVICE_PASSWORD, dropped ? "" : kept);
        return new Resolved(resolved, dropped);
    }

    /** Whether the settings would send the service password somewhere else, or differently. */
    static boolean targetChanged(LdapSettings before, LdapSettings after) {
        return !before.targetFingerprint().equals(after.targetFingerprint());
    }

    /**
     * @return why search binds can't use the stored service password (it was sealed for another
     *         target), or null when it is fine or not needed
     */
    static String unusable(LdapSettings settings, SecretCipher cipher) {
        if (settings.bindMode() != BindMode.SEARCH || settings.serviceDn().isEmpty() || settings.servicePassword().isEmpty()) {
            return null;
        }
        return cipher.fits(settings.servicePassword(), settings.targetFingerprint()) ? null : WRONG_TARGET;
    }
}
