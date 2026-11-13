// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import com.mirth.connect.server.controllers.ConfigurationController;

/**
 * Seals the service account password with the engine's encryptor before it is
 * stored, marked with {@link LdapSettings#SEALED_PREFIX}. The sealed text holds the
 * connection target's fingerprint ({@link LdapSettings#targetFingerprint()}) with the
 * password, so a password stored for one target can't be opened for another, however
 * the settings were changed. A stored value without the marker is clear text and is
 * refused, never used.
 */
final class SecretCipher {

    /** The encryptor; the engine's in production, a stand-in in tests. */
    interface Engine {
        String encrypt(String clear) throws Exception;

        String decrypt(String sealed) throws Exception;
    }

    /** A sealed password stored for a different connection target. */
    static final class WrongTarget extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        WrongTarget() {
            super("The service password was stored for a different url, starttls, ca-certificate, bind-mode or service-dn; "
                    + "enter it again.");
        }
    }

    private static final char SEPARATOR = '\n';

    private final Engine engine;

    SecretCipher(Engine engine) {
        this.engine = engine;
    }

    static SecretCipher engine() {
        return new SecretCipher(new Engine() {
            @Override
            public String encrypt(String clear) throws Exception {
                return ConfigurationController.getInstance().getEncryptor().encrypt(clear);
            }

            @Override
            public String decrypt(String sealed) throws Exception {
                return ConfigurationController.getInstance().getEncryptor().decrypt(sealed);
            }
        });
    }

    static boolean isSealed(String stored) {
        return stored != null && stored.startsWith(LdapSettings.SEALED_PREFIX);
    }

    /** @return the sealed form for this connection target, or an empty string for an empty password */
    String seal(String clear, String fingerprint) {
        if (clear == null || clear.isEmpty()) {
            return "";
        }
        try {
            return LdapSettings.SEALED_PREFIX + engine.encrypt(fingerprint + SEPARATOR + clear);
        } catch (Exception e) {
            throw new IllegalStateException("The engine's encryptor could not seal the password: " + e.getMessage(), e);
        }
    }

    /**
     * @return the clear password, or an empty string for an empty stored value
     * @throws WrongTarget if it was stored for another connection target
     * @throws IllegalStateException if it is stored in clear or can't be decrypted
     */
    String open(String stored, String fingerprint) {
        if (stored == null || stored.isEmpty()) {
            return "";
        }
        if (!isSealed(stored)) {
            throw new IllegalStateException("The service password is stored in clear; it is not used.");
        }
        String plain;
        try {
            plain = engine.decrypt(stored.substring(LdapSettings.SEALED_PREFIX.length()));
        } catch (Exception e) {
            throw new IllegalStateException("The engine's encryptor could not open the service password: " + e.getMessage(), e);
        }
        int cut = plain.indexOf(SEPARATOR);
        if (cut < 0 || !plain.substring(0, cut).equals(fingerprint)) {
            throw new WrongTarget();
        }
        return plain.substring(cut + 1);
    }

    /** Whether the stored value opens for this connection target. */
    boolean fits(String stored, String fingerprint) {
        try {
            open(stored, fingerprint);
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }
}
