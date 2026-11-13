// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SecretCipherTest {

    private static final String TARGET = "a".repeat(64);
    private static final String OTHER = "b".repeat(64);

    private final SecretCipher cipher = TestSupport.CIPHER;

    @Test
    void aSealedPasswordCarriesTheMarkerAndOpensForItsTarget() {
        String sealed = cipher.seal("p@ss\nword", TARGET);
        assertTrue(sealed.startsWith(LdapSettings.SEALED_PREFIX), sealed);
        assertFalse(sealed.contains("p@ss"));
        assertEquals("p@ss\nword", cipher.open(sealed, TARGET));
        assertTrue(cipher.fits(sealed, TARGET));
    }

    @Test
    void itDoesNotOpenForAnotherTarget() {
        String sealed = cipher.seal("p@ss", TARGET);
        assertThrows(SecretCipher.WrongTarget.class, () -> cipher.open(sealed, OTHER));
        assertFalse(cipher.fits(sealed, OTHER));
    }

    @Test
    void aValueSealedWithoutATargetDoesNotOpen() {
        String old = LdapSettings.SEALED_PREFIX + "B64" + java.util.Base64.getEncoder().encodeToString("p@ss".getBytes());
        assertThrows(SecretCipher.WrongTarget.class, () -> cipher.open(old, TARGET));
    }

    @Test
    void anEmptyPasswordStaysEmpty() {
        assertEquals("", cipher.seal("", TARGET));
        assertEquals("", cipher.seal(null, TARGET));
        assertEquals("", cipher.open("", TARGET));
    }

    @Test
    void aStoredValueWithoutTheMarkerIsRefusedNotUsed() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> cipher.open("plain-text", TARGET));
        assertTrue(e.getMessage().contains("in clear"), e.getMessage());
    }

    @Test
    void anEncryptorFailureIsReported() {
        SecretCipher broken = new SecretCipher(new SecretCipher.Engine() {
            @Override
            public String encrypt(String clear) throws Exception {
                throw new Exception("no key");
            }

            @Override
            public String decrypt(String sealed) throws Exception {
                throw new Exception("no key");
            }
        });
        assertThrows(IllegalStateException.class, () -> broken.seal("x", TARGET));
        assertThrows(IllegalStateException.class, () -> broken.open("enc:x", TARGET));
    }
}
