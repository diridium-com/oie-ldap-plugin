// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** When the stored service password is kept for a masked one, and when it is dropped or unusable. */
class ServicePasswordTest {

    private static Properties stored() {
        Properties p = new Properties();
        p.setProperty(LdapSettings.URL, "ldap://a.example.com ldap://b.example.com");
        p.setProperty(LdapSettings.BIND_MODE, "search");
        p.setProperty(LdapSettings.SERVICE_DN, "cn=service,dc=example,dc=com");
        p.setProperty(LdapSettings.CA_CERTIFICATE, "");
        p.setProperty(LdapSettings.SERVICE_PASSWORD, TestSupport.sealFor(p, "service-pw"));
        return p;
    }

    private static ServicePassword.Resolved resolve(String key, String value, String password) {
        Properties incoming = stored();
        incoming.setProperty(key, value);
        if (password == null) {
            incoming.remove(LdapSettings.SERVICE_PASSWORD);
        } else {
            incoming.setProperty(LdapSettings.SERVICE_PASSWORD, password);
        }
        return ServicePassword.resolve(incoming, stored(), TestSupport.CIPHER);
    }

    @ParameterizedTest
    @CsvSource({
        "url, ldap://c.example.com",
        "url, ldap://b.example.com ldap://a.example.com",
        "starttls, true",
        "ca-certificate, -----BEGIN CERTIFICATE-----",
        "bind-mode, template",
        "service-dn, 'cn=other,dc=example,dc=com'",
    })
    void aChangedConnectionTargetDropsTheStoredPassword(String key, String value) {
        for (String password : new String[] { LdapSettings.SECRET_MASK, null }) {
            ServicePassword.Resolved resolved = resolve(key, value, password);
            assertTrue(resolved.dropped(), key);
            assertEquals("", resolved.settings().getProperty(LdapSettings.SERVICE_PASSWORD), key);
        }
    }

    @ParameterizedTest
    @CsvSource({
        "url, ldap://a.example.com   ldap://b.example.com",
        "group-filter, (member={dn})",
        "linked-accounts, admin=jdoe",
        "retries, 5",
        "enabled, true",
    })
    void anythingElseKeepsTheStoredPassword(String key, String value) {
        ServicePassword.Resolved resolved = resolve(key, value, LdapSettings.SECRET_MASK);
        assertFalse(resolved.dropped(), key);
        assertEquals(stored().getProperty(LdapSettings.SERVICE_PASSWORD), resolved.settings().getProperty(LdapSettings.SERVICE_PASSWORD));
        assertEquals("service-pw", TestSupport.openFor(resolved.settings()));
    }

    @ParameterizedTest
    @CsvSource({ "url, ldap://c.example.com", "retries, 5" })
    void aTypedPasswordIsSealedForTheNewTarget(String key, String value) {
        ServicePassword.Resolved resolved = resolve(key, value, "new-pw");
        assertFalse(resolved.dropped());
        assertEquals("new-pw", TestSupport.openFor(resolved.settings()));
    }

    @Test
    void withNothingStoredThereIsNothingToDrop() {
        Properties incoming = stored();
        incoming.setProperty(LdapSettings.URL, "ldap://c.example.com");
        incoming.setProperty(LdapSettings.SERVICE_PASSWORD, LdapSettings.SECRET_MASK);
        ServicePassword.Resolved resolved = ServicePassword.resolve(incoming, new Properties(), TestSupport.CIPHER);
        assertFalse(resolved.dropped());
        assertEquals("", resolved.settings().getProperty(LdapSettings.SERVICE_PASSWORD));
    }

    @ParameterizedTest
    @CsvSource({
        "url, ldap://c.example.com",
        "starttls, true",
        "ca-certificate, -----BEGIN CERTIFICATE-----",
        "service-dn, 'cn=other,dc=example,dc=com'",
    })
    void aPasswordSealedForAnotherTargetIsUnusable(String key, String value) {
        Properties changedBehindTheScreen = stored();
        changedBehindTheScreen.setProperty(key, value);
        assertEquals(ServicePassword.WRONG_TARGET,
                ServicePassword.unusable(LdapSettings.parse(changedBehindTheScreen), TestSupport.CIPHER), key);
    }

    @Test
    void aPasswordForItsOwnTargetOrNotNeededIsFine() {
        assertNull(ServicePassword.unusable(LdapSettings.parse(stored()), TestSupport.CIPHER));
        Properties template = stored();
        template.setProperty(LdapSettings.BIND_MODE, "template");
        assertNull(ServicePassword.unusable(LdapSettings.parse(template), TestSupport.CIPHER), "template binds don't use it");
    }
}
