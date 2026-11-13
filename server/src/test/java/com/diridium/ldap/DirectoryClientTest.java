// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.List;
import java.util.Properties;

import javax.naming.AuthenticationException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The JNDI client against the in-memory server, TLS included: ldaps and StartTLS
 * with a CA made at test time, trusted when configured, refused when not, and a
 * certificate for another host name refused on both paths.
 */
class DirectoryClientTest {

    private static final String ALICE = "uid=alice," + TestDirectory.PEOPLE;
    private static final String STARTTLS_OID = "1.3.6.1.4.1.1466.20037";

    private static TestCertificates certificates;
    private static TestDirectory directory;

    @BeforeAll
    static void start() throws Exception {
        certificates = new TestCertificates("oie-ldap-plugin test CA");
        directory = TestDirectory.startWithTls(certificates);
    }

    @AfterAll
    static void stop() {
        directory.close();
    }

    @BeforeEach
    void forget() {
        directory.drain();
    }

    private static DirectoryClient client(String... keysAndValues) throws Exception {
        Properties p = TestSupport.with(TestSupport.template(directory), keysAndValues);
        return new DirectoryClient(TestSupport.settings(p), TestSupport.CIPHER);
    }

    private static String aliceUid(DirectoryClient client) throws Exception {
        try (DirectorySession session = client.bind(ALICE, "alice-pw")) {
            return session.read(ALICE, List.of("uid")).first("uid");
        }
    }

    @Test
    void bindsAndReadsOverPlainLdap() throws Exception {
        assertEquals("alice", aliceUid(client()));
    }

    @Test
    void aRefusedPasswordIsAnAuthenticationException() {
        Exception e = assertThrows(AuthenticationException.class, () -> client().bind(ALICE, "wrong").close());
        assertFalse(Failures.isConnectionFailure(e));
    }

    @Test
    void anEmptyPasswordIsNeverSent() throws Exception {
        DirectoryClient client = client();
        assertThrows(IllegalArgumentException.class, () -> client.bind(ALICE, ""));
        assertThrows(IllegalArgumentException.class, () -> client.bind(ALICE, null));
        assertEquals(List.of(), directory.drain());
    }

    @Test
    void theServiceAccountBindsWithItsSealedPassword() throws Exception {
        Properties p = TestSupport.search(directory);
        DirectoryClient client = new DirectoryClient(TestSupport.settings(p), TestSupport.CIPHER);
        try (DirectorySession session = client.bindService()) {
            assertEquals(1, session.search(TestDirectory.PEOPLE, "(uid=bob)", List.of("uid"), 2).size());
        }
        assertTrue(directory.drain().stream().anyMatch(line -> line.startsWith("BIND RESULT") && line.contains("resultCode=0")));
    }

    @Test
    void ldapsWithTheConfiguredCaConnects() throws Exception {
        assertEquals("alice", aliceUid(client(LdapSettings.URL, directory.url("ldaps"),
                LdapSettings.CA_CERTIFICATE, certificates.caPem())));
    }

    @Test
    void ldapsByIpAddressMatchesTheAddressInTheCertificate() throws Exception {
        assertEquals("alice", aliceUid(client(LdapSettings.URL, "ldaps://127.0.0.1:" + directory.port("ldaps"),
                LdapSettings.CA_CERTIFICATE, certificates.caPem())));
    }

    @Test
    void ldapsWithoutTheCaIsRefused() throws Exception {
        DirectoryClient client = client(LdapSettings.URL, directory.url("ldaps"));
        Exception e = assertThrows(Exception.class, () -> aliceUid(client));
        assertTrue(Failures.isTls(e), Failures.describe(e));
        assertFalse(Failures.isConnectionFailure(e), "a TLS failure is not retried");
        assertNoBindReached();
    }

    @Test
    void ldapsWithAnotherCaIsRefused() throws Exception {
        String otherCa = new TestCertificates("another CA").caPem();
        DirectoryClient client = client(LdapSettings.URL, directory.url("ldaps"), LdapSettings.CA_CERTIFICATE, otherCa);
        Exception e = assertThrows(Exception.class, () -> aliceUid(client));
        assertTrue(Failures.isTls(e), Failures.describe(e));
        assertNoBindReached();
    }

    @Test
    void ldapsToAHostTheCertificateDoesNotNameIsRefused() throws Exception {
        DirectoryClient client = client(LdapSettings.URL, directory.url("ldaps-wrong-host"),
                LdapSettings.CA_CERTIFICATE, certificates.caPem());
        Exception e = assertThrows(Exception.class, () -> aliceUid(client));
        assertTrue(Failures.isTls(e), Failures.describe(e));
        assertNoBindReached();
    }

    @Test
    void startTlsWithTheConfiguredCaSendsThePasswordOnlyEncrypted() throws Exception {
        try (WireRecorder wire = new WireRecorder(directory.port("starttls"))) {
            DirectoryClient client = client(LdapSettings.URL, "ldap://localhost:" + wire.port(), LdapSettings.STARTTLS, "true",
                    LdapSettings.CA_CERTIFICATE, certificates.caPem());
            assertEquals("alice", aliceUid(client));
            assertTrue(wire.clientSent(STARTTLS_OID), "the StartTLS request goes in clear");
            assertFalse(wire.clientSent("alice-pw"), "the password must not cross the wire in clear");
        }
    }

    @Test
    void controlWithoutStartTlsThePasswordCrossesInClear() throws Exception {
        try (WireRecorder wire = new WireRecorder(directory.port("ldap"))) {
            assertEquals("alice", aliceUid(client(LdapSettings.URL, "ldap://localhost:" + wire.port())));
            assertTrue(wire.clientSent("alice-pw"), "the recorder sees a clear-text bind");
        }
    }

    @Test
    void startTlsRefusesAWrongPassword() throws Exception {
        DirectoryClient client = client(LdapSettings.URL, directory.url("starttls"), LdapSettings.STARTTLS, "true",
                LdapSettings.CA_CERTIFICATE, certificates.caPem());
        assertThrows(AuthenticationException.class, () -> client.bind(ALICE, "wrong").close());
    }

    @Test
    void startTlsWithoutTheCaIsRefused() throws Exception {
        DirectoryClient client = client(LdapSettings.URL, directory.url("starttls"), LdapSettings.STARTTLS, "true");
        Exception e = assertThrows(Exception.class, () -> aliceUid(client));
        assertTrue(Failures.isTls(e), Failures.describe(e));
        assertNoBindReached();
    }

    @Test
    void startTlsToAHostTheCertificateDoesNotNameIsRefused() throws Exception {
        DirectoryClient client = client(LdapSettings.URL, directory.url("starttls-wrong-host"), LdapSettings.STARTTLS, "true",
                LdapSettings.CA_CERTIFICATE, certificates.caPem());
        Exception e = assertThrows(Exception.class, () -> aliceUid(client));
        assertTrue(Failures.isTls(e), Failures.describe(e));
        assertNoBindReached();
    }

    @Test
    void startTlsAgainstAServerWithoutItNeverSendsThePassword() throws Exception {
        DirectoryClient client = client(LdapSettings.STARTTLS, "true", LdapSettings.CA_CERTIFICATE, certificates.caPem());
        assertThrows(Exception.class, () -> aliceUid(client));
        assertNoBindReached();
    }

    @Test
    void aClosedPortIsAConnectionFailure() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = socket.getLocalPort();
        }
        DirectoryClient client = client(LdapSettings.URL, "ldap://localhost:" + port);
        Exception e = assertThrows(Exception.class, () -> aliceUid(client));
        assertTrue(Failures.isConnectionFailure(e), Failures.describe(e));
    }

    private static void assertNoBindReached() {
        List<String> seen = directory.drain();
        assertEquals(0, count(seen, "BIND REQUEST"), "no bind may reach the server: " + seen);
    }

    private static long count(List<String> seen, String kind) {
        return seen.stream().filter(line -> line.startsWith(kind)).count();
    }
}
