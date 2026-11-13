// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The plugin checks the ldaps server's host name itself, so a JVM where the JDK's own
 * LDAP check is turned off ({@code com.sun.jndi.ldap.object.disableEndpointIdentification=true})
 * still refuses a certificate for another host. JNDI reads that property once per JVM,
 * so this class runs alone, in the surefire execution {@code jdk-hostname-check-off},
 * which sets it before anything connects; the default execution leaves it out.
 */
public class PluginHostnameCheckTest {

    static final String JDK_CHECK_OFF = "com.sun.jndi.ldap.object.disableEndpointIdentification";

    private static TestCertificates certificates;
    private static TestDirectory directory;

    /** Trusts the test CA and checks no host name, as JNDI's own path does with the check off. */
    public static final class CaOnly extends SSLSocketFactory {
        static volatile SSLSocketFactory trust;

        public static SocketFactory getDefault() {
            return new CaOnly();
        }

        @Override public Socket createSocket() throws IOException { return trust.createSocket(); }
        @Override public Socket createSocket(String host, int port) throws IOException { return trust.createSocket(host, port); }
        @Override public Socket createSocket(String host, int port, InetAddress local, int localPort) throws IOException {
            return trust.createSocket(host, port, local, localPort);
        }
        @Override public Socket createSocket(InetAddress host, int port) throws IOException { return trust.createSocket(host, port); }
        @Override public Socket createSocket(InetAddress host, int port, InetAddress local, int localPort) throws IOException {
            return trust.createSocket(host, port, local, localPort);
        }
        @Override public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            return trust.createSocket(s, host, port, autoClose);
        }
        @Override public String[] getDefaultCipherSuites() { return trust.getDefaultCipherSuites(); }
        @Override public String[] getSupportedCipherSuites() { return trust.getSupportedCipherSuites(); }
    }

    @BeforeAll
    static void start() throws Exception {
        certificates = new TestCertificates("oie-ldap-plugin test CA");
        directory = TestDirectory.startWithTls(certificates);
        CaOnly.trust = TlsTrust.socketFactory(certificates.caPem());
    }

    @AfterAll
    static void stop() {
        directory.close();
        System.clearProperty(JDK_CHECK_OFF);
    }

    @Test
    void thePluginRefusesAnotherHostsCertificateWithTheJdksCheckOff() throws Exception {
        assertEquals("true", System.getProperty(JDK_CHECK_OFF), "runs only in the jdk-hostname-check-off execution");

        // Control: with only the CA trusted, JNDI itself now accepts the certificate for wrong.example.com.
        Hashtable<String, Object> environment = new Hashtable<>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, directory.url("ldaps-wrong-host"));
        environment.put("java.naming.ldap.factory.socket", CaOnly.class.getName());
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, "uid=alice," + TestDirectory.PEOPLE);
        environment.put(Context.SECURITY_CREDENTIALS, "alice-pw");
        new InitialLdapContext(environment, null).close();
        directory.drain();

        // The plugin's own check refuses it.
        DirectoryClient client = new DirectoryClient(TestSupport.settings(TestSupport.with(TestSupport.template(directory),
                LdapSettings.URL, directory.url("ldaps-wrong-host"), LdapSettings.CA_CERTIFICATE, certificates.caPem())),
                TestSupport.CIPHER);
        Exception e = assertThrows(Exception.class, () -> client.bind("uid=alice," + TestDirectory.PEOPLE, "alice-pw").close());
        assertTrue(Failures.isTls(e), Failures.describe(e));
        assertEquals(List.of(), directory.drain().stream().filter(line -> line.startsWith("BIND REQUEST")).toList(),
                "no bind reached the server");
    }
}
