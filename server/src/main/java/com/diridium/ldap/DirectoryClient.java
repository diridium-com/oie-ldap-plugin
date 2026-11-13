// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Hashtable;
import java.util.Locale;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLSocketFactory;

/**
 * Opens bound connections with the JDK's JNDI LDAP provider: ldap:// or
 * ldaps://, StartTLS when set, connect and read timeouts, no connection pooling,
 * referrals ignored. Over ldaps and StartTLS the server certificate must chain to
 * the configured CA (or the JVM's trust without one) and match the host name.
 */
final class DirectoryClient {

    private static final String CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    private final LdapSettings settings;
    private final SecretCipher cipher;
    private final boolean ldaps;
    private final SSLSocketFactory trust;

    DirectoryClient(LdapSettings settings, SecretCipher cipher) throws GeneralSecurityException, IOException {
        this.settings = settings;
        this.cipher = cipher;
        this.ldaps = !settings.urls().isEmpty()
                && settings.urls().stream().allMatch(url -> url.toLowerCase(Locale.ROOT).startsWith("ldaps:"));
        this.trust = ldaps || settings.startTls() ? TlsTrust.socketFactory(settings.caCertificate()) : null;
    }

    /**
     * Binds as {@code principal}. An empty password is refused here as well as in the
     * login flow: the directory would take a bind with one as anonymous and succeed.
     */
    DirectorySession bind(String principal, String password) throws NamingException, IOException {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("An empty password is never sent to the directory.");
        }
        return open(principal, password);
    }

    /** Binds as the service account, or anonymously when none is set. */
    DirectorySession bindService() throws NamingException, IOException {
        if (settings.serviceDn().isEmpty()) {
            return open(null, null);
        }
        return bind(settings.serviceDn(), cipher.open(settings.servicePassword(), settings.targetFingerprint()));
    }

    private DirectorySession open(String principal, String password) throws NamingException, IOException {
        Hashtable<String, Object> environment = environment();
        if (principal != null && !settings.startTls()) {
            credentials(environment, principal, password);
        } else {
            environment.put(Context.SECURITY_AUTHENTICATION, "none");
        }
        LdapContext context = connect(environment);
        try {
            if (settings.startTls()) {
                StartTlsResponse tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
                tls.negotiate(LdapsSocketFactory.checking(trust));
                if (principal != null) {
                    context.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
                    context.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
                    context.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
                }
                // JNDI binds on the next operation, over the encrypted connection.
                context.getAttributes(new LdapName(""), new String[] { "supportedLDAPVersion" });
            }
            return new DirectorySession(context, settings.readTimeoutMs());
        } catch (NamingException | IOException | RuntimeException e) {
            try {
                context.close();
            } catch (NamingException ignored) {
                // the original failure is the one to report
            }
            throw e;
        }
    }

    private Hashtable<String, Object> environment() {
        Hashtable<String, Object> environment = new Hashtable<>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
        environment.put(Context.PROVIDER_URL, String.join(" ", settings.urls()));
        environment.put(Context.REFERRAL, "ignore");
        environment.put("java.naming.ldap.version", "3");
        environment.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(settings.connectTimeoutMs()));
        environment.put("com.sun.jndi.ldap.read.timeout", String.valueOf(settings.readTimeoutMs()));
        environment.put("com.sun.jndi.ldap.connect.pool", "false");
        environment.put("java.naming.ldap.attributes.binary", binaryAttributes());
        return environment;
    }

    /**
     * objectGUID comes back as bytes, and so does an entry-id-attribute other than
     * entryUUID: as text, JNDI would decode bytes that aren't UTF-8 into look-alikes.
     */
    private String binaryAttributes() {
        String id = settings.entryIdAttribute();
        if (id.equalsIgnoreCase(LdapSettings.ENTRY_ID_AUTO) || id.equalsIgnoreCase("entryUUID")
                || id.equalsIgnoreCase("objectGUID")) {
            return "objectGUID";
        }
        return "objectGUID " + id;
    }

    private static void credentials(Hashtable<String, Object> environment, String principal, String password) {
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, principal);
        environment.put(Context.SECURITY_CREDENTIALS, password);
    }

    private LdapContext connect(Hashtable<String, Object> environment) throws NamingException {
        if (!ldaps) {
            return new InitialLdapContext(environment, null);
        }
        environment.put("java.naming.ldap.factory.socket", LdapsSocketFactory.class.getName());
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        // JNDI loads the socket factory class through the context class loader.
        thread.setContextClassLoader(LdapsSocketFactory.class.getClassLoader());
        try {
            return LdapsSocketFactory.using(trust, () -> new InitialLdapContext(environment, null));
        } catch (NamingException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            NamingException wrapped = new NamingException(e.getMessage());
            wrapped.setRootCause(e);
            throw wrapped;
        } finally {
            thread.setContextClassLoader(previous);
        }
    }
}
