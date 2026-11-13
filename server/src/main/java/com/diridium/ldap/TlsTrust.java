// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * The TLS trust for directory connections. With a {@code ca-certificate} set,
 * only those certificates are trusted, for this plugin's connections only; the
 * JVM's trust store and every other connection are left alone. Without one, the
 * JVM's default trust applies.
 */
final class TlsTrust {

    private TlsTrust() {
    }

    static SSLSocketFactory socketFactory(String caPem) throws GeneralSecurityException, IOException {
        if (caPem == null || caPem.isBlank()) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
        KeyStore trusted = KeyStore.getInstance(KeyStore.getDefaultType());
        trusted.load(null, null);
        int i = 0;
        for (X509Certificate certificate : PemCertificates.parse(caPem)) {
            trusted.setCertificateEntry("ca-" + i++, certificate);
        }
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(trusted);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trust.getTrustManagers(), null);
        return context.getSocketFactory();
    }
}
