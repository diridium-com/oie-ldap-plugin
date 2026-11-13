// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/** Reads the {@code ca-certificate} setting: one or more PEM certificates. */
public final class PemCertificates {

    private PemCertificates() {
    }

    /**
     * @return the certificates in the text, in order
     * @throws CertificateException if the text holds no certificate or one that can't be read
     */
    public static List<X509Certificate> parse(String pem) throws CertificateException {
        if (pem == null || pem.isBlank()) {
            throw new CertificateException("no certificate found");
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates = new ArrayList<>();
        for (Certificate certificate : factory.generateCertificates(
                new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.US_ASCII)))) {
            certificates.add((X509Certificate) certificate);
        }
        if (certificates.isEmpty()) {
            throw new CertificateException("no certificate found");
        }
        return certificates;
    }
}
