// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ssl.cert.BasicConstraintsExtension;
import com.unboundid.util.ssl.cert.PublicKeyAlgorithmIdentifier;
import com.unboundid.util.ssl.cert.SignatureAlgorithmIdentifier;
import com.unboundid.util.ssl.cert.SubjectAlternativeNameExtension;
import com.unboundid.util.ssl.cert.X509Certificate;
import com.unboundid.util.ssl.cert.X509CertificateExtension;

/**
 * A certificate authority made at test time, and server certificates it signs
 * for given host names, built with the UnboundID SDK so no keytool is needed.
 */
final class TestCertificates {

    private static final char[] PASSWORD = "test".toCharArray();

    private final long notBefore = System.currentTimeMillis() - 3_600_000L;
    private final long notAfter = System.currentTimeMillis() + 86_400_000L;
    private final ObjectPair<X509Certificate, KeyPair> ca;

    TestCertificates(String name) throws Exception {
        ASN1Sequence constraints = new ASN1Sequence(new ASN1Boolean(true));
        ca = X509Certificate.generateSelfSignedCertificate(SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
                PublicKeyAlgorithmIdentifier.RSA, 2048, new DN("CN=" + name), notBefore, notAfter,
                new X509CertificateExtension(BasicConstraintsExtension.BASIC_CONSTRAINTS_OID, true, constraints.encode()));
    }

    /** The CA certificate, as the ca-certificate setting takes it. */
    String caPem() {
        return ca.getFirst().toPEMString();
    }

    /** A server TLS context whose certificate this CA signed, for the given DNS names and IP addresses. */
    SSLContext server(List<String> dnsNames, List<String> ipAddresses) throws Exception {
        ObjectPair<X509Certificate, KeyPair> key = X509Certificate.generateSelfSignedCertificate(
                SignatureAlgorithmIdentifier.SHA_256_WITH_RSA, PublicKeyAlgorithmIdentifier.RSA, 2048,
                new DN("CN=test directory"), notBefore, notAfter);
        List<ASN1Element> names = new ArrayList<>();
        for (String dns : dnsNames) {
            names.add(new ASN1OctetString((byte) 0x82, dns));
        }
        for (String ip : ipAddresses) {
            names.add(new ASN1OctetString((byte) 0x87, InetAddress.getByName(ip).getAddress()));
        }
        X509Certificate leaf = X509Certificate.generateIssuerSignedCertificate(SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
                ca.getFirst(), ca.getSecond().getPrivate(), key.getFirst().getPublicKeyAlgorithmOID(),
                key.getFirst().getPublicKeyAlgorithmParameters(), key.getFirst().getEncodedPublicKey(),
                key.getFirst().getDecodedPublicKey(), new DN("CN=test directory"), notBefore, notAfter,
                new X509CertificateExtension(SubjectAlternativeNameExtension.SUBJECT_ALTERNATIVE_NAME_OID, false,
                        new ASN1Sequence(names).encode()));
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("server", key.getSecond().getPrivate(), PASSWORD, new Certificate[] { jca(leaf), jca(ca.getFirst()) });
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, null);
        return context;
    }

    private static Certificate jca(X509Certificate certificate) throws Exception {
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate.getX509CertificateBytes()));
    }
}
