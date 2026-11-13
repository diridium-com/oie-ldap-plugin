// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.concurrent.Callable;

import javax.net.SocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The socket factory JNDI uses for ldaps:// URLs. JNDI takes it by class name
 * ({@code java.naming.ldap.factory.socket}) and calls the static
 * {@link #getDefault()}, so the trust for one connection is handed over in a
 * thread-local around the connect, see {@link #using}. Every socket checks the
 * server's certificate against the host name ("LDAPS" endpoint
 * identification), whatever JNDI's own setting is.
 */
public final class LdapsSocketFactory extends SSLSocketFactory {

    private static final ThreadLocal<SSLSocketFactory> CURRENT = new ThreadLocal<>();

    private final SSLSocketFactory delegate;

    private LdapsSocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    /** Runs a connect with {@code factory} as the trust for the sockets JNDI opens on this thread. */
    static <T> T using(SSLSocketFactory factory, Callable<T> connect) throws Exception {
        CURRENT.set(factory);
        try {
            return connect.call();
        } finally {
            CURRENT.remove();
        }
    }

    /** Called by JNDI while {@link #using} runs on this thread. */
    public static SocketFactory getDefault() {
        SSLSocketFactory factory = CURRENT.get();
        if (factory == null) {
            throw new IllegalStateException("LdapsSocketFactory is only usable while a directory connection is opened");
        }
        return new LdapsSocketFactory(factory);
    }

    /** Also used for StartTLS, where JNDI layers TLS over the open connection. */
    static SSLSocketFactory checking(SSLSocketFactory factory) {
        return new LdapsSocketFactory(factory);
    }

    @Override
    public Socket createSocket() throws IOException {
        return checked(delegate.createSocket());
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return checked(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return checked(delegate.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return checked(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return checked(delegate.createSocket(address, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return checked(delegate.createSocket(socket, host, port, autoClose));
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    private static Socket checked(Socket socket) {
        if (socket instanceof SSLSocket) {
            SSLSocket ssl = (SSLSocket) socket;
            SSLParameters parameters = ssl.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("LDAPS");
            ssl.setSSLParameters(parameters);
        }
        return socket;
    }
}
