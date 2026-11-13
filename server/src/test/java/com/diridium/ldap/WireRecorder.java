// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A TCP relay in front of a directory listener that keeps every byte the client
 * sends, so a test can check what crossed the wire in clear.
 */
final class WireRecorder implements AutoCloseable {

    private final ServerSocket listener;
    private final ByteArrayOutputStream fromClient = new ByteArrayOutputStream();
    private final List<Socket> sockets = Collections.synchronizedList(new ArrayList<>());

    WireRecorder(int targetPort) throws Exception {
        listener = new ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"));
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    Socket client = listener.accept();
                    Socket upstream = new Socket("127.0.0.1", targetPort);
                    sockets.add(client);
                    sockets.add(upstream);
                    pump(client.getInputStream(), upstream.getOutputStream(), true);
                    pump(upstream.getInputStream(), client.getOutputStream(), false);
                }
            } catch (Exception closed) {
                // the test is over
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
    }

    int port() {
        return listener.getLocalPort();
    }

    boolean clientSent(String text) {
        byte[] sent;
        synchronized (fromClient) {
            sent = fromClient.toByteArray();
        }
        return new String(sent, StandardCharsets.ISO_8859_1).contains(text);
    }

    private void pump(InputStream in, OutputStream out, boolean record) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[8192];
            try {
                int n;
                while ((n = in.read(buffer)) > 0) {
                    if (record) {
                        synchronized (fromClient) {
                            fromClient.write(buffer, 0, n);
                        }
                    }
                    out.write(buffer, 0, n);
                    out.flush();
                }
            } catch (Exception closed) {
                // one side hung up
            }
        });
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void close() throws Exception {
        listener.close();
        synchronized (sockets) {
            for (Socket socket : sockets) {
                socket.close();
            }
        }
    }
}
