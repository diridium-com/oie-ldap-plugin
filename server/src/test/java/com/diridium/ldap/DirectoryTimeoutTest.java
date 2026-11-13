// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A server that accepts the connection and never answers. Measured on JDK 17:
 * JNDI waits for the reply to the first bind for up to the connect timeout, not
 * the read timeout, and reports it as a plain NamingException ("LDAP response
 * read timed out"). That counts as the directory being unreachable, but it isn't
 * tried again: the bind may have reached the directory. The time bounds are loose,
 * so a busy machine can't fail them.
 */
class DirectoryTimeoutTest {

    private final List<Socket> held = new ArrayList<>();
    private ServerSocket silent;

    @BeforeEach
    void listen() throws Exception {
        silent = new ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"));
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    held.add(silent.accept());
                }
            } catch (Exception closed) {
                // the test is over
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @AfterEach
    void close() throws Exception {
        silent.close();
        for (Socket socket : held) {
            socket.close();
        }
    }

    private long millisToGiveUp(String connectTimeout, String readTimeout) throws Exception {
        try (TestDirectory directory = TestDirectory.start()) {
            Properties p = TestSupport.with(TestSupport.template(directory),
                    LdapSettings.URL, "ldap://localhost:" + silent.getLocalPort(),
                    LdapSettings.CONNECT_TIMEOUT_MS, connectTimeout, LdapSettings.READ_TIMEOUT_MS, readTimeout);
            DirectoryClient client = new DirectoryClient(TestSupport.settings(p), TestSupport.CIPHER);
            long started = System.nanoTime();
            try {
                client.bind("uid=alice," + TestDirectory.PEOPLE, "alice-pw").close();
            } catch (Exception e) {
                assertTrue(Failures.isConnectionFailure(e), Failures.describe(e));
                assertFalse(Failures.failedBeforeSending(e), "sent, so not tried again: " + Failures.describe(e));
                return (System.nanoTime() - started) / 1_000_000;
            }
            throw new AssertionError("a server that never answers can't let a bind succeed");
        }
    }

    @Test
    void theFirstBindWaitsForTheConnectTimeout() throws Exception {
        long millis = millisToGiveUp("1500", "300");
        assertTrue(millis >= 1_200, "gave up after " + millis + " ms, before the connect timeout");
        assertTrue(millis < 30_000, "gave up after " + millis + " ms");
    }

    @Test
    void aShortConnectTimeoutEndsTheBindEarly() throws Exception {
        long millis = millisToGiveUp("300", "20000");
        assertTrue(millis < 15_000, "gave up after " + millis + " ms, so the read timeout decided");
    }
}
