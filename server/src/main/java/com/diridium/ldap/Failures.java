// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Locale;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.net.ssl.SSLException;

/** Sorts what JNDI throws into what is worth retrying and what isn't. */
final class Failures {

    private Failures() {
    }

    /**
     * A connection that failed or timed out: the directory can't be used right now. A refused
     * password, bad settings and TLS failures are not that; TLS failures come wrapped in a
     * CommunicationException too, so they are ruled out first.
     */
    static boolean isConnectionFailure(Throwable e) {
        if (isTls(e)) {
            return false;
        }
        if (e instanceof CommunicationException || e instanceof ServiceUnavailableException
                || has(e, SocketTimeoutException.class)) {
            return true;
        }
        // JNDI reports a read timeout as a plain NamingException ("LDAP response read timed out").
        return e.getClass() == NamingException.class && e.getMessage() != null && e.getMessage().contains("timed out");
    }

    /**
     * The connection failed before any LDAP request was written: the name didn't resolve, the
     * connection was refused or unroutable, or connecting timed out ("Connect timed out"). Only
     * these are tried again. Once a request may have reached the directory (a read timeout, a
     * reset, an answer), a second bind could count twice against the directory's lockout.
     */
    static boolean failedBeforeSending(Throwable e) {
        if (isTls(e)) {
            return false;
        }
        if (has(e, ConnectException.class) || has(e, NoRouteToHostException.class) || has(e, UnknownHostException.class)) {
            return true;
        }
        Throwable current = e;
        for (int depth = 0; current != null && depth < 16; depth++) {
            if (current instanceof SocketTimeoutException && current.getMessage() != null
                    && current.getMessage().toLowerCase(Locale.ROOT).contains("connect")) {
                return true;
            }
            current = next(current);
        }
        return false;
    }

    static boolean isTls(Throwable e) {
        return has(e, SSLException.class);
    }

    /** One line for a log or a test step: the class and message, and the root cause's. */
    static String describe(Throwable e) {
        if (e == null) {
            return "(none)";
        }
        StringBuilder out = new StringBuilder(e.getClass().getSimpleName());
        if (e.getMessage() != null) {
            out.append(": ").append(e.getMessage());
        }
        Throwable root = cause(e);
        if (root != null && root != e) {
            out.append(" (").append(root.getClass().getSimpleName());
            if (root.getMessage() != null) {
                out.append(": ").append(root.getMessage());
            }
            out.append(')');
        }
        return out.toString();
    }

    private static boolean has(Throwable e, Class<? extends Throwable> type) {
        Throwable current = e;
        for (int depth = 0; current != null && depth < 16; depth++) {
            if (type.isInstance(current)) {
                return true;
            }
            current = next(current);
        }
        return false;
    }

    private static Throwable cause(Throwable e) {
        Throwable current = e;
        for (int depth = 0; depth < 16; depth++) {
            Throwable next = next(current);
            if (next == null || next == current) {
                return current;
            }
            current = next;
        }
        return current;
    }

    private static Throwable next(Throwable e) {
        if (e instanceof NamingException && ((NamingException) e).getRootCause() != null) {
            return ((NamingException) e).getRootCause();
        }
        return e.getCause();
    }
}
