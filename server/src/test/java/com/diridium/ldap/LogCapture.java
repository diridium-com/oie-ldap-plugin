// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;

/** Records what the plugin logs while it is open (log4j2-test.xml sets the plugin's logger to DEBUG). */
final class LogCapture implements AutoCloseable {

    private final List<LogEvent> events = Collections.synchronizedList(new ArrayList<>());
    private final AbstractAppender appender;
    private final LoggerConfig loggerConfig;
    private final LoggerContext context;

    LogCapture() {
        context = (LoggerContext) LogManager.getContext(false);
        loggerConfig = context.getConfiguration().getLoggerConfig("com.diridium.ldap");
        appender = new AbstractAppender("capture-" + UUID.randomUUID(), null, null, true, Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                events.add(event.toImmutable());
            }
        };
        appender.start();
        loggerConfig.addAppender(appender, Level.ALL, null);
        context.updateLoggers();
    }

    List<LogEvent> at(Level level) {
        List<LogEvent> matching = new ArrayList<>();
        synchronized (events) {
            for (LogEvent event : events) {
                if (event.getLevel().equals(level)) {
                    matching.add(event);
                }
            }
        }
        return matching;
    }

    /** Events at INFO or above: what an engine at its default level would show. */
    List<LogEvent> infoAndAbove() {
        List<LogEvent> matching = new ArrayList<>();
        synchronized (events) {
            for (LogEvent event : events) {
                if (event.getLevel().isMoreSpecificThan(Level.INFO)) {
                    matching.add(event);
                }
            }
        }
        return matching;
    }

    static String text(LogEvent event) {
        return event.getMessage().getFormattedMessage();
    }

    void clear() {
        events.clear();
    }

    @Override
    public void close() {
        loggerConfig.removeAppender(appender.getName());
        context.updateLoggers();
        appender.stop();
    }
}
