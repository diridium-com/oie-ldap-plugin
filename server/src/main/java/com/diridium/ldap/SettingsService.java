// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.CA_CERTIFICATE;
import static com.diridium.ldap.LdapSettings.SECRET_MASK;
import static com.diridium.ldap.LdapSettings.SERVICE_PASSWORD;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import javax.naming.NamingException;

import com.diridium.ldap.LdapSettings.BindMode;

/**
 * What the servlet does: hands out the settings with the service password
 * masked, checks and saves new ones (see {@link ServicePassword} for what a
 * masked password keeps, and {@link SaveGuard} for the checks that need the
 * engine), applies them to the running plugin, and runs the connection and
 * login tests against unsaved settings. Saves run one at a time.
 */
final class SettingsService {

    /** One save at a time, so the stored and the running settings can't end up different. */
    private static final Object SAVE_LOCK = new Object();

    /** Where the settings live; the engine's CONFIGURATION table in production. */
    interface Store {
        Properties load() throws Exception;

        void save(Properties properties) throws Exception;

        /** Hands the saved settings to the running plugin. */
        void apply(Properties properties);
    }

    /** Writes an audit event; never given a password. */
    interface Audit {
        void record(String action, Map<String, String> attributes, boolean success);
    }

    /** Settings that were not saved, and why. */
    static final class Rejected extends Exception {
        private static final long serialVersionUID = 1L;
        private final List<String> problems;

        Rejected(List<String> problems) {
            super(String.join("\n", problems));
            this.problems = List.copyOf(problems);
        }

        List<String> problems() {
            return problems;
        }
    }

    private final Store store;
    private final SecretCipher cipher;
    private final LoginFlow.Factory flows;
    private final Audit audit;
    private final SaveGuard guard;

    SettingsService(Store store, SecretCipher cipher, LoginFlow.Factory flows, Audit audit, SaveGuard guard) {
        this.store = store;
        this.cipher = cipher;
        this.flows = flows;
        this.audit = audit;
        this.guard = guard;
    }

    /** The stored settings over the defaults, service password masked. */
    Properties getMasked() throws Exception {
        Properties settings = LdapSettings.defaults();
        settings.putAll(store.load());
        if (!settings.getProperty(SERVICE_PASSWORD, "").isEmpty()) {
            settings.setProperty(SERVICE_PASSWORD, SECRET_MASK);
        }
        return settings;
    }

    /**
     * Checks, saves and applies; nothing is saved when anything is wrong. A key left out takes
     * its default.
     *
     * @param saverId the engine user saving, who must still be able to sign in afterwards
     * @return the warnings about the saved settings
     */
    List<String> save(Properties incoming, Integer saverId) throws Exception {
        synchronized (SAVE_LOCK) {
            ServicePassword.Resolved resolved = ServicePassword.resolve(incoming, store.load(), cipher);
            LdapSettings settings = LdapSettings.parse(resolved.settings());
            List<String> problems = new ArrayList<>();
            if (resolved.dropped() && !settings.isValid()) {
                problems.add(ServicePassword.RETYPE);
            }
            problems.addAll(settings.problems());
            if (settings.isValid()) {
                String unusable = ServicePassword.unusable(settings, cipher);
                if (unusable != null) {
                    problems.add(unusable);
                }
                problems.addAll(guard.problems(settings, saverId));
            }
            if (!problems.isEmpty()) {
                Map<String, String> attributes = new TreeMap<>();
                attributes.put("problems", String.join(" ", problems));
                audit.record("Settings not saved", attributes, false);
                throw new Rejected(problems);
            }
            Properties canonical = settings.toProperties();
            store.save(canonical);
            store.apply(canonical);
            Map<String, String> attributes = auditView(canonical);
            if (!settings.warnings().isEmpty()) {
                attributes.put("warnings", String.join(" ", settings.warnings()));
            }
            audit.record("Settings saved", attributes, true);
            return settings.warnings();
        }
    }

    LdapTestResult testConnection(Properties incoming) {
        LdapTestResult result = new LdapTestResult();
        LdapSettings settings = testSettings(incoming, result);
        if (settings != null) {
            boolean ok = true;
            try (DirectorySession session = new DirectoryClient(settings, cipher).bindService()) {
                step(result, settings.serviceDn().isEmpty() ? "Connect anonymously" : "Bind as " + settings.serviceDn(), true,
                        String.join(" ", settings.urls()));
                ok &= read(session, "", "the root DSE", result);
                if (settings.bindMode() == BindMode.SEARCH) {
                    ok &= read(session, settings.userSearchBase(), LdapSettings.USER_SEARCH_BASE, result);
                }
                if (!settings.groupSearchBase().isEmpty() && settings.bindMode() == BindMode.SEARCH) {
                    ok &= read(session, settings.groupSearchBase(), LdapSettings.GROUP_SEARCH_BASE, result);
                }
            } catch (Exception e) {
                step(result, "Connect", false, Failures.describe(e));
                ok = false;
            }
            result.setSuccess(ok);
            result.setMessage(ok ? "The directory answered." : "The connection test failed.");
        }
        Map<String, String> attributes = new TreeMap<>();
        attributes.put("url", incoming == null ? "" : incoming.getProperty(LdapSettings.URL, ""));
        audit.record("Connection tested", attributes, result.isSuccess());
        return result;
    }

    LdapTestResult testLogin(LdapTestLoginRequest request) {
        LdapTestResult result = new LdapTestResult();
        String username = request == null || request.getUsername() == null ? "" : request.getUsername();
        LdapSettings settings = request == null ? null : testSettings(request.getSettings(), result);
        if (settings != null) {
            try {
                LoginResult login = flows.build(settings, true).login(username, request.getPassword(), true);
                result.getSteps().addAll(login.steps());
                result.setDn(login.dn());
                result.setEntryId(login.entryId());
                result.setEngineUsername(login.engineUsername());
                result.setGroups(login.groups());
                result.setRole(login.role());
                result.setSuccess(login.outcome() == LoginResult.Outcome.SUCCESS);
                result.setMessage(describe(login));
            } catch (RuntimeException e) {
                step(result, "Sign-in", false, Failures.describe(e));
                result.setMessage("The login test failed.");
            }
        }
        Map<String, String> attributes = new TreeMap<>();
        attributes.put("username", username);
        attributes.put("result", result.getMessage());
        audit.record("Login tested", attributes, result.isSuccess());
        return result;
    }

    /**
     * Settings as an enabled plugin would use them, or null (with the reason in the result).
     * A stored service password dropped because the connection target changed fails the test
     * before anything connects, whether or not the bind mode would use it.
     */
    private LdapSettings testSettings(Properties incoming, LdapTestResult result) {
        LdapSettings settings;
        try {
            ServicePassword.Resolved resolved = ServicePassword.resolve(incoming, store.load(), cipher);
            resolved.settings().setProperty(LdapSettings.ENABLED, "true");
            settings = LdapSettings.parse(resolved.settings());
            if (resolved.dropped() && !settings.serviceDn().isEmpty()) {
                step(result, "Settings", false, ServicePassword.RETYPE);
                result.setMessage("Enter the service password: the stored one is not used when url, starttls, "
                        + "ca-certificate, bind-mode or service-dn changes.");
                return null;
            }
        } catch (Exception e) {
            step(result, "Settings", false, Failures.describe(e));
            result.setMessage("The settings could not be read.");
            return null;
        }
        if (!settings.isValid()) {
            step(result, "Settings", false, String.join(" ", settings.problems()));
            result.setMessage("The settings have problems.");
            return null;
        }
        step(result, "Settings", true, null);
        return settings;
    }

    private static boolean read(DirectorySession session, String dn, String what, LdapTestResult result) {
        try {
            session.read(dn, List.of("1.1"));
            step(result, "Read " + what, true, dn);
            return true;
        } catch (NamingException e) {
            step(result, "Read " + what, false, Failures.describe(e));
            return false;
        }
    }

    private static String describe(LoginResult login) {
        switch (login.outcome()) {
        case SUCCESS:
            return "Signs in as engine user " + login.engineUsername() + ".";
        case LOCAL:
            return "The engine would check the local password: " + login.reason().text + ".";
        default:
            return "Refused: " + login.reason().text + (login.logDetail() == null ? "" : " (" + login.logDetail() + ")") + ".";
        }
    }

    private static void step(LdapTestResult result, String name, boolean passed, String detail) {
        result.getSteps().add(new LdapTestStep(name, passed, detail));
    }

    /** The saved settings for the audit: the service password masked, the CA certificate counted. */
    private static Map<String, String> auditView(Properties settings) {
        Map<String, String> view = new TreeMap<>();
        for (String key : settings.stringPropertyNames()) {
            view.put(key, settings.getProperty(key));
        }
        if (!view.getOrDefault(SERVICE_PASSWORD, "").isEmpty()) {
            view.put(SERVICE_PASSWORD, SECRET_MASK);
        }
        String pem = view.getOrDefault(CA_CERTIFICATE, "");
        if (!pem.isEmpty()) {
            String marker = "-----BEGIN CERTIFICATE-----";
            int count = (pem.length() - pem.replace(marker, "").length()) / marker.length();
            view.put(CA_CERTIFICATE, "(PEM, " + count + " certificate(s))");
        }
        return view;
    }
}
