// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.diridium.ldap.AccountLinker.Lookup;
import com.diridium.ldap.AccountLinker.Resolution;
import com.diridium.ldap.LdapSettings.BindMode;
import com.diridium.ldap.LoginResult.Reason;

/**
 * One sign-in, decided on the engine account the typed name means (found the way the
 * engine finds it): the kill switch, the local-only list, then either the directory
 * (bind, entry, group check, then the engine account and its role) or, when the
 * directory can't be used, the outage rules. An ordinary refusal is a result, never
 * an exception.
 *
 * <p>Local-only names always get the engine's own password check. A directory account
 * (an engine account with a link, or named in {@code linked-accounts}) gets it only when
 * the directory can't be used (unreachable, LDAP off, or settings with a problem) and
 * {@code outage-local-passwords} is on, never after a refused password. Any other name
 * gets it when the directory can't be used, or, with
 * {@code fallback-to-local-for-unknown-users}, when the directory doesn't know the name.
 * The engine username is the entry's {@code username-attribute} value, never the typed
 * text. Accounts the plugin created sign in only while Role-Based Access Control runs.</p>
 */
final class LoginFlow {

    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    /** Builds a flow for settings; without the directory when it can't be used. */
    interface Factory {
        LoginFlow build(LdapSettings settings, boolean directoryUsable);
    }

    private static final Logger LOG = LoggerFactory.getLogger(LoginFlow.class);

    private final LdapSettings settings;
    private final DirectoryLogin directory;
    private final AccountLinker accounts;
    private final RbacRoles roles;
    private final KillSwitch killSwitch;

    /** @param directory null when the directory can't be used (LDAP off, or settings with a problem) */
    LoginFlow(LdapSettings settings, DirectoryLogin directory, AccountLinker accounts, RbacRoles roles, KillSwitch killSwitch) {
        this.settings = settings;
        this.directory = directory;
        this.accounts = accounts;
        this.roles = roles;
        this.killSwitch = killSwitch;
    }

    /**
     * @param dryRun a test login: the kill switch and the enabled setting are reported but don't
     *               stop it; nothing is created, linked or assigned, and the refusal line isn't
     *               logged (warnings about rbac or the engine accounts still are)
     */
    LoginResult login(String typed, String password, boolean dryRun) {
        LoginResult result = new LoginResult();
        String name = typed == null ? "" : typed;
        try {
            run(result, name, password, dryRun);
        } catch (RuntimeException e) {
            LOG.error("LDAP sign-in for " + LogText.quote(name) + " failed unexpectedly", e);
            result.step("Sign-in", false, Failures.describe(e)).refused(Reason.UNEXPECTED, null);
        }
        if (!dryRun) {
            log(result, name);
        }
        return result;
    }

    private void run(LoginResult result, String typed, String password, boolean dryRun) {
        String killedBy = killSwitch.source();
        if (killedBy != null) {
            result.step("Kill switch", false, "on (" + killedBy + "): every name uses the local password");
            if (!dryRun) {
                result.local(Reason.KILL_SWITCH);
                return;
            }
        }
        String stripped = typed.strip();
        if (stripped.isEmpty()) {
            result.step("Username", false, "empty").refused(Reason.EMPTY_NAME, null);
            return;
        }
        Lookup account = accounts.lookup(typed);
        if (account.user() != null && createdWithoutRbac(result, account.user().getId())) {
            return;
        }
        if (accounts.isLocalOnly(account, typed)) {
            result.step("Local-only list", true, "the name is on it: the engine checks the local password").local(Reason.LOCAL_ONLY);
            return;
        }
        if (directory == null) {
            outage(result, account, typed, !settings.isValid() || settings.enabled() ? Reason.INVALID_SETTINGS : Reason.TURNED_OFF);
            return;
        }
        if (!settings.enabled()) {
            result.step("Enabled", false, "LDAP is turned off in the settings");
        }
        if (password == null || password.isEmpty()) {
            result.step("Password", false, "empty: refused without asking the directory").refused(Reason.EMPTY_PASSWORD, null);
            return;
        }
        String lookup = accounts.directoryName(stripped);
        if (!lookup.equals(stripped)) {
            result.step("Linked account", true, LogText.quote(stripped) + " signs in as directory user " + LogText.quote(lookup));
        }
        DirectoryLogin.Facts facts = directory.read(lookup, password, result);
        if (facts.refusal() != null) {
            refusedByDirectory(result, facts.refusal(), account, typed);
            return;
        }
        Resolution resolved = accounts.resolve(account, facts.username(), facts.entryId(), dryRun);
        if (resolved.refused()) {
            String detail = resolved.refusal().text + (resolved.detail() == null ? "" : " (" + resolved.detail() + ")");
            result.step("Engine account", false, detail).refused(resolved.refusal(), resolved.detail());
            return;
        }
        if (resolved.toCreate()) {
            create(result, resolved.username(), facts, dryRun);
            return;
        }
        if (createdWithoutRbac(result, resolved.userId())) {
            return;
        }
        result.step("Engine account", true, LogText.quote(resolved.username()));
        if (roles.wanted()) {
            String role = roles.apply(resolved.userId(), facts.groups(), dryRun);
            result.role(role);
            result.step("Role", true, role);
        }
        result.success(resolved.username());
    }

    /**
     * Refuses an account the plugin created while rbac isn't running: without rbac the engine
     * lets every signed-in user do everything. The outage setting doesn't change that.
     */
    private boolean createdWithoutRbac(LoginResult result, int userId) {
        if (!accounts.isCreated(userId) || roles.available()) {
            return false;
        }
        result.step("Role-Based Access Control", false, "not installed or not running; the plugin created this account")
                .refused(Reason.CREATED_NEEDS_RBAC, "engine user id " + userId);
        return true;
    }

    /** No directory: local-only names were handled; directory accounts need the outage setting. */
    private void outage(LoginResult result, Lookup account, String typed, Reason why) {
        result.step("Directory", false, why.text);
        if (!accounts.isDirectoryAccount(account, typed)) {
            result.local(why);
        } else if (settings.outageLocalPasswords()) {
            result.step("Outage", true, "a directory account; outage-local-passwords is on").local(Reason.OUTAGE);
        } else {
            result.refused(Reason.DIRECTORY_OFF, why.text);
        }
    }

    private void refusedByDirectory(LoginResult result, Reason refusal, Lookup account, String typed) {
        boolean directoryAccount = accounts.isDirectoryAccount(account, typed);
        if (refusal == Reason.UNREACHABLE) {
            boolean local = directoryAccount ? settings.outageLocalPasswords() : settings.fallbackToLocal();
            if (local) {
                result.step(directoryAccount ? "Outage" : "Fallback", true, "the directory can't be used");
                result.local(directoryAccount ? Reason.OUTAGE : Reason.FALLBACK);
                return;
            }
        } else if (refusal == Reason.UNKNOWN_USER || (refusal == Reason.BIND_REFUSED && settings.bindMode() == BindMode.TEMPLATE)) {
            // The directory doesn't know the name, or (template binds) can't say: a missing entry and a
            // wrong password look alike. A directory account's entry is known to exist, so it never falls back.
            if (!directoryAccount && settings.fallbackToLocal()) {
                result.step("Fallback", true, "not a directory account: the engine checks the local password").local(Reason.FALLBACK);
                return;
            }
            if (settings.fallbackToLocal()) {
                result.step("Fallback", false, "a directory account, or one that can't be checked");
            }
        }
        result.refused(refusal, null);
    }

    private void create(LoginResult result, String name, DirectoryLogin.Facts facts, boolean dryRun) {
        String problem = roles.creationProblem();
        if (problem != null) {
            LOG.warn("No engine account created for " + LogText.quote(name) + ": " + problem);
            result.step("Engine account", false, "can't be created: " + problem).refused(Reason.CREATION_NOT_ALLOWED, problem);
            return;
        }
        if (dryRun) {
            String role = roles.assignNew(null, facts.groups(), true);
            result.step("Engine account", true, "would create " + LogText.quote(name));
            result.role(role == null ? "no role could be given; the sign-in would be refused" : role);
            result.step("Role", role != null, result.role());
            if (role == null) {
                result.refused(Reason.ROLE_NOT_ASSIGNED, null);
            } else {
                result.success(name);
            }
            return;
        }
        Resolution created = accounts.create(name, facts.entryId(), facts.entry());
        if (created.refused()) {
            result.step("Engine account", false, created.refusal().text).refused(created.refusal(), null);
            return;
        }
        result.step("Engine account", true, "created " + LogText.quote(created.username()));
        String role = roles.assignNew(created.userId(), facts.groups(), false);
        if (role == null) {
            LOG.warn("New engine user " + LogText.quote(created.username()) + " got no role; sign-in refused");
            result.step("Role", false, "none could be given").refused(Reason.ROLE_NOT_ASSIGNED, "engine user id " + created.userId());
            return;
        }
        result.role(role);
        result.step("Role", true, role);
        result.success(created.username());
    }

    private static void log(LoginResult result, String typed) {
        if (result.outcome() == LoginResult.Outcome.REFUSED) {
            String detail = result.logDetail() == null ? "" : " (" + result.logDetail() + ")";
            LOG.info("LDAP sign-in refused for " + LogText.quote(typed) + ": " + result.reason().text + detail);
        } else if (result.outcome() == LoginResult.Outcome.LOCAL) {
            LOG.debug("LDAP sign-in for " + LogText.quote(typed) + " goes to the local password check: " + result.reason().text);
        } else {
            LOG.debug("LDAP sign-in for " + LogText.quote(typed) + " as engine user " + LogText.quote(result.engineUsername()));
        }
        if (LOG.isDebugEnabled()) {
            for (LdapTestStep step : result.steps()) {
                LOG.debug("  " + LogText.clean(step.toString()));
            }
        }
    }
}
