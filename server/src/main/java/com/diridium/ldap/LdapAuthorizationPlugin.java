// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.plugins.AuthorizationPlugin;
import com.mirth.connect.plugins.ServicePlugin;

/**
 * The engine's entry point: signs users in against the directory and takes new
 * settings without a restart. The engine allows one authorization plugin, so this
 * plugin and any other (OIDC, for one) can't be installed together.
 *
 * <p>The engine stores the settings under the plugin.xml name, calls {@link #init}
 * with them at startup, and calls {@link #update} when they are saved through
 * {@code ExtensionController.updatePluginProperties}, which finds this plugin by
 * {@link #getPluginPointName()}; that is why it returns the same name. {@code update}
 * reads the stored settings back instead of trusting what it is handed, which can be
 * only the changed keys.</p>
 *
 * <p>{@link #authorizeUser} returns null (the engine checks the local password) when the
 * kill switch is on, and otherwise as {@link LoginFlow} decides. Anything unexpected is
 * a refusal.</p>
 */
public class LdapAuthorizationPlugin implements AuthorizationPlugin, ServicePlugin {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthorizationPlugin.class);
    private static final String NOT_SEEN = "(not seen yet)";

    private final KillSwitch killSwitch;
    private final LoginFlow.Factory flows;
    private final Supplier<Properties> storedSettings;
    private final SecretCipher cipher;
    private final Runnable linkSweep;
    private final AtomicReference<String> killSwitchSeen = new AtomicReference<>(NOT_SEEN);
    private volatile LoginFlow flow;

    public LdapAuthorizationPlugin() {
        this(KillSwitch.system(), EngineWiring::flow, EngineWiring::storedSettings, SecretCipher.engine(), EngineWiring::sweepLinks);
    }

    LdapAuthorizationPlugin(KillSwitch killSwitch, LoginFlow.Factory flows, Supplier<Properties> storedSettings,
            SecretCipher cipher, Runnable linkSweep) {
        this.killSwitch = killSwitch;
        this.flows = flows;
        this.storedSettings = storedSettings;
        this.cipher = cipher;
        this.linkSweep = linkSweep;
    }

    @Override
    public String getPluginPointName() {
        return LdapServletInterface.PLUGIN_NAME;
    }

    @Override
    public void init(Properties properties) {
        apply(properties, "at startup");
    }

    @Override
    public void update(Properties properties) {
        Properties stored;
        try {
            stored = storedSettings.get();
        } catch (RuntimeException e) {
            LOG.error("The saved LDAP settings could not be read back, so the settings in use stay as they were: "
                    + Failures.describe(e));
            return;
        }
        apply(stored, "after the save");
    }

    @Override
    public void start() {
        try {
            linkSweep.run();
        } catch (RuntimeException e) {
            LOG.warn("Account links not checked: " + Failures.describe(e));
        }
        LdapSerialization.register();
    }

    @Override
    public void stop() {
        // nothing held open between sign-ins
    }

    @Override
    public Properties getDefaultProperties() {
        return LdapSettings.defaults();
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return LdapPermissionsProvider.permissions();
    }

    @Override
    public LoginStatus authorizeUser(String username, String plainPassword) {
        if (watchKillSwitch(false) != null) {
            return null;
        }
        LoginFlow current = flow;
        if (current == null) {
            return null;
        }
        LoginResult result;
        try {
            result = current.login(username, plainPassword, false);
        } catch (RuntimeException e) {
            LOG.error("LDAP sign-in failed unexpectedly", e);
            return new LoginStatus(LoginStatus.Status.FAIL, LoginResult.Reason.UNEXPECTED.userMessage);
        }
        switch (result.outcome()) {
        case SUCCESS:
            return new LoginStatus(LoginStatus.Status.SUCCESS, "", result.engineUsername());
        case REFUSED:
            return new LoginStatus(LoginStatus.Status.FAIL, result.userMessage());
        default:
            return null;
        }
    }

    /**
     * Logs the kill switch at WARN: every time when {@code always}, otherwise when it changed since
     * last seen, which a script can do at runtime with the system property.
     *
     * @return what turned it on, or null when it is off
     */
    private String watchKillSwitch(boolean always) {
        String now = killSwitch.source();
        String before = killSwitchSeen.getAndSet(now == null ? "" : now);
        boolean changed = !Objects.equals(before, now == null ? "" : now);
        if (now != null && (always || changed)) {
            LOG.warn("LDAP sign-in is turned off by the " + now
                    + ": every user signs in with the engine's own password check. The stored settings are unchanged.");
        } else if (now == null && changed && !NOT_SEEN.equals(before)) {
            LOG.warn("The LDAP kill switch is off again: sign-in follows the LDAP settings.");
        }
        return now;
    }

    private void apply(Properties properties, String when) {
        watchKillSwitch(true);
        LdapSettings settings = LdapSettings.parse(properties);
        for (String warning : settings.warnings()) {
            LOG.warn("LDAP settings " + when + ": " + warning);
        }
        String problem = !settings.isValid() ? String.join(" ", settings.problems()) : ServicePassword.unusable(settings, cipher);
        boolean usable = problem == null && settings.enabled();
        LoginFlow built;
        try {
            built = flows.build(settings, usable);
        } catch (RuntimeException e) {
            problem = Failures.describe(e);
            built = flows.build(settings, false);
        }
        flow = built;
        if (problem != null) {
            LOG.error("LDAP sign-in is off " + when + ": " + problem + " Directory accounts are refused"
                    + (settings.outageLocalPasswords() ? ", or use their engine passwords (outage-local-passwords is on)." : "."));
        } else if (!settings.enabled()) {
            LOG.info("LDAP sign-in is off " + when + " (" + LdapSettings.ENABLED + " is false)");
        } else {
            LOG.info("LDAP sign-in is on " + when + ": " + settings.bindMode().name().toLowerCase(Locale.ROOT) + " bind to "
                    + String.join(" ", settings.urls()) + (settings.startTls() ? " with StartTLS" : ""));
        }
    }
}
