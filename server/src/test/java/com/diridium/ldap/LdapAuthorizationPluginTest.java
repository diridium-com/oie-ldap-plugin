// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.rbac.RbacRepository;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * The plugin as the engine sees it: settings at startup and on save, and the
 * LoginStatus it returns. The engine's controller factory is a stand-in set by
 * reflection, as in the upstream probe, so the account code reaches the user
 * controller the way it does in production.
 */
class LdapAuthorizationPluginTest {

    private static TestDirectory directory;
    private StandInUsers users;
    private LogCapture log;
    /** What the engine has stored; {@code update()} reads it back. */
    private final Properties stored = new Properties();
    private final AtomicInteger sweeps = new AtomicInteger();

    @BeforeAll
    static void start() throws Exception {
        directory = TestDirectory.start();
    }

    @AfterAll
    static void stop() {
        directory.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        users = new StandInUsers();
        StandInFactory.install(users);
        TestSupport.standardRbac();
        log = new LogCapture();
    }

    @AfterEach
    void tearDown() throws Exception {
        log.close();
        StandInFactory.uninstall();
        RbacRepository.instance = null;
    }

    private LdapAuthorizationPlugin plugin(KillSwitch killSwitch) {
        return new LdapAuthorizationPlugin(killSwitch, (settings, usable) -> {
            AccountLinker accounts = new AccountLinker(settings, () -> ControllerFactory.getFactory().createUserController(),
                    users.links);
            RbacRoles roles = TestSupport.roles(settings);
            try {
                DirectoryLogin login = usable ? new DirectoryLogin(settings, new DirectoryClient(settings, TestSupport.CIPHER),
                        roles.needsGroups(), millis -> { }) : null;
                return new LoginFlow(settings, login, accounts, roles, killSwitch);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }, () -> {
            Properties copy = new Properties();
            copy.putAll(stored);
            return copy;
        }, TestSupport.CIPHER, sweeps::incrementAndGet);
    }

    private LdapAuthorizationPlugin started(Properties settings) {
        stored.clear();
        stored.putAll(settings);
        LdapAuthorizationPlugin plugin = plugin(TestSupport.OFF);
        plugin.init(settings);
        return plugin;
    }

    /** What the engine's generic plugin properties PUT does: store, then hand the plugin what it got. */
    private void genericPut(LdapAuthorizationPlugin plugin, Properties incoming, boolean merge) {
        if (!merge) {
            stored.clear();
        }
        stored.putAll(incoming);
        plugin.update(incoming);
    }

    @Test
    void thePluginPointNameIsTheNameTheEngineStoresTheSettingsUnder() {
        assertEquals("LDAP Authentication", new LdapAuthorizationPlugin().getPluginPointName());
        assertEquals(LdapServletInterface.PLUGIN_NAME, new LdapAuthorizationPlugin().getPluginPointName());
    }

    @Test
    void theDefaultsHoldEveryKeyWithLdapAndAccountCreationOff() {
        Properties defaults = new LdapAuthorizationPlugin().getDefaultProperties();
        assertEquals(LdapSettings.parse(new Properties()).toProperties(), defaults);
        assertEquals("false", defaults.getProperty(LdapSettings.ENABLED));
        assertEquals("false", defaults.getProperty(LdapSettings.CREATE_USERS));
        assertEquals("false", defaults.getProperty(LdapSettings.OUTAGE_LOCAL_PASSWORDS));
    }

    @Test
    void withTheDefaultsTheEngineChecksEveryPasswordThatIsntADirectoryAccounts() throws Exception {
        assertNull(started(LdapSettings.defaults()).authorizeUser("alice", "alice-pw"));
    }

    @Test
    void aSuccessTellsTheEngineToSignInAsTheDirectoryName() throws Exception {
        LoginStatus status = started(TestSupport.template(directory)).authorizeUser(" ALICE ", "alice-pw");
        assertEquals(LoginStatus.Status.SUCCESS, status.getStatus());
        assertEquals("alice", status.getUpdatedUsername());
    }

    @Test
    void aRefusalIsAFailWithAPlainMessage() throws Exception {
        LoginStatus status = started(TestSupport.template(directory)).authorizeUser("alice", "wrong");
        assertEquals(LoginStatus.Status.FAIL, status.getStatus());
        assertEquals("Incorrect username or password.", status.getMessage());
    }

    @Test
    void probeFinding3AnUnlinkedEngineAccountIsRefusedThroughTheEngineEntryPoint() throws Exception {
        users.add("admin");
        LoginStatus status = started(TestSupport.template(directory)).authorizeUser("admin", "dir-admin-pw");
        assertEquals(LoginStatus.Status.FAIL, status.getStatus());
        assertTrue(status.getMessage().contains("not linked"), status.getMessage());
        assertEquals(List.of(), users.writes);
    }

    @Test
    void savedSettingsApplyWithoutARestart() throws Exception {
        LdapAuthorizationPlugin plugin = started(LdapSettings.defaults());
        assertNull(plugin.authorizeUser("alice", "alice-pw"));
        genericPut(plugin, TestSupport.template(directory), false);
        assertEquals(LoginStatus.Status.SUCCESS, plugin.authorizeUser("alice", "alice-pw").getStatus());
        genericPut(plugin, TestSupport.with(TestSupport.template(directory), LdapSettings.ENABLED, "false"), false);
        assertEquals(LoginStatus.Status.FAIL, plugin.authorizeUser("alice", "alice-pw").getStatus(),
                "alice is a directory account now, so LDAP off refuses her");
    }

    @Test
    void aMergingWriteOfOneKeyDoesntTurnLdapOff() throws Exception {
        LdapAuthorizationPlugin plugin = started(TestSupport.template(directory));
        Properties oneKey = new Properties();
        oneKey.setProperty(LdapSettings.RETRIES, "1");
        genericPut(plugin, oneKey, true);
        assertEquals(LoginStatus.Status.SUCCESS, plugin.authorizeUser("alice", "alice-pw").getStatus());
    }

    @Test
    void ifTheStoredSettingsCantBeReadBackTheSettingsInUseStay() throws Exception {
        AtomicReference<Boolean> broken = new AtomicReference<>(false);
        LdapAuthorizationPlugin plugin = new LdapAuthorizationPlugin(TestSupport.OFF, (settings, usable) -> {
            try {
                return TestSupport.flow(settings, users, TestSupport.roles(settings), TestSupport.OFF, new java.util.ArrayList<>());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }, () -> {
            if (broken.get()) {
                throw new IllegalStateException("database down");
            }
            return TestSupport.template(directory);
        }, TestSupport.CIPHER, () -> { });
        plugin.init(TestSupport.template(directory));
        broken.set(true);
        plugin.update(new Properties());
        assertEquals(LoginStatus.Status.SUCCESS, plugin.authorizeUser("alice", "alice-pw").getStatus());
        assertTrue(LogCapture.text(log.at(Level.ERROR).get(0)).contains("could not be read back"));
    }

    @Test
    void aGenericWriteThatChangesTheUrlCantSendTheServicePasswordAnywhere() throws Exception {
        try (TestDirectory elsewhere = TestDirectory.start(); WireRecorder wire = new WireRecorder(elsewhere.port("ldap"))) {
            LdapAuthorizationPlugin plugin = started(TestSupport.search(directory));
            assertEquals(LoginStatus.Status.SUCCESS, plugin.authorizeUser("alice", "alice-pw").getStatus());
            // The generic GET hands out the sealed password; the PUT sends it back with another url.
            Properties generic = TestSupport.with(stored, LdapSettings.URL, "ldap://127.0.0.1:" + wire.port());
            log.clear();
            genericPut(plugin, generic, false);
            String error = LogCapture.text(log.at(Level.ERROR).get(0));
            assertTrue(error.contains("Enter it again"), error);
            assertEquals(LoginStatus.Status.FAIL, plugin.authorizeUser("alice", "alice-pw").getStatus());
            assertNull(plugin.authorizeUser("bob", "bob-pw"), "not a directory account: the engine checks it");
            assertFalse(wire.clientSent(TestDirectory.SERVICE_DN));
            assertFalse(wire.clientSent(TestDirectory.SERVICE_PASSWORD));
        }
    }

    @Test
    void storedSettingsWithAClearPasswordTurnLdapOffAndSaySo() throws Exception {
        Properties clear = TestSupport.with(TestSupport.search(directory), LdapSettings.SERVICE_PASSWORD, "in-clear");
        LdapAuthorizationPlugin plugin = started(clear);
        assertNull(plugin.authorizeUser("alice", "alice-pw"));
        String error = LogCapture.text(log.at(Level.ERROR).get(0));
        assertTrue(error.contains("stored in clear"), error);
        assertFalse(error.contains("in-clear"), "the password itself is not logged: " + error);
    }

    @Test
    void theKillSwitchIsLoggedAtStartupOnEverySaveAndWhenItChanges() throws Exception {
        AtomicReference<String> property = new AtomicReference<>("true");
        KillSwitch killSwitch = new KillSwitch(name -> null, name -> name.equals(KillSwitch.SYSTEM_PROPERTY) ? property.get() : null);
        stored.putAll(TestSupport.template(directory));
        LdapAuthorizationPlugin plugin = plugin(killSwitch);
        plugin.init(TestSupport.template(directory));
        plugin.update(TestSupport.template(directory));
        assertEquals(2, killSwitchLines().size());
        assertTrue(killSwitchLines().get(0).contains(KillSwitch.SYSTEM_PROPERTY));
        assertNull(plugin.authorizeUser("alice", "wrong"));
        assertEquals(2, killSwitchLines().size(), "no new line while it stays on");
        property.set(null);
        assertEquals(LoginStatus.Status.FAIL, plugin.authorizeUser("alice", "wrong").getStatus());
        assertTrue(killSwitchLines().get(2).contains("off again"));
        property.set("true");
        assertNull(plugin.authorizeUser("alice", "wrong"));
        assertEquals(4, killSwitchLines().size());
    }

    private List<String> killSwitchLines() {
        return log.at(Level.WARN).stream().map(LogCapture::text)
                .filter(text -> text.startsWith("LDAP sign-in is turned off by") || text.startsWith("The LDAP kill switch is off again"))
                .toList();
    }

    @Test
    void theOutageSettingIsLoggedAtStartupAndOnSave() throws Exception {
        Properties outage = TestSupport.with(TestSupport.template(directory), LdapSettings.OUTAGE_LOCAL_PASSWORDS, "true");
        LdapAuthorizationPlugin plugin = started(outage);
        genericPut(plugin, outage, false);
        assertEquals(2, log.at(Level.WARN).stream().filter(e -> LogCapture.text(e).contains("outage-local-passwords: on")).count());
    }

    @Test
    void withLdapOffADirectoryAccountIsRefusedAndAnyOtherGoesToTheEngine() throws Exception {
        User alice = users.add("alice");
        users.links.link(alice.getId(), "entry-of-alice");
        users.add("ops");
        LdapAuthorizationPlugin plugin = started(TestSupport.with(TestSupport.template(directory), LdapSettings.ENABLED, "false"));
        assertEquals(LoginStatus.Status.FAIL, plugin.authorizeUser("alice", "her-old-engine-pw").getStatus());
        assertNull(plugin.authorizeUser("ops", "pw"));
    }

    @Test
    void startChecksTheAccountLinks() {
        try {
            plugin(TestSupport.OFF).start();
        } catch (LinkageError expected) {
            // registering the REST types needs the engine's XStream, which the tests don't load
        }
        assertEquals(1, sweeps.get());
    }

    @Test
    void anEngineFailureIsARefusalNeverAFallback() throws Exception {
        StandInFactory.install(new StandInUsers() {
            @Override
            public User getUser(Integer userId, String userName) throws com.mirth.connect.client.core.ControllerException {
                throw new com.mirth.connect.client.core.ControllerException("database down");
            }
        });
        Properties fallback = TestSupport.with(TestSupport.template(directory), LdapSettings.FALLBACK_TO_LOCAL, "true");
        LoginStatus status = started(fallback).authorizeUser("ops", "wrong");
        assertEquals(LoginStatus.Status.FAIL, status.getStatus(), "a refused bind reaches the fallback, which refuses an unknown account");
    }

    @Test
    void thePluginRegistersItsPermission() {
        assertEquals(1, new LdapAuthorizationPlugin().getExtensionPermissions().length);
    }

    @Test
    void storedSettingsWithoutAnySignInFilterTurnLdapOff() throws Exception {
        LdapAuthorizationPlugin plugin = started(TestSupport.with(TestSupport.template(directory), LdapSettings.GROUP_FILTER, "",
                LdapSettings.CREATE_USERS, "false"));
        assertTrue(LogCapture.text(log.at(Level.ERROR).get(0)).contains(LdapSettings.LOGIN_FILTER + ": needed"));
        assertNull(plugin.authorizeUser("bob", "bob-pw"), "LDAP is off, and bob isn't a directory account");
    }
}
