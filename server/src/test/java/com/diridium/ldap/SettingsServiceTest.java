// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.diridium.rbac.RbacRepository;

/**
 * Getting, saving and testing settings: the service password masked on the way
 * out, sealed on the way in, a masked value keeping the stored one, nothing saved
 * when anything is wrong, and no password in any audit event.
 */
class SettingsServiceTest {

    private static TestDirectory directory;
    private static String otherCa;

    private final Properties stored = new Properties();
    private final List<Properties> applied = new ArrayList<>();
    private final List<String> audits = new ArrayList<>();
    private final StandInUsers users = new StandInUsers();

    private final SettingsService service = new SettingsService(new SettingsService.Store() {
        @Override
        public Properties load() {
            Properties copy = new Properties();
            copy.putAll(stored);
            return copy;
        }

        @Override
        public void save(Properties properties) {
            stored.clear();
            stored.putAll(properties);
        }

        @Override
        public void apply(Properties properties) {
            applied.add(properties);
        }
    }, TestSupport.CIPHER, (settings, usable) -> {
        try {
            return TestSupport.flow(settings, users, TestSupport.roles(settings), TestSupport.OFF, new ArrayList<>());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }, (action, attributes, success) -> audits.add(action + " " + success + " " + attributes),
            new SaveGuard(() -> users, users.links, TestSupport::roles));

    /** The engine account saving the settings. */
    private Integer saver;

    @BeforeAll
    static void start() throws Exception {
        directory = TestDirectory.start();
        otherCa = new TestCertificates("some CA").caPem();
    }

    @AfterAll
    static void stop() {
        directory.close();
        RbacRepository.instance = null;
    }

    @BeforeEach
    void setUp() {
        TestSupport.standardRbac();
        saver = users.add("admin").getId();
    }

    private List<String> save(Properties settings) throws Exception {
        return service.save(settings, saver);
    }

    private static Properties searchWithClearPassword(String password) {
        return TestSupport.with(TestSupport.search(directory), LdapSettings.SERVICE_PASSWORD, password);
    }

    @Test
    void theStoredPasswordIsMaskedOnTheWayOut() throws Exception {
        stored.putAll(TestSupport.search(directory));
        Properties shown = service.getMasked();
        assertEquals(LdapSettings.SECRET_MASK, shown.getProperty(LdapSettings.SERVICE_PASSWORD));
        assertEquals(TestDirectory.SERVICE_DN, shown.getProperty(LdapSettings.SERVICE_DN));
        assertEquals("uid", shown.getProperty(LdapSettings.USERNAME_ATTRIBUTE), "defaults fill in missing keys");
        stored.setProperty(LdapSettings.SERVICE_PASSWORD, "");
        assertEquals("", service.getMasked().getProperty(LdapSettings.SERVICE_PASSWORD));
    }

    @Test
    void aNewPasswordIsSealedAndNeverStoredInClear() throws Exception {
        save(searchWithClearPassword("s3cret-service"));
        String saved = stored.getProperty(LdapSettings.SERVICE_PASSWORD);
        assertTrue(saved.startsWith(LdapSettings.SEALED_PREFIX), saved);
        assertFalse(stored.toString().contains("s3cret-service"));
        assertEquals("s3cret-service", TestSupport.openFor(stored));
        assertEquals(1, applied.size());
        assertEquals(stored, applied.get(0));
    }

    @Test
    void savingTheMaskOrLeavingThePasswordOutKeepsTheStoredOne() throws Exception {
        save(searchWithClearPassword(TestDirectory.SERVICE_PASSWORD));
        String sealed = stored.getProperty(LdapSettings.SERVICE_PASSWORD);
        save(searchWithClearPassword(LdapSettings.SECRET_MASK));
        assertEquals(sealed, stored.getProperty(LdapSettings.SERVICE_PASSWORD));
        Properties without = TestSupport.search(directory);
        without.remove(LdapSettings.SERVICE_PASSWORD);
        save(without);
        assertEquals(sealed, stored.getProperty(LdapSettings.SERVICE_PASSWORD));
    }

    @Test
    void aSubmittedValueThatLooksSealedIsSealedAnyway() throws Exception {
        save(searchWithClearPassword("enc:not-really"));
        assertEquals("enc:not-really", TestSupport.openFor(stored));
    }

    @Test
    void settingsWithProblemsAreNotSavedOrApplied() throws Exception {
        stored.putAll(TestSupport.template(directory));
        Properties before = new Properties();
        before.putAll(stored);
        Properties bad = TestSupport.with(TestSupport.template(directory), LdapSettings.RETRIES, "99",
                LdapSettings.URL, "http://wrong");
        SettingsService.Rejected rejected = assertThrows(SettingsService.Rejected.class, () -> save(bad));
        assertEquals(2, rejected.problems().size(), rejected.problems().toString());
        assertEquals(before, stored);
        assertEquals(List.of(), applied);
        assertTrue(audits.get(0).contains("false"), audits.toString());
    }

    @Test
    void theAuditShowsTheChangeButNeverThePassword() throws Exception {
        save(TestSupport.with(searchWithClearPassword("s3cret-service"), LdapSettings.LINKED_ACCOUNTS, "admin=jdoe"));
        String sealed = stored.getProperty(LdapSettings.SERVICE_PASSWORD);
        assertEquals(1, audits.size());
        String audit = audits.get(0);
        assertTrue(audit.contains("linked-accounts=admin=jdoe"), audit);
        assertTrue(audit.contains("service-password=" + LdapSettings.SECRET_MASK), audit);
        assertFalse(audit.contains("s3cret-service"), audit);
        assertFalse(audit.contains(sealed), audit);
    }

    @Test
    void theConnectionTestUsesTheStoredPasswordForTheMask() throws Exception {
        save(searchWithClearPassword(TestDirectory.SERVICE_PASSWORD));
        LdapTestResult result = service.testConnection(searchWithClearPassword(LdapSettings.SECRET_MASK));
        assertTrue(result.isSuccess(), result.getSteps().toString());
        LdapTestResult wrong = service.testConnection(searchWithClearPassword("wrong"));
        assertFalse(wrong.isSuccess());
        assertTrue(wrong.getSteps().toString().contains("FAIL Connect"), wrong.getSteps().toString());
    }

    @Test
    void theConnectionTestReportsSettingsProblemsWithoutConnecting() {
        directory.drain();
        LdapTestResult result = service.testConnection(TestSupport.with(TestSupport.template(directory), LdapSettings.URL, ""));
        assertFalse(result.isSuccess());
        assertTrue(result.getSteps().get(0).getDetail().contains("url"), result.getSteps().toString());
        assertEquals(List.of(), directory.drain());
    }

    @Test
    void theLoginTestReportsWhatASignInWouldDoAndWritesNothing() {
        LdapTestResult result = service.testLogin(new LdapTestLoginRequest(TestSupport.template(directory), "ALICE", "alice-pw"));
        assertTrue(result.isSuccess(), result.getSteps().toString());
        assertEquals("alice", result.getEngineUsername());
        assertEquals("uid=alice," + TestDirectory.PEOPLE, result.getDn());
        assertFalse(result.getEntryId().isEmpty());
        assertEquals(List.of(), users.writes);
        assertTrue(audits.get(0).contains("username=ALICE"), audits.toString());
        assertFalse(audits.get(0).contains("alice-pw"), audits.toString());
    }

    @Test
    void theLoginTestRunsWhileLdapIsStillTurnedOff() {
        Properties off = TestSupport.with(TestSupport.template(directory), LdapSettings.ENABLED, "false");
        assertTrue(service.testLogin(new LdapTestLoginRequest(off, "alice", "alice-pw")).isSuccess());
    }

    @Test
    void theLoginTestExplainsARefusal() {
        LdapTestResult result = service.testLogin(new LdapTestLoginRequest(TestSupport.template(directory), "bob", "bob-pw"));
        assertFalse(result.isSuccess());
        assertTrue(result.getMessage().contains(LoginResult.Reason.NOT_IN_GROUP.text), result.getMessage());
    }

    /** Search settings with one connection-target field changed to another valid value, and the mask. */
    private static Properties targetChanged(String field) {
        Properties p = searchWithClearPassword(LdapSettings.SECRET_MASK);
        switch (field) {
        case LdapSettings.URL:
            p.setProperty(LdapSettings.URL, "ldap://127.0.0.1:" + directory.port("ldap"));
            break;
        case LdapSettings.STARTTLS:
            p.setProperty(LdapSettings.STARTTLS, "true");
            break;
        case LdapSettings.CA_CERTIFICATE:
            p.setProperty(LdapSettings.CA_CERTIFICATE, otherCa);
            break;
        case LdapSettings.BIND_MODE:
            p.setProperty(LdapSettings.BIND_MODE, "template");
            p.setProperty(LdapSettings.USER_DN_TEMPLATE, "uid={username}," + TestDirectory.PEOPLE);
            break;
        case LdapSettings.SERVICE_DN:
            p.setProperty(LdapSettings.SERVICE_DN, "cn=other," + TestDirectory.BASE);
            break;
        default:
            throw new IllegalArgumentException(field);
        }
        return p;
    }

    private void storeSearchSettings() throws Exception {
        save(searchWithClearPassword(TestDirectory.SERVICE_PASSWORD));
        audits.clear();
        applied.clear();
        directory.drain();
    }

    @ParameterizedTest
    @ValueSource(strings = { LdapSettings.URL, LdapSettings.STARTTLS, LdapSettings.CA_CERTIFICATE, LdapSettings.BIND_MODE,
            LdapSettings.SERVICE_DN })
    void savingAChangedTargetWithTheMaskClearsTheStoredPassword(String field) throws Exception {
        storeSearchSettings();
        save(TestSupport.with(targetChanged(field), LdapSettings.ENABLED, "false"));
        assertEquals("", stored.getProperty(LdapSettings.SERVICE_PASSWORD), field);
    }

    @ParameterizedTest
    @ValueSource(strings = { LdapSettings.URL, LdapSettings.STARTTLS, LdapSettings.CA_CERTIFICATE, LdapSettings.SERVICE_DN })
    void aSaveThatNeedsTheClearedPasswordIsRefusedWithTheReason(String field) throws Exception {
        storeSearchSettings();
        Properties before = new Properties();
        before.putAll(stored);
        SettingsService.Rejected rejected = assertThrows(SettingsService.Rejected.class, () -> save(targetChanged(field)));
        assertEquals(ServicePassword.RETYPE, rejected.problems().get(0), field);
        assertEquals(before, stored);
        assertEquals(List.of(), applied);
    }

    @ParameterizedTest
    @ValueSource(strings = { LdapSettings.URL, LdapSettings.STARTTLS, LdapSettings.CA_CERTIFICATE, LdapSettings.BIND_MODE,
            LdapSettings.SERVICE_DN })
    void aConnectionTestToAChangedTargetNeverUsesTheStoredPassword(String field) throws Exception {
        storeSearchSettings();
        LdapTestResult result = service.testConnection(targetChanged(field));
        assertFalse(result.isSuccess(), field);
        assertTrue(result.getMessage().startsWith("Enter the service password"), result.getMessage());
        assertEquals(List.of(), directory.drain(), "nothing reaches the directory");
    }

    @ParameterizedTest
    @ValueSource(strings = { LdapSettings.URL, LdapSettings.STARTTLS, LdapSettings.CA_CERTIFICATE, LdapSettings.BIND_MODE,
            LdapSettings.SERVICE_DN })
    void aLoginTestToAChangedTargetNeverUsesTheStoredPassword(String field) throws Exception {
        storeSearchSettings();
        LdapTestResult result = service.testLogin(new LdapTestLoginRequest(targetChanged(field), "alice", "alice-pw"));
        assertFalse(result.isSuccess(), field);
        assertTrue(result.getMessage().startsWith("Enter the service password"), result.getMessage());
        assertEquals(List.of(), directory.drain(), "nothing reaches the directory");
    }

    @Test
    void controlTheSameTargetKeepsTheStoredPasswordForAllThreeOperations() throws Exception {
        storeSearchSettings();
        String sealed = stored.getProperty(LdapSettings.SERVICE_PASSWORD);
        Properties masked = TestSupport.with(searchWithClearPassword(LdapSettings.SECRET_MASK), LdapSettings.RETRIES, "1");
        assertTrue(service.testConnection(masked).isSuccess());
        LdapTestResult login = service.testLogin(new LdapTestLoginRequest(masked, "alice", "alice-pw"));
        assertTrue(login.isSuccess(), login.getSteps().toString());
        save(masked);
        assertEquals(sealed, stored.getProperty(LdapSettings.SERVICE_PASSWORD));
    }

    @Test
    void controlATypedPasswordWorksWithAChangedTarget() throws Exception {
        storeSearchSettings();
        Properties typed = TestSupport.with(targetChanged(LdapSettings.URL), LdapSettings.SERVICE_PASSWORD, TestDirectory.SERVICE_PASSWORD);
        assertTrue(service.testConnection(typed).isSuccess());
        assertTrue(service.testLogin(new LdapTestLoginRequest(typed, "alice", "alice-pw")).isSuccess());
    }

    @Test
    void anEmptyLocalOnlyListSavesWithAWarningThatIsReturnedAndAudited() throws Exception {
        List<String> warnings = save(TestSupport.template(directory));
        assertTrue(warnings.stream().anyMatch(w -> w.startsWith(LdapSettings.LOCAL_ONLY_USERNAMES + ": empty")), warnings.toString());
        assertTrue(audits.get(audits.size() - 1).contains("warnings="), audits.toString());
    }

    @Test
    void aSaveIsRefusedWhenTheSaverCouldNotSignInUnderIt() throws Exception {
        Properties others = TestSupport.with(TestSupport.template(directory), LdapSettings.LOCAL_ONLY_USERNAMES, "ops");
        SettingsService.Rejected rejected = assertThrows(SettingsService.Rejected.class, () -> save(others));
        assertTrue(rejected.problems().get(0).contains("you could not sign in") && rejected.problems().get(0).contains("\"admin\""),
                rejected.problems().toString());
        assertEquals(List.of(), applied);
    }

    @Test
    void theSaverMayBeOnTheLocalOnlyListOrLinked() throws Exception {
        save(TestSupport.with(TestSupport.template(directory), LdapSettings.LOCAL_ONLY_USERNAMES, "ops, ADMIN"));
        users.links.link(saver, "entry-of-admin");
        save(TestSupport.with(TestSupport.template(directory), LdapSettings.LOCAL_ONLY_USERNAMES, "ops"));
        assertEquals(2, applied.size());
    }

    @Test
    void theSaverCheckOnlyAppliesWithLdapOn() throws Exception {
        save(TestSupport.with(TestSupport.template(directory), LdapSettings.LOCAL_ONLY_USERNAMES, "ops", LdapSettings.ENABLED, "false"));
        assertEquals(1, applied.size());
    }

    @Test
    void creatingAccountsIsRefusedWithoutRbacOrAUsableDefaultRole() throws Exception {
        Properties creating = TestSupport.template(directory);
        RbacRepository.instance = null;
        assertTrue(assertThrows(SettingsService.Rejected.class, () -> save(creating)).problems().get(0)
                .contains("not installed or not started"));
        TestSupport.standardRbac();
        assertTrue(assertThrows(SettingsService.Rejected.class,
                () -> save(TestSupport.with(creating, LdapSettings.ROLES_DEFAULT, "Missing"))).problems().get(0).contains("names no"));
        assertTrue(assertThrows(SettingsService.Rejected.class,
                () -> save(TestSupport.with(creating, LdapSettings.ROLES_DEFAULT, "Admin"))).problems().get(0).contains("admin role"));
        assertEquals(List.of(), applied);
    }

    @Test
    void theAdminRoleIsNeverAcceptedAsTheDefaultEvenWithoutAccountCreation() {
        Properties p = TestSupport.with(TestSupport.template(directory), LdapSettings.CREATE_USERS, "false",
                LdapSettings.ROLES_DEFAULT, "Admin");
        assertTrue(assertThrows(SettingsService.Rejected.class, () -> save(p)).problems().get(0).contains("admin role"));
    }

    @Test
    void plainLdapWithoutStartTlsIsAWarning() throws Exception {
        assertTrue(save(TestSupport.template(directory)).stream().anyMatch(w -> w.contains("in clear")));
    }

    @Test
    void theOutageSettingIsNamedInTheWarningsAndTheAudit() throws Exception {
        List<String> warnings = save(TestSupport.with(TestSupport.template(directory), LdapSettings.OUTAGE_LOCAL_PASSWORDS, "true"));
        assertTrue(warnings.stream().anyMatch(w -> w.startsWith(LdapSettings.OUTAGE_LOCAL_PASSWORDS)), warnings.toString());
        String audit = audits.get(audits.size() - 1);
        assertTrue(audit.contains("outage-local-passwords=true") && audit.contains(LdapSettings.OUTAGE_LOCAL_PASSWORDS + ": on"), audit);
    }

    @Test
    void aStoredPasswordThatNoLongerOpensIsRefusedOnSave() throws Exception {
        storeSearchSettings();
        // Changed behind the settings screen: the stored password was sealed for another url.
        stored.setProperty(LdapSettings.URL, "ldap://127.0.0.1:" + directory.port("ldap"));
        Properties sameAsStored = new Properties();
        sameAsStored.putAll(stored);
        sameAsStored.setProperty(LdapSettings.SERVICE_PASSWORD, LdapSettings.SECRET_MASK);
        SettingsService.Rejected rejected = assertThrows(SettingsService.Rejected.class, () -> save(sameAsStored));
        assertEquals(ServicePassword.WRONG_TARGET, rejected.problems().get(0));
    }

    @Test
    void withLdapOnASaveWithoutAnySignInFilterIsRefused() {
        Properties none = TestSupport.with(TestSupport.template(directory), LdapSettings.GROUP_FILTER, "",
                LdapSettings.CREATE_USERS, "false");
        SettingsService.Rejected rejected = assertThrows(SettingsService.Rejected.class, () -> save(none));
        assertTrue(rejected.problems().get(0).startsWith(LdapSettings.LOGIN_FILTER + ": needed"), rejected.problems().toString());
        assertEquals(List.of(), applied);
    }
}
