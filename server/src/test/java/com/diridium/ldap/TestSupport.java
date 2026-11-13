// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.function.UnaryOperator;

import com.diridium.rbac.RbacRepository;

/** Settings, a stand-in encryptor, the rbac stand-in and login flows for the tests. */
final class TestSupport {

    static final int ADMIN = 1;
    static final int OPERATOR = 2;
    static final int VIEWER = 3;

    /** Reversible, and the clear text never shows in what it stores. */
    static final SecretCipher CIPHER = new SecretCipher(new SecretCipher.Engine() {
        @Override
        public String encrypt(String clear) {
            return "B64" + Base64.getEncoder().encodeToString(clear.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public String decrypt(String sealed) {
            return new String(Base64.getDecoder().decode(sealed.substring(3)), StandardCharsets.UTF_8);
        }
    });

    static final KillSwitch OFF = new KillSwitch(name -> null, name -> null);

    /** rbac's authorization controller, as far as the plugin reaches into it. */
    public static final class Authorization {
        public final List<Integer> invalidated = new ArrayList<>();

        public void invalidateCache(Integer userId) {
            invalidated.add(userId);
        }
    }

    private TestSupport() {
    }

    /**
     * Template binds as uid={username} under ou=people, the mirth-users group required, and
     * accounts created with rbac's Viewer role as the default.
     */
    static Properties template(TestDirectory directory) {
        Properties p = new Properties();
        p.setProperty(LdapSettings.ENABLED, "true");
        p.setProperty(LdapSettings.URL, directory.url());
        p.setProperty(LdapSettings.BIND_MODE, "template");
        p.setProperty(LdapSettings.USER_DN_TEMPLATE, "uid={username}," + TestDirectory.PEOPLE);
        p.setProperty(LdapSettings.GROUP_SEARCH_BASE, TestDirectory.GROUPS);
        p.setProperty(LdapSettings.GROUP_FILTER, "(&(objectClass=groupOfUniqueNames)(cn=mirth-users)(uniqueMember={dn}))");
        p.setProperty(LdapSettings.RETRIES, "0");
        p.setProperty(LdapSettings.RETRY_INTERVAL_MS, "0");
        p.setProperty(LdapSettings.ORGANIZATION_ATTRIBUTE, "o");
        p.setProperty(LdapSettings.CREATE_USERS, "true");
        p.setProperty(LdapSettings.ROLES_DEFAULT, "Viewer");
        return p;
    }

    /** Search binds through the service account, finding (uid={username}) under ou=people. */
    static Properties search(TestDirectory directory) {
        Properties p = template(directory);
        p.setProperty(LdapSettings.BIND_MODE, "search");
        p.remove(LdapSettings.USER_DN_TEMPLATE);
        p.setProperty(LdapSettings.SERVICE_DN, TestDirectory.SERVICE_DN);
        p.setProperty(LdapSettings.USER_SEARCH_BASE, TestDirectory.PEOPLE);
        p.setProperty(LdapSettings.USER_SEARCH_FILTER, "(uid={username})");
        p.setProperty(LdapSettings.SERVICE_PASSWORD, sealFor(p, TestDirectory.SERVICE_PASSWORD));
        return p;
    }

    /** The password sealed for the connection target of these settings. */
    static String sealFor(Properties p, String password) {
        return CIPHER.seal(password, LdapSettings.parse(p).targetFingerprint());
    }

    /** Opens a stored password with the target of these settings. */
    static String openFor(Properties p) {
        return CIPHER.open(p.getProperty(LdapSettings.SERVICE_PASSWORD), LdapSettings.parse(p).targetFingerprint());
    }

    static Properties with(Properties base, String... keysAndValues) {
        Properties p = new Properties();
        p.putAll(base);
        for (int i = 0; i + 1 < keysAndValues.length; i += 2) {
            p.setProperty(keysAndValues[i], keysAndValues[i + 1]);
        }
        return p;
    }

    static LdapSettings settings(Properties p) {
        LdapSettings settings = LdapSettings.parse(p);
        assertEquals(List.of(), settings.problems(), "test settings must be valid");
        return settings;
    }

    /** A fresh rbac stand-in: Admin (the admin role), Operator and Viewer, nobody assigned. */
    static RbacRepository standardRbac() {
        RbacRepository repository = new RbacRepository();
        repository.roles.put("Admin", ADMIN);
        repository.roles.put("Operator", OPERATOR);
        repository.roles.put("Viewer", VIEWER);
        repository.adminRoleId = ADMIN;
        RbacRepository.instance = repository;
        return repository;
    }

    static RbacRoles roles(LdapSettings settings) {
        return new RbacRoles(settings, RbacRoles.REPOSITORY_CLASS, Authorization::new);
    }

    /** A flow on the settings, with a fresh rbac stand-in installed. */
    static LoginFlow flow(Properties p, StandInUsers users) throws Exception {
        LdapSettings settings = settings(p);
        standardRbac();
        return flow(settings, users, roles(settings), OFF, new ArrayList<>());
    }

    /** @param sleeps receives every pause between attempts */
    static LoginFlow flow(LdapSettings settings, StandInUsers users, RbacRoles roles, KillSwitch killSwitch, List<Long> sleeps)
            throws Exception {
        DirectoryLogin directory = new DirectoryLogin(settings, new DirectoryClient(settings, CIPHER), roles.needsGroups(), sleeps::add);
        return new LoginFlow(settings, directory, new AccountLinker(settings, () -> users, users.links), roles, killSwitch);
    }

    /** A flow for when the directory can't be used: LDAP off, or settings with a problem. */
    static LoginFlow offline(LdapSettings settings, StandInUsers users) {
        return new LoginFlow(settings, null, new AccountLinker(settings, () -> users, users.links), roles(settings), OFF);
    }

    static KillSwitch environment(String variable, String value) {
        UnaryOperator<String> env = name -> name.equals(variable) ? value : null;
        return new KillSwitch(env, name -> null);
    }
}
