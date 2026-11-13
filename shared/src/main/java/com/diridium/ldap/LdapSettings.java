// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * The plugin's settings, stored as the plugin's properties in the engine's
 * CONFIGURATION table. Immutable: {@link #parse(Properties)} reads them and
 * {@link #toProperties()} writes them back. Parsing never throws; everything
 * wrong is listed in {@link #problems()}, worded for the settings screen.
 * Settings with problems are never used to sign anyone in.
 */
public final class LdapSettings {

    public static final String ENABLED = "enabled";
    public static final String URL = "url";
    public static final String STARTTLS = "starttls";
    public static final String CA_CERTIFICATE = "ca-certificate";
    public static final String CONNECT_TIMEOUT_MS = "connect-timeout-ms";
    public static final String READ_TIMEOUT_MS = "read-timeout-ms";
    public static final String RETRIES = "retries";
    public static final String RETRY_INTERVAL_MS = "retry-interval-ms";
    public static final String BIND_MODE = "bind-mode";
    public static final String USER_DN_TEMPLATE = "user-dn-template";
    public static final String SERVICE_DN = "service-dn";
    public static final String SERVICE_PASSWORD = "service-password";
    public static final String USER_SEARCH_BASE = "user-search-base";
    public static final String USER_SEARCH_FILTER = "user-search-filter";
    public static final String USERNAME_ATTRIBUTE = "username-attribute";
    public static final String ENTRY_ID_ATTRIBUTE = "entry-id-attribute";
    public static final String GROUP_SEARCH_BASE = "group-search-base";
    public static final String GROUP_FILTER = "group-filter";
    public static final String LOGIN_FILTER = "login-filter";
    public static final String CREATE_USERS = "create-users";
    public static final String FIRST_NAME_ATTRIBUTE = "first-name-attribute";
    public static final String LAST_NAME_ATTRIBUTE = "last-name-attribute";
    public static final String EMAIL_ATTRIBUTE = "email-attribute";
    public static final String ORGANIZATION_ATTRIBUTE = "organization-attribute";
    public static final String LINKED_ACCOUNTS = "linked-accounts";
    public static final String LOCAL_ONLY_USERNAMES = "local-only-usernames";
    public static final String FALLBACK_TO_LOCAL = "fallback-to-local-for-unknown-users";
    public static final String OUTAGE_LOCAL_PASSWORDS = "outage-local-passwords";
    public static final String ROLES_GROUP_ATTRIBUTE = "roles.group-attribute";
    public static final String ROLES_MEMBER_FILTER = "roles.member-filter";
    public static final String ROLES_MAP = "roles.map";
    public static final String ROLES_DEFAULT = "roles.default";
    public static final String ROLES_SYNC = "roles.sync";

    /** What the settings screen shows instead of a stored service password; saving it keeps the stored one. */
    public static final String SECRET_MASK = "********";
    /** PERSON.USERNAME holds 40 characters on every database the engine supports. */
    public static final int MAX_USERNAME_LENGTH = 40;
    /** entry-id-attribute value that reads entryUUID, then objectGUID. */
    public static final String ENTRY_ID_AUTO = "auto";
    /** Prefix of a service password sealed with the engine's encryptor; anything else is clear text. */
    public static final String SEALED_PREFIX = "enc:";

    public enum BindMode { TEMPLATE, SEARCH }

    public enum RoleSync { ALWAYS, JIT_ONLY, NEVER }

    private static final Properties DEFAULTS = new Properties();

    static {
        String[][] defaults = {
            { ENABLED, "false" }, { URL, "" }, { STARTTLS, "false" }, { CA_CERTIFICATE, "" },
            { CONNECT_TIMEOUT_MS, "5000" }, { READ_TIMEOUT_MS, "10000" }, { RETRIES, "2" },
            { RETRY_INTERVAL_MS, "500" }, { BIND_MODE, "template" }, { USER_DN_TEMPLATE, "" },
            { SERVICE_DN, "" }, { SERVICE_PASSWORD, "" }, { USER_SEARCH_BASE, "" }, { USER_SEARCH_FILTER, "" },
            { USERNAME_ATTRIBUTE, "uid" }, { ENTRY_ID_ATTRIBUTE, ENTRY_ID_AUTO }, { GROUP_SEARCH_BASE, "" },
            { GROUP_FILTER, "" }, { LOGIN_FILTER, "" }, { CREATE_USERS, "false" }, { FIRST_NAME_ATTRIBUTE, "givenName" },
            { LAST_NAME_ATTRIBUTE, "sn" }, { EMAIL_ATTRIBUTE, "mail" }, { ORGANIZATION_ATTRIBUTE, "" },
            { LINKED_ACCOUNTS, "" }, { LOCAL_ONLY_USERNAMES, "" }, { FALLBACK_TO_LOCAL, "false" },
            { OUTAGE_LOCAL_PASSWORDS, "false" },
            { ROLES_GROUP_ATTRIBUTE, "cn" },
            { ROLES_MEMBER_FILTER, "(|(member={dn})(uniqueMember={dn})(memberUid={username}))" },
            { ROLES_MAP, "" }, { ROLES_DEFAULT, "" }, { ROLES_SYNC, "always" },
        };
        for (String[] d : defaults) {
            DEFAULTS.setProperty(d[0], d[1]);
        }
    }

    final boolean enabled;
    final List<String> urls;
    final boolean startTls;
    final String caCertificate;
    final int connectTimeoutMs;
    final int readTimeoutMs;
    final int retries;
    final int retryIntervalMs;
    final BindMode bindMode;
    final String userDnTemplate;
    final String serviceDn;
    final String servicePassword;
    final String userSearchBase;
    final String userSearchFilter;
    final String usernameAttribute;
    final String entryIdAttribute;
    final String groupSearchBase;
    final String groupFilter;
    final String loginFilter;
    final boolean createUsers;
    final String firstNameAttribute;
    final String lastNameAttribute;
    final String emailAttribute;
    final String organizationAttribute;
    final List<NamePair> linkedAccounts;
    final Set<String> localOnlyUsernames;
    final boolean fallbackToLocal;
    final boolean outageLocalPasswords;
    final String rolesGroupAttribute;
    final String rolesMemberFilter;
    final List<NamePair> rolesMap;
    final String rolesDefault;
    final RoleSync rolesSync;
    private final List<String> problems;
    private final List<String> warnings;

    private LdapSettings(Properties source) {
        Reader r = new Reader(source);
        enabled = r.bool(ENABLED);
        urls = List.of(r.text(URL).isEmpty() ? new String[0] : r.text(URL).split("\\s+"));
        startTls = r.bool(STARTTLS);
        caCertificate = r.text(CA_CERTIFICATE);
        connectTimeoutMs = r.number(CONNECT_TIMEOUT_MS, 100, 60_000);
        readTimeoutMs = r.number(READ_TIMEOUT_MS, 100, 300_000);
        retries = r.number(RETRIES, 0, 10);
        retryIntervalMs = r.number(RETRY_INTERVAL_MS, 0, 10_000);
        bindMode = r.choice(BIND_MODE, BindMode.class, BindMode.TEMPLATE);
        userDnTemplate = r.text(USER_DN_TEMPLATE);
        serviceDn = r.text(SERVICE_DN);
        servicePassword = r.text(SERVICE_PASSWORD);
        userSearchBase = r.text(USER_SEARCH_BASE);
        userSearchFilter = r.text(USER_SEARCH_FILTER);
        usernameAttribute = r.text(USERNAME_ATTRIBUTE);
        entryIdAttribute = r.text(ENTRY_ID_ATTRIBUTE);
        groupSearchBase = r.text(GROUP_SEARCH_BASE);
        groupFilter = r.text(GROUP_FILTER);
        loginFilter = r.text(LOGIN_FILTER);
        createUsers = r.bool(CREATE_USERS);
        firstNameAttribute = r.text(FIRST_NAME_ATTRIBUTE);
        lastNameAttribute = r.text(LAST_NAME_ATTRIBUTE);
        emailAttribute = r.text(EMAIL_ATTRIBUTE);
        organizationAttribute = r.text(ORGANIZATION_ATTRIBUTE);
        linkedAccounts = NameLists.parsePairs(r.text(LINKED_ACCOUNTS), LINKED_ACCOUNTS, "localUser=directoryUsername", r.problems,
                false);
        Set<String> localOnly = new LinkedHashSet<>();
        for (String name : NameLists.parseNames(r.text(LOCAL_ONLY_USERNAMES))) {
            localOnly.add(normalize(name));
        }
        localOnlyUsernames = Collections.unmodifiableSet(localOnly);
        fallbackToLocal = r.bool(FALLBACK_TO_LOCAL);
        outageLocalPasswords = r.bool(OUTAGE_LOCAL_PASSWORDS);
        rolesGroupAttribute = r.text(ROLES_GROUP_ATTRIBUTE);
        rolesMemberFilter = r.text(ROLES_MEMBER_FILTER);
        // Split at the last "=", so a key can be a group DN; its commas are written \, as in any list.
        rolesMap = NameLists.parsePairs(r.text(ROLES_MAP), ROLES_MAP, "group=RBAC role", r.problems, true);
        rolesDefault = r.text(ROLES_DEFAULT);
        rolesSync = r.choice(ROLES_SYNC, RoleSync.class, RoleSync.ALWAYS);
        r.problems.addAll(LdapSettingsCheck.problems(this));
        problems = List.copyOf(r.problems);
        warnings = List.copyOf(LdapSettingsCheck.warnings(this));
    }

    /** Reads settings from stored or submitted properties; a missing key takes its default. */
    public static LdapSettings parse(Properties properties) {
        return new LdapSettings(properties == null ? new Properties() : properties);
    }

    /** Every key with its default value, which the engine stores on first start. */
    public static Properties defaults() {
        Properties copy = new Properties();
        copy.putAll(DEFAULTS);
        return copy;
    }

    /**
     * How the plugin compares the names in its own settings lists (local-only list, linked
     * accounts, group names): NFKC, so compatibility spaces become plain ones, then
     * {@link String#strip()}, which removes Unicode whitespace, then lower case with
     * {@link Locale#ROOT}.
     */
    public static String normalize(String name) {
        return name == null ? "" : Normalizer.normalize(name, Normalizer.Form.NFKC).strip().toLowerCase(Locale.ROOT);
    }

    /**
     * SHA-256, in hex, over what decides where and how the service password is sent: the URL
     * list, starttls, ca-certificate, bind-mode and service-dn. The sealed service password
     * carries it, so the password can't be used once any of them changes.
     */
    public String targetFingerprint() {
        String target = "url=" + String.join(" ", urls) + "\nstarttls=" + startTls + "\nca-certificate="
                + caCertificate.replace("\r\n", "\n") + "\nbind-mode=" + bindMode + "\nservice-dn=" + serviceDn;
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(target.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0x0f, 16)).append(Character.forDigit(b & 0x0f, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is missing from this JVM", e);
        }
    }

    /** Every key, written the way {@link #parse(Properties)} reads it. */
    public Properties toProperties() {
        Properties p = new Properties();
        p.setProperty(ENABLED, String.valueOf(enabled));
        p.setProperty(URL, String.join(" ", urls));
        p.setProperty(STARTTLS, String.valueOf(startTls));
        p.setProperty(CA_CERTIFICATE, caCertificate);
        p.setProperty(CONNECT_TIMEOUT_MS, String.valueOf(connectTimeoutMs));
        p.setProperty(READ_TIMEOUT_MS, String.valueOf(readTimeoutMs));
        p.setProperty(RETRIES, String.valueOf(retries));
        p.setProperty(RETRY_INTERVAL_MS, String.valueOf(retryIntervalMs));
        p.setProperty(BIND_MODE, Reader.name(bindMode));
        p.setProperty(USER_DN_TEMPLATE, userDnTemplate);
        p.setProperty(SERVICE_DN, serviceDn);
        p.setProperty(SERVICE_PASSWORD, servicePassword);
        p.setProperty(USER_SEARCH_BASE, userSearchBase);
        p.setProperty(USER_SEARCH_FILTER, userSearchFilter);
        p.setProperty(USERNAME_ATTRIBUTE, usernameAttribute);
        p.setProperty(ENTRY_ID_ATTRIBUTE, entryIdAttribute);
        p.setProperty(GROUP_SEARCH_BASE, groupSearchBase);
        p.setProperty(GROUP_FILTER, groupFilter);
        p.setProperty(LOGIN_FILTER, loginFilter);
        p.setProperty(CREATE_USERS, String.valueOf(createUsers));
        p.setProperty(FIRST_NAME_ATTRIBUTE, firstNameAttribute);
        p.setProperty(LAST_NAME_ATTRIBUTE, lastNameAttribute);
        p.setProperty(EMAIL_ATTRIBUTE, emailAttribute);
        p.setProperty(ORGANIZATION_ATTRIBUTE, organizationAttribute);
        p.setProperty(LINKED_ACCOUNTS, NameLists.formatPairs(linkedAccounts));
        p.setProperty(LOCAL_ONLY_USERNAMES, NameLists.formatNames(localOnlyUsernames));
        p.setProperty(FALLBACK_TO_LOCAL, String.valueOf(fallbackToLocal));
        p.setProperty(OUTAGE_LOCAL_PASSWORDS, String.valueOf(outageLocalPasswords));
        p.setProperty(ROLES_GROUP_ATTRIBUTE, rolesGroupAttribute);
        p.setProperty(ROLES_MEMBER_FILTER, rolesMemberFilter);
        p.setProperty(ROLES_MAP, NameLists.formatPairs(rolesMap));
        p.setProperty(ROLES_DEFAULT, rolesDefault);
        p.setProperty(ROLES_SYNC, Reader.name(rolesSync));
        return p;
    }

    public List<String> problems() { return problems; }
    public boolean isValid() { return problems.isEmpty(); }
    /** Settings that work but deserve a second look; shown on save and logged at WARN. */
    public List<String> warnings() { return warnings; }
    public boolean enabled() { return enabled; }
    public List<String> urls() { return urls; }
    public boolean startTls() { return startTls; }
    public String caCertificate() { return caCertificate; }
    public int connectTimeoutMs() { return connectTimeoutMs; }
    public int readTimeoutMs() { return readTimeoutMs; }
    public int retries() { return retries; }
    public int retryIntervalMs() { return retryIntervalMs; }
    public BindMode bindMode() { return bindMode; }
    public String userDnTemplate() { return userDnTemplate; }
    /** Whether {@link #userDnTemplate()} builds a DN; otherwise it builds a userPrincipalName. */
    public boolean userDnTemplateIsDn() { return LdapSettingsCheck.isDnTemplate(userDnTemplate); }
    public String serviceDn() { return serviceDn; }
    /** The stored, sealed form ({@code enc:...}), never the clear password. */
    public String servicePassword() { return servicePassword; }
    public String userSearchBase() { return userSearchBase; }
    public String userSearchFilter() { return userSearchFilter; }
    public String usernameAttribute() { return usernameAttribute; }
    public String entryIdAttribute() { return entryIdAttribute; }
    public String groupSearchBase() { return groupSearchBase; }
    public String groupFilter() { return groupFilter; }
    /** A filter the user's own entry must match, checked with a base-scope search on its DN. */
    public String loginFilter() { return loginFilter; }
    public boolean createUsers() { return createUsers; }
    public String firstNameAttribute() { return firstNameAttribute; }
    public String lastNameAttribute() { return lastNameAttribute; }
    public String emailAttribute() { return emailAttribute; }
    public String organizationAttribute() { return organizationAttribute; }
    /** Pairs of local engine username (left) and directory username (right). */
    public List<NamePair> linkedAccounts() { return linkedAccounts; }
    /** Already normalized with {@link #normalize(String)}. */
    public Set<String> localOnlyUsernames() { return localOnlyUsernames; }
    public boolean fallbackToLocal() { return fallbackToLocal; }
    /** Whether directory accounts sign in with their engine password while the directory can't be used. */
    public boolean outageLocalPasswords() { return outageLocalPasswords; }
    public String rolesGroupAttribute() { return rolesGroupAttribute; }
    public String rolesMemberFilter() { return rolesMemberFilter; }
    /** Pairs of directory group, a name or (with "=") a DN, and RBAC role name, in the order listed. */
    public List<NamePair> rolesMap() { return rolesMap; }
    public String rolesDefault() { return rolesDefault; }
    public RoleSync rolesSync() { return rolesSync; }

    /** Reads typed values, recording a problem and keeping the default for anything unreadable. */
    private static final class Reader {
        private final Properties source;
        private final List<String> problems = new ArrayList<>();

        Reader(Properties source) {
            this.source = source;
        }

        String text(String key) {
            String value = source.getProperty(key);
            return value == null ? DEFAULTS.getProperty(key, "") : value.trim();
        }

        boolean bool(String key) {
            String value = text(key).toLowerCase(Locale.ROOT);
            if (value.equals("true") || value.equals("false")) {
                return Boolean.parseBoolean(value);
            }
            problems.add(key + ": \"" + text(key) + "\" is not true or false.");
            return Boolean.parseBoolean(DEFAULTS.getProperty(key));
        }

        int number(String key, int min, int max) {
            try {
                int value = Integer.parseInt(text(key));
                if (value >= min && value <= max) {
                    return value;
                }
            } catch (NumberFormatException e) {
                // reported below
            }
            problems.add(key + ": \"" + text(key) + "\" is not a whole number from " + min + " to " + max + ".");
            return Integer.parseInt(DEFAULTS.getProperty(key));
        }

        <E extends Enum<E>> E choice(String key, Class<E> type, E fallback) {
            for (E constant : type.getEnumConstants()) {
                if (name(constant).equals(text(key).toLowerCase(Locale.ROOT))) {
                    return constant;
                }
            }
            List<String> names = new ArrayList<>();
            for (E constant : type.getEnumConstants()) {
                names.add(name(constant));
            }
            problems.add(key + ": \"" + text(key) + "\" is not one of " + String.join(", ", names) + ".");
            return fallback;
        }

        static String name(Enum<?> constant) {
            return constant.name().toLowerCase(Locale.ROOT).replace('_', '-');
        }
    }
}
