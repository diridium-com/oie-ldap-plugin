// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.SimpleBindRequest;

/**
 * The UnboundID in-memory directory server the tests sign in against, with a
 * fixed set of people and groups under {@value #BASE}. It records what it
 * receives, so a test can assert what reached the directory.
 */
final class TestDirectory implements AutoCloseable {

    static final String BASE = "dc=example,dc=com";
    static final String PEOPLE = "ou=people," + BASE;
    static final String GROUPS = "ou=groups," + BASE;
    static final String SERVICE_DN = "cn=service," + BASE;
    static final String SERVICE_PASSWORD = "service-pw";
    /** 41 characters, one more than an engine username holds. */
    static final String LONG_NAME = "a-directory-name-of-forty-one-characters1";
    /** The AD-style directory's alice is a member (memberOf); bob is disabled (userAccountControl 514). */
    static final String AD_USERS_GROUP = "CN=OIE Users,OU=Groups,DC=corp,DC=example";

    private static final Pattern KIND = Pattern.compile(
            "\\] (CONNECT|BIND REQUEST|BIND RESULT|SEARCH REQUEST|SEARCH RESULT|EXTENDED REQUEST|EXTENDED RESULT) ");
    private static final Pattern FIELD = Pattern.compile("(dn|filter|resultCode|entriesReturned|requestOID|diagnosticMessage)=(\"[^\"]*\"|\\S+)");

    private final InMemoryDirectoryServer server;
    private final List<String> access;

    private TestDirectory(InMemoryDirectoryServer server, List<String> access) {
        this.server = server;
        this.access = access;
    }

    /** The standard directory on a plain ldap:// listener. */
    static TestDirectory start() throws Exception {
        return start(null, null, false);
    }

    /**
     * With ldaps:// and StartTLS listeners as well: "ldaps" and "starttls" present a
     * certificate for localhost and 127.0.0.1, "ldaps-wrong-host" and "starttls-wrong-host"
     * one for wrong.example.com, all signed by {@code certificates}.
     */
    static TestDirectory startWithTls(TestCertificates certificates) throws Exception {
        return start(certificates.server(List.of("localhost"), List.of("127.0.0.1")),
                certificates.server(List.of("wrong.example.com"), List.of()), false);
    }

    /**
     * Shaped like Active Directory: no schema checks, no entryUUID, a binary objectGUID,
     * sAMAccountName and userPrincipalName, and simple binds by userPrincipalName.
     */
    static TestDirectory startActiveDirectory() throws Exception {
        return start(null, null, true);
    }

    private static TestDirectory start(SSLContext tls, SSLContext wrongHost, boolean activeDirectory) throws Exception {
        List<String> access = Collections.synchronizedList(new ArrayList<>());
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        List<InMemoryListenerConfig> listeners = new ArrayList<>();
        listeners.add(InMemoryListenerConfig.createLDAPConfig("ldap", loopback, 0, null));
        if (tls != null) {
            listeners.add(InMemoryListenerConfig.createLDAPSConfig("ldaps", loopback, 0, tls.getServerSocketFactory(), null));
            listeners.add(InMemoryListenerConfig.createLDAPSConfig("ldaps-wrong-host", loopback, 0,
                    wrongHost.getServerSocketFactory(), null));
            listeners.add(InMemoryListenerConfig.createLDAPConfig("starttls", loopback, 0, tls.getSocketFactory()));
            listeners.add(InMemoryListenerConfig.createLDAPConfig("starttls-wrong-host", loopback, 0, wrongHost.getSocketFactory()));
        }
        config.setListenerConfigs(listeners);
        config.addAdditionalBindCredentials(SERVICE_DN, SERVICE_PASSWORD);
        config.setAccessLogHandler(new Handler() {
            @Override
            public void publish(LogRecord record) {
                access.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        });
        Map<String, String> principals = new HashMap<>();
        if (activeDirectory) {
            config.setSchema(null);
            config.setGenerateOperationalAttributes(false);
            config.addInMemoryOperationInterceptor(new InMemoryOperationInterceptor() {
                @Override
                public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) {
                    SimpleBindRequest bind = request.getRequest();
                    String dn = principals.get(bind.getBindDN().toLowerCase(Locale.ROOT));
                    if (dn != null) {
                        request.setRequest(new SimpleBindRequest(dn, bind.getPassword().getValue()));
                    }
                }
            });
        }
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        TestDirectory directory = new TestDirectory(server, access);
        directory.load(activeDirectory, principals);
        server.startListening();
        return directory;
    }

    private void load(boolean activeDirectory, Map<String, String> principals) throws Exception {
        server.add("dn: " + BASE, "objectClass: top", "objectClass: domain", "dc: example");
        server.add("dn: " + PEOPLE, "objectClass: top", "objectClass: organizationalUnit", "ou: people");
        server.add("dn: ou=contractors," + PEOPLE, "objectClass: top", "objectClass: organizationalUnit", "ou: contractors");
        server.add("dn: " + GROUPS, "objectClass: top", "objectClass: organizationalUnit", "ou: groups");
        if (activeDirectory) {
            adPerson("alice", "Alice", "Smith", "alice-pw", "corp.example.com", principals, 0x11,
                    new Attribute("memberOf", AD_USERS_GROUP), new Attribute("userAccountControl", "512"));
            adPerson("bob", "Bob", "Brown", "bob-pw", "corp.example.com", principals, 0x22,
                    new Attribute("userAccountControl", "514"));
            server.add("dn: cn=mirth-users," + GROUPS, "objectClass: group", "cn: mirth-users",
                    "member: cn=alice," + PEOPLE);
            return;
        }
        person("uid=alice," + PEOPLE, "alice", "Alice", "Smith", "alice-pw");
        person("uid=admin," + PEOPLE, "admin", "Directory", "Admin", "dir-admin-pw");
        person("uid=mjones," + PEOPLE, "mjones", "Mary", "Jones", "mary-pw");
        person("uid=mary," + PEOPLE, "mary", "Mary", "Other", "other-mary-pw");
        person("uid=bob," + PEOPLE, "bob", "Bob", "Brown", "bob-pw");
        person("uid=eve,ou=contractors," + PEOPLE, "eve", "Eve", "Contractor", "eve-pw");
        person("uid=" + LONG_NAME + "," + PEOPLE, LONG_NAME, "Long", "Name", "long-pw");
        server.add("dn: uid=carol+cn=Carol," + PEOPLE, "objectClass: top", "objectClass: person",
                "objectClass: organizationalPerson", "objectClass: inetOrgPerson",
                "uid: carol", "cn: Carol", "sn: C", "userPassword: carol-pw");
        String[] members = { "alice", "admin", "mjones", "mary", "eve,ou=contractors", LONG_NAME };
        List<String> users = new ArrayList<>(List.of("dn: cn=mirth-users," + GROUPS, "objectClass: top",
                "objectClass: groupOfUniqueNames", "cn: mirth-users"));
        for (String member : members) {
            users.add("uniqueMember: uid=" + member + "," + PEOPLE);
        }
        users.add("uniqueMember: uid=carol+cn=Carol," + PEOPLE);
        server.add(users.toArray(new String[0]));
        server.add("dn: cn=mirth-admins," + GROUPS, "objectClass: top", "objectClass: groupOfUniqueNames",
                "cn: mirth-admins", "uniqueMember: uid=alice," + PEOPLE);
        server.add("dn: cn=Night Ops," + GROUPS, "objectClass: top", "objectClass: groupOfUniqueNames",
                "cn: Night Ops", "uniqueMember: uid=mjones," + PEOPLE, "uniqueMember: uid=alice," + PEOPLE);
    }

    private void person(String dn, String uid, String given, String surname, String password) throws Exception {
        server.add("dn: " + dn, "objectClass: top", "objectClass: person", "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson", "uid: " + uid, "cn: " + given + " " + surname, "givenName: " + given,
                "sn: " + surname, "mail: " + uid + "@example.com", "o: Example Org", "userPassword: " + password);
    }

    private void adPerson(String name, String given, String surname, String password, String domain,
            Map<String, String> principals, int guidByte, Attribute... extra) throws Exception {
        String dn = "cn=" + name + "," + PEOPLE;
        byte[] guid = new byte[16];
        java.util.Arrays.fill(guid, (byte) guidByte);
        guid[0] = (byte) 0xff;
        List<Attribute> attributes = new ArrayList<>(List.of(new Attribute("objectClass", "user"), new Attribute("cn", name),
                new Attribute("sAMAccountName", name), new Attribute("userPrincipalName", name + "@" + domain),
                new Attribute("givenName", given), new Attribute("sn", surname), new Attribute("objectGUID", guid),
                new Attribute("userPassword", password)));
        attributes.addAll(List.of(extra));
        server.add(new Entry(dn, attributes));
        principals.put((name + "@" + domain).toLowerCase(Locale.ROOT), dn);
    }

    void add(String... ldif) throws Exception {
        server.add(ldif);
    }

    void delete(String dn) throws Exception {
        server.delete(dn);
    }

    /** ldap://localhost:port of a listener. */
    String url(String listener) {
        String scheme = listener.startsWith("ldaps") ? "ldaps" : "ldap";
        return scheme + "://localhost:" + server.getListenPort(listener);
    }

    String url() {
        return url("ldap");
    }

    int port(String listener) {
        return server.getListenPort(listener);
    }

    /** What the server received since the last call: requests and results, reduced to the fields that matter. */
    List<String> drain() {
        List<String> seen = new ArrayList<>();
        synchronized (access) {
            for (String line : access) {
                // The kind is the words after the timestamp; "UNBIND REQUEST" is not a bind.
                Matcher kindMatch = KIND.matcher(line);
                if (!kindMatch.find()) {
                    continue;
                }
                String kind = kindMatch.group(1);
                StringBuilder out = new StringBuilder(kind);
                Matcher m = FIELD.matcher(line);
                while (m.find()) {
                    out.append(' ').append(m.group(1)).append('=').append(m.group(2));
                }
                Matcher conn = Pattern.compile("conn=(\\d+)").matcher(line);
                if (conn.find()) {
                    out.append(" conn=").append(conn.group(1));
                }
                seen.add(out.toString());
            }
            access.clear();
        }
        return seen;
    }

    @Override
    public void close() {
        server.shutDown(true);
    }
}
