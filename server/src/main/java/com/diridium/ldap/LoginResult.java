// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.List;

/**
 * What one sign-in attempt came to, and the checks on the way, which a test
 * login shows. Filled in by {@link LoginFlow} as it goes; read by the plugin
 * (the decision) and the servlet (everything).
 */
final class LoginResult {

    enum Outcome {
        /** Signed in; the engine signs in as {@link #engineUsername()}. */
        SUCCESS,
        /** Refused; the engine shows {@link #userMessage()}. */
        REFUSED,
        /** Not the plugin's to answer: the engine checks the local password. */
        LOCAL
    }

    private static final String BAD_CREDENTIALS = "Incorrect username or password.";
    private static final String ASK_ADMIN = "Sign-in through the directory is not working. Ask an administrator.";

    enum Reason {
        TURNED_OFF("LDAP is turned off", null),
        INVALID_SETTINGS("the LDAP settings have a problem, so LDAP is off", null),
        KILL_SWITCH("the LDAP kill switch is on", null),
        LOCAL_ONLY("the name is on the local-only list", null),
        FALLBACK("the directory doesn't know the name, so the local password is checked", null),
        OUTAGE("the directory can't be used and outage-local-passwords is on", null),
        DIRECTORY_OFF("a directory account can't use its engine password while the directory can't be used",
                "Sign-in through the directory is not available. Ask an administrator."),
        EMPTY_NAME("the username is empty", BAD_CREDENTIALS),
        EMPTY_PASSWORD("the password is empty", BAD_CREDENTIALS),
        BIND_REFUSED("the directory refused the password", BAD_CREDENTIALS),
        UNKNOWN_USER("the directory has no entry for the name", BAD_CREDENTIALS),
        AMBIGUOUS_USER("more than one directory entry matches the name",
                "More than one directory account matches this name. Ask an administrator."),
        UNREACHABLE("the directory could not be reached", "The directory server could not be reached. Try again in a moment."),
        TLS("the TLS connection to the directory failed", ASK_ADMIN),
        SERVICE_BIND_REFUSED("the directory refused the service account", ASK_ADMIN),
        DIRECTORY_ERROR("the directory returned an error", ASK_ADMIN),
        ENTRY_NOT_FOUND("the entry could not be read after the bind", ASK_ADMIN),
        NO_USERNAME("the entry has no value for the username-attribute setting", ASK_ADMIN),
        USERNAME_AMBIGUOUS("the entry has several username-attribute values and not exactly one equals the name signed in with",
                ASK_ADMIN),
        USERNAME_INVALID("the directory name contains control characters", ASK_ADMIN),
        NO_ENTRY_ID("the entry has no stable id (entry-id-attribute)", ASK_ADMIN),
        NOT_IN_GROUP("the entry is in no group the group-filter allows",
                "Your directory account is not allowed to sign in to this engine."),
        NOT_ALLOWED("the entry doesn't match the login-filter",
                "Your directory account is not allowed to sign in to this engine."),
        CREATED_NEEDS_RBAC("the plugin created this account, and such accounts sign in only while Role-Based Access Control "
                + "is installed and running", "Sign-in is not available right now. Ask an administrator."),
        NAME_TOO_LONG("the directory name is longer than " + LdapSettings.MAX_USERNAME_LENGTH + " characters",
                "Your directory name is longer than the " + LdapSettings.MAX_USERNAME_LENGTH
                        + " characters an engine username can hold. Ask an administrator to change the username-attribute setting."),
        DUPLICATE_LOCAL("more than one engine account matches the name, differing only in case",
                "More than one engine account matches this name. Ask an administrator."),
        NOT_LINKED("an engine account with this name exists and is not linked to the directory entry",
                "This engine account is not linked to your directory account. Ask an administrator to link it."),
        ENTRY_MISMATCH("the engine account is linked to a different directory entry",
                "This engine account is linked to a different directory account. Ask an administrator."),
        OTHER_ACCOUNT_TYPED("the typed name belongs to a different engine account",
                "The name you typed belongs to a different engine account. Ask an administrator."),
        NO_LOCAL_ACCOUNT("there is no engine account and create-users is off",
                "There is no engine account for your directory account. Ask an administrator."),
        CREATION_NOT_ALLOWED("there is no engine account and one can't be created",
                "There is no engine account for your directory account. Ask an administrator."),
        ROLE_NOT_ASSIGNED("the new engine account could not be given a role",
                "Your engine account could not be given a role. Ask an administrator."),
        ACCOUNT_ERROR("the engine account could not be read or written", ASK_ADMIN),
        UNEXPECTED("an unexpected error", ASK_ADMIN);

        final String text;
        final String userMessage;

        Reason(String text, String userMessage) {
            this.text = text;
            this.userMessage = userMessage;
        }
    }

    private final List<LdapTestStep> steps = new ArrayList<>();
    private Outcome outcome;
    private Reason reason;
    private String logDetail;
    private String engineUsername;
    private String dn;
    private String entryId;
    private List<String> groups = List.of();
    private String role;

    Outcome outcome() { return outcome; }
    Reason reason() { return reason; }
    /** Shown in the refusal's log line, for account problems an administrator resolves (ids, names). */
    String logDetail() { return logDetail; }
    String engineUsername() { return engineUsername; }
    String userMessage() { return reason == null ? null : reason.userMessage; }
    List<LdapTestStep> steps() { return steps; }
    String dn() { return dn; }
    String entryId() { return entryId; }
    List<String> groups() { return groups; }
    String role() { return role; }

    LoginResult step(String name, boolean passed, String detail) {
        steps.add(new LdapTestStep(name, passed, detail));
        return this;
    }

    LoginResult success(String username) {
        outcome = Outcome.SUCCESS;
        engineUsername = username;
        return this;
    }

    LoginResult refused(Reason why, String detail) {
        outcome = Outcome.REFUSED;
        reason = why;
        logDetail = detail;
        return this;
    }

    LoginResult local(Reason why) {
        outcome = Outcome.LOCAL;
        reason = why;
        return this;
    }

    void entry(String entryDn, String id) {
        dn = entryDn;
        entryId = id;
    }

    void groups(List<String> names) {
        groups = List.copyOf(names);
    }

    void role(String description) {
        role = description;
    }
}
