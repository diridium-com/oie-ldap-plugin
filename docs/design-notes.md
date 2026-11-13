<!-- SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc. -->
<!-- SPDX-License-Identifier: MPL-2.0 -->

# Design notes

Each section describes a choice in the plugin that can look wrong, and the reason for it.

## 2026-11-12: sign-in and settings

### Terms

An **engine account** is a user in the engine's own database. A **directory entry** is the user's object in the LDAP directory. A **directory account** is an engine account linked to a directory entry, or one named in the `linked-accounts` setting. Role-Based Access Control, the plugin that gives engine users roles, is called rbac below.

### Engine username

After the bind, the plugin reads the directory entry and takes the engine username from the attribute named in `username-attribute` (`uid` by default, `sAMAccountName` for Active Directory). The engine signs the user in under that name, whatever was typed. Spaces before or after the typed name are removed, and directories compare `uid` and `sAMAccountName` without regard to case, so a user typing `ALICE`, or `alice` with a trailing space, reaches the engine as `alice`. When the attribute has several values, the plugin takes the one equal to the name used to sign in, and refuses the sign-in if there isn't exactly one. A value containing control characters is refused.

Before a typed name goes into a DN or a search filter, the plugin escapes it as RFC 4514 and RFC 4515 describe. A name such as `eve,ou=contractors` is escaped as one value, so it can't change which directory entry the bind reaches.

### Username length

The engine stores usernames in a column of 40 characters on every database it supports. A directory name longer than that is refused with a message naming the limit and the `username-attribute` setting, so an administrator can choose a shorter attribute. First and last names are cut to 40 characters, and email and organization to 255, the sizes of their columns. A display value starting with `<html` is left out, because the Swing Administrator renders such text as HTML.

### Finding the engine account

To decide which engine account a typed name belongs to, the plugin uses the engine's own user lookup, `UserController.getUser`. The database's rules for case and accents then apply exactly as they do when the engine checks a password, and the local-only and directory account decisions are made on the account that lookup returns.

### Linking existing accounts

An engine account that existed before the plugin signs in through the directory only after an administrator lists it in `linked-accounts`. Each item there pairs an engine username with a directory username: `mary=mjones` lets the engine account `mary` sign in with the password of the directory user `mjones`, typing either name. The first such sign-in records the link. Accounts the plugin creates are linked when they are created. Without the pairing, the owner of a directory entry named `admin` could sign in to the engine's own `admin` account.

A link records the directory entry's stable id: `entryUUID`, or Active Directory's `objectGUID` as hex. A directory user who is deleted and created again under the same name has a new id, and that sign-in is refused.

The engine lets every user edit their own user preferences, so links aren't stored there. They are kept in the engine's CONFIGURATION table, in a category named `LDAP Authentication account links`, keyed by the engine account's id. At startup the plugin removes links whose engine account no longer exists. It skips that step when the list of engine accounts comes back empty or can't be read.

### Basic sign-in to the REST API

When the engine's REST API is called with HTTP Basic credentials, the engine looks the user up by the typed name and ignores the name the plugin returns (engine 4.7.0, `MirthServlet.initLogin`). Suppose `linked-accounts` pairs the engine account `mary` with the directory user `mjones`, and a different engine account is also named `mjones`. A Basic sign-in typed as `mjones` with that directory user's password would then run as the other engine account. The plugin refuses a sign-in when the typed name finds a different engine account from the one the directory entry belongs to.

### Sign-in filter

With LDAP on, the settings need at least one sign-in filter: `login-filter`, `group-filter`, or both. Settings without one are refused when saved, and stored settings without one are treated as settings with a problem. The original plugin required a group filter: it stopped every directory sign-in with "No LDAP URL configured" when the URL or the group filter was missing (OpenIntegrationEngine/ldap-plugin at e06118a, `LDAPAuthenticatorPlugin.performUserAuthenticationAndAuthorization`). This keeps that requirement and adds a second kind of filter.

`group-filter` is searched under `group-search-base`, with `{username}` and `{dn}` filled in, and at least one group has to match. `login-filter` is matched against the user's own directory entry: right after the bind, the plugin searches the entry's DN with base scope, on the same connection the group check uses. Examples are `(memberOf=CN=OIE Users,OU=Groups,DC=corp,DC=example)`, or Active Directory's disabled-account test `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`. When both filters are set, both have to match. A filter the directory can't evaluate refuses the sign-in.

That search asks for the attribute `1.1`, meaning none. Given no attributes and a filter such as `(uid=bob)`, the JDK's LDAP client sends an LDAP compare in place of the search (measured on Java 17.0.17), and a directory's access control can allow compare and search separately, as OpenLDAP's access levels do.

### Account creation

Creating engine accounts (`create-users`) is off by default. Turning it on needs rbac 1.3.0 or later installed and running, a `roles.default` that exists in rbac and isn't its admin role, and a sign-in filter (`login-filter` or `group-filter`) naming who is allowed in. The plugin checks all three when the settings are saved and again at each sign-in that would create an account. A new account gets the role its groups map to, or the default role. If rbac can't assign one, that first sign-in is refused and logged at WARN. Created accounts have no engine password, and the Administrator's first-login prompt is turned off for them.

Without rbac, the engine lets every signed-in user do everything (engine 4.7.0, `DefaultAuthorizationController`). That is why the plugin creates no accounts while rbac is missing, and why an account it created signs in only while rbac is installed and running. The plugin records in the link store which accounts it created; while rbac's repository is missing or not started, it refuses their sign-in and logs an INFO line saying rbac is needed. `outage-local-passwords` doesn't change that. Accounts an administrator made and linked through `linked-accounts` aren't affected.

### Roles

The first `roles.map` item the user's groups match decides the role, in the order listed. A key containing `=` is a group DN, with its commas written `\,`, and matches only that group. Any other key is a group name and matches every group of that name under `group-search-base`, which is why saving one returns a warning. Users in no mapped group get `roles.default`, which is required whenever roles are synced, so someone who leaves every mapped group moves to the default role.

A mapped group can grant rbac's admin role. The default role can't be the admin role. Role changes run one at a time, and the plugin doesn't move the last user with the admin role to another role. If a change made elsewhere leaves no admin anyway, the plugin gives the admin role back to the user it just moved. When changing an existing account's role fails, the failure is logged and the sign-in goes ahead.

### Local passwords

Names on `local-only-usernames` always use the engine's own password check and skip the directory.

A directory account uses its engine password only when `outage-local-passwords` is on and the directory can't be used: it is unreachable, LDAP is off in the settings, or the stored settings have a problem. A wrong password is refused even then. While `outage-local-passwords` is on, the plugin logs a WARN line at every start and save, and the save's audit event names it.

Any other engine account uses its engine password when the directory can't be used, and also, with `fallback-to-local-for-unknown-users` on, when the directory doesn't know the name. A search bind tells an unknown name apart, because the search finds no entry. A template bind goes straight to a DN built from the name, and the directory gives the same answer for a missing entry as for a wrong password, so for these accounts a refused template bind counts as an unknown name. A TLS failure refuses the sign-in.

### Stored settings with a problem

The settings are checked before they are saved. Stored settings can still be wrong, for example after a write through the engine's generic plugin properties API, which skips those checks and can store the service password unencrypted. LDAP is then off: directory accounts are refused unless `outage-local-passwords` is on, other accounts use their engine passwords, and the reason is logged at ERROR.

When the engine hands the plugin new settings, the plugin reads the stored settings back in full. A merging write through the generic API passes on only the keys it changed, and the rest would otherwise read as defaults.

The environment variable `OIE_LDAP_DISABLED=true`, or the system property `com.diridium.ldap.disabled=true`, turns LDAP off for every account without touching the stored settings. It is meant for when a setting locks everyone out. The plugin logs a WARN line at start and save while it is on, and whenever it changes.

### Saving the settings

A save is refused when the account making it couldn't sign in under the new settings. With LDAP on, that account has to be on `local-only-usernames` or be a directory account with a link. When `local-only-usernames` is empty, the save goes ahead and returns a warning, which is also logged at WARN. Saves run one at a time. A plain `ldap://` URL without StartTLS is accepted with a warning that passwords will cross the network unencrypted.

### Permission

The settings are stored as the plugin's properties in the engine database. Besides the plugin's own REST API, the engine's generic `GET` and `PUT /extensions/LDAP Authentication/properties` read and write the same values. rbac allows any operation that no permission claims, so the plugin's permission, Manage LDAP Authentication, claims those two operations for this plugin as well. rbac 1.3.0 is the minimum, because it is the first version whose check on these operations also covers other spellings of the plugin's name.

Anyone holding the permission can link any engine account to a directory account and map groups to rbac's roles. Give it only to roles you would trust with the admin role.

### Service password

The settings screen shows a stored service password as a mask. Saving the mask keeps the stored password while `url`, `starttls`, `ca-certificate`, `bind-mode` and `service-dn` stay the same. When one of them changes, the stored password is dropped and has to be typed again, and the connection and login tests follow the same rule.

The stored password is sealed with the engine's encryptor together with a fingerprint of those five settings, so it can't be sent to a server it wasn't entered for. If the settings change another way, through the engine's generic plugin properties API or by restoring a backup, the stored password no longer matches them. LDAP is then off for search binds, and the ERROR line asks for the password to be entered again.

### Restoring a backup

The engine's server configuration backup contains the plugin's settings as stored, and restoring one writes them back as they were, service password included. The restored settings apply at the next restart.

### Connection and login tests

The test buttons connect to whatever host the settings name, from the engine. The login test checks a directory user's password without signing anyone in. Both need the plugin's permission and are audited.

### Lockout

The plugin doesn't count failed sign-ins or lock accounts. The engine's lockout doesn't run for a sign-in a plugin decides (engine 4.7.0, `DefaultUserController.authorizeUser` returns the plugin's answer before its lockout check), so the directory's own lockout is the one that applies: an Active Directory lockout policy, or OpenLDAP's password policy overlay. Each refused password logs one INFO line with the username and the reason.

### Timeouts and retries

The plugin uses the JDK's own LDAP client, which waits for the answer to the first bind for up to `connect-timeout-ms`. Measured on Java 17.0.17 with `connect-timeout-ms` at 1000 and `read-timeout-ms` at 300, a server that accepted the connection and never answered held the sign-in for about one second. The plugin tries again only when the connection failed before anything was sent: the host name didn't resolve, the connection was refused or unroutable, or connecting timed out. A bind that may have reached the directory isn't sent again, since a second attempt could count twice against the directory's lockout.
