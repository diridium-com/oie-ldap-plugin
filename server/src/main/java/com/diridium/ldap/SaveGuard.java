// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.normalize;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.UserController;

/**
 * Checks on a save that need the engine and rbac, beyond what the settings check
 * can see: account creation needs rbac with a default role that exists and isn't
 * the admin role, and the account saving the settings must still be able to sign
 * in under them.
 */
final class SaveGuard {

    private final Supplier<UserController> users;
    private final LinkStore links;
    private final Function<LdapSettings, RbacRoles> roles;

    SaveGuard(Supplier<UserController> users, LinkStore links, Function<LdapSettings, RbacRoles> roles) {
        this.users = users;
        this.links = links;
        this.roles = roles;
    }

    /** @param saverId the engine user saving the settings */
    List<String> problems(LdapSettings settings, Integer saverId) {
        List<String> problems = new ArrayList<>();
        RbacRoles rbac = roles.apply(settings);
        if (settings.createUsers()) {
            String why = rbac.creationProblem();
            if (why != null) {
                problems.add(LdapSettings.CREATE_USERS + ": can't be on: " + why + ".");
            }
        } else {
            String why = rbac.defaultRoleProblem();
            if (why != null) {
                problems.add(why + ".");
            }
        }
        // With no local-only name the save goes ahead; the settings warn about it instead.
        if (settings.enabled() && !settings.localOnlyUsernames().isEmpty()) {
            String saver = saverName(saverId);
            if (!canSignIn(settings, saver, saverId)) {
                problems.add(LdapSettings.LOCAL_ONLY_USERNAMES + ": you could not sign in with these settings. Add your engine "
                        + "username" + (saver == null ? "" : " (" + LogText.quote(saver) + ")")
                        + ", or link your engine account to the directory first.");
            }
        }
        return problems;
    }

    private String saverName(Integer saverId) {
        if (saverId == null) {
            return null;
        }
        try {
            User saver = users.get().getUser(saverId, null);
            return saver == null ? null : saver.getUsername();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean canSignIn(LdapSettings settings, String saver, Integer saverId) {
        if (saver == null) {
            return false;
        }
        if (settings.localOnlyUsernames().contains(normalize(saver))) {
            return true;
        }
        try {
            return links.entryId(saverId) != null;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
