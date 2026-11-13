// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static com.diridium.ldap.LdapSettings.normalize;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.diridium.ldap.LdapSettings.RoleSync;
import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * Gives a user the Role-Based Access Control role their directory groups map to,
 * through rbac's repository by reflection (rbac publishes no API for it yet; see
 * diridium-com/role-based-access-control#56 and #57).
 *
 * <p>The first {@code roles.map} entry the user's groups match wins, in the order
 * listed; a key with {@code =} is a group DN, any other key a group name. Without a
 * match the user gets {@code roles.default}, which is never rbac's admin role. A new
 * account always gets a role, or its sign-in is refused. For existing accounts,
 * {@code roles.sync} says when: {@code always} on every sign-in, {@code jit-only}
 * never after creation, {@code never} not at all; nothing here stops their sign-in.
 * Role changes are made one at a time, and the last user with the admin role is
 * never moved off it.</p>
 */
final class RbacRoles {

    static final String REPOSITORY_CLASS = "com.diridium.rbac.RbacRepository";

    private static final Logger LOG = LoggerFactory.getLogger(RbacRoles.class);
    /** Count and assign under one lock, so two sign-ins can't each see another admin left. */
    private static final Object LOCK = new Object();

    private final LdapSettings settings;
    private final String repositoryClass;
    private final Supplier<Object> authorizationController;

    RbacRoles(LdapSettings settings, String repositoryClass, Supplier<Object> authorizationController) {
        this.settings = settings;
        this.repositoryClass = repositoryClass;
        this.authorizationController = authorizationController;
    }

    static RbacRoles engine(LdapSettings settings) {
        return new RbacRoles(settings, REPOSITORY_CLASS, () -> ControllerFactory.getFactory().createAuthorizationController());
    }

    /** Whether existing accounts get their role on each sign-in. */
    boolean wanted() {
        return settings.rolesSync() == RoleSync.ALWAYS && (!settings.rolesMap().isEmpty() || !settings.rolesDefault().isEmpty());
    }

    /** Whether the user's groups need reading. */
    boolean needsGroups() {
        return !settings.rolesMap().isEmpty() && settings.rolesSync() != RoleSync.NEVER;
    }

    /** The mapped role name, or the default; null when neither applies. */
    String roleFor(List<DirectoryGroup> groups) {
        NamePair mapped = mapped(groups);
        if (mapped != null) {
            return mapped.right();
        }
        return settings.rolesDefault().isEmpty() ? null : settings.rolesDefault();
    }

    private NamePair mapped(List<DirectoryGroup> groups) {
        for (NamePair mapping : settings.rolesMap()) {
            boolean dn = mapping.left().contains("=");
            String key = dn ? DirectoryGroup.normalizeDn(mapping.left()) : normalize(mapping.left());
            for (DirectoryGroup group : groups) {
                if (dn ? group.dn().equals(key) : group.names().contains(key)) {
                    return mapping;
                }
            }
        }
        return null;
    }

    /** Whether rbac is installed and running: its repository class is there and {@code getInstance()} answers. */
    boolean available() {
        try {
            return repository() != null;
        } catch (Exception | LinkageError e) {
            return false;
        }
    }

    /** Why accounts can't be created now, or null. Checked when settings are saved and at sign-in. */
    String creationProblem() {
        if (settings.groupFilter().isEmpty() && settings.loginFilter().isEmpty()) {
            return LdapSettings.LOGIN_FILTER + " and " + LdapSettings.GROUP_FILTER + " are both empty";
        }
        if (settings.rolesDefault().isEmpty()) {
            return LdapSettings.ROLES_DEFAULT + " is empty";
        }
        String role = defaultRoleProblem();
        if (role != null) {
            return role;
        }
        try {
            return repository() == null ? "Role-Based Access Control is not installed or not started" : null;
        } catch (Exception | LinkageError e) {
            return "Role-Based Access Control could not be read: " + e;
        }
    }

    /** What's wrong with {@code roles.default} in rbac (missing, or the admin role), or null; null too without rbac. */
    String defaultRoleProblem() {
        if (settings.rolesDefault().isEmpty()) {
            return null;
        }
        try {
            Object repository = repository();
            if (repository == null) {
                return null;
            }
            Integer roleId = (Integer) call(repository, "findRoleIdByName", new Class<?>[] { String.class }, settings.rolesDefault());
            if (roleId == null) {
                return LdapSettings.ROLES_DEFAULT + " names no Role-Based Access Control role (\"" + settings.rolesDefault() + "\")";
            }
            if (roleId.equals(call(repository, "getAdminRoleId", new Class<?>[0]))) {
                return LdapSettings.ROLES_DEFAULT + " is Role-Based Access Control's admin role, which is never given by default";
            }
            return null;
        } catch (Exception | LinkageError e) {
            return "Role-Based Access Control could not be read: " + e;
        }
    }

    /**
     * Gives a new account its role: the mapped one (the default when none matches, or when
     * roles.sync is never), or in a dry run says which.
     *
     * @return what was assigned, or null when no role could be given (the sign-in is refused)
     */
    String assignNew(Integer userId, List<DirectoryGroup> groups, boolean dryRun) {
        try {
            NamePair mapped = settings.rolesSync() == RoleSync.NEVER ? null : mapped(groups);
            String roleName = mapped != null ? mapped.right() : settings.rolesDefault();
            Object repository = repository();
            Integer roleId = repository == null || roleName.isEmpty() ? null
                    : (Integer) call(repository, "findRoleIdByName", new Class<?>[] { String.class }, roleName);
            if (roleId == null || (mapped == null && roleId.equals(call(repository, "getAdminRoleId", new Class<?>[0])))) {
                LOG.warn("No Role-Based Access Control role for the new account (" + LogText.quote(roleName)
                        + " is missing, or is the admin role given as the default)");
                return null;
            }
            if (dryRun) {
                return "would assign " + roleName;
            }
            synchronized (LOCK) {
                call(repository, "assignUserRole", new Class<?>[] { int.class, int.class }, userId, roleId);
            }
            refreshPermissions(userId);
            LOG.info("Assigned the Role-Based Access Control role " + LogText.quote(roleName) + " to new engine user id " + userId);
            return roleName;
        } catch (Throwable e) {
            rethrowFatal(e);
            LOG.warn("No Role-Based Access Control role for new engine user id " + userId + ": " + cause(e));
            return null;
        }
    }

    /**
     * Assigns the mapped role to an existing account, or in a dry run says what it would do.
     *
     * @return what was done, for the log and the test login; never throws
     */
    String apply(Integer userId, List<DirectoryGroup> groups, boolean dryRun) {
        try {
            return applyOrThrow(userId, groups, dryRun);
        } catch (Throwable e) {
            rethrowFatal(e);
            LOG.warn("Role-Based Access Control role not assigned to engine user id " + userId + ": " + cause(e));
            return "not assigned: " + cause(e);
        }
    }

    private String applyOrThrow(Integer userId, List<DirectoryGroup> groups, boolean dryRun) throws Exception {
        if (!wanted()) {
            return "left as it is (roles.sync is " + settings.rolesSync().name().toLowerCase(Locale.ROOT) + ")";
        }
        NamePair mapped = mapped(groups);
        String roleName = mapped != null ? mapped.right() : settings.rolesDefault();
        if (roleName.isEmpty()) {
            return "left as it is (no group matched and there is no default)";
        }
        Object repository = repository();
        if (repository == null) {
            return "left as it is (Role-Based Access Control is not installed or not started)";
        }
        Integer roleId = (Integer) call(repository, "findRoleIdByName", new Class<?>[] { String.class }, roleName);
        if (roleId == null) {
            LOG.warn("Role-Based Access Control has no role named " + LogText.quote(roleName) + "; role not assigned");
            return "left as it is (no role named " + roleName + ")";
        }
        synchronized (LOCK) {
            Integer adminRoleId = (Integer) call(repository, "getAdminRoleId", new Class<?>[0]);
            if (mapped == null && roleId.equals(adminRoleId)) {
                LOG.warn("roles.default is the admin role, which is never given by default; role not assigned");
                return "left as it is (the admin role is never given by default)";
            }
            Integer current = (Integer) call(repository, "getUserRoleId", new Class<?>[] { int.class }, userId);
            if (roleId.equals(current)) {
                return roleName + " (already assigned)";
            }
            boolean wasAdmin = adminRoleId != null && adminRoleId.equals(current);
            if (wasAdmin && admins(repository, adminRoleId) <= 1) {
                LOG.warn("Engine user id " + userId + " is the last user with the admin role; not moved to " + LogText.quote(roleName));
                return "left as it is (the last user with the admin role is never moved off it)";
            }
            if (dryRun) {
                return "would assign " + roleName;
            }
            call(repository, "assignUserRole", new Class<?>[] { int.class, int.class }, userId, roleId);
            if (wasAdmin && admins(repository, adminRoleId) == 0) {
                // Someone else changed roles meanwhile; never leave the engine without an admin.
                call(repository, "assignUserRole", new Class<?>[] { int.class, int.class }, userId, adminRoleId);
                refreshPermissions(userId);
                LOG.warn("No user had the admin role after moving engine user id " + userId + " to " + LogText.quote(roleName)
                        + "; the admin role was given back");
                return "left with the admin role (no other user had it)";
            }
        }
        refreshPermissions(userId);
        LOG.info("Assigned the Role-Based Access Control role " + LogText.quote(roleName) + " to engine user id " + userId);
        return roleName;
    }

    private static int admins(Object repository, int adminRoleId) throws Exception {
        return (Integer) call(repository, "countUsersByRoleId", new Class<?>[] { int.class }, adminRoleId);
    }

    /** rbac's repository, or null when rbac isn't installed or hasn't started. */
    private Object repository() throws Exception {
        Class<?> type;
        try {
            type = Class.forName(repositoryClass, false, RbacRoles.class.getClassLoader());
        } catch (Throwable e) {
            return null;
        }
        try {
            return type.getMethod("getInstance").invoke(null);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof IllegalStateException) {
                return null;
            }
            throw e;
        }
    }

    /** Drops the user's cached permissions in rbac's authorization controller, so the new role applies now. */
    private void refreshPermissions(int userId) {
        try {
            Object controller = authorizationController.get();
            controller.getClass().getMethod("invalidateCache", Integer.class).invoke(controller, userId);
        } catch (Exception | LinkageError e) {
            LOG.warn("Could not refresh the cached permissions of engine user id " + userId + ": " + e);
        }
    }

    private static Object call(Object target, String name, Class<?>[] types, Object... arguments) throws Exception {
        return target.getClass().getMethod(name, types).invoke(target, arguments);
    }

    private static Throwable cause(Throwable e) {
        return e instanceof InvocationTargetException && e.getCause() != null ? e.getCause() : e;
    }

    private static void rethrowFatal(Throwable e) {
        if (cause(e) instanceof VirtualMachineError) {
            throw (VirtualMachineError) cause(e);
        }
    }
}
