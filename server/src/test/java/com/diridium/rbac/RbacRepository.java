// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test stand-in for Role-Based Access Control's repository, with the methods the
 * LDAP plugin calls by reflection and the signatures rbac v1.3.0 has. Like the
 * real one, {@link #getInstance()} throws until an instance is set.
 */
public class RbacRepository {

    public static RbacRepository instance;

    public final Map<String, Integer> roles = new HashMap<>();
    public final Map<Integer, Integer> userRoles = new HashMap<>();
    public final List<String> assignments = new ArrayList<>();
    public Integer adminRoleId;
    public RuntimeException failure;

    public static RbacRepository getInstance() {
        if (instance == null) {
            throw new IllegalStateException("RbacRepository not initialized, call init() first");
        }
        return instance;
    }

    public Integer findRoleIdByName(String name) {
        fail();
        return roles.get(name);
    }

    public Integer getAdminRoleId() {
        fail();
        return adminRoleId;
    }

    public int countUsersByRoleId(int roleId) {
        fail();
        int count = 0;
        for (Integer assigned : userRoles.values()) {
            if (assigned == roleId) {
                count++;
            }
        }
        return count;
    }

    public Integer getUserRoleId(int userId) {
        fail();
        return userRoles.get(userId);
    }

    public void assignUserRole(int userId, int roleId) {
        fail();
        userRoles.put(userId, roleId);
        assignments.add(userId + "->" + roleId);
    }

    private void fail() {
        if (failure != null) {
            throw failure;
        }
    }
}
