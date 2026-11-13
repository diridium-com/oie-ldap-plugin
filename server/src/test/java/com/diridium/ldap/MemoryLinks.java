// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Account links in memory, with every write recorded. */
final class MemoryLinks implements LinkStore {

    final Map<Integer, String> links = new HashMap<>();
    final Set<Integer> created = new HashSet<>();
    final List<String> writes = new ArrayList<>();

    @Override
    public String entryId(int userId) {
        return links.get(userId);
    }

    @Override
    public void link(int userId, String entryId) {
        links.put(userId, entryId);
        writes.add("link " + userId + "=" + entryId);
    }

    @Override
    public void markCreated(int userId) {
        created.add(userId);
        writes.add("created " + userId);
    }

    @Override
    public boolean created(int userId) {
        return created.contains(userId);
    }

    @Override
    public void unlink(int userId) {
        links.remove(userId);
        created.remove(userId);
        writes.add("unlink " + userId);
    }

    @Override
    public Map<Integer, String> all() {
        return new HashMap<>(links);
    }
}
