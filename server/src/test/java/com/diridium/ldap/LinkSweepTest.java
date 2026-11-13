// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mirth.connect.model.User;

class LinkSweepTest {

    private final MemoryLinks links = new MemoryLinks();

    private static User user(int id) {
        User user = new User();
        user.setId(id);
        user.setUsername("u" + id);
        return user;
    }

    @Test
    void theLinksOfDeletedAccountsAreDropped() {
        links.links.putAll(Map.of(1, "a", 2, "b", 3, "c"));
        assertEquals(1, LinkSweep.run(links, () -> List.of(user(1), user(3))));
        assertEquals(Map.of(1, "a", 3, "c"), links.all());
    }

    @Test
    void anEmptyAccountListDropsNothing() {
        links.links.put(1, "a");
        assertEquals(0, LinkSweep.run(links, List::of));
        assertEquals(Map.of(1, "a"), links.all());
    }

    @Test
    void anAccountListThatCantBeReadDropsNothing() {
        links.links.put(1, "a");
        assertEquals(0, LinkSweep.run(links, () -> {
            throw new IllegalStateException("database down");
        }));
        assertEquals(Map.of(1, "a"), links.all());
    }

    @Test
    void withoutLinksTheAccountsAreNotRead() {
        assertEquals(0, LinkSweep.run(links, () -> {
            throw new AssertionError("read without a reason");
        }));
    }
}
