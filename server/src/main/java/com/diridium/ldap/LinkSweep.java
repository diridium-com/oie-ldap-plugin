// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.model.User;

/**
 * Drops the links of engine accounts that no longer exist; the engine deletes users
 * without telling plugins. Run at startup. When the user list reads empty or can't
 * be read while links exist, nothing is dropped: that looks like a database problem,
 * not every account gone.
 */
final class LinkSweep {

    private static final Logger LOG = LoggerFactory.getLogger(LinkSweep.class);

    private LinkSweep() {
    }

    /** @return how many links were dropped */
    static int run(LinkStore links, Callable<List<User>> users) {
        Map<Integer, String> all = links.all();
        if (all.isEmpty()) {
            return 0;
        }
        List<User> accounts;
        try {
            accounts = users.call();
        } catch (Exception e) {
            LOG.warn("Account links not checked: the engine accounts could not be read: " + e);
            return 0;
        }
        if (accounts == null || accounts.isEmpty()) {
            LOG.warn("Account links not checked: the engine returned no accounts while " + all.size() + " link(s) exist");
            return 0;
        }
        Set<Integer> ids = new HashSet<>();
        for (User account : accounts) {
            ids.add(account.getId());
        }
        int dropped = 0;
        for (Integer userId : all.keySet()) {
            if (!ids.contains(userId)) {
                links.unlink(userId);
                dropped++;
                LOG.info("Dropped the account link of deleted engine user id " + userId);
            }
        }
        return dropped;
    }
}
