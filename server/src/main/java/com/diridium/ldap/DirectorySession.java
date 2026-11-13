// SPDX-FileCopyrightText: Copyright 2020-2025 Christopher Schultz
// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;

/**
 * One bound connection. Names are passed to JNDI as {@link LdapName}s, never as
 * strings, so a {@code /} in a DN can't be read as a JNDI composite-name separator.
 */
final class DirectorySession implements AutoCloseable {

    private final LdapContext context;
    private final int timeLimitMs;

    DirectorySession(LdapContext context, int timeLimitMs) {
        this.context = context;
        this.timeLimitMs = timeLimitMs;
    }

    /** Reads one entry by DN. */
    DirectoryEntry read(String dn, Collection<String> attributes) throws NamingException {
        List<DirectoryEntry> found = search(dn, "(objectClass=*)", attributes, SearchControls.OBJECT_SCOPE, 1);
        if (found.isEmpty()) {
            throw new NameNotFoundException(dn);
        }
        return found.get(0);
    }

    /**
     * Whether the entry at {@code dn} matches the filter: a base-scope search. It asks for the
     * "1.1" attribute (none): given no attributes and a filter such as (uid=bob), JNDI sends an
     * LDAP compare instead of a search, which needs a different right on the directory.
     */
    boolean matches(String dn, String filter) throws NamingException {
        return !search(dn, filter, List.of("1.1"), SearchControls.OBJECT_SCOPE, 1).isEmpty();
    }

    /** A subtree search returning at most {@code limit} entries. */
    List<DirectoryEntry> search(String base, String filter, Collection<String> attributes, int limit) throws NamingException {
        return search(base, filter, attributes, SearchControls.SUBTREE_SCOPE, limit);
    }

    private List<DirectoryEntry> search(String base, String filter, Collection<String> attributes, int scope, int limit)
            throws NamingException {
        SearchControls controls = new SearchControls(scope, limit, timeLimitMs, attributes.toArray(new String[0]), false, false);
        List<DirectoryEntry> found = new ArrayList<>();
        NamingEnumeration<SearchResult> results = context.search(new LdapName(base), filter, controls);
        try {
            while (found.size() < limit && results.hasMore()) {
                SearchResult result = results.next();
                found.add(DirectoryEntry.from(result.getNameInNamespace(), result.getAttributes()));
            }
        } catch (PartialResultException e) {
            // A referral, which is ignored (Active Directory returns them from a domain root);
            // the entries read before it are the answer.
        } catch (SizeLimitExceededException e) {
            // More than the limit match; the caller sees a full list.
        } finally {
            results.close();
        }
        return found;
    }

    @Override
    public void close() {
        try {
            context.close();
        } catch (NamingException e) {
            // closing anyway
        }
    }
}
