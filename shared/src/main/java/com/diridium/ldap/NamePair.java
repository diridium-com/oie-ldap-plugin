// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

/**
 * One {@code left=right} entry of a settings list: a linked account
 * ({@code localUser=directoryUsername}) or a role mapping ({@code group=RBAC role}).
 * Both sides are trimmed and never empty.
 */
public record NamePair(String left, String right) {
}
