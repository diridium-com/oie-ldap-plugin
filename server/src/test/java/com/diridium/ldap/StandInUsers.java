// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.ldap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.model.Credentials;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStrike;
import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.UserController;

/**
 * The engine's user controller, as far as the plugin uses it, behaving as engine
 * v4.7.0's DefaultUserController does: {@code getUser} matches
 * {@code LOWER(USERNAME) = LOWER(name)} without trimming and prefers the exact
 * case; {@code updateUser} refuses a duplicate name and doesn't hand back the
 * new id. Writes are recorded in {@link #writes}.
 */
class StandInUsers extends UserController {

    final Map<Integer, User> users = new LinkedHashMap<>();
    /** The account links that go with these accounts, kept here so a test passes one object around. */
    final MemoryLinks links = new MemoryLinks();
    final Map<Integer, Map<String, String>> preferences = new HashMap<>();
    final List<String> writes = new ArrayList<>();
    private int nextId = 1;

    /** An existing engine account, as an administrator made it. */
    User add(String username) {
        User user = new User();
        user.setId(nextId++);
        user.setUsername(username);
        users.put(user.getId(), user);
        return user;
    }

    String preference(Integer userId, String name) {
        return preferences.getOrDefault(userId, Map.of()).get(name);
    }

    User byName(String username) {
        for (User user : users.values()) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }

    @Override
    public List<User> getAllUsers() {
        return new ArrayList<>(users.values());
    }

    @Override
    public User getUser(Integer userId, String userName) throws ControllerException {
        if (userId == null && userName == null) {
            throw new ControllerException("Both user ID and user name cannot be null.");
        }
        if (userId != null) {
            return users.get(userId);
        }
        List<User> matches = new ArrayList<>();
        for (User user : users.values()) {
            if (user.getUsername().toLowerCase(Locale.ROOT).equals(userName.toLowerCase(Locale.ROOT))) {
                matches.add(user);
            }
        }
        for (User user : matches) {
            if (user.getUsername().equals(userName)) {
                return user;
            }
        }
        return matches.isEmpty() ? null : matches.get(0);
    }

    @Override
    public void updateUser(User user) throws ControllerException {
        if (user.getId() == null) {
            if (getUser(null, user.getUsername()) != null) {
                throw new ControllerException("Error adding user: username must be unique");
            }
            User stored = new User();
            stored.setId(nextId++);
            stored.setUsername(user.getUsername());
            stored.setFirstName(user.getFirstName());
            stored.setLastName(user.getLastName());
            stored.setEmail(user.getEmail());
            stored.setOrganization(user.getOrganization());
            users.put(stored.getId(), stored);
            writes.add("insert " + user.getUsername());
        } else {
            users.put(user.getId(), user);
            writes.add("update " + user.getUsername());
        }
    }

    @Override
    public String getUserPreference(Integer userId, String name) {
        return preference(userId, name);
    }

    @Override
    public void setUserPreference(Integer userId, String name, String value) {
        preferences.computeIfAbsent(userId, id -> new HashMap<>()).put(name, value);
        writes.add("preference " + userId + " " + name + "=" + value);
    }

    private static UnsupportedOperationException unused() {
        return new UnsupportedOperationException("not used by the plugin");
    }

    @Override public void resetUserStatus() { throw unused(); }
    @Override public List<String> checkOrUpdateUserPassword(Integer userId, String plainPassword) { throw unused(); }
    @Override public void removeUser(Integer userId, Integer currentUserId) { throw unused(); }
    @Override public LoginStatus authorizeUser(String username, String plainPassword, String serverURL) { throw unused(); }
    @Override public boolean checkPassword(String plainPassword, String encryptedPassword) { throw unused(); }
    @Override public void loginUser(User user) { throw unused(); }
    @Override public void logoutUser(User user) { throw unused(); }
    @Override public boolean isUserLoggedIn(Integer userId) { throw unused(); }
    @Override public List<Credentials> getUserCredentials(Integer userId) { throw unused(); }
    @Override public LoginStrike incrementStrikes(Integer userId) { throw unused(); }
    @Override public LoginStrike resetStrikes(Integer userId) { throw unused(); }
    @Override public Properties getUserPreferences(Integer userId, Set<String> names) { throw unused(); }
    @Override public void setUserPreferences(Integer userId, Properties properties) { throw unused(); }
    @Override public void removePreferencesForUser(int id) { throw unused(); }
    @Override public void removePreference(int id, String name) { throw unused(); }
}
