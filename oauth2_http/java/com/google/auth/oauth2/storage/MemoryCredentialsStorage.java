package com.google.auth.oauth2.storage;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class MemoryCredentialsStorage implements TokenStore {

    private Map<String, String> tokensStorage;

    public MemoryCredentialsStorage() {
        tokensStorage = new HashMap<>();
    }

    @Override
    public String load(String id) throws IOException {
        return tokensStorage.get(id);
    }

    @Override
    public void store(String id, String tokens) throws IOException {
        tokensStorage.put(id, tokens);
    }

    @Override
    public void delete(String id) throws IOException {
        tokensStorage.remove(id);
    }
}
