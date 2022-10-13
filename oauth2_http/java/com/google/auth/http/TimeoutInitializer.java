package com.google.auth.http;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;

public class TimeoutInitializer implements HttpRequestInitializer {

    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    public TimeoutInitializer(int connectTimeoutMillis, int readTimeoutMillis) {
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
    }

    @Override
    public void initialize(HttpRequest request) {
        request.setConnectTimeout(connectTimeoutMillis);
        request.setReadTimeout(readTimeoutMillis);
    }
}
