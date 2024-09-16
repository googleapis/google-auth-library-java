package com.google.auth;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class ApiKeyCredentials extends Credentials {
  static final String API_KEY_HEADER_KEY = "x-goog-api-key";
  private final String apiKey;

  ApiKeyCredentials(String apiKey) {
    this.apiKey = apiKey;
  }

  public static ApiKeyCredentials create(String apiKey) {
    return new ApiKeyCredentials(apiKey);
  }

  @Override
  public String getAuthenticationType() {
    return "";
  }

  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    return Collections.singletonMap(API_KEY_HEADER_KEY, Collections.singletonList(apiKey));
  }

  @Override
  public boolean hasRequestMetadata() {
    return true;
  }

  @Override
  public boolean hasRequestMetadataOnly() {
    return true;
  }

  @Override
  public void refresh() throws IOException {
    // no-op
  }
}
