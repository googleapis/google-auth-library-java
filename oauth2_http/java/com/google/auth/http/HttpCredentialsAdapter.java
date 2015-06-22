package com.google.auth.http;

import com.google.auth.Credentials;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.util.Preconditions;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A wrapper for using Credentials with the Google API Client Libraries for Java with Http.
 */
public class HttpCredentialsAdapter implements HttpRequestInitializer {

  private final Credentials credentials;

  /**
   * @param credentials Credentials instance to adapt for HTTP
   */
  public HttpCredentialsAdapter(Credentials credentials) {
    Preconditions.checkNotNull(credentials);
    this.credentials = credentials;
  }

    /**
     * Initialize the HTTP request prior to execution.
     *
     * @param request HTTP request
     */
  public void initialize(HttpRequest request) throws IOException {
    if (!credentials.hasRequestMetadata()) {
      return;
    }
    HttpHeaders requestHeaders = request.getHeaders();
    URI uri = request.getUrl().toURI();
    Map<String, List<String>> credentialHeaders = credentials.getRequestMetadata(uri);
    if (credentialHeaders == null) {
      return;
    }
    for (Map.Entry<String, List<String>> entry : credentialHeaders.entrySet()) {
      String headerName = entry.getKey();
      List<String> requestValues = getHeadersValue(requestHeaders, headerName);
      if (requestValues == null) {
        requestValues = new ArrayList<String>();
        requestHeaders.put(headerName, requestValues);
      }
      List<String> credentialValues = entry.getValue();
      for (String credentialValue : credentialValues) {
        requestValues.add(credentialValue);
      }
    }
  }

  // Get header value, casting to List<String>.
  @SuppressWarnings("unchecked")
  private List<String> getHeadersValue(HttpHeaders headers, String headerName) {
    return (List<String>) headers.get(headerName);
  }
}
