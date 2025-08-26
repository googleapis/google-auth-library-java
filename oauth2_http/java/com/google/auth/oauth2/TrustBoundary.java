/*
 * Copyright 2024, Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.annotation.Nullable;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.api.client.util.Key;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.MoreObjects;

/**
 * Represents a trust boundary that can be used to restrict access to resources. This is an
 * experimental feature.
 */
public final class TrustBoundary {

static final String TRUST_BOUNDARY_KEY = "x-allowed-locations";
  static final String GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR =
      "GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED";
  private static final String NO_OP_VALUE = "0x0";
  private final String encodedLocations;
  private final List<String> locations;

  private TrustBoundary(String encodedLocations, List<String> locations) {
    this.encodedLocations = encodedLocations;
    this.locations =
        locations == null ? Collections.<String>emptyList() : Collections.unmodifiableList(locations);
  }

  private static EnvironmentProvider environmentProvider = SystemEnvironmentProvider.getInstance();

    public String getEncodedLocations() {
    return encodedLocations;
  }

  public List<String> getLocations() {
    return locations;
  }

  public boolean isNoOp() {
    return NO_OP_VALUE.equals(encodedLocations);
  }

    /** Represents the JSON response from the trust boundary endpoint. */
  public static class TrustBoundaryResponse extends GenericJson {
    @Key("encodedLocations")
    private String encodedLocations;

    @Key("locations")
    private List<String> locations;

    public String getEncodedLocations() {
      return encodedLocations;
    }

    public List<String> getLocations() {
      return locations;
    }

    @Override
    public String toString() {
      return MoreObjects.toStringHelper(this)
          .add("encodedLocations", encodedLocations)
          .add("locations", locations)
          .toString();
    }
  }

  // expose this setter only for testing purposes
  static void setEnvironmentProvider(EnvironmentProvider provider) {
    environmentProvider = provider;
  }

  static boolean isTrustBoundaryEnabled() throws IOException {
    String tbEnabled = environmentProvider.getEnv(GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR);
    if (tbEnabled == null) {
      return false;
    }
    String lowercasedTbEnabled = tbEnabled.toLowerCase();
    if ("true".equals(lowercasedTbEnabled) || "1".equals(tbEnabled)) {
      return true;
    }
    if ("false".equals(lowercasedTbEnabled) || "0".equals(tbEnabled)) {
      return false;
    }
    throw new IOException(
        String.format(
            "Invalid value for %s environment variable: \"%s\". Supported values are 'true', '1', 'false', or '0'.",
            GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR,
            tbEnabled));
  }

  static TrustBoundary refresh(
      HttpTransportFactory transportFactory,
      String url,
      AccessToken accessToken,
      @Nullable TrustBoundary cachedTrustBoundary)
      throws IOException {
    if (accessToken == null) {
      throw new IOException("The provided access token is null.");
    }
    if (accessToken.getExpirationTime() != null
        && accessToken.getExpirationTime().before(new Date())) {
      throw new IOException("The provided access token is expired.");
    }

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));
    // request.getHeaders().setAuthorization("Bearer " + accessToken.getTokenValue());

    // Add the cached trust boundary header, if available.
    if (cachedTrustBoundary != null) {
      String headerValue =
          cachedTrustBoundary.isNoOp() ? "" : cachedTrustBoundary.getEncodedLocations();
      // request.getHeaders().set(TRUST_BOUNDARY_KEY, headerValue);
    }
        TrustBoundaryResponse json;
    try {
      HttpResponse response = request.execute();
      String responseString = response.parseAsString();
      System.out.println("TrustBoundary lookup endpoint response: " + responseString);
      JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(responseString);
      json = parser.parseAndClose(TrustBoundaryResponse.class);
      System.out.println("TrustBoundary lookup endpoint json response: " + json.toString());

    } catch (HttpResponseException e) {
      throw new IOException(
          String.format(
              "Unexpected error response when retrieving trust boundary: %s", e.getMessage()),
          e);
    } catch (IOException e) {
      throw new IOException("Failed to retrieve or parse trust boundary.", e);
    }
    String encodedLocations = json.getEncodedLocations();
    if (encodedLocations == null) {
      throw new IOException("TrustBoundary: Malformed response from lookup endpoint.");
    }
    return new TrustBoundary(encodedLocations, json.getLocations());
  }
}