/*
 * Copyright 2025, Google LLC
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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpBackOffIOExceptionHandler;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpIOExceptionHandler;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpUnsuccessfulResponseHandler;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.client.util.Key;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.base.Preconditions;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.annotation.Nullable;

/**
 * Represents the trust boundary configuration for a credential. This class holds the information
 * retrieved from the IAM `allowedLocations` endpoint. This data is then used to populate the
 * `x-allowed-locations` header in outgoing API requests, which in turn allows Google's
 * infrastructure to enforce regional security restrictions. This class does not perform any
 * client-side validation or enforcement.
 */
final class TrustBoundary {

  static final String TRUST_BOUNDARY_KEY = "x-allowed-locations";
  static final String GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR =
      "GOOGLE_AUTH_TRUST_BOUNDARY_ENABLE_EXPERIMENT";
  private static final String NO_OP_VALUE = "0x0";
  private final String encodedLocations;
  private final List<String> locations;

  /**
   * Creates a new TrustBoundary instance.
   *
   * @param encodedLocations The encoded string representation of the allowed locations.
   * @param locations A list of human-readable location strings.
   */
  TrustBoundary(String encodedLocations, List<String> locations) {
    this.encodedLocations = encodedLocations;
    this.locations =
        locations == null
            ? Collections.<String>emptyList()
            : Collections.unmodifiableList(locations);
  }

  private static EnvironmentProvider environmentProvider = SystemEnvironmentProvider.getInstance();

  /** Returns the encoded string representation of the allowed locations. */
  public String getEncodedLocations() {
    return encodedLocations;
  }

  /** Returns a list of human-readable location strings. */
  public List<String> getLocations() {
    return locations;
  }

  /**
   * Checks if this TrustBoundary represents a "no-op" (no restrictions).
   *
   * @return True if the encoded locations indicate no restrictions, false otherwise.
   */
  public boolean isNoOp() {
    return NO_OP_VALUE.equals(encodedLocations);
  }

  /** Represents the JSON response from the trust boundary endpoint. */
  public static class TrustBoundaryResponse extends GenericJson {
    @Key("encodedLocations")
    private String encodedLocations;

    @Key("locations")
    private List<String> locations;

    /** Returns the encoded string representation of the allowed locations from the API response. */
    public String getEncodedLocations() {
      return encodedLocations;
    }

    /** Returns a list of human-readable location strings from the API response. */
    public List<String> getLocations() {
      return locations;
    }

    @Override
    /** Returns a string representation of the TrustBoundaryResponse. */
    public String toString() {
      return MoreObjects.toStringHelper(this)
          .add("encodedLocations", encodedLocations)
          .add("locations", locations)
          .toString();
    }
  }

  @VisibleForTesting
  static void setEnvironmentProviderForTest(@Nullable EnvironmentProvider provider) {
    environmentProvider = provider == null ? SystemEnvironmentProvider.getInstance() : provider;
  }

  /**
   * Checks if the trust boundary feature is enabled based on an environment variable. The feature
   * is enabled if the environment variable is set to "true" or "1" (case-insensitive). Any other
   * value, or if the variable is unset, will result in the feature being disabled.
   *
   * @return True if the trust boundary feature is enabled, false otherwise.
   */
  static boolean isTrustBoundaryEnabled() {
    String trustBoundaryEnabled =
        environmentProvider.getEnv(GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR);
    if (trustBoundaryEnabled == null) {
      return false;
    }
    String lowercasedTrustBoundaryEnabled = trustBoundaryEnabled.toLowerCase();
    return "true".equals(lowercasedTrustBoundaryEnabled) || "1".equals(trustBoundaryEnabled);
  }

  /**
   * Refreshes the trust boundary by making a network call to the trust boundary endpoint.
   *
   * @param transportFactory The HTTP transport factory to use for the network request.
   * @param url The URL of the trust boundary endpoint.
   * @param accessToken The access token to authenticate the request.
   * @param cachedTrustBoundary An optional previously cached trust boundary, which may be used in
   *     the request headers.
   * @return A new TrustBoundary object containing the refreshed information.
   * @throws IllegalArgumentException If the provided access token is null or expired.
   * @throws IOException If a network error occurs or the response is malformed.
   */
  static TrustBoundary refresh(
      HttpTransportFactory transportFactory,
      String url,
      AccessToken accessToken,
      @Nullable TrustBoundary cachedTrustBoundary)
      throws IOException {
    Preconditions.checkNotNull(accessToken, "The provided access token is null.");
    if (accessToken.getExpirationTime() != null
        && accessToken.getExpirationTime().before(new Date())) {
      throw new IllegalArgumentException("The provided access token is expired.");
    }

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));
    //    request.getHeaders().setAuthorization("Bearer " + accessToken.getTokenValue());

    // Add the cached trust boundary header, if available.
    if (cachedTrustBoundary != null) {
      String headerValue =
          cachedTrustBoundary.isNoOp() ? "" : cachedTrustBoundary.getEncodedLocations();
      //      request.getHeaders().set(TRUST_BOUNDARY_KEY, headerValue);
    }

    // Add retry logic
    ExponentialBackOff backoff =
        new ExponentialBackOff.Builder()
            .setInitialIntervalMillis(OAuth2Utils.INITIAL_RETRY_INTERVAL_MILLIS)
            .setRandomizationFactor(OAuth2Utils.RETRY_RANDOMIZATION_FACTOR)
            .setMultiplier(OAuth2Utils.RETRY_MULTIPLIER)
            .build();

    HttpUnsuccessfulResponseHandler unsuccessfulResponseHandler =
        new HttpBackOffUnsuccessfulResponseHandler(backoff);
    request.setUnsuccessfulResponseHandler(unsuccessfulResponseHandler);

    HttpIOExceptionHandler ioExceptionHandler = new HttpBackOffIOExceptionHandler(backoff);
    request.setIOExceptionHandler(ioExceptionHandler);

    TrustBoundaryResponse json;
    try {
      HttpResponse response = request.execute();
      String responseString = response.parseAsString();
      JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(responseString);
      json = parser.parseAndClose(TrustBoundaryResponse.class);
    } catch (IOException e) {
      throw new IOException("TrustBoundary: Failure while getting trust boundaries:", e);
    }
    String encodedLocations = json.getEncodedLocations();
    // The encodedLocations is the value attached to the x-allowed-locations header and
    // it should always have a value. In case of NO_OP the lookup endpoint returns
    // encodedLocations as '0x0' and locations as null. That is why we only check for
    // encodedLocations.
    if (encodedLocations == null) {
      throw new IOException(
          "TrustBoundary: Malformed response from lookup endpoint - `encodedLocations` was null.");
    }
    return new TrustBoundary(encodedLocations, json.getLocations());
  }
}
