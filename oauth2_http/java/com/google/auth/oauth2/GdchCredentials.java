/*
 * Copyright 2015, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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

import static com.google.common.base.MoreObjects.firstNonNull;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;
import com.google.api.client.util.SecurityUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

public class GdchCredentials extends GoogleCredentials implements JwtProvider {

  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final int DEFAULT_LIFETIME_IN_SECONDS = 3600;

  private final PrivateKey privateKey;
  private final String privateKeyId;
  private final String projectId;
  private final String serviceIdentityName;
  private final URI tokenServerUri;
  private final URI apiAudience;
  private final int lifetime;
  private transient HttpTransportFactory transportFactory;

  /**
   * Internal constructor.
   *
   * @param builder A builder for {@link GdchCredentials} See {@link
   *     GdchCredentials.Builder}.
   */
  GdchCredentials(GdchCredentials.Builder builder) {

    this.projectId = builder.projectId;
    this.privateKeyId = builder.privateKeyId;
    this.privateKey = builder.privateKey;
    this.serviceIdentityName = builder.serviceIdentityName;
    this.tokenServerUri = builder.tokenServerUri;

    this.transportFactory =
        firstNonNull(
            builder.transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.apiAudience = builder.apiAudience;
    this.lifetime = builder.lifetime;
  }

  /**
   * Create GDCH service account credentials defined by JSON.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the GDCH service account credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   */
  static GdchCredentials fromJson(Map<String, Object> json,
      HttpTransportFactory transportFactory) throws IOException {

    String formatVersion = (String) json.get("format_version");
    String projectId = (String) json.get("project");
    String privateKeyId = (String) json.get("private_key_id");
    String privateKeyPkcs8 = (String) json.get("private_key");
    String serviceIdentityName = (String) json.get("name");
    String tokenServerUriStringFromCreds = (String) json.get("token_uri");

    if (formatVersion == null
        || privateKeyPkcs8 == null
        || privateKeyId == null
        || projectId == null
        || serviceIdentityName == null
        || tokenServerUriStringFromCreds == null) {
      throw new IOException(
          "Error reading GDCH service account credential from JSON, "
              + "expecting 'format_version', 'private_key', 'private_key_id', 'project', 'name' and 'token_uri'.");
    }

    if (!formatVersion.equals("1")) {
      throw new IOException("Only format version 1 is supported.");
    }

    URI tokenServerUriFromCreds = null;
    try {
      if (tokenServerUriStringFromCreds != null) {
        tokenServerUriFromCreds = new URI(tokenServerUriStringFromCreds);
      }
    } catch (URISyntaxException e) {
      throw new IOException("Token server URI specified in 'token_uri' could not be parsed.");
    }

    GdchCredentials.Builder builder = GdchCredentials.newBuilder()
        .setProjectId(projectId)
        .setPrivateKeyId(privateKeyId)
        .setTokenServerUri(tokenServerUriFromCreds)
        .setServiceIdentityName(serviceIdentityName)
        .setHttpTransportFactory(transportFactory);

    return fromPkcs8(privateKeyPkcs8, builder);
  }

  /**
   * Internal constructor
   *
   * @param privateKeyPkcs8 RSA private key object for the service account in PKCS#8 format.
   * @param builder A builder for GdchCredentials.
   * @return an instance of GdchCredentials.
   */
  static GdchCredentials fromPkcs8(
      String privateKeyPkcs8,
      GdchCredentials.Builder builder) throws IOException {
    PrivateKey privateKey = privateKeyFromPkcs8(privateKeyPkcs8);
    builder.setPrivateKey(privateKey);

    return new GdchCredentials(builder);
  }

  /** Helper to convert from a PKCS#8 String to an RSA private key */
  static PrivateKey privateKeyFromPkcs8(String privateKeyPkcs8) throws IOException {
    Reader reader = new StringReader(privateKeyPkcs8);
    Section section = PemReader.readFirstSectionAndClose(reader, "PRIVATE KEY");
    if (section == null) {
      throw new IOException("Invalid PKCS#8 data.");
    }
    byte[] bytes = section.getBase64DecodedBytes();
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
    Exception unexpectedException;
    try {
      KeyFactory keyFactory = SecurityUtils.getRsaKeyFactory();
      return keyFactory.generatePrivate(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
      unexpectedException = exception;
    }
    throw new IOException("Unexpected exception reading PKCS#8 data",
        unexpectedException);
  }

  /**
   * Create a copy of GDCH credentials with the specified audience.
   * @param apiAudience The intended audience for GDCH credentials.
   */
  public GdchCredentials createWithGdchAudience(URI apiAudience) throws IOException {

    if (apiAudience == null) {
      throw new IOException(
          "Audience are not configured for GDCH service account credentials.");
    }
    return this.toBuilder()
        .setGdchAudience(apiAudience).build();
  }

  /**
   * Refresh the OAuth2 access token by getting a new access
   * token using a JSON Web Token (JWT).
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {

    if (this.apiAudience == null) {
      throw new IOException(
          "Audience are not configured for GDCH service account. Specify the "
              + "audience by calling createWithGDCHAudience.");
    }

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTime = clock.currentTimeMillis();
    String assertion = createAssertion(jsonFactory, currentTime, getApiAudience());

    GenericData tokenRequest = new GenericData();
    tokenRequest.set("grant_type", GRANT_TYPE);
    tokenRequest.set("assertion", assertion);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(tokenServerUri), content);

    request.setParser(new JsonObjectParser(jsonFactory));

    HttpResponse response;
    String errorTemplate = "Error getting access token for GDCH service account: %s, iss: %s";

    try {
      response = request.execute();
    } catch (HttpResponseException re) {
      String message = String.format(errorTemplate, re.getMessage(), getServiceIdentityName());
      throw GoogleAuthException.createWithTokenEndpointResponseException(re, message);
    } catch (IOException e) {
      throw GoogleAuthException.createWithTokenEndpointIOException(
          e, String.format(errorTemplate, e.getMessage(), getServiceIdentityName()));
    }

    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken =
        OAuth2Utils.validateString(responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds =
        OAuth2Utils.validateInt32(responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000L;
    return new AccessToken(accessToken, new Date(expiresAtMilliseconds));
  }

  /**
   * Create a self-signed JWT.
   *
   */
  String createAssertion(JsonFactory jsonFactory, long currentTime, URI apiAudience) throws IOException {

    // Set JWT header.
    JsonWebSignature.Header header = new JsonWebSignature.Header();
    header.setAlgorithm("RS256");
    header.setType("JWT");
    header.setKeyId(privateKeyId);

    // Set JWT payload.
    JsonWebToken.Payload payload = new JsonWebToken.Payload();
    payload.setIssuer(getIssSubValue());
    payload.setSubject(getIssSubValue());
    payload.setIssuedAtTimeSeconds(currentTime / 1000);
    payload.setExpirationTimeSeconds(currentTime / 1000 + this.lifetime);
    payload.setAudience(getTokenServerUri().toString());

    // Sign the JWT by calling the existing JsonWebSignature library.
    String assertion;
    try {
      payload.set("api_audience", apiAudience.toString());
      assertion = JsonWebSignature.signUsingRsaSha256(privateKey, jsonFactory, header, payload);
    } catch (GeneralSecurityException e) {
      throw new IOException(
          "Error signing service account access token request with private key.", e);
    }

    return assertion;
  }

  /**
   * Get the issuer and subject value in the format GDCH token server required.
   *
   */
  @VisibleForTesting
  String getIssSubValue() {
    return String.format("system:serviceaccount:%s:%s", getProjectId(), getServiceIdentityName());
  }

  /**
   * Return a new JwtCredentials instance with modified claims.
   *
   * @param newClaims new claims. Any unspecified claim fields will default to the the current
   *     values.
   * @return new credentials
   */
  @Override
  public JwtCredentials jwtWithClaims(JwtClaims newClaims) {

    JwtClaims.Builder claimsBuilder =
        JwtClaims.newBuilder()
            .setIssuer(getIssSubValue())
            .setSubject(getIssSubValue());
    return JwtCredentials.newBuilder()
        .setPrivateKey(privateKey)
        .setPrivateKeyId(privateKeyId)
        .setJwtClaims(claimsBuilder.build().merge(newClaims))
        .setClock(clock)
        .build();
  }

  public final String getProjectId() {
    return projectId;
  }

  public final String getPrivateKeyId() {
    return privateKeyId;
  }

  public final PrivateKey getPrivateKey() {
    return privateKey;
  }

  public final String getServiceIdentityName() {
    return serviceIdentityName;
  }

  public final URI getTokenServerUri() {
    return tokenServerUri;
  }

  public final URI getApiAudience() {
    return apiAudience;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("projectId", projectId)
        .add("privateKeyId", privateKeyId)
        .add("privateKey", privateKey)
        .add("serviceIdentityName", serviceIdentityName)
        .add("tokenServerUri", tokenServerUri)
        .add("lifetime", lifetime)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof GdchCredentials)) {
      return false;
    }
    GdchCredentials other = (GdchCredentials) obj;
    return Objects.equals(this.projectId, other.projectId)
        && Objects.equals(this.privateKeyId, other.privateKeyId)
        && Objects.equals(this.privateKey, other.privateKey)
        && Objects.equals(this.serviceIdentityName, other.serviceIdentityName)
        && Objects.equals(this.tokenServerUri, other.tokenServerUri)
        && Objects.equals(this.lifetime, other.lifetime);
  }

  public static class Builder extends GoogleCredentials.Builder {

    private String projectId;
    private String privateKeyId;
    private PrivateKey privateKey;
    private String serviceIdentityName;
    private URI tokenServerUri;
    private URI apiAudience;
    private HttpTransportFactory transportFactory;
    private int lifetime = DEFAULT_LIFETIME_IN_SECONDS;

    protected Builder() {}

    protected Builder(GdchCredentials credentials) {
      this.privateKey = credentials.privateKey;
      this.privateKeyId = credentials.privateKeyId;
      this.projectId = credentials.projectId;
      this.tokenServerUri = credentials.tokenServerUri;
      this.serviceIdentityName = credentials.serviceIdentityName;
      this.transportFactory = credentials.transportFactory;
      this.lifetime = credentials.lifetime;
    }

    public Builder setProjectId(String projectId) {
      this.projectId = projectId;
      return this;
    }

    public Builder setPrivateKeyId(String privateKeyId) {
      this.privateKeyId = privateKeyId;
      return this;
    }

    public Builder setPrivateKey(PrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public Builder setServiceIdentityName(String name) {
      this.serviceIdentityName = name;
      return this;
    }

    public Builder setTokenServerUri(URI tokenServerUri) {
      this.tokenServerUri = tokenServerUri;
      return this;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public Builder setLifetime(int lifetime) {
      this.lifetime = lifetime == 0 ? DEFAULT_LIFETIME_IN_SECONDS : lifetime;
      return this;
    }

    public Builder setGdchAudience(URI apiAudience) {
      this.apiAudience = apiAudience;
      return this;
    }

    public String getProjectId() {
      return projectId;
    }

    public String getPrivateKeyId() {
      return privateKeyId;
    }

    public PrivateKey getPrivateKey() {
      return privateKey;
    }

    public String getServiceIdentityName() {
      return serviceIdentityName;
    }

    public URI getTokenServerUri() {
      return tokenServerUri;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public int getLifetime() {
      return lifetime;
    }

    public GdchCredentials build() {
      return new GdchCredentials(this);
    }

  }
}
