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

import static com.google.auth.oauth2.OAuth2Utils.JSON_FACTORY;
import static com.google.auth.oauth2.OAuth2Utils.UTF_8;
import static com.google.common.base.MoreObjects.firstNonNull;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Preconditions;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.MoreObjects;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** OAuth2 Credentials representing a user's identity and consent. */
public class UserCredentials extends GoogleCredentials implements QuotaProjectIdProvider {

  private static final String GRANT_TYPE = "refresh_token";
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final long serialVersionUID = -4800758775038679176L;

  private final String clientId;
  private final String clientSecret;
  private final String refreshToken;
  private final URI tokenServerUri;
  private final String transportFactoryClassName;
  private final String quotaProjectId;

  private transient HttpTransportFactory transportFactory;

  /**
   * Constructor with all parameters allowing custom transport and server URL.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   * @param accessToken Initial or temporary access token.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @param tokenServerUri URI of the end point that provides tokens
   */
  private UserCredentials(
      String clientId,
      String clientSecret,
      String refreshToken,
      AccessToken accessToken,
      HttpTransportFactory transportFactory,
      URI tokenServerUri,
      String quotaProjectId) {
    super(accessToken);
    this.clientId = Preconditions.checkNotNull(clientId);
    this.clientSecret = Preconditions.checkNotNull(clientSecret);
    this.refreshToken = refreshToken;
    this.transportFactory =
        firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.tokenServerUri = (tokenServerUri == null) ? OAuth2Utils.TOKEN_SERVER_URI : tokenServerUri;
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
    this.quotaProjectId = quotaProjectId;
    Preconditions.checkState(
        accessToken != null || refreshToken != null,
        "Either accessToken or refreshToken must not be null");
  }

  /**
   * Returns user credentials defined by JSON contents using the format supported by the Cloud SDK.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   */
  static UserCredentials fromJson(Map<String, Object> json, HttpTransportFactory transportFactory)
      throws IOException {
    String clientId = (String) json.get("client_id");
    String clientSecret = (String) json.get("client_secret");
    String refreshToken = (String) json.get("refresh_token");
    String quotaProjectId = (String) json.get("quota_project_id");
    if (clientId == null || clientSecret == null || refreshToken == null) {
      throw new IOException(
          "Error reading user credential from JSON, "
              + " expecting 'client_id', 'client_secret' and 'refresh_token'.");
    }
    return UserCredentials.newBuilder()
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setRefreshToken(refreshToken)
        .setAccessToken(null)
        .setHttpTransportFactory(transportFactory)
        .setTokenServerUri(null)
        .setQuotaProjectId(quotaProjectId)
        .build();
  }

  /**
   * Returns credentials defined by a JSON file stream using the format supported by the Cloud SDK.
   *
   * @param credentialsStream the stream with the credential definition.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static UserCredentials fromStream(InputStream credentialsStream) throws IOException {
    return fromStream(credentialsStream, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  /**
   * Returns credentials defined by a JSON file stream using the format supported by the Cloud SDK.
   *
   * @param credentialsStream the stream with the credential definition.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static UserCredentials fromStream(
      InputStream credentialsStream, HttpTransportFactory transportFactory) throws IOException {
    Preconditions.checkNotNull(credentialsStream);
    Preconditions.checkNotNull(transportFactory);

    JsonFactory jsonFactory = JSON_FACTORY;
    JsonObjectParser parser = new JsonObjectParser(jsonFactory);
    GenericJson fileContents =
        parser.parseAndClose(credentialsStream, OAuth2Utils.UTF_8, GenericJson.class);

    String fileType = (String) fileContents.get("type");
    if (fileType == null) {
      throw new IOException("Error reading credentials from stream, 'type' field not specified.");
    }
    if (USER_FILE_TYPE.equals(fileType)) {
      return fromJson(fileContents, transportFactory);
    }
    throw new IOException(
        String.format(
            "Error reading credentials from stream, 'type' value '%s' not recognized."
                + " Expecting '%s'.",
            fileType, USER_FILE_TYPE));
  }

  /** Refreshes the OAuth2 access token by getting a new access token from the refresh token */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (refreshToken == null) {
      throw new IllegalStateException(
          "UserCredentials instance cannot refresh because there is no" + " refresh token.");
    }
    GenericData tokenRequest = new GenericData();
    tokenRequest.set("client_id", clientId);
    tokenRequest.set("client_secret", clientSecret);
    tokenRequest.set("refresh_token", refreshToken);
    tokenRequest.set("grant_type", GRANT_TYPE);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(tokenServerUri), content);
    request.setParser(new JsonObjectParser(JSON_FACTORY));
    HttpResponse response = request.execute();
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken =
        OAuth2Utils.validateString(responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds =
        OAuth2Utils.validateInt32(responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000;
    return new AccessToken(accessToken, new Date(expiresAtMilliseconds));
  }

  /**
   * Returns client ID of the credential from the console.
   *
   * @return client ID
   */
  public final String getClientId() {
    return clientId;
  }

  /**
   * Returns client secret of the credential from the console.
   *
   * @return client secret
   */
  public final String getClientSecret() {
    return clientSecret;
  }

  /**
   * Returns the refresh token resulting from a OAuth2 consent flow.
   *
   * @return refresh token
   */
  public final String getRefreshToken() {
    return refreshToken;
  }

  /**
   * Returns the instance of InputStream containing the following user credentials in JSON format: -
   * RefreshToken - ClientId - ClientSecret - ServerTokenUri
   *
   * @return user credentials stream
   */
  private InputStream getUserCredentialsStream() throws IOException {
    GenericJson json = new GenericJson();
    json.put("type", GoogleCredentials.USER_FILE_TYPE);
    if (refreshToken != null) {
      json.put("refresh_token", refreshToken);
    }
    if (tokenServerUri != null) {
      json.put("token_server_uri", tokenServerUri);
    }
    if (clientId != null) {
      json.put("client_id", clientId);
    }
    if (clientSecret != null) {
      json.put("client_secret", clientSecret);
    }
    if (quotaProjectId != null) {
      json.put("quota_project", clientSecret);
    }
    json.setFactory(JSON_FACTORY);
    String text = json.toPrettyString();
    return new ByteArrayInputStream(text.getBytes(UTF_8));
  }

  /**
   * Saves the end user credentials into the given file path.
   *
   * @param filePath Path to file where to store the credentials
   * @throws IOException An error storing the credentials.
   */
  public void save(String filePath) throws IOException {
    OAuth2Utils.writeInputStreamToFile(getUserCredentialsStream(), filePath);
  }

  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    Map<String, List<String>> requestMetadata = super.getRequestMetadata(uri);
    return addQuotaProjectIdToRequestMetadata(quotaProjectId, requestMetadata);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        super.hashCode(),
        clientId,
        clientSecret,
        refreshToken,
        tokenServerUri,
        transportFactoryClassName,
        quotaProjectId);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("requestMetadata", getRequestMetadataInternal())
        .add("temporaryAccess", getAccessToken())
        .add("clientId", clientId)
        .add("refreshToken", refreshToken)
        .add("tokenServerUri", tokenServerUri)
        .add("transportFactoryClassName", transportFactoryClassName)
        .add("quotaProjectId", quotaProjectId)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof UserCredentials)) {
      return false;
    }
    UserCredentials other = (UserCredentials) obj;
    return super.equals(other)
        && Objects.equals(this.clientId, other.clientId)
        && Objects.equals(this.clientSecret, other.clientSecret)
        && Objects.equals(this.refreshToken, other.refreshToken)
        && Objects.equals(this.tokenServerUri, other.tokenServerUri)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName)
        && Objects.equals(this.quotaProjectId, other.quotaProjectId);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    transportFactory = newInstance(transportFactoryClassName);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public String getQuotaProjectId() {
    return quotaProjectId;
  }

  public static class Builder extends GoogleCredentials.Builder {

    private String clientId;
    private String clientSecret;
    private String refreshToken;
    private URI tokenServerUri;
    private HttpTransportFactory transportFactory;
    private String quotaProjectId;

    protected Builder() {}

    protected Builder(UserCredentials credentials) {
      this.clientId = credentials.clientId;
      this.clientSecret = credentials.clientSecret;
      this.refreshToken = credentials.refreshToken;
      this.transportFactory = credentials.transportFactory;
      this.tokenServerUri = credentials.tokenServerUri;
      this.quotaProjectId = credentials.quotaProjectId;
    }

    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder setClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public Builder setRefreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
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

    public Builder setAccessToken(AccessToken token) {
      super.setAccessToken(token);
      return this;
    }

    public Builder setQuotaProjectId(String quotaProjectId) {
      this.quotaProjectId = quotaProjectId;
      return this;
    }

    public String getClientId() {
      return clientId;
    }

    public String getClientSecret() {
      return clientSecret;
    }

    public String getRefreshToken() {
      return refreshToken;
    }

    public URI getTokenServerUri() {
      return tokenServerUri;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public String getQuotaProjectId() {
      return quotaProjectId;
    }

    public UserCredentials build() {
      return new UserCredentials(
          clientId,
          clientSecret,
          refreshToken,
          getAccessToken(),
          transportFactory,
          tokenServerUri,
          quotaProjectId);
    }
  }
}
