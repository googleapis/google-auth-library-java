/*
 * Copyright 2022 Google LLC
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

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.Preconditions;
import com.google.auth.http.HttpTransportFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * OAuth2 credentials sourced using external identities through Workforce Identity Federation. These
 * credentials usually access resources on behalf of a user (resource owner).
 *
 * <p>Obtaining the initial access and refresh token can be done through the Google Cloud CLI.
 *
 * <pre>
 * Example credentials file:
 * {
 *   "type": "external_account_authorized_user",
 *   "audience": "//iam.googleapis.com/locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID",
 *   "refresh_token": "refreshToken",
 *   "token_url": "https://sts.googleapis.com/v1/oauth/token",
 *   "token_info_url": "https://sts.googleapis.com/v1/instrospect",
 *   "client_id": "clientId",
 *   "client_secret": "clientSecret"
 * }
 * </pre>
 */
public class ExternalAccountAuthorizedUserCredentials extends GoogleCredentials {

  private static final String GRANT_TYPE = "refresh_token";
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final long serialVersionUID = -4800758775038679176L;

  private final String transportFactoryClassName;
  private final String audience;
  private final String refreshToken;
  private final String tokenUrl;
  private final String tokenInfoUrl;
  private final String revokeUrl;
  private final String clientId;
  private final String clientSecret;

  private transient HttpTransportFactory transportFactory;

  /**
   * Internal constructor.
   *
   * @param builder A builder for {@link ExternalAccountAuthorizedUserCredentials} See {@link
   *     ExternalAccountAuthorizedUserCredentials.Builder}.
   */
  private ExternalAccountAuthorizedUserCredentials(Builder builder) {
    super(builder.getAccessToken(), builder.getQuotaProjectId());
    this.audience = builder.audience;
    this.refreshToken = builder.refreshToken;
    this.tokenUrl = builder.tokenUrl;
    this.tokenInfoUrl = builder.tokenInfoUrl;
    this.revokeUrl = builder.revokeUrl;
    this.clientId = builder.clientId;
    this.clientSecret = builder.clientSecret;

    this.transportFactory =
        firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = this.transportFactory.getClass().getName();

    Preconditions.checkState(
        getAccessToken() != null
            || (refreshToken != null
                && refreshToken.trim().length() > 0
                && tokenUrl != null
                && tokenUrl.trim().length() > 0
                && clientId != null
                && clientId.trim().length() > 0
                && clientSecret != null
                && clientSecret.trim().length() > 0),
        "Initialize with either accessToken or fields to enable refresh (refresh_token "
            + "token_url, client_id, client_secret).");
  }

  /**
   * Returns external account authorized user credentials defined by JSON contents using the format
   * supported by the Cloud SDK.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the external account authorized user credentials defined by the JSON.
   */
  static ExternalAccountAuthorizedUserCredentials fromJson(
      Map<String, Object> json, HttpTransportFactory transportFactory) {
    String audience = (String) json.get("audience");
    String refreshToken = (String) json.get("refresh_token");
    String tokenUrl = (String) json.get("token_url");
    String tokenInfoUrl = (String) json.get("token_info_url");
    String revokeUrl = (String) json.get("revoke_url");
    String clientId = (String) json.get("client_id");
    String clientSecret = (String) json.get("client_secret");
    String quotaProjectId = (String) json.get("quota_project_id");

    return (ExternalAccountAuthorizedUserCredentials)
        ExternalAccountAuthorizedUserCredentials.newBuilder()
            .setAudience(audience)
            .setRefreshToken(refreshToken)
            .setTokenUrl(tokenUrl)
            .setTokenInfoUrl(tokenInfoUrl)
            .setRevokeUrl(revokeUrl)
            .setClientId(clientId)
            .setClientSecret(clientSecret)
            .setRefreshToken(refreshToken)
            .setHttpTransportFactory(transportFactory)
            .setQuotaProjectId(quotaProjectId)
            .build();
  }

  /**
   * Returns external account authorized user credentials defined by a JSON file stream.
   *
   * @param credentialsStream the stream with the credential definition
   * @param transportFactory the HTTP transport factory used to create the transport to get access
   *     tokens
   * @return the credential defined by the credentialsStream
   * @throws IOException if the credential cannot be created from the stream
   */
  public static ExternalAccountAuthorizedUserCredentials fromStream(
          InputStream credentialsStream, HttpTransportFactory transportFactory) throws IOException {
    checkNotNull(credentialsStream);
    checkNotNull(transportFactory);

    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    GenericJson fileContents =
            parser.parseAndClose(credentialsStream, StandardCharsets.UTF_8, GenericJson.class);
    try {
      return fromJson(fileContents, transportFactory);
    } catch (ClassCastException | IllegalArgumentException e) {
      throw new CredentialFormatException("An invalid input stream was provided.", e);
    }
  }

  @Nullable
  public String getAudience() {
    return this.audience;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  /** Builder for {@link ExternalAccountAuthorizedUserCredentials}. */
  public static class Builder extends GoogleCredentials.Builder {

    private HttpTransportFactory transportFactory;
    private String audience;
    private String refreshToken;
    private String tokenUrl;
    private String tokenInfoUrl;
    private String revokeUrl;
    private String clientId;
    private String clientSecret;

    @Nullable protected String quotaProjectId;

    protected Builder() {}

    protected Builder(ExternalAccountAuthorizedUserCredentials credentials) {
      this.transportFactory = credentials.transportFactory;
      this.audience = credentials.audience;
      this.refreshToken = credentials.refreshToken;
      this.tokenUrl = credentials.tokenUrl;
      this.tokenInfoUrl = credentials.tokenInfoUrl;
      this.clientId = credentials.clientId;
      this.clientSecret = credentials.clientSecret;
      this.quotaProjectId = credentials.quotaProjectId;
    }

    /**
     * Sets the HTTP transport factory.
     *
     * @param transportFactory the {@code HttpTransportFactory} to set
     * @return this {@code Builder} object
     */
    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    /**
     * Sets the optional Security Token Service audience, which is usually the fully specified
     * resource name of the workforce pool provider.
     *
     * @param audience the Security Token Service audience to set
     * @return this {@code Builder} object
     */
    public Builder setAudience(String audience) {
      this.audience = audience;
      return this;
    }

    /**
     * Sets the Security Token Service token exchange endpoint.
     *
     * @param tokenUrl the Security Token Service token exchange url to set
     * @return this {@code Builder} object
     */
    public Builder setTokenUrl(String tokenUrl) {
      this.tokenUrl = tokenUrl;
      return this;
    }

    /**
     * Sets the Security Token Service token introspection endpoint used to retrieve account related
     * information.
     *
     * @param tokenInfoUrl the token info url to set
     * @return this {@code Builder} object
     */
    public Builder setTokenInfoUrl(String tokenInfoUrl) {
      this.tokenInfoUrl = tokenInfoUrl;
      return this;
    }

    /**
     * Sets the Security Token Service token revocation endpoint.
     *
     * @param revokeUrl the revoke url to set
     * @return this {@code Builder} object
     */
    public Builder setRevokeUrl(String revokeUrl) {
      this.revokeUrl = revokeUrl;
      return this;
    }

    /**
     * Sets the OAuth 2.0 refresh token.
     *
     * @param refreshToken the refresh token
     * @return this {@code Builder} object
     */
    public Builder setRefreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
      return this;
    }

    /**
     * Sets the OAuth 2.0 client ID.
     *
     * @param clientId the client ID
     * @return this {@code Builder} object
     */
    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /**
     * Sets the OAuth 2.0 client secret.
     *
     * @param clientSecret the client secret
     * @return this {@code Builder} object
     */
    public Builder setClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public ExternalAccountAuthorizedUserCredentials build() {
      return new ExternalAccountAuthorizedUserCredentials(this);
    }
  }
}
