/*
 * Copyright 2020 Google LLC
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

import static com.google.api.client.util.Preconditions.checkNotNull;
import static com.google.common.base.MoreObjects.firstNonNull;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.http.AuthHttpConstants;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Base external account credentials class.
 *
 * <p>Handles initializing 3PI credentials, calls to STS and service account impersonation.
 */
public abstract class ExternalAccountCredentials extends GoogleCredentials
    implements QuotaProjectIdProvider {

  /** Base credential source class. Dictates the retrieval method of the 3PI credential. */
  abstract static class CredentialSource {

    protected Map<String, Object> credentialSourceMap;

    protected CredentialSource(Map<String, Object> credentialSourceMap) {
      this.credentialSourceMap = checkNotNull(credentialSourceMap);
    }
  }

  private static final String RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";

  static final String EXTERNAL_ACCOUNT_FILE_TYPE = "external_account";

  protected final String transportFactoryClassName;
  protected final String audience;
  protected final String subjectTokenType;
  protected final String tokenUrl;
  protected final String tokenInfoUrl;
  protected final String serviceAccountImpersonationUrl;
  protected final CredentialSource credentialSource;

  @Nullable protected final Collection<String> scopes;
  @Nullable protected final String quotaProjectId;
  @Nullable protected final String clientId;
  @Nullable protected final String clientSecret;

  protected transient HttpTransportFactory transportFactory;

  /**
   * Constructor with minimum identifying information and custom HTTP transport.
   *
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @param audience The STS audience which is usually the fully specified resource name of the
   *     workload/workforce pool provider.
   * @param subjectTokenType The STS subject token type based on the OAuth 2.0 token exchange spec.
   *     Indicates the type of the security token in the credential file.
   * @param tokenUrl The STS token exchange endpoint.
   * @param tokenInfoUrl The endpoint used to retrieve account related information. Required for
   *     gCloud session account identification.
   * @param credentialSource The 3PI credential source.
   * @param serviceAccountImpersonationUrl The URL for the service account impersonation request.
   *     This is only required for workload identity pools when APIs to be accessed have not
   *     integrated with UberMint. If this is not available, the STS returned GCP access token is
   *     directly used. May be null.
   * @param quotaProjectId The project used for quota and billing purposes. May be null.
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientSecret Client secret of the service account from the console. May be null.
   * @param scopes The scopes to request during the authorization grant. May be null.
   */
  protected ExternalAccountCredentials(
      HttpTransportFactory transportFactory,
      String audience,
      String subjectTokenType,
      String tokenUrl,
      String tokenInfoUrl,
      CredentialSource credentialSource,
      @Nullable String serviceAccountImpersonationUrl,
      @Nullable String quotaProjectId,
      @Nullable String clientId,
      @Nullable String clientSecret,
      @Nullable Collection<String> scopes) {
    this.transportFactory =
        firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = checkNotNull(this.transportFactory.getClass().getName());
    this.audience = checkNotNull(audience);
    this.subjectTokenType = checkNotNull(subjectTokenType);
    this.tokenUrl = checkNotNull(tokenUrl);
    this.tokenInfoUrl = checkNotNull(tokenInfoUrl);
    this.credentialSource = checkNotNull(credentialSource);
    this.serviceAccountImpersonationUrl = serviceAccountImpersonationUrl;
    this.quotaProjectId = quotaProjectId;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scopes =
        (scopes == null || scopes.isEmpty()) ? Arrays.asList(CLOUD_PLATFORM_SCOPE) : scopes;
  }

  /**
   * Returns credentials defined by a JSON file stream.
   *
   * <p>This will either return {@link IdentityPoolCredentials} or AwsCredentials.
   *
   * @param credentialsStream the stream with the credential definition.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static ExternalAccountCredentials fromStream(InputStream credentialsStream)
      throws IOException {
    return fromStream(credentialsStream, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  /**
   * Returns credentials defined by a JSON file stream.
   *
   * <p>This will either return a IdentityPoolCredentials or AwsCredentials.
   *
   * @param credentialsStream the stream with the credential definition.
   * @param transportFactory the HTTP transport factory used to create the transport to get access
   *     tokens.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static ExternalAccountCredentials fromStream(
      InputStream credentialsStream, HttpTransportFactory transportFactory) throws IOException {
    checkNotNull(credentialsStream);
    checkNotNull(transportFactory);

    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    GenericJson fileContents =
        parser.parseAndClose(credentialsStream, OAuth2Utils.UTF_8, GenericJson.class);
    return fromJson(fileContents, transportFactory);
  }

  /**
   * Returns external account credentials defined by JSON using the format generated by gCloud.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   */
  public static ExternalAccountCredentials fromJson(
      Map<String, Object> json, HttpTransportFactory transportFactory) {
    checkNotNull(json);
    checkNotNull(transportFactory);

    String audience = (String) json.get("audience");
    String subjectTokenType = (String) json.get("subject_token_type");
    String tokenUrl = (String) json.get("token_url");
    String tokenInfoUrl = (String) json.get("token_info_url");
    String serviceAccountImpersonationUrl = (String) json.get("service_account_impersonation_url");

    Map<String, Object> credentialSourceMap = (Map<String, Object>) json.get("credential_source");

    // Optional params.
    String clientId = json.containsKey("client_id") ? (String) json.get("client_id") : null;
    String clientSecret =
        json.containsKey("client_secret") ? (String) json.get("client_secret") : null;
    String quotaProjectId =
        json.containsKey("quota_project_id") ? (String) json.get("quota_project_id") : null;

    if (isAwsCredential(credentialSourceMap)) {
      // TODO(lsirac) return AWS credential here.
    }
    return new IdentityPoolCredentials(
        transportFactory,
        audience,
        subjectTokenType,
        tokenUrl,
        tokenInfoUrl,
        new IdentityPoolCredentialSource(credentialSourceMap),
        serviceAccountImpersonationUrl,
        quotaProjectId,
        clientId,
        clientSecret,
        /* scopes= */ null);
  }

  private static boolean isAwsCredential(Map<String, Object> credentialSource) {
    return credentialSource.containsKey("environment_id")
        && ((String) credentialSource.get("environment_id")).startsWith("aws");
  }

  /**
   * Exchanges the 3PI credential for a GCP access token.
   *
   * @param stsTokenExchangeRequest the STS token exchange request.
   * @return the access token returned by STS.
   * @throws OAuthException if the call to STS fails.
   */
  protected AccessToken exchange3PICredentialForAccessToken(
      StsTokenExchangeRequest stsTokenExchangeRequest) throws IOException {

    StsRequestHandler requestHandler =
        StsRequestHandler.newBuilder(
                tokenUrl, stsTokenExchangeRequest, transportFactory.create().createRequestFactory())
            .setHeaders(new HttpHeaders().setContentType("application/x-www-form-urlencoded"))
            .build();

    StsTokenExchangeResponse response = requestHandler.exchangeToken();
    return response.getAccessToken();
  }

  /**
   * Attempts service account impersonation.
   *
   * @param accessToken the access token to be included in the request.
   * @return the access token returned by the generateAccessToken call.
   * @throws OAuthException if the service account impersonation call fails.
   */
  protected AccessToken attemptServiceAccountImpersonation(AccessToken accessToken)
      throws IOException {
    if (serviceAccountImpersonationUrl == null) {
      return accessToken;
    }

    HttpRequest request =
        transportFactory
            .create()
            .createRequestFactory()
            .buildPostRequest(
                new GenericUrl(serviceAccountImpersonationUrl),
                new UrlEncodedContent(new GenericData().set("scope", scopes.toArray())));
    request.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));
    request.setHeaders(
        new HttpHeaders()
            .setAuthorization(
                String.format("%s %s", AuthHttpConstants.BEARER, accessToken.getTokenValue())));

    HttpResponse response;
    try {
      response = request.execute();
    } catch (IOException e) {
      throw new IOException(
          String.format("Error getting access token for service account: %s", e.getMessage()), e);
    }

    GenericData responseData = response.parseAs(GenericData.class);
    String token =
        OAuth2Utils.validateString(responseData, "accessToken", "Expected to find an accessToken");

    DateFormat format = new SimpleDateFormat(RFC3339);
    String expireTime =
        OAuth2Utils.validateString(responseData, "expireTime", "Expected to find an expireTime");
    try {
      Date date = format.parse(expireTime);
      return new AccessToken(token, date);
    } catch (ParseException e) {
      throw new IOException("Error parsing expireTime: " + e.getMessage());
    }
  }

  /**
   * Retrieves the 3PI subject token to be exchanged for a GCP access token.
   *
   * <p>Must be implemented by subclasses as the retrieval method is dependent on the credential
   * source.
   *
   * @return the 3PI subject token
   */
  public abstract String retrieveSubjectToken() throws IOException;

  public String getAudience() {
    return audience;
  }

  public String getSubjectTokenType() {
    return subjectTokenType;
  }

  public String getTokenUrl() {
    return tokenUrl;
  }

  public String getTokenInfoUrl() {
    return tokenInfoUrl;
  }

  public CredentialSource getCredentialSource() {
    return credentialSource;
  }

  @Nullable
  public String getServiceAccountImpersonationUrl() {
    return serviceAccountImpersonationUrl;
  }

  @Override
  @Nullable
  public String getQuotaProjectId() {
    return quotaProjectId;
  }

  @Nullable
  public String getClientId() {
    return clientId;
  }

  @Nullable
  public String getClientSecret() {
    return clientSecret;
  }

  @Nullable
  public Collection<String> getScopes() {
    return scopes;
  }

  /** Base builder for external account credentials. */
  public abstract static class Builder extends GoogleCredentials.Builder {

    protected String audience;
    protected String subjectTokenType;
    protected String tokenUrl;
    protected String tokenInfoUrl;
    protected CredentialSource credentialSource;
    protected HttpTransportFactory transportFactory;

    @Nullable protected String serviceAccountImpersonationUrl;
    @Nullable protected String quotaProjectId;
    @Nullable protected String clientId;
    @Nullable protected String clientSecret;
    @Nullable protected Collection<String> scopes;

    protected Builder() {}

    protected Builder(ExternalAccountCredentials credentials) {
      this.audience = credentials.audience;
      this.subjectTokenType = credentials.subjectTokenType;
      this.tokenUrl = credentials.tokenUrl;
      this.tokenInfoUrl = credentials.tokenInfoUrl;
      this.serviceAccountImpersonationUrl = credentials.serviceAccountImpersonationUrl;
      this.credentialSource = credentials.credentialSource;
      this.quotaProjectId = credentials.quotaProjectId;
      this.clientId = credentials.clientId;
      this.clientSecret = credentials.clientSecret;
      this.scopes = credentials.scopes;
    }

    public Builder setAudience(String audience) {
      this.audience = audience;
      return this;
    }

    public Builder setSubjectTokenType(String subjectTokenType) {
      this.subjectTokenType = subjectTokenType;
      return this;
    }

    public Builder setTokenUrl(String tokenUrl) {
      this.tokenUrl = tokenUrl;
      return this;
    }

    public Builder setTokenInfoUrl(String tokenInfoUrl) {
      this.tokenInfoUrl = tokenInfoUrl;
      return this;
    }

    public Builder setServiceAccountImpersonationUrl(String serviceAccountImpersonationUrl) {
      this.serviceAccountImpersonationUrl = serviceAccountImpersonationUrl;
      return this;
    }

    public Builder setCredentialSource(CredentialSource credentialSource) {
      this.credentialSource = credentialSource;
      return this;
    }

    public Builder setScopes(Collection<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public Builder setQuotaProjectId(String quotaProjectId) {
      this.quotaProjectId = quotaProjectId;
      return this;
    }

    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder setClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public abstract ExternalAccountCredentials build();
  }
}
