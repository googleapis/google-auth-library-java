/*
 * Copyright 2021 Google LLC
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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.RequestMetadataCallback;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AwsCredentials.AwsCredentialSource;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource;
import com.google.common.base.MoreObjects;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * Base external account credentials class.
 *
 * <p>Handles initializing external credentials, calls to the Security Token Service, and service
 * account impersonation.
 */
public abstract class ExternalAccountCredentials extends GoogleCredentials
    implements QuotaProjectIdProvider {

  /** Base credential source class. Dictates the retrieval method of the external credential. */
  abstract static class CredentialSource {

    CredentialSource(Map<String, Object> credentialSourceMap) {
      checkNotNull(credentialSourceMap);
    }
  }

  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";

  static final String EXTERNAL_ACCOUNT_FILE_TYPE = "external_account";

  private final String transportFactoryClassName;
  private final String audience;
  private final String subjectTokenType;
  private final String tokenUrl;
  private final CredentialSource credentialSource;
  private final Collection<String> scopes;

  @Nullable private final String tokenInfoUrl;
  @Nullable private final String serviceAccountImpersonationUrl;
  @Nullable private final String quotaProjectId;
  @Nullable private final String clientId;
  @Nullable private final String clientSecret;

  // This is used for Workforce Pools. It is passed to the Security Token Service during token
  // exchange in the `options` param and will be embedded in the token by the Security Token
  // Service.
  @Nullable private final String workforcePoolUserProject;

  protected transient HttpTransportFactory transportFactory;

  @Nullable protected final ImpersonatedCredentials impersonatedCredentials;

  private EnvironmentProvider environmentProvider;

  /**
   * Constructor with minimum identifying information and custom HTTP transport. Does not support
   * workforce credentials.
   *
   * @param transportFactory HTTP transport factory, creates the transport used to get access tokens
   * @param audience the Security Token Service audience, which is usually the fully specified
   *     resource name of the workload/workforce pool provider
   * @param subjectTokenType the Security Token Service subject token type based on the OAuth 2.0
   *     token exchange spec. Indicates the type of the security token in the credential file
   * @param tokenUrl the Security Token Service token exchange endpoint
   * @param tokenInfoUrl the endpoint used to retrieve account related information. Required for
   *     gCloud session account identification.
   * @param credentialSource the external credential source
   * @param serviceAccountImpersonationUrl the URL for the service account impersonation request.
   *     This URL is required for some APIs. If this URL is not available, the access token from the
   *     Security Token Service is used directly. May be null.
   * @param quotaProjectId the project used for quota and billing purposes. May be null.
   * @param clientId client ID of the service account from the console. May be null.
   * @param clientSecret client secret of the service account from the console. May be null.
   * @param scopes the scopes to request during the authorization grant. May be null.
   */
  protected ExternalAccountCredentials(
      HttpTransportFactory transportFactory,
      String audience,
      String subjectTokenType,
      String tokenUrl,
      CredentialSource credentialSource,
      @Nullable String tokenInfoUrl,
      @Nullable String serviceAccountImpersonationUrl,
      @Nullable String quotaProjectId,
      @Nullable String clientId,
      @Nullable String clientSecret,
      @Nullable Collection<String> scopes) {
    this(
        transportFactory,
        audience,
        subjectTokenType,
        tokenUrl,
        credentialSource,
        tokenInfoUrl,
        serviceAccountImpersonationUrl,
        quotaProjectId,
        clientId,
        clientSecret,
        scopes,
        /* environmentProvider= */ null);
  }

  /**
   * See {@link ExternalAccountCredentials#ExternalAccountCredentials(HttpTransportFactory, String,
   * String, String, CredentialSource, String, String, String, String, String, Collection)}
   *
   * @param environmentProvider the environment provider. May be null. Defaults to {@link
   *     SystemEnvironmentProvider}.
   */
  protected ExternalAccountCredentials(
      HttpTransportFactory transportFactory,
      String audience,
      String subjectTokenType,
      String tokenUrl,
      CredentialSource credentialSource,
      @Nullable String tokenInfoUrl,
      @Nullable String serviceAccountImpersonationUrl,
      @Nullable String quotaProjectId,
      @Nullable String clientId,
      @Nullable String clientSecret,
      @Nullable Collection<String> scopes,
      @Nullable EnvironmentProvider environmentProvider) {
    this.transportFactory =
        MoreObjects.firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = checkNotNull(this.transportFactory.getClass().getName());
    this.audience = checkNotNull(audience);
    this.subjectTokenType = checkNotNull(subjectTokenType);
    this.tokenUrl = checkNotNull(tokenUrl);
    this.credentialSource = checkNotNull(credentialSource);
    this.tokenInfoUrl = tokenInfoUrl;
    this.serviceAccountImpersonationUrl = serviceAccountImpersonationUrl;
    this.quotaProjectId = quotaProjectId;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scopes =
        (scopes == null || scopes.isEmpty()) ? Arrays.asList(CLOUD_PLATFORM_SCOPE) : scopes;
    this.environmentProvider =
        environmentProvider == null ? SystemEnvironmentProvider.getInstance() : environmentProvider;
    this.workforcePoolUserProject = null;

    validateTokenUrl(tokenUrl);
    if (serviceAccountImpersonationUrl != null) {
      validateServiceAccountImpersonationInfoUrl(serviceAccountImpersonationUrl);
    }

    this.impersonatedCredentials = initializeImpersonatedCredentials();
  }

  /**
   * Internal constructor with minimum identifying information and custom HTTP transport. See {@link
   * ExternalAccountCredentials.Builder}.
   */
  protected ExternalAccountCredentials(ExternalAccountCredentials.Builder builder) {
    this.transportFactory =
        MoreObjects.firstNonNull(
            builder.transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = checkNotNull(this.transportFactory.getClass().getName());
    this.audience = checkNotNull(builder.audience);
    this.subjectTokenType = checkNotNull(builder.subjectTokenType);
    this.tokenUrl = checkNotNull(builder.tokenUrl);
    this.credentialSource = checkNotNull(builder.credentialSource);
    this.tokenInfoUrl = builder.tokenInfoUrl;
    this.serviceAccountImpersonationUrl = builder.serviceAccountImpersonationUrl;
    this.quotaProjectId = builder.quotaProjectId;
    this.clientId = builder.clientId;
    this.clientSecret = builder.clientSecret;
    this.scopes =
        (builder.scopes == null || builder.scopes.isEmpty())
            ? Arrays.asList(CLOUD_PLATFORM_SCOPE)
            : builder.scopes;
    this.environmentProvider =
        builder.environmentProvider == null
            ? SystemEnvironmentProvider.getInstance()
            : builder.environmentProvider;

    this.workforcePoolUserProject = builder.workforcePoolUserProject;
    if (workforcePoolUserProject != null && !isWorkforcePoolConfiguration()) {
      throw new IllegalArgumentException(
          "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.");
    }

    validateTokenUrl(tokenUrl);
    if (serviceAccountImpersonationUrl != null) {
      validateServiceAccountImpersonationInfoUrl(serviceAccountImpersonationUrl);
    }

    this.impersonatedCredentials = initializeImpersonatedCredentials();
  }

  private ImpersonatedCredentials initializeImpersonatedCredentials() {
    if (serviceAccountImpersonationUrl == null) {
      return null;
    }
    // Create a copy of this instance without service account impersonation.
    ExternalAccountCredentials sourceCredentials;
    if (this instanceof AwsCredentials) {
      sourceCredentials =
          AwsCredentials.newBuilder((AwsCredentials) this)
              .setServiceAccountImpersonationUrl(null)
              .build();
    } else {
      sourceCredentials =
          IdentityPoolCredentials.newBuilder((IdentityPoolCredentials) this)
              .setServiceAccountImpersonationUrl(null)
              .build();
    }

    String targetPrincipal =
        ImpersonatedCredentials.extractTargetPrincipal(serviceAccountImpersonationUrl);
    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setHttpTransportFactory(transportFactory)
        .setTargetPrincipal(targetPrincipal)
        .setScopes(new ArrayList<>(scopes))
        .setLifetime(3600) // 1 hour in seconds
        .setIamEndpointOverride(serviceAccountImpersonationUrl)
        .build();
  }

  @Override
  public void getRequestMetadata(
      URI uri, Executor executor, final RequestMetadataCallback callback) {
    super.getRequestMetadata(
        uri,
        executor,
        new RequestMetadataCallback() {
          @Override
          public void onSuccess(Map<String, List<String>> metadata) {
            metadata = addQuotaProjectIdToRequestMetadata(quotaProjectId, metadata);
            callback.onSuccess(metadata);
          }

          @Override
          public void onFailure(Throwable exception) {
            callback.onFailure(exception);
          }
        });
  }

  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    Map<String, List<String>> requestMetadata = super.getRequestMetadata(uri);
    return addQuotaProjectIdToRequestMetadata(quotaProjectId, requestMetadata);
  }

  /**
   * Returns credentials defined by a JSON file stream.
   *
   * <p>Returns {@link IdentityPoolCredentials} or {@link AwsCredentials}.
   *
   * @param credentialsStream the stream with the credential definition
   * @return the credential defined by the credentialsStream
   * @throws IOException if the credential cannot be created from the stream
   */
  public static ExternalAccountCredentials fromStream(InputStream credentialsStream)
      throws IOException {
    return fromStream(credentialsStream, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  /**
   * Returns credentials defined by a JSON file stream.
   *
   * <p>Returns a {@link IdentityPoolCredentials} or {@link AwsCredentials}.
   *
   * @param credentialsStream the stream with the credential definition
   * @param transportFactory the HTTP transport factory used to create the transport to get access
   *     tokens
   * @return the credential defined by the credentialsStream
   * @throws IOException if the credential cannot be created from the stream
   */
  public static ExternalAccountCredentials fromStream(
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

  /**
   * Returns external account credentials defined by JSON using the format generated by gCloud.
   *
   * @param json a map from the JSON representing the credentials
   * @param transportFactory HTTP transport factory, creates the transport used to get access tokens
   * @return the credentials defined by the JSON
   */
  static ExternalAccountCredentials fromJson(
      Map<String, Object> json, HttpTransportFactory transportFactory) {
    checkNotNull(json);
    checkNotNull(transportFactory);

    String audience = (String) json.get("audience");
    String subjectTokenType = (String) json.get("subject_token_type");
    String tokenUrl = (String) json.get("token_url");

    Map<String, Object> credentialSourceMap = (Map<String, Object>) json.get("credential_source");

    // Optional params.
    String serviceAccountImpersonationUrl = (String) json.get("service_account_impersonation_url");
    String tokenInfoUrl = (String) json.get("token_info_url");
    String clientId = (String) json.get("client_id");
    String clientSecret = (String) json.get("client_secret");
    String quotaProjectId = (String) json.get("quota_project_id");
    String userProject = (String) json.get("workforce_pool_user_project");

    if (isAwsCredential(credentialSourceMap)) {
      return AwsCredentials.newBuilder()
          .setHttpTransportFactory(transportFactory)
          .setAudience(audience)
          .setSubjectTokenType(subjectTokenType)
          .setTokenUrl(tokenUrl)
          .setTokenInfoUrl(tokenInfoUrl)
          .setCredentialSource(new AwsCredentialSource(credentialSourceMap))
          .setServiceAccountImpersonationUrl(serviceAccountImpersonationUrl)
          .setQuotaProjectId(quotaProjectId)
          .setClientId(clientId)
          .setClientSecret(clientSecret)
          .build();
    }

    return IdentityPoolCredentials.newBuilder()
        .setHttpTransportFactory(transportFactory)
        .setAudience(audience)
        .setSubjectTokenType(subjectTokenType)
        .setTokenUrl(tokenUrl)
        .setTokenInfoUrl(tokenInfoUrl)
        .setCredentialSource(new IdentityPoolCredentialSource(credentialSourceMap))
        .setServiceAccountImpersonationUrl(serviceAccountImpersonationUrl)
        .setQuotaProjectId(quotaProjectId)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setWorkforcePoolUserProject(userProject)
        .build();
  }

  private static boolean isAwsCredential(Map<String, Object> credentialSource) {
    return credentialSource.containsKey("environment_id")
        && ((String) credentialSource.get("environment_id")).startsWith("aws");
  }

  /**
   * Exchanges the external credential for a Google Cloud access token.
   *
   * @param stsTokenExchangeRequest the Security Token Service token exchange request
   * @return the access token returned by the Security Token Service
   * @throws OAuthException if the call to the Security Token Service fails
   */
  protected AccessToken exchangeExternalCredentialForAccessToken(
      StsTokenExchangeRequest stsTokenExchangeRequest) throws IOException {
    // Handle service account impersonation if necessary.
    if (impersonatedCredentials != null) {
      return impersonatedCredentials.refreshAccessToken();
    }

    StsRequestHandler.Builder requestHandler =
        StsRequestHandler.newBuilder(
            tokenUrl, stsTokenExchangeRequest, transportFactory.create().createRequestFactory());

    // If this credential was initialized with a Workforce configuration then the
    // workforcePoolUserProject must be passed to the Security Token Service via the internal
    // options param.
    if (isWorkforcePoolConfiguration()) {
      GenericJson options = new GenericJson();
      options.setFactory(OAuth2Utils.JSON_FACTORY);
      options.put("userProject", workforcePoolUserProject);
      requestHandler.setInternalOptions(options.toString());
    }

    if (stsTokenExchangeRequest.getInternalOptions() != null) {
      // Overwrite internal options. Let subclass handle setting options.
      requestHandler.setInternalOptions(stsTokenExchangeRequest.getInternalOptions());
    }

    StsTokenExchangeResponse response = requestHandler.build().exchangeToken();
    return response.getAccessToken();
  }

  /**
   * Retrieves the external subject token to be exchanged for a Google Cloud access token.
   *
   * <p>Must be implemented by subclasses as the retrieval method is dependent on the credential
   * source.
   *
   * @return the external subject token
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

  @Nullable
  public String getWorkforcePoolUserProject() {
    return workforcePoolUserProject;
  }

  EnvironmentProvider getEnvironmentProvider() {
    return environmentProvider;
  }

  /**
   * Returns whether or not the current configuration is for Workforce Pools (which enable 3p user
   * identities, rather than workloads).
   */
  public boolean isWorkforcePoolConfiguration() {
    Pattern workforceAudiencePattern =
        Pattern.compile("^//iam.googleapis.com/locations/.+/workforcePools/.+/providers/.+$");
    return workforcePoolUserProject != null
        && workforceAudiencePattern.matcher(getAudience()).matches();
  }

  static void validateTokenUrl(String tokenUrl) {
    List<Pattern> patterns = new ArrayList<>();
    patterns.add(Pattern.compile("^[^\\.\\s\\/\\\\]+\\.sts\\.googleapis\\.com$"));
    patterns.add(Pattern.compile("^sts\\.googleapis\\.com$"));
    patterns.add(Pattern.compile("^sts\\.[^\\.\\s\\/\\\\]+\\.googleapis\\.com$"));
    patterns.add(Pattern.compile("^[^\\.\\s\\/\\\\]+\\-sts\\.googleapis\\.com$"));

    if (!isValidUrl(patterns, tokenUrl)) {
      throw new IllegalArgumentException("The provided token URL is invalid.");
    }
  }

  static void validateServiceAccountImpersonationInfoUrl(String serviceAccountImpersonationUrl) {
    List<Pattern> patterns = new ArrayList<>();
    patterns.add(Pattern.compile("^[^\\.\\s\\/\\\\]+\\.iamcredentials\\.googleapis\\.com$"));
    patterns.add(Pattern.compile("^iamcredentials\\.googleapis\\.com$"));
    patterns.add(Pattern.compile("^iamcredentials\\.[^\\.\\s\\/\\\\]+\\.googleapis\\.com$"));
    patterns.add(Pattern.compile("^[^\\.\\s\\/\\\\]+\\-iamcredentials\\.googleapis\\.com$"));

    if (!isValidUrl(patterns, serviceAccountImpersonationUrl)) {
      throw new IllegalArgumentException(
          "The provided service account impersonation URL is invalid.");
    }
  }

  /**
   * Returns true if the provided URL's scheme is HTTPS and the host comforms to at least one of the
   * provided patterns.
   */
  private static boolean isValidUrl(List<Pattern> patterns, String url) {
    URI uri;

    try {
      uri = URI.create(url);
    } catch (Exception e) {
      return false;
    }

    // Scheme must be https and host must not be null.
    if (uri.getScheme() == null
        || uri.getHost() == null
        || !"https".equals(uri.getScheme().toLowerCase(Locale.US))) {
      return false;
    }

    for (Pattern pattern : patterns) {
      Matcher match = pattern.matcher(uri.getHost().toLowerCase(Locale.US));
      if (match.matches()) {
        return true;
      }
    }
    return false;
  }

  /** Base builder for external account credentials. */
  public abstract static class Builder extends GoogleCredentials.Builder {

    protected String audience;
    protected String subjectTokenType;
    protected String tokenUrl;
    protected String tokenInfoUrl;
    protected CredentialSource credentialSource;
    protected EnvironmentProvider environmentProvider;
    protected HttpTransportFactory transportFactory;

    @Nullable protected String serviceAccountImpersonationUrl;
    @Nullable protected String quotaProjectId;
    @Nullable protected String clientId;
    @Nullable protected String clientSecret;
    @Nullable protected Collection<String> scopes;
    @Nullable protected String workforcePoolUserProject;

    protected Builder() {}

    protected Builder(ExternalAccountCredentials credentials) {
      this.transportFactory = credentials.transportFactory;
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
      this.environmentProvider = credentials.environmentProvider;
      this.workforcePoolUserProject = credentials.workforcePoolUserProject;
    }

    /** Sets the HTTP transport factory, creates the transport used to get access tokens. */
    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    /**
     * Sets the Security Token Service audience, which is usually the fully specified resource name
     * of the workload/workforce pool provider.
     */
    public Builder setAudience(String audience) {
      this.audience = audience;
      return this;
    }

    /**
     * Sets the Security Token Service subject token type based on the OAuth 2.0 token exchange
     * spec. Indicates the type of the security token in the credential file.
     */
    public Builder setSubjectTokenType(String subjectTokenType) {
      this.subjectTokenType = subjectTokenType;
      return this;
    }

    /** Sets the Security Token Service token exchange endpoint. */
    public Builder setTokenUrl(String tokenUrl) {
      this.tokenUrl = tokenUrl;
      return this;
    }

    /** Sets the external credential source. */
    public Builder setCredentialSource(CredentialSource credentialSource) {
      this.credentialSource = credentialSource;
      return this;
    }

    /**
     * Sets the optional URL used for service account impersonation, which is required for some
     * APIs. If this URL is not available, the access token from the Security Token Service is used
     * directly.
     */
    public Builder setServiceAccountImpersonationUrl(String serviceAccountImpersonationUrl) {
      this.serviceAccountImpersonationUrl = serviceAccountImpersonationUrl;
      return this;
    }

    /**
     * Sets the optional endpoint used to retrieve account related information. Required for gCloud
     * session account identification.
     */
    public Builder setTokenInfoUrl(String tokenInfoUrl) {
      this.tokenInfoUrl = tokenInfoUrl;
      return this;
    }

    /** Sets the optional project used for quota and billing purposes. */
    public Builder setQuotaProjectId(String quotaProjectId) {
      this.quotaProjectId = quotaProjectId;
      return this;
    }

    /** Sets the optional client ID of the service account from the console. */
    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /** Sets the optional client secret of the service account from the console. */
    public Builder setClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    /** Sets the optional scopes to request during the authorization grant. */
    public Builder setScopes(Collection<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    /**
     * Sets the optional workforce pool user project number when the credential corresponds to a
     * workforce pool and not a workload identity pool. The underlying principal must still have
     * serviceusage.services.use IAM permission to use the project for billing/quota.
     */
    public Builder setWorkforcePoolUserProject(String workforcePoolUserProject) {
      this.workforcePoolUserProject = workforcePoolUserProject;
      return this;
    }

    Builder setEnvironmentProvider(EnvironmentProvider environmentProvider) {
      this.environmentProvider = environmentProvider;
      return this;
    }

    public abstract ExternalAccountCredentials build();
  }
}
