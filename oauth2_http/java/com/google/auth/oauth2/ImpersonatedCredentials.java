/*
 * Copyright 2018, Google Inc. All rights reserved.
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
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.ServiceAccountSigner;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * ImpersonatedCredentials allowing credentials issued to a user or service account to impersonate
 * another. The source project using ImpersonatedCredentials must enable the "IAMCredentials" API.
 * Also, the target service account must grant the originating principal the "Service Account Token
 * Creator" IAM role.
 *
 * <p>Usage:
 *
 * <pre>
 * String credPath = "/path/to/svc_account.json";
 * ServiceAccountCredentials sourceCredentials = ServiceAccountCredentials
 *     .fromStream(new FileInputStream(credPath));
 * sourceCredentials = (ServiceAccountCredentials) sourceCredentials
 *     .createScoped(Arrays.asList("https://www.googleapis.com/auth/iam"));
 *
 * ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
 *     "impersonated-account@project.iam.gserviceaccount.com", null,
 *     Arrays.asList("https://www.googleapis.com/auth/devstorage.read_only"), 300);
 *
 * Storage storage_service = StorageOptions.newBuilder().setProjectId("project-id")
 *    .setCredentials(targetCredentials).build().getService();
 *
 * for (Bucket b : storage_service.list().iterateAll())
 *     System.out.println(b);
 * </pre>
 */
public class ImpersonatedCredentials extends GoogleCredentials
    implements ServiceAccountSigner, IdTokenProvider, QuotaProjectIdProvider {

  private static final long serialVersionUID = -2133257318957488431L;
  private static final String RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
  private static final int TWELVE_HOURS_IN_SECONDS = 43200;
  private static final int DEFAULT_LIFETIME_IN_SECONDS = 3600;
  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final String IAM_ACCESS_TOKEN_ENDPOINT =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken";

  private GoogleCredentials sourceCredentials;
  private String targetPrincipal;
  private List<String> delegates;
  private List<String> scopes;
  private int lifetime;
  private String quotaProjectId;
  private String iamEndpointOverride;
  private final String transportFactoryClassName;

  private transient HttpTransportFactory transportFactory;

  /**
   * @param sourceCredentials the source credential used to acquire the impersonated credentials. It
   *     should be either a user account credential or a service account credential.
   * @param targetPrincipal the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If unset, sourceCredential must have that role on
   *     targetPrincipal.
   * @param scopes scopes to request during the authorization grant
   * @param lifetime number of seconds the delegated credential should be valid. By default this
   *     value should be at most 3600. However, you can follow <a
   *     href='https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oauth'>these
   *     instructions</a> to set up the service account and extend the maximum lifetime to 43200 (12
   *     hours). If the given lifetime is 0, default value 3600 will be used instead when creating
   *     the credentials.
   * @param transportFactory HTTP transport factory that creates the transport used to get access
   *     tokens
   * @return new credentials
   */
  public static ImpersonatedCredentials create(
      GoogleCredentials sourceCredentials,
      String targetPrincipal,
      List<String> delegates,
      List<String> scopes,
      int lifetime,
      HttpTransportFactory transportFactory) {
    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal)
        .setDelegates(delegates)
        .setScopes(scopes)
        .setLifetime(lifetime)
        .setHttpTransportFactory(transportFactory)
        .build();
  }

  /**
   * @param sourceCredentials the source credential used to acquire the impersonated credentials. It
   *     should be either a user account credential or a service account credential.
   * @param targetPrincipal the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If unset, sourceCredential must have that role on
   *     targetPrincipal.
   * @param scopes scopes to request during the authorization grant
   * @param lifetime number of seconds the delegated credential should be valid. By default this
   *     value should be at most 3600. However, you can follow <a
   *     href='https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oauth'>these
   *     instructions</a> to set up the service account and extend the maximum lifetime to 43200 (12
   *     hours). If the given lifetime is 0, default value 3600 will be used instead when creating
   *     the credentials.
   * @param transportFactory HTTP transport factory that creates the transport used to get access
   *     tokens.
   * @param quotaProjectId the project used for quota and billing purposes. Should be null unless
   *     the caller wants to use a project different from the one that owns the impersonated
   *     credential for billing/quota purposes.
   * @return new credentials
   */
  public static ImpersonatedCredentials create(
      GoogleCredentials sourceCredentials,
      String targetPrincipal,
      List<String> delegates,
      List<String> scopes,
      int lifetime,
      HttpTransportFactory transportFactory,
      String quotaProjectId) {
    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal)
        .setDelegates(delegates)
        .setScopes(scopes)
        .setLifetime(lifetime)
        .setHttpTransportFactory(transportFactory)
        .setQuotaProjectId(quotaProjectId)
        .build();
  }

  /**
   * @param sourceCredentials the source credential used to acquire the impersonated credentials. It
   *     should be either a user account credential or a service account credential.
   * @param targetPrincipal the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If unset, sourceCredential must have that role on
   *     targetPrincipal.
   * @param scopes scopes to request during the authorization grant
   * @param lifetime number of seconds the delegated credential should be valid. By default this
   *     value should be at most 3600. However, you can follow <a
   *     href='https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oauth'>these
   *     instructions</a> to set up the service account and extend the maximum lifetime to 43200 (12
   *     hours). If the given lifetime is 0, default value 3600 will be used instead when creating
   *     the credentials.
   * @param transportFactory HTTP transport factory that creates the transport used to get access
   *     tokens.
   * @param quotaProjectId the project used for quota and billing purposes. Should be null unless
   *     the caller wants to use a project different from the one that owns the impersonated
   *     credential for billing/quota purposes.
   * @param iamEndpointOverride The full IAM endpoint override with the target_principal embedded.
   *     This is useful when supporting impersonation with regional endpoints.
   * @return new credentials
   */
  public static ImpersonatedCredentials create(
      GoogleCredentials sourceCredentials,
      String targetPrincipal,
      List<String> delegates,
      List<String> scopes,
      int lifetime,
      HttpTransportFactory transportFactory,
      String quotaProjectId,
      String iamEndpointOverride) {
    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal)
        .setDelegates(delegates)
        .setScopes(scopes)
        .setLifetime(lifetime)
        .setHttpTransportFactory(transportFactory)
        .setQuotaProjectId(quotaProjectId)
        .setIamEndpointOverride(iamEndpointOverride)
        .build();
  }

  /**
   * @param sourceCredentials the source credential used to acquire the impersonated credentials. It
   *     should be either a user account credential or a service account credential.
   * @param targetPrincipal the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If left unset, sourceCredential must have that role on
   *     targetPrincipal.
   * @param scopes scopes to request during the authorization grant
   * @param lifetime number of seconds the delegated credential should be valid. By default this
   *     value should be at most 3600. However, you can follow <a
   *     href='https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oauth'>these
   *     instructions</a> to set up the service account and extend the maximum lifetime to 43200 (12
   *     hours).
   *     https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oauth
   *     If the given lifetime is 0, default value 3600 will be used instead when creating the
   *     credentials.
   * @return new credentials
   */
  public static ImpersonatedCredentials create(
      GoogleCredentials sourceCredentials,
      String targetPrincipal,
      List<String> delegates,
      List<String> scopes,
      int lifetime) {
    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal)
        .setDelegates(delegates)
        .setScopes(scopes)
        .setLifetime(lifetime)
        .build();
  }

  static String extractTargetPrincipal(String serviceAccountImpersonationUrl) {
    // Extract the target principal.
    int startIndex = serviceAccountImpersonationUrl.lastIndexOf('/');
    int endIndex = serviceAccountImpersonationUrl.indexOf(":generateAccessToken");

    if (startIndex != -1 && endIndex != -1 && startIndex < endIndex) {
      return serviceAccountImpersonationUrl.substring(startIndex + 1, endIndex);
    } else {
      throw new IllegalArgumentException(
          "Unable to determine target principal from service account impersonation URL.");
    }
  }

  /**
   * Returns the email field of the serviceAccount that is being impersonated.
   *
   * @return email address of the impersonated service account
   */
  @Override
  public String getAccount() {
    return this.targetPrincipal;
  }

  @Override
  public String getQuotaProjectId() {
    return this.quotaProjectId;
  }

  @VisibleForTesting
  String getIamEndpointOverride() {
    return this.iamEndpointOverride;
  }

  @VisibleForTesting
  List<String> getDelegates() {
    return delegates;
  }

  @VisibleForTesting
  List<String> getScopes() {
    return scopes;
  }

  public GoogleCredentials getSourceCredentials() {
    return sourceCredentials;
  }

  int getLifetime() {
    return this.lifetime;
  }

  public void setTransportFactory(HttpTransportFactory httpTransportFactory) {
    this.transportFactory = httpTransportFactory;
  }

  /**
   * Signs the provided bytes using the private key associated with the impersonated service account
   *
   * @param toSign bytes to sign
   * @return signed bytes
   * @throws SigningException if the attempt to sign the provided bytes failed
   * @see <a
   *     href="https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/signBlob">Blob
   *     Signing</a>
   */
  @Override
  public byte[] sign(byte[] toSign) {
    return IamUtils.sign(
        getAccount(),
        sourceCredentials,
        transportFactory.create(),
        toSign,
        ImmutableMap.of("delegates", this.delegates));
  }

  /**
   * Returns impersonation account credentials defined by JSON using the format generated by gCloud.
   * The source credentials in the JSON should be either user account credentials or service account
   * credentials.
   *
   * @param json a map from the JSON representing the credentials
   * @param transportFactory HTTP transport factory, creates the transport used to get access tokens
   * @return the credentials defined by the JSON
   * @throws IOException if the credential cannot be created from the JSON.
   */
  static ImpersonatedCredentials fromJson(
      Map<String, Object> json, HttpTransportFactory transportFactory) throws IOException {

    checkNotNull(json);
    checkNotNull(transportFactory);

    List<String> delegates = null;
    Map<String, Object> sourceCredentialsJson;
    String sourceCredentialsType;
    String quotaProjectId;
    String targetPrincipal;
    String serviceAccountImpersonationUrl;
    try {
      serviceAccountImpersonationUrl = (String) json.get("service_account_impersonation_url");
      if (json.containsKey("delegates")) {
        delegates = (List<String>) json.get("delegates");
      }
      sourceCredentialsJson = (Map<String, Object>) json.get("source_credentials");
      sourceCredentialsType = (String) sourceCredentialsJson.get("type");
      quotaProjectId = (String) json.get("quota_project_id");
      targetPrincipal = extractTargetPrincipal(serviceAccountImpersonationUrl);
    } catch (ClassCastException | NullPointerException | IllegalArgumentException e) {
      throw new CredentialFormatException("An invalid input stream was provided.", e);
    }

    GoogleCredentials sourceCredentials;
    if (GoogleCredentials.USER_FILE_TYPE.equals(sourceCredentialsType)) {
      sourceCredentials = UserCredentials.fromJson(sourceCredentialsJson, transportFactory);
    } else if (GoogleCredentials.SERVICE_ACCOUNT_FILE_TYPE.equals(sourceCredentialsType)) {
      sourceCredentials =
          ServiceAccountCredentials.fromJson(sourceCredentialsJson, transportFactory);
    } else {
      throw new IOException(
          String.format(
              "A credential of type %s is not supported as source credential for impersonation.",
              sourceCredentialsType));
    }
    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal)
        .setDelegates(delegates)
        .setScopes(new ArrayList<String>())
        .setLifetime(DEFAULT_LIFETIME_IN_SECONDS)
        .setHttpTransportFactory(transportFactory)
        .setQuotaProjectId(quotaProjectId)
        .setIamEndpointOverride(serviceAccountImpersonationUrl)
        .build();
  }

  @Override
  public boolean createScopedRequired() {
    return this.scopes == null || this.scopes.isEmpty();
  }

  @Override
  public GoogleCredentials createScoped(Collection<String> scopes) {
    return toBuilder()
        .setScopes(new ArrayList(scopes))
        .setLifetime(this.lifetime)
        .setDelegates(this.delegates)
        .setHttpTransportFactory(this.transportFactory)
        .setQuotaProjectId(this.quotaProjectId)
        .setIamEndpointOverride(this.iamEndpointOverride)
        .build();
  }

  @Override
  protected Map<String, List<String>> getAdditionalHeaders() {
    Map<String, List<String>> headers = super.getAdditionalHeaders();
    if (quotaProjectId != null) {
      return addQuotaProjectIdToRequestMetadata(quotaProjectId, headers);
    }
    return headers;
  }

  private ImpersonatedCredentials(Builder builder) {
    this.sourceCredentials = builder.getSourceCredentials();
    this.targetPrincipal = builder.getTargetPrincipal();
    this.delegates = builder.getDelegates();
    this.scopes = builder.getScopes();
    this.lifetime = builder.getLifetime();
    this.transportFactory =
        firstNonNull(
            builder.getHttpTransportFactory(),
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.quotaProjectId = builder.quotaProjectId;
    this.iamEndpointOverride = builder.iamEndpointOverride;
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
    if (this.delegates == null) {
      this.delegates = new ArrayList<String>();
    }
    if (this.scopes == null) {
      throw new IllegalStateException("Scopes cannot be null");
    }
    if (this.lifetime > TWELVE_HOURS_IN_SECONDS) {
      throw new IllegalStateException("lifetime must be less than or equal to 43200");
    }
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (this.sourceCredentials.getAccessToken() == null) {
      this.sourceCredentials =
          this.sourceCredentials.createScoped(Arrays.asList(CLOUD_PLATFORM_SCOPE));
    }

    try {
      this.sourceCredentials.refreshIfExpired();
    } catch (IOException e) {
      throw new IOException("Unable to refresh sourceCredentials", e);
    }

    HttpTransport httpTransport = this.transportFactory.create();
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);

    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(sourceCredentials);
    HttpRequestFactory requestFactory = httpTransport.createRequestFactory();

    String endpointUrl =
        this.iamEndpointOverride != null
            ? this.iamEndpointOverride
            : String.format(IAM_ACCESS_TOKEN_ENDPOINT, this.targetPrincipal);
    GenericUrl url = new GenericUrl(endpointUrl);

    Map<String, Object> body =
        ImmutableMap.<String, Object>of(
            "delegates", this.delegates, "scope", this.scopes, "lifetime", this.lifetime + "s");

    HttpContent requestContent = new JsonHttpContent(parser.getJsonFactory(), body);
    HttpRequest request = requestFactory.buildPostRequest(url, requestContent);
    adapter.initialize(request);
    request.setParser(parser);

    HttpResponse response = null;
    try {
      response = request.execute();
    } catch (IOException e) {
      throw new IOException("Error requesting access token", e);
    }

    GenericData responseData = response.parseAs(GenericData.class);
    response.disconnect();

    String accessToken =
        OAuth2Utils.validateString(responseData, "accessToken", "Expected to find an accessToken");
    String expireTime =
        OAuth2Utils.validateString(responseData, "expireTime", "Expected to find an expireTime");

    DateFormat format = new SimpleDateFormat(RFC3339);
    try {
      Date date = format.parse(expireTime);
      return new AccessToken(accessToken, date);
    } catch (ParseException pe) {
      throw new IOException("Error parsing expireTime: " + pe.getMessage());
    }
  }

  /**
   * Returns an IdToken for the current Credential.
   *
   * @param targetAudience the audience field for the issued ID token
   * @param options credential specific options for for the token. For example, an ID token for an
   *     ImpersonatedCredentials can return the email address within the token claims if
   *     "ImpersonatedCredentials.INCLUDE_EMAIL" is provided as a list option.<br>
   *     Only one option value is supported: "ImpersonatedCredentials.INCLUDE_EMAIL" If no options
   *     are set, the default excludes the "includeEmail" attribute in the API request.
   * @return IdToken object which includes the raw id_token, expiration, and audience
   * @throws IOException if the attempt to get an ID token failed
   */
  @Override
  public IdToken idTokenWithAudience(String targetAudience, List<IdTokenProvider.Option> options)
      throws IOException {
    boolean includeEmail =
        options != null && options.contains(IdTokenProvider.Option.INCLUDE_EMAIL);
    return IamUtils.getIdToken(
        getAccount(),
        sourceCredentials,
        transportFactory.create(),
        targetAudience,
        includeEmail,
        ImmutableMap.of("delegates", this.delegates));
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        sourceCredentials,
        targetPrincipal,
        delegates,
        scopes,
        lifetime,
        quotaProjectId,
        iamEndpointOverride);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("sourceCredentials", sourceCredentials)
        .add("targetPrincipal", targetPrincipal)
        .add("delegates", delegates)
        .add("scopes", scopes)
        .add("lifetime", lifetime)
        .add("transportFactoryClassName", transportFactoryClassName)
        .add("quotaProjectId", quotaProjectId)
        .add("iamEndpointOverride", iamEndpointOverride)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ImpersonatedCredentials)) {
      return false;
    }
    ImpersonatedCredentials other = (ImpersonatedCredentials) obj;
    return Objects.equals(this.sourceCredentials, other.sourceCredentials)
        && Objects.equals(this.targetPrincipal, other.targetPrincipal)
        && Objects.equals(this.delegates, other.delegates)
        && Objects.equals(this.scopes, other.scopes)
        && Objects.equals(this.lifetime, other.lifetime)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName)
        && Objects.equals(this.quotaProjectId, other.quotaProjectId)
        && Objects.equals(this.iamEndpointOverride, other.iamEndpointOverride);
  }

  public Builder toBuilder() {
    return new Builder(this.sourceCredentials, this.targetPrincipal);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends GoogleCredentials.Builder {

    private GoogleCredentials sourceCredentials;
    private String targetPrincipal;
    private List<String> delegates;
    private List<String> scopes;
    private int lifetime = DEFAULT_LIFETIME_IN_SECONDS;
    private HttpTransportFactory transportFactory;
    private String quotaProjectId;
    private String iamEndpointOverride;

    protected Builder() {}

    protected Builder(GoogleCredentials sourceCredentials, String targetPrincipal) {
      this.sourceCredentials = sourceCredentials;
      this.targetPrincipal = targetPrincipal;
    }

    public Builder setSourceCredentials(GoogleCredentials sourceCredentials) {
      this.sourceCredentials = sourceCredentials;
      return this;
    }

    public GoogleCredentials getSourceCredentials() {
      return this.sourceCredentials;
    }

    public Builder setTargetPrincipal(String targetPrincipal) {
      this.targetPrincipal = targetPrincipal;
      return this;
    }

    public String getTargetPrincipal() {
      return this.targetPrincipal;
    }

    public Builder setDelegates(List<String> delegates) {
      this.delegates = delegates;
      return this;
    }

    public List<String> getDelegates() {
      return this.delegates;
    }

    public Builder setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public List<String> getScopes() {
      return this.scopes;
    }

    public Builder setLifetime(int lifetime) {
      this.lifetime = lifetime == 0 ? DEFAULT_LIFETIME_IN_SECONDS : lifetime;
      return this;
    }

    public int getLifetime() {
      return this.lifetime;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public Builder setQuotaProjectId(String quotaProjectId) {
      this.quotaProjectId = quotaProjectId;
      return this;
    }

    public Builder setIamEndpointOverride(String iamEndpointOverride) {
      this.iamEndpointOverride = iamEndpointOverride;
      return this;
    }

    public ImpersonatedCredentials build() {
      return new ImpersonatedCredentials(this);
    }
  }
}
