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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.Preconditions;
import com.google.auth.Credentials;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.base.MoreObjects.ToStringHelper;
import com.google.common.collect.ImmutableList;
import com.google.errorprone.annotations.CanIgnoreReturnValue;

/** Base type for credentials for authorizing calls to Google APIs using OAuth2. */
public class GoogleCredentials extends OAuth2Credentials implements QuotaProjectIdProvider {

  private static final long serialVersionUID = -1522852442442473691L;

  static final String QUOTA_PROJECT_ID_HEADER_KEY = "x-goog-user-project";
  static final String USER_FILE_TYPE = "authorized_user";
  static final String SERVICE_ACCOUNT_FILE_TYPE = "service_account";
  static final String GDCH_SERVICE_ACCOUNT_FILE_TYPE = "gdch_service_account";

  private final String universeDomain;
  private final boolean isExplicitUniverseDomain;

  protected final boolean trustBoundaryEnabled;
  private transient TrustBoundary trustBoundary;

  protected final String quotaProjectId;

  private static final DefaultCredentialsProvider defaultCredentialsProvider =
      new DefaultCredentialsProvider();

  /**
   * Returns the credentials instance from the given access token.
   *
   * @param accessToken the access token
   * @return the credentials instance
   */
  public static GoogleCredentials create(AccessToken accessToken) {
    return GoogleCredentials.newBuilder().setAccessToken(accessToken).build();
  }

  /**
   * Returns the credentials instance from the given access token and universe domain.
   *
   * @param universeDomain the universe domain
   * @param accessToken the access token
   * @return the credentials instance
   */
  public static GoogleCredentials create(String universeDomain, AccessToken accessToken) {
    return GoogleCredentials.newBuilder()
        .setAccessToken(accessToken)
        .setUniverseDomain(universeDomain)
        .build();
  }

  /**
   * Returns the Application Default Credentials.
   *
   * <p>Returns the Application Default Credentials which are used to identify and authorize the
   * whole application. The following are searched (in order) to find the Application Default
   * Credentials:
   *
   * <ol>
   *   <li>Credentials file pointed to by the {@code GOOGLE_APPLICATION_CREDENTIALS} environment
   *       variable
   *   <li>Credentials provided by the Google Cloud SDK.
   *       <ol>
   *         <li>{@code gcloud auth application-default login} for user account credentials.
   *         <li>{@code gcloud auth application-default login --impersonate-service-account} for
   *             impersonated service account credentials.
   *       </ol>
   *   <li>Google App Engine built-in credentials
   *   <li>Google Cloud Shell built-in credentials
   *   <li>Google Compute Engine built-in credentials
   * </ol>
   *
   * @return the credentials instance.
   * @throws IOException if the credentials cannot be created in the current environment.
   */
  public static GoogleCredentials getApplicationDefault() throws IOException {
    return getApplicationDefault(OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  /**
   * Returns the Application Default Credentials.
   *
   * <p>Returns the Application Default Credentials which are used to identify and authorize the
   * whole application. The following are searched (in order) to find the Application Default
   * Credentials:
   *
   * <ol>
   *   <li>Credentials file pointed to by the {@code GOOGLE_APPLICATION_CREDENTIALS} environment
   *       variable
   *   <li>Credentials provided by the Google Cloud SDK {@code gcloud auth application-default
   *       login} command
   *   <li>Google App Engine built-in credentials
   *   <li>Google Cloud Shell built-in credentials
   *   <li>Google Compute Engine built-in credentials
   * </ol>
   *
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credentials instance.
   * @throws IOException if the credentials cannot be created in the current environment.
   */
  public static GoogleCredentials getApplicationDefault(HttpTransportFactory transportFactory)
      throws IOException {
    Preconditions.checkNotNull(transportFactory);
    return defaultCredentialsProvider.getDefaultCredentials(transportFactory);
  }

  /**
   * Returns credentials defined by a JSON file stream.
   *
   * <p>The stream can contain a Service Account key file in JSON format from the Google Developers
   * Console or a stored user credential using the format supported by the Cloud SDK.
   *
   * <p>Important: If you accept a credential configuration (credential JSON/File/Stream) from an
   * external source for authentication to Google Cloud Platform, you must validate it before
   * providing it to any Google API or library. Providing an unvalidated credential configuration to
   * Google APIs can compromise the security of your systems and data. For more information, refer
   * to {@link <a
   * href="https://cloud.google.com/docs/authentication/external/externally-sourced-credentials">documentation</a>}.
   *
   * @param credentialsStream the stream with the credential definition.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static GoogleCredentials fromStream(InputStream credentialsStream) throws IOException {
    return fromStream(credentialsStream, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  /**
   * Returns credentials defined by a JSON file stream.
   *
   * <p>The stream can contain a Service Account key file in JSON format from the Google Developers
   * Console or a stored user credential using the format supported by the Cloud SDK.
   *
   * <p>Important: If you accept a credential configuration (credential JSON/File/Stream) from an
   * external source for authentication to Google Cloud Platform, you must validate it before
   * providing it to any Google API or library. Providing an unvalidated credential configuration to
   * Google APIs can compromise the security of your systems and data. For more information, refer
   * to {@link <a
   * href="https://cloud.google.com/docs/authentication/external/externally-sourced-credentials">documentation</a>}.
   *
   * @param credentialsStream the stream with the credential definition.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static GoogleCredentials fromStream(
      InputStream credentialsStream, HttpTransportFactory transportFactory) throws IOException {
    Preconditions.checkNotNull(credentialsStream);
    Preconditions.checkNotNull(transportFactory);

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    JsonObjectParser parser = new JsonObjectParser(jsonFactory);
    GenericJson fileContents =
        parser.parseAndClose(credentialsStream, StandardCharsets.UTF_8, GenericJson.class);

    String fileType = (String) fileContents.get("type");
    if (fileType == null) {
      throw new IOException("Error reading credentials from stream, 'type' field not specified.");
    }

    if (USER_FILE_TYPE.equals(fileType)) {
      return UserCredentials.fromJson(fileContents, transportFactory);
    }
    if (SERVICE_ACCOUNT_FILE_TYPE.equals(fileType)) {
      return ServiceAccountCredentials.fromJson(fileContents, transportFactory);
    }
    if (GDCH_SERVICE_ACCOUNT_FILE_TYPE.equals(fileType)) {
      return GdchCredentials.fromJson(fileContents);
    }
    if (ExternalAccountCredentials.EXTERNAL_ACCOUNT_FILE_TYPE.equals(fileType)) {
      return ExternalAccountCredentials.fromJson(fileContents, transportFactory);
    }
    if (ExternalAccountAuthorizedUserCredentials.EXTERNAL_ACCOUNT_AUTHORIZED_USER_FILE_TYPE.equals(
        fileType)) {
      return ExternalAccountAuthorizedUserCredentials.fromJson(fileContents, transportFactory);
    }
    if (ImpersonatedCredentials.IMPERSONATED_CREDENTIALS_FILE_TYPE.equals(fileType)) {
      return ImpersonatedCredentials.fromJson(fileContents, transportFactory);
    }
    throw new IOException(
        String.format(
            "Error reading credentials from stream, 'type' value '%s' not recognized."
                + " Valid values are '%s', '%s', '%s', '%s', '%s', '%s'.",
            fileType,
            USER_FILE_TYPE,
            SERVICE_ACCOUNT_FILE_TYPE,
            GDCH_SERVICE_ACCOUNT_FILE_TYPE,
            ExternalAccountCredentials.EXTERNAL_ACCOUNT_FILE_TYPE,
            ExternalAccountAuthorizedUserCredentials.EXTERNAL_ACCOUNT_AUTHORIZED_USER_FILE_TYPE,
            ImpersonatedCredentials.IMPERSONATED_CREDENTIALS_FILE_TYPE));
  }

  /**
   * Creates a credential with the provided quota project.
   *
   * @param quotaProject the quota project to set on the credential
   * @return credential with the provided quota project
   */
  public GoogleCredentials createWithQuotaProject(String quotaProject) {
    return this.toBuilder().setQuotaProjectId(quotaProject).build();
  }

  /**
   * Gets the universe domain for the credential.
   *
   * @return An explicit universe domain if it was explicitly provided, invokes the super
   *     implementation otherwise
   */
  @Override
  public String getUniverseDomain() throws IOException {
    return this.universeDomain;
  }

  /**
   * Gets the flag indicating whether universeDomain was explicitly set by the developer.
   *
   * <p>If subclass has a requirement to give priority to developer-set universeDomain, this
   * property must be used to check if the universeDomain value was provided by the user. It could
   * be a default otherwise.
   *
   * @return true if universeDomain value was provided by the developer, false otherwise
   */
  @VisibleForTesting
  protected boolean isExplicitUniverseDomain() {
    return this.isExplicitUniverseDomain;
  }

  /**
   * Checks if universe domain equals to {@link Credentials#GOOGLE_DEFAULT_UNIVERSE}.
   *
   * @return true if universe domain equals to {@link Credentials#GOOGLE_DEFAULT_UNIVERSE}, false
   *     otherwise
   */
  boolean isDefaultUniverseDomain() throws IOException {
    return getUniverseDomain().equals(Credentials.GOOGLE_DEFAULT_UNIVERSE);
  }

  /**
   * Adds quota project ID to requestMetadata if present.
   *
   * @return a new map with quotaProjectId added if needed
   */
  static Map<String, List<String>> addQuotaProjectIdToRequestMetadata(
      String quotaProjectId, Map<String, List<String>> requestMetadata) {
    Preconditions.checkNotNull(requestMetadata);
    Map<String, List<String>> newRequestMetadata = new HashMap<>(requestMetadata);
    if (quotaProjectId != null && !requestMetadata.containsKey(QUOTA_PROJECT_ID_HEADER_KEY)) {
      newRequestMetadata.put(
          QUOTA_PROJECT_ID_HEADER_KEY, Collections.singletonList(quotaProjectId));
    }
    return Collections.unmodifiableMap(newRequestMetadata);
  }

  /**
   * Provide additional headers to return as request metadata.
   *
   * @return additional headers
   * @deprecated This method is no longer used for refreshing headers. Override {@link
   *     #refreshAndGetAdditionalHeaders()} instead. This method will be removed in a future major
   *     version.
   */
  @Deprecated
  protected Map<String, List<String>> getAdditionalHeaders() {
    String quotaProjectId = this.getQuotaProjectId();
    if (quotaProjectId != null) {
      return addQuotaProjectIdToRequestMetadata(quotaProjectId, Collections.emptyMap());
    }
    return Collections.emptyMap();
  }

  @Override
  protected Map<String, List<String>> refreshAndGetAdditionalHeaders(AccessToken newAccessToken)
      throws IOException {
    // Call the deprecated method to maintain backward compatibility for subclasses that override it.
    Map<String, List<String>> headers = new HashMap<>(getAdditionalHeaders());

    if (!this.trustBoundaryEnabled || !isDefaultUniverseDomain()) {
      return Collections.unmodifiableMap(headers);
    }

    if (this instanceof TrustBoundaryProvider) {
      TrustBoundaryProvider provider = (TrustBoundaryProvider) this;
      synchronized (lock) {
        // No-op check. If cached value is a no-op, we don't need to call the endpoint.
        if (this.trustBoundary != null && this.trustBoundary.isNoOp()) {
          // Fall through to add header.
        } else {
          try {
            this.trustBoundary =
                TrustBoundary.refresh(
                    provider.getTransportFactory(),
                    provider.getTrustBoundaryUrl(),
                    newAccessToken,
                    this.trustBoundary);
          } catch (IOException e) {
            // If refresh fails, check for cached value.
            if (this.trustBoundary == null) {
              // No cached value, so fail hard.
              throw new IOException(
                  "Failed to refresh trust boundary and no cached value is available.", e);
            }
            // Log the error and continue with the stale cached value.
          }
        }
      }
    }

    if (trustBoundary != null) {
      String headerValue = trustBoundary.isNoOp() ? "" : trustBoundary.getEncodedLocations();
      headers.put(
          TrustBoundary.TRUST_BOUNDARY_KEY, Collections.singletonList(headerValue));
    }
    return Collections.unmodifiableMap(headers);
  }

  /** Default constructor. */
  protected GoogleCredentials() {
    this(new Builder());
  }

  /**
   * Constructor with an explicit access token and quotaProjectId.
   *
   * <p>Deprecated, please use the {@link GoogleCredentials#GoogleCredentials(Builder)} constructor
   * whenever possible.
   *
   * @param accessToken initial or temporary access token
   * @param quotaProjectId a quotaProjectId, a project id to be used for billing purposes
   */
  @Deprecated
  protected GoogleCredentials(AccessToken accessToken, String quotaProjectId) {
    this(
        GoogleCredentials.newBuilder()
            .setAccessToken(accessToken)
            .setQuotaProjectId(quotaProjectId));
  }

  /**
   * Constructor with explicit access token.
   *
   * @param accessToken initial or temporary access token
   */
  @Deprecated
  public GoogleCredentials(AccessToken accessToken) {
    this(accessToken, null);
  }

  /**
   * Constructor that relies on a {@link Builder} to provide all the necessary field values for
   * initialization.
   *
   * @param builder an instance of a builder
   */
  protected GoogleCredentials(Builder builder) {
    super(builder.getAccessToken(), builder.getRefreshMargin(), builder.getExpirationMargin());
    this.quotaProjectId = builder.getQuotaProjectId();
    this.trustBoundaryEnabled = builder.trustBoundaryEnabled;

    if (builder.universeDomain == null || builder.universeDomain.trim().isEmpty()) {
      this.universeDomain = Credentials.GOOGLE_DEFAULT_UNIVERSE;
      this.isExplicitUniverseDomain = false;
    } else {
      this.universeDomain = builder.getUniverseDomain();
      this.isExplicitUniverseDomain = true;
    }
  }

  /**
   * Constructor with explicit access token and refresh margins.
   *
   * <p>Deprecated, please use the {@link GoogleCredentials#GoogleCredentials(Builder)} constructor
   * whenever possible.
   *
   * @param accessToken initial or temporary access token
   */
  @Deprecated
  protected GoogleCredentials(
      AccessToken accessToken, Duration refreshMargin, Duration expirationMargin) {
    this(
        (Builder)
            GoogleCredentials.newBuilder()
                .setAccessToken(accessToken)
                .setRefreshMargin(refreshMargin)
                .setExpirationMargin(expirationMargin));
  }

  /**
   * A helper for overriding the toString() method. This allows inheritance of super class fields.
   * Extending classes can override this implementation and call super implementation and add more
   * fields. Same cannot be done with overriding the toString() directly.
   *
   * @return an instance of the ToStringHelper that has public fields added
   */
  protected ToStringHelper toStringHelper() {
    return MoreObjects.toStringHelper(this)
        .omitNullValues()
        .add("quotaProjectId", this.quotaProjectId)
        .add("universeDomain", this.universeDomain)
        .add("trustBoundaryEnabled", this.trustBoundaryEnabled)
        .add("isExplicitUniverseDomain", this.isExplicitUniverseDomain);
  }

  @Override
  public String toString() {
    return toStringHelper().toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof GoogleCredentials)) {
      return false;
    }
    GoogleCredentials other = (GoogleCredentials) obj;
    return Objects.equals(this.quotaProjectId, other.quotaProjectId)
        && Objects.equals(this.universeDomain, other.universeDomain)
        && Objects.equals(this.trustBoundaryEnabled, other.trustBoundaryEnabled)
        && Objects.equals(this.isExplicitUniverseDomain, other.isExplicitUniverseDomain);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        this.quotaProjectId,
        this.universeDomain,
        this.trustBoundaryEnabled,
        this.isExplicitUniverseDomain);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  @Override
  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public String getQuotaProjectId() {
    return this.quotaProjectId;
  }

  /**
   * Indicates whether the credentials require scopes to be specified via a call to {@link
   * GoogleCredentials#createScoped} before use.
   *
   * @return Whether the credentials require scopes to be specified.
   */
  public boolean createScopedRequired() {
    return false;
  }

  /**
   * If the credentials support scopes, creates a copy of the identity with the specified scopes,
   * invalidates the existing scoped access token; otherwise, return the same instance.
   *
   * @param scopes Collection of scopes to request.
   * @return GoogleCredentials with requested scopes.
   */
  public GoogleCredentials createScoped(Collection<String> scopes) {
    return this;
  }

  /**
   * If the credentials support scopes, creates a copy of the identity with the specified scopes and
   * default scopes; otherwise, returns the same instance. This is mainly used by client libraries.
   *
   * @param scopes Collection of scopes to request.
   * @param defaultScopes Collection of default scopes to request.
   * @return GoogleCredentials with requested scopes.
   */
  public GoogleCredentials createScoped(
      Collection<String> scopes, Collection<String> defaultScopes) {
    return this;
  }

  /**
   * If the credentials support scopes, creates a copy of the identity with the specified scopes;
   * otherwise, returns the same instance.
   *
   * @param scopes Collection of scopes to request.
   * @return GoogleCredentials with requested scopes.
   */
  public GoogleCredentials createScoped(String... scopes) {
    return createScoped(ImmutableList.copyOf(scopes));
  }

  /**
   * If the credentials support automatic retries, creates a copy of the identity with the provided
   * retry strategy
   *
   * @param defaultRetriesEnabled a flag enabling or disabling default retries
   * @return GoogleCredentials with the new default retries configuration.
   */
  public GoogleCredentials createWithCustomRetryStrategy(boolean defaultRetriesEnabled) {
    return this;
  }

  /**
   * If the credentials support domain-wide delegation, creates a copy of the identity so that it
   * impersonates the specified user; otherwise, returns the same instance.
   *
   * @param user User to impersonate.
   * @return GoogleCredentials with a delegated user.
   */
  public GoogleCredentials createDelegated(String user) {
    return this;
  }

  public static class Builder extends OAuth2Credentials.Builder {
    @Nullable protected String quotaProjectId;
    @Nullable protected String universeDomain;
    protected boolean trustBoundaryEnabled;

    protected Builder() {}

    protected Builder(GoogleCredentials credentials) {
      super(credentials);
      this.quotaProjectId = credentials.quotaProjectId;
      this.trustBoundaryEnabled = credentials.trustBoundaryEnabled;
      if (credentials.isExplicitUniverseDomain) {
        this.universeDomain = credentials.universeDomain;
      }
    }

    protected Builder(GoogleCredentials.Builder builder) {
      setAccessToken(builder.getAccessToken());
      this.quotaProjectId = builder.quotaProjectId;
      this.universeDomain = builder.universeDomain;
      this.trustBoundaryEnabled = builder.trustBoundaryEnabled;
    }

    @Override
    public GoogleCredentials build() {
      return new GoogleCredentials(this);
    }

    @CanIgnoreReturnValue
    public Builder setQuotaProjectId(String quotaProjectId) {
      this.quotaProjectId = quotaProjectId;
      return this;
    }

    public Builder setUniverseDomain(String universeDomain) {
      this.universeDomain = universeDomain;
      return this;
    }

    public String getQuotaProjectId() {
      return this.quotaProjectId;
    }

    public String getUniverseDomain() {
      return this.universeDomain;
    }

    @Override
    @CanIgnoreReturnValue
    public Builder setAccessToken(AccessToken token) {
      super.setAccessToken(token);
      return this;
    }
  }
}
