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
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.ServiceAccountSigner;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.Beta;
import com.google.common.base.MoreObjects;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * OAuth2 credentials representing the built-in service account for a Google Compute Engine VM.
 *
 * <p>Fetches access tokens from the Google Compute Engine metadata server.
 *
 * <p>These credentials use the IAM API to sign data. See {@link #sign(byte[])} for more details.
 */
public class ComputeEngineCredentials extends GoogleCredentials
    implements ServiceAccountSigner, IdTokenProvider {

  private static final Logger LOGGER = Logger.getLogger(ComputeEngineCredentials.class.getName());

  // Note: the explicit IP address is used to avoid name server resolution issues.
  static final String DEFAULT_METADATA_SERVER_URL = "http://metadata.google.internal";

  static final String SIGN_BLOB_URL_FORMAT =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:signBlob";

  // Note: the explicit `timeout` and `tries` below is a workaround. The underlying
  // issue is that resolving an unknown host on some networks will take
  // 20-30 seconds; making this timeout short fixes the issue, but
  // could lead to false negatives in the event that we are on GCE, but
  // the metadata resolution was particularly slow. The latter case is
  // "unlikely" since the expected 4-nines time is about 0.5 seconds.
  // This allows us to limit the total ping maximum timeout to 1.5 seconds
  // for developer desktop scenarios.
  static final int MAX_COMPUTE_PING_TRIES = 3;
  static final int COMPUTE_PING_CONNECTION_TIMEOUT_MS = 500;

  private static final String METADATA_FLAVOR = "Metadata-Flavor";
  private static final String GOOGLE = "Google";

  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final String PARSE_ERROR_ACCOUNT = "Error parsing service account response. ";
  private static final long serialVersionUID = -4113476462526554235L;

  private final String transportFactoryClassName;

  private transient HttpTransportFactory transportFactory;
  private transient String serviceAccountEmail;

  /**
   * Constructor with overridden transport.
   *
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   */
  private ComputeEngineCredentials(HttpTransportFactory transportFactory) {
    this.transportFactory =
        firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
  }

  /**
   * Create a new ComputeEngineCredentials instance with default behavior.
   *
   * @return new ComputeEngineCredentials
   */
  public static ComputeEngineCredentials create() {
    return new ComputeEngineCredentials(null);
  }

  /** Refresh the access token by getting it from the GCE metadata server */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    HttpResponse response = getMetadataResponse(getTokenServerEncodedUrl());
    int statusCode = response.getStatusCode();
    if (statusCode == HttpStatusCodes.STATUS_CODE_NOT_FOUND) {
      throw new IOException(
          String.format(
              "Error code %s trying to get security access token from"
                  + " Compute Engine metadata for the default service account. This may be because"
                  + " the virtual machine instance does not have permission scopes specified."
                  + " It is possible to skip checking for Compute Engine metadata by specifying the environment "
                  + " variable "
                  + DefaultCredentialsProvider.NO_GCE_CHECK_ENV_VAR
                  + "=true.",
              statusCode));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(
          String.format(
              "Unexpected Error code %s trying to get security access"
                  + " token from Compute Engine metadata for the default service account: %s",
              statusCode, response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from metadata token server request.");
    }
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken =
        OAuth2Utils.validateString(responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds =
        OAuth2Utils.validateInt32(responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000;
    return new AccessToken(accessToken, new Date(expiresAtMilliseconds));
  }

  /**
   * Returns a Google ID Token from the metadata server on ComputeEngine
   *
   * @param targetAudience the aud: field the IdToken should include
   * @param options list of Credential specific options for the token. For example, an IDToken for a
   *     ComputeEngineCredential could have the full formatted claims returned if
   *     IdTokenProvider.Option.FORMAT_FULL) is provided as a list option. Valid option values are:
   *     <br>
   *     IdTokenProvider.Option.FORMAT_FULL<br>
   *     IdTokenProvider.Option.LICENSES_TRUE<br>
   *     If no options are set, the defaults are "&amp;format=standard&amp;licenses=false"
   * @throws IOException if the attempt to get an IdToken failed
   * @return IdToken object which includes the raw id_token, JsonWebSignature
   */
  @Beta
  @Override
  public IdToken idTokenWithAudience(String targetAudience, List<IdTokenProvider.Option> options)
      throws IOException {
    GenericUrl documentUrl = new GenericUrl(getIdentityDocumentUrl());
    if (options != null) {
      if (options.contains(IdTokenProvider.Option.FORMAT_FULL)) {
        documentUrl.set("format", "full");
      }
      if (options.contains(IdTokenProvider.Option.LICENSES_TRUE)) {
        // license will only get returned if format is also full
        documentUrl.set("format", "full");
        documentUrl.set("license", "TRUE");
      }
    }
    documentUrl.set("audience", targetAudience);
    HttpResponse response = getMetadataResponse(documentUrl.toString());
    InputStream content = response.getContent();
    if (content == null) {
      throw new IOException("Empty content from metadata token server request.");
    }
    String rawToken = response.parseAsString();
    return IdToken.create(rawToken);
  }

  private HttpResponse getMetadataResponse(String url) throws IOException {
    GenericUrl genericUrl = new GenericUrl(url);
    HttpRequest request =
        transportFactory.create().createRequestFactory().buildGetRequest(genericUrl);
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.getHeaders().set(METADATA_FLAVOR, GOOGLE);
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response;
    try {
      response = request.execute();
    } catch (UnknownHostException exception) {
      throw new IOException(
          "ComputeEngineCredentials cannot find the metadata server. This is"
              + " likely because code is not running on Google Compute Engine.",
          exception);
    }
    return response;
  }

  /** Return whether code is running on Google Compute Engine. */
  static boolean runningOnComputeEngine(
      HttpTransportFactory transportFactory, DefaultCredentialsProvider provider) {
    // If the environment has requested that we do no GCE checks, return immediately.
    if (Boolean.parseBoolean(provider.getEnv(DefaultCredentialsProvider.NO_GCE_CHECK_ENV_VAR))) {
      return false;
    }

    GenericUrl tokenUrl = new GenericUrl(getMetadataServerUrl(provider));
    for (int i = 1; i <= MAX_COMPUTE_PING_TRIES; ++i) {
      try {
        HttpRequest request =
            transportFactory.create().createRequestFactory().buildGetRequest(tokenUrl);
        request.setConnectTimeout(COMPUTE_PING_CONNECTION_TIMEOUT_MS);
        request.getHeaders().set(METADATA_FLAVOR, GOOGLE);

        HttpResponse response = request.execute();
        try {
          // Internet providers can return a generic response to all requests, so it is necessary
          // to check that metadata header is present also.
          HttpHeaders headers = response.getHeaders();
          return OAuth2Utils.headersContainValue(headers, METADATA_FLAVOR, GOOGLE);
        } finally {
          response.disconnect();
        }
      } catch (SocketTimeoutException expected) {
        // Ignore logging timeouts which is the expected failure mode in non GCE environments.
      } catch (IOException e) {
        LOGGER.log(
            Level.FINE,
            "Encountered an unexpected exception when determining"
                + " if we are running on Google Compute Engine.",
            e);
      }
    }
    LOGGER.log(Level.INFO, "Failed to detect whether we are running on Google Compute Engine.");
    return false;
  }

  public static String getMetadataServerUrl(DefaultCredentialsProvider provider) {
    String metadataServerAddress =
        provider.getEnv(DefaultCredentialsProvider.GCE_METADATA_HOST_ENV_VAR);
    if (metadataServerAddress != null) {
      return "http://" + metadataServerAddress;
    }
    return DEFAULT_METADATA_SERVER_URL;
  }

  public static String getMetadataServerUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT);
  }

  public static String getTokenServerEncodedUrl(DefaultCredentialsProvider provider) {
    return getMetadataServerUrl(provider)
        + "/computeMetadata/v1/instance/service-accounts/default/token";
  }

  public static String getTokenServerEncodedUrl() {
    return getTokenServerEncodedUrl(DefaultCredentialsProvider.DEFAULT);
  }

  public static String getServiceAccountsUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT)
        + "/computeMetadata/v1/instance/service-accounts/?recursive=true";
  }

  public static String getIdentityDocumentUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT)
        + "/computeMetadata/v1/instance/service-accounts/default/identity";
  }

  @Override
  public int hashCode() {
    return Objects.hash(transportFactoryClassName);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("transportFactoryClassName", transportFactoryClassName)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ComputeEngineCredentials)) {
      return false;
    }
    ComputeEngineCredentials other = (ComputeEngineCredentials) obj;
    return Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    transportFactory = newInstance(transportFactoryClassName);
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  /**
   * Returns the email address associated with the GCE default service account.
   *
   * @throws RuntimeException if the default service account cannot be read
   */
  @Override
  // todo(#314) getAccount should not throw a RuntimeException
  public String getAccount() {
    if (serviceAccountEmail == null) {
      try {
        serviceAccountEmail = getDefaultServiceAccount();
      } catch (IOException ex) {
        throw new RuntimeException("Failed to get service account", ex);
      }
    }
    return serviceAccountEmail;
  }

  /**
   * Signs the provided bytes using the private key associated with the service account.
   *
   * <p>The Compute Engine's project must enable the Identity and Access Management (IAM) API and
   * the instance's service account must have the iam.serviceAccounts.signBlob permission.
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
    try {
      String account = getAccount();
      return IamUtils.sign(
          account, this, transportFactory.create(), toSign, Collections.<String, Object>emptyMap());
    } catch (SigningException ex) {
      throw ex;
    } catch (RuntimeException ex) {
      throw new SigningException("Signing failed", ex);
    }
  }

  private String getDefaultServiceAccount() throws IOException {
    HttpResponse response = getMetadataResponse(getServiceAccountsUrl());
    int statusCode = response.getStatusCode();
    if (statusCode == HttpStatusCodes.STATUS_CODE_NOT_FOUND) {
      throw new IOException(
          String.format(
              "Error code %s trying to get service accounts from"
                  + " Compute Engine metadata. This may be because the virtual machine instance"
                  + " does not have permission scopes specified.",
              statusCode));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(
          String.format(
              "Unexpected Error code %s trying to get service accounts"
                  + " from Compute Engine metadata: %s",
              statusCode, response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from metadata token server request.");
    }
    GenericData responseData = response.parseAs(GenericData.class);
    Map<String, Object> defaultAccount =
        OAuth2Utils.validateMap(responseData, "default", PARSE_ERROR_ACCOUNT);
    return OAuth2Utils.validateString(defaultAccount, "email", PARSE_ERROR_ACCOUNT);
  }

  public static class Builder extends GoogleCredentials.Builder {
    private HttpTransportFactory transportFactory;

    protected Builder() {}

    protected Builder(ComputeEngineCredentials credentials) {
      this.transportFactory = credentials.transportFactory;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public ComputeEngineCredentials build() {
      return new ComputeEngineCredentials(transportFactory);
    }
  }
}
