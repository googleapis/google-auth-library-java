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
import com.google.api.client.http.HttpBackOffIOExceptionHandler;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler.BackOffRequired;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Joiner;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;
import com.google.api.client.util.Preconditions;
import com.google.api.client.util.SecurityUtils;
import com.google.auth.ServiceAccountSigner;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.Beta;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Reader;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * OAuth2 credentials representing a Service Account for calling Google APIs.
 *
 * <p>By default uses a JSON Web Token (JWT) to fetch access tokens.
 */
public class ServiceAccountCredentials extends GoogleCredentials
    implements ServiceAccountSigner, IdTokenProvider, JwtProvider {

  private static final long serialVersionUID = 7807543542681217978L;
  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";

  private final String clientId;
  private final String clientEmail;
  private final PrivateKey privateKey;
  private final String privateKeyId;
  private final String serviceAccountUser;
  private final String projectId;
  private final String transportFactoryClassName;
  private final URI tokenServerUri;
  private final Collection<String> scopes;

  private transient HttpTransportFactory transportFactory;

  /**
   * Constructor with minimum identifying information and custom HTTP transport.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKey RSA private key object for the service account.
   * @param privateKeyId Private key identifier for the service account. May be null.
   * @param scopes Scope strings for the APIs to be called. May be null or an empty collection,
   *     which results in a credential that must have createScoped called before use.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @param tokenServerUri URI of the end point that provides tokens.
   * @param serviceAccountUser Email of the user account to impersonate, if delegating domain-wide
   *     authority to the service account.
   */
  ServiceAccountCredentials(
      String clientId,
      String clientEmail,
      PrivateKey privateKey,
      String privateKeyId,
      Collection<String> scopes,
      HttpTransportFactory transportFactory,
      URI tokenServerUri,
      String serviceAccountUser,
      String projectId) {
    this.clientId = clientId;
    this.clientEmail = Preconditions.checkNotNull(clientEmail);
    this.privateKey = Preconditions.checkNotNull(privateKey);
    this.privateKeyId = privateKeyId;
    this.scopes = (scopes == null) ? ImmutableSet.<String>of() : ImmutableSet.copyOf(scopes);
    this.transportFactory =
        firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
    this.tokenServerUri = (tokenServerUri == null) ? OAuth2Utils.TOKEN_SERVER_URI : tokenServerUri;
    this.serviceAccountUser = serviceAccountUser;
    this.projectId = projectId;
  }

  /**
   * Returns service account credentials defined by JSON using the format supported by the Google
   * Developers Console.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   */
  static ServiceAccountCredentials fromJson(
      Map<String, Object> json, HttpTransportFactory transportFactory) throws IOException {
    String clientId = (String) json.get("client_id");
    String clientEmail = (String) json.get("client_email");
    String privateKeyPkcs8 = (String) json.get("private_key");
    String privateKeyId = (String) json.get("private_key_id");
    String projectId = (String) json.get("project_id");
    String tokenServerUriStringFromCreds = (String) json.get("token_uri");
    URI tokenServerUriFromCreds = null;
    try {
      if (tokenServerUriStringFromCreds != null) {
        tokenServerUriFromCreds = new URI(tokenServerUriStringFromCreds);
      }
    } catch (URISyntaxException e) {
      throw new IOException("Token server URI specified in 'token_uri' could not be parsed.");
    }
    if (clientId == null
        || clientEmail == null
        || privateKeyPkcs8 == null
        || privateKeyId == null) {
      throw new IOException(
          "Error reading service account credential from JSON, "
              + "expecting  'client_id', 'client_email', 'private_key' and 'private_key_id'.");
    }

    return fromPkcs8(
        clientId,
        clientEmail,
        privateKeyPkcs8,
        privateKeyId,
        null,
        transportFactory,
        tokenServerUriFromCreds,
        null,
        projectId);
  }

  /**
   * Factory with minimum identifying information using PKCS#8 for the private key.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKeyPkcs8 RSA private key object for the service account in PKCS#8 format.
   * @param privateKeyId Private key identifier for the service account. May be null.
   * @param scopes Scope strings for the APIs to be called. May be null or an empty collection,
   *     which results in a credential that must have createScoped called before use.
   * @return New ServiceAccountCredentials created from a private key.
   * @throws IOException if the credential cannot be created from the private key.
   */
  public static ServiceAccountCredentials fromPkcs8(
      String clientId,
      String clientEmail,
      String privateKeyPkcs8,
      String privateKeyId,
      Collection<String> scopes)
      throws IOException {
    return fromPkcs8(
        clientId, clientEmail, privateKeyPkcs8, privateKeyId, scopes, null, null, null);
  }

  /**
   * Factory with minimum identifying information and custom transport using PKCS#8 for the private
   * key.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKeyPkcs8 RSA private key object for the service account in PKCS#8 format.
   * @param privateKeyId Private key identifier for the service account. May be null.
   * @param scopes Scope strings for the APIs to be called. May be null or an empty collection,
   *     which results in a credential that must have createScoped called before use.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @param tokenServerUri URI of the end point that provides tokens.
   * @return New ServiceAccountCredentials created from a private key.
   * @throws IOException if the credential cannot be created from the private key.
   */
  public static ServiceAccountCredentials fromPkcs8(
      String clientId,
      String clientEmail,
      String privateKeyPkcs8,
      String privateKeyId,
      Collection<String> scopes,
      HttpTransportFactory transportFactory,
      URI tokenServerUri)
      throws IOException {
    return fromPkcs8(
        clientId,
        clientEmail,
        privateKeyPkcs8,
        privateKeyId,
        scopes,
        transportFactory,
        tokenServerUri,
        null);
  }

  /**
   * Factory with minimum identifying information and custom transport using PKCS#8 for the private
   * key.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKeyPkcs8 RSA private key object for the service account in PKCS#8 format.
   * @param privateKeyId Private key identifier for the service account. May be null.
   * @param scopes Scope strings for the APIs to be called. May be null or an empty collection,
   *     which results in a credential that must have createScoped called before use.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @param tokenServerUri URI of the end point that provides tokens.
   * @param serviceAccountUser The email of the user account to impersonate, if delegating
   *     domain-wide authority to the service account.
   * @return New ServiceAccountCredentials created from a private key.
   * @throws IOException if the credential cannot be created from the private key.
   */
  public static ServiceAccountCredentials fromPkcs8(
      String clientId,
      String clientEmail,
      String privateKeyPkcs8,
      String privateKeyId,
      Collection<String> scopes,
      HttpTransportFactory transportFactory,
      URI tokenServerUri,
      String serviceAccountUser)
      throws IOException {
    return fromPkcs8(
        clientId,
        clientEmail,
        privateKeyPkcs8,
        privateKeyId,
        scopes,
        transportFactory,
        tokenServerUri,
        serviceAccountUser,
        null);
  }

  static ServiceAccountCredentials fromPkcs8(
      String clientId,
      String clientEmail,
      String privateKeyPkcs8,
      String privateKeyId,
      Collection<String> scopes,
      HttpTransportFactory transportFactory,
      URI tokenServerUri,
      String serviceAccountUser,
      String projectId)
      throws IOException {
    PrivateKey privateKey = privateKeyFromPkcs8(privateKeyPkcs8);
    return new ServiceAccountCredentials(
        clientId,
        clientEmail,
        privateKey,
        privateKeyId,
        scopes,
        transportFactory,
        tokenServerUri,
        serviceAccountUser,
        projectId);
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
    throw new IOException("Unexpected exception reading PKCS#8 data", unexpectedException);
  }

  /**
   * Returns credentials defined by a Service Account key file in JSON format from the Google
   * Developers Console.
   *
   * @param credentialsStream the stream with the credential definition.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static ServiceAccountCredentials fromStream(InputStream credentialsStream)
      throws IOException {
    return fromStream(credentialsStream, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  /**
   * Returns credentials defined by a Service Account key file in JSON format from the Google
   * Developers Console.
   *
   * @param credentialsStream the stream with the credential definition.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @return the credential defined by the credentialsStream.
   * @throws IOException if the credential cannot be created from the stream.
   */
  public static ServiceAccountCredentials fromStream(
      InputStream credentialsStream, HttpTransportFactory transportFactory) throws IOException {
    Preconditions.checkNotNull(credentialsStream);
    Preconditions.checkNotNull(transportFactory);

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    JsonObjectParser parser = new JsonObjectParser(jsonFactory);
    GenericJson fileContents =
        parser.parseAndClose(credentialsStream, OAuth2Utils.UTF_8, GenericJson.class);

    String fileType = (String) fileContents.get("type");
    if (fileType == null) {
      throw new IOException("Error reading credentials from stream, 'type' field not specified.");
    }
    if (SERVICE_ACCOUNT_FILE_TYPE.equals(fileType)) {
      return fromJson(fileContents, transportFactory);
    }
    throw new IOException(
        String.format(
            "Error reading credentials from stream, 'type' value '%s' not recognized."
                + " Expecting '%s'.",
            fileType, SERVICE_ACCOUNT_FILE_TYPE));
  }

  /**
   * Refreshes the OAuth2 access token by getting a new access token using a JSON Web Token (JWT).
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (createScopedRequired()) {
      throw new IOException(
          "Scopes not configured for service account. Scoped should be specified"
              + " by calling createScoped or passing scopes to constructor.");
    }

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTime = clock.currentTimeMillis();
    String assertion = createAssertion(jsonFactory, currentTime, tokenServerUri.toString());

    GenericData tokenRequest = new GenericData();
    tokenRequest.set("grant_type", GRANT_TYPE);
    tokenRequest.set("assertion", assertion);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(tokenServerUri), content);
    request.setParser(new JsonObjectParser(jsonFactory));

    request.setIOExceptionHandler(new HttpBackOffIOExceptionHandler(new ExponentialBackOff()));
    request.setUnsuccessfulResponseHandler(
        new HttpBackOffUnsuccessfulResponseHandler(new ExponentialBackOff())
            .setBackOffRequired(
                new BackOffRequired() {
                  public boolean isRequired(HttpResponse response) {
                    int code = response.getStatusCode();
                    return (
                    // Server error --- includes timeout errors, which use 500 instead of 408
                    code / 100 == 5
                        // Forbidden error --- for historical reasons, used for rate_limit_exceeded
                        // errors instead of 429, but there currently seems no robust automatic way
                        // to
                        // distinguish these cases: see
                        // https://github.com/google/google-api-java-client/issues/662
                        || code == 403);
                  }
                }));

    HttpResponse response;
    try {
      response = request.execute();
    } catch (IOException e) {
      throw new IOException(
          String.format("Error getting access token for service account: %s", e.getMessage()), e);
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
   * Returns a Google ID Token from the metadata server on ComputeEngine.
   *
   * @param targetAudience the aud: field the IdToken should include.
   * @param options list of Credential specific options for for the token. Currently unused for
   *     ServiceAccountCredentials.
   * @throws IOException if the attempt to get an IdToken failed
   * @return IdToken object which includes the raw id_token, expiration and audience
   */
  @Beta
  @Override
  public IdToken idTokenWithAudience(String targetAudience, List<IdTokenProvider.Option> options)
      throws IOException {

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTime = clock.currentTimeMillis();
    String assertion =
        createAssertionForIdToken(
            jsonFactory, currentTime, tokenServerUri.toString(), targetAudience);

    GenericData tokenRequest = new GenericData();
    tokenRequest.set("grant_type", GRANT_TYPE);
    tokenRequest.set("assertion", assertion);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(tokenServerUri), content);
    request.setParser(new JsonObjectParser(jsonFactory));
    HttpResponse response = request.execute();

    GenericData responseData = response.parseAs(GenericData.class);
    String rawToken = OAuth2Utils.validateString(responseData, "id_token", PARSE_ERROR_PREFIX);

    return IdToken.create(rawToken);
  }

  /** Returns whether the scopes are empty, meaning createScoped must be called before use. */
  @Override
  public boolean createScopedRequired() {
    return scopes.isEmpty();
  }

  /**
   * Clones the service account with the specified scopes.
   *
   * <p>Should be called before use for instances with empty scopes.
   */
  @Override
  public GoogleCredentials createScoped(Collection<String> newScopes) {
    return new ServiceAccountCredentials(
        clientId,
        clientEmail,
        privateKey,
        privateKeyId,
        newScopes,
        transportFactory,
        tokenServerUri,
        serviceAccountUser,
        projectId);
  }

  @Override
  public GoogleCredentials createDelegated(String user) {
    return new ServiceAccountCredentials(
        clientId,
        clientEmail,
        privateKey,
        privateKeyId,
        scopes,
        transportFactory,
        tokenServerUri,
        user,
        projectId);
  }

  public final String getClientId() {
    return clientId;
  }

  public final String getClientEmail() {
    return clientEmail;
  }

  public final PrivateKey getPrivateKey() {
    return privateKey;
  }

  public final String getPrivateKeyId() {
    return privateKeyId;
  }

  public final Collection<String> getScopes() {
    return scopes;
  }

  public final String getServiceAccountUser() {
    return serviceAccountUser;
  }

  public final String getProjectId() {
    return projectId;
  }

  public final URI getTokenServerUri() {
    return tokenServerUri;
  }

  @Override
  public String getAccount() {
    return getClientEmail();
  }

  @Override
  public byte[] sign(byte[] toSign) {
    try {
      Signature signer = Signature.getInstance(OAuth2Utils.SIGNATURE_ALGORITHM);
      signer.initSign(getPrivateKey());
      signer.update(toSign);
      return signer.sign();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
      throw new SigningException("Failed to sign the provided bytes", ex);
    }
  }

  /**
   * Returns a new JwtCredentials instance with modified claims.
   *
   * @param newClaims new claims. Any unspecified claim fields will default to the the current
   *     values.
   * @return new credentials
   */
  @Override
  public JwtCredentials jwtWithClaims(JwtClaims newClaims) {
    JwtClaims.Builder claimsBuilder =
        JwtClaims.newBuilder().setIssuer(clientEmail).setSubject(clientEmail);
    return JwtCredentials.newBuilder()
        .setPrivateKey(privateKey)
        .setPrivateKeyId(privateKeyId)
        .setJwtClaims(claimsBuilder.build().merge(newClaims))
        .setClock(clock)
        .build();
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        clientId,
        clientEmail,
        privateKey,
        privateKeyId,
        transportFactoryClassName,
        tokenServerUri,
        scopes);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("clientId", clientId)
        .add("clientEmail", clientEmail)
        .add("privateKeyId", privateKeyId)
        .add("transportFactoryClassName", transportFactoryClassName)
        .add("tokenServerUri", tokenServerUri)
        .add("scopes", scopes)
        .add("serviceAccountUser", serviceAccountUser)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ServiceAccountCredentials)) {
      return false;
    }
    ServiceAccountCredentials other = (ServiceAccountCredentials) obj;
    return Objects.equals(this.clientId, other.clientId)
        && Objects.equals(this.clientEmail, other.clientEmail)
        && Objects.equals(this.privateKey, other.privateKey)
        && Objects.equals(this.privateKeyId, other.privateKeyId)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName)
        && Objects.equals(this.tokenServerUri, other.tokenServerUri)
        && Objects.equals(this.scopes, other.scopes);
  }

  String createAssertion(JsonFactory jsonFactory, long currentTime, String audience)
      throws IOException {
    JsonWebSignature.Header header = new JsonWebSignature.Header();
    header.setAlgorithm("RS256");
    header.setType("JWT");
    header.setKeyId(privateKeyId);

    JsonWebToken.Payload payload = new JsonWebToken.Payload();
    payload.setIssuer(clientEmail);
    payload.setIssuedAtTimeSeconds(currentTime / 1000);
    payload.setExpirationTimeSeconds(currentTime / 1000 + 3600);
    payload.setSubject(serviceAccountUser);
    payload.put("scope", Joiner.on(' ').join(scopes));

    if (audience == null) {
      payload.setAudience(OAuth2Utils.TOKEN_SERVER_URI.toString());
    } else {
      payload.setAudience(audience);
    }

    String assertion;
    try {
      assertion = JsonWebSignature.signUsingRsaSha256(privateKey, jsonFactory, header, payload);
    } catch (GeneralSecurityException e) {
      throw new IOException(
          "Error signing service account access token request with private key.", e);
    }
    return assertion;
  }

  String createAssertionForIdToken(
      JsonFactory jsonFactory, long currentTime, String audience, String targetAudience)
      throws IOException {
    JsonWebSignature.Header header = new JsonWebSignature.Header();
    header.setAlgorithm("RS256");
    header.setType("JWT");
    header.setKeyId(privateKeyId);

    JsonWebToken.Payload payload = new JsonWebToken.Payload();
    payload.setIssuer(clientEmail);
    payload.setIssuedAtTimeSeconds(currentTime / 1000);
    payload.setExpirationTimeSeconds(currentTime / 1000 + 3600);
    payload.setSubject(serviceAccountUser);

    if (audience == null) {
      payload.setAudience(OAuth2Utils.TOKEN_SERVER_URI.toString());
    } else {
      payload.setAudience(audience);
    }

    try {
      payload.set("target_audience", targetAudience);

      String assertion =
          JsonWebSignature.signUsingRsaSha256(privateKey, jsonFactory, header, payload);
      return assertion;
    } catch (GeneralSecurityException e) {
      throw new IOException(
          "Error signing service account access token request with private key.", e);
    }
  }

  @SuppressWarnings("unused")
  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    // properly deserialize the transient transportFactory
    input.defaultReadObject();
    transportFactory = newInstance(transportFactoryClassName);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static class Builder extends GoogleCredentials.Builder {

    private String clientId;
    private String clientEmail;
    private PrivateKey privateKey;
    private String privateKeyId;
    private String serviceAccountUser;
    private String projectId;
    private URI tokenServerUri;
    private Collection<String> scopes;
    private HttpTransportFactory transportFactory;

    protected Builder() {}

    protected Builder(ServiceAccountCredentials credentials) {
      this.clientId = credentials.clientId;
      this.clientEmail = credentials.clientEmail;
      this.privateKey = credentials.privateKey;
      this.privateKeyId = credentials.privateKeyId;
      this.scopes = credentials.scopes;
      this.transportFactory = credentials.transportFactory;
      this.tokenServerUri = credentials.tokenServerUri;
      this.serviceAccountUser = credentials.serviceAccountUser;
      this.projectId = credentials.projectId;
    }

    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder setClientEmail(String clientEmail) {
      this.clientEmail = clientEmail;
      return this;
    }

    public Builder setPrivateKey(PrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public Builder setPrivateKeyId(String privateKeyId) {
      this.privateKeyId = privateKeyId;
      return this;
    }

    public Builder setScopes(Collection<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public Builder setServiceAccountUser(String serviceAccountUser) {
      this.serviceAccountUser = serviceAccountUser;
      return this;
    }

    public Builder setProjectId(String projectId) {
      this.projectId = projectId;
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

    public String getClientId() {
      return clientId;
    }

    public String getClientEmail() {
      return clientEmail;
    }

    public PrivateKey getPrivateKey() {
      return privateKey;
    }

    public String getPrivateKeyId() {
      return privateKeyId;
    }

    public Collection<String> getScopes() {
      return scopes;
    }

    public String getServiceAccountUser() {
      return serviceAccountUser;
    }

    public String getProjectId() {
      return projectId;
    }

    public URI getTokenServerUri() {
      return tokenServerUri;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public ServiceAccountCredentials build() {
      return new ServiceAccountCredentials(
          clientId,
          clientEmail,
          privateKey,
          privateKeyId,
          scopes,
          transportFactory,
          tokenServerUri,
          serviceAccountUser,
          projectId);
    }
  }
}
