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

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.Clock;
import com.google.api.client.util.Preconditions;
import com.google.auth.Credentials;
import com.google.auth.RequestMetadataCallback;
import com.google.auth.http.AuthHttpConstants;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Service Account credentials for calling Google APIs using a JWT directly for access.
 *
 * <p>Uses a JSON Web Token (JWT) directly in the request metadata to provide authorization.
 */
public class ServiceAccountJwtAccessCredentials extends Credentials {

  private static final long serialVersionUID = -7274955171379494197L;
  static final String JWT_ACCESS_PREFIX = OAuth2Utils.BEARER_PREFIX;

  private final String clientId;
  private final String clientEmail;
  private final PrivateKey privateKey;
  private final String privateKeyId;
  private final URI defaultAudience;

  // Until we expose this to the users it can remain transient and non-serializable
  @VisibleForTesting
  transient Clock clock = Clock.SYSTEM;

  /**
   * Constructor with minimum identifying information.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKey RSA private key object for the service account.
   * @param privateKeyId Private key identifier for the service account. May be null.
   */
  public ServiceAccountJwtAccessCredentials(
      String clientId, String clientEmail, PrivateKey privateKey, String privateKeyId) {
    this(clientId, clientEmail, privateKey, privateKeyId, null);
  }

  /**
   * Constructor with full information.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKey RSA private key object for the service account.
   * @param privateKeyId Private key identifier for the service account. May be null.
   * @param defaultAudience Audience to use if not provided by transport. May be null.
   */
  public ServiceAccountJwtAccessCredentials(String clientId, String clientEmail,
      PrivateKey privateKey, String privateKeyId, URI defaultAudience) {
    this.clientId = clientId;
    this.clientEmail = Preconditions.checkNotNull(clientEmail);
    this.privateKey = Preconditions.checkNotNull(privateKey);
    this.privateKeyId = privateKeyId;
    this.defaultAudience = defaultAudience;
  }

  /**
   * Returns service account crentials defined by JSON using the format supported by the Google
   * Developers Console.
   *
   * @param json a map from the JSON representing the credentials.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   **/
  static ServiceAccountJwtAccessCredentials fromJson(Map<String, Object> json) throws IOException {
    return fromJson(json, null);
  }

  /**
   * Returns service account crentials defined by JSON using the format supported by the Google
   * Developers Console.
   *
   * @param json a map from the JSON representing the credentials.
   * @param defaultAudience Audience to use if not provided by transport. May be null.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   **/
  static ServiceAccountJwtAccessCredentials fromJson(Map<String, Object> json, URI defaultAudience)
      throws IOException {
    String clientId = (String) json.get("client_id");
    String clientEmail = (String) json.get("client_email");
    String privateKeyPkcs8 = (String) json.get("private_key");
    String privateKeyId = (String) json.get("private_key_id");
    if (clientId == null || clientEmail == null
        || privateKeyPkcs8 == null || privateKeyId == null) {
      throw new IOException("Error reading service account credential from JSON, "
          + "expecting  'client_id', 'client_email', 'private_key' and 'private_key_id'.");
    }
    return fromPkcs8(clientId, clientEmail, privateKeyPkcs8, privateKeyId, defaultAudience);
  }

  /**
   * Factory using PKCS#8 for the private key.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKeyPkcs8 RSA private key object for the service account in PKCS#8 format.
   * @param privateKeyId Private key identifier for the service account. May be null.
   */
  public static ServiceAccountJwtAccessCredentials fromPkcs8(String clientId, String clientEmail, 
      String privateKeyPkcs8, String privateKeyId) throws IOException {
    return fromPkcs8(clientId, clientEmail, privateKeyPkcs8, privateKeyId, null);
  }

  /**
   * Factory using PKCS#8 for the private key.
   *
   * @param clientId Client ID of the service account from the console. May be null.
   * @param clientEmail Client email address of the service account from the console.
   * @param privateKeyPkcs8 RSA private key object for the service account in PKCS#8 format.
   * @param privateKeyId Private key identifier for the service account. May be null.
   * @param defaultAudience Audience to use if not provided by transport. May be null.
   */
  public static ServiceAccountJwtAccessCredentials fromPkcs8(String clientId, String clientEmail, 
      String privateKeyPkcs8, String privateKeyId, URI defaultAudience) throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(privateKeyPkcs8);
    return new ServiceAccountJwtAccessCredentials(
        clientId, clientEmail, privateKey, privateKeyId, defaultAudience);
  }

  @Override
  public String getAuthenticationType() {
    return "JWTAccess";
  }

  @Override
  public boolean hasRequestMetadata() {
    return true;
  }

  @Override
  public boolean hasRequestMetadataOnly() {
    return true;
  }

  @Override
  public void getRequestMetadata(final URI uri, Executor executor,
      final RequestMetadataCallback callback) {
    // It doesn't use network. Only some CPU work on par with TLS handshake. So it's preferrable
    // to do it in the current thread, which is likely to be the network thread.
    blockingGetToCallback(uri, callback);
  }

  /**
   * Provide the request metadata by putting an access JWT directly in the metadata.
   */
  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    if (uri == null) {
      if (defaultAudience != null) {
        uri = defaultAudience;
      } else {
        throw new IOException("JwtAccess requires Audience uri to be passed in or the " 
          + "defaultAudience to be specified");
      }
    }
    String assertion = getJwtAccess(uri);
    String authorizationHeader = JWT_ACCESS_PREFIX + assertion;
    List<String> newAuthorizationHeaders = Collections.singletonList(authorizationHeader);
    Map<String, List<String>> newRequestMetadata =
        Collections.singletonMap(AuthHttpConstants.AUTHORIZATION, newAuthorizationHeaders);
    return newRequestMetadata;
  }

  /**
   * Discard any cached data
   */
  @Override
  public void refresh() {
  }

  private String getJwtAccess(URI uri) throws IOException {

    JsonWebSignature.Header header = new JsonWebSignature.Header();
    header.setAlgorithm("RS256");
    header.setType("JWT");
    header.setKeyId(privateKeyId);

    JsonWebToken.Payload payload = new JsonWebToken.Payload();
    long currentTime = clock.currentTimeMillis();
    // Both copies of the email are required
    payload.setIssuer(clientEmail);
    payload.setSubject(clientEmail);
    payload.setAudience(uri.toString());
    payload.setIssuedAtTimeSeconds(currentTime / 1000);
    payload.setExpirationTimeSeconds(currentTime / 1000 + 3600);

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;

    String assertion = null;
    try {
      assertion = JsonWebSignature.signUsingRsaSha256(
          privateKey, jsonFactory, header, payload);
    } catch (GeneralSecurityException e) {
      throw OAuth2Utils.exceptionWithCause(new IOException(
          "Error signing service account JWT access header with private key."), e);
    }
    return assertion;
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

  @Override
  public int hashCode() {
    return Objects.hash(clientId, clientEmail, privateKey, privateKeyId, defaultAudience);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("clientId", clientId)
        .add("clientEmail", clientEmail)
        .add("privateKeyId", privateKeyId)
        .add("defaultAudience", defaultAudience)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ServiceAccountJwtAccessCredentials)) {
      return false;
    }
    ServiceAccountJwtAccessCredentials other = (ServiceAccountJwtAccessCredentials) obj;
    return Objects.equals(this.clientId, other.clientId)
        && Objects.equals(this.clientEmail, other.clientEmail)
        && Objects.equals(this.privateKey, other.privateKey)
        && Objects.equals(this.privateKeyId, other.privateKeyId)
        && Objects.equals(this.defaultAudience, other.defaultAudience);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    clock = Clock.SYSTEM;
  }
}
