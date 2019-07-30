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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Joiner;
import com.google.api.client.util.Preconditions;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.collect.ImmutableList;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.Date;

/** Handles an interactive 3-Legged-OAuth2 (3LO) user consent authorization. */
public class UserAuthorizer {

  static final URI DEFAULT_CALLBACK_URI = URI.create("/oauth2callback");

  private final String TOKEN_STORE_ERROR = "Error parsing stored token data.";
  private final String FETCH_TOKEN_ERROR = "Error reading result of Token API:";

  private final ClientId clientId;
  private final Collection<String> scopes;
  private final TokenStore tokenStore;
  private final URI callbackUri;

  private final HttpTransportFactory transportFactory;
  private final URI tokenServerUri;
  private final URI userAuthUri;

  /**
   * Constructor with all parameters.
   *
   * @param clientId Client ID to identify the OAuth2 consent prompt
   * @param scopes OAuth2 scopes defining the user consent
   * @param tokenStore Implementation of a component for long term storage of tokens
   * @param callbackUri URI for implementation of the OAuth2 web callback
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *     tokens.
   * @param tokenServerUri URI of the end point that provides tokens
   * @param userAuthUri URI of the Web UI for user consent
   */
  private UserAuthorizer(
      ClientId clientId,
      Collection<String> scopes,
      TokenStore tokenStore,
      URI callbackUri,
      HttpTransportFactory transportFactory,
      URI tokenServerUri,
      URI userAuthUri) {
    this.clientId = Preconditions.checkNotNull(clientId);
    this.scopes = ImmutableList.copyOf(Preconditions.checkNotNull(scopes));
    this.callbackUri = (callbackUri == null) ? DEFAULT_CALLBACK_URI : callbackUri;
    this.transportFactory =
        (transportFactory == null) ? OAuth2Utils.HTTP_TRANSPORT_FACTORY : transportFactory;
    this.tokenServerUri = (tokenServerUri == null) ? OAuth2Utils.TOKEN_SERVER_URI : tokenServerUri;
    this.userAuthUri = (userAuthUri == null) ? OAuth2Utils.USER_AUTH_URI : userAuthUri;
    this.tokenStore = (tokenStore == null) ? new MemoryTokensStorage() : tokenStore;
  }

  /**
   * Returns the Client ID user to identify the OAuth2 consent prompt.
   *
   * @return The Client ID.
   */
  public ClientId getClientId() {
    return clientId;
  }

  /**
   * Returns the scopes defining the user consent.
   *
   * @return The collection of scopes defining the user consent.
   */
  public Collection<String> getScopes() {
    return scopes;
  }

  /**
   * Returns the URI for implementation of the OAuth2 web callback.
   *
   * @return The URI for the OAuth2 web callback.
   */
  public URI getCallbackUri() {
    return callbackUri;
  }

  /**
   * Returns the URI for implementation of the OAuth2 web callback, optionally relative to the
   * specified URI.
   *
   * <p>The callback URI is often relative to enable an application to be tested from more than one
   * place so this can be used to resolve it relative to another URI.
   *
   * @param baseUri The URI to resolve the callback URI relative to.
   * @return The resolved URI.
   */
  public URI getCallbackUri(URI baseUri) {
    if (callbackUri.isAbsolute()) {
      return callbackUri;
    }
    if (baseUri == null || !baseUri.isAbsolute()) {
      throw new IllegalStateException(
          "If the callback URI is relative, the baseUri passed must" + " be an absolute URI");
    }
    return baseUri.resolve(callbackUri);
  }

  /**
   * Returns the implementation of a component for long term storage of tokens.
   *
   * @return The token storage implementation for long term storage of tokens.
   */
  public TokenStore getTokenStore() {
    return tokenStore;
  }

  /**
   * Return an URL that performs the authorization consent prompt web UI.
   *
   * @param userId Application's identifier for the end user.
   * @param state State that is passed on to the OAuth2 callback URI after the consent.
   * @param baseUri The URI to resolve the OAuth2 callback URI relative to.
   * @return The URL that can be navigated or redirected to.
   */
  public URL getAuthorizationUrl(String userId, String state, URI baseUri) {
    URI resolvedCallbackUri = getCallbackUri(baseUri);
    String scopesString = Joiner.on(' ').join(scopes);

    GenericUrl url = new GenericUrl(userAuthUri);
    url.put("response_type", "code");
    url.put("client_id", clientId.getClientId());
    url.put("redirect_uri", resolvedCallbackUri);
    url.put("scope", scopesString);
    if (state != null) {
      url.put("state", state);
    }
    url.put("access_type", "offline");
    url.put("approval_prompt", "force");
    if (userId != null) {
      url.put("login_hint", userId);
    }
    url.put("include_granted_scopes", true);
    return url.toURL();
  }

  /**
   * Attempts to retrieve credentials for the approved end user consent.
   *
   * @param userId Application's identifier for the end user.
   * @return The loaded credentials or null if there are no valid approved credentials.
   * @throws IOException If there is error retrieving or loading the credentials.
   */
  public UserCredentials getCredentials(String userId) throws IOException {
    Preconditions.checkNotNull(userId);
    if (tokenStore == null) {
      throw new IllegalStateException("Method cannot be called if token store is not specified.");
    }
    String tokenData = tokenStore.load(userId);
    if (tokenData == null) {
      return null;
    }
    GenericJson tokenJson = OAuth2Utils.parseJson(tokenData);
    String accessTokenValue =
        OAuth2Utils.validateString(tokenJson, "access_token", TOKEN_STORE_ERROR);
    Long expirationMillis =
        OAuth2Utils.validateLong(tokenJson, "expiration_time_millis", TOKEN_STORE_ERROR);
    Date expirationTime = new Date(expirationMillis);
    AccessToken accessToken = new AccessToken(accessTokenValue, expirationTime);
    String refreshToken =
        OAuth2Utils.validateOptionalString(tokenJson, "refresh_token", TOKEN_STORE_ERROR);
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(clientId.getClientId())
            .setClientSecret(clientId.getClientSecret())
            .setRefreshToken(refreshToken)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServerUri)
            .build();
    monitorCredentials(userId, credentials);
    return credentials;
  }

  /**
   * Returns a UserCredentials instance by exchanging an OAuth2 authorization code for tokens.
   *
   * @param code Code returned from OAuth2 consent prompt.
   * @param baseUri The URI to resolve the OAuth2 callback URI relative to.
   * @return the UserCredentials instance created from the authorization code.
   * @throws IOException An error from the server API call to get the tokens.
   */
  public UserCredentials getCredentialsFromCode(String code, URI baseUri) throws IOException {
    Preconditions.checkNotNull(code);
    URI resolvedCallbackUri = getCallbackUri(baseUri);

    GenericData tokenData = new GenericData();
    tokenData.put("code", code);
    tokenData.put("client_id", clientId.getClientId());
    tokenData.put("client_secret", clientId.getClientSecret());
    tokenData.put("redirect_uri", resolvedCallbackUri);
    tokenData.put("grant_type", "authorization_code");
    UrlEncodedContent tokenContent = new UrlEncodedContent(tokenData);
    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest tokenRequest =
        requestFactory.buildPostRequest(new GenericUrl(tokenServerUri), tokenContent);
    tokenRequest.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));

    HttpResponse tokenResponse = tokenRequest.execute();

    GenericJson parsedTokens = tokenResponse.parseAs(GenericJson.class);
    String accessTokenValue =
        OAuth2Utils.validateString(parsedTokens, "access_token", FETCH_TOKEN_ERROR);
    int expiresInSecs = OAuth2Utils.validateInt32(parsedTokens, "expires_in", FETCH_TOKEN_ERROR);
    Date expirationTime = new Date(new Date().getTime() + expiresInSecs * 1000);
    AccessToken accessToken = new AccessToken(accessTokenValue, expirationTime);
    String refreshToken =
        OAuth2Utils.validateOptionalString(parsedTokens, "refresh_token", FETCH_TOKEN_ERROR);

    return UserCredentials.newBuilder()
        .setClientId(clientId.getClientId())
        .setClientSecret(clientId.getClientSecret())
        .setRefreshToken(refreshToken)
        .setAccessToken(accessToken)
        .setHttpTransportFactory(transportFactory)
        .setTokenServerUri(tokenServerUri)
        .build();
  }

  /**
   * Exchanges an authorization code for tokens and stores them.
   *
   * @param userId Application's identifier for the end user.
   * @param code Code returned from OAuth2 consent prompt.
   * @param baseUri The URI to resolve the OAuth2 callback URI relative to.
   * @return UserCredentials instance created from the authorization code.
   * @throws IOException An error from the server API call to get the tokens or store the tokens.
   */
  public UserCredentials getAndStoreCredentialsFromCode(String userId, String code, URI baseUri)
      throws IOException {
    Preconditions.checkNotNull(userId);
    Preconditions.checkNotNull(code);
    UserCredentials credentials = getCredentialsFromCode(code, baseUri);
    storeCredentials(userId, credentials);
    monitorCredentials(userId, credentials);
    return credentials;
  }

  /**
   * Revokes the authorization for tokens stored for the user.
   *
   * @param userId Application's identifier for the end user.
   * @throws IOException An error calling the revoke API or deleting the state.
   */
  public void revokeAuthorization(String userId) throws IOException {
    Preconditions.checkNotNull(userId);
    if (tokenStore == null) {
      throw new IllegalStateException("Method cannot be called if token store is not specified.");
    }
    String tokenData = tokenStore.load(userId);
    if (tokenData == null) {
      return;
    }
    IOException deleteTokenException = null;
    try {
      // Delete the stored version first. If token reversion fails it is less harmful to have an
      // non revoked token to hold on to a potentially revoked token.
      tokenStore.delete(userId);
    } catch (IOException e) {
      deleteTokenException = e;
    }

    GenericJson tokenJson = OAuth2Utils.parseJson(tokenData);
    String accessTokenValue =
        OAuth2Utils.validateOptionalString(tokenJson, "access_token", TOKEN_STORE_ERROR);
    String refreshToken =
        OAuth2Utils.validateOptionalString(tokenJson, "refresh_token", TOKEN_STORE_ERROR);
    // If both tokens are present, either can be used
    String revokeToken = (refreshToken != null) ? refreshToken : accessTokenValue;
    GenericUrl revokeUrl = new GenericUrl(OAuth2Utils.TOKEN_REVOKE_URI);
    revokeUrl.put("token", revokeToken);
    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest tokenRequest = requestFactory.buildGetRequest(revokeUrl);
    tokenRequest.execute();

    if (deleteTokenException != null) {
      throw deleteTokenException;
    }
  }

  /**
   * Puts the end user credentials in long term storage.
   *
   * @param userId Application's identifier for the end user.
   * @param credentials UserCredentials instance for the authorized consent.
   * @throws IOException An error storing the credentials.
   */
  public void storeCredentials(String userId, UserCredentials credentials) throws IOException {
    if (tokenStore == null) {
      throw new IllegalStateException("Cannot store tokens if tokenStore is not specified.");
    }
    AccessToken accessToken = credentials.getAccessToken();
    String acessTokenValue = null;
    Date expiresBy = null;
    if (accessToken != null) {
      acessTokenValue = accessToken.getTokenValue();
      expiresBy = accessToken.getExpirationTime();
    }
    String refreshToken = credentials.getRefreshToken();
    GenericJson tokenStateJson = new GenericJson();
    tokenStateJson.setFactory(OAuth2Utils.JSON_FACTORY);
    tokenStateJson.put("access_token", acessTokenValue);
    tokenStateJson.put("expiration_time_millis", expiresBy.getTime());
    if (refreshToken != null) {
      tokenStateJson.put("refresh_token", refreshToken);
    }
    String tokenState = tokenStateJson.toString();
    tokenStore.store(userId, tokenState);
  }

  /**
   * Adds a listen to rewrite the credentials when the tokens are refreshed.
   *
   * @param userId Application's identifier for the end user.
   * @param credentials UserCredentials instance to listen to.
   */
  protected void monitorCredentials(String userId, UserCredentials credentials) {
    credentials.addChangeListener(new UserCredentialsListener(userId));
  }

  /**
   * Implementation of listener used by monitorCredentials to rewrite the credentials when the
   * tokens are refreshed.
   */
  private class UserCredentialsListener implements OAuth2Credentials.CredentialsChangedListener {
    private final String userId;

    /** Construct new listener. */
    public UserCredentialsListener(String userId) {
      this.userId = userId;
    }

    /** Handle change event by rewriting to token store. */
    @Override
    public void onChanged(OAuth2Credentials credentials) throws IOException {
      UserCredentials userCredentials = (UserCredentials) credentials;
      storeCredentials(userId, userCredentials);
    }
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static class Builder {

    private ClientId clientId;
    private TokenStore tokenStore;
    private URI callbackUri;
    private URI tokenServerUri;
    private URI userAuthUri;
    private Collection<String> scopes;
    private HttpTransportFactory transportFactory;

    protected Builder() {}

    protected Builder(UserAuthorizer authorizer) {
      this.clientId = authorizer.clientId;
      this.scopes = authorizer.scopes;
      this.transportFactory = authorizer.transportFactory;
      this.tokenServerUri = authorizer.tokenServerUri;
      this.tokenStore = authorizer.tokenStore;
      this.callbackUri = authorizer.callbackUri;
      this.userAuthUri = authorizer.userAuthUri;
    }

    public Builder setClientId(ClientId clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder setTokenStore(TokenStore tokenStore) {
      this.tokenStore = tokenStore;
      return this;
    }

    public Builder setScopes(Collection<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public Builder setTokenServerUri(URI tokenServerUri) {
      this.tokenServerUri = tokenServerUri;
      return this;
    }

    public Builder setCallbackUri(URI callbackUri) {
      this.callbackUri = callbackUri;
      return this;
    }

    public Builder setUserAuthUri(URI userAuthUri) {
      this.userAuthUri = userAuthUri;
      return this;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public ClientId getClientId() {
      return clientId;
    }

    public TokenStore getTokenStore() {
      return tokenStore;
    }

    public Collection<String> getScopes() {
      return scopes;
    }

    public URI getTokenServerUri() {
      return tokenServerUri;
    }

    public URI getCallbackUri() {
      return callbackUri;
    }

    public URI getUserAuthUri() {
      return userAuthUri;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public UserAuthorizer build() {
      return new UserAuthorizer(
          clientId, scopes, tokenStore, callbackUri, transportFactory, tokenServerUri, userAuthUri);
    }
  }
}
