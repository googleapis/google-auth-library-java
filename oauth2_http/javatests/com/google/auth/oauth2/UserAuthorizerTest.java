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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import com.google.auth.TestUtils;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit Tests for UserAuthorizer */
@RunWith(JUnit4.class)
public class UserAuthorizerTest {
  private static final String CLIENT_ID_VALUE = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN_VALUE = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final List<String> GRANTED_SCOPES = Arrays.asList("scope1", "scope2");
  private static final String GRANTED_SCOPES_STRING = String.join(" ", GRANTED_SCOPES);
  private static final String DUMMY_SCOPE = "dummy_scope";
  private static final List<String> DUMMY_SCOPES = Arrays.asList(DUMMY_SCOPE);
  private static final Long EXPIRATION_TIME = 504000300L;
  private static final AccessToken ACCESS_TOKEN =
      AccessToken.newBuilder()
          .setTokenValue(ACCESS_TOKEN_VALUE)
          .setExpirationTime(new Date(EXPIRATION_TIME))
          .setScopes(GRANTED_SCOPES)
          .build();
  private static final ClientId CLIENT_ID = ClientId.of(CLIENT_ID_VALUE, CLIENT_SECRET);
  private static final String USER_ID = "foo@bar.com";
  private static final URI CALLBACK_URI = URI.create("/testcallback");
  private static final String CODE = "thisistheend";
  private static final URI BASE_URI = URI.create("http://example.com/foo");
  private static final PKCEProvider pkce = new DefaultPKCEProvider();

  @Test
  public void constructorMinimum() {
    TokenStore store = new MemoryTokensStorage();

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(store)
            .build();

    assertSame(CLIENT_ID, authorizer.getClientId());
    assertSame(store, authorizer.getTokenStore());
    assertEquals(DUMMY_SCOPES, authorizer.getScopes());
    assertEquals(UserAuthorizer.DEFAULT_CALLBACK_URI, authorizer.getCallbackUri());
  }

  @Test
  public void constructorCommon() {
    TokenStore store = new MemoryTokensStorage();

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(store)
            .setCallbackUri(CALLBACK_URI)
            .build();

    assertSame(CLIENT_ID, authorizer.getClientId());
    assertSame(store, authorizer.getTokenStore());
    assertEquals(DUMMY_SCOPES, authorizer.getScopes());
    assertEquals(CALLBACK_URI, authorizer.getCallbackUri());
  }

  @Test(expected = NullPointerException.class)
  public void constructorCommon_nullClientId_throws() {
    UserAuthorizer.newBuilder().setScopes(DUMMY_SCOPES).setCallbackUri(CALLBACK_URI).build();
  }

  @Test(expected = NullPointerException.class)
  public void constructorCommon_nullScopes_throws() {
    UserAuthorizer.newBuilder().setClientId(CLIENT_ID).build();
  }

  @Test
  public void getCallbackUri_relativeToBase() {
    final URI callbackURI = URI.create("/bar");
    final URI expectedCallbackURI = URI.create("http://example.com/bar");
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setCallbackUri(callbackURI)
            .build();

    URI absoluteCallbackURI = authorizer.getCallbackUri(BASE_URI);

    assertEquals(expectedCallbackURI, absoluteCallbackURI);
  }

  @Test
  public void getAuthorizationUrl() throws IOException {
    final String CUSTOM_STATE = "custom_state";
    final String PROTOCOL = "https";
    final String HOST = "accounts.test.com";
    final String PATH = "/o/o/oauth2/auth";
    final URI AUTH_URI = URI.create(PROTOCOL + "://" + HOST + PATH);
    final String EXPECTED_CALLBACK = "http://example.com" + CALLBACK_URI.toString();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setCallbackUri(CALLBACK_URI)
            .setUserAuthUri(AUTH_URI)
            .setPKCEProvider(pkce)
            .build();

    URL authorizationUrl = authorizer.getAuthorizationUrl(USER_ID, CUSTOM_STATE, BASE_URI);

    assertEquals(PROTOCOL, authorizationUrl.getProtocol());
    assertEquals(-1, authorizationUrl.getPort());
    assertEquals(PATH, authorizationUrl.getPath());
    assertEquals(HOST, authorizationUrl.getHost());
    String query = authorizationUrl.getQuery();
    Map<String, String> parameters = TestUtils.parseQuery(query);
    assertEquals(CUSTOM_STATE, parameters.get("state"));
    assertEquals(USER_ID, parameters.get("login_hint"));
    assertEquals(EXPECTED_CALLBACK, parameters.get("redirect_uri"));
    assertEquals(CLIENT_ID_VALUE, parameters.get("client_id"));
    assertEquals(DUMMY_SCOPE, parameters.get("scope"));
    assertEquals("code", parameters.get("response_type"));
    assertEquals(pkce.getCodeChallenge(), parameters.get("code_challenge"));
    assertEquals(pkce.getCodeChallengeMethod(), parameters.get("code_challenge_method"));
  }

  @Test
  public void getAuthorizationUrl_additionalParameters() throws IOException {
    final String CUSTOM_STATE = "custom_state";
    final String PROTOCOL = "https";
    final String HOST = "accounts.test.com";
    final String PATH = "/o/o/oauth2/auth";
    final URI AUTH_URI = URI.create(PROTOCOL + "://" + HOST + PATH);
    final String EXPECTED_CALLBACK = "http://example.com" + CALLBACK_URI.toString();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setCallbackUri(CALLBACK_URI)
            .setUserAuthUri(AUTH_URI)
            .build();
    Map<String, String> additionalParameters = new HashMap<String, String>();
    additionalParameters.put("param1", "value1");
    additionalParameters.put("param2", "value2");

    // Verify that the authorization URL doesn't include the additional parameters if they are not
    // passed in.
    URL authorizationUrl = authorizer.getAuthorizationUrl(USER_ID, CUSTOM_STATE, BASE_URI);
    String query = authorizationUrl.getQuery();
    Map<String, String> parameters = TestUtils.parseQuery(query);
    assertFalse(parameters.containsKey("param1"));
    assertFalse(parameters.containsKey("param2"));

    // Verify that the authorization URL includes the additional parameters if they are passed in.
    authorizationUrl =
        authorizer.getAuthorizationUrl(USER_ID, CUSTOM_STATE, BASE_URI, additionalParameters);
    query = authorizationUrl.getQuery();
    parameters = TestUtils.parseQuery(query);
    assertEquals("value1", parameters.get("param1"));
    assertEquals("value2", parameters.get("param2"));

    // Verify that the authorization URL doesn't include the additional parameters passed in the
    // previous call to the authorizer
    authorizationUrl = authorizer.getAuthorizationUrl(USER_ID, CUSTOM_STATE, BASE_URI);
    query = authorizationUrl.getQuery();
    parameters = TestUtils.parseQuery(query);
    assertFalse(parameters.containsKey("param1"));
    assertFalse(parameters.containsKey("param2"));
  }

  @Test
  public void getCredentials_noCredentials_returnsNull() throws IOException {
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .build();

    UserCredentials credentials = authorizer.getCredentials(USER_ID);

    assertNull(credentials);
  }

  @Test
  public void getCredentials_storedCredentials_returnsStored() throws IOException {
    TokenStore tokenStore = new MemoryTokensStorage();

    UserCredentials initialCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID_VALUE)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(ACCESS_TOKEN)
            .build();

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .build();
    authorizer.storeCredentials(USER_ID, initialCredentials);

    UserCredentials credentials = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(ACCESS_TOKEN_VALUE, credentials.getAccessToken().getTokenValue());
    assertEquals(EXPIRATION_TIME, credentials.getAccessToken().getExpirationTimeMillis());
    assertEquals(GRANTED_SCOPES, credentials.getAccessToken().getScopes());
  }

  @Test(expected = NullPointerException.class)
  public void getCredentials_nullUserId_throws() throws IOException {
    TokenStore tokenStore = new MemoryTokensStorage();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .build();

    authorizer.getCredentials(null);
  }

  @Test
  public void getCredentials_refreshedToken_stored() throws IOException {
    final String accessTokenValue1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessTokenValue2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    AccessToken accessToken1 =
        AccessToken.newBuilder()
            .setTokenValue(accessTokenValue1)
            .setExpirationTime(new Date(EXPIRATION_TIME))
            .setScopes(GRANTED_SCOPES)
            .build();
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(
        REFRESH_TOKEN, accessTokenValue2, GRANTED_SCOPES_STRING);
    TokenStore tokenStore = new MemoryTokensStorage();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .setHttpTransportFactory(transportFactory)
            .build();

    UserCredentials originalCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID_VALUE)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken1)
            .setHttpTransportFactory(transportFactory)
            .build();

    authorizer.storeCredentials(USER_ID, originalCredentials);

    UserCredentials credentials1 = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue1, credentials1.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials1.getAccessToken().getScopes());

    // Refresh the token to get update from token server
    credentials1.refresh();
    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue2, credentials1.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials1.getAccessToken().getScopes());

    // Load a second credentials instance
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);

    // Verify that token refresh stored the updated tokens
    assertEquals(REFRESH_TOKEN, credentials2.getRefreshToken());
    assertEquals(accessTokenValue2, credentials2.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials2.getAccessToken().getScopes());
  }

  @Test
  public void getCredentials_refreshedToken_different_granted_scopes() throws IOException {
    final String accessTokenValue1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessTokenValue2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    final List<String> grantedRefreshScopes = Arrays.asList("scope3");
    AccessToken accessToken1 =
        AccessToken.newBuilder()
            .setTokenValue(accessTokenValue1)
            .setExpirationTime(new Date(EXPIRATION_TIME))
            .setScopes(GRANTED_SCOPES)
            .build();
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessTokenValue2, "scope3");
    TokenStore tokenStore = new MemoryTokensStorage();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .setHttpTransportFactory(transportFactory)
            .build();

    UserCredentials originalCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID_VALUE)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken1)
            .setHttpTransportFactory(transportFactory)
            .build();

    authorizer.storeCredentials(USER_ID, originalCredentials);

    UserCredentials credentials1 = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue1, credentials1.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials1.getAccessToken().getScopes());

    // Refresh the token to get update from token server
    credentials1.refresh();
    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue2, credentials1.getAccessToken().getTokenValue());
    assertEquals(grantedRefreshScopes, credentials1.getAccessToken().getScopes());

    // Load a second credentials instance
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);

    // Verify that token refresh stored the updated tokens
    assertEquals(REFRESH_TOKEN, credentials2.getRefreshToken());
    assertEquals(accessTokenValue2, credentials2.getAccessToken().getTokenValue());
    assertEquals(grantedRefreshScopes, credentials2.getAccessToken().getScopes());
  }

  @Test
  public void getCredentialsFromCode_conevertsCodeToTokens() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addAuthorizationCode(
        CODE, REFRESH_TOKEN, ACCESS_TOKEN_VALUE, GRANTED_SCOPES_STRING, null);
    TokenStore tokenStore = new MemoryTokensStorage();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .setHttpTransportFactory(transportFactory)
            .build();

    UserCredentials credentials = authorizer.getCredentialsFromCode(CODE, BASE_URI);

    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(ACCESS_TOKEN_VALUE, credentials.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials.getAccessToken().getScopes());
  }

  @Test
  public void getCredentialsFromCode_additionalParameters() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);

    Map<String, String> additionalParameters = new HashMap<String, String>();
    additionalParameters.put("param1", "value1");
    additionalParameters.put("param2", "value2");

    String code2 = "code2";
    String refreshToken2 = "refreshToken2";
    String accessTokenValue2 = "accessTokenValue2";

    transportFactory.transport.addAuthorizationCode(
        CODE, REFRESH_TOKEN, ACCESS_TOKEN_VALUE, GRANTED_SCOPES_STRING, null);
    transportFactory.transport.addAuthorizationCode(
        code2, refreshToken2, accessTokenValue2, GRANTED_SCOPES_STRING, additionalParameters);

    TokenStore tokenStore = new MemoryTokensStorage();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .setHttpTransportFactory(transportFactory)
            .build();

    // Verify that the additional parameters are not attached to the post body when not specified
    UserCredentials credentials = authorizer.getCredentialsFromCode(CODE, BASE_URI);
    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(ACCESS_TOKEN_VALUE, credentials.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials.getAccessToken().getScopes());

    // Verify that the additional parameters are attached to the post body when specified
    credentials = authorizer.getCredentialsFromCode(code2, BASE_URI, additionalParameters);
    assertEquals(refreshToken2, credentials.getRefreshToken());
    assertEquals(accessTokenValue2, credentials.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials.getAccessToken().getScopes());

    // Verify that the additional parameters from previous request are not attached to the post body
    credentials = authorizer.getCredentialsFromCode(CODE, BASE_URI);
    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(ACCESS_TOKEN_VALUE, credentials.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials.getAccessToken().getScopes());
  }

  @Test(expected = NullPointerException.class)
  public void getCredentialsFromCode_nullCode_throws() throws IOException {
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .build();

    authorizer.getCredentialsFromCode(null, BASE_URI);
  }

  @Test
  public void getAndStoreCredentialsFromCode_getAndStoresCredentials() throws IOException {
    final String accessTokenValue1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessTokenValue2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addAuthorizationCode(
        CODE, REFRESH_TOKEN, accessTokenValue1, GRANTED_SCOPES_STRING, null);
    TokenStore tokenStore = new MemoryTokensStorage();
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .setHttpTransportFactory(transportFactory)
            .build();

    UserCredentials credentials1 =
        authorizer.getAndStoreCredentialsFromCode(USER_ID, CODE, BASE_URI);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(GRANTED_SCOPES, credentials1.getAccessToken().getScopes());
    assertEquals(accessTokenValue1, credentials1.getAccessToken().getTokenValue());

    // Refresh the token to get update from token server
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessTokenValue2);
    credentials1.refresh();
    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue2, credentials1.getAccessToken().getTokenValue());

    // Load a second credentials instance
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);

    // Verify that token refresh stored the updated tokens
    assertEquals(REFRESH_TOKEN, credentials2.getRefreshToken());
    assertEquals(GRANTED_SCOPES, credentials2.getAccessToken().getScopes());
    assertEquals(accessTokenValue2, credentials2.getAccessToken().getTokenValue());
  }

  @Test(expected = NullPointerException.class)
  public void getAndStoreCredentialsFromCode_nullCode_throws() throws IOException {
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .build();

    authorizer.getAndStoreCredentialsFromCode(USER_ID, null, BASE_URI);
  }

  @Test(expected = NullPointerException.class)
  public void getAndStoreCredentialsFromCode_nullUserId_throws() throws IOException {
    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .build();

    authorizer.getAndStoreCredentialsFromCode(null, CODE, BASE_URI);
  }

  @Test
  public void revokeAuthorization_revokesAndClears() throws IOException {
    TokenStore tokenStore = new MemoryTokensStorage();
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(
        REFRESH_TOKEN, ACCESS_TOKEN_VALUE, GRANTED_SCOPES_STRING);
    UserCredentials initialCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID_VALUE)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(ACCESS_TOKEN)
            .build();

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(tokenStore)
            .setHttpTransportFactory(transportFactory)
            .build();

    authorizer.storeCredentials(USER_ID, initialCredentials);

    UserCredentials credentials1 = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    credentials1.refresh();
    assertEquals(ACCESS_TOKEN_VALUE, credentials1.getAccessToken().getTokenValue());
    assertEquals(GRANTED_SCOPES, credentials1.getAccessToken().getScopes());

    authorizer.revokeAuthorization(USER_ID);

    try {
      credentials1.refresh();
      fail("Credentials should not refresh after revoke.");
    } catch (IOException expected) {
      // Expected
    }
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);
    assertNull(credentials2);
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullCodeVerifierPKCEProvider() {
    PKCEProvider pkce =
        new PKCEProvider() {
          @Override
          public String getCodeVerifier() {
            return null;
          }

          @Override
          public String getCodeChallengeMethod() {
            return "dummy string";
          }

          @Override
          public String getCodeChallenge() {
            return "dummy string";
          }
        };

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .setPKCEProvider(pkce)
            .build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullCodeChallengePKCEProvider() {
    PKCEProvider pkce =
        new PKCEProvider() {
          @Override
          public String getCodeVerifier() {
            return "dummy string";
          }

          @Override
          public String getCodeChallengeMethod() {
            return "dummy string";
          }

          @Override
          public String getCodeChallenge() {
            return null;
          }
        };

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .setPKCEProvider(pkce)
            .build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullCodeChallengeMethodPKCEProvider() {
    PKCEProvider pkce =
        new PKCEProvider() {
          @Override
          public String getCodeVerifier() {
            return "dummy string";
          }

          @Override
          public String getCodeChallengeMethod() {
            return null;
          }

          @Override
          public String getCodeChallenge() {
            return "dummy string";
          }
        };

    UserAuthorizer authorizer =
        UserAuthorizer.newBuilder()
            .setClientId(CLIENT_ID)
            .setScopes(DUMMY_SCOPES)
            .setTokenStore(new MemoryTokensStorage())
            .setPKCEProvider(pkce)
            .build();
  }
}
