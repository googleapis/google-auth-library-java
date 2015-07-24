package com.google.auth.oauth2;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Test case for {@link UserCredentials}.
 */
@RunWith(JUnit4.class)
public class UserCredentialsTest {

  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private final static Collection<String> SCOPES = Collections.singletonList("dummy.scope");
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  @Test(expected = IllegalStateException.class)
  public void constructor_accessAndRefreshTokenNull_throws() {
    new UserCredentials(CLIENT_ID, CLIENT_SECRET, null, null);
  }

  @Test
  public void createScoped_same() {
    UserCredentials userCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);
    assertSame(userCredentials, userCredentials.createScoped(SCOPES));
  }

  @Test
  public void createScopedRequired_false() {
    UserCredentials userCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);
    assertFalse(userCredentials.createScopedRequired());
  }

  @Test
  public void fromJson_hasAccessToken() throws IOException {
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    GenericJson json = writeUserJson(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);

    GoogleCredentials credentials = UserCredentials.fromJson(json, transport);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_initialToken_hasAccessToken() throws IOException {
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, null, accessToken, transport, null);

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_initialTokenRefreshed_throws() throws IOException {
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, null, accessToken, transport, null);

    try {
      userCredentials.refresh();
      fail("Should not be able to refresh without refresh token.");
    } catch (IllegalStateException expected) {
    }
  }

  @Test
  public void getRequestMetadata_fromRefreshToken_hasAccessToken() throws IOException {
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transport, null);

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  static GenericJson writeUserJson(String clientId, String clientSecret, String refreshToken) {
    GenericJson json = new GenericJson();
    if (clientId != null) {
      json.put("client_id", clientId);
    }
    if (clientSecret != null) {
      json.put("client_secret", clientSecret);
    }
    if (refreshToken != null) {
      json.put("refresh_token", refreshToken);
    }
    json.put("type", GoogleCredentials.USER_FILE_TYPE);
    return json;
  }

  static InputStream writeUserStream(String clientId, String clientSecret, String refreshToken)
      throws IOException {
    GenericJson json = writeUserJson(clientId, clientSecret, refreshToken);
    InputStream stream = TestUtils.jsonToInputStream(json);
    return stream;
  }
}
