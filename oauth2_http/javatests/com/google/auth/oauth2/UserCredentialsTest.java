package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.http.AuthHttpConstants;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Test case for {@link UserCredentials}.
 */
@RunWith(JUnit4.class)
public class UserCredentialsTest extends BaseSerializationTest {

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
  public void constructor_storesRefreshToken() {
    UserCredentials credentials =
        new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null);
    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
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
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    GenericJson json = writeUserJson(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);

    GoogleCredentials credentials = UserCredentials.fromJson(json, transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_initialToken_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, null, accessToken, transportFactory, null);

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_initialTokenRefreshed_throws() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, null, accessToken, transportFactory, null);

    try {
      userCredentials.refresh();
      fail("Should not be able to refresh without refresh token.");
    } catch (IllegalStateException expected) {
      // expected
    }
  }

  @Test
  public void getRequestMetadata_fromRefreshToken_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transportFactory, null);

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_customTokenServer_hasAccessToken() throws IOException {
    final URI TOKEN_SERVER = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    transportFactory.transport.setTokenServerUri(TOKEN_SERVER);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transportFactory, TOKEN_SERVER);

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void equals_true() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    OAuth2Credentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, accessToken, transportFactory, tokenServer);
    OAuth2Credentials otherCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, accessToken, transportFactory, tokenServer);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    final URI tokenServer2 = URI.create("https://foo2.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    AccessToken otherAccessToken = new AccessToken("otherAccessToken", null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, httpTransportFactory, tokenServer1);
    OAuth2Credentials otherCredentials = new UserCredentials("otherClientId", CLIENT_SECRET,
        REFRESH_TOKEN, accessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = new UserCredentials(CLIENT_ID, "otherClientSecret", REFRESH_TOKEN,
        accessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, "otherRefreshToken",
        accessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        otherAccessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, serverTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, httpTransportFactory, tokenServer2);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, transportFactory, tokenServer);
    String expectedToString = String.format(
        "UserCredentials{requestMetadata=%s, temporaryAccess=%s, clientId=%s, refreshToken=%s, "
            + "tokenServerUri=%s, transportFactoryClassName=%s}",
        ImmutableMap.of(AuthHttpConstants.AUTHORIZATION,
            ImmutableList.of(OAuth2Utils.BEARER_PREFIX + accessToken.getTokenValue())),
        accessToken.toString(),
        CLIENT_ID,
        REFRESH_TOKEN,
        tokenServer,
        MockTokenServerTransportFactory.class.getName());
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    OAuth2Credentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, accessToken, transportFactory, tokenServer);
    OAuth2Credentials otherCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, accessToken, transportFactory, tokenServer);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void hashCode_notEquals() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    final URI tokenServer2 = URI.create("https://foo2.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    AccessToken otherAccessToken = new AccessToken("otherAccessToken", null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, httpTransportFactory, tokenServer1);
    OAuth2Credentials otherCredentials = new UserCredentials("otherClientId", CLIENT_SECRET,
        REFRESH_TOKEN, accessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = new UserCredentials(CLIENT_ID, "otherClientSecret", REFRESH_TOKEN,
        accessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, "otherRefreshToken",
        accessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        otherAccessToken, httpTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, serverTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN,
        accessToken, httpTransportFactory, tokenServer2);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    UserCredentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, accessToken, transportFactory, tokenServer);
    UserCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
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
