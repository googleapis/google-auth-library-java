package com.google.auth.oauth2;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import com.google.auth.TestClock;
import com.google.auth.TestUtils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.List;

/**
 * Test case for {@link OAuth2Credentials}.
 */
@RunWith(JUnit4.class)
public class OAuth2CredentialsTest {

  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "aashpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  @Test
  public void constructor_storesAccessToken() {
    OAuth2Credentials credentials = new OAuth2Credentials(new AccessToken(ACCESS_TOKEN, null));

    assertEquals(credentials.getAccessToken().getTokenValue(), ACCESS_TOKEN);
  }

  @Test
  public void getAuthenticationType_returnsOAuth2() {
    OAuth2Credentials credentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);
    assertEquals(credentials.getAuthenticationType(), "OAuth2");
  }

  @Test
  public void hasRequestMetadata_returnsTrue() {
    OAuth2Credentials credentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);
    assertTrue(credentials.hasRequestMetadata());
  }

  @Test
  public void hasRequestMetadataOnly_returnsTrue() {
    OAuth2Credentials credentials = new UserCredentials(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN);
    assertTrue(credentials.hasRequestMetadata());
  }

  @Test
  public void addaddChangeListener_notifiesOnRefresh() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transport, null);
    // Use a fixed clock so tokens don't expire
    userCredentials.clock = new TestClock();
    TestChangeListener listener = new TestChangeListener();
    userCredentials.addChangeListener(listener);
    Map<String, List<String>> metadata;
    assertEquals(0, listener.callCount);

    // Get a first token
    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);
    assertEquals(accessToken1, listener.accessToken.getTokenValue());
    assertEquals(1, listener.callCount);

    // Change server to a different token and refresh
    transport.addRefreshToken(REFRESH_TOKEN, accessToken2);
    // Refresh to force getting next token
    userCredentials.refresh();

    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);
    assertEquals(accessToken2, listener.accessToken.getTokenValue());
    assertEquals(2, listener.callCount);
  }

  @Test
  public void getRequestMetadata_cachesExpiringToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    TestClock clock = new TestClock();
    OAuth2Credentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transport, null);
    credentials.clock = clock;

    // Verify getting the first token
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);

    // Change server to a different token
    transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    // Advance 5 minutes and verify original token
    clock.addToCurrentTime(5 * 60 * 1000);
    metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);

    // Advance 60 minutes and verify revised token
    clock.addToCurrentTime(60 * 60 * 1000);
    metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);
  }

  @Test
  public void getRequestMetadata_temporaryToken_hasToken() throws IOException {
    OAuth2Credentials credentials = new OAuth2Credentials(new AccessToken(ACCESS_TOKEN, null));

    // Verify getting the first token
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void refresh_refreshesToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    OAuth2Credentials userCredentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transport, null);
    // Use a fixed clock so tokens don't exire
    userCredentials.clock = new TestClock();

    // Get a first token
    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);

    // Change server to a different token
    transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    // Confirm token being cached
    TestUtils.assertContainsBearerToken(metadata, accessToken1);

    // Refresh to force getting next token
    userCredentials.refresh();
    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);
  }

  @Test(expected = IllegalStateException.class)
  public void refresh_temporaryToken_throws() throws IOException {
    OAuth2Credentials credentials = new OAuth2Credentials(new AccessToken(ACCESS_TOKEN, null));
    credentials.refresh();
  }

  private static class TestChangeListener implements OAuth2Credentials.CredentialsChangedListener {

    public AccessToken accessToken = null;
    public int callCount = 0;
    @Override
    public void onChanged(OAuth2Credentials credentials) throws IOException {
      accessToken = credentials.getAccessToken();
      callCount++;
    }
  }
}
