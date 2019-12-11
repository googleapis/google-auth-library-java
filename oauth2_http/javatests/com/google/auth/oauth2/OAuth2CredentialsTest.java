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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.util.Clock;
import com.google.auth.TestClock;
import com.google.auth.TestUtils;
import com.google.auth.http.AuthHttpConstants;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link OAuth2Credentials}. */
@RunWith(JUnit4.class)
public class OAuth2CredentialsTest extends BaseSerializationTest {

  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "aashpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  @Test
  public void constructor_storesAccessToken() {
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(ACCESS_TOKEN, null)).build();
    assertEquals(credentials.getAccessToken().getTokenValue(), ACCESS_TOKEN);
  }

  @Test
  public void getAuthenticationType_returnsOAuth2() {
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();
    assertEquals(credentials.getAuthenticationType(), "OAuth2");
  }

  @Test
  public void hasRequestMetadata_returnsTrue() {
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();
    assertTrue(credentials.hasRequestMetadata());
  }

  @Test
  public void hasRequestMetadataOnly_returnsTrue() {
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();
    assertTrue(credentials.hasRequestMetadata());
  }

  @Test
  public void addChangeListener_notifiesOnRefresh() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    OAuth2Credentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
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
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);
    // Refresh to force getting next token
    userCredentials.refresh();

    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);
    assertEquals(accessToken2, listener.accessToken.getTokenValue());
    assertEquals(2, listener.callCount);
  }

  @Test
  public void removeChangeListener_unregisters_observer() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    OAuth2Credentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
    // Use a fixed clock so tokens don't expire
    userCredentials.clock = new TestClock();
    TestChangeListener listener = new TestChangeListener();
    userCredentials.addChangeListener(listener);
    assertEquals(0, listener.callCount);

    // Get a first token
    userCredentials.getRequestMetadata(CALL_URI);
    assertEquals(1, listener.callCount);

    // Change server to a different token and refresh
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);
    // Refresh to force getting next token
    userCredentials.refresh();
    assertEquals(2, listener.callCount);

    // Remove the listener and refresh the credential again
    userCredentials.removeChangeListener(listener);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);
    userCredentials.refresh();
    assertEquals(2, listener.callCount);
  }

  @Test
  public void getRequestMetadata_blocking_cachesExpiringToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    TestClock clock = new TestClock();
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
    credentials.clock = clock;

    // Verify getting the first token
    assertEquals(0, transportFactory.transport.buildRequestCount);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);
    assertEquals(1, transportFactory.transport.buildRequestCount--);

    // Change server to a different token
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    // Make transport fail when used next time.
    IOException error = new IOException("error");
    transportFactory.transport.setError(error);

    // Advance 5 minutes and verify original token
    clock.addToCurrentTime(5 * 60 * 1000);
    metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);

    // Advance 60 minutes and verify revised token
    clock.addToCurrentTime(60 * 60 * 1000);
    assertEquals(0, transportFactory.transport.buildRequestCount);

    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Should throw");
    } catch (IOException e) {
      assertSame(error, e);
      assertEquals(1, transportFactory.transport.buildRequestCount--);
    }

    // Reset the error and try again
    transportFactory.transport.setError(null);
    metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);
    assertEquals(1, transportFactory.transport.buildRequestCount--);
  }

  @Test
  public void getRequestMetadata_async() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    TestClock clock = new TestClock();
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
    credentials.clock = clock;

    MockExecutor executor = new MockExecutor();
    MockRequestMetadataCallback callback = new MockRequestMetadataCallback();
    // Verify getting the first token, which uses the transport and calls the callback in the
    // executor.
    credentials.getRequestMetadata(CALL_URI, executor, callback);
    assertEquals(0, transportFactory.transport.buildRequestCount);
    assertNull(callback.metadata);

    assertEquals(1, executor.runTasksExhaustively());
    assertNotNull(callback.metadata);
    TestUtils.assertContainsBearerToken(callback.metadata, accessToken1);
    assertEquals(1, transportFactory.transport.buildRequestCount--);

    // Change server to a different token
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    // Make transport fail when used next time.
    IOException error = new IOException("error");
    transportFactory.transport.setError(error);

    // Advance 5 minutes and verify original token. Callback is called inline.
    callback.reset();
    clock.addToCurrentTime(5 * 60 * 1000);
    assertNull(callback.metadata);
    credentials.getRequestMetadata(CALL_URI, executor, callback);
    assertNotNull(callback.metadata);
    assertEquals(0, executor.numTasks());
    TestUtils.assertContainsBearerToken(callback.metadata, accessToken1);

    // Advance 60 minutes and verify revised token, which uses the executor.
    callback.reset();
    clock.addToCurrentTime(60 * 60 * 1000);
    credentials.getRequestMetadata(CALL_URI, executor, callback);
    assertEquals(0, transportFactory.transport.buildRequestCount);
    assertNull(callback.exception);

    assertEquals(1, executor.runTasksExhaustively());
    assertSame(error, callback.exception);
    assertEquals(1, transportFactory.transport.buildRequestCount--);

    // Reset the error and try again
    transportFactory.transport.setError(null);
    callback.reset();
    credentials.getRequestMetadata(CALL_URI, executor, callback);
    assertEquals(0, transportFactory.transport.buildRequestCount);
    assertNull(callback.metadata);

    assertEquals(1, executor.runTasksExhaustively());
    assertNotNull(callback.metadata);
    TestUtils.assertContainsBearerToken(callback.metadata, accessToken2);
    assertEquals(1, transportFactory.transport.buildRequestCount--);
  }

  @Test
  public void getRequestMetadata_async_refreshRace() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    TestClock clock = new TestClock();
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
    credentials.clock = clock;

    MockExecutor executor = new MockExecutor();
    MockRequestMetadataCallback callback = new MockRequestMetadataCallback();
    // Getting the first token, which uses the transport and calls the callback in the executor.
    credentials.getRequestMetadata(CALL_URI, executor, callback);
    assertEquals(0, transportFactory.transport.buildRequestCount);
    assertNull(callback.metadata);

    // Asynchronous task is scheduled, but beaten by another blocking get call.
    assertEquals(1, executor.numTasks());
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    assertEquals(1, transportFactory.transport.buildRequestCount--);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);

    // When the task is run, the cached data is used.
    assertEquals(1, executor.runTasksExhaustively());
    assertEquals(0, transportFactory.transport.buildRequestCount);
    assertEquals(metadata, callback.metadata);
  }

  @Test
  public void getRequestMetadata_temporaryToken_hasToken() throws IOException {
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(ACCESS_TOKEN, null)).build();

    // Verify getting the first token
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void refresh_refreshesToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    OAuth2Credentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
    // Use a fixed clock so tokens don't expire
    userCredentials.clock = new TestClock();

    // Get a first token
    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);
    assertEquals(1, transportFactory.transport.buildRequestCount--);

    // Change server to a different token
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    // Confirm token being cached
    TestUtils.assertContainsBearerToken(metadata, accessToken1);
    assertEquals(0, transportFactory.transport.buildRequestCount);

    // Refresh to force getting next token
    userCredentials.refresh();
    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);
    assertEquals(1, transportFactory.transport.buildRequestCount--);
  }

  @Test
  public void refreshIfExpired_refreshesToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken1);
    OAuth2Credentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();
    // Use a fixed clock so tokens don't expire
    TestClock mockClock = new TestClock();
    userCredentials.clock = mockClock;

    // Get a first token
    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken1);
    assertEquals(1, transportFactory.transport.buildRequestCount--);

    // Change server to a different token
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    // Confirm token being cached
    TestUtils.assertContainsBearerToken(metadata, accessToken1);
    assertEquals(0, transportFactory.transport.buildRequestCount);

    // Should not refresh yet
    userCredentials.refreshIfExpired();
    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertNotContainsBearerToken(metadata, accessToken2);

    // Jump ahead to expire the token
    mockClock.addToCurrentTime(3600000);
    userCredentials.refreshIfExpired();
    metadata = userCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, accessToken2);

    assertEquals(1, transportFactory.transport.buildRequestCount--);
  }

  @Test(expected = IllegalStateException.class)
  public void refresh_temporaryToken_throws() throws IOException {
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(ACCESS_TOKEN, null)).build();
    credentials.refresh();
  }

  @Test
  public void equals_true() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(accessToken1, null)).build();
    OAuth2Credentials otherCredentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(accessToken1, null)).build();
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_accessToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(accessToken1, null)).build();
    OAuth2Credentials otherCredentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(accessToken2, null)).build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    AccessToken accessToken = new AccessToken("1/MkSJoj1xsli0AccessToken_NKPY2", null);
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(accessToken).build();
    String expectedToString =
        String.format(
            "OAuth2Credentials{requestMetadata=%s, temporaryAccess=%s}",
            ImmutableMap.of(
                AuthHttpConstants.AUTHORIZATION,
                ImmutableList.of(OAuth2Utils.BEARER_PREFIX + accessToken.getTokenValue())),
            accessToken.toString());
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(accessToken, null)).build();
    OAuth2Credentials otherCredentials =
        OAuth2Credentials.create(new AccessToken(accessToken, null));
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    OAuth2Credentials credentials =
        OAuth2Credentials.newBuilder().setAccessToken(new AccessToken(accessToken, null)).build();
    OAuth2Credentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
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
