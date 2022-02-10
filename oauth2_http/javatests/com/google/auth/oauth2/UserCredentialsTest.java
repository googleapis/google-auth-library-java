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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.google.api.client.json.GenericJson;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.client.util.Clock;
import com.google.auth.RequestMetadataCallback;
import com.google.auth.TestUtils;
import com.google.auth.http.AuthHttpConstants;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

/** Test case for {@link UserCredentials}. */
class UserCredentialsTest extends BaseSerializationTest {

  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final String QUOTA_PROJECT = "sample-quota-project-id";
  private static final Collection<String> SCOPES = Collections.singletonList("dummy.scope");
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  public static final String DEFAULT_ID_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOGI3OTIyO"
          + "TNhZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiL"
          + "CJhenAiOiIxMDIxMDE1NTA4MzQyMDA3MDg1NjgiLCJleHAiOjE1NjQ0NzUwNTEsImlhdCI6MTU2NDQ3MTQ1MSwi"
          + "aXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTAyMTAxNTUwODM0MjAwNzA4NTY4In0"
          + ".redacted";

  @Test
  void constructor_accessAndRefreshTokenNull_throws() {
    assertThrows(
        IllegalStateException.class,
        () ->
            UserCredentials.newBuilder()
                .setClientId(CLIENT_ID)
                .setClientSecret(CLIENT_SECRET)
                .build());
  }

  @Test
  void constructor() {
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();
    assertEquals(CLIENT_ID, credentials.getClientId());
    assertEquals(CLIENT_SECRET, credentials.getClientSecret());
    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(QUOTA_PROJECT, credentials.getQuotaProjectId());
  }

  @Test
  void createScoped_same() {
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();
    assertSame(userCredentials, userCredentials.createScoped(SCOPES));
  }

  @Test
  void createScopedRequired_false() {
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();
    assertFalse(userCredentials.createScopedRequired());
  }

  @Test
  void fromJson_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    GenericJson json = writeUserJson(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null);

    GoogleCredentials credentials = UserCredentials.fromJson(json, transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void fromJson_hasQuotaProjectId() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    GenericJson json = writeUserJson(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    GoogleCredentials credentials = UserCredentials.fromJson(json, transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    assertTrue(metadata.containsKey(GoogleCredentials.QUOTA_PROJECT_ID_HEADER_KEY));
    assertEquals(
        metadata.get(GoogleCredentials.QUOTA_PROJECT_ID_HEADER_KEY),
        Collections.singletonList(QUOTA_PROJECT));
  }

  @Test
  void getRequestMetadata_initialToken_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .build();

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void getRequestMetadata_initialTokenRefreshed_throws() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .build();

    assertThrows(
        IllegalStateException.class,
        userCredentials::refresh,
        "Should not be able to refresh without refresh token.");
  }

  @Test
  void getRequestMetadata_fromRefreshToken_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void getRequestMetadata_customTokenServer_hasAccessToken() throws IOException {
    final URI TOKEN_SERVER = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    transportFactory.transport.setTokenServerUri(TOKEN_SERVER);
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(TOKEN_SERVER)
            .build();

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void equals_true() {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServer)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServer)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_clientId() {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId("other client id")
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_clientSecret() {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret("other client secret")
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_refreshToken() {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    OAuth2Credentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    OAuth2Credentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken("otherRefreshToken")
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_accessToken() {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    AccessToken otherAccessToken = new AccessToken("otherAccessToken", null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(otherAccessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_transportFactory() {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(serverTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_tokenServer() {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    final URI tokenServer2 = URI.create("https://foo2.com/bar");
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer1)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setTokenServerUri(tokenServer2)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void equals_false_quotaProjectId() {
    final String quotaProject1 = "sample-id-1";
    final String quotaProject2 = "sample-id-2";
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setQuotaProjectId(quotaProject1)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(httpTransportFactory)
            .setQuotaProjectId(quotaProject2)
            .build();
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  void toString_containsFields() {
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServer)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();

    String expectedToString =
        String.format(
            "UserCredentials{requestMetadata=%s, temporaryAccess=%s, clientId=%s, refreshToken=%s, "
                + "tokenServerUri=%s, transportFactoryClassName=%s, quotaProjectId=%s}",
            ImmutableMap.of(
                AuthHttpConstants.AUTHORIZATION,
                ImmutableList.of(OAuth2Utils.BEARER_PREFIX + accessToken.getTokenValue())),
            accessToken.toString(),
            CLIENT_ID,
            REFRESH_TOKEN,
            tokenServer,
            MockTokenServerTransportFactory.class.getName(),
            QUOTA_PROJECT);
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  void hashCode_equals() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServer)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();
    UserCredentials otherCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServer)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  void serialize() throws IOException, ClassNotFoundException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    AccessToken accessToken = new AccessToken(ACCESS_TOKEN, null);
    UserCredentials credentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setAccessToken(accessToken)
            .setHttpTransportFactory(transportFactory)
            .setTokenServerUri(tokenServer)
            .build();
    UserCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  @Test
  void fromStream_nullTransport_throws() throws IOException {
    InputStream stream = new ByteArrayInputStream("foo".getBytes());
    assertThrows(
        NullPointerException.class,
        () -> UserCredentials.fromStream(stream, null),
        "Should throw if HttpTransportFactory is null");
  }

  @Test
  void fromStream_nullStream_throws() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    assertThrows(
        NullPointerException.class,
        () -> UserCredentials.fromStream(null, transportFactory),
        "Should throw if InputStream is null");
  }

  @Test
  void fromStream_user_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    InputStream userStream =
        writeUserStream(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    UserCredentials credentials = UserCredentials.fromStream(userStream, transportFactory);

    assertNotNull(credentials);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void fromStream_userNoClientId_throws() throws IOException {
    InputStream userStream = writeUserStream(null, CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_id");
  }

  @Test
  void fromStream_userNoClientSecret_throws() throws IOException {
    InputStream userStream = writeUserStream(CLIENT_ID, null, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_secret");
  }

  @Test
  void fromStream_userNoRefreshToken_throws() throws IOException {
    InputStream userStream = writeUserStream(CLIENT_ID, CLIENT_SECRET, null, QUOTA_PROJECT);

    testFromStreamException(userStream, "refresh_token");
  }

  @Test
  void saveUserCredentials_saved_throws() throws IOException {
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();
    File file = File.createTempFile("GOOGLE_APPLICATION_CREDENTIALS", null, null);
    file.deleteOnExit();

    String filePath = file.getAbsolutePath();
    userCredentials.save(filePath);
  }

  @Test
  void saveAndRestoreUserCredential_saveAndRestored_throws() throws IOException {
    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .build();

    File file = File.createTempFile("GOOGLE_APPLICATION_CREDENTIALS", null, null);
    file.deleteOnExit();

    String filePath = file.getAbsolutePath();

    userCredentials.save(filePath);

    FileInputStream inputStream = new FileInputStream(new File(filePath));

    UserCredentials restoredCredentials = UserCredentials.fromStream(inputStream);

    assertEquals(userCredentials.getClientId(), restoredCredentials.getClientId());
    assertEquals(userCredentials.getClientSecret(), restoredCredentials.getClientSecret());
    assertEquals(userCredentials.getRefreshToken(), restoredCredentials.getRefreshToken());
  }

  @Test
  void getRequestMetadataSetsQuotaProjectId() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);

    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setQuotaProjectId("my-quota-project-id")
            .setHttpTransportFactory(transportFactory)
            .build();

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata();
    assertTrue(metadata.containsKey("x-goog-user-project"));
    List<String> headerValues = metadata.get("x-goog-user-project");
    assertEquals(1, headerValues.size());
    assertEquals("my-quota-project-id", headerValues.get(0));
  }

  @Test
  void getRequestMetadataNoQuotaProjectId() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);

    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setHttpTransportFactory(transportFactory)
            .build();

    Map<String, List<String>> metadata = userCredentials.getRequestMetadata();
    assertFalse(metadata.containsKey("x-goog-user-project"));
  }

  @Test
  void getRequestMetadataWithCallback() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);

    UserCredentials userCredentials =
        UserCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientSecret(CLIENT_SECRET)
            .setRefreshToken(REFRESH_TOKEN)
            .setQuotaProjectId("my-quota-project-id")
            .setHttpTransportFactory(transportFactory)
            .build();
    final Map<String, List<String>> plainMetadata = userCredentials.getRequestMetadata();
    final AtomicBoolean success = new AtomicBoolean(false);
    userCredentials.getRequestMetadata(
        null,
        null,
        new RequestMetadataCallback() {
          @Override
          public void onSuccess(Map<String, List<String>> metadata) {
            assertEquals(plainMetadata, metadata);
            success.set(true);
          }

          @Override
          public void onFailure(Throwable exception) {
            fail("Should not throw a failure.");
          }
        });

    assertTrue(success.get(), "Should have run onSuccess() callback");
  }

  @Test
  void IdTokenCredentials_WithUserEmailScope_success() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    String refreshToken = MockTokenServerTransport.REFRESH_TOKEN_WITH_USER_SCOPE;

    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(refreshToken, ACCESS_TOKEN);
    InputStream userStream = writeUserStream(CLIENT_ID, CLIENT_SECRET, refreshToken, QUOTA_PROJECT);

    UserCredentials credentials = UserCredentials.fromStream(userStream, transportFactory);
    credentials.refresh();

    assertEquals(ACCESS_TOKEN, credentials.getAccessToken().getTokenValue());

    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder().setIdTokenProvider(credentials).build();

    assertNull(tokenCredential.getAccessToken());
    assertNull(tokenCredential.getIdToken());

    // trigger the refresh like it would happen during a request build
    tokenCredential.getRequestMetadata();

    assertEquals(DEFAULT_ID_TOKEN, tokenCredential.getAccessToken().getTokenValue());
    assertEquals(DEFAULT_ID_TOKEN, tokenCredential.getIdToken().getTokenValue());
  }

  @Test
  void IdTokenCredentials_NoRetry_RetryableStatus_throws() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    String refreshToken = MockTokenServerTransport.REFRESH_TOKEN_WITH_USER_SCOPE;

    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(refreshToken, ACCESS_TOKEN);
    InputStream userStream = writeUserStream(CLIENT_ID, CLIENT_SECRET, refreshToken, QUOTA_PROJECT);

    MockLowLevelHttpResponse response408 = new MockLowLevelHttpResponse().setStatusCode(408);
    MockLowLevelHttpResponse response429 = new MockLowLevelHttpResponse().setStatusCode(429);

    UserCredentials credentials = UserCredentials.fromStream(userStream, transportFactory);

    GoogleAuthException ex =
        assertThrows(
            GoogleAuthException.class,
            () -> {
              transportFactory.transport.addResponseSequence(response408, response429);
              credentials.refresh();
            },
            "Should not retry");

    assertTrue(ex.getMessage().contains("com.google.api.client.http.HttpResponseException: 408"));
    assertTrue(ex.isRetryable());
    assertEquals(0, ex.getRetryCount());

    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder().setIdTokenProvider(credentials).build();

    assertNull(tokenCredential.getAccessToken());
    assertNull(tokenCredential.getIdToken());

    // trigger the refresh like it would happen during a request build
    ex =
        assertThrows(
            GoogleAuthException.class,
            () -> {
              tokenCredential.getRequestMetadata();
            },
            "Should not retry");

    assertTrue(ex.getMessage().contains("com.google.api.client.http.HttpResponseException: 429"));
    assertTrue(ex.isRetryable());
    assertEquals(0, ex.getRetryCount());
  }

  @Test
  void refreshAccessToken_4xx_5xx_NonRetryableFails() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    String refreshToken = MockTokenServerTransport.REFRESH_TOKEN_WITH_USER_SCOPE;

    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(refreshToken, ACCESS_TOKEN);
    InputStream userStream = writeUserStream(CLIENT_ID, CLIENT_SECRET, refreshToken, QUOTA_PROJECT);

    UserCredentials credentials = UserCredentials.fromStream(userStream, transportFactory);

    for (int status = 400; status < 600; status++) {
      if (OAuth2Utils.TOKEN_ENDPOINT_RETRYABLE_STATUS_CODES.contains(status)) {
        continue;
      }

      MockLowLevelHttpResponse mockResponse = new MockLowLevelHttpResponse().setStatusCode(status);
      GoogleAuthException ex =
          assertThrows(
              GoogleAuthException.class,
              () -> {
                transportFactory.transport.addResponseSequence(mockResponse);
                credentials.refresh();
              },
              "Should not retry status " + status);
      assertFalse(ex.isRetryable());
      assertEquals(0, ex.getRetryCount());
    }
  }

  @Test
  void IdTokenCredentials_NoUserEmailScope_throws() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    InputStream userStream =
        writeUserStream(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    UserCredentials credentials = UserCredentials.fromStream(userStream, transportFactory);

    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder().setIdTokenProvider(credentials).build();

    String expectedMessageContent =
        "UserCredentials can obtain an id token only when authenticated through"
            + " gcloud running 'gcloud auth login --update-adc' or 'gcloud auth application-default"
            + " login'. The latter form would not work for Cloud Run, but would still generate an"
            + " id token.";

    IOException exception = assertThrows(IOException.class, tokenCredential::refresh);
    assertTrue(exception.getMessage().equals(expectedMessageContent));
  }

  static GenericJson writeUserJson(
      String clientId, String clientSecret, String refreshToken, String quotaProjectId) {
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
    if (quotaProjectId != null) {
      json.put("quota_project_id", quotaProjectId);
    }
    json.put("type", GoogleCredentials.USER_FILE_TYPE);
    return json;
  }

  static InputStream writeUserStream(
      String clientId, String clientSecret, String refreshToken, String quotaProjectId)
      throws IOException {
    GenericJson json = writeUserJson(clientId, clientSecret, refreshToken, quotaProjectId);
    return TestUtils.jsonToInputStream(json);
  }

  private static void testFromStreamException(InputStream stream, String expectedMessageContent) {
    IOException exception =
        assertThrows(
            IOException.class,
            () -> UserCredentials.fromStream(stream),
            String.format(
                "Should throw exception with message containing '%s'", expectedMessageContent));
    assertTrue(exception.getMessage().contains(expectedMessageContent));
  }
}
