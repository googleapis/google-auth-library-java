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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentialsTest.MockExternalAccountCredentialsTransportFactory;
import com.google.auth.oauth2.ImpersonatedCredentialsTest.MockIAMCredentialsServiceTransportFactory;
import com.google.common.collect.ImmutableList;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** Test case for {@link GoogleCredentials}. */
public class GoogleCredentialsTest {

  private static final String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private static final String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private static final String SA_PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private static final String SA_PRIVATE_KEY_PKCS8 =
      ServiceAccountCredentialsTest.PRIVATE_KEY_PKCS8;
  private static final String USER_CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String USER_CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final HttpTransportFactory DUMMY_TRANSPORT_FACTORY =
      new MockTokenServerTransportFactory();
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  private static final String QUOTA_PROJECT = "sample-quota-project-id";

  private static final Collection<String> SCOPES =
      Collections.unmodifiableCollection(Arrays.asList("scope1", "scope2"));
  private static final Collection<String> DEFAULT_SCOPES =
      Collections.unmodifiableCollection(Arrays.asList("scope3"));

  static class MockHttpTransportFactory implements HttpTransportFactory {

    MockHttpTransport transport = new MockHttpTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  public static class MockTokenServerTransportFactory implements HttpTransportFactory {

    public MockTokenServerTransport transport = new MockTokenServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  void getApplicationDefault_nullTransport_throws() {
    assertThrows(NullPointerException.class, () -> GoogleCredentials.getApplicationDefault(null));
  }

  @Test
  void fromStream_nullTransport_throws() {
    InputStream stream = new ByteArrayInputStream("foo".getBytes());
    assertThrows(
        NullPointerException.class,
        () -> GoogleCredentials.fromStream(stream, null),
        "Should throw if HttpTransportFactory is null");
  }

  @Test
  void fromStream_nullStream_throws() {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    assertThrows(
        NullPointerException.class,
        () -> GoogleCredentials.fromStream(null, transportFactory),
        "Should throw if InputStream is null");
  }

  @Test
  void fromStream_serviceAccount_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(serviceAccountStream, transportFactory);

    assertNotNull(credentials);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);

    credentials = credentials.createScoped(SCOPES, DEFAULT_SCOPES);
    metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void fromStream_serviceAccountNoClientId_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            null, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_id");
  }

  @Test
  void fromStream_serviceAccountNoClientEmail_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, null, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_email");
  }

  @Test
  void fromStream_serviceAccountNoPrivateKey_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, null, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "private_key");
  }

  @Test
  void fromStream_serviceAccountNoPrivateKeyId_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, null);

    testFromStreamException(serviceAccountStream, "private_key_id");
  }

  @Test
  void fromStream_user_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(USER_CLIENT_ID, USER_CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, null);

    GoogleCredentials credentials = GoogleCredentials.fromStream(userStream, transportFactory);

    assertNotNull(credentials);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  void fromStream_userNoClientId_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(null, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_id");
  }

  @Test
  void fromStream_userNoClientSecret_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, null, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_secret");
  }

  @Test
  void fromStream_userNoRefreshToken_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, null, QUOTA_PROJECT);

    testFromStreamException(userStream, "refresh_token");
  }

  @Test
  void fromStream_identityPoolCredentials_providesToken() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    InputStream identityPoolCredentialStream =
        IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
            transportFactory.transport.getStsUrl(),
            transportFactory.transport.getMetadataUrl(),
            /* serviceAccountImpersonationUrl= */ null);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(identityPoolCredentialStream, transportFactory);

    assertNotNull(credentials);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, transportFactory.transport.getAccessToken());
  }

  @Test
  void fromStream_awsCredentials_providesToken() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    InputStream awsCredentialStream =
        AwsCredentialsTest.writeAwsCredentialsStream(
            transportFactory.transport.getStsUrl(),
            transportFactory.transport.getAwsRegionUrl(),
            transportFactory.transport.getAwsCredentialsUrl());

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(awsCredentialStream, transportFactory);

    assertNotNull(credentials);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, transportFactory.transport.getAccessToken());
  }

  @Test
  void fromStream_Impersonation_providesToken_WithQuotaProject() throws IOException {
    MockTokenServerTransportFactory transportFactoryForSource =
        new MockTokenServerTransportFactory();
    transportFactoryForSource.transport.addServiceAccount(
        ImpersonatedCredentialsTest.SA_CLIENT_EMAIL, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    MockIAMCredentialsServiceTransportFactory transportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setTargetPrincipal(
        ImpersonatedCredentialsTest.IMPERSONATED_CLIENT_EMAIL);
    transportFactory.transport.setAccessToken(ImpersonatedCredentialsTest.ACCESS_TOKEN);
    transportFactory.transport.setExpireTime(ImpersonatedCredentialsTest.getDefaultExpireTime());
    transportFactory.transport.setAccessTokenEndpoint(
        ImpersonatedCredentialsTest.IMPERSONATION_URL);

    InputStream impersonationCredentialsStream =
        ImpersonatedCredentialsTest.writeImpersonationCredentialsStream(
            ImpersonatedCredentialsTest.IMPERSONATION_URL,
            ImpersonatedCredentialsTest.DELEGATES,
            ImpersonatedCredentialsTest.QUOTA_PROJECT_ID);

    ImpersonatedCredentials credentials =
        (ImpersonatedCredentials)
            GoogleCredentials.fromStream(impersonationCredentialsStream, transportFactoryForSource);
    credentials.setTransportFactory(transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    assertTrue(metadata.containsKey("x-goog-user-project"));
    List<String> headerValues = metadata.get("x-goog-user-project");
    assertEquals(1, headerValues.size());
    assertEquals(ImpersonatedCredentialsTest.QUOTA_PROJECT_ID, headerValues.get(0));
  }

  @Test
  void fromStream_Impersonation_providesToken_WithoutQuotaProject() throws IOException {
    MockTokenServerTransportFactory transportFactoryForSource =
        new MockTokenServerTransportFactory();
    transportFactoryForSource.transport.addServiceAccount(
        ImpersonatedCredentialsTest.SA_CLIENT_EMAIL, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    MockIAMCredentialsServiceTransportFactory transportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    transportFactory.transport.setTargetPrincipal(
        ImpersonatedCredentialsTest.IMPERSONATED_CLIENT_EMAIL);
    transportFactory.transport.setAccessToken(ImpersonatedCredentialsTest.ACCESS_TOKEN);
    transportFactory.transport.setExpireTime(ImpersonatedCredentialsTest.getDefaultExpireTime());
    transportFactory.transport.setAccessTokenEndpoint(
        ImpersonatedCredentialsTest.IMPERSONATION_URL);

    InputStream impersonationCredentialsStream =
        ImpersonatedCredentialsTest.writeImpersonationCredentialsStream(
            ImpersonatedCredentialsTest.IMPERSONATION_URL,
            ImpersonatedCredentialsTest.DELEGATES,
            null);

    ImpersonatedCredentials credentials =
        (ImpersonatedCredentials)
            GoogleCredentials.fromStream(impersonationCredentialsStream, transportFactoryForSource);
    credentials.setTransportFactory(transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    assertFalse(metadata.containsKey("x-goog-user-project"));
  }

  @Test
  void createScoped_overloadCallsImplementation() {
    final AtomicReference<Collection<String>> called = new AtomicReference<>();
    final GoogleCredentials expectedScopedCredentials = new GoogleCredentials();

    GoogleCredentials credentials =
        new GoogleCredentials() {
          @Override
          public GoogleCredentials createScoped(Collection<String> scopes) {
            called.set(scopes);
            return expectedScopedCredentials;
          }
        };

    GoogleCredentials scopedCredentials = credentials.createScoped("foo", "bar");

    assertEquals(expectedScopedCredentials, scopedCredentials);
    assertEquals(ImmutableList.of("foo", "bar"), called.get());
  }

  private static void testFromStreamException(InputStream stream, String expectedMessageContent) {
    IOException exception =
        assertThrows(
            IOException.class,
            () -> GoogleCredentials.fromStream(stream, DUMMY_TRANSPORT_FACTORY),
            String.format(
                "Should throw exception with message containing '%s'", expectedMessageContent));
    assertTrue(exception.getMessage().contains(expectedMessageContent));
  }
}
