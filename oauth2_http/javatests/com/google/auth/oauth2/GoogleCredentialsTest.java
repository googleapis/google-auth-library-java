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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link GoogleCredentials}. */
@RunWith(JUnit4.class)
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
  public void getApplicationDefault_nullTransport_throws() throws IOException {
    try {
      GoogleCredentials.getApplicationDefault(null);
      fail();
    } catch (NullPointerException expected) {
      // Expected
    }
  }

  @Test
  public void fromStream_nullTransport_throws() throws IOException {
    InputStream stream = new ByteArrayInputStream("foo".getBytes());
    try {
      GoogleCredentials.fromStream(stream, null);
      fail("Should throw if HttpTransportFactory is null");
    } catch (NullPointerException expected) {
      // Expected
    }
  }

  @Test
  public void fromStream_nullStream_throws() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    try {
      GoogleCredentials.fromStream(null, transportFactory);
      fail("Should throw if InputStream is null");
    } catch (NullPointerException expected) {
      // Expected
    }
  }

  @Test
  public void fromStream_serviceAccount_providesToken() throws IOException {
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
  }

  @Test
  public void fromStream_serviceAccountNoClientId_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            null, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_id");
  }

  @Test
  public void fromStream_serviceAccountNoClientEmail_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, null, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_email");
  }

  @Test
  public void fromStream_serviceAccountNoPrivateKey_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, null, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "private_key");
  }

  @Test
  public void fromStream_serviceAccountNoPrivateKeyId_throws() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, null);

    testFromStreamException(serviceAccountStream, "private_key_id");
  }

  @Test
  public void fromStream_user_providesToken() throws IOException {
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
  public void fromStream_userNoClientId_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(null, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_id");
  }

  @Test
  public void fromStream_userNoClientSecret_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, null, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_secret");
  }

  @Test
  public void fromStream_userNoRefreshToken_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, null, QUOTA_PROJECT);

    testFromStreamException(userStream, "refresh_token");
  }

  @Test
  public void createScoped_overloadCallsImplementation() {
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
    try {
      GoogleCredentials.fromStream(stream, DUMMY_TRANSPORT_FACTORY);
      fail(
          String.format(
              "Should throw exception with message containing '%s'", expectedMessageContent));
    } catch (IOException expected) {
      assertTrue(expected.getMessage().contains(expectedMessageContent));
    }
  }
}
