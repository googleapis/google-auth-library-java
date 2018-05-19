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

package com.google.auth.http;

import static org.junit.Assert.assertEquals;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.auth.oauth2.MockTokenCheckingTransport;
import com.google.auth.oauth2.OAuth2Credentials;
import com.google.auth.oauth2.UserCredentials;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;

/**
 * Test case for {@link HttpCredentialsAdapter}.
 */
@RunWith(JUnit4.class)
public class HttpCredentialsAdapterTest {

  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";

  @Test
  public void initialize_populatesOAuth2Credentials() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU0MjViYjg0NjE2ZWJmOTczYWU4MGJjNjJhYzY4OGQyYTcyNzE1YWQifQ.eyJhenAiOiI4ODIwMzQ1NDEwMzctYjM5a3B2OWU4M2d2MmVzNnAyY243bG5lb3E0aHVqMDAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4ODIwMzQ1NDEwMzctYjM5a3B2OWU4M2d2MmVzNnAyY243bG5lb3E0aHVqMDAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDY5NTgzMjUxNzYwMTY0MzYyOTYiLCJoZCI6Im5pYW50aWNsYWJzLmNvbSIsImVtYWlsIjoiYWNhYnJlcmFAbmlhbnRpY2xhYnMuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJzMGVzY1VZc0RMb09UUlptRkRKS0FnIiwibm9uY2UiOiJOMC41MDA5MzE4NDMxMDYzNTYxMTUyNDMyNjU0Nzg2MyIsImV4cCI6MTUyNDMzMDE0OCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwianRpIjoiYTU4Y2JlYjBlNWJkMmUxZDRlY2M3MmQ3MjljOGRlZjViNzdiNDYyMCIsImlhdCI6MTUyNDMyNjU0OCwibmFtZSI6IkFsYW4gQ2FicmVyYSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLTRjTjQ0cUEteUNrL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFjL2p0UUtQcVpDWGRjL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbGFuIiwiZmFtaWx5X25hbWUiOiJDYWJyZXJhIiwibG9jYWxlIjoiZW4ifQ.Ro3ru4YuhPIQqDLIQiGp81Pha1hMVxFfeaeIIrEgZbp9-UG8I6cZEqlhLpOeLCJP3bQk5r9sHAZLUY_eoG-i_OBicX5g3Kos643ZMXgBPxLHRQcwAJfhlpwzLS-dxrYCqUOMw2JQUDji0KSIzTDREbO7r_54agvEn4WWYTxuj2jyBxm66GkiigNzCIfp1n3BQ5O94yGU77DUjA2o6SXaPVh82IwrNDXpp8wnRXtY_jzCMS5k8pAs8f62EqFUSZfJO6MwV7QG7SZ460ORWNV3zJiuaWx2UhStis6cjVxxaB6LiR5pDa4QvKLmyysXc6EeZ12h8EOgcP4C_EDSWmUmnA";
    final String expectedAuthorization = InternalAuthHttpConstants.BEARER_PREFIX + accessToken;
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshTokens(REFRESH_TOKEN, accessToken, idToken);

    OAuth2Credentials credentials = UserCredentials.newBuilder()
        .setClientId(CLIENT_ID)
        .setClientSecret(CLIENT_SECRET)
        .setRefreshToken(REFRESH_TOKEN)
        .setHttpTransportFactory(transportFactory)
        .build();

    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory requestFactory = transportFactory.transport.createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("http://foo"));

    adapter.initialize(request);

    HttpHeaders requestHeaders = request.getHeaders();
    String authorizationHeader = requestHeaders.getAuthorization();
    assertEquals(authorizationHeader, expectedAuthorization);
  }

  @Test
  public void initialize_populatesOAuth2Credentials_handle401() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";

    final String idToken = "1/eyJhbGciOiJSUzI1NiIsImtpZCI6IjU0MjViYjg0NjE2ZWJmOTczYWU4MGJjNjJhYzY4OGQyYTcyNzE1YWQifQ.eyJhenAiOiI4ODIwMzQ1NDEwMzctYjM5a3B2OWU4M2d2MmVzNnAyY243bG5lb3E0aHVqMDAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4ODIwMzQ1NDEwMzctYjM5a3B2OWU4M2d2MmVzNnAyY243bG5lb3E0aHVqMDAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDY5NTgzMjUxNzYwMTY0MzYyOTYiLCJoZCI6Im5pYW50aWNsYWJzLmNvbSIsImVtYWlsIjoiYWNhYnJlcmFAbmlhbnRpY2xhYnMuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJzMGVzY1VZc0RMb09UUlptRkRKS0FnIiwibm9uY2UiOiJOMC41MDA5MzE4NDMxMDYzNTYxMTUyNDMyNjU0Nzg2MyIsImV4cCI6MTUyNDMzMDE0OCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwianRpIjoiYTU4Y2JlYjBlNWJkMmUxZDRlY2M3MmQ3MjljOGRlZjViNzdiNDYyMCIsImlhdCI6MTUyNDMyNjU0OCwibmFtZSI6IkFsYW4gQ2FicmVyYSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLTRjTjQ0cUEteUNrL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFjL2p0UUtQcVpDWGRjL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbGFuIiwiZmFtaWx5X25hbWUiOiJDYWJyZXJhIiwibG9jYWxlIjoiZW4ifQ.Ro3ru4YuhPIQqDLIQiGp81Pha1hMVxFfeaeIIrEgZbp9-UG8I6cZEqlhLpOeLCJP3bQk5r9sHAZLUY_eoG-i_OBicX5g3Kos643ZMXgBPxLHRQcwAJfhlpwzLS-dxrYCqUOMw2JQUDji0KSIzTDREbO7r_54agvEn4WWYTxuj2jyBxm66GkiigNzCIfp1n3BQ5O94yGU77DUjA2o6SXaPVh82IwrNDXpp8wnRXtY_jzCMS5k8pAs8f62EqFUSZfJO6MwV7QG7SZ460ORWNV3zJiuaWx2UhStis6cjVxxaB6LiR5pDa4QvKLmyysXc6EeZ12h8EOgcP4C_EDSWmUmnA";
    final String idToken2 = "2/eyJhbGciOiJSUzI1NiIsImtpZCI6IjU0MjViYjg0NjE2ZWJmOTczYWU4MGJjNjJhYzY4OGQyYTcyNzE1YWQifQ.eyJhenAiOiI4ODIwMzQ1NDEwMzctYjM5a3B2OWU4M2d2MmVzNnAyY243bG5lb3E0aHVqMDAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4ODIwMzQ1NDEwMzctYjM5a3B2OWU4M2d2MmVzNnAyY243bG5lb3E0aHVqMDAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDY5NTgzMjUxNzYwMTY0MzYyOTYiLCJoZCI6Im5pYW50aWNsYWJzLmNvbSIsImVtYWlsIjoiYWNhYnJlcmFAbmlhbnRpY2xhYnMuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJzMGVzY1VZc0RMb09UUlptRkRKS0FnIiwibm9uY2UiOiJOMC41MDA5MzE4NDMxMDYzNTYxMTUyNDMyNjU0Nzg2MyIsImV4cCI6MTUyNDMzMDE0OCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwianRpIjoiYTU4Y2JlYjBlNWJkMmUxZDRlY2M3MmQ3MjljOGRlZjViNzdiNDYyMCIsImlhdCI6MTUyNDMyNjU0OCwibmFtZSI6IkFsYW4gQ2FicmVyYSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLTRjTjQ0cUEteUNrL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFjL2p0UUtQcVpDWGRjL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbGFuIiwiZmFtaWx5X25hbWUiOiJDYWJyZXJhIiwibG9jYWxlIjoiZW4ifQ.Ro3ru4YuhPIQqDLIQiGp81Pha1hMVxFfeaeIIrEgZbp9-UG8I6cZEqlhLpOeLCJP3bQk5r9sHAZLUY_eoG-i_OBicX5g3Kos643ZMXgBPxLHRQcwAJfhlpwzLS-dxrYCqUOMw2JQUDji0KSIzTDREbO7r_54agvEn4WWYTxuj2jyBxm66GkiigNzCIfp1n3BQ5O94yGU77DUjA2o6SXaPVh82IwrNDXpp8wnRXtY_jzCMS5k8pAs8f62EqFUSZfJO6MwV7QG7SZ460ORWNV3zJiuaWx2UhStis6cjVxxaB6LiR5pDa4QvKLmyysXc6EeZ12h8EOgcP4C_EDSWmUmnA";

    MockTokenServerTransportFactory tokenServerTransportFactory =
        new MockTokenServerTransportFactory();
    tokenServerTransportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    tokenServerTransportFactory.transport.addRefreshTokens(REFRESH_TOKEN, accessToken, idToken);

    OAuth2Credentials credentials = UserCredentials.newBuilder()
        .setClientId(CLIENT_ID)
        .setClientSecret(CLIENT_SECRET)
        .setRefreshToken(REFRESH_TOKEN)
        .setHttpTransportFactory(tokenServerTransportFactory)
//        .forEsp()
        .build();

    credentials.refresh();
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);

    HttpTransport primaryHttpTransport =
        new MockTokenCheckingTransport(tokenServerTransportFactory.transport, REFRESH_TOKEN);
    HttpRequestFactory requestFactory = primaryHttpTransport.createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("http://foo"));
    adapter.initialize(request);

    // now switch out the access token so that the original one is invalid,
    //   requiring a refresh of the access token
    tokenServerTransportFactory.transport.addRefreshTokens(REFRESH_TOKEN, accessToken2, idToken2);

    HttpResponse response = request.execute();

    // make sure that the request is successful despite the invalid access token
    assertEquals(200, response.getStatusCode());
    assertEquals(MockTokenCheckingTransport.SUCCESS_CONTENT, response.parseAsString());
  }

  @Test
  public void initialize_noURI() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String idToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String expectedAuthorization = InternalAuthHttpConstants.BEARER_PREFIX + accessToken;
    MockTokenServerTransportFactory tokenServerTransportFactory =
        new MockTokenServerTransportFactory();
    tokenServerTransportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    tokenServerTransportFactory.transport.addRefreshTokens(REFRESH_TOKEN, accessToken, idToken);

    OAuth2Credentials credentials = UserCredentials.newBuilder()
        .setClientId(CLIENT_ID)
        .setClientSecret(CLIENT_SECRET)
        .setRefreshToken(REFRESH_TOKEN)
        .setHttpTransportFactory(tokenServerTransportFactory)
        .build();

    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory requestFactory =
        tokenServerTransportFactory.transport.createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(null);

    adapter.initialize(request);

    HttpHeaders requestHeaders = request.getHeaders();
    String authorizationHeader = requestHeaders.getAuthorization();
    assertEquals(authorizationHeader, expectedAuthorization);
  }
}
