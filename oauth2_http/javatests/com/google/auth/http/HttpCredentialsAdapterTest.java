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
    final String expectedAuthorization = InternalAuthHttpConstants.BEARER_PREFIX + accessToken;
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken);
    OAuth2Credentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, transportFactory, null);
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

    MockTokenServerTransportFactory tokenServerTransportFactory =
        new MockTokenServerTransportFactory();
    tokenServerTransportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    tokenServerTransportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken);

    OAuth2Credentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, tokenServerTransportFactory, null);
    credentials.refresh();
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(credentials);

    HttpTransport primaryHttpTransport =
        new MockTokenCheckingTransport(tokenServerTransportFactory.transport, REFRESH_TOKEN);
    HttpRequestFactory requestFactory = primaryHttpTransport.createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("http://foo"));
    adapter.initialize(request);

    // now switch out the access token so that the original one is invalid,
    //   requiring a refresh of the access token
    tokenServerTransportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken2);

    HttpResponse response = request.execute();

    // make sure that the request is successful despite the invalid access token
    assertEquals(200, response.getStatusCode());
    assertEquals(MockTokenCheckingTransport.SUCCESS_CONTENT, response.parseAsString());
  }

  @Test
  public void initialize_noURI() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String expectedAuthorization = InternalAuthHttpConstants.BEARER_PREFIX + accessToken;
    MockTokenServerTransportFactory tokenServerTransportFactory =
        new MockTokenServerTransportFactory();
    tokenServerTransportFactory.transport.addClient(CLIENT_ID, CLIENT_SECRET);
    tokenServerTransportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessToken);
    OAuth2Credentials credentials = new UserCredentials(
        CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, null, tokenServerTransportFactory, null);
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
