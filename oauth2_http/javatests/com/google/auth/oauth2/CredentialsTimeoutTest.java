/*
 * Copyright 2025 Google LLC
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
 *    * Neither the name of Google LLC nor the names of its
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT of THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.http.HttpTransportFactory;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.Test;

public class CredentialsTimeoutTest {

  private static final int TIMEOUT_MS = 1000; // 1 second

  @Test
  public void externalAccount_shouldTimeout() throws Exception {
    // Create a server that is slow on the second (access token) request.
    MockWebServer server = createExternalAccountMockServer(0, 2000);
    server.start();

    String tokenUrl = server.url("/token").toString();
    String subjectTokenUrl = server.url("/subject_token").toString();

    HttpTransportFactory transportFactory = createTimeoutTransportFactory(TIMEOUT_MS);
    ExternalAccountCredentials credentials =
        createExternalAccountCredentials(tokenUrl, subjectTokenUrl, transportFactory);

    IOException exception = assertThrows(IOException.class, credentials::refresh);
    assertTrue(exception.getCause() instanceof SocketTimeoutException);

    server.shutdown();
  }

  @Test
  public void externalAccount_shouldNotTimeout() throws Exception {
    // Create a server that is faster than the client's timeout.
    MockWebServer server = createExternalAccountMockServer(0, 500);
    server.start();

    String tokenUrl = server.url("/token").toString();
    String subjectTokenUrl = server.url("/subject_token").toString();

    HttpTransportFactory transportFactory = createTimeoutTransportFactory(TIMEOUT_MS);
    ExternalAccountCredentials credentials =
        createExternalAccountCredentials(tokenUrl, subjectTokenUrl, transportFactory);

    credentials.refresh();
    assertNotNull(credentials.getAccessToken());
    assertEquals("test_token", credentials.getAccessToken().getTokenValue());

    server.shutdown();
  }

  @Test
  public void impersonatedCredentials_shouldTimeout() throws Exception {
    // Create a server that is slower than the client's timeout.
    MockWebServer server = createImpersonatedMockServer(2000);
    server.start();

    String iamEndpoint = server.url("/").toString();

    HttpTransportFactory transportFactory = createTimeoutTransportFactory(TIMEOUT_MS);
    ImpersonatedCredentials credentials =
        createImpersonatedCredentials(iamEndpoint, transportFactory);

    IOException exception = assertThrows(IOException.class, credentials::refresh);
    assertTrue(exception.getCause() instanceof SocketTimeoutException);

    server.shutdown();
  }

  @Test
  public void impersonatedCredentials_shouldNotTimeout() throws Exception {
    // Create a server that is faster than the client's timeout.
    MockWebServer server = createImpersonatedMockServer(500);
    server.start();

    String iamEndpoint = server.url("/").toString();

    HttpTransportFactory transportFactory = createTimeoutTransportFactory(TIMEOUT_MS);
    ImpersonatedCredentials credentials =
        createImpersonatedCredentials(iamEndpoint, transportFactory);

    credentials.refresh();
    assertNotNull(credentials.getAccessToken());
    assertEquals("impersonated-token", credentials.getAccessToken().getTokenValue());

    server.shutdown();
  }

  // Server and Credential Helper Methods

  private static MockWebServer createExternalAccountMockServer(
      int subjectTokenDelayMs, int accessTokenDelayMs) throws IOException {
    MockWebServer server = new MockWebServer();
    configureServerForHttps(server);

    server.enqueue(
        new MockResponse()
            .setBody("dummy-subject-token")
            .setBodyDelay(subjectTokenDelayMs, TimeUnit.MILLISECONDS));

    String tokenResponse =
        "{"
            + "\"access_token\": \"test_token\","
            + "\"issued_token_type\": \"urn:ietf:params:oauth:token-type:access_token\","
            + "\"token_type\": \"Bearer\","
            + "\"expires_in\": 3600"
            + "}";
    server.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setBodyDelay(accessTokenDelayMs, TimeUnit.MILLISECONDS));

    return server;
  }

  private static String getDefaultExpireTime() {
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(new Date());
    calendar.add(Calendar.SECOND, 300);
    return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(calendar.getTime());
  }

  private static MockWebServer createImpersonatedMockServer(int delayMs) throws IOException {
    MockWebServer server = new MockWebServer();
    configureServerForHttps(server);

    String expireTime = getDefaultExpireTime();
    String tokenResponse =
        "{"
            + "\"accessToken\": \"impersonated-token\","
            + "\"expireTime\": \""
            + expireTime
            + "\""
            + "}";
    server.enqueue(
        new MockResponse().setBody(tokenResponse).setBodyDelay(delayMs, TimeUnit.MILLISECONDS));

    return server;
  }

  private static void configureServerForHttps(MockWebServer server) throws IOException {
    String localhost = InetAddress.getByName("localhost").getCanonicalHostName();
    HeldCertificate localhostCertificate =
        new HeldCertificate.Builder().addSubjectAlternativeName(localhost).build();
    HandshakeCertificates serverCertificates =
        new HandshakeCertificates.Builder().heldCertificate(localhostCertificate).build();
    server.useHttps(serverCertificates.sslSocketFactory(), false);
  }

  private static ExternalAccountCredentials createExternalAccountCredentials(
      String tokenUrl, String subjectTokenUrl, HttpTransportFactory transportFactory)
      throws IOException {
    GenericJson credentialSource = new GenericJson();
    credentialSource.put("url", subjectTokenUrl);
    credentialSource.put("headers", Collections.singletonMap("Metadata-Flavor", "Google"));

    GenericJson json = new GenericJson();
    json.put("type", "external_account");
    json.put(
        "audience",
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider");
    json.put("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
    json.put("token_url", tokenUrl);
    json.put("credential_source", credentialSource);

    return ExternalAccountCredentials.fromJson(json, transportFactory);
  }

  private static ImpersonatedCredentials createImpersonatedCredentials(
      String iamEndpoint, HttpTransportFactory transportFactory) {
    GoogleCredentials source =
        new GoogleCredentials(new AccessToken("dummy-token", new Date())) {
          @Override
          public AccessToken refreshAccessToken() throws IOException {
            // In a real scenario, this would fetch a new token. For this test,
            // we just return a dummy token since the impersonation flow will
            // use this credential's metadata, not its token.
            return new AccessToken("refreshed-dummy-token", new Date());
          }
        };

    return ImpersonatedCredentials.newBuilder()
        .setSourceCredentials(source)
        .setTargetPrincipal("test-sa@example.iam.gserviceaccount.com")
        .setScopes(Collections.singletonList("https://www.googleapis.com/auth/cloud-platform"))
        .setIamEndpointOverride(iamEndpoint)
        .setHttpTransportFactory(transportFactory)
        .build();
  }

  private static HttpTransportFactory createTimeoutTransportFactory(int timeoutMs) {
    return () -> {
      TrustManager[] trustAllCerts =
          new TrustManager[] {
            new X509TrustManager() {
              public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
              }

              public void checkClientTrusted(X509Certificate[] certs, String authType) {}

              public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
          };

      SSLContext sslContext;
      try {
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }
      SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
      HostnameVerifier hostnameVerifier = (hostname, session) -> true;

      NetHttpTransport.Builder builder =
          new NetHttpTransport.Builder()
              .setSslSocketFactory(sslSocketFactory)
              .setHostnameVerifier(hostnameVerifier);

      builder.setConnectionFactory(
          url -> {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(timeoutMs);
            connection.setReadTimeout(timeoutMs);
            return connection;
          });
      return builder.build();
    };
  }
}
