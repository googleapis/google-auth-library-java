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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.testing.http.FixedClock;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.client.util.Clock;
import com.google.api.client.util.Joiner;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.common.collect.ImmutableSet;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link ServiceAccountCredentials}. */
@RunWith(JUnit4.class)
public class ServiceAccountCredentialsTest extends BaseSerializationTest {

  private static final String CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private static final String CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private static final String PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  static final String PRIVATE_KEY_PKCS8 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALX0PQoe1igW12i"
          + "kv1bN/r9lN749y2ijmbc/mFHPyS3hNTyOCjDvBbXYbDhQJzWVUikh4mvGBA07qTj79Xc3yBDfKP2IeyYQIFe0t0"
          + "zkd7R9Zdn98Y2rIQC47aAbDfubtkU1U72t4zL11kHvoa0/RuFZjncvlr42X7be7lYh4p3NAgMBAAECgYASk5wDw"
          + "4Az2ZkmeuN6Fk/y9H+Lcb2pskJIXjrL533vrDWGOC48LrsThMQPv8cxBky8HFSEklPpkfTF95tpD43iVwJRB/Gr"
          + "CtGTw65IfJ4/tI09h6zGc4yqvIo1cHX/LQ+SxKLGyir/dQM925rGt/VojxY5ryJR7GLbCzxPnJm/oQJBANwOCO6"
          + "D2hy1LQYJhXh7O+RLtA/tSnT1xyMQsGT+uUCMiKS2bSKx2wxo9k7h3OegNJIu1q6nZ6AbxDK8H3+d0dUCQQDTrP"
          + "SXagBxzp8PecbaCHjzNRSQE2in81qYnrAFNB4o3DpHyMMY6s5ALLeHKscEWnqP8Ur6X4PvzZecCWU9BKAZAkAut"
          + "LPknAuxSCsUOvUfS1i87ex77Ot+w6POp34pEX+UWb+u5iFn2cQacDTHLV1LtE80L8jVLSbrbrlH43H0DjU5AkEA"
          + "gidhycxS86dxpEljnOMCw8CKoUBd5I880IUahEiUltk7OLJYS/Ts1wbn3kPOVX3wyJs8WBDtBkFrDHW2ezth2QJ"
          + "ADj3e1YhMVdjJW5jqwlD/VNddGjgzyunmiZg0uOXsHXbytYmsA545S8KRQFaJKFXYYFo2kOjqOiC1T2cAzMDjCQ"
          + "==\n-----END PRIVATE KEY-----\n";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final Collection<String> SCOPES = Collections.singletonList("dummy.scope");
  private static final String USER = "user@example.com";
  private static final String PROJECT_ID = "project-id";
  private static final Collection<String> EMPTY_SCOPES = Collections.emptyList();
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  private static final HttpTransportFactory DUMMY_TRANSPORT_FACTORY =
      new MockTokenServerTransportFactory();
  public static final String DEFAULT_ID_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOGI3OTIyO"
          + "TNhZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiL"
          + "CJhenAiOiIxMDIxMDE1NTA4MzQyMDA3MDg1NjgiLCJleHAiOjE1NjQ0NzUwNTEsImlhdCI6MTU2NDQ3MTQ1MSwi"
          + "aXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTAyMTAxNTUwODM0MjAwNzA4NTY4In0"
          + ".redacted";
  private static final String QUOTA_PROJECT = "sample-quota-project-id";

  @Test
  public void createdScoped_clones() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY_PKCS8);
    GoogleCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientEmail(CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(PRIVATE_KEY_ID)
            .setScopes(SCOPES)
            .setServiceAccountUser(USER)
            .setProjectId(PROJECT_ID)
            .build();
    List<String> newScopes = Arrays.asList("scope1", "scope2");

    ServiceAccountCredentials newCredentials =
        (ServiceAccountCredentials) credentials.createScoped(newScopes);

    assertEquals(CLIENT_ID, newCredentials.getClientId());
    assertEquals(CLIENT_EMAIL, newCredentials.getClientEmail());
    assertEquals(privateKey, newCredentials.getPrivateKey());
    assertEquals(PRIVATE_KEY_ID, newCredentials.getPrivateKeyId());
    assertArrayEquals(newScopes.toArray(), newCredentials.getScopes().toArray());
    assertEquals(USER, newCredentials.getServiceAccountUser());
    assertEquals(PROJECT_ID, newCredentials.getProjectId());

    assertArrayEquals(
        SCOPES.toArray(), ((ServiceAccountCredentials) credentials).getScopes().toArray());
  }

  @Test
  public void createdDelegated_clones() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY_PKCS8);
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientEmail(CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(PRIVATE_KEY_ID)
            .setScopes(SCOPES)
            .setServiceAccountUser(USER)
            .setProjectId(PROJECT_ID)
            .setQuotaProjectId(QUOTA_PROJECT)
            .build();
    String newServiceAccountUser = "stranger@other.org";

    ServiceAccountCredentials newCredentials =
        (ServiceAccountCredentials) credentials.createDelegated(newServiceAccountUser);

    assertEquals(CLIENT_ID, newCredentials.getClientId());
    assertEquals(CLIENT_EMAIL, newCredentials.getClientEmail());
    assertEquals(privateKey, newCredentials.getPrivateKey());
    assertEquals(PRIVATE_KEY_ID, newCredentials.getPrivateKeyId());
    assertArrayEquals(SCOPES.toArray(), newCredentials.getScopes().toArray());
    assertEquals(newServiceAccountUser, newCredentials.getServiceAccountUser());
    assertEquals(PROJECT_ID, newCredentials.getProjectId());
    assertEquals(QUOTA_PROJECT, newCredentials.getQuotaProjectId());

    assertEquals(USER, ((ServiceAccountCredentials) credentials).getServiceAccountUser());
  }

  @Test
  public void createAssertion_correct() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY_PKCS8);
    List<String> scopes = Arrays.asList("scope1", "scope2");
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientEmail(CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(PRIVATE_KEY_ID)
            .setScopes(scopes)
            .setServiceAccountUser(USER)
            .setProjectId(PROJECT_ID)
            .build();

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTimeMillis = Clock.SYSTEM.currentTimeMillis();
    String assertion = credentials.createAssertion(jsonFactory, currentTimeMillis, null);

    JsonWebSignature signature = JsonWebSignature.parse(jsonFactory, assertion);
    JsonWebToken.Payload payload = signature.getPayload();
    assertEquals(CLIENT_EMAIL, payload.getIssuer());
    assertEquals(OAuth2Utils.TOKEN_SERVER_URI.toString(), payload.getAudience());
    assertEquals(currentTimeMillis / 1000, (long) payload.getIssuedAtTimeSeconds());
    assertEquals(currentTimeMillis / 1000 + 3600, (long) payload.getExpirationTimeSeconds());
    assertEquals(USER, payload.getSubject());
    assertEquals(Joiner.on(' ').join(scopes), payload.get("scope"));
  }

  @Test
  public void createAssertionForIdToken_correct() throws IOException {

    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY_PKCS8);
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientEmail(CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(PRIVATE_KEY_ID)
            .setServiceAccountUser(USER)
            .setProjectId(PROJECT_ID)
            .build();

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTimeMillis = Clock.SYSTEM.currentTimeMillis();
    String assertion =
        credentials.createAssertionForIdToken(
            jsonFactory, currentTimeMillis, null, "https://foo.com/bar");

    JsonWebSignature signature = JsonWebSignature.parse(jsonFactory, assertion);
    JsonWebToken.Payload payload = signature.getPayload();
    assertEquals(CLIENT_EMAIL, payload.getIssuer());
    assertEquals("https://foo.com/bar", (String) (payload.getUnknownKeys().get("target_audience")));
    assertEquals(currentTimeMillis / 1000, (long) payload.getIssuedAtTimeSeconds());
    assertEquals(currentTimeMillis / 1000 + 3600, (long) payload.getExpirationTimeSeconds());
    assertEquals(USER, payload.getSubject());
  }

  @Test
  public void createAssertionForIdToken_incorrect() throws IOException {

    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY_PKCS8);
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientEmail(CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(PRIVATE_KEY_ID)
            .setServiceAccountUser(USER)
            .setProjectId(PROJECT_ID)
            .build();

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTimeMillis = Clock.SYSTEM.currentTimeMillis();
    String assertion =
        credentials.createAssertionForIdToken(
            jsonFactory, currentTimeMillis, null, "https://foo.com/bar");

    JsonWebSignature signature = JsonWebSignature.parse(jsonFactory, assertion);
    JsonWebToken.Payload payload = signature.getPayload();
    assertEquals(CLIENT_EMAIL, payload.getIssuer());
    assertNotEquals(
        "https://bar.com/foo", (String) (payload.getUnknownKeys().get("target_audience")));
    assertEquals(currentTimeMillis / 1000, (long) payload.getIssuedAtTimeSeconds());
    assertEquals(currentTimeMillis / 1000 + 3600, (long) payload.getExpirationTimeSeconds());
    assertEquals(USER, payload.getSubject());
  }

  @Test
  public void createAssertion_withTokenUri_correct() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY_PKCS8);
    List<String> scopes = Arrays.asList("scope1", "scope2");
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientId(CLIENT_ID)
            .setClientEmail(CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(PRIVATE_KEY_ID)
            .setScopes(scopes)
            .setServiceAccountUser(USER)
            .setProjectId(PROJECT_ID)
            .build();

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTimeMillis = Clock.SYSTEM.currentTimeMillis();
    String assertion =
        credentials.createAssertion(jsonFactory, currentTimeMillis, "https://foo.com/bar");

    JsonWebSignature signature = JsonWebSignature.parse(jsonFactory, assertion);
    JsonWebToken.Payload payload = signature.getPayload();
    assertEquals(CLIENT_EMAIL, payload.getIssuer());
    assertEquals("https://foo.com/bar", payload.getAudience());
    assertEquals(currentTimeMillis / 1000, (long) payload.getIssuedAtTimeSeconds());
    assertEquals(currentTimeMillis / 1000 + 3600, (long) payload.getExpirationTimeSeconds());
    assertEquals(USER, payload.getSubject());
    assertEquals(Joiner.on(' ').join(scopes), payload.get("scope"));
  }

  @Test
  public void createdScoped_enablesAccessTokens() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    GoogleCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            null,
            transportFactory,
            null);

    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Should not be able to get token without scopes");
    } catch (Exception expected) {
      // Expected
    }

    GoogleCredentials scopedCredentials = credentials.createScoped(SCOPES);

    Map<String, List<String>> metadata = scopedCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void createScopedRequired_emptyScopes_true() throws IOException {
    GoogleCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, EMPTY_SCOPES);

    assertTrue(credentials.createScopedRequired());
  }

  @Test
  public void createScopedRequired_nonEmptyScopes_false() throws IOException {
    GoogleCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, SCOPES);

    assertFalse(credentials.createScopedRequired());
  }

  @Test
  public void fromJSON_getProjectId() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    GenericJson json =
        writeServiceAccountJson(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, PROJECT_ID, null);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromJson(json, transportFactory);
    assertEquals(PROJECT_ID, credentials.getProjectId());
  }

  @Test
  public void fromJSON_getProjectIdNull() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    GenericJson json =
        writeServiceAccountJson(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, null, null);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromJson(json, transportFactory);
    assertNull(credentials.getProjectId());
  }

  @Test
  public void fromJSON_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    GenericJson json =
        writeServiceAccountJson(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, PROJECT_ID, null);

    GoogleCredentials credentials = ServiceAccountCredentials.fromJson(json, transportFactory);

    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void fromJSON_tokenServerUri() throws IOException {
    final String tokenServerUri = "https://foo.com/bar";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    GenericJson json =
        writeServiceAccountJson(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, PROJECT_ID, null);
    json.put("token_uri", tokenServerUri);
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromJson(json, transportFactory);
    assertEquals(URI.create(tokenServerUri), credentials.getTokenServerUri());
  }

  @Test
  public void fromJson_hasQuotaProjectId() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    GenericJson json =
        writeServiceAccountJson(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, PROJECT_ID, QUOTA_PROJECT);
    GoogleCredentials credentials = ServiceAccountCredentials.fromJson(json, transportFactory);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    assertTrue(metadata.containsKey(GoogleCredentials.QUOTA_PROJECT_ID_HEADER_KEY));
    assertEquals(
        metadata.get(GoogleCredentials.QUOTA_PROJECT_ID_HEADER_KEY),
        Collections.singletonList(QUOTA_PROJECT));
  }

  @Test
  public void getRequestMetadata_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_customTokenServer_hasAccessToken() throws IOException {
    final URI TOKEN_SERVER = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    transportFactory.transport.setTokenServerUri(TOKEN_SERVER);
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            TOKEN_SERVER);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void refreshAccessToken_refreshesToken() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken2);
    credentials.refresh();
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken2);
  }

  @Test
  public void refreshAccessToken_tokenExpiry() throws IOException {
    final String tokenString = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);
    credentials.clock = new FixedClock(0L);

    transport.addServiceAccount(CLIENT_EMAIL, tokenString);
    AccessToken accessToken = credentials.refreshAccessToken();
    assertEquals(tokenString, accessToken.getTokenValue());
    assertEquals(3600 * 1000L, accessToken.getExpirationTimeMillis().longValue());

    // Test for large expires_in values (should not overflow).
    transport.setExpiresInSeconds(3600 * 1000);
    accessToken = credentials.refreshAccessToken();
    assertEquals(tokenString, accessToken.getTokenValue());
    assertEquals(3600 * 1000 * 1000L, accessToken.getExpirationTimeMillis().longValue());
  }

  @Test
  public void refreshAccessToken_retriesIOException() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    transport.addResponseErrorSequence(new IOException());
    transport.addServiceAccount(CLIENT_EMAIL, accessToken2);
    credentials.refresh();
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken2);
  }

  @Test
  public void refreshAccessToken_retriesForbiddenError() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    transport.addResponseSequence(new MockLowLevelHttpResponse().setStatusCode(403));
    transport.addServiceAccount(CLIENT_EMAIL, accessToken2);
    credentials.refresh();
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken2);
  }

  @Test
  public void refreshAccessToken_retriesServerError() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    transport.addResponseSequence(new MockLowLevelHttpResponse().setStatusCode(500));
    transport.addServiceAccount(CLIENT_EMAIL, accessToken2);
    credentials.refresh();
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken2);
  }

  @Test
  public void refreshAccessToken_failsNotFoundError() throws IOException {
    final String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessToken2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    try {
      transport.addResponseSequence(new MockLowLevelHttpResponse().setStatusCode(404));
      transport.addServiceAccount(CLIENT_EMAIL, accessToken2);
      credentials.refresh();
      fail("Should not retry on Not Found");
    } catch (IOException expected) {
      // Expected
    }
  }

  @Test
  public void idTokenWithAudience_correct() throws IOException {
    String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .build();
    tokenCredential.refresh();
    assertEquals(DEFAULT_ID_TOKEN, tokenCredential.getAccessToken().getTokenValue());
    assertEquals(DEFAULT_ID_TOKEN, tokenCredential.getIdToken().getTokenValue());
    assertEquals(
        targetAudience,
        (String) tokenCredential.getIdToken().getJsonWebSignature().getPayload().getAudience());
  }

  @Test
  public void idTokenWithAudience_incorrect() throws IOException {
    String accessToken1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    MockTokenServerTransport transport = transportFactory.transport;
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            null);

    transport.addServiceAccount(CLIENT_EMAIL, accessToken1);
    TestUtils.assertContainsBearerToken(credentials.getRequestMetadata(CALL_URI), accessToken1);

    String targetAudience = "https://bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(credentials)
            .setTargetAudience(targetAudience)
            .build();
    tokenCredential.refresh();
    assertNotEquals(
        targetAudience,
        (String) tokenCredential.getIdToken().getJsonWebSignature().getPayload().getAudience());
  }

  @Test
  public void getScopes_nullReturnsEmpty() throws IOException {
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, null);

    Collection<String> scopes = credentials.getScopes();

    assertNotNull(scopes);
    assertTrue(scopes.isEmpty());
  }

  @Test
  public void getAccount_sameAs() throws IOException {
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, null);
    assertEquals(CLIENT_EMAIL, credentials.getAccount());
  }

  @Test
  public void sign_sameAs()
      throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    byte[] toSign = {0xD, 0xE, 0xA, 0xD};
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID, null);
    byte[] signedBytes = credentials.sign(toSign);
    Signature signature = Signature.getInstance(OAuth2Utils.SIGNATURE_ALGORITHM);
    signature.initSign(credentials.getPrivateKey());
    signature.update(toSign);
    assertArrayEquals(signature.sign(), signedBytes);
  }

  @Test
  public void equals_true() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            tokenServer);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            tokenServer);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_clientId() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            "otherClientId",
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_email() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            "otherEmail",
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_keyId() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            "otherId",
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_scopes() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            ImmutableSet.<String>of(),
            serverTransportFactory,
            tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_transportFactory() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            httpTransportFactory,
            tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_tokenServer() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    final URI tokenServer2 = URI.create("https://foo2.com/bar");
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer1);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            serverTransportFactory,
            tokenServer2);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            tokenServer,
            USER,
            null,
            QUOTA_PROJECT);
    String expectedToString =
        String.format(
            "ServiceAccountCredentials{clientId=%s, clientEmail=%s, privateKeyId=%s, "
                + "transportFactoryClassName=%s, tokenServerUri=%s, scopes=%s, serviceAccountUser=%s, "
                + "quotaProjectId=%s}",
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_ID,
            MockTokenServerTransportFactory.class.getName(),
            tokenServer,
            SCOPES,
            USER,
            QUOTA_PROJECT);
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            tokenServer);
    OAuth2Credentials otherCredentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            tokenServer);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.fromPkcs8(
            CLIENT_ID,
            CLIENT_EMAIL,
            PRIVATE_KEY_PKCS8,
            PRIVATE_KEY_ID,
            SCOPES,
            transportFactory,
            tokenServer);
    ServiceAccountCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
    assertEquals(
        MockTokenServerTransportFactory.class,
        deserializedCredentials.toBuilder().getHttpTransportFactory().getClass());
  }

  @Test
  public void fromStream_nullTransport_throws() throws IOException {
    InputStream stream = new ByteArrayInputStream("foo".getBytes());
    try {
      ServiceAccountCredentials.fromStream(stream, null);
      fail("Should throw if HttpTransportFactory is null");
    } catch (NullPointerException expected) {
      // Expected
    }
  }

  @Test
  public void fromStream_nullStream_throws() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    try {
      ServiceAccountCredentials.fromStream(null, transportFactory);
      fail("Should throw if InputStream is null");
    } catch (NullPointerException expected) {
      // Expected
    }
  }

  @Test
  public void fromStream_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream =
        writeServiceAccountStream(CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID);

    GoogleCredentials credentials =
        ServiceAccountCredentials.fromStream(serviceAccountStream, transportFactory);

    assertNotNull(credentials);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void fromStream_noClientId_throws() throws IOException {
    InputStream serviceAccountStream =
        writeServiceAccountStream(null, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_id");
  }

  @Test
  public void fromStream_noClientEmail_throws() throws IOException {
    InputStream serviceAccountStream =
        writeServiceAccountStream(CLIENT_ID, null, PRIVATE_KEY_PKCS8, PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_email");
  }

  @Test
  public void fromStream_noPrivateKey_throws() throws IOException {
    InputStream serviceAccountStream =
        writeServiceAccountStream(CLIENT_ID, CLIENT_EMAIL, null, PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "private_key");
  }

  @Test
  public void fromStream_noPrivateKeyId_throws() throws IOException {
    InputStream serviceAccountStream =
        writeServiceAccountStream(CLIENT_ID, CLIENT_EMAIL, PRIVATE_KEY_PKCS8, null);

    testFromStreamException(serviceAccountStream, "private_key_id");
  }

  static GenericJson writeServiceAccountJson(
      String clientId,
      String clientEmail,
      String privateKeyPkcs8,
      String privateKeyId,
      String projectId,
      String quotaProjectId) {
    GenericJson json = new GenericJson();
    if (clientId != null) {
      json.put("client_id", clientId);
    }
    if (clientEmail != null) {
      json.put("client_email", clientEmail);
    }
    if (privateKeyPkcs8 != null) {
      json.put("private_key", privateKeyPkcs8);
    }
    if (privateKeyId != null) {
      json.put("private_key_id", privateKeyId);
    }
    if (projectId != null) {
      json.put("project_id", projectId);
    }
    if (quotaProjectId != null) {
      json.put("quota_project_id", quotaProjectId);
    }
    json.put("type", GoogleCredentials.SERVICE_ACCOUNT_FILE_TYPE);
    return json;
  }

  static InputStream writeServiceAccountStream(
      String clientId, String clientEmail, String privateKeyPkcs8, String privateKeyId)
      throws IOException {
    GenericJson json =
        writeServiceAccountJson(clientId, clientEmail, privateKeyPkcs8, privateKeyId, null, null);
    return TestUtils.jsonToInputStream(json);
  }

  private static void testFromStreamException(InputStream stream, String expectedMessageContent) {
    try {
      ServiceAccountCredentials.fromStream(stream, DUMMY_TRANSPORT_FACTORY);
      fail(
          String.format(
              "Should throw exception with message containing '%s'", expectedMessageContent));
    } catch (IOException expected) {
      assertTrue(expected.getMessage().contains(expectedMessageContent));
    }
  }
}
