/*
 * Copyright 2022, Google Inc. All rights reserved.
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

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.testing.http.FixedClock;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link GdchCredentials}. */
@RunWith(JUnit4.class)
public class GdchCredentialsTest extends BaseSerializationTest {
  private static final String FORMAT_VERSION = GdchCredentials.SUPPORTED_FORMAT_VERSION;
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
  private static final String PROJECT_ID = "project-id";
  private static final String SERVICE_IDENTITY_NAME = "service-identity-name";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final URI TOKEN_SERVER_URI =
      URI.create("https://service-identity.domain/authenticate");
  private static final String CA_CERT_FILE_NAME = "cert.pem";
  private static final String CA_CERT_PATH =
      GdchCredentialsTest.class.getClassLoader().getResource(CA_CERT_FILE_NAME).getPath();
  private static final URI API_AUDIENCE = URI.create("https://gdch-api-audience");
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  @Test
  public void fromJSON_getProjectId() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);

    assertEquals(PROJECT_ID, credentials.getProjectId());
  }

  @Test
  public void fromJSON_getServiceIdentityName() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);

    assertEquals(SERVICE_IDENTITY_NAME, credentials.getServiceIdentityName());
  }

  @Test
  public void fromJSON_getCaCertPath() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);

    assertEquals(CA_CERT_PATH, credentials.getCaCertPath());
  }

  @Test
  public void fromJSON_getTokenServerUri() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);

    assertEquals(TOKEN_SERVER_URI, credentials.getTokenServerUri());
  }

  @Test
  public void fromJSON_nullFormatVersion() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            null,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  String.format(
                      "Error reading GDCH service account credential from JSON, "
                          + "%s is misconfigured.",
                      "format_version")));
    }
  }

  @Test
  public void fromJSON_nullProjectId() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            null,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  String.format(
                      "Error reading GDCH service account credential from JSON, "
                          + "%s is misconfigured.",
                      "project")));
    }
  }

  @Test
  public void fromJSON_nullPrivateKeyId() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            null,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  String.format(
                      "Error reading GDCH service account credential from JSON, "
                          + "%s is misconfigured.",
                      "private_key_id")));
    }
  }

  @Test
  public void fromJSON_nullPrivateKey() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            null,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  String.format(
                      "Error reading GDCH service account credential from JSON, "
                          + "%s is misconfigured.",
                      "private_key")));
    }
  }

  @Test
  public void fromJSON_nullServiceIdentityName() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            null,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  String.format(
                      "Error reading GDCH service account credential from JSON, "
                          + "%s is misconfigured.",
                      "name")));
    }
  }

  @Test
  public void fromJSON_nullCaCertPath() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            null,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);
    assertNull(credentials.getCaCertPath());
  }

  @Test
  public void fromJSON_nullTokenServerUri() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            null);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  String.format(
                      "Error reading GDCH service account credential from JSON, "
                          + "%s is misconfigured.",
                      "token_uri")));
    }
  }

  @Test
  public void fromJSON_invalidFormatVersion() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            "100",
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(
          ex.getMessage()
              .contains(String.format("Only format version %s is supported", FORMAT_VERSION)));
    }
  }

  @Test
  public void fromJSON_invalidCaCertPath() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            "/path/to/missing/file",
            TOKEN_SERVER_URI);

    try {
      GdchCredentials credentials = GdchCredentials.fromJson(json);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (IOException ex) {
      assertTrue(ex.getMessage().contains("Error reading certificate file from CA cert path"));
    }
  }

  @Test
  public void fromJSON_emptyCaCertPath() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            "",
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);
    assertEquals("", credentials.getCaCertPath());
  }

  @Test
  public void fromJSON_transportFactoryForGdch() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);
    assertEquals(
        GdchCredentials.TransportFactoryForGdch.class,
        credentials.getTransportFactory().getClass());
  }

  @Test
  public void fromJSON_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json, transportFactory);
    GdchCredentials gdchWithAudience = credentials.createWithGdchAudience(API_AUDIENCE);
    transportFactory.transport.addGdchServiceAccount(
        GdchCredentials.getIssuerSubjectValue(PROJECT_ID, SERVICE_IDENTITY_NAME), ACCESS_TOKEN);
    transportFactory.transport.setTokenServerUri(TOKEN_SERVER_URI);
    Map<String, List<String>> metadata = gdchWithAudience.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void createWithGdchAudience_correct() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);

    assertEquals(PROJECT_ID, credentials.getProjectId());
    assertEquals(SERVICE_IDENTITY_NAME, credentials.getServiceIdentityName());
    assertEquals(TOKEN_SERVER_URI, credentials.getTokenServerUri());
    assertEquals(CA_CERT_PATH, credentials.getCaCertPath());
    assertNull(credentials.getApiAudience());

    GdchCredentials gdchWithAudience = credentials.createWithGdchAudience(API_AUDIENCE);

    assertEquals(PROJECT_ID, gdchWithAudience.getProjectId());
    assertEquals(SERVICE_IDENTITY_NAME, gdchWithAudience.getServiceIdentityName());
    assertEquals(TOKEN_SERVER_URI, gdchWithAudience.getTokenServerUri());
    assertEquals(CA_CERT_PATH, credentials.getCaCertPath());
    assertEquals(API_AUDIENCE, gdchWithAudience.getApiAudience());
  }

  @Test
  public void createWithGdchAudience_nullApiAudience() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);

    try {
      GdchCredentials gdchWithAudience = credentials.createWithGdchAudience(null);
      fail("Should not be able to create GDCH credential without exception.");
    } catch (NullPointerException ex) {
      assertTrue(ex.getMessage().contains("Audience are not configured for GDCH service account"));
    }
  }

  @Test
  public void createAssertion_correct() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);
    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    long currentTimeMillis = Clock.SYSTEM.currentTimeMillis();
    String assertion = credentials.createAssertion(jsonFactory, currentTimeMillis, API_AUDIENCE);

    JsonWebSignature signature = JsonWebSignature.parse(jsonFactory, assertion);
    JsonWebToken.Payload payload = signature.getPayload();

    String expectedIssSubValue =
        GdchCredentials.getIssuerSubjectValue(PROJECT_ID, SERVICE_IDENTITY_NAME);
    assertEquals(expectedIssSubValue, payload.getIssuer());
    assertEquals(expectedIssSubValue, payload.getSubject());
    assertEquals(TOKEN_SERVER_URI.toString(), payload.getAudience());
    assertEquals(currentTimeMillis / 1000, (long) payload.getIssuedAtTimeSeconds());
    assertEquals(currentTimeMillis / 1000 + 3600, (long) payload.getExpirationTimeSeconds());
  }

  @Test
  public void refreshAccessToken_correct() throws IOException {
    final String tokenString = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json, transportFactory);
    GdchCredentials gdchWithAudience = credentials.createWithGdchAudience(API_AUDIENCE);

    GdchCredentialsTestUtil.registerGdchCredentialWithMockTransport(
        gdchWithAudience,
        transportFactory.transport,
        PROJECT_ID,
        SERVICE_IDENTITY_NAME,
        tokenString,
        TOKEN_SERVER_URI);

    AccessToken accessToken = gdchWithAudience.refreshAccessToken();
    assertNotNull(accessToken);
    assertEquals(tokenString, accessToken.getTokenValue());
    assertEquals(3600 * 1000L, accessToken.getExpirationTimeMillis().longValue());

    // Test for large expires_in values (should not overflow).
    transportFactory.transport.setExpiresInSeconds(3600 * 1000);
    accessToken = gdchWithAudience.refreshAccessToken();
    assertNotNull(accessToken);
    assertEquals(tokenString, accessToken.getTokenValue());
    assertEquals(3600 * 1000 * 1000L, accessToken.getExpirationTimeMillis().longValue());
  }

  @Test
  public void refreshAccessToken_nullApiAudience() throws IOException {
    final String tokenString = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json, transportFactory);

    credentials.clock = new FixedClock(0L);

    transportFactory.transport.addGdchServiceAccount(
        GdchCredentials.getIssuerSubjectValue(PROJECT_ID, SERVICE_IDENTITY_NAME), tokenString);
    transportFactory.transport.setTokenServerUri(TOKEN_SERVER_URI);
    try {
      AccessToken accessToken = credentials.refreshAccessToken();
      fail("Should not be able to refresh access token without exception.");
    } catch (NullPointerException ex) {
      assertTrue(
          ex.getMessage()
              .contains(
                  "Audience are not configured for GDCH service account. Specify the "
                      + "audience by calling createWithGDCHAudience"));
    }
  }

  @Test
  public void getIssuerSubjectValue_correct() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json);
    Object expectedIssSubValue =
        String.format("system:serviceaccount:%s:%s", PROJECT_ID, SERVICE_IDENTITY_NAME);
    assertEquals(
        expectedIssSubValue,
        GdchCredentials.getIssuerSubjectValue(PROJECT_ID, SERVICE_IDENTITY_NAME));
  }

  @Test
  public void equals_same() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_projectId() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            "otherProjectId",
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_keyId() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            "otherId",
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_serviceIdentityName() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            "otherServiceIdentityName",
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_caCertPath() throws IOException {
    File tmpDirectory = Files.createTempDirectory("tmpDirectory").toFile();
    File testCaCertFile = File.createTempFile("testCert", ".pem", tmpDirectory);
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            testCaCertFile.getPath(),
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));

    testCaCertFile.delete();
  }

  @Test
  public void equals_false_tokenServer() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            URI.create("https://foo1.com/bar"));
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_apiAudience() throws IOException {
    URI otherApiAudience = URI.create("https://foo1.com/bar");

    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials =
        ((GdchCredentials) otherCredentials).createWithGdchAudience(otherApiAudience);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    String expectedToString =
        String.format(
            "GdchCredentials{projectId=%s, privateKeyId=%s, serviceIdentityName=%s, "
                + "tokenServerUri=%s, transportFactoryClassName=%s, caCertPath=%s, apiAudience=%s, lifetime=3600}",
            PROJECT_ID,
            PRIVATE_KEY_ID,
            SERVICE_IDENTITY_NAME,
            TOKEN_SERVER_URI,
            GdchCredentials.TransportFactoryForGdch.class.getName(),
            CA_CERT_PATH,
            API_AUDIENCE);
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials credentials = GdchCredentials.fromJson(json);
    GenericJson otherJson =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    OAuth2Credentials otherCredentials = GdchCredentials.fromJson(otherJson);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(API_AUDIENCE);
    otherCredentials = ((GdchCredentials) otherCredentials).createWithGdchAudience(API_AUDIENCE);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize_correct() throws IOException, ClassNotFoundException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    GenericJson json =
        writeGdchServiceAccountJson(
            FORMAT_VERSION,
            PROJECT_ID,
            PRIVATE_KEY_ID,
            PRIVATE_KEY_PKCS8,
            SERVICE_IDENTITY_NAME,
            CA_CERT_PATH,
            TOKEN_SERVER_URI);
    GdchCredentials credentials = GdchCredentials.fromJson(json, transportFactory);
    credentials = credentials.createWithGdchAudience(API_AUDIENCE);

    GdchCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
    assertEquals(
        MockTokenServerTransportFactory.class,
        deserializedCredentials.toBuilder().getHttpTransportFactory().getClass());
  }

  static GenericJson writeGdchServiceAccountJson(
      String formatVersion,
      String project,
      String privateKeyId,
      String privateKeyPkcs8,
      String serviceIdentityName,
      String caCertPath,
      URI tokenServerUri) {
    GenericJson json = new GenericJson();

    if (formatVersion != null) {
      json.put("format_version", formatVersion);
    }
    if (project != null) {
      json.put("project", project);
    }
    if (privateKeyId != null) {
      json.put("private_key_id", privateKeyId);
    }
    if (privateKeyPkcs8 != null) {
      json.put("private_key", privateKeyPkcs8);
    }
    if (serviceIdentityName != null) {
      json.put("name", serviceIdentityName);
    }
    if (caCertPath != null) {
      json.put("ca_cert_path", caCertPath);
    }
    if (tokenServerUri != null) {
      json.put("token_uri", tokenServerUri.toString());
    }
    json.put("type", GoogleCredentials.GDCH_SERVICE_ACCOUNT_FILE_TYPE);
    return json;
  }

  static InputStream writeGdchServiceAccountStream(
      String formatVersion,
      String project,
      String privateKeyId,
      String privateKeyPkcs8,
      String serviceIdentityName,
      String caCertPath,
      URI tokenServerUri)
      throws IOException {
    GenericJson json =
        writeGdchServiceAccountJson(
            formatVersion,
            project,
            privateKeyId,
            privateKeyPkcs8,
            serviceIdentityName,
            caCertPath,
            tokenServerUri);
    return TestUtils.jsonToInputStream(json);
  }
}
