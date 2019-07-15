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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.auth.Credentials;
import com.google.common.collect.ImmutableList;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonGenerator;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Clock;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.auth.ServiceAccountSigner.SigningException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * Test case for {@link ImpersonatedCredentials}.
 */
@RunWith(JUnit4.class)
public class ImpersonatedCredentialsTest extends BaseSerializationTest {

  private static final String SA_CLIENT_EMAIL = "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private static final String SA_PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  static final String SA_PRIVATE_KEY_PKCS8 = "-----BEGIN PRIVATE KEY-----\n"
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
  private static final String IMPERSONATED_CLIENT_EMAIL = "impersonated-account@iam.gserviceaccount.com";
  private static final List<String> SCOPES = Arrays.asList("https://www.googleapis.com/auth/devstorage.read_only");
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final int VALID_LIFETIME = 300;
  private static final int INVALID_LIFETIME = 3800;
  private static JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

  private static final String RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";

  static class MockIAMCredentialsServiceTransportFactory implements HttpTransportFactory {

    MockIAMCredentialsServiceTransport transport = new MockIAMCredentialsServiceTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  private GoogleCredentials getSourceCredentials() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountCredentials sourceCredentials = ServiceAccountCredentials.newBuilder()
        .setClientEmail(SA_CLIENT_EMAIL)
        .setPrivateKey(privateKey)
        .setPrivateKeyId(SA_PRIVATE_KEY_ID)
        .setScopes(SCOPES)
        .setProjectId(PROJECT_ID)
        .setHttpTransportFactory(transportFactory).build();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);

    return sourceCredentials;
  }

  @Test()
  public void refreshAccessToken_unauthorized() throws IOException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    String expectedMessage = "The caller does not have permission";
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setTokenResponseErrorCode(HttpStatusCodes.STATUS_CODE_UNAUTHORIZED);
    mtransportFactory.transport.setTokenResponseErrorContent(
        generateErrorJson(HttpStatusCodes.STATUS_CODE_UNAUTHORIZED,
            expectedMessage, "global", "forbidden"));
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    try {
      targetCredentials.refreshAccessToken().getTokenValue();
      fail(String.format("Should throw exception with message containing '%s'", expectedMessage));
    } catch (IOException expected) {
      assertEquals("Error requesting access token", expected.getMessage());
      assertTrue(expected.getCause().getMessage().contains(expectedMessage));
    }
  }

  @Test()
  public void refreshAccessToken_malformedTarget() throws IOException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    String invalidTargetEmail = "foo";
    String expectedMessage = "Request contains an invalid argument";
    mtransportFactory.transport.setTargetPrincipal(invalidTargetEmail);
    mtransportFactory.transport.setTokenResponseErrorCode(HttpStatusCodes.STATUS_CODE_BAD_REQUEST);
    mtransportFactory.transport.setTokenResponseErrorContent(
        generateErrorJson(HttpStatusCodes.STATUS_CODE_BAD_REQUEST,
            expectedMessage, "global", "badRequest"));
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        invalidTargetEmail, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    try {
      targetCredentials.refreshAccessToken().getTokenValue();
      fail(String.format("Should throw exception with message containing '%s'", expectedMessage));
    } catch (IOException expected) {
      assertEquals("Error requesting access token", expected.getMessage());
      assertTrue(expected.getCause().getMessage().contains(expectedMessage));
    }
  }

  @Test()
  public void credential_with_invalid_lifetime() throws IOException, IllegalStateException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    try {
      ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
          IMPERSONATED_CLIENT_EMAIL, null, SCOPES, INVALID_LIFETIME);
      targetCredentials.refreshAccessToken().getTokenValue();
      fail(String.format("Should throw exception with message containing '%s'",
          "lifetime must be less than or equal to 3600"));
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("lifetime must be less than or equal to 3600"));
    }

  }

  @Test()
  public void credential_with_invalid_scope() throws IOException, IllegalStateException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    try {
      ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
          IMPERSONATED_CLIENT_EMAIL, null, null, VALID_LIFETIME);
      targetCredentials.refreshAccessToken().getTokenValue();
      fail(String.format("Should throw exception with message containing '%s'",
          "Scopes cannot be null"));
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("Scopes cannot be null"));
    }

  }

  @Test()
  public void refreshAccessToken_success() throws IOException, IllegalStateException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
  }

  @Test()
  public void refreshAccessToken_delegates_success() throws IOException, IllegalStateException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    List<String> delegates = Arrays.asList("delegate-account@iam.gserviceaccount.com");
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, delegates, SCOPES, VALID_LIFETIME, mtransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
  }

  @Test()
  public void refreshAccessToken_invalidDate() throws IOException, IllegalStateException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    String expectedMessage = "Unparseable date";
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken("foo");
    mtransportFactory.transport.setExpireTime("1973-09-29T15:01:23");
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    try {
      targetCredentials.refreshAccessToken().getTokenValue();
      fail(String.format("Should throw exception with message containing '%s'", expectedMessage));
    } catch (IOException expected) {
      assertTrue(expected.getMessage().contains(expectedMessage));
    }
  }

  @Test
  public void getAccount_sameAs() throws IOException {
    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    assertEquals(IMPERSONATED_CLIENT_EMAIL, targetCredentials.getAccount());
  }


  @Test
  public void sign_sameAs() throws IOException {
    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));
  }

  @Test
  public void sign_requestIncludesDelegates() throws IOException {
    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, ImmutableList.of("delegate@example.com"), SCOPES, VALID_LIFETIME,
        mtransportFactory);


    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));

    MockLowLevelHttpRequest request = mtransportFactory.transport.getRequest();
    GenericJson body = JSON_FACTORY.createJsonParser(request.getContentAsString())
        .parseAndClose(GenericJson.class);
    List<String> delegates = new ArrayList<>();
    delegates.add("delegate@example.com");
    assertEquals(delegates, body.get("delegates"));
  }

  @Test
  public void sign_usesSourceCredentials() throws IOException {
    Date expiry = new Date();
    Calendar c = Calendar.getInstance();
    c.setTime(expiry);
    c.add(Calendar.DATE, 1);
    expiry = c.getTime();
    GoogleCredentials sourceCredentials = new GoogleCredentials.Builder()
        .setAccessToken(new AccessToken("source-token", expiry))
        .build();

    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, ImmutableList.of("delegate@example.com"), SCOPES, VALID_LIFETIME,
        mtransportFactory);


    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));

    MockLowLevelHttpRequest request = mtransportFactory.transport.getRequest();
    assertEquals("Bearer source-token", request.getFirstHeaderValue("Authorization"));
  }

  @Test
  public void sign_accessDenied_throws() throws IOException  {
    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setSignedBlob(expectedSignature);
    mtransportFactory.transport.setSigningErrorResponseCodeAndMessage(HttpStatusCodes.STATUS_CODE_FORBIDDEN, "Sign Error");

    try {
      byte[] bytes = {0xD, 0xE, 0xA, 0xD};
      targetCredentials.sign(bytes);
      fail("Signing should have failed");
    } catch (SigningException e) {
      assertEquals("Failed to sign the provided bytes", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("403"));
    }
  }

  @Test
  public void sign_serverError_throws() throws IOException {
    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setSignedBlob(expectedSignature);
    mtransportFactory.transport.setSigningErrorResponseCodeAndMessage(HttpStatusCodes.STATUS_CODE_SERVER_ERROR, "Sign Error");

    try {
      byte[] bytes = {0xD, 0xE, 0xA, 0xD};
      targetCredentials.sign(bytes);
      fail("Signing should have failed");
    } catch (SigningException e) {
      assertEquals("Failed to sign the provided bytes", e.getMessage());
      assertNotNull(e.getCause());
      assertTrue(e.getCause().getMessage().contains("500"));
    }
  }

  @Test
  public void hashCode_equals() throws IOException {
    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials credentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    ImpersonatedCredentials otherCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);

    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {

    GoogleCredentials sourceCredentials = getSourceCredentials();
    MockIAMCredentialsServiceTransportFactory mtransportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    mtransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mtransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mtransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
        IMPERSONATED_CLIENT_EMAIL, null, SCOPES, VALID_LIFETIME, mtransportFactory);
    GoogleCredentials deserializedCredentials = serializeAndDeserialize(targetCredentials);
    assertEquals(targetCredentials, deserializedCredentials);
    assertEquals(targetCredentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(targetCredentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  private String getDefaultExpireTime() {
    Date currentDate = new Date();
    Calendar c = Calendar.getInstance();
    c.setTime(currentDate);
    c.add(Calendar.SECOND, VALID_LIFETIME);    
    return new SimpleDateFormat(RFC3339).format(c.getTime());
  }

  private String generateErrorJson(int errorCode, String errorMessage, String errorDomain,
      String errorReason) throws IOException {

    JsonFactory factory = new JacksonFactory();
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    JsonGenerator generator = factory.createJsonGenerator(bout, Charset.defaultCharset());
    generator.enablePrettyPrint();

    generator.writeStartObject();
    generator.writeFieldName("error");

    generator.writeStartObject();
    generator.writeFieldName("code");
    generator.writeNumber(errorCode);
    generator.writeFieldName("message");
    generator.writeString(errorMessage);

    generator.writeFieldName("errors");
    generator.writeStartArray();
    generator.writeStartObject();
    generator.writeFieldName("message");
    generator.writeString(errorMessage);
    generator.writeFieldName("domain");
    generator.writeString(errorDomain);
    generator.writeFieldName("reason");
    generator.writeString(errorReason);
    generator.writeEndObject();
    generator.writeEndArray();

    generator.writeFieldName("status");
    generator.writeString("PERMISSION_DENIED");

    generator.writeEndObject();
    generator.writeEndObject();
    generator.close();
    return bout.toString();
  }
}
