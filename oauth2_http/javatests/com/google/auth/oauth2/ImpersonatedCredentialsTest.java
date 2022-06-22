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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonGenerator;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebToken.Payload;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.util.Clock;
import com.google.auth.ServiceAccountSigner.SigningException;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Test case for {@link ImpersonatedCredentials}. */
class ImpersonatedCredentialsTest extends BaseSerializationTest {

  public static final String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private static final String SA_PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  static final String SA_PRIVATE_KEY_PKCS8 =
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

  // Id Token provided by the default IAM API that does not include the "email" claim
  public static final String STANDARD_ID_TOKEN =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOGI3OTIy"
          + "OTNhZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIi"
          + "LCJhenAiOiIxMDIxMDE1NTA4MzQyMDA3MDg1NjgiLCJleHAiOjE1NjQ1MzI5NzIsImlhdCI6MTU2NDUyOTM3Miw"
          + "iaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTAyMTAxNTUwODM0MjAwNzA4NTY4In"
          + "0.redacted";

  // Id Token provided by the default IAM API that includes the "email" claim
  public static final String TOKEN_WITH_EMAIL =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRmMzc1ODkwOGI3OTIy"
          + "OTNhZDk3N2EwYjk5MWQ5OGE3N2Y0ZWVlY2QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIi"
          + "LCJhenAiOiIxMDIxMDE1NTA4MzQyMDA3MDg1NjgiLCJlbWFpbCI6ImltcGVyc29uYXRlZC1hY2NvdW50QGZhYmx"
          + "lZC1yYXktMTA0MTE3LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cC"
          + "I6MTU2NDUzMzA0MiwiaWF0IjoxNTY0NTI5NDQyLCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iL"
          + "CJzdWIiOiIxMDIxMDE1NTA4MzQyMDA3MDg1NjgifQ.redacted";
  public static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";

  private static final Set<String> IMMUTABLE_SCOPES_SET = ImmutableSet.of("scope1", "scope2");
  private static final String PROJECT_ID = "project-id";
  public static final String IMPERSONATED_CLIENT_EMAIL =
      "impersonated-account@iam.gserviceaccount.com";
  private static final List<String> IMMUTABLE_SCOPES_LIST = ImmutableList.of("scope1", "scope2");
  private static final int VALID_LIFETIME = 300;
  private static final int INVALID_LIFETIME = 43210;
  private static JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

  private static final String RFC3339 = "yyyy-MM-dd'T'HH:mm:ssX";
  public static final String DEFAULT_IMPERSONATION_URL =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
          + IMPERSONATED_CLIENT_EMAIL
          + ":generateAccessToken";
  public static final String IMPERSONATION_URL =
      "https://us-east1-iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
          + IMPERSONATED_CLIENT_EMAIL
          + ":generateAccessToken";
  private static final String USER_ACCOUNT_CLIENT_ID =
      "76408650-6qr441hur.apps.googleusercontent.com";
  private static final String USER_ACCOUNT_CLIENT_SECRET = "d-F499q74hFpdHD0T5";
  public static final String QUOTA_PROJECT_ID = "quota-project-id";
  private static final String REFRESH_TOKEN = "dasdfasdffa4ffdfadgyjirasdfadsft";
  public static final List<String> DELEGATES =
      Arrays.asList("sa1@developer.gserviceaccount.com", "sa2@developer.gserviceaccount.com");

  static class MockIAMCredentialsServiceTransportFactory implements HttpTransportFactory {

    MockIAMCredentialsServiceTransport transport = new MockIAMCredentialsServiceTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  private GoogleCredentials sourceCredentials;
  private MockIAMCredentialsServiceTransportFactory mockTransportFactory;

  @BeforeEach
  void setup() throws IOException {
    sourceCredentials = getSourceCredentials();
    mockTransportFactory = new MockIAMCredentialsServiceTransportFactory();
  }

  private GoogleCredentials getSourceCredentials() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountCredentials sourceCredentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(privateKey)
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setScopes(IMMUTABLE_SCOPES_LIST)
            .setProjectId(PROJECT_ID)
            .setHttpTransportFactory(transportFactory)
            .build();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);

    return sourceCredentials;
  }

  @Test
  void fromJson_userAsSource_WithQuotaProjectId() throws IOException {
    GenericJson json =
        buildImpersonationCredentialsJson(
            IMPERSONATION_URL,
            DELEGATES,
            QUOTA_PROJECT_ID,
            USER_ACCOUNT_CLIENT_ID,
            USER_ACCOUNT_CLIENT_SECRET,
            REFRESH_TOKEN);
    ImpersonatedCredentials credentials =
        ImpersonatedCredentials.fromJson(json, mockTransportFactory);
    assertEquals(IMPERSONATED_CLIENT_EMAIL, credentials.getAccount());
    assertEquals(IMPERSONATION_URL, credentials.getIamEndpointOverride());
    assertEquals(QUOTA_PROJECT_ID, credentials.getQuotaProjectId());
    assertEquals(DELEGATES, credentials.getDelegates());
    assertEquals(new ArrayList<String>(), credentials.getScopes());
    assertEquals(3600, credentials.getLifetime());
    GoogleCredentials sourceCredentials = credentials.getSourceCredentials();
    assertTrue(sourceCredentials instanceof UserCredentials);
  }

  @Test
  void fromJson_userAsSource_WithoutQuotaProjectId() throws IOException {
    GenericJson json =
        buildImpersonationCredentialsJson(
            IMPERSONATION_URL,
            DELEGATES,
            null,
            USER_ACCOUNT_CLIENT_ID,
            USER_ACCOUNT_CLIENT_SECRET,
            REFRESH_TOKEN);
    ImpersonatedCredentials credentials =
        ImpersonatedCredentials.fromJson(json, mockTransportFactory);
    assertEquals(IMPERSONATED_CLIENT_EMAIL, credentials.getAccount());
    assertEquals(IMPERSONATION_URL, credentials.getIamEndpointOverride());
    assertNull(credentials.getQuotaProjectId());
    assertEquals(DELEGATES, credentials.getDelegates());
    assertEquals(new ArrayList<String>(), credentials.getScopes());
    assertEquals(3600, credentials.getLifetime());
    GoogleCredentials sourceCredentials = credentials.getSourceCredentials();
    assertTrue(sourceCredentials instanceof UserCredentials);
  }

  @Test
  void fromJson_userAsSource_MissingDelegatesField() throws IOException {
    GenericJson json =
        buildImpersonationCredentialsJson(
            IMPERSONATION_URL,
            DELEGATES,
            null,
            USER_ACCOUNT_CLIENT_ID,
            USER_ACCOUNT_CLIENT_SECRET,
            REFRESH_TOKEN);
    json.remove("delegates");
    ImpersonatedCredentials credentials =
        ImpersonatedCredentials.fromJson(json, mockTransportFactory);
    assertEquals(IMPERSONATED_CLIENT_EMAIL, credentials.getAccount());
    assertEquals(IMPERSONATION_URL, credentials.getIamEndpointOverride());
    assertNull(credentials.getQuotaProjectId());
    assertEquals(new ArrayList<String>(), credentials.getDelegates());
    assertEquals(new ArrayList<String>(), credentials.getScopes());
    assertEquals(3600, credentials.getLifetime());
    GoogleCredentials sourceCredentials = credentials.getSourceCredentials();
    assertTrue(sourceCredentials instanceof UserCredentials);
  }

  @Test
  void fromJson_ServiceAccountAsSource() throws IOException {
    GenericJson json =
        buildImpersonationCredentialsJson(IMPERSONATION_URL, DELEGATES, QUOTA_PROJECT_ID);
    ImpersonatedCredentials credentials =
        ImpersonatedCredentials.fromJson(json, mockTransportFactory);
    assertEquals(IMPERSONATED_CLIENT_EMAIL, credentials.getAccount());
    assertEquals(IMPERSONATION_URL, credentials.getIamEndpointOverride());
    assertEquals(QUOTA_PROJECT_ID, credentials.getQuotaProjectId());
    assertEquals(DELEGATES, credentials.getDelegates());
    assertEquals(new ArrayList<String>(), credentials.getScopes());
    assertEquals(3600, credentials.getLifetime());
    GoogleCredentials sourceCredentials = credentials.getSourceCredentials();
    assertTrue(sourceCredentials instanceof ServiceAccountCredentials);
  }

  @Test
  void fromJson_InvalidFormat() throws IOException {
    GenericJson json = buildInvalidCredentialsJson();
    CredentialFormatException exception =
        assertThrows(
            CredentialFormatException.class,
            () -> ImpersonatedCredentials.fromJson(json, mockTransportFactory),
            "An exception should be thrown.");
    assertEquals("An invalid input stream was provided.", exception.getMessage());
  }

  @Test
  void createScopedRequired_True() {
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            new ArrayList<String>(),
            VALID_LIFETIME,
            mockTransportFactory);
    assertTrue(targetCredentials.createScopedRequired());
  }

  @Test
  void createScopedRequired_False() {
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);
    assertFalse(targetCredentials.createScopedRequired());
  }

  @Test
  void createScoped() {
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            DELEGATES,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory,
            QUOTA_PROJECT_ID);

    ImpersonatedCredentials scoped_credentials =
        (ImpersonatedCredentials) targetCredentials.createScoped(IMMUTABLE_SCOPES_LIST);
    assertEquals(targetCredentials.getAccount(), scoped_credentials.getAccount());
    assertEquals(targetCredentials.getDelegates(), scoped_credentials.getDelegates());
    assertEquals(targetCredentials.getLifetime(), scoped_credentials.getLifetime());
    assertEquals(
        targetCredentials.getSourceCredentials(), scoped_credentials.getSourceCredentials());
    assertEquals(targetCredentials.getQuotaProjectId(), scoped_credentials.getQuotaProjectId());
    assertEquals(Arrays.asList("scope1", "scope2"), scoped_credentials.getScopes());
  }

  @Test
  void createScopedWithImmutableScopes() {
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            DELEGATES,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory,
            QUOTA_PROJECT_ID);

    ImpersonatedCredentials scoped_credentials =
        (ImpersonatedCredentials) targetCredentials.createScoped(IMMUTABLE_SCOPES_SET);
    assertEquals(targetCredentials.getAccount(), scoped_credentials.getAccount());
    assertEquals(targetCredentials.getDelegates(), scoped_credentials.getDelegates());
    assertEquals(targetCredentials.getLifetime(), scoped_credentials.getLifetime());
    assertEquals(
        targetCredentials.getSourceCredentials(), scoped_credentials.getSourceCredentials());
    assertEquals(targetCredentials.getQuotaProjectId(), scoped_credentials.getQuotaProjectId());
    assertEquals(Arrays.asList("scope1", "scope2"), scoped_credentials.getScopes());
  }

  @Test
  void createScopedWithIamEndpointOverride() {
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            DELEGATES,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory,
            QUOTA_PROJECT_ID,
            IMPERSONATION_URL);

    ImpersonatedCredentials scoped_credentials =
        (ImpersonatedCredentials) targetCredentials.createScoped(IMMUTABLE_SCOPES_SET);
    assertEquals(
        targetCredentials.getIamEndpointOverride(), scoped_credentials.getIamEndpointOverride());
  }

  @Test
  void refreshAccessToken_unauthorized() throws IOException {

    String expectedMessage = "The caller does not have permission";
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setTokenResponseErrorCode(
        HttpStatusCodes.STATUS_CODE_UNAUTHORIZED);
    mockTransportFactory.transport.setTokenResponseErrorContent(
        generateErrorJson(
            HttpStatusCodes.STATUS_CODE_UNAUTHORIZED, expectedMessage, "global", "forbidden"));
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    IOException exception =
        assertThrows(
            IOException.class,
            () -> targetCredentials.refreshAccessToken().getTokenValue(),
            String.format("Should throw exception with message containing '%s'", expectedMessage));
    assertEquals("Error requesting access token", exception.getMessage());
    assertTrue(exception.getCause().getMessage().contains(expectedMessage));
  }

  @Test
  void refreshAccessToken_malformedTarget() throws IOException {

    String invalidTargetEmail = "foo";
    String expectedMessage = "Request contains an invalid argument";
    mockTransportFactory.transport.setTargetPrincipal(invalidTargetEmail);
    mockTransportFactory.transport.setTokenResponseErrorCode(
        HttpStatusCodes.STATUS_CODE_BAD_REQUEST);
    mockTransportFactory.transport.setTokenResponseErrorContent(
        generateErrorJson(
            HttpStatusCodes.STATUS_CODE_BAD_REQUEST, expectedMessage, "global", "badRequest"));
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            invalidTargetEmail,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    IOException exception =
        assertThrows(
            IOException.class,
            () -> targetCredentials.refreshAccessToken().getTokenValue(),
            String.format("Should throw exception with message containing '%s'", expectedMessage));
    assertEquals("Error requesting access token", exception.getMessage());
    assertTrue(exception.getCause().getMessage().contains(expectedMessage));
  }

  @Test
  void credential_with_zero_lifetime() throws IllegalStateException {
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials, IMPERSONATED_CLIENT_EMAIL, null, IMMUTABLE_SCOPES_LIST, 0);
    assertEquals(3600, targetCredentials.getLifetime());
  }

  @Test
  void credential_with_invalid_lifetime() throws IOException, IllegalStateException {

    IllegalStateException exception =
        assertThrows(
            IllegalStateException.class,
            () -> {
              ImpersonatedCredentials targetCredentials =
                  ImpersonatedCredentials.create(
                      sourceCredentials,
                      IMPERSONATED_CLIENT_EMAIL,
                      null,
                      IMMUTABLE_SCOPES_LIST,
                      INVALID_LIFETIME);
              targetCredentials.refreshAccessToken().getTokenValue();
            },
            String.format(
                "Should throw exception with message containing '%s'",
                "lifetime must be less than or equal to 43200"));
    assertTrue(exception.getMessage().contains("lifetime must be less than or equal to 43200"));
  }

  @Test
  void credential_with_invalid_scope() throws IOException, IllegalStateException {

    IllegalStateException exception =
        assertThrows(
            IllegalStateException.class,
            () -> {
              ImpersonatedCredentials targetCredentials =
                  ImpersonatedCredentials.create(
                      sourceCredentials, IMPERSONATED_CLIENT_EMAIL, null, null, VALID_LIFETIME);
              targetCredentials.refreshAccessToken().getTokenValue();
            },
            String.format(
                "Should throw exception with message containing '%s'", "Scopes cannot be null"));
    assertTrue(exception.getMessage().contains("Scopes cannot be null"));
  }

  @Test
  void refreshAccessToken_success() throws IOException, IllegalStateException {

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
    assertEquals(DEFAULT_IMPERSONATION_URL, mockTransportFactory.transport.getRequest().getUrl());
  }

  @Test
  void refreshAccessToken_endpointOverride() throws IOException, IllegalStateException {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    mockTransportFactory.transport.setAccessTokenEndpoint(IMPERSONATION_URL);

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory,
            QUOTA_PROJECT_ID,
            IMPERSONATION_URL);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
    assertEquals(IMPERSONATION_URL, mockTransportFactory.transport.getRequest().getUrl());
  }

  @Test
  void getRequestMetadata_withQuotaProjectId() throws IOException, IllegalStateException {

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory,
            QUOTA_PROJECT_ID);

    Map<String, List<String>> metadata = targetCredentials.getRequestMetadata();
    assertTrue(metadata.containsKey("x-goog-user-project"));
    List<String> headerValues = metadata.get("x-goog-user-project");
    assertEquals(1, headerValues.size());
    assertEquals(QUOTA_PROJECT_ID, headerValues.get(0));
  }

  @Test
  void getRequestMetadata_withoutQuotaProjectId() throws IOException, IllegalStateException {

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    Map<String, List<String>> metadata = targetCredentials.getRequestMetadata();
    assertFalse(metadata.containsKey("x-goog-user-project"));
  }

  @Test
  void refreshAccessToken_delegates_success() throws IOException, IllegalStateException {

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    List<String> delegates = Arrays.asList("delegate-account@iam.gserviceaccount.com");
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            delegates,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
  }

  @Test
  void refreshAccessToken_GMT_dateParsedCorrectly() throws IOException, IllegalStateException {

    Calendar c = Calendar.getInstance();
    c.add(Calendar.SECOND, VALID_LIFETIME);

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getFormattedTime(c.getTime()));
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
    assertEquals(c.getTime().toInstant().truncatedTo(ChronoUnit.SECONDS).toEpochMilli(),
        targetCredentials.refreshAccessToken().getExpirationTimeMillis());
    assertEquals(DEFAULT_IMPERSONATION_URL, mockTransportFactory.transport.getRequest().getUrl());
  }

  @Test
  void refreshAccessToken_PDT_dateParsedCorrectly() throws IOException, IllegalStateException {

    Calendar c = Calendar.getInstance();
    c.add(Calendar.SECOND, VALID_LIFETIME);

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getFormattedTime(c.getTime(), TimeZone.getTimeZone("PDT")));
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(ACCESS_TOKEN, targetCredentials.refreshAccessToken().getTokenValue());
    assertEquals(c.getTime().toInstant().truncatedTo(ChronoUnit.SECONDS).toEpochMilli(),
        targetCredentials.refreshAccessToken().getExpirationTimeMillis());
    assertEquals(DEFAULT_IMPERSONATION_URL, mockTransportFactory.transport.getRequest().getUrl());
  }

  @Test
  void refreshAccessToken_invalidDate() throws IllegalStateException {

    String expectedMessage = "Unparseable date";
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken("foo");
    mockTransportFactory.transport.setExpireTime("1973-09-29T15:01:23");
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    IOException exception =
        assertThrows(
            IOException.class,
            () -> targetCredentials.refreshAccessToken().getTokenValue(),
            String.format("Should throw exception with message containing '%s'", expectedMessage));
    assertTrue(exception.getMessage().contains(expectedMessage));
  }

  @Test
  void getAccount_sameAs() {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(IMPERSONATED_CLIENT_EMAIL, targetCredentials.getAccount());
  }

  @Test
  void sign_sameAs() {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));
  }

  @Test
  void sign_requestIncludesDelegates() throws IOException {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            ImmutableList.of("delegate@example.com"),
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));

    MockLowLevelHttpRequest request = mockTransportFactory.transport.getRequest();
    GenericJson body =
        JSON_FACTORY
            .createJsonParser(request.getContentAsString())
            .parseAndClose(GenericJson.class);
    List<String> delegates = new ArrayList<>();
    delegates.add("delegate@example.com");
    assertEquals(delegates, body.get("delegates"));
  }

  @Test
  void sign_usesSourceCredentials() {
    Calendar c = Calendar.getInstance();
    c.add(Calendar.DATE, 1);
    Date expiry = c.getTime();
    GoogleCredentials sourceCredentials =
        new GoogleCredentials.Builder()
            .setAccessToken(new AccessToken("source-token", expiry))
            .build();

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            ImmutableList.of("delegate@example.com"),
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setSignedBlob(expectedSignature);

    assertArrayEquals(expectedSignature, targetCredentials.sign(expectedSignature));

    MockLowLevelHttpRequest request = mockTransportFactory.transport.getRequest();
    assertEquals("Bearer source-token", request.getFirstHeaderValue("Authorization"));
  }

  @Test
  void sign_accessDenied_throws() {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setSignedBlob(expectedSignature);
    mockTransportFactory.transport.setErrorResponseCodeAndMessage(
        HttpStatusCodes.STATUS_CODE_FORBIDDEN, "Sign Error");

    byte[] bytes = {0xD, 0xE, 0xA, 0xD};
    SigningException exception =
        assertThrows(
            SigningException.class,
            () -> targetCredentials.sign(bytes),
            "Signing should have failed");
    assertEquals("Failed to sign the provided bytes", exception.getMessage());
    assertNotNull(exception.getCause());
    assertTrue(exception.getCause().getMessage().contains("403"));
  }

  @Test
  void sign_serverError_throws() {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());
    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    byte[] expectedSignature = {0xD, 0xE, 0xA, 0xD};

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setSignedBlob(expectedSignature);
    mockTransportFactory.transport.setErrorResponseCodeAndMessage(
        HttpStatusCodes.STATUS_CODE_SERVER_ERROR, "Sign Error");

    byte[] bytes = {0xD, 0xE, 0xA, 0xD};
    SigningException exception =
        assertThrows(
            SigningException.class,
            () -> targetCredentials.sign(bytes),
            "Signing should have failed");
    assertEquals("Failed to sign the provided bytes", exception.getMessage());
    assertNotNull(exception.getCause());
    assertTrue(exception.getCause().getMessage().contains("500"));
  }

  @Test
  void idTokenWithAudience_sameAs() throws IOException {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    mockTransportFactory.transport.setIdToken(STANDARD_ID_TOKEN);

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(targetCredentials)
            .setTargetAudience(targetAudience)
            .build();
    tokenCredential.refresh();
    assertEquals(STANDARD_ID_TOKEN, tokenCredential.getAccessToken().getTokenValue());
    assertEquals(STANDARD_ID_TOKEN, tokenCredential.getIdToken().getTokenValue());
    assertEquals(
        targetAudience,
        (String) tokenCredential.getIdToken().getJsonWebSignature().getPayload().getAudience());
  }

  @Test
  void idTokenWithAudience_withEmail() throws IOException {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    mockTransportFactory.transport.setIdToken(TOKEN_WITH_EMAIL);

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(targetCredentials)
            .setTargetAudience(targetAudience)
            .setOptions(Arrays.asList(IdTokenProvider.Option.INCLUDE_EMAIL))
            .build();
    tokenCredential.refresh();
    assertEquals(TOKEN_WITH_EMAIL, tokenCredential.getAccessToken().getTokenValue());
    Payload p = tokenCredential.getIdToken().getJsonWebSignature().getPayload();
    assertTrue(p.containsKey("email"));
  }

  @Test
  void idToken_withServerError() {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    mockTransportFactory.transport.setIdToken(STANDARD_ID_TOKEN);
    mockTransportFactory.transport.setErrorResponseCodeAndMessage(
        HttpStatusCodes.STATUS_CODE_SERVER_ERROR, "Internal Server Error");

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(targetCredentials)
            .setTargetAudience(targetAudience)
            .build();

    IOException exception = assertThrows(IOException.class, tokenCredential::refresh);
    assertTrue(exception.getMessage().contains("Error code 500 trying to getIDToken"));
  }

  @Test
  void idToken_withOtherError() {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    mockTransportFactory.transport.setIdToken(STANDARD_ID_TOKEN);
    mockTransportFactory.transport.setErrorResponseCodeAndMessage(
        HttpStatusCodes.STATUS_CODE_MOVED_PERMANENTLY, "Redirect");

    String targetAudience = "https://foo.bar";
    IdTokenCredentials tokenCredential =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(targetCredentials)
            .setTargetAudience(targetAudience)
            .build();

    IOException exception = assertThrows(IOException.class, tokenCredential::refresh);
    assertTrue(exception.getMessage().contains("Unexpected Error code 301 trying to getIDToken"));
  }

  @Test
  void hashCode_equals() throws IOException {
    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials credentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    ImpersonatedCredentials otherCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);

    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  void serialize() throws IOException, ClassNotFoundException {

    mockTransportFactory.transport.setTargetPrincipal(IMPERSONATED_CLIENT_EMAIL);
    mockTransportFactory.transport.setAccessToken(ACCESS_TOKEN);
    mockTransportFactory.transport.setExpireTime(getDefaultExpireTime());

    ImpersonatedCredentials targetCredentials =
        ImpersonatedCredentials.create(
            sourceCredentials,
            IMPERSONATED_CLIENT_EMAIL,
            null,
            IMMUTABLE_SCOPES_LIST,
            VALID_LIFETIME,
            mockTransportFactory);
    GoogleCredentials deserializedCredentials = serializeAndDeserialize(targetCredentials);
    assertEquals(targetCredentials, deserializedCredentials);
    assertEquals(targetCredentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(targetCredentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  public static String getDefaultExpireTime() {
    Calendar c = Calendar.getInstance();
    c.add(Calendar.SECOND, VALID_LIFETIME);
    return getFormattedTime(c.getTime());
  }

  /**
   Given a {@link Date}, it will return a string of the date
   formatted like <b>yyyy-MM-dd'T'HH:mm:ss'Z'</b>
   */
  private static String getFormattedTime(final Date date) {
    //Set timezone to GMT since that's the TZ used in the response from the service impersonation token exchange
    return getFormattedTime(date, TimeZone.getTimeZone("GMT"));
  }

  /**
   Given a {@link Date} and a desired {@link TimeZone}, it will return a string of the date
   formatted like <b>yyyy-MM-dd'T'HH:mm:ssX'</b> where X represents a timezone
   code following RFC3339 standard
   */
  private static String getFormattedTime(final Date date, final TimeZone timeZone) {
    final DateFormat formatter = new SimpleDateFormat(RFC3339);
    formatter.setTimeZone(timeZone);
    return formatter.format(date);
  }

  private String generateErrorJson(
      int errorCode, String errorMessage, String errorDomain, String errorReason)
      throws IOException {

    JsonFactory factory = new GsonFactory();
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

  static GenericJson buildImpersonationCredentialsJson(
      String impersonationUrl,
      List<String> delegates,
      String quotaProjectId,
      String sourceClientId,
      String sourceClientSecret,
      String sourceRefreshToken) {
    GenericJson sourceJson = new GenericJson();

    sourceJson.put("client_id", sourceClientId);
    sourceJson.put("client_secret", sourceClientSecret);
    sourceJson.put("refresh_token", sourceRefreshToken);
    sourceJson.put("type", "authorized_user");
    GenericJson json = new GenericJson();

    json.put("service_account_impersonation_url", impersonationUrl);
    json.put("delegates", delegates);
    if (quotaProjectId != null) {
      json.put("quota_project_id", quotaProjectId);
    }
    json.put("source_credentials", sourceJson);
    json.put("type", "impersonated_service_account");
    return json;
  }

  static GenericJson buildImpersonationCredentialsJson(
      String impersonationUrl, List<String> delegates, String quotaProjectId) {
    GenericJson sourceJson = new GenericJson();
    sourceJson.put("type", "service_account");
    sourceJson.put("project_id", PROJECT_ID);
    sourceJson.put("private_key_id", SA_PRIVATE_KEY_ID);
    sourceJson.put("private_key", SA_PRIVATE_KEY_PKCS8);
    sourceJson.put("client_email", SA_CLIENT_EMAIL);
    sourceJson.put("client_id", "10848832332323213");
    sourceJson.put("auth_uri", "https://oauth2.googleapis.com/o/oauth2/auth");
    sourceJson.put("token_uri", "https://oauth2.googleapis.com/token");
    sourceJson.put("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs");
    sourceJson.put(
        "client_x509_cert_url",
        "https://www.googleapis.com/robot/v1/metadata/x509/chaoren-test-sc%40cloudsdktest.iam.gserviceaccount.com");

    GenericJson json = new GenericJson();
    json.put("source_credentials", sourceJson);
    json.put("service_account_impersonation_url", impersonationUrl);
    json.put("delegates", delegates);
    if (quotaProjectId != null) {
      json.put("quota_project_id", quotaProjectId);
    }
    json.put("type", "impersonated_service_account");
    return json;
  }

  static GenericJson buildInvalidCredentialsJson() {
    GenericJson json = new GenericJson();
    json.put("service_account_impersonation_url", "mock_url");
    return json;
  }

  static InputStream writeImpersonationCredentialsStream(
      String impersonationUrl, List<String> delegates, String quotaProjectId) throws IOException {
    GenericJson json =
        buildImpersonationCredentialsJson(impersonationUrl, delegates, quotaProjectId);
    return TestUtils.jsonToInputStream(json);
  }
}
