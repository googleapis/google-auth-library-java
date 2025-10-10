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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExternalAccountAuthorizedUserCredentialsTest.MockExternalAccountAuthorizedUserCredentialsTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentialsTest.MockExternalAccountCredentialsTransportFactory;
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
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test case for {@link GoogleCredentials}. */
@RunWith(JUnit4.class)
public class GoogleCredentialsTest extends BaseSerializationTest {

  private static final String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private static final String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private static final String SA_PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private static final String SA_PRIVATE_KEY_PKCS8 =
      ServiceAccountCredentialsTest.PRIVATE_KEY_PKCS8;
  private static final String GDCH_SA_FORMAT_VERSION = GdchCredentials.SUPPORTED_FORMAT_VERSION;
  private static final String GDCH_SA_PROJECT_ID = "gdch-service-account-project-id";
  private static final String GDCH_SA_PRIVATE_KEY_ID = "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private static final String GDCH_SA_PRIVATE_KEY_PKC8 = GdchCredentialsTest.PRIVATE_KEY_PKCS8;
  private static final String GDCH_SA_SERVICE_IDENTITY_NAME =
      "gdch-service-account-service-identity-name";
  private static final URI GDCH_SA_TOKEN_SERVER_URI =
      URI.create("https://service-identity.domain/authenticate");
  private static final String GDCH_SA_CA_CERT_FILE_NAME = "cert.pem";
  private static final String GDCH_SA_CA_CERT_PATH =
      GdchCredentialsTest.class.getClassLoader().getResource(GDCH_SA_CA_CERT_FILE_NAME).getPath();
  private static final URI GDCH_API_AUDIENCE = URI.create("https://gdch-api-audience");
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
  private static final String GOOGLE_DEFAULT_UNIVERSE = "googleapis.com";
  private static final String TPC_UNIVERSE = "foo.bar";

  @After
  public void tearDown() {
    TrustBoundary.setEnvironmentProviderForTest(null);
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
  public void fromStream_unknownType_throws() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    GenericJson json = new GenericJson();
    json.put("type", "unsupported_credential");
    InputStream stream = TestUtils.jsonToInputStream(json);
    try {
      GoogleCredentials.fromStream(stream, transportFactory);
      fail("Should throw if type is unknown.");
    } catch (IOException expected) {
      String expectedError =
          "Error reading credentials from stream, 'type' value "
              + "'unsupported_credential' not recognized. Valid values are 'authorized_user', "
              + "'service_account', 'gdch_service_account', 'external_account', "
              + "'external_account_authorized_user', 'impersonated_service_account'.";
      assertTrue(expected.getMessage().contains(expectedError));
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
  public void fromStream_noType_throws() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    GenericJson json =
        ServiceAccountCredentialsTest.writeServiceAccountJson(
            "project_id", QUOTA_PROJECT, "universe");
    json.remove("type");
    InputStream stream = TestUtils.jsonToInputStream(json);
    try {
      GoogleCredentials.fromStream(stream, transportFactory);
      fail("Should throw if type is unknown.");
    } catch (IOException expected) {
      String expectedError = "Error reading credentials from stream, 'type' field not specified.";
      assertEquals(expectedError, expected.getMessage());
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
  public void fromStream_serviceAccount_noUniverse_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(serviceAccountStream, transportFactory);

    assertNotNull(credentials);
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
    assertEquals(false, credentials.isExplicitUniverseDomain());
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);

    credentials = credentials.createScoped(SCOPES, DEFAULT_SCOPES);
    metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void fromStream_serviceAccount_Universe_noToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, TPC_UNIVERSE);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(serviceAccountStream, transportFactory);

    assertNotNull(credentials);
    assertEquals(TPC_UNIVERSE, credentials.getUniverseDomain());
    assertEquals(true, credentials.isExplicitUniverseDomain());
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    assertNotNull(((ServiceAccountCredentials) credentials).getSelfSignedJwtCredentialsWithScope());
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
  public void fromStream_gdchServiceAccount_correct() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);
    GoogleCredentials credentials =
        GoogleCredentials.fromStream(gdchServiceAccountStream, transportFactory);

    assertNotNull(credentials);
    assertTrue(credentials instanceof GdchCredentials);
    assertEquals(GDCH_SA_PROJECT_ID, ((GdchCredentials) credentials).getProjectId());
    assertEquals(
        GDCH_SA_SERVICE_IDENTITY_NAME, ((GdchCredentials) credentials).getServiceIdentityName());
    assertEquals(GDCH_SA_TOKEN_SERVER_URI, ((GdchCredentials) credentials).getTokenServerUri());
    assertEquals(GDCH_SA_CA_CERT_PATH, ((GdchCredentials) credentials).getCaCertPath());
    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
    assertNull(((GdchCredentials) credentials).getApiAudience());

    credentials = ((GdchCredentials) credentials).createWithGdchAudience(GDCH_API_AUDIENCE);
    assertNotNull(credentials);
    assertTrue(credentials instanceof GdchCredentials);
    assertEquals(GDCH_SA_PROJECT_ID, ((GdchCredentials) credentials).getProjectId());
    assertEquals(
        GDCH_SA_SERVICE_IDENTITY_NAME, ((GdchCredentials) credentials).getServiceIdentityName());
    assertEquals(GDCH_SA_TOKEN_SERVER_URI, ((GdchCredentials) credentials).getTokenServerUri());
    assertEquals(GDCH_SA_CA_CERT_PATH, ((GdchCredentials) credentials).getCaCertPath());
    assertNotNull(((GdchCredentials) credentials).getApiAudience());
  }

  @Test
  public void fromStream_gdchServiceAccountNoFormatVersion_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            null,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(gdchServiceAccountStream, "format_version");
  }

  @Test
  public void fromStream_gdchServiceAccountNoProjectId_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            null,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(gdchServiceAccountStream, "project");
  }

  @Test
  public void fromStream_gdchServiceAccountNoPrivateKeyId_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            null,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(gdchServiceAccountStream, "private_key_id");
  }

  @Test
  public void fromStream_gdchServiceAccountNoPrivateKey_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            null,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(gdchServiceAccountStream, "private_key");
  }

  @Test
  public void fromStream_gdchServiceAccountNoServiceIdentityName_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            null,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(gdchServiceAccountStream, "name");
  }

  @Test
  public void fromStream_gdchServiceAccountNoTokenServerUri_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            null);

    testFromStreamException(gdchServiceAccountStream, "token_uri");
  }

  @Test
  public void fromStream_gdchServiceAccountInvalidFormatVersion_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            "100",
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(
        gdchServiceAccountStream,
        String.format("Only format version %s is supported", GDCH_SA_FORMAT_VERSION));
  }

  @Test
  public void fromStream_gdchServiceAccountInvalidCaCertPath_throws() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            "/path/to/missing/file",
            GDCH_SA_TOKEN_SERVER_URI);

    testFromStreamException(
        gdchServiceAccountStream,
        String.format("Error reading certificate file from CA cert path"));
  }

  @Test
  public void fromStream_userCredentials_providesToken() throws IOException {
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
  public void fromStream_userCredentials_defaultUniverse() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, null);

    GoogleCredentials credentials = GoogleCredentials.fromStream(userStream, transportFactory);

    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void fromStream_userCredentials_NoClientId_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(null, USER_CLIENT_SECRET, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_id");
  }

  @Test
  public void fromStream_userCredentials_NoClientSecret_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, null, REFRESH_TOKEN, QUOTA_PROJECT);

    testFromStreamException(userStream, "client_secret");
  }

  @Test
  public void fromStream_userCredentials_NoRefreshToken_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, null, QUOTA_PROJECT);

    testFromStreamException(userStream, "refresh_token");
  }

  @Test
  public void fromStream_identityPoolCredentials_providesToken() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    InputStream identityPoolCredentialStream =
        IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
            transportFactory.transport.getStsUrl(),
            transportFactory.transport.getMetadataUrl(),
            /* serviceAccountImpersonationUrl= */ null,
            /* serviceAccountImpersonationOptionsMap= */ null);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(identityPoolCredentialStream, transportFactory);

    assertNotNull(credentials);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, transportFactory.transport.getAccessToken());
  }

  @Test
  public void fromStream_identityPoolCredentials_defaultUniverse() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    InputStream identityPoolCredentialStream =
        IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
            transportFactory.transport.getStsUrl(),
            transportFactory.transport.getMetadataUrl(),
            /* serviceAccountImpersonationUrl= */ null,
            /* serviceAccountImpersonationOptionsMap= */ null);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(identityPoolCredentialStream, transportFactory);

    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void fromStream_awsCredentials_providesToken() throws IOException {
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
  public void fromStream_awsCredentials_defaultUniverse() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    InputStream awsCredentialStream =
        AwsCredentialsTest.writeAwsCredentialsStream(
            transportFactory.transport.getStsUrl(),
            transportFactory.transport.getAwsRegionUrl(),
            transportFactory.transport.getAwsCredentialsUrl());

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(awsCredentialStream, transportFactory);

    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void fromStream_pluggableAuthCredentials_providesToken() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    InputStream stream =
        PluggableAuthCredentialsTest.writeCredentialsStream(transportFactory.transport.getStsUrl());

    GoogleCredentials credentials = GoogleCredentials.fromStream(stream, transportFactory);

    assertNotNull(credentials);

    // Create copy with mock executable handler.
    PluggableAuthCredentials copy =
        PluggableAuthCredentials.newBuilder((PluggableAuthCredentials) credentials)
            .setExecutableHandler(options -> "pluggableAuthToken")
            .build();

    copy = copy.createScoped(SCOPES);
    Map<String, List<String>> metadata = copy.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, transportFactory.transport.getAccessToken());
  }

  @Test
  public void fromStream_pluggableAuthCredentials_defaultUniverse() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    InputStream stream =
        PluggableAuthCredentialsTest.writeCredentialsStream(transportFactory.transport.getStsUrl());

    GoogleCredentials credentials = GoogleCredentials.fromStream(stream, transportFactory);

    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void fromStream_externalAccountAuthorizedUserCredentials_providesToken()
      throws IOException {
    MockExternalAccountAuthorizedUserCredentialsTransportFactory transportFactory =
        new MockExternalAccountAuthorizedUserCredentialsTransportFactory();
    InputStream stream =
        TestUtils.jsonToInputStream(
            ExternalAccountAuthorizedUserCredentialsTest.buildJsonCredentials());

    GoogleCredentials credentials = GoogleCredentials.fromStream(stream, transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, transportFactory.transport.getAccessToken());
  }

  @Test
  public void fromStream_externalAccountAuthorizedUserCredentials_defaultUniverse()
      throws IOException {
    MockExternalAccountAuthorizedUserCredentialsTransportFactory transportFactory =
        new MockExternalAccountAuthorizedUserCredentialsTransportFactory();

    GenericJson json = ExternalAccountAuthorizedUserCredentialsTest.buildJsonCredentials();
    json.remove("universe_domain");
    InputStream stream = TestUtils.jsonToInputStream(json);

    GoogleCredentials credentials = GoogleCredentials.fromStream(stream, transportFactory);

    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void fromStream_Impersonation_providesToken_WithQuotaProject() throws IOException {
    MockTokenServerTransportFactory transportFactoryForSource =
        new MockTokenServerTransportFactory();
    transportFactoryForSource.transport.addServiceAccount(
        ImpersonatedCredentialsTest.SA_CLIENT_EMAIL, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    MockIAMCredentialsServiceTransportFactory transportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    transportFactory
        .getTransport()
        .setTargetPrincipal(ImpersonatedCredentialsTest.IMPERSONATED_CLIENT_EMAIL);
    transportFactory.getTransport().setAccessToken(ImpersonatedCredentialsTest.ACCESS_TOKEN);
    transportFactory
        .getTransport()
        .setExpireTime(ImpersonatedCredentialsTest.getDefaultExpireTime());
    transportFactory
        .getTransport()
        .setAccessTokenEndpoint(ImpersonatedCredentialsTest.IMPERSONATION_OVERRIDE_URL);
    transportFactory.getTransport().addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");

    InputStream impersonationCredentialsStream =
        ImpersonatedCredentialsTest.writeImpersonationCredentialsStream(
            ImpersonatedCredentialsTest.IMPERSONATION_OVERRIDE_URL,
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
  public void fromStream_Impersonation_defaultUniverse() throws IOException {
    MockTokenServerTransportFactory transportFactoryForSource =
        new MockTokenServerTransportFactory();
    transportFactoryForSource.transport.addServiceAccount(
        ImpersonatedCredentialsTest.SA_CLIENT_EMAIL, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    MockIAMCredentialsServiceTransportFactory transportFactory =
        new MockIAMCredentialsServiceTransportFactory();

    InputStream impersonationCredentialsStream =
        ImpersonatedCredentialsTest.writeImpersonationCredentialsStream(
            ImpersonatedCredentialsTest.IMPERSONATION_OVERRIDE_URL,
            ImpersonatedCredentialsTest.DELEGATES,
            ImpersonatedCredentialsTest.QUOTA_PROJECT_ID);

    ImpersonatedCredentials credentials =
        (ImpersonatedCredentials)
            GoogleCredentials.fromStream(impersonationCredentialsStream, transportFactoryForSource);
    credentials.setTransportFactory(transportFactory);

    assertEquals(Credentials.GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void fromStream_Impersonation_providesToken_WithoutQuotaProject() throws IOException {
    MockTokenServerTransportFactory transportFactoryForSource =
        new MockTokenServerTransportFactory();
    transportFactoryForSource.transport.addServiceAccount(
        ImpersonatedCredentialsTest.SA_CLIENT_EMAIL, ImpersonatedCredentialsTest.ACCESS_TOKEN);

    MockIAMCredentialsServiceTransportFactory transportFactory =
        new MockIAMCredentialsServiceTransportFactory();
    transportFactory
        .getTransport()
        .setTargetPrincipal(ImpersonatedCredentialsTest.IMPERSONATED_CLIENT_EMAIL);
    transportFactory.getTransport().setAccessToken(ImpersonatedCredentialsTest.ACCESS_TOKEN);
    transportFactory
        .getTransport()
        .setExpireTime(ImpersonatedCredentialsTest.getDefaultExpireTime());
    transportFactory
        .getTransport()
        .setAccessTokenEndpoint(ImpersonatedCredentialsTest.IMPERSONATION_OVERRIDE_URL);
    transportFactory.getTransport().addStatusCodeAndMessage(HttpStatusCodes.STATUS_CODE_OK, "");

    InputStream impersonationCredentialsStream =
        ImpersonatedCredentialsTest.writeImpersonationCredentialsStream(
            ImpersonatedCredentialsTest.IMPERSONATION_OVERRIDE_URL,
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

  @Test
  public void create_withoutUniverse() throws IOException {
    AccessToken token = AccessToken.newBuilder().setTokenValue(ACCESS_TOKEN).build();
    GoogleCredentials credentials = GoogleCredentials.create(token);

    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
    assertEquals(false, credentials.isExplicitUniverseDomain());
  }

  @Test
  public void create_withUniverse() throws IOException {
    AccessToken token = AccessToken.newBuilder().setTokenValue(ACCESS_TOKEN).build();
    GoogleCredentials credentials = GoogleCredentials.create("some-universe", token);

    assertEquals("some-universe", credentials.getUniverseDomain());
    assertEquals(true, credentials.isExplicitUniverseDomain());
  }

  @Test
  public void buildWithQuotaProject() {
    final GoogleCredentials googleCredentials =
        new GoogleCredentials.Builder().setQuotaProjectId("old_quota").build();
    GoogleCredentials withUpdatedQuota = googleCredentials.createWithQuotaProject("new_quota");

    assertEquals("old_quota", googleCredentials.getQuotaProjectId());
    assertEquals("new_quota", withUpdatedQuota.getQuotaProjectId());

    GoogleCredentials withEmptyQuota = googleCredentials.createWithQuotaProject("");
    assertEquals("", withEmptyQuota.getQuotaProjectId());

    GoogleCredentials sameCredentials = googleCredentials.createWithQuotaProject(null);
    assertEquals(null, sameCredentials.getQuotaProjectId());
  }

  @Test
  public void buildWithUniverseDomain() throws IOException {
    final GoogleCredentials original =
        new GoogleCredentials.Builder().setUniverseDomain("universe1").build();
    GoogleCredentials updated = original.toBuilder().setUniverseDomain("universe2").build();

    assertEquals("universe1", original.getUniverseDomain());
    assertEquals(true, original.isExplicitUniverseDomain());
    assertEquals("universe2", updated.getUniverseDomain());
    assertEquals(true, updated.isExplicitUniverseDomain());

    GoogleCredentials withEmpty = original.toBuilder().setUniverseDomain("").build();
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, withEmpty.getUniverseDomain());
    assertEquals(false, withEmpty.isExplicitUniverseDomain());

    GoogleCredentials withNull = original.toBuilder().setUniverseDomain(null).build();
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, withNull.getUniverseDomain());
    assertEquals(false, withNull.isExplicitUniverseDomain());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    final GoogleCredentials testCredentials = new GoogleCredentials.Builder().build();
    GoogleCredentials deserializedCredentials = serializeAndDeserialize(testCredentials);
    assertEquals(testCredentials, deserializedCredentials);
    assertEquals(testCredentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(testCredentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  @Test
  public void toString_containsFields() throws IOException {
    String expectedToString =
        String.format(
            "GoogleCredentials{quotaProjectId=%s, universeDomain=%s, isExplicitUniverseDomain=%s}",
            "some-project", "googleapis.com", false, "[some scope]");
    GoogleCredentials credentials =
        GoogleCredentials.newBuilder().setQuotaProjectId("some-project").build();
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    GoogleCredentials credentials =
        GoogleCredentials.newBuilder().setUniverseDomain("some-domain").build();
    GoogleCredentials otherCredentials =
        GoogleCredentials.newBuilder().setUniverseDomain("some-domain").build();
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void equals_true() throws IOException {
    GoogleCredentials credentials =
        GoogleCredentials.newBuilder().setUniverseDomain("some-domain").build();
    GoogleCredentials otherCredentials =
        GoogleCredentials.newBuilder().setUniverseDomain("some-domain").build();
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
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

  @Test
  public void getCredentialInfo_serviceAccountCredentials() throws IOException {
    InputStream serviceAccountStream =
        ServiceAccountCredentialsTest.writeServiceAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);
    GoogleCredentials credentials = GoogleCredentials.fromStream(serviceAccountStream);
    Map<String, String> credentialInfo = credentials.getCredentialInfo();

    // No need to test the Credential Source as this is fake data
    // Credential Source is tested in DefaultCredentialsProviderTest
    assertEquals("Service Account Credentials", credentialInfo.get("Credential Name"));
    assertEquals(SA_CLIENT_EMAIL, credentialInfo.get("Principal"));
  }

  @Test
  public void getCredentialInfo_userCredentials() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(
            USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN, null);
    GoogleCredentials credentials = GoogleCredentials.fromStream(userStream);
    Map<String, String> credentialInfo = credentials.getCredentialInfo();

    // No need to test the Credential Source as this is fake data
    // Credential Source is tested in DefaultCredentialsProviderTest
    assertEquals("User Credentials", credentialInfo.get("Credential Name"));
    assertNull(credentialInfo.get("Principal"));
  }

  @Test
  public void getCredentialInfo_gdchCredentials() throws IOException {
    InputStream gdchServiceAccountStream =
        GdchCredentialsTest.writeGdchServiceAccountStream(
            GDCH_SA_FORMAT_VERSION,
            GDCH_SA_PROJECT_ID,
            GDCH_SA_PRIVATE_KEY_ID,
            GDCH_SA_PRIVATE_KEY_PKC8,
            GDCH_SA_SERVICE_IDENTITY_NAME,
            GDCH_SA_CA_CERT_PATH,
            GDCH_SA_TOKEN_SERVER_URI);
    GoogleCredentials credentials = GoogleCredentials.fromStream(gdchServiceAccountStream);
    Map<String, String> credentialInfo = credentials.getCredentialInfo();

    // No need to test the Credential Source as this is fake data
    // Credential Source is tested in DefaultCredentialsProviderTest
    assertEquals("GDCH Credentials", credentialInfo.get("Credential Name"));
    assertNull(credentialInfo.get("Principal"));
  }

  @Test
  public void getCredentialInfo_externalAccount() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    InputStream identityPoolCredentialStream =
        IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
            transportFactory.transport.getStsUrl(),
            transportFactory.transport.getMetadataUrl(),
            /* serviceAccountImpersonationUrl= */ null,
            /* serviceAccountImpersonationOptionsMap= */ null);

    GoogleCredentials credentials = GoogleCredentials.fromStream(identityPoolCredentialStream);
    Map<String, String> credentialInfo = credentials.getCredentialInfo();

    // No need to test the Credential Source as this is fake data
    // Credential Source is tested in DefaultCredentialsProviderTest
    assertEquals("External Account Credentials", credentialInfo.get("Credential Name"));
    assertNull(credentialInfo.get("Principal"));
  }

  @Test
  public void getCredentialInfo_externalAccountUserCredentials() throws IOException {
    InputStream externalAccountUserCredentialStream =
        ExternalAccountAuthorizedUserCredentialsTest.writeExternalAccountUserCredentialStream(
            USER_CLIENT_ID,
            USER_CLIENT_SECRET,
            REFRESH_TOKEN,
            "https://sts.googleapis.com/v1/oauthtoken");

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(externalAccountUserCredentialStream);
    Map<String, String> credentialInfo = credentials.getCredentialInfo();

    // No need to test the Credential Source as this is fake data
    // Credential Source is tested in DefaultCredentialsProviderTest
    assertEquals(
        "External Account Authorized User Credentials", credentialInfo.get("Credential Name"));
    assertNull(credentialInfo.get("Principal"));
  }

  @Test
  public void getCredentialInfo_impersonatedServiceAccount() throws IOException {
    InputStream impersonationCredentialsStream =
        ImpersonatedCredentialsTest.writeImpersonationCredentialsStream(
            ImpersonatedCredentialsTest.IMPERSONATION_OVERRIDE_URL,
            ImpersonatedCredentialsTest.DELEGATES,
            null);

    ImpersonatedCredentials credentials =
        (ImpersonatedCredentials) GoogleCredentials.fromStream(impersonationCredentialsStream);
    Map<String, String> credentialInfo = credentials.getCredentialInfo();

    // No need to test the Credential Source as this is fake data
    // Credential Source is tested in DefaultCredentialsProviderTest
    assertEquals("Impersonated Credentials", credentialInfo.get("Credential Name"));
    assertEquals(
        ImpersonatedCredentialsTest.IMPERSONATED_CLIENT_EMAIL, credentialInfo.get("Principal"));
  }

  @Test
  public void trustBoundary_shouldNotCallLookupEndpointWhenDisabled() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "false");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    credentials.getRequestMetadata();
    assertEquals(credentials.getTrustBoundary(), null);
  }

  @Test
  public void trustBoundary_shouldFetchAndReturnTrustBoundaryDataSuccessfully() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    TrustBoundary trustBoundary =
        new TrustBoundary("0x80000", Collections.singletonList("us-central1"));
    transport.setTrustBoundary(trustBoundary);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    Map<String, List<String>> headers = credentials.getRequestMetadata();
    assertEquals(headers.get("x-allowed-locations"), Arrays.asList("0x80000"));
  }

  @Test
  public void trustBoundary_shouldRetryTrustBoundaryLookupOnFailure() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    // This transport will be used for the trust boundary lookup.
    // We will configure it to fail on the first attempt.
    MockTokenServerTransport trustBoundaryTransport = new MockTokenServerTransport();
    trustBoundaryTransport.addResponseErrorSequence(new IOException("Service Unavailable"));
    TrustBoundary trustBoundary =
        new TrustBoundary("0x80000", Collections.singletonList("us-central1"));
    trustBoundaryTransport.setTrustBoundary(trustBoundary);

    // This transport will be used for the access token refresh.
    // It will succeed.
    MockTokenServerTransport accessTokenTransport = new MockTokenServerTransport();
    accessTokenTransport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            // Use a custom transport factory that returns the correct transport for each endpoint.
            .setHttpTransportFactory(
                () ->
                    new com.google.api.client.testing.http.MockHttpTransport() {
                      @Override
                      public com.google.api.client.http.LowLevelHttpRequest buildRequest(
                          String method, String url) throws IOException {
                        if (url.endsWith("/allowedLocations")) {
                          return trustBoundaryTransport.buildRequest(method, url);
                        }
                        return accessTokenTransport.buildRequest(method, url);
                      }
                    })
            .setScopes(SCOPES)
            .build();

    Map<String, List<String>> headers = credentials.getRequestMetadata();
    assertEquals(headers.get("x-allowed-locations"), Arrays.asList("0x80000"));
  }

  @Test
  public void trustBoundary_refreshShouldReturnNullWhenDefaultDomainIsNotGoogleApis()
      throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .setUniverseDomain("other.universe")
            .build();

    credentials.refreshAccessToken();
    assertNull(credentials.getTrustBoundary());
  }

  @Test
  public void trustBoundary_refreshShouldThrowWhenNoValidAccessTokenIsPassed() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    // Return an expired access token.
    transport.addServiceAccount(SA_CLIENT_EMAIL, "expired-token");
    transport.setExpiresInSeconds(-1);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    try {
      credentials.getRequestMetadata();
      fail("Should have thrown an IOException.");
    } catch (IllegalArgumentException e) {
      assertEquals("The provided access token is expired.", e.getMessage());
    }
  }

  @Test
  public void trustBoundary_refreshShouldReturnNoOpIfResponseFromLookupIsNoOp() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    transport.setTrustBoundary(new TrustBoundary("0x0", Collections.emptyList()));

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    credentials.refresh();

    assertTrue(credentials.getTrustBoundary().isNoOp());
  }

  @Test
  public void trustBoundary_refreshShouldReturnNoOpAndNotCallLookupEndpointWhenCachedIsNoOp()
      throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    transport.setTrustBoundary(new TrustBoundary("0x0", Collections.emptyList()));

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    // First refresh to cache the no-op trust boundary.
    credentials.refresh();

    // Set trust boundary to a valid non No-Op value.
    transport.setTrustBoundary(
        new TrustBoundary("0x80000", Collections.singletonList("us-central1")));

    // Refresh trust boundaries
    credentials.refresh();

    // Check whether the trust boundaries are still no_op.
    assertTrue(credentials.getTrustBoundary().isNoOp());
  }

  @Test
  public void trustBoundary_refreshShouldReturnCachedTbIfCallToLookupFails() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    TrustBoundary trustBoundary =
        new TrustBoundary("0x80000", Collections.singletonList("us-central1"));
    transport.setTrustBoundary(trustBoundary);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    // First refresh to cache the trust boundary.
    credentials.refresh();

    // Set the trust boundary to be returned to null so we get an exception.
    transport.setTrustBoundary(null);

    credentials.refresh();

    assertEquals(
        trustBoundary.getEncodedLocations(), credentials.getTrustBoundary().getEncodedLocations());
  }

  @Test
  public void trustBoundary_refreshShouldThrowIfCallToLookupFailsAndNoCachedTb()
      throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    transport.addResponseErrorSequence(new IOException("Service Unavailable"));

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    try {
      credentials.refresh();
      fail("Should have thrown an IOException.");
    } catch (IOException e) {
      assertTrue(
          e.getMessage()
              .contains("Failed to refresh trust boundary and no cached value is available."));
    }
  }

  @Test
  public void trustBoundary_refreshShouldThrowInCaseOfMalformedResponse() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    // The transport will return a response with no encodedLocations field.
    transport.setTrustBoundary(new TrustBoundary(null, Collections.emptyList()));

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    try {
      credentials.refresh();
      fail("Should have thrown an IOException.");
    } catch (IOException e) {
      assertTrue(
          e.getMessage()
              .contains("Failed to refresh trust boundary and no cached value is available."));
    }
  }

  @Test
  public void trustBoundary_getRequestHeadersShouldAttachTrustBoundaryHeader() throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    TrustBoundary trustBoundary =
        new TrustBoundary("0x80000", Collections.singletonList("us-central1"));
    transport.setTrustBoundary(trustBoundary);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    Map<String, List<String>> headers = credentials.getRequestMetadata();

    assertEquals(Arrays.asList("0x80000"), headers.get("x-allowed-locations"));
  }

  @Test
  public void trustBoundary_getRequestHeadersShouldAttachEmptyStringTbHeaderInCaseOfNoOp()
      throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    transport.setTrustBoundary(new TrustBoundary("0x0", Collections.emptyList()));

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .build();

    Map<String, List<String>> headers = credentials.getRequestMetadata();

    assertEquals(Arrays.asList(""), headers.get("x-allowed-locations"));
  }

  @Test
  public void trustBoundary_getRequestHeadersShouldNotAttachTbHeaderInCaseOfNonGduUniverse()
      throws IOException {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    TrustBoundary.setEnvironmentProviderForTest(environmentProvider);
    environmentProvider.setEnv(TrustBoundary.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED_ENV_VAR, "true");

    MockTokenServerTransport transport = new MockTokenServerTransport();
    transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);

    ServiceAccountCredentials credentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(SA_CLIENT_EMAIL)
            .setPrivateKey(OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId(SA_PRIVATE_KEY_ID)
            .setHttpTransportFactory(() -> transport)
            .setScopes(SCOPES)
            .setUniverseDomain("other.universe")
            .build();

    Map<String, List<String>> headers = credentials.getRequestMetadata();

    assertNull(headers.get("x-allowed-locations"));
  }
}
