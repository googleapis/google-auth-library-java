/*
 * Copyright 2021 Google LLC
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static com.google.auth.oauth2.MockExternalAccountCredentialsTransport.SERVICE_ACCOUNT_IMPERSONATION_URL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExternalAccountCredentialsTest.TestExternalAccountCredentials.TestCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Tests for {@link ExternalAccountCredentials}. */
public class ExternalAccountCredentialsTest {

  private static final String STS_URL = "https://sts.googleapis.com";

  private static final Map<String, Object> FILE_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put("file", "file");
        }
      };

  static class MockExternalAccountCredentialsTransportFactory implements HttpTransportFactory {

    MockExternalAccountCredentialsTransport transport =
        new MockExternalAccountCredentialsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  private MockExternalAccountCredentialsTransportFactory transportFactory;

  @BeforeEach
  void setup() {
    transportFactory = new MockExternalAccountCredentialsTransportFactory();
  }

  @Test
  void fromStream_identityPoolCredentials() throws IOException {
    GenericJson json = buildJsonIdentityPoolCredential();

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof IdentityPoolCredentials);
  }

  @Test
  void fromStream_awsCredentials() throws IOException {
    GenericJson json = buildJsonAwsCredential();

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof AwsCredentials);
  }

  @Test
  void fromStream_invalidStream_throws() {
    GenericJson json = buildJsonAwsCredential();

    json.put("audience", new HashMap<>());

    CredentialFormatException exception =
        assertThrows(
            CredentialFormatException.class,
            () -> ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json)),
            "Should fail.");
    assertEquals("An invalid input stream was provided.", exception.getMessage());
  }

  @Test
  void fromStream_nullTransport_throws() {
    assertThrows(
        NullPointerException.class,
        () -> {
          ExternalAccountCredentials.fromStream(
              new ByteArrayInputStream("foo".getBytes()), /* transportFactory= */ null);
        },
        "NullPointerException should be thrown.");
  }

  @Test
  void fromStream_nullStream_throws() {
    assertThrows(
        NullPointerException.class,
        () -> {
          ExternalAccountCredentials.fromStream(
              /* credentialsStream= */ null, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
        },
        "NullPointerException should be thrown.");
  }

  @Test
  void fromStream_invalidWorkloadAudience_throws() throws IOException {
    CredentialFormatException exception =
        assertThrows(
            CredentialFormatException.class,
            () -> {
              GenericJson json = buildJsonIdentityPoolWorkforceCredential();
              json.put("audience", "invalidAudience");
              ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));
            },
            "CredentialFormatException should be thrown.");
    assertEquals("An invalid input stream was provided.", exception.getMessage());
  }

  @Test
  void fromJson_identityPoolCredentialsWorkload() {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonIdentityPoolCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof IdentityPoolCredentials);
    assertEquals(
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
        credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
  }

  @Test
  void fromJson_identityPoolCredentialsWorkforce() {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonIdentityPoolWorkforceCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof IdentityPoolCredentials);
    assertEquals(
        "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider",
        credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertEquals(
        "userProject", ((IdentityPoolCredentials) credential).getWorkforcePoolUserProject());
    assertNotNull(credential.getCredentialSource());
  }

  @Test
  void fromJson_awsCredentials() {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonAwsCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof AwsCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
  }

  @Test
  void fromJson_nullJson_throws() {
    assertThrows(
        NullPointerException.class,
        () ->
            ExternalAccountCredentials.fromJson(
                /* json= */ null, OAuth2Utils.HTTP_TRANSPORT_FACTORY),
        "Exception should be thrown.");
  }

  @Test
  void fromJson_invalidServiceAccountImpersonationUrl_throws() {
    GenericJson json = buildJsonIdentityPoolCredential();
    json.put("service_account_impersonation_url", "https://iamcredentials.googleapis.com");

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY),
            "Exception should be thrown.");
    assertEquals(
        "Unable to determine target principal from service account impersonation URL.",
        exception.getMessage());
  }

  @Test
  void fromJson_nullTransport_throws() {
    assertThrows(
        NullPointerException.class,
        () -> ExternalAccountCredentials.fromJson(new HashMap<>(), /* transportFactory= */ null),
        "Exception should be thrown.");
  }

  @Test
  void fromJson_invalidWorkforceAudiences_throws() {
    List<String> invalidAudiences =
        Arrays.asList(
            "//iam.googleapis.com/locations/global/workloadIdentityPools/pool/providers/provider",
            "//iam.googleapis.com/locations/global/workforcepools/pool/providers/provider",
            "//iam.googleapis.com/locations/global/workforcePools/providers/provider",
            "//iam.googleapis.com/locations/global/workforcePools/providers",
            "//iam.googleapis.com/locations/global/workforcePools/",
            "//iam.googleapis.com/locations//workforcePools/providers",
            "//iam.googleapis.com/notlocations/global/workforcePools/providers",
            "//iam.googleapis.com/locations/global/workforce/providers");

    for (String audience : invalidAudiences) {
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () -> {
                GenericJson json = buildJsonIdentityPoolCredential();
                json.put("audience", audience);
                json.put("workforce_pool_user_project", "userProject");

                ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
              },
              "Exception should be thrown.");
      assertEquals(
          "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.",
          exception.getMessage());
    }
  }

  @Test
  void constructor_builder() {
    HashMap<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("file", "file");

    ExternalAccountCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("https://tokeninfo.com")
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setCredentialSource(new TestCredentialSource(credentialSource))
            .setScopes(Arrays.asList("scope1", "scope2"))
            .setQuotaProjectId("projectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .build();

    assertEquals(
        "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider",
        credentials.getAudience());
    assertEquals("subjectTokenType", credentials.getSubjectTokenType());
    assertEquals(STS_URL, credentials.getTokenUrl());
    assertEquals("https://tokeninfo.com", credentials.getTokenInfoUrl());
    assertEquals(
        SERVICE_ACCOUNT_IMPERSONATION_URL, credentials.getServiceAccountImpersonationUrl());
    assertEquals(Arrays.asList("scope1", "scope2"), credentials.getScopes());
    assertEquals("projectId", credentials.getQuotaProjectId());
    assertEquals("clientId", credentials.getClientId());
    assertEquals("clientSecret", credentials.getClientSecret());
    assertEquals("workforcePoolUserProject", credentials.getWorkforcePoolUserProject());
    assertNotNull(credentials.getCredentialSource());
  }

  @Test
  void constructor_builder_invalidTokenUrl() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              ExternalAccountCredentials.Builder builder =
                  TestExternalAccountCredentials.newBuilder()
                      .setHttpTransportFactory(transportFactory)
                      .setAudience("audience")
                      .setSubjectTokenType("subjectTokenType")
                      .setTokenUrl("tokenUrl")
                      .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP));
              new TestExternalAccountCredentials(builder);
            },
            "Should have failed since an invalid token URL was passed.");
    assertEquals("The provided token URL is invalid.", exception.getMessage());
  }

  @Test
  void constructor_builder_invalidServiceAccountImpersonationUrl() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> {
              ExternalAccountCredentials.Builder builder =
                  TestExternalAccountCredentials.newBuilder()
                      .setHttpTransportFactory(transportFactory)
                      .setAudience("audience")
                      .setSubjectTokenType("subjectTokenType")
                      .setTokenUrl("tokenUrl")
                      .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
                      .setServiceAccountImpersonationUrl("serviceAccountImpersonationUrl");
              new TestExternalAccountCredentials(builder);
            },
            "Should have failed since an invalid token URL was passed.");
    assertEquals("The provided token URL is invalid.", exception.getMessage());
  }

  @Test
  void constructor_builderWithInvalidWorkforceAudiences_throws() {
    List<String> invalidAudiences =
        Arrays.asList(
            "",
            "//iam.googleapis.com/projects/x23/locations/global/workloadIdentityPools/pool/providers/provider",
            "//iam.googleapis.com/locations/global/workforcepools/pool/providers/provider",
            "//iam.googleapis.com/locations/global/workforcePools/providers/provider",
            "//iam.googleapis.com/locations/global/workforcePools/providers",
            "//iam.googleapis.com/locations/global/workforcePools/",
            "//iam.googleapis.com/locations//workforcePools/providers",
            "//iam.googleapis.com/notlocations/global/workforcePools/providers",
            "//iam.googleapis.com/locations/global/workforce/providers");

    HashMap<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("file", "file");
    for (String audience : invalidAudiences) {
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () -> {
                TestExternalAccountCredentials.newBuilder()
                    .setWorkforcePoolUserProject("workforcePoolUserProject")
                    .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                    .setAudience(audience)
                    .setSubjectTokenType("subjectTokenType")
                    .setTokenUrl(STS_URL)
                    .setCredentialSource(new TestCredentialSource(credentialSource))
                    .build();
              },
              "Exception should be thrown.");
      assertEquals(
          "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.",
          exception.getMessage());
    }
  }

  @Test
  void constructor_builderWithEmptyWorkforceUserProjectAndWorkforceAudience() {
    HashMap<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("file", "file");
    // No exception should be thrown.
    TestExternalAccountCredentials.newBuilder()
        .setWorkforcePoolUserProject("")
        .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
        .setAudience("//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
        .setSubjectTokenType("subjectTokenType")
        .setTokenUrl(STS_URL)
        .setCredentialSource(new TestCredentialSource(credentialSource))
        .build();
  }

  @Test
  void exchangeExternalCredentialForAccessToken() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildJsonIdentityPoolCredential(), transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken accessToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate no internal options set.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getLastRequest().getContentAsString());
    assertNull(query.get("options"));
  }

  @Test
  void exchangeExternalCredentialForAccessToken_withInternalOptions() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildJsonIdentityPoolCredential(), transportFactory);

    GenericJson internalOptions = new GenericJson();
    internalOptions.setFactory(OAuth2Utils.JSON_FACTORY);
    internalOptions.put("key", "value");
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType")
            .setInternalOptions(internalOptions.toString())
            .build();

    AccessToken accessToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate internal options set.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getLastRequest().getContentAsString());
    assertNotNull(query.get("options"));
    assertEquals(internalOptions.toString(), query.get("options"));
  }

  @Test
  void exchangeExternalCredentialForAccessToken_workforceCred_expectUserProjectPassedToSts()
      throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonIdentityPoolWorkforceCredential(), transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken accessToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate internal options set.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getLastRequest().getContentAsString());
    GenericJson internalOptions = new GenericJson();
    internalOptions.setFactory(OAuth2Utils.JSON_FACTORY);
    internalOptions.put("userProject", "userProject");
    assertEquals(internalOptions.toString(), query.get("options"));
  }

  @Test
  void exchangeExternalCredentialForAccessToken_workforceCredWithInternalOptions_expectOverridden()
      throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonIdentityPoolWorkforceCredential(), transportFactory);

    GenericJson internalOptions = new GenericJson();
    internalOptions.put("key", "value");
    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType")
            .setInternalOptions(internalOptions.toString())
            .build();

    AccessToken accessToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate internal options set.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getLastRequest().getContentAsString());
    assertNotNull(query.get("options"));
    assertEquals(internalOptions.toString(), query.get("options"));
  }

  @Test
  void exchangeExternalCredentialForAccessToken_withServiceAccountImpersonation()
      throws IOException {
    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(
            IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
                transportFactory.transport.getStsUrl(),
                transportFactory.transport.getMetadataUrl(),
                transportFactory.transport.getServiceAccountImpersonationUrl()),
            transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken returnedToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), returnedToken.getTokenValue());
  }

  @Test
  void exchangeExternalCredentialForAccessToken_throws() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildJsonIdentityPoolCredential(), transportFactory);

    String errorCode = "invalidRequest";
    String errorDescription = "errorDescription";
    String errorUri = "errorUri";
    transportFactory.transport.addResponseErrorSequence(
        TestUtils.buildHttpResponseException(errorCode, errorDescription, errorUri));

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    OAuthException exception =
        assertThrows(
            OAuthException.class,
            () -> credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest),
            "Exception should be thrown.");
    assertEquals(errorCode, exception.getErrorCode());
    assertEquals(errorDescription, exception.getErrorDescription());
    assertEquals(errorUri, exception.getErrorUri());
  }

  @Test
  void getRequestMetadata_withQuotaProjectId() throws IOException {
    TestExternalAccountCredentials testCredentials =
        (TestExternalAccountCredentials)
            TestExternalAccountCredentials.newBuilder()
                .setHttpTransportFactory(transportFactory)
                .setAudience("audience")
                .setSubjectTokenType("subjectTokenType")
                .setTokenUrl(STS_URL)
                .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
                .setQuotaProjectId("quotaProjectId")
                .build();

    Map<String, List<String>> requestMetadata =
        testCredentials.getRequestMetadata(URI.create("http://googleapis.com/foo/bar"));

    assertEquals("quotaProjectId", requestMetadata.get("x-goog-user-project").get(0));
  }

  @Test
  void validateTokenUrl_validUrls() {
    List<String> validUrls =
        Arrays.asList(
            "https://sts.googleapis.com",
            "https://us-east-1.sts.googleapis.com",
            "https://US-EAST-1.sts.googleapis.com",
            "https://sts.us-east-1.googleapis.com",
            "https://sts.US-WEST-1.googleapis.com",
            "https://us-east-1-sts.googleapis.com",
            "https://US-WEST-1-sts.googleapis.com",
            "https://us-west-1-sts.googleapis.com/path?query");

    for (String url : validUrls) {
      ExternalAccountCredentials.validateTokenUrl(url);
      ExternalAccountCredentials.validateTokenUrl(url.toUpperCase(Locale.US));
    }
  }

  @Test
  void validateTokenUrl_invalidUrls() {
    List<String> invalidUrls =
        Arrays.asList(
            "https://iamcredentials.googleapis.com",
            "sts.googleapis.com",
            "https://",
            "http://sts.googleapis.com",
            "https://st.s.googleapis.com",
            "https://us-eas\\t-1.sts.googleapis.com",
            "https:/us-east-1.sts.googleapis.com",
            "https://US-WE/ST-1-sts.googleapis.com",
            "https://sts-us-east-1.googleapis.com",
            "https://sts-US-WEST-1.googleapis.com",
            "testhttps://us-east-1.sts.googleapis.com",
            "https://us-east-1.sts.googleapis.comevil.com",
            "https://us-east-1.us-east-1.sts.googleapis.com",
            "https://us-ea.s.t.sts.googleapis.com",
            "https://sts.googleapis.comevil.com",
            "hhttps://us-east-1.sts.googleapis.com",
            "https://us- -1.sts.googleapis.com",
            "https://-sts.googleapis.com",
            "https://us-east-1.sts.googleapis.com.evil.com");

    for (String url : invalidUrls) {
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () -> ExternalAccountCredentials.validateTokenUrl(url),
              "Should have failed since an invalid URL was passed.");
      assertEquals("The provided token URL is invalid.", exception.getMessage());
    }
  }

  @Test
  void validateServiceAccountImpersonationUrls_validUrls() {
    List<String> validUrls =
        Arrays.asList(
            "https://iamcredentials.googleapis.com",
            "https://us-east-1.iamcredentials.googleapis.com",
            "https://US-EAST-1.iamcredentials.googleapis.com",
            "https://iamcredentials.us-east-1.googleapis.com",
            "https://iamcredentials.US-WEST-1.googleapis.com",
            "https://us-east-1-iamcredentials.googleapis.com",
            "https://US-WEST-1-iamcredentials.googleapis.com",
            "https://us-west-1-iamcredentials.googleapis.com/path?query");

    for (String url : validUrls) {
      ExternalAccountCredentials.validateServiceAccountImpersonationInfoUrl(url);
      ExternalAccountCredentials.validateServiceAccountImpersonationInfoUrl(
          url.toUpperCase(Locale.US));
    }
  }

  @Test
  void validateServiceAccountImpersonationUrls_invalidUrls() {
    List<String> invalidUrls =
        Arrays.asList(
            "https://sts.googleapis.com",
            "iamcredentials.googleapis.com",
            "https://",
            "http://iamcredentials.googleapis.com",
            "https://iamcre.dentials.googleapis.com",
            "https://us-eas\t-1.iamcredentials.googleapis.com",
            "https:/us-east-1.iamcredentials.googleapis.com",
            "https://US-WE/ST-1-iamcredentials.googleapis.com",
            "https://iamcredentials-us-east-1.googleapis.com",
            "https://iamcredentials-US-WEST-1.googleapis.com",
            "testhttps://us-east-1.iamcredentials.googleapis.com",
            "https://us-east-1.iamcredentials.googleapis.comevil.com",
            "https://us-east-1.us-east-1.iamcredentials.googleapis.com",
            "https://us-ea.s.t.iamcredentials.googleapis.com",
            "https://iamcredentials.googleapis.comevil.com",
            "hhttps://us-east-1.iamcredentials.googleapis.com",
            "https://us- -1.iamcredentials.googleapis.com",
            "https://-iamcredentials.googleapis.com",
            "https://us-east-1.iamcredentials.googleapis.com.evil.com");

    for (String url : invalidUrls) {
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () -> ExternalAccountCredentials.validateServiceAccountImpersonationInfoUrl(url),
              "Should have failed since an invalid URL was passed.");
      assertEquals(
          "The provided service account impersonation URL is invalid.", exception.getMessage());
    }
  }

  private GenericJson buildJsonIdentityPoolCredential() {
    GenericJson json = new GenericJson();
    json.put(
        "audience",
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", STS_URL);
    json.put("token_info_url", "tokenInfoUrl");

    Map<String, String> map = new HashMap<>();
    map.put("file", "file");
    json.put("credential_source", map);
    return json;
  }

  private GenericJson buildJsonIdentityPoolWorkforceCredential() {
    GenericJson json = buildJsonIdentityPoolCredential();
    json.put(
        "audience", "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider");
    json.put("workforce_pool_user_project", "userProject");
    return json;
  }

  private GenericJson buildJsonAwsCredential() {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", STS_URL);
    json.put("token_info_url", "tokenInfoUrl");

    Map<String, String> map = new HashMap<>();
    map.put("environment_id", "aws1");
    map.put("region_url", "regionUrl");
    map.put("url", "url");
    map.put("regional_cred_verification_url", "regionalCredVerificationUrl");
    json.put("credential_source", map);

    return json;
  }

  static class TestExternalAccountCredentials extends ExternalAccountCredentials {
    static class TestCredentialSource extends IdentityPoolCredentials.IdentityPoolCredentialSource {
      protected TestCredentialSource(Map<String, Object> credentialSourceMap) {
        super(credentialSourceMap);
      }
    }

    public static Builder newBuilder() {
      return new Builder();
    }

    static class Builder extends ExternalAccountCredentials.Builder {
      Builder() {}

      @Override
      public TestExternalAccountCredentials build() {
        return new TestExternalAccountCredentials(this);
      }
    }

    protected TestExternalAccountCredentials(ExternalAccountCredentials.Builder builder) {
      super(builder);
    }

    @Override
    public AccessToken refreshAccessToken() {
      return new AccessToken("accessToken", new Date());
    }

    @Override
    public String retrieveSubjectToken() {
      return "subjectToken";
    }
  }
}
