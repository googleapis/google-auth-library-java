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
import static com.google.auth.oauth2.OAuth2Utils.JSON_FACTORY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/** Tests for {@link IdentityPoolCredentials}. */
class IdentityPoolCredentialsTest {

  private static final String STS_URL = "https://sts.googleapis.com";

  private static final Map<String, Object> FILE_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put("file", "file");
        }
      };

  private static final IdentityPoolCredentialSource FILE_CREDENTIAL_SOURCE =
      new IdentityPoolCredentialSource(FILE_CREDENTIAL_SOURCE_MAP);

  private static final IdentityPoolCredentials FILE_SOURCED_CREDENTIAL =
      (IdentityPoolCredentials)
          IdentityPoolCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience(
                  "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl(STS_URL)
              .setTokenInfoUrl("tokenInfoUrl")
              .setCredentialSource(FILE_CREDENTIAL_SOURCE)
              .build();

  static class MockExternalAccountCredentialsTransportFactory implements HttpTransportFactory {

    MockExternalAccountCredentialsTransport transport =
        new MockExternalAccountCredentialsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  void createdScoped_clonedCredentialWithAddedScopes() {
    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .build();

    List<String> newScopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials newCredentials = credentials.createScoped(newScopes);

    assertEquals(credentials.getAudience(), newCredentials.getAudience());
    assertEquals(credentials.getSubjectTokenType(), newCredentials.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), newCredentials.getTokenUrl());
    assertEquals(credentials.getTokenInfoUrl(), newCredentials.getTokenInfoUrl());
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(),
        newCredentials.getServiceAccountImpersonationUrl());
    assertEquals(credentials.getCredentialSource(), newCredentials.getCredentialSource());
    assertEquals(newScopes, newCredentials.getScopes());
    assertEquals(credentials.getQuotaProjectId(), newCredentials.getQuotaProjectId());
    assertEquals(credentials.getClientId(), newCredentials.getClientId());
    assertEquals(credentials.getClientSecret(), newCredentials.getClientSecret());
  }

  @Test
  void retrieveSubjectToken_fileSourced() throws IOException {
    File file =
        File.createTempFile("RETRIEVE_SUBJECT_TOKEN", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    String credential = "credential";
    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(credential.getBytes(StandardCharsets.UTF_8)),
        file.getAbsolutePath());

    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("file", file.getAbsolutePath());
    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credentials.retrieveSubjectToken();

    assertEquals(credential, subjectToken);
  }

  @Test
  void retrieveSubjectToken_fileSourcedWithJsonFormat() throws IOException {
    File file =
        File.createTempFile("RETRIEVE_SUBJECT_TOKEN", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setMetadataServerContentType("json");

    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", "json");
    formatMap.put("subject_token_field_name", "subjectToken");

    credentialSourceMap.put("file", file.getAbsolutePath());
    credentialSourceMap.put("format", formatMap);

    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    GenericJson response = new GenericJson();
    response.setFactory(JSON_FACTORY);
    response.put("subjectToken", "subjectToken");

    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(response.toString().getBytes(StandardCharsets.UTF_8)),
        file.getAbsolutePath());

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals("subjectToken", subjectToken);
  }

  @Test
  void retrieveSubjectToken_fileSourcedWithNullFormat_throws() throws IOException {
    File file =
        File.createTempFile("RETRIEVE_SUBJECT_TOKEN", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", null);

    credentialSourceMap.put("file", file.getAbsolutePath());
    credentialSourceMap.put("format", formatMap);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IdentityPoolCredentialSource(credentialSourceMap),
            "Exception should be thrown due to null format.");
    assertEquals("Invalid credential source format type: null.", exception.getMessage());
  }

  @Test
  void retrieveSubjectToken_noFile_throws() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    String path = "badPath";
    credentialSourceMap.put("file", path);
    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setCredentialSource(credentialSource)
                .build();

    IOException exception =
        assertThrows(
            IOException.class, credentials::retrieveSubjectToken, "Exception should be thrown.");
    assertEquals(
        String.format("Invalid credential location. The file at %s does not exist.", path),
        exception.getMessage());
  }

  @Test
  void retrieveSubjectToken_urlSourced() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(transportFactory.transport.getSubjectToken(), subjectToken);
  }

  @Test
  void retrieveSubjectToken_urlSourcedWithJsonFormat() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setMetadataServerContentType("json");

    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", "json");
    formatMap.put("subject_token_field_name", "subjectToken");

    IdentityPoolCredentialSource credentialSource =
        buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl(), formatMap);

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(credentialSource)
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(transportFactory.transport.getSubjectToken(), subjectToken);
  }

  @Test
  void retrieveSubjectToken_urlSourcedCredential_throws() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    IOException exception =
        assertThrows(
            IOException.class, credential::retrieveSubjectToken, "Exception should be thrown.");
    assertEquals(
        String.format(
            "Error getting subject token from metadata server: %s", response.getMessage()),
        exception.getMessage());
  }

  @Test
  void refreshAccessToken_withoutServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());
  }

  @Test
  void refreshAccessToken_internalOptionsSet() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setWorkforcePoolUserProject("userProject")
                .setAudience(
                    "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // If the IdentityPoolCredential is initialized with a userProject, it must be passed
    // to STS via internal options.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getLastRequest().getContentAsString());
    assertNotNull(query.get("options"));

    GenericJson expectedInternalOptions = new GenericJson();
    expectedInternalOptions.setFactory(OAuth2Utils.JSON_FACTORY);
    expectedInternalOptions.put("userProject", "userProject");

    assertEquals(expectedInternalOptions.toString(), query.get("options"));
  }

  @Test
  void refreshAccessToken_withServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());
  }

  @Test
  void refreshAccessToken_workforceWithServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
                .setAudience(
                    "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .setCredentialSource(
                    buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
                .setWorkforcePoolUserProject("userProject")
                .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    // Validate internal options set.
    Map<String, String> query = TestUtils.parseQuery(transportFactory.transport.getStsContent());

    GenericJson expectedInternalOptions = new GenericJson();
    expectedInternalOptions.setFactory(OAuth2Utils.JSON_FACTORY);
    expectedInternalOptions.put("userProject", "userProject");

    assertNotNull(query.get("options"));
    assertEquals(expectedInternalOptions.toString(), query.get("options"));
  }

  @Test
  void identityPoolCredentialSource_validFormats() {
    Map<String, Object> credentialSourceMapWithFileTextSource = new HashMap<>();
    Map<String, Object> credentialSourceMapWithFileJsonTextSource = new HashMap<>();
    Map<String, Object> credentialSourceMapWithUrlTextSource = new HashMap<>();
    Map<String, Object> credentialSourceMapWithUrlJsonTextSource = new HashMap<>();

    credentialSourceMapWithFileTextSource.put("file", "/path/to/file");
    credentialSourceMapWithFileJsonTextSource.put("file", "/path/to/file");

    credentialSourceMapWithUrlTextSource.put("url", "https://google.com");
    credentialSourceMapWithUrlJsonTextSource.put("url", "https://google.com");
    Map<String, String> headersMap = new HashMap<>();
    headersMap.put("header1", "value1");
    headersMap.put("header2", "value2");
    credentialSourceMapWithUrlTextSource.put("headers", headersMap);
    credentialSourceMapWithUrlJsonTextSource.put("headers", headersMap);

    Map<String, String> textFormat = new HashMap<>();
    textFormat.put("type", "text");

    Map<String, String> jsonTextFormat = new HashMap<>();
    jsonTextFormat.put("type", "json");
    jsonTextFormat.put("subject_token_field_name", "access_token");

    credentialSourceMapWithFileTextSource.put("format", textFormat);
    credentialSourceMapWithFileJsonTextSource.put("format", jsonTextFormat);

    credentialSourceMapWithUrlTextSource.put("format", textFormat);
    credentialSourceMapWithUrlJsonTextSource.put("format", jsonTextFormat);

    List<Map<String, Object>> sources =
        Arrays.asList(
            credentialSourceMapWithFileTextSource,
            credentialSourceMapWithFileJsonTextSource,
            credentialSourceMapWithUrlTextSource,
            credentialSourceMapWithUrlJsonTextSource);
    for (Map<String, Object> source : sources) {
      // Should not throw.
      new IdentityPoolCredentialSource(source);
    }
  }

  @Test
  void identityPoolCredentialSource_caseInsensitive() {
    Map<String, Object> credentialSourceMapWithFileTextSource = new HashMap<>();
    Map<String, Object> credentialSourceMapWithFileJsonTextSource = new HashMap<>();
    Map<String, Object> credentialSourceMapWithUrlTextSource = new HashMap<>();
    Map<String, Object> credentialSourceMapWithUrlJsonTextSource = new HashMap<>();

    credentialSourceMapWithFileTextSource.put("file", "/path/to/file");
    credentialSourceMapWithFileJsonTextSource.put("file", "/path/to/file");

    credentialSourceMapWithUrlTextSource.put("url", "https://google.com");
    credentialSourceMapWithUrlJsonTextSource.put("url", "https://google.com");
    Map<String, String> headersMap = new HashMap<>();
    headersMap.put("HeaDer1", "Value1");
    headersMap.put("HeaDer2", "Value2");
    credentialSourceMapWithUrlTextSource.put("headers", headersMap);
    credentialSourceMapWithUrlJsonTextSource.put("headers", headersMap);

    Map<String, String> textFormat = new HashMap<>();
    textFormat.put("type", "TEXT");

    Map<String, String> jsonTextFormat = new HashMap<>();
    jsonTextFormat.put("type", "JSON");
    jsonTextFormat.put("subject_token_field_name", "access_token");

    credentialSourceMapWithFileTextSource.put("format", textFormat);
    credentialSourceMapWithFileJsonTextSource.put("format", jsonTextFormat);

    credentialSourceMapWithUrlTextSource.put("format", textFormat);
    credentialSourceMapWithUrlJsonTextSource.put("format", jsonTextFormat);

    List<Map<String, Object>> sources =
        Arrays.asList(
            credentialSourceMapWithFileTextSource,
            credentialSourceMapWithFileJsonTextSource,
            credentialSourceMapWithUrlTextSource,
            credentialSourceMapWithUrlJsonTextSource);
    for (Map<String, Object> source : sources) {
      // Should not throw.
      new IdentityPoolCredentialSource(source);
    }
  }

  @Test
  void identityPoolCredentialSource_invalidSourceType() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IdentityPoolCredentialSource(new HashMap<>()),
            "Exception should be thrown.");
    assertEquals(
        "Missing credential source file location or URL. At least one must be specified.",
        exception.getMessage());
  }

  @Test
  void identityPoolCredentialSource_invalidFormatType() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", "unsupportedType");
    credentialSourceMap.put("format", format);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IdentityPoolCredentialSource(credentialSourceMap),
            "Exception should be thrown.");
    assertEquals("Invalid credential source format type: unsupportedType.", exception.getMessage());
  }

  @Test
  void identityPoolCredentialSource_nullFormatType() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", null);
    credentialSourceMap.put("format", format);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IdentityPoolCredentialSource(credentialSourceMap),
            "Exception should be thrown.");
    assertEquals("Invalid credential source format type: null.", exception.getMessage());
  }

  @Test
  void identityPoolCredentialSource_subjectTokenFieldNameUnset() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", "json");
    credentialSourceMap.put("format", format);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IdentityPoolCredentialSource(credentialSourceMap),
            "Exception should be thrown.");
    assertEquals(
        "When specifying a JSON credential type, the subject_token_field_name must be set.",
        exception.getMessage());
  }

  @Test
  void builder() {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder()
                .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                .setAudience("audience")
                .setSubjectTokenType("subjectTokenType")
                .setTokenUrl(STS_URL)
                .setTokenInfoUrl("tokenInfoUrl")
                .setCredentialSource(FILE_CREDENTIAL_SOURCE)
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .setScopes(scopes)
                .build();

    assertEquals("audience", credentials.getAudience());
    assertEquals("subjectTokenType", credentials.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), STS_URL);
    assertEquals(credentials.getTokenInfoUrl(), "tokenInfoUrl");
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(), SERVICE_ACCOUNT_IMPERSONATION_URL);
    assertEquals(credentials.getCredentialSource(), FILE_CREDENTIAL_SOURCE);
    assertEquals(credentials.getQuotaProjectId(), "quotaProjectId");
    assertEquals(credentials.getClientId(), "clientId");
    assertEquals(credentials.getClientSecret(), "clientSecret");
    assertEquals(credentials.getScopes(), scopes);
    assertEquals(credentials.getEnvironmentProvider(), SystemEnvironmentProvider.getInstance());
  }

  @Test
  void builder_invalidWorkforceAudiences_throws() {
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

    for (String audience : invalidAudiences) {
      IllegalArgumentException exception =
          assertThrows(
              IllegalArgumentException.class,
              () -> {
                IdentityPoolCredentials.newBuilder()
                    .setWorkforcePoolUserProject("workforcePoolUserProject")
                    .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                    .setAudience(audience)
                    .setSubjectTokenType("subjectTokenType")
                    .setTokenUrl(STS_URL)
                    .setTokenInfoUrl("tokenInfoUrl")
                    .setCredentialSource(FILE_CREDENTIAL_SOURCE)
                    .setQuotaProjectId("quotaProjectId")
                    .build();
              },
              "Exception should be thrown.");
      assertEquals(
          "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.",
          exception.getMessage());
    }
  }

  @Test
  void builder_emptyWorkforceUserProjectWithWorkforceAudience() {
    // No exception should be thrown.
    IdentityPoolCredentials credentials =
        (IdentityPoolCredentials)
            IdentityPoolCredentials.newBuilder()
                .setWorkforcePoolUserProject("")
                .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                .setAudience(
                    "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
                .setSubjectTokenType("subjectTokenType")
                .setTokenUrl(STS_URL)
                .setTokenInfoUrl("tokenInfoUrl")
                .setCredentialSource(FILE_CREDENTIAL_SOURCE)
                .setQuotaProjectId("quotaProjectId")
                .build();

    assertTrue(credentials.isWorkforcePoolConfiguration());
  }

  static InputStream writeIdentityPoolCredentialsStream(
      String tokenUrl, String url, @Nullable String serviceAccountImpersonationUrl)
      throws IOException {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", tokenUrl);
    json.put("token_info_url", "tokenInfoUrl");
    json.put("type", ExternalAccountCredentials.EXTERNAL_ACCOUNT_FILE_TYPE);

    if (serviceAccountImpersonationUrl != null) {
      json.put("service_account_impersonation_url", serviceAccountImpersonationUrl);
    }

    GenericJson credentialSource = new GenericJson();
    GenericJson headers = new GenericJson();
    headers.put("Metadata-Flavor", "Google");
    credentialSource.put("url", url);
    credentialSource.put("headers", headers);

    json.put("credential_source", credentialSource);
    return TestUtils.jsonToInputStream(json);
  }

  private static IdentityPoolCredentialSource buildUrlBasedCredentialSource(String url) {
    return buildUrlBasedCredentialSource(url, /* formatMap= */ null);
  }

  private static IdentityPoolCredentialSource buildUrlBasedCredentialSource(
      String url, Map<String, String> formatMap) {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> headers = new HashMap<>();
    headers.put("Metadata-Flavor", "Google");
    credentialSourceMap.put("url", url);
    credentialSourceMap.put("headers", headers);
    credentialSourceMap.put("format", formatMap);

    return new IdentityPoolCredentialSource(credentialSourceMap);
  }
}
