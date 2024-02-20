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

import static com.google.auth.Credentials.GOOGLE_DEFAULT_UNIVERSE;
import static com.google.auth.oauth2.MockExternalAccountCredentialsTransport.SERVICE_ACCOUNT_IMPERSONATION_URL;
import static com.google.auth.oauth2.OAuth2Utils.JSON_FACTORY;
import static org.junit.Assert.*;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link IdentityPoolCredentials}. */
@RunWith(JUnit4.class)
public class IdentityPoolCredentialsTest extends BaseSerializationTest {

  private static final String STS_URL = "https://sts.googleapis.com/v1/token";

  private static final Map<String, Object> FILE_CREDENTIAL_SOURCE_MAP =
      new HashMap<String, Object>() {
        {
          put("file", "file");
        }
      };

  private static final IdentityPoolCredentialSource FILE_CREDENTIAL_SOURCE =
      new IdentityPoolCredentialSource(FILE_CREDENTIAL_SOURCE_MAP);

  private static final IdentityPoolCredentials FILE_SOURCED_CREDENTIAL =
      IdentityPoolCredentials.newBuilder()
          .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
          .setAudience(
              "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
          .setSubjectTokenType("subjectTokenType")
          .setTokenUrl(STS_URL)
          .setTokenInfoUrl("tokenInfoUrl")
          .setCredentialSource(FILE_CREDENTIAL_SOURCE)
          .build();

  private static final IdentityPoolSubjectTokenSupplier testProvider =
      (ExternalAccountSupplierContext context) -> "testSubjectToken";

  private static final ExternalAccountSupplierContext emptyContext =
      ExternalAccountSupplierContext.newBuilder().setAudience("").setSubjectTokenType("").build();

  static class MockExternalAccountCredentialsTransportFactory implements HttpTransportFactory {

    MockExternalAccountCredentialsTransport transport =
        new MockExternalAccountCredentialsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void createdScoped_clonedCredentialWithAddedScopes() throws IOException {
    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setQuotaProjectId("quotaProjectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setUniverseDomain("universeDomain")
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
    assertEquals(credentials.getUniverseDomain(), newCredentials.getUniverseDomain());
    assertEquals("universeDomain", newCredentials.getUniverseDomain());
  }

  @Test
  public void retrieveSubjectToken_fileSourced() throws IOException {
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
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setCredentialSource(credentialSource)
            .build();

    String subjectToken = credentials.retrieveSubjectToken();

    assertEquals(credential, subjectToken);
  }

  @Test
  public void retrieveSubjectToken_fileSourcedWithJsonFormat() throws IOException {
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
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setHttpTransportFactory(transportFactory)
            .setCredentialSource(credentialSource)
            .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals("subjectToken", subjectToken);
  }

  @Test
  public void retrieveSubjectToken_fileSourcedWithNullFormat_throws() throws IOException {
    File file =
        File.createTempFile("RETRIEVE_SUBJECT_TOKEN", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();

    Map<String, Object> credentialSourceMap = new HashMap<>();
    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", null);

    credentialSourceMap.put("file", file.getAbsolutePath());
    credentialSourceMap.put("format", formatMap);

    try {
      new IdentityPoolCredentialSource(credentialSourceMap);
      fail("Exception should be thrown due to null format.");
    } catch (IllegalArgumentException e) {
      assertEquals("Invalid credential source format type: null.", e.getMessage());
    }
  }

  @Test
  public void retrieveSubjectToken_noFile_throws() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    String path = "badPath";
    credentialSourceMap.put("file", path);
    IdentityPoolCredentialSource credentialSource =
        new IdentityPoolCredentialSource(credentialSourceMap);

    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setCredentialSource(credentialSource)
            .build();

    try {
      credentials.retrieveSubjectToken();
      fail("Exception should be thrown.");
    } catch (IOException e) {
      assertEquals(
          String.format("Invalid credential location. The file at %s does not exist.", path),
          e.getMessage());
    }
  }

  @Test
  public void retrieveSubjectToken_urlSourced() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setHttpTransportFactory(transportFactory)
            .setCredentialSource(
                buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
            .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(transportFactory.transport.getSubjectToken(), subjectToken);
  }

  @Test
  public void retrieveSubjectToken_urlSourcedWithJsonFormat() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setMetadataServerContentType("json");

    Map<String, String> formatMap = new HashMap<>();
    formatMap.put("type", "json");
    formatMap.put("subject_token_field_name", "subjectToken");

    IdentityPoolCredentialSource credentialSource =
        buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl(), formatMap);

    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setHttpTransportFactory(transportFactory)
            .setCredentialSource(credentialSource)
            .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(transportFactory.transport.getSubjectToken(), subjectToken);
  }

  @Test
  public void retrieveSubjectToken_urlSourcedCredential_throws() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IOException response = new IOException();
    transportFactory.transport.addResponseErrorSequence(response);

    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setHttpTransportFactory(transportFactory)
            .setCredentialSource(
                buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
            .build();

    try {
      credential.retrieveSubjectToken();
      fail("Exception should be thrown.");
    } catch (IOException e) {
      assertEquals(
          String.format(
              "Error getting subject token from metadata server: %s", response.getMessage()),
          e.getMessage());
    }
  }

  @Test
  public void retrieveSubjectToken_provider() throws IOException {

    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setCredentialSource(null)
            .setSubjectTokenSupplier(testProvider)
            .build();

    String subjectToken = credentials.retrieveSubjectToken();

    assertEquals(testProvider.getSubjectToken(emptyContext), subjectToken);
  }

  @Test
  public void retrieveSubjectToken_providerThrowsError() throws IOException {
    IOException testException = new IOException("test");

    IdentityPoolSubjectTokenSupplier errorProvider =
        (ExternalAccountSupplierContext context) -> {
          throw testException;
        };
    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setCredentialSource(null)
            .setSubjectTokenSupplier(errorProvider)
            .build();

    try {
      String subjectToken = credentials.retrieveSubjectToken();
      fail("retrieveSubjectToken should fail.");
    } catch (IOException e) {
      assertEquals("test", e.getMessage());
    }
  }

  @Test
  public void retrieveSubjectToken_supplierPassesContext() throws IOException {
    ExternalAccountSupplierContext expectedContext =
        ExternalAccountSupplierContext.newBuilder()
            .setAudience(FILE_SOURCED_CREDENTIAL.getAudience())
            .setSubjectTokenType(FILE_SOURCED_CREDENTIAL.getSubjectTokenType())
            .build();

    IdentityPoolSubjectTokenSupplier testSupplier =
        (ExternalAccountSupplierContext context) -> {
          assertEquals(expectedContext.getAudience(), context.getAudience());
          assertEquals(expectedContext.getSubjectTokenType(), context.getSubjectTokenType());
          return "token";
        };
    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setCredentialSource(null)
            .setSubjectTokenSupplier(testSupplier)
            .build();

    credentials.retrieveSubjectToken();
  }

  @Test
  public void refreshAccessToken_withoutServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder()
            .setAudience(
                "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenInfoUrl("tokenInfoUrl")
            .setCredentialSource(FILE_CREDENTIAL_SOURCE)
            .setTokenUrl(transportFactory.transport.getStsUrl())
            .setHttpTransportFactory(transportFactory)
            .setCredentialSource(
                buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
            .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(1).getHeaders();
    ExternalAccountCredentialsTest.validateMetricsHeader(headers, "url", false, false);
  }

  @Test
  public void refreshAccessToken_internalOptionsSet() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    IdentityPoolCredentials credential =
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
  public void refreshAccessToken_withServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder()
            .setAudience(
                "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenInfoUrl("tokenInfoUrl")
            .setServiceAccountImpersonationUrl(
                transportFactory.transport.getServiceAccountImpersonationUrl())
            .setTokenUrl(transportFactory.transport.getStsUrl())
            .setHttpTransportFactory(transportFactory)
            .setCredentialSource(
                buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
            .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(2).getHeaders();
    ExternalAccountCredentialsTest.validateMetricsHeader(headers, "url", true, false);
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonationOptions() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder()
            .setAudience(
                "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenInfoUrl("tokenInfoUrl")
            .setTokenUrl(transportFactory.transport.getStsUrl())
            .setHttpTransportFactory(transportFactory)
            .setServiceAccountImpersonationUrl(
                transportFactory.transport.getServiceAccountImpersonationUrl())
            .setCredentialSource(
                buildUrlBasedCredentialSource(transportFactory.transport.getMetadataUrl()))
            .setServiceAccountImpersonationOptions(
                ExternalAccountCredentialsTest.buildServiceAccountImpersonationOptions(2800))
            .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    // Validate that default lifetime was set correctly on the request.
    GenericJson query =
        OAuth2Utils.JSON_FACTORY
            .createJsonParser(transportFactory.transport.getLastRequest().getContentAsString())
            .parseAndClose(GenericJson.class);

    assertEquals("2800s", query.get("lifetime"));

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(2).getHeaders();
    ExternalAccountCredentialsTest.validateMetricsHeader(headers, "url", true, true);
  }

  @Test
  public void refreshAccessToken_Provider() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder()
            .setSubjectTokenSupplier(testProvider)
            .setAudience(
                "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenInfoUrl("tokenInfoUrl")
            .setTokenUrl(transportFactory.transport.getStsUrl())
            .setHttpTransportFactory(transportFactory)
            .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(0).getHeaders();
    ExternalAccountCredentialsTest.validateMetricsHeader(headers, "programmatic", false, false);
  }

  @Test
  public void refreshAccessToken_providerWithServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
        IdentityPoolCredentials.newBuilder()
            .setSubjectTokenSupplier(testProvider)
            .setAudience(
                "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenInfoUrl("tokenInfoUrl")
            .setServiceAccountImpersonationUrl(
                transportFactory.transport.getServiceAccountImpersonationUrl())
            .setTokenUrl(transportFactory.transport.getStsUrl())
            .setHttpTransportFactory(transportFactory)
            .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(0).getHeaders();
    ExternalAccountCredentialsTest.validateMetricsHeader(headers, "programmatic", true, false);
  }

  @Test
  public void refreshAccessToken_workforceWithServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
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
  public void refreshAccessToken_workforceWithServiceAccountImpersonationOptions()
      throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());
    IdentityPoolCredentials credential =
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
            .setServiceAccountImpersonationOptions(
                ExternalAccountCredentialsTest.buildServiceAccountImpersonationOptions(2800))
            .build();

    AccessToken accessToken = credential.refreshAccessToken();

    // Validate that default lifetime was set correctly on the request.
    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    GenericJson query =
        OAuth2Utils.JSON_FACTORY
            .createJsonParser(transportFactory.transport.getLastRequest().getContentAsString())
            .parseAndClose(GenericJson.class);

    assertEquals("2800s", query.get("lifetime"));
  }

  @Test
  public void identityPoolCredentialSource_validFormats() {
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
  public void identityPoolCredentialSource_caseInsensitive() {
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
  public void identityPoolCredentialSource_invalidSourceType() {
    try {
      new IdentityPoolCredentialSource(new HashMap<>());
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals(
          "Missing credential source file location or URL. At least one must be specified.",
          exception.getMessage());
    }
  }

  @Test
  public void identityPoolCredentialSource_invalidFormatType() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", "unsupportedType");
    credentialSourceMap.put("format", format);

    try {
      new IdentityPoolCredentialSource(credentialSourceMap);
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals("Invalid credential source format type: unsupportedType.", e.getMessage());
    }
  }

  @Test
  public void identityPoolCredentialSource_nullFormatType() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", null);
    credentialSourceMap.put("format", format);

    try {
      new IdentityPoolCredentialSource(credentialSourceMap);
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals("Invalid credential source format type: null.", e.getMessage());
    }
  }

  @Test
  public void identityPoolCredentialSource_subjectTokenFieldNameUnset() {
    Map<String, Object> credentialSourceMap = new HashMap<>();
    credentialSourceMap.put("url", "url");

    Map<String, String> format = new HashMap<>();
    format.put("type", "json");
    credentialSourceMap.put("format", format);

    try {
      new IdentityPoolCredentialSource(credentialSourceMap);
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals(
          "When specifying a JSON credential type, the subject_token_field_name must be set.",
          e.getMessage());
    }
  }

  @Test
  public void builder_allFields() throws IOException {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials credentials =
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
            .setUniverseDomain("universeDomain")
            .build();

    assertEquals("audience", credentials.getAudience());
    assertEquals("subjectTokenType", credentials.getSubjectTokenType());
    assertEquals(STS_URL, credentials.getTokenUrl());
    assertEquals("tokenInfoUrl", credentials.getTokenInfoUrl());
    assertEquals(
        SERVICE_ACCOUNT_IMPERSONATION_URL, credentials.getServiceAccountImpersonationUrl());
    assertEquals(FILE_CREDENTIAL_SOURCE, credentials.getCredentialSource());
    assertEquals("quotaProjectId", credentials.getQuotaProjectId());
    assertEquals("clientId", credentials.getClientId());
    assertEquals("clientSecret", credentials.getClientSecret());
    assertEquals(scopes, credentials.getScopes());
    assertEquals(SystemEnvironmentProvider.getInstance(), credentials.getEnvironmentProvider());
    assertEquals("universeDomain", credentials.getUniverseDomain());
  }

  @Test
  public void builder_subjectTokenSupplier() {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setSubjectTokenSupplier(testProvider)
            .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
            .setAudience("audience")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("tokenInfoUrl")
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setQuotaProjectId("quotaProjectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setScopes(scopes)
            .build();

    assertEquals(testProvider, credentials.getIdentityPoolSubjectTokenSupplier());
  }

  @Test
  public void builder_invalidWorkforceAudiences_throws() {
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
      try {
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
        fail("Exception should be thrown.");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.",
            e.getMessage());
      }
    }
  }

  @Test
  public void builder_emptyWorkforceUserProjectWithWorkforceAudience() {
    // No exception should be thrown.
    IdentityPoolCredentials credentials =
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

  @Test
  public void builder_supplierAndCredSourceThrows() throws IOException {
    try {
      IdentityPoolCredentials credentials =
          IdentityPoolCredentials.newBuilder()
              .setSubjectTokenSupplier(testProvider)
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl(STS_URL)
              .setCredentialSource(FILE_CREDENTIAL_SOURCE)
              .build();
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals(
          "IdentityPoolCredentials cannot have both a subjectTokenSupplier and a credentialSource.",
          exception.getMessage());
    }
  }

  @Test
  public void builder_noSupplierOrCredSourceThrows() throws IOException {

    try {
      IdentityPoolCredentials credentials =
          IdentityPoolCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl(STS_URL)
              .build();
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals(
          "A subjectTokenSupplier or a credentialSource must be provided.", exception.getMessage());
    }
  }

  public void builder_missingUniverseDomain_defaults() throws IOException {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials credentials =
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
    assertEquals(STS_URL, credentials.getTokenUrl());
    assertEquals("tokenInfoUrl", credentials.getTokenInfoUrl());
    assertEquals(
        SERVICE_ACCOUNT_IMPERSONATION_URL, credentials.getServiceAccountImpersonationUrl());
    assertEquals(FILE_CREDENTIAL_SOURCE, credentials.getCredentialSource());
    assertEquals("quotaProjectId", credentials.getQuotaProjectId());
    assertEquals("clientId", credentials.getClientId());
    assertEquals("clientSecret", credentials.getClientSecret());
    assertEquals(scopes, credentials.getScopes());
    assertEquals(SystemEnvironmentProvider.getInstance(), credentials.getEnvironmentProvider());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credentials.getUniverseDomain());
  }

  @Test
  public void newBuilder_allFields() throws IOException {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("tokenInfoUrl")
            .setCredentialSource(FILE_CREDENTIAL_SOURCE)
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setQuotaProjectId("quotaProjectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setScopes(scopes)
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .setUniverseDomain("universeDomain")
            .build();

    IdentityPoolCredentials newBuilderCreds =
        IdentityPoolCredentials.newBuilder(credentials).build();
    assertEquals(credentials.getAudience(), newBuilderCreds.getAudience());
    assertEquals(credentials.getSubjectTokenType(), newBuilderCreds.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), newBuilderCreds.getTokenUrl());
    assertEquals(credentials.getTokenInfoUrl(), newBuilderCreds.getTokenInfoUrl());
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(),
        newBuilderCreds.getServiceAccountImpersonationUrl());
    assertEquals(credentials.getCredentialSource(), newBuilderCreds.getCredentialSource());
    assertEquals(credentials.getQuotaProjectId(), newBuilderCreds.getQuotaProjectId());
    assertEquals(credentials.getClientId(), newBuilderCreds.getClientId());
    assertEquals(credentials.getClientSecret(), newBuilderCreds.getClientSecret());
    assertEquals(credentials.getScopes(), newBuilderCreds.getScopes());
    assertEquals(credentials.getEnvironmentProvider(), newBuilderCreds.getEnvironmentProvider());
    assertEquals(
        credentials.getWorkforcePoolUserProject(), newBuilderCreds.getWorkforcePoolUserProject());
    assertEquals(credentials.getUniverseDomain(), newBuilderCreds.getUniverseDomain());
  }

  @Test
  public void newBuilder_noUniverseDomain_defaults() throws IOException {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    IdentityPoolCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("tokenInfoUrl")
            .setCredentialSource(FILE_CREDENTIAL_SOURCE)
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setQuotaProjectId("quotaProjectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setScopes(scopes)
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .build();

    IdentityPoolCredentials newBuilderCreds =
        IdentityPoolCredentials.newBuilder(credentials).build();
    assertEquals(credentials.getAudience(), newBuilderCreds.getAudience());
    assertEquals(credentials.getSubjectTokenType(), newBuilderCreds.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), newBuilderCreds.getTokenUrl());
    assertEquals(credentials.getTokenInfoUrl(), newBuilderCreds.getTokenInfoUrl());
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(),
        newBuilderCreds.getServiceAccountImpersonationUrl());
    assertEquals(credentials.getCredentialSource(), newBuilderCreds.getCredentialSource());
    assertEquals(credentials.getQuotaProjectId(), newBuilderCreds.getQuotaProjectId());
    assertEquals(credentials.getClientId(), newBuilderCreds.getClientId());
    assertEquals(credentials.getClientSecret(), newBuilderCreds.getClientSecret());
    assertEquals(credentials.getScopes(), newBuilderCreds.getScopes());
    assertEquals(credentials.getEnvironmentProvider(), newBuilderCreds.getEnvironmentProvider());
    assertEquals(
        credentials.getWorkforcePoolUserProject(), newBuilderCreds.getWorkforcePoolUserProject());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, newBuilderCreds.getUniverseDomain());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    IdentityPoolCredentials testCredentials =
        IdentityPoolCredentials.newBuilder(FILE_SOURCED_CREDENTIAL)
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setQuotaProjectId("quotaProjectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setUniverseDomain("universeDomain")
            .build();

    IdentityPoolCredentials deserializedCredentials = serializeAndDeserialize(testCredentials);
    assertEquals(testCredentials, deserializedCredentials);
    assertEquals(testCredentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(testCredentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  static InputStream writeIdentityPoolCredentialsStream(
      String tokenUrl,
      String url,
      @Nullable String serviceAccountImpersonationUrl,
      @Nullable Map<String, Object> serviceAccountImpersonationOptionsMap)
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

    if (serviceAccountImpersonationOptionsMap != null) {
      json.put("service_account_impersonation", serviceAccountImpersonationOptionsMap);
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
