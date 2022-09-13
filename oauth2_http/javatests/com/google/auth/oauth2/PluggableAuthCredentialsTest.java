/*
 * Copyright 2022 Google LLC
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExecutableHandler.ExecutableOptions;
import com.google.auth.oauth2.ExternalAccountCredentials.CredentialSource;
import com.google.auth.oauth2.PluggableAuthCredentials.PluggableAuthCredentialSource;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;

/** Tests for {@link PluggableAuthCredentials}. */
public class PluggableAuthCredentialsTest {
  // The default timeout for waiting for the executable to finish (30 seconds).
  private static final int DEFAULT_EXECUTABLE_TIMEOUT_MS = 30 * 1000;
  // The minimum timeout for waiting for the executable to finish (5 seconds).
  private static final int MINIMUM_EXECUTABLE_TIMEOUT_MS = 5 * 1000;
  // The maximum timeout for waiting for the executable to finish (120 seconds).
  private static final int MAXIMUM_EXECUTABLE_TIMEOUT_MS = 120 * 1000;
  private static final String STS_URL = "https://sts.googleapis.com";

  private static final PluggableAuthCredentials CREDENTIAL =
      (PluggableAuthCredentials)
          PluggableAuthCredentials.newBuilder()
              .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
              .setAudience(
                  "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl(STS_URL)
              .setTokenInfoUrl("tokenInfoUrl")
              .setCredentialSource(buildCredentialSource())
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
  public void retrieveSubjectToken_shouldDelegateToHandler() throws IOException {
    PluggableAuthCredentials credential =
        PluggableAuthCredentials.newBuilder(CREDENTIAL)
            .setExecutableHandler(options -> "pluggableAuthToken")
            .build();
    String subjectToken = credential.retrieveSubjectToken();
    assertEquals(subjectToken, "pluggableAuthToken");
  }

  @Test
  public void retrieveSubjectToken_shouldPassAllOptionsToHandler() throws IOException {
    String command = "/path/to/executable";
    String timeout = "5000";
    String outputFile = "/path/to/output/file";

    final ExecutableOptions[] providedOptions = {null};
    ExecutableHandler executableHandler =
        options -> {
          providedOptions[0] = options;
          return "pluggableAuthToken";
        };

    PluggableAuthCredentials credential =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder(CREDENTIAL)
                .setExecutableHandler(executableHandler)
                .setCredentialSource(buildCredentialSource(command, timeout, outputFile))
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(subjectToken, "pluggableAuthToken");

    // Validate that the correct options were passed to the executable handler.
    ExecutableOptions options = providedOptions[0];
    assertEquals(options.getExecutableCommand(), command);
    assertEquals(options.getExecutableTimeoutMs(), Integer.parseInt(timeout));
    assertEquals(options.getOutputFilePath(), outputFile);

    Map<String, String> envMap = options.getEnvironmentMap();
    assertEquals(envMap.size(), 5);
    assertEquals(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"), credential.getAudience());
    assertEquals(
        envMap.get("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"), credential.getSubjectTokenType());
    assertEquals(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE"), "0");
    assertEquals(
        envMap.get("GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"),
        credential.getServiceAccountEmail());
    assertEquals(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"), outputFile);
  }

  @Test
  public void retrieveSubjectToken_shouldPassMinimalOptionsToHandler() throws IOException {
    String command = "/path/to/executable";

    final ExecutableOptions[] providedOptions = {null};
    ExecutableHandler executableHandler =
        options -> {
          providedOptions[0] = options;
          return "pluggableAuthToken";
        };

    PluggableAuthCredentials credential =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder(CREDENTIAL)
                .setExecutableHandler(executableHandler)
                .setCredentialSource(
                    buildCredentialSource(command, /* timeoutMs= */ null, /* outputFile= */ null))
                .build();

    String subjectToken = credential.retrieveSubjectToken();

    assertEquals(subjectToken, "pluggableAuthToken");

    // Validate that the correct options were passed to the executable handler.
    ExecutableOptions options = providedOptions[0];
    assertEquals(options.getExecutableCommand(), command);
    assertEquals(options.getExecutableTimeoutMs(), DEFAULT_EXECUTABLE_TIMEOUT_MS);
    assertNull(options.getOutputFilePath());

    Map<String, String> envMap = options.getEnvironmentMap();
    assertEquals(envMap.size(), 3);
    assertEquals(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"), credential.getAudience());
    assertEquals(
        envMap.get("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"), credential.getSubjectTokenType());
    assertEquals(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE"), "0");
    assertNull(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"));
    assertNull(envMap.get("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"));
  }

  @Test
  public void refreshAccessToken_withoutServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    PluggableAuthCredentials credential =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder(CREDENTIAL)
                .setExecutableHandler(options -> "pluggableAuthToken")
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setHttpTransportFactory(transportFactory)
                .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    // Validate that the correct subject token was passed to STS.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getRequests().get(0).getContentAsString());
    assertEquals(query.get("subject_token"), "pluggableAuthToken");
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonation() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    PluggableAuthCredentials credential =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder(CREDENTIAL)
                .setExecutableHandler(options -> "pluggableAuthToken")
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
                .build();

    AccessToken accessToken = credential.refreshAccessToken();

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), accessToken.getTokenValue());

    // Validate that the correct subject token was passed to STS.
    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getRequests().get(0).getContentAsString());
    assertEquals(query.get("subject_token"), "pluggableAuthToken");
  }

  @Test
  public void refreshAccessToken_withServiceAccountImpersonationOptions() throws IOException {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    PluggableAuthCredentials credential =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder(CREDENTIAL)
                .setExecutableHandler(options -> "pluggableAuthToken")
                .setTokenUrl(transportFactory.transport.getStsUrl())
                .setServiceAccountImpersonationUrl(
                    transportFactory.transport.getServiceAccountImpersonationUrl())
                .setHttpTransportFactory(transportFactory)
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
  }

  @Test
  public void pluggableAuthCredentialSource_allFields() {
    Map<String, Object> source = new HashMap<>();
    Map<String, Object> executable = new HashMap<>();
    source.put("executable", executable);
    executable.put("command", "/path/to/executable");
    executable.put("timeout_millis", "10000");
    executable.put("output_file", "/path/to/output/file");

    PluggableAuthCredentialSource credentialSource = new PluggableAuthCredentialSource(source);

    assertEquals(credentialSource.getCommand(), "/path/to/executable");
    assertEquals(credentialSource.getTimeoutMs(), 10000);
    assertEquals(credentialSource.getOutputFilePath(), "/path/to/output/file");
  }

  @Test
  public void pluggableAuthCredentialSource_noTimeoutProvided_setToDefault() {
    Map<String, Object> source = new HashMap<>();
    Map<String, Object> executable = new HashMap<>();
    source.put("executable", executable);
    executable.put("command", "command");
    PluggableAuthCredentialSource credentialSource = new PluggableAuthCredentialSource(source);

    assertEquals(credentialSource.getCommand(), "command");
    assertEquals(credentialSource.getTimeoutMs(), DEFAULT_EXECUTABLE_TIMEOUT_MS);
    assertNull(credentialSource.getOutputFilePath());
  }

  @Test
  public void pluggableAuthCredentialSource_timeoutProvidedOutOfRange_throws() {
    Map<String, Object> source = new HashMap<>();
    Map<String, Object> executable = new HashMap<>();
    source.put("executable", executable);

    executable.put("command", "command");

    int[] possibleOutOfRangeValues = new int[] {0, 4 * 1000, 121 * 1000};

    for (int value : possibleOutOfRangeValues) {
      executable.put("timeout_millis", value);

      try {
        new PluggableAuthCredentialSource(source);
        fail("Should not be able to continue without exception.");
      } catch (IllegalArgumentException exception) {
        assertEquals(
            String.format(
                "The executable timeout must be between %s and %s milliseconds.",
                MINIMUM_EXECUTABLE_TIMEOUT_MS, MAXIMUM_EXECUTABLE_TIMEOUT_MS),
            exception.getMessage());
      }
    }
  }

  @Test
  public void pluggableAuthCredentialSource_validTimeoutProvided() {
    Map<String, Object> source = new HashMap<>();
    Map<String, Object> executable = new HashMap<>();
    source.put("executable", executable);

    executable.put("command", "command");

    Object[] possibleValues = new Object[] {"10000", 10000, BigDecimal.valueOf(10000L)};

    for (Object value : possibleValues) {
      executable.put("timeout_millis", value);
      PluggableAuthCredentialSource credentialSource = new PluggableAuthCredentialSource(source);

      assertEquals(credentialSource.getCommand(), "command");
      assertEquals(credentialSource.getTimeoutMs(), 10000);
      assertNull(credentialSource.getOutputFilePath());
    }
  }

  @Test
  public void pluggableAuthCredentialSource_missingExecutableField_throws() {
    try {
      new PluggableAuthCredentialSource(new HashMap<>());
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals(
          "Invalid credential source for PluggableAuth credentials.", exception.getMessage());
    }
  }

  @Test
  public void pluggableAuthCredentialSource_missingExecutableCommandField_throws() {
    Map<String, Object> source = new HashMap<>();
    Map<String, Object> executable = new HashMap<>();
    source.put("executable", executable);

    try {
      new PluggableAuthCredentialSource(source);
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals(
          "The PluggableAuthCredentialSource is missing the required 'command' field.",
          exception.getMessage());
    }
  }

  @Test
  public void builder_allFields() {
    List<String> scopes = Arrays.asList("scope1", "scope2");

    CredentialSource source = buildCredentialSource();
    ExecutableHandler handler = options -> "Token";

    PluggableAuthCredentials credentials =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder()
                .setExecutableHandler(handler)
                .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
                .setAudience("audience")
                .setSubjectTokenType("subjectTokenType")
                .setTokenUrl(STS_URL)
                .setTokenInfoUrl("tokenInfoUrl")
                .setCredentialSource(source)
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .setScopes(scopes)
                .build();

    assertEquals(credentials.getExecutableHandler(), handler);
    assertEquals("audience", credentials.getAudience());
    assertEquals("subjectTokenType", credentials.getSubjectTokenType());
    assertEquals(credentials.getTokenUrl(), STS_URL);
    assertEquals(credentials.getTokenInfoUrl(), "tokenInfoUrl");
    assertEquals(
        credentials.getServiceAccountImpersonationUrl(), SERVICE_ACCOUNT_IMPERSONATION_URL);
    assertEquals(credentials.getCredentialSource(), source);
    assertEquals(credentials.getQuotaProjectId(), "quotaProjectId");
    assertEquals(credentials.getClientId(), "clientId");
    assertEquals(credentials.getClientSecret(), "clientSecret");
    assertEquals(credentials.getScopes(), scopes);
    assertEquals(credentials.getEnvironmentProvider(), SystemEnvironmentProvider.getInstance());
  }

  @Test
  public void createdScoped_clonedCredentialWithAddedScopes() {
    PluggableAuthCredentials credentials =
        (PluggableAuthCredentials)
            PluggableAuthCredentials.newBuilder(CREDENTIAL)
                .setExecutableHandler(options -> "pluggableAuthToken")
                .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
                .setQuotaProjectId("quotaProjectId")
                .setClientId("clientId")
                .setClientSecret("clientSecret")
                .build();

    List<String> newScopes = Arrays.asList("scope1", "scope2");

    PluggableAuthCredentials newCredentials = credentials.createScoped(newScopes);

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
    assertEquals(credentials.getExecutableHandler(), newCredentials.getExecutableHandler());
  }

  private static CredentialSource buildCredentialSource() {
    return buildCredentialSource("command", null, null);
  }

  private static CredentialSource buildCredentialSource(
      String command, @Nullable String timeoutMs, @Nullable String outputFile) {
    Map<String, Object> source = new HashMap<>();
    Map<String, Object> executable = new HashMap<>();
    source.put("executable", executable);
    executable.put("command", command);
    if (timeoutMs != null) {
      executable.put("timeout_millis", timeoutMs);
    }
    if (outputFile != null) {
      executable.put("output_file", outputFile);
    }

    return new PluggableAuthCredentialSource(source);
  }

  static InputStream writeCredentialsStream(String tokenUrl) throws IOException {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", tokenUrl);
    json.put("token_info_url", "tokenInfoUrl");
    json.put("type", ExternalAccountCredentials.EXTERNAL_ACCOUNT_FILE_TYPE);

    GenericJson credentialSource = new GenericJson();
    GenericJson executable = new GenericJson();
    executable.put("command", "/path/to/executable");
    credentialSource.put("executable", executable);

    json.put("credential_source", credentialSource);
    return TestUtils.jsonToInputStream(json);
  }
}
