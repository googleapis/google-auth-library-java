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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExternalAccountCredentials.SubjectTokenTypes;
import com.google.auth.oauth2.ExternalAccountCredentialsTest.TestExternalAccountCredentials.TestCredentialSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ExternalAccountCredentials}. */
@RunWith(JUnit4.class)
public class ExternalAccountCredentialsTest extends BaseSerializationTest {

  private static final String STS_URL = "https://sts.googleapis.com/v1/token";
  private static final String GOOGLE_DEFAULT_UNIVERSE = "googleapis.com";

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

  @Before
  public void setup() {
    transportFactory = new MockExternalAccountCredentialsTransportFactory();
  }

  @Test
  public void fromStream_identityPoolCredentials() throws IOException {
    GenericJson json = buildJsonIdentityPoolCredential();

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof IdentityPoolCredentials);
  }

  @Test
  public void fromStream_awsCredentials() throws IOException {
    GenericJson json = buildJsonAwsCredential();

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof AwsCredentials);
  }

  @Test
  public void fromStream_pluggableAuthCredentials() throws IOException {
    GenericJson json = buildJsonPluggableAuthCredential();

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));

    assertTrue(credential instanceof PluggableAuthCredentials);
  }

  @Test
  public void fromStream_invalidStream_throws() throws IOException {
    GenericJson json = buildJsonAwsCredential();

    json.put("audience", new HashMap<>());

    try {
      ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));
      fail("Should fail.");
    } catch (CredentialFormatException e) {
      assertEquals("An invalid input stream was provided.", e.getMessage());
    }
  }

  @Test
  public void fromStream_nullTransport_throws() throws IOException {
    try {
      ExternalAccountCredentials.fromStream(
          new ByteArrayInputStream("foo".getBytes()), /* transportFactory= */ null);
      fail("NullPointerException should be thrown.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void fromStream_nullStream_throws() throws IOException {
    try {
      ExternalAccountCredentials.fromStream(
          /* credentialsStream= */ null, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
      fail("NullPointerException should be thrown.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void fromStream_invalidWorkloadAudience_throws() throws IOException {
    try {
      GenericJson json = buildJsonIdentityPoolWorkforceCredential();
      json.put("audience", "invalidAudience");
      ExternalAccountCredentials credential =
          ExternalAccountCredentials.fromStream(TestUtils.jsonToInputStream(json));
      fail("CredentialFormatException should be thrown.");
    } catch (CredentialFormatException e) {
      assertEquals("An invalid input stream was provided.", e.getMessage());
    }
  }

  @Test
  public void fromJson_identityPoolCredentialsWorkload() throws IOException {
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
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_identityPoolCredentialsWorkforce() throws IOException {
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
    assertEquals("userProject", credential.getWorkforcePoolUserProject());
    assertNotNull(credential.getCredentialSource());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_identityPoolCredentialsWithServiceAccountImpersonationOptions()
      throws IOException {
    GenericJson identityPoolCredentialJson = buildJsonIdentityPoolCredential();
    identityPoolCredentialJson.set(
        "service_account_impersonation", buildServiceAccountImpersonationOptions(2800));

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            identityPoolCredentialJson, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof IdentityPoolCredentials);
    assertEquals(
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
        credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
    assertEquals(2800, credential.getServiceAccountImpersonationOptions().getLifetime());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_identityPoolCredentialsWithUniverseDomain() throws IOException {
    GenericJson identityPoolCredentialJson = buildJsonIdentityPoolCredential();
    identityPoolCredentialJson.set("universe_domain", "universeDomain");

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            identityPoolCredentialJson, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof IdentityPoolCredentials);
    assertNotNull(credential.getCredentialSource());
    assertEquals(
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
        credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertEquals("universeDomain", credential.getUniverseDomain());
  }

  @Test
  public void fromJson_awsCredentials() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonAwsCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof AwsCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_awsCredentialsWithServiceAccountImpersonationOptions() throws IOException {
    GenericJson awsCredentialJson = buildJsonAwsCredential();
    awsCredentialJson.set(
        "service_account_impersonation", buildServiceAccountImpersonationOptions(2800));

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(awsCredentialJson, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof AwsCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
    assertEquals(2800, credential.getServiceAccountImpersonationOptions().getLifetime());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_awsCredentialsWithUniverseDomain() throws IOException {
    GenericJson awsCredentialJson = buildJsonAwsCredential();
    awsCredentialJson.set("universe_domain", "universeDomain");

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(awsCredentialJson, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof AwsCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertEquals("universeDomain", credential.getUniverseDomain());
    assertNotNull(credential.getCredentialSource());
  }

  @Test
  public void fromJson_pluggableAuthCredentials() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonPluggableAuthCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof PluggableAuthCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());

    PluggableAuthCredentialSource source =
        (PluggableAuthCredentialSource) credential.getCredentialSource();
    assertEquals("command", source.getCommand());
    assertEquals(30000, source.getTimeoutMs()); // Default timeout is 30s.
    assertNull(source.getOutputFilePath());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_pluggableAuthCredentialsWorkforce() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            buildJsonPluggableAuthWorkforceCredential(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof PluggableAuthCredentials);
    assertEquals(
        "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider",
        credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertEquals("userProject", credential.getWorkforcePoolUserProject());

    assertNotNull(credential.getCredentialSource());

    PluggableAuthCredentialSource source =
        (PluggableAuthCredentialSource) credential.getCredentialSource();
    assertEquals("command", source.getCommand());
    assertEquals(30000, source.getTimeoutMs()); // Default timeout is 30s.
    assertNull(source.getOutputFilePath());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void fromJson_pluggableAuthCredentials_allExecutableOptionsSet() throws IOException {
    GenericJson json = buildJsonPluggableAuthCredential();
    Map<String, Object> credentialSourceMap = (Map<String, Object>) json.get("credential_source");
    // Add optional params to the executable config (timeout, output file path).
    Map<String, Object> executableConfig =
        (Map<String, Object>) credentialSourceMap.get("executable");
    executableConfig.put("timeout_millis", 5000);
    executableConfig.put("output_file", "path/to/output/file");

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof PluggableAuthCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());

    PluggableAuthCredentialSource source =
        (PluggableAuthCredentialSource) credential.getCredentialSource();
    assertEquals("command", source.getCommand());
    assertEquals("path/to/output/file", source.getOutputFilePath());
    assertEquals(5000, source.getTimeoutMs());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  public void fromJson_pluggableAuthCredentialsWithServiceAccountImpersonationOptions()
      throws IOException {
    GenericJson pluggableAuthCredentialJson = buildJsonPluggableAuthCredential();
    pluggableAuthCredentialJson.set(
        "service_account_impersonation", buildServiceAccountImpersonationOptions(2800));

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            pluggableAuthCredentialJson, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof PluggableAuthCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
    assertEquals(2800, credential.getServiceAccountImpersonationOptions().getLifetime());

    PluggableAuthCredentialSource source =
        (PluggableAuthCredentialSource) credential.getCredentialSource();
    assertEquals("command", source.getCommand());
    assertEquals(30000, source.getTimeoutMs()); // Default timeout is 30s.
    assertNull(source.getOutputFilePath());
    assertEquals(GOOGLE_DEFAULT_UNIVERSE, credential.getUniverseDomain());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void fromJson_pluggableAuthCredentials_withUniverseDomain() throws IOException {
    GenericJson json = buildJsonPluggableAuthCredential();
    json.set("universe_domain", "universeDomain");

    Map<String, Object> credentialSourceMap = (Map<String, Object>) json.get("credential_source");
    // Add optional params to the executable config (timeout, output file path).
    Map<String, Object> executableConfig =
        (Map<String, Object>) credentialSourceMap.get("executable");
    executableConfig.put("timeout_millis", 5000);
    executableConfig.put("output_file", "path/to/output/file");

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof PluggableAuthCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());

    PluggableAuthCredentialSource source =
        (PluggableAuthCredentialSource) credential.getCredentialSource();
    assertEquals("command", source.getCommand());
    assertEquals("path/to/output/file", source.getOutputFilePath());
    assertEquals(5000, source.getTimeoutMs());
    assertEquals("universeDomain", credential.getUniverseDomain());
  }

  @Test
  public void fromJson_pluggableAuthCredentialsWithUniverseDomain() throws IOException {
    GenericJson pluggableAuthCredentialJson = buildJsonPluggableAuthCredential();
    pluggableAuthCredentialJson.set("universe_domain", "universeDomain");

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(
            pluggableAuthCredentialJson, OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    assertTrue(credential instanceof PluggableAuthCredentials);
    assertEquals("audience", credential.getAudience());
    assertEquals("subjectTokenType", credential.getSubjectTokenType());
    assertEquals(STS_URL, credential.getTokenUrl());
    assertEquals("tokenInfoUrl", credential.getTokenInfoUrl());
    assertNotNull(credential.getCredentialSource());
    assertEquals("universeDomain", credential.getUniverseDomain());

    PluggableAuthCredentialSource source =
        (PluggableAuthCredentialSource) credential.getCredentialSource();
    assertEquals("command", source.getCommand());
    assertEquals(30000, source.getTimeoutMs()); // Default timeout is 30s.
    assertNull(source.getOutputFilePath());
  }

  @Test
  public void fromJson_nullJson_throws() throws IOException {
    try {
      ExternalAccountCredentials.fromJson(/* json= */ null, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
      fail("Exception should be thrown.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void fromJson_nullTransport_throws() throws IOException {
    try {
      ExternalAccountCredentials.fromJson(
          new HashMap<String, Object>(), /* transportFactory= */ null);
      fail("Exception should be thrown.");
    } catch (NullPointerException e) {
      // Expected.
    }
  }

  @Test
  public void fromJson_invalidWorkforceAudiences_throws() throws IOException {
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
      try {
        GenericJson json = buildJsonIdentityPoolCredential();
        json.put("audience", audience);
        json.put("workforce_pool_user_project", "userProject");

        ExternalAccountCredentials.fromJson(json, OAuth2Utils.HTTP_TRANSPORT_FACTORY);
        fail("Exception should be thrown.");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.",
            e.getMessage());
      }
    }
  }

  @Test
  public void constructor_builder() throws IOException {
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
            .setUniverseDomain("universeDomain")
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
    assertEquals("universeDomain", credentials.getUniverseDomain());
    assertNotNull(credentials.getCredentialSource());
  }

  @Test
  public void constructor_builder_defaultTokenUrl() {
    HashMap<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("file", "file");

    ExternalAccountCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setCredentialSource(new TestCredentialSource(credentialSource))
            .build();

    assertEquals(STS_URL, credentials.getTokenUrl());
  }

  @Test
  public void constructor_builder_subjectTokenTypeEnum() {
    HashMap<String, Object> credentialSource = new HashMap<>();
    credentialSource.put("file", "file");

    ExternalAccountCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType(SubjectTokenTypes.SAML2)
            .setTokenUrl(STS_URL)
            .setCredentialSource(new TestCredentialSource(credentialSource))
            .build();

    assertEquals(SubjectTokenTypes.SAML2.value, credentials.getSubjectTokenType());
  }

  @Test
  public void constructor_builder_invalidTokenUrl() {
    try {
      ExternalAccountCredentials.Builder builder =
          TestExternalAccountCredentials.newBuilder()
              .setHttpTransportFactory(transportFactory)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl("tokenUrl")
              .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP));
      new TestExternalAccountCredentials(builder);
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals("The provided token URL is invalid.", exception.getMessage());
    }
  }

  @Test
  public void constructor_builder_invalidServiceAccountImpersonationUrl() {
    try {
      ExternalAccountCredentials.Builder builder =
          TestExternalAccountCredentials.newBuilder()
              .setHttpTransportFactory(transportFactory)
              .setAudience("audience")
              .setSubjectTokenType("subjectTokenType")
              .setTokenUrl("tokenUrl")
              .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
              .setServiceAccountImpersonationUrl("serviceAccountImpersonationUrl");
      new TestExternalAccountCredentials(builder);
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals("The provided token URL is invalid.", exception.getMessage());
    }
  }

  @Test
  public void constructor_builderWithInvalidWorkforceAudiences_throws() {
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
      try {
        TestExternalAccountCredentials.newBuilder()
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY)
            .setAudience(audience)
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setCredentialSource(new TestCredentialSource(credentialSource))
            .build();
        fail("Should not be able to continue without exception.");
      } catch (IllegalArgumentException exception) {
        assertEquals(
            "The workforce_pool_user_project parameter should only be provided for a Workforce Pool configuration.",
            exception.getMessage());
      }
    }
  }

  @Test
  public void constructor_builderWithEmptyWorkforceUserProjectAndWorkforceAudience() {
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
  public void constructor_builder_invalidTokenLifetime_throws() {
    Map<String, Object> invalidOptionsMap = new HashMap<String, Object>();
    invalidOptionsMap.put("token_lifetime_seconds", "thisIsAString");

    try {
      IdentityPoolCredentials.newBuilder()
          .setHttpTransportFactory(transportFactory)
          .setAudience(
              "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
          .setSubjectTokenType("subjectTokenType")
          .setTokenUrl(STS_URL)
          .setTokenInfoUrl("https://tokeninfo.com")
          .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
          .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
          .setScopes(Arrays.asList("scope1", "scope2"))
          .setQuotaProjectId("projectId")
          .setClientId("clientId")
          .setClientSecret("clientSecret")
          .setWorkforcePoolUserProject("workforcePoolUserProject")
          .setUniverseDomain("universeDomain")
          .setServiceAccountImpersonationOptions(invalidOptionsMap)
          .build();
      fail("Should not be able to continue without exception.");
    } catch (IllegalArgumentException exception) {
      assertEquals(
          "Value of \"token_lifetime_seconds\" field could not be parsed into an integer.",
          exception.getMessage());
      assertEquals(NumberFormatException.class, exception.getCause().getClass());
    }
  }

  @Test
  public void constructor_builder_stringTokenLifetime() {
    Map<String, Object> optionsMap = new HashMap<String, Object>();
    optionsMap.put("token_lifetime_seconds", "2800");

    ExternalAccountCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("https://tokeninfo.com")
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
            .setScopes(Arrays.asList("scope1", "scope2"))
            .setQuotaProjectId("projectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .setUniverseDomain("universeDomain")
            .setServiceAccountImpersonationOptions(optionsMap)
            .build();

    assertEquals(2800, credentials.getServiceAccountImpersonationOptions().getLifetime());
  }

  @Test
  public void constructor_builder_bigDecimalTokenLifetime() {
    Map<String, Object> optionsMap = new HashMap<String, Object>();
    optionsMap.put("token_lifetime_seconds", new BigDecimal("2800"));

    ExternalAccountCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("https://tokeninfo.com")
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
            .setScopes(Arrays.asList("scope1", "scope2"))
            .setQuotaProjectId("projectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .setUniverseDomain("universeDomain")
            .setServiceAccountImpersonationOptions(optionsMap)
            .build();

    assertEquals(2800, credentials.getServiceAccountImpersonationOptions().getLifetime());
  }

  @Test
  public void constructor_builder_integerTokenLifetime() {
    Map<String, Object> optionsMap = new HashMap<String, Object>();
    optionsMap.put("token_lifetime_seconds", Integer.valueOf(2800));

    ExternalAccountCredentials credentials =
        IdentityPoolCredentials.newBuilder()
            .setHttpTransportFactory(transportFactory)
            .setAudience(
                "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
            .setSubjectTokenType("subjectTokenType")
            .setTokenUrl(STS_URL)
            .setTokenInfoUrl("https://tokeninfo.com")
            .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
            .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
            .setScopes(Arrays.asList("scope1", "scope2"))
            .setQuotaProjectId("projectId")
            .setClientId("clientId")
            .setClientSecret("clientSecret")
            .setWorkforcePoolUserProject("workforcePoolUserProject")
            .setUniverseDomain("universeDomain")
            .setServiceAccountImpersonationOptions(optionsMap)
            .build();

    assertEquals(2800, credentials.getServiceAccountImpersonationOptions().getLifetime());
  }

  @Test
  public void constructor_builder_lowTokenLifetime_throws() {
    Map<String, Object> optionsMap = new HashMap<String, Object>();
    optionsMap.put("token_lifetime_seconds", 599);

    try {
      IdentityPoolCredentials.newBuilder()
          .setHttpTransportFactory(transportFactory)
          .setAudience(
              "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
          .setSubjectTokenType("subjectTokenType")
          .setTokenUrl(STS_URL)
          .setTokenInfoUrl("https://tokeninfo.com")
          .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
          .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
          .setScopes(Arrays.asList("scope1", "scope2"))
          .setQuotaProjectId("projectId")
          .setClientId("clientId")
          .setClientSecret("clientSecret")
          .setWorkforcePoolUserProject("workforcePoolUserProject")
          .setUniverseDomain("universeDomain")
          .setServiceAccountImpersonationOptions(optionsMap)
          .build();
    } catch (IllegalArgumentException e) {
      assertEquals(
          "The \"token_lifetime_seconds\" field must be between 600 and 43200 seconds.",
          e.getMessage());
    }
  }

  @Test
  public void constructor_builder_highTokenLifetime_throws() {
    Map<String, Object> optionsMap = new HashMap<String, Object>();
    optionsMap.put("token_lifetime_seconds", 43201);

    try {
      IdentityPoolCredentials.newBuilder()
          .setHttpTransportFactory(transportFactory)
          .setAudience(
              "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider")
          .setSubjectTokenType("subjectTokenType")
          .setTokenUrl(STS_URL)
          .setTokenInfoUrl("https://tokeninfo.com")
          .setServiceAccountImpersonationUrl(SERVICE_ACCOUNT_IMPERSONATION_URL)
          .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
          .setScopes(Arrays.asList("scope1", "scope2"))
          .setQuotaProjectId("projectId")
          .setClientId("clientId")
          .setClientSecret("clientSecret")
          .setWorkforcePoolUserProject("workforcePoolUserProject")
          .setUniverseDomain("universeDomain")
          .setServiceAccountImpersonationOptions(optionsMap)
          .build();
    } catch (IllegalArgumentException e) {
      assertEquals(
          "The \"token_lifetime_seconds\" field must be between 600 and 43200 seconds.",
          e.getMessage());
    }
  }

  @Test
  public void exchangeExternalCredentialForAccessToken() throws IOException {
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

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(0).getHeaders();
    validateMetricsHeader(headers, "file", false, false);
  }

  @Test
  public void exchangeExternalCredentialForAccessToken_withInternalOptions() throws IOException {
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
  public void exchangeExternalCredentialForAccessToken_workforceCred_expectUserProjectPassedToSts()
      throws IOException {
    ExternalAccountCredentials identityPoolCredential =
        ExternalAccountCredentials.fromJson(
            buildJsonIdentityPoolWorkforceCredential(), transportFactory);

    ExternalAccountCredentials pluggableAuthCredential =
        ExternalAccountCredentials.fromJson(
            buildJsonPluggableAuthWorkforceCredential(), transportFactory);

    List<ExternalAccountCredentials> credentials =
        Arrays.asList(identityPoolCredential, pluggableAuthCredential);

    for (int i = 0; i < credentials.size(); i++) {
      StsTokenExchangeRequest stsTokenExchangeRequest =
          StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

      AccessToken accessToken =
          credentials.get(i).exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

      assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

      // Validate internal options set.
      Map<String, String> query =
          TestUtils.parseQuery(transportFactory.transport.getLastRequest().getContentAsString());
      GenericJson internalOptions = new GenericJson();
      internalOptions.setFactory(OAuth2Utils.JSON_FACTORY);
      internalOptions.put("userProject", "userProject");
      assertEquals(internalOptions.toString(), query.get("options"));
      assertEquals(i + 1, transportFactory.transport.getRequests().size());
    }
  }

  @Test
  public void
      exchangeExternalCredentialForAccessToken_workforceCredWithInternalOptions_expectOverridden()
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
  public void exchangeExternalCredentialForAccessToken_withServiceAccountImpersonation()
      throws IOException {
    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(
            IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
                transportFactory.transport.getStsUrl(),
                transportFactory.transport.getMetadataUrl(),
                transportFactory.transport.getServiceAccountImpersonationUrl(),
                /* serviceAccountImpersonationOptionsMap= */ null),
            transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken returnedToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), returnedToken.getTokenValue());

    // Validate that default lifetime was set correctly on the request.
    GenericJson query =
        OAuth2Utils.JSON_FACTORY
            .createJsonParser(transportFactory.transport.getLastRequest().getContentAsString())
            .parseAndClose(GenericJson.class);

    assertEquals("3600s", query.get("lifetime"));

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(1).getHeaders();
    validateMetricsHeader(headers, "url", true, false);
  }

  @Test
  public void exchangeExternalCredentialForAccessToken_withServiceAccountImpersonationOptions()
      throws IOException {
    transportFactory.transport.setExpireTime(TestUtils.getDefaultExpireTime());

    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromStream(
            IdentityPoolCredentialsTest.writeIdentityPoolCredentialsStream(
                transportFactory.transport.getStsUrl(),
                transportFactory.transport.getMetadataUrl(),
                transportFactory.transport.getServiceAccountImpersonationUrl(),
                buildServiceAccountImpersonationOptions(2800)),
            transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    AccessToken returnedToken =
        credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);

    assertEquals(
        transportFactory.transport.getServiceAccountAccessToken(), returnedToken.getTokenValue());

    // Validate that lifetime was set correctly on the request.
    GenericJson query =
        OAuth2Utils.JSON_FACTORY
            .createJsonParser(transportFactory.transport.getLastRequest().getContentAsString())
            .parseAndClose(GenericJson.class);

    // Validate metrics header is set correctly on the sts request.
    Map<String, List<String>> headers =
        transportFactory.transport.getRequests().get(1).getHeaders();
    validateMetricsHeader(headers, "url", true, true);
    assertEquals("2800s", query.get("lifetime"));
  }

  @Test
  public void exchangeExternalCredentialForAccessToken_throws() throws IOException {
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(buildJsonIdentityPoolCredential(), transportFactory);

    String errorCode = "invalidRequest";
    String errorDescription = "errorDescription";
    String errorUri = "errorUri";
    transportFactory.transport.addResponseErrorSequence(
        TestUtils.buildHttpResponseException(errorCode, errorDescription, errorUri));

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    try {
      credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);
      fail("Exception should be thrown.");
    } catch (OAuthException e) {
      assertEquals(errorCode, e.getErrorCode());
      assertEquals(errorDescription, e.getErrorDescription());
      assertEquals(errorUri, e.getErrorUri());
    }
  }

  @Test
  public void exchangeExternalCredentialForAccessToken_invalidImpersonatedCredentialsThrows()
      throws IOException {
    GenericJson json = buildJsonIdentityPoolCredential();
    json.put("service_account_impersonation_url", "https://iamcredentials.googleapis.com");
    ExternalAccountCredentials credential =
        ExternalAccountCredentials.fromJson(json, transportFactory);

    StsTokenExchangeRequest stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder("credential", "subjectTokenType").build();

    try {
      credential.exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest);
      fail("Exception should be thrown.");
    } catch (IllegalArgumentException e) {
      assertEquals(
          "Unable to determine target principal from service account impersonation URL.",
          e.getMessage());
    }
  }

  @Test
  public void getRequestMetadata_withQuotaProjectId() throws IOException {
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
  public void serialize() throws IOException, ClassNotFoundException {
    Map<String, Object> impersonationOpts =
        new HashMap<String, Object>() {
          {
            put("token_lifetime_seconds", 1000);
          }
        };

    TestExternalAccountCredentials testCredentials =
        (TestExternalAccountCredentials)
            TestExternalAccountCredentials.newBuilder()
                .setHttpTransportFactory(transportFactory)
                .setAudience("audience")
                .setSubjectTokenType("subjectTokenType")
                .setTokenUrl(STS_URL)
                .setCredentialSource(new TestCredentialSource(FILE_CREDENTIAL_SOURCE_MAP))
                .setServiceAccountImpersonationOptions(impersonationOpts)
                .build();

    TestExternalAccountCredentials deserializedCredentials =
        serializeAndDeserialize(testCredentials);
    assertEquals(testCredentials, deserializedCredentials);
    assertEquals(testCredentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(testCredentials.toString(), deserializedCredentials.toString());
    assertEquals(
        testCredentials.getServiceAccountImpersonationOptions().getLifetime(),
        deserializedCredentials.getServiceAccountImpersonationOptions().getLifetime());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
    assertEquals(
        MockExternalAccountCredentialsTransportFactory.class,
        deserializedCredentials.toBuilder().getHttpTransportFactory().getClass());
  }

  @Test
  public void validateTokenUrl_validUrls() {
    List<String> validUrls =
        Arrays.asList(
            "https://sts.googleapis.com",
            "https://us-east-1.sts.googleapis.com",
            "https://US-EAST-1.sts.googleapis.com",
            "https://sts.us-east-1.googleapis.com",
            "https://sts.US-WEST-1.googleapis.com",
            "https://us-east-1-sts.googleapis.com",
            "https://US-WEST-1-sts.googleapis.com",
            "https://us-west-1-sts.googleapis.com/path?query",
            "https://sts-xyz123.p.googleapis.com/path?query",
            "https://sts-xyz123.p.googleapis.com",
            "https://sts-xyz-123.p.googleapis.com");

    for (String url : validUrls) {
      ExternalAccountCredentials.validateTokenUrl(url);
      ExternalAccountCredentials.validateTokenUrl(url.toUpperCase(Locale.US));
    }
  }

  @Test
  public void validateTokenUrl_invalidUrls() {
    List<String> invalidUrls =
        Arrays.asList(
            "sts.googleapis.com",
            "https://",
            "http://sts.googleapis.com",
            "https://us-eas\\t-1.sts.googleapis.com",
            "https:/us-east-1.sts.googleapis.com",
            "testhttps://us-east-1.sts.googleapis.com",
            "hhttps://us-east-1.sts.googleapis.com",
            "https://us- -1.sts.googleapis.com");

    for (String url : invalidUrls) {
      try {
        ExternalAccountCredentials.validateTokenUrl(url);
        fail("Should have failed since an invalid URL was passed.");
      } catch (IllegalArgumentException e) {
        assertEquals("The provided token URL is invalid.", e.getMessage());
      }
    }
  }

  @Test
  public void validateServiceAccountImpersonationUrls_validUrls() {
    List<String> validUrls =
        Arrays.asList(
            "https://iamcredentials.googleapis.com",
            "https://us-east-1.iamcredentials.googleapis.com",
            "https://US-EAST-1.iamcredentials.googleapis.com",
            "https://iamcredentials.us-east-1.googleapis.com",
            "https://iamcredentials.US-WEST-1.googleapis.com",
            "https://us-east-1-iamcredentials.googleapis.com",
            "https://US-WEST-1-iamcredentials.googleapis.com",
            "https://us-west-1-iamcredentials.googleapis.com/path?query",
            "https://iamcredentials-xyz123.p.googleapis.com/path?query",
            "https://iamcredentials-xyz123.p.googleapis.com",
            "https://iamcredentials-xyz-123.p.googleapis.com");

    for (String url : validUrls) {
      ExternalAccountCredentials.validateServiceAccountImpersonationInfoUrl(url);
      ExternalAccountCredentials.validateServiceAccountImpersonationInfoUrl(
          url.toUpperCase(Locale.US));
    }
  }

  @Test
  public void validateServiceAccountImpersonationUrls_invalidUrls() {
    List<String> invalidUrls =
        Arrays.asList(
            "iamcredentials.googleapis.com",
            "https://",
            "http://iamcredentials.googleapis.com",
            "https:/iamcredentials.googleapis.com",
            "https://us-eas\t-1.iamcredentials.googleapis.com",
            "testhttps://us-east-1.iamcredentials.googleapis.com",
            "hhttps://us-east-1.iamcredentials.googleapis.com",
            "https://us- -1.iamcredentials.googleapis.com");

    for (String url : invalidUrls) {
      try {
        ExternalAccountCredentials.validateServiceAccountImpersonationInfoUrl(url);
        fail("Should have failed since an invalid URL was passed.");
      } catch (IllegalArgumentException e) {
        assertEquals("The provided service account impersonation URL is invalid.", e.getMessage());
      }
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
    map.put("region_url", "https://169.254.169.254/region");
    map.put("url", "https://169.254.169.254/");
    map.put("regional_cred_verification_url", "regionalCredVerificationUrl");
    json.put("credential_source", map);

    return json;
  }

  private GenericJson buildJsonPluggableAuthCredential() {
    GenericJson json = new GenericJson();
    json.put("audience", "audience");
    json.put("subject_token_type", "subjectTokenType");
    json.put("token_url", STS_URL);
    json.put("token_info_url", "tokenInfoUrl");

    Map<String, Map<String, Object>> credentialSource = new HashMap<>();

    Map<String, Object> executableConfig = new HashMap<>();
    executableConfig.put("command", "command");

    credentialSource.put("executable", executableConfig);
    json.put("credential_source", credentialSource);

    return json;
  }

  private GenericJson buildJsonPluggableAuthWorkforceCredential() {
    GenericJson json = buildJsonPluggableAuthCredential();
    json.put(
        "audience", "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider");
    json.put("workforce_pool_user_project", "userProject");
    return json;
  }

  static Map<String, Object> buildServiceAccountImpersonationOptions(Integer lifetime) {
    Map<String, Object> map = new HashMap<String, Object>();
    map.put("token_lifetime_seconds", lifetime);

    return map;
  }

  static void validateMetricsHeader(
      Map<String, List<String>> headers,
      String source,
      boolean saImpersonationUsed,
      boolean configLifetimeUsed) {
    assertTrue(headers.containsKey(MetricsUtils.API_CLIENT_HEADER));
    String actualMetricsValue = headers.get(MetricsUtils.API_CLIENT_HEADER).get(0);
    String expectedMetricsValue =
        String.format(
            "%s google-byoid-sdk source/%s sa-impersonation/%s config-lifetime/%s",
            MetricsUtils.getLanguageAndAuthLibraryVersions(),
            source,
            saImpersonationUsed,
            configLifetimeUsed);
    assertEquals(expectedMetricsValue, actualMetricsValue);
  }

  static class TestExternalAccountCredentials extends ExternalAccountCredentials {
    static class TestCredentialSource extends IdentityPoolCredentialSource {
      protected TestCredentialSource(Map<String, Object> credentialSourceMap) {
        super(credentialSourceMap);
      }
    }

    @Override
    public Builder toBuilder() {
      return new Builder(this);
    }

    public static Builder newBuilder() {
      return new Builder();
    }

    static class Builder extends ExternalAccountCredentials.Builder {
      Builder() {}

      Builder(TestExternalAccountCredentials credentials) {
        super(credentials);
      }

      @Override
      public TestExternalAccountCredentials build() {
        return new TestExternalAccountCredentials(this);
      }

      public HttpTransportFactory getHttpTransportFactory() {
        return transportFactory;
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
