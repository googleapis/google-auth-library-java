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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.http.HttpCredentialsAdapter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for Workload Identity Federation.
 *
 * <p>The only requirements for this test suite to run is to set the environment variable
 * GOOGLE_APPLICATION_CREDENTIALS to point to the same service account keys used in the setup script
 * (workloadidentityfederation-setup). These tests call GCS to get bucket information. The bucket
 * name must be provided through the GCS_BUCKET environment variable.
 */
class ITWorkloadIdentityFederationTest {

  // Copy output from workloadidentityfederation-setup.
  private static final String AUDIENCE_PREFIX =
      "//iam.googleapis.com/projects/1016721519174/locations/global/workloadIdentityPools/pool-1/providers/";
  private static final String AWS_ROLE_NAME = "ci-java-test";
  private static final String AWS_ROLE_ARN = "arn:aws:iam::027472800722:role/ci-java-test";

  private static final String AWS_AUDIENCE = AUDIENCE_PREFIX + "aws-1";
  private static final String OIDC_AUDIENCE = AUDIENCE_PREFIX + "oidc-1";

  private String clientEmail;

  @BeforeEach
  void setup() throws IOException {
    GenericJson keys = getServiceAccountKeyFileAsJson();
    clientEmail = (String) keys.get("client_email");
  }

  /**
   * IdentityPoolCredentials (OIDC provider): Uses the service account to generate a Google ID token
   * using the iamcredentials generateIdToken API. This will use the service account client ID as
   * the sub field of the token. This OIDC token will be used as the external subject token to be
   * exchanged for a GCP access token via GCP STS endpoint and then to impersonate the original
   * service account key.
   */
  @Test
  void identityPoolCredentials() throws IOException {
    IdentityPoolCredentials identityPoolCredentials =
        (IdentityPoolCredentials)
            ExternalAccountCredentials.fromJson(
                buildIdentityPoolCredentialConfig(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);

    callGcs(identityPoolCredentials);
  }

  /**
   * AwsCredentials (AWS provider): Uses the service account keys to generate a Google ID token
   * using the iamcredentials generateIdToken API. Exchanges the OIDC ID token for AWS security keys
   * using AWS STS AssumeRoleWithWebIdentity API. These values will be set as AWS environment
   * variables to simulate an AWS VM. The Auth library can now read these variables and create a
   * signed request to AWS GetCallerIdentity. This will be used as the external subject token to be
   * exchanged for a GCP access token via GCP STS endpoint and then to impersonate the original
   * service account key.
   */
  @Test
  void awsCredentials() throws Exception {
    String idToken = generateGoogleIdToken(AWS_AUDIENCE);

    String url =
        String.format(
            "https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity"
                + "&Version=2011-06-15&DurationSeconds=3600&RoleSessionName=%s"
                + "&RoleArn=%s&WebIdentityToken=%s",
            AWS_ROLE_NAME, AWS_ROLE_ARN, idToken);

    HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));

    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();
    String rawXml = response.parseAsString();

    String awsAccessKeyId = getXmlValueByTagName(rawXml, "AccessKeyId");
    String awsSecretAccessKey = getXmlValueByTagName(rawXml, "SecretAccessKey");
    String awsSessionToken = getXmlValueByTagName(rawXml, "SessionToken");

    AwsCredentials awsCredentialWithoutEnvProvider =
        (AwsCredentials)
            AwsCredentials.fromJson(buildAwsCredentialConfig(), OAuth2Utils.HTTP_TRANSPORT_FACTORY);
    TestEnvironmentProvider testEnvironmentProvider = new TestEnvironmentProvider();
    testEnvironmentProvider
        .setEnv("AWS_ACCESS_KEY_ID", awsAccessKeyId)
        .setEnv("AWS_SECRET_ACCESS_KEY", awsSecretAccessKey)
        .setEnv("AWS_SESSION_TOKEN", awsSessionToken)
        .setEnv("AWS_REGION", "us-east-2");

    AwsCredentials awsCredential =
        (AwsCredentials)
            AwsCredentials.newBuilder(awsCredentialWithoutEnvProvider)
                .setEnvironmentProvider(testEnvironmentProvider)
                .build();

    callGcs(awsCredential);
  }

  private GenericJson buildIdentityPoolCredentialConfig() throws IOException {
    String idToken = generateGoogleIdToken(OIDC_AUDIENCE);

    File file =
        File.createTempFile(
            "ITWorkloadIdentityFederation", /* suffix= */ null, /* directory= */ null);
    file.deleteOnExit();
    OAuth2Utils.writeInputStreamToFile(
        new ByteArrayInputStream(idToken.getBytes(StandardCharsets.UTF_8)), file.getAbsolutePath());

    GenericJson config = new GenericJson();
    config.put("type", "external_account");
    config.put("audience", OIDC_AUDIENCE);
    config.put("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
    config.put("token_url", "https://sts.googleapis.com/v1/token");
    config.put(
        "service_account_impersonation_url",
        String.format(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
            clientEmail));

    GenericJson credentialSource = new GenericJson();
    credentialSource.put("file", file.getAbsolutePath());
    config.put("credential_source", credentialSource);

    return config;
  }

  private GenericJson buildAwsCredentialConfig() {
    GenericJson config = new GenericJson();
    config.put("type", "external_account");
    config.put("audience", AWS_AUDIENCE);
    config.put("subject_token_type", "urn:ietf:params:aws:token-type:aws4_request");
    config.put("token_url", "https://sts.googleapis.com/v1/token");
    config.put(
        "service_account_impersonation_url",
        String.format(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
            clientEmail));

    GenericJson credentialSource = new GenericJson();
    credentialSource.put("environment_id", "aws1");
    credentialSource.put(
        "regional_cred_verification_url",
        "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15");
    config.put("credential_source", credentialSource);

    return config;
  }

  private void callGcs(GoogleCredentials credentials) throws IOException {
    String bucketName = System.getenv("GCS_BUCKET");
    assertNotNull(bucketName, "GCS bucket name not set through GCS_BUCKET env variable.");

    String url = "https://storage.googleapis.com/storage/v1/b/" + bucketName;

    HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory requestFactory =
        new NetHttpTransport().createRequestFactory(credentialsAdapter);
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));

    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();
    assertTrue(response.isSuccessStatusCode());
  }

  /**
   * Generates a Google ID token using the iamcredentials generateIdToken API.
   * https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oidc
   */
  private String generateGoogleIdToken(String audience) throws IOException {
    GoogleCredentials googleCredentials =
        GoogleCredentials.getApplicationDefault()
            .createScoped("https://www.googleapis.com/auth/cloud-platform");

    HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(googleCredentials);
    HttpRequestFactory requestFactory =
        new NetHttpTransport().createRequestFactory(credentialsAdapter);

    String url =
        String.format(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
            clientEmail);

    GenericData data = new GenericData();
    data.set("audience", audience);
    data.set("includeEmail", true);
    UrlEncodedContent content = new UrlEncodedContent(data);

    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(url), content);
    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();
    GenericData responseData = response.parseAs(GenericData.class);
    return (String) responseData.get("token");
  }

  private GenericJson getServiceAccountKeyFileAsJson() throws IOException {
    String credentialsPath = System.getenv(DefaultCredentialsProvider.CREDENTIAL_ENV_VAR);
    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    JsonObjectParser parser = new JsonObjectParser(jsonFactory);
    return parser.parseAndClose(
        new FileInputStream(credentialsPath), StandardCharsets.UTF_8, GenericJson.class);
  }

  private String getXmlValueByTagName(String rawXml, String tagName) {
    int startIndex = rawXml.indexOf("<" + tagName + ">");
    int endIndex = rawXml.indexOf("</" + tagName + ">", startIndex);

    if (startIndex >= 0 && endIndex > startIndex) {
      return rawXml.substring(startIndex + tagName.length() + 2, endIndex);
    }
    return null;
  }
}
