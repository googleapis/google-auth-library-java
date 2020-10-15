/*
 * Copyright 2020 Google LLC
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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonParser;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * AWS credentials representing a third-party identity for calling Google APIs.
 *
 * <p>By default, attempts to exchange the 3PI credential for a GCP access token.
 */
public class AwsCredentials extends ExternalAccountCredentials {

  /**
   * The AWS credential source. Stores data required to retrieve the AWS credential from the AWS
   * metadata server.
   */
  static class AwsCredentialSource extends CredentialSource {

    private String regionUrl;
    private String url;
    private String regionalCredentialVerificationUrl;

    /**
     * The source of the AWS credential. The credential source map must contain the `region_url`,
     * `url, and `regional_cred_verification_url` entries.
     *
     * <p>The `region_url` is used to retrieve to targeted region.
     *
     * <p>The `url` is the metadata server URL which is used to retrieve the AWS credentials.
     *
     * <p>The `regional_cred_verification_url` is the regional GetCallerIdentity action URL, used to
     * determine the account ID and its roles.
     */
    AwsCredentialSource(Map<String, Object> credentialSourceMap) {
      super(credentialSourceMap);
      if (!credentialSourceMap.containsKey("region_url")) {
        throw new IllegalArgumentException(
            "A region_url representing the targeted region must be specified.");
      }
      if (!credentialSourceMap.containsKey("url")) {
        throw new IllegalArgumentException(
            "A url representing the metadata server endpoint must be specified.");
      }
      if (!credentialSourceMap.containsKey("regional_cred_verification_url")) {
        throw new IllegalArgumentException(
            "A regional_cred_verification_url representing the"
                + " GetCallerIdentity action URL must be specified.");
      }
      this.regionUrl = (String) credentialSourceMap.get("region_url");
      this.url = (String) credentialSourceMap.get("url");
      this.regionalCredentialVerificationUrl =
          (String) credentialSourceMap.get("regional_cred_verification_url");
    }
  }

  /**
   * Internal constructor. See {@link
   * ExternalAccountCredentials#ExternalAccountCredentials(HttpTransportFactory, String, String,
   * String, String, CredentialSource, String, String, String, String, Collection)}
   */
  AwsCredentials(
      HttpTransportFactory transportFactory,
      String audience,
      String subjectTokenType,
      String tokenUrl,
      String tokenInfoUrl,
      AwsCredentialSource credentialSource,
      @Nullable String serviceAccountImpersonationUrl,
      @Nullable String quotaProjectId,
      @Nullable String clientId,
      @Nullable String clientSecret,
      @Nullable Collection<String> scopes) {
    super(
        transportFactory,
        audience,
        subjectTokenType,
        tokenUrl,
        tokenInfoUrl,
        credentialSource,
        serviceAccountImpersonationUrl,
        quotaProjectId,
        clientId,
        clientSecret,
        scopes);
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    StsTokenExchangeRequest.Builder stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(retrieveSubjectToken(), subjectTokenType)
            .setAudience(audience);

    // Add scopes, if possible.
    if (scopes != null && !scopes.isEmpty()) {
      stsTokenExchangeRequest.setScopes(new ArrayList<>(scopes));
    }

    AccessToken accessToken = exchange3PICredentialForAccessToken(stsTokenExchangeRequest.build());
    return attemptServiceAccountImpersonation(accessToken);
  }

  @Override
  public String retrieveSubjectToken() throws IOException {
    // The targeted region is required to generate the signed request. The regional
    // endpoint must also be used.
    String region = getAwsRegion();

    AwsSecurityCredentials credentials = getAwsSecurityCredentials();

    // Generate the signed request to the AWS STS GetCallerIdentity API.
    Map<String, String> headers = new HashMap<>();
    headers.put("x-goog-cloud-target-resource", audience);

    AwsRequestSigner signer =
        AwsRequestSigner.newBuilder(
                credentials,
                "POST",
                ((AwsCredentialSource) credentialSource)
                    .regionalCredentialVerificationUrl.replace("{region}", region),
                region)
            .setAdditionalHeaders(headers)
            .build();

    AwsRequestSignature awsRequestSignature = signer.sign();
    return buildSubjectToken(awsRequestSignature);
  }

  /** Clones the AwsCredentials with the specified scopes. */
  @Override
  public GoogleCredentials createScoped(Collection<String> newScopes) {
    return new AwsCredentials(
        transportFactory,
        audience,
        subjectTokenType,
        tokenUrl,
        tokenInfoUrl,
        (AwsCredentialSource) credentialSource,
        serviceAccountImpersonationUrl,
        quotaProjectId,
        clientId,
        clientSecret,
        newScopes);
  }

  private String retrieveResource(String url, String resourceName) throws IOException {
    try {
      HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
      HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));
      HttpResponse response = request.execute();
      return response.parseAsString();
    } catch (IOException e) {
      throw new IOException(String.format("Failed to retrieve AWS %s.", resourceName), e);
    }
  }

  private String buildSubjectToken(AwsRequestSignature signature) {
    GenericJson headers = new GenericJson();
    headers.setFactory(OAuth2Utils.JSON_FACTORY);

    Map<String, String> canonicalHeaders = signature.getCanonicalHeaders();
    for (String headerName : canonicalHeaders.keySet()) {
      headers.put(headerName, canonicalHeaders.get(headerName));
    }

    headers.put("Authorization", signature.getAuthorizationHeader());
    headers.put("x-goog-cloud-target-resource", audience);

    GenericJson token = new GenericJson();
    token.setFactory(OAuth2Utils.JSON_FACTORY);

    token.put("headers", headers);
    token.put("method", signature.getHttpMethod());
    token.put(
        "url",
        ((AwsCredentialSource) credentialSource)
            .regionalCredentialVerificationUrl.replace("{region}", signature.getRegion()));
    return token.toString();
  }

  private String getAwsRegion() throws IOException {
    // For AWS Lambda, the region is retrieved through the AWS_REGION environment variable.
    String region = getEnv("AWS_REGION");
    if (region != null) {
      return region;
    }
    region = retrieveResource(((AwsCredentialSource) credentialSource).regionUrl, "region");

    // There is an extra appended character that must be removed. If `us-east-1b` is returned,
    // we want `us-east-1`.
    return region.substring(0, region.length() - 1);
  }

  @VisibleForTesting
  AwsSecurityCredentials getAwsSecurityCredentials() throws IOException {
    // Check environment variables for credentials first.
    String accessKeyId = getEnv("AWS_ACCESS_KEY_ID");
    String secretAccessKey = getEnv("AWS_SECRET_ACCESS_KEY");
    String token = getEnv("Token");
    if (accessKeyId != null && secretAccessKey != null) {
      return new AwsSecurityCredentials(accessKeyId, secretAccessKey, token);
    }

    // Credentials not retrievable from environment variables - call metadata server.
    AwsCredentialSource awsCredentialSource = (AwsCredentialSource) credentialSource;
    // Retrieve the IAM role that is attached to the VM. This is required to retrieve the AWS
    // security credentials.
    String roleName = retrieveResource(awsCredentialSource.url, "IAM role");

    // Retrieve the AWS security credentials by calling the endpoint specified by the credential
    // source.
    String awsCredentials =
        retrieveResource(awsCredentialSource.url + "/" + roleName, "credentials");

    JsonParser parser = OAuth2Utils.JSON_FACTORY.createJsonParser(awsCredentials);
    GenericJson genericJson = parser.parseAndClose(GenericJson.class);

    accessKeyId = (String) genericJson.get("AccessKeyId");
    secretAccessKey = (String) genericJson.get("SecretAccessKey");
    token = (String) genericJson.get("Token");

    // These credentials last for a few hours - we may consider caching these in the
    // future.
    return new AwsSecurityCredentials(accessKeyId, secretAccessKey, token);
  }

  @VisibleForTesting
  String getEnv(String name) {
    return System.getenv(name);
  }

  public static AwsCredentials.Builder newBuilder() {
    return new AwsCredentials.Builder();
  }

  public static AwsCredentials.Builder newBuilder(AwsCredentials awsCredentials) {
    return new AwsCredentials.Builder(awsCredentials);
  }

  public static class Builder extends ExternalAccountCredentials.Builder {

    protected Builder() {}

    protected Builder(AwsCredentials credentials) {
      super(credentials);
    }

    @Override
    public AwsCredentials build() {
      return new AwsCredentials(
          transportFactory,
          audience,
          subjectTokenType,
          tokenUrl,
          tokenInfoUrl,
          (AwsCredentialSource) credentialSource,
          serviceAccountImpersonationUrl,
          quotaProjectId,
          clientId,
          clientSecret,
          scopes);
    }
  }
}
