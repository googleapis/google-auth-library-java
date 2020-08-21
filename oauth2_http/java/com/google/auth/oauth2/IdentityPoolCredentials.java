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
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Url-sourced and file-sourced external account credentials.
 *
 * <p>By default, attempts to exchange the 3PI credential for a GCP access token.
 */
public class IdentityPoolCredentials extends ExternalAccountCredentials {

  /**
   * The IdentityPool credential source. Dictates the retrieval method of the 3PI credential, which
   * can either be through a metadata server or a local file.
   */
  @VisibleForTesting
  static class IdentityPoolCredentialSource extends CredentialSource {

    enum IdentityPoolCredentialSourceType {
      FILE,
      URL
    }

    private String credentialLocation;
    private IdentityPoolCredentialSourceType credentialSourceType;

    @Nullable private Map<String, String> headers;

    /**
     * The source of the 3P credential.
     *
     * <p>If the this a file based 3P credential, the credentials file can be retrieved using the
     * `file` key.
     *
     * <p>If this is URL-based 3p credential, the metadata server URL can be retrieved using the
     * `url` key.
     *
     * <p>Optional headers can be present, and should be keyed by `headers`.
     */
    public IdentityPoolCredentialSource(Map<String, Object> credentialSourceMap) {
      super(credentialSourceMap);

      if (credentialSourceMap.containsKey("file")) {
        credentialLocation = (String) credentialSourceMap.get("file");
        credentialSourceType = IdentityPoolCredentialSourceType.FILE;
      } else {
        credentialLocation = (String) credentialSourceMap.get("url");
        credentialSourceType = IdentityPoolCredentialSourceType.URL;
      }

      Map<String, String> headersMap = (Map<String, String>) credentialSourceMap.get("headers");
      if (headersMap != null && !headersMap.isEmpty()) {
        headers = new HashMap<>();
        headers.putAll(headersMap);
      }
    }

    private boolean hasHeaders() {
      return headers != null && !headers.isEmpty();
    }
  }

  /**
   * Internal constructor. See {@link
   * ExternalAccountCredentials#ExternalAccountCredentials(HttpTransportFactory, String, String,
   * String, String, CredentialSource, String, String, String, String, Collection)}
   */
  IdentityPoolCredentials(
      HttpTransportFactory transportFactory,
      String audience,
      String subjectTokenType,
      String tokenUrl,
      String tokenInfoUrl,
      IdentityPoolCredentialSource credentialSource,
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
    String credential = retrieveSubjectToken();
    StsTokenExchangeRequest.Builder stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(credential, subjectTokenType).setAudience(audience);

    if (scopes != null && !scopes.isEmpty()) {
      stsTokenExchangeRequest.setScopes(new ArrayList<>(scopes));
    }

    AccessToken accessToken = exchange3PICredentialForAccessToken(stsTokenExchangeRequest.build());
    return attemptServiceAccountImpersonation(accessToken);
  }

  @Override
  public String retrieveSubjectToken() throws IOException {
    IdentityPoolCredentialSource identityPoolCredentialSource =
        (IdentityPoolCredentialSource) credentialSource;
    if (identityPoolCredentialSource.credentialSourceType
        == IdentityPoolCredentialSource.IdentityPoolCredentialSourceType.FILE) {
      return retrieveSubjectTokenFromCredentialFile();
    }
    return getSubjectTokenFromMetadataServer();
  }

  private String retrieveSubjectTokenFromCredentialFile() throws IOException {
    IdentityPoolCredentialSource identityPoolCredentialSource =
        (IdentityPoolCredentialSource) credentialSource;
    String credentialFilePath = identityPoolCredentialSource.credentialLocation;
    if (!Files.exists(Paths.get(credentialFilePath), LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException(
          String.format(
              "Invalid credential location. The file at %s does not exist.", credentialFilePath));
    }
    try {
      return new String(Files.readAllBytes(Paths.get(credentialFilePath)));
    } catch (IOException e) {
      throw new IOException(
          "Error when attempting to read the subject token from the credential file.", e);
    }
  }

  private String getSubjectTokenFromMetadataServer() throws IOException {
    IdentityPoolCredentialSource identityPoolCredentialSource =
        (IdentityPoolCredentialSource) credentialSource;

    HttpRequest request =
        transportFactory
            .create()
            .createRequestFactory()
            .buildGetRequest(new GenericUrl(identityPoolCredentialSource.credentialLocation));
    request.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));

    if (identityPoolCredentialSource.hasHeaders()) {
      HttpHeaders headers = new HttpHeaders();
      headers.putAll(identityPoolCredentialSource.headers);
      request.setHeaders(headers);
    }

    try {
      HttpResponse response = request.execute();
      return response.parseAsString();
    } catch (IOException e) {
      throw new IOException(
          String.format("Error getting subject token from metadata server: %s", e.getMessage()), e);
    }
  }

  /** Clones the IdentityPoolCredentials with the specified scopes. */
  @Override
  public GoogleCredentials createScoped(Collection<String> newScopes) {
    return new IdentityPoolCredentials(
        transportFactory,
        audience,
        subjectTokenType,
        tokenUrl,
        tokenInfoUrl,
        (IdentityPoolCredentialSource) credentialSource,
        serviceAccountImpersonationUrl,
        quotaProjectId,
        clientId,
        clientSecret,
        newScopes);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static Builder newBuilder(IdentityPoolCredentials identityPoolCredentials) {
    return new Builder(identityPoolCredentials);
  }

  public static class Builder extends ExternalAccountCredentials.Builder {

    protected Builder() {}

    protected Builder(ExternalAccountCredentials credentials) {
      super(credentials);
    }

    @Override
    public IdentityPoolCredentials build() {
      return new IdentityPoolCredentials(
          transportFactory,
          audience,
          subjectTokenType,
          tokenUrl,
          tokenInfoUrl,
          (IdentityPoolCredentialSource) credentialSource,
          serviceAccountImpersonationUrl,
          quotaProjectId,
          clientId,
          clientSecret,
          scopes);
    }
  }
}
