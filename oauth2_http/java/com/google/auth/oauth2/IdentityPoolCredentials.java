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
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentials.IdentityPoolCredentialSource.CredentialFormatType;
import com.google.common.io.CharStreams;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
 * <p>By default, attempts to exchange the third-party credential for a GCP access token.
 */
public class IdentityPoolCredentials extends ExternalAccountCredentials {

  /**
   * The IdentityPool credential source. Dictates the retrieval method of the 3PI credential, which
   * can either be through a metadata server or a local file.
   */
  static class IdentityPoolCredentialSource extends ExternalAccountCredentials.CredentialSource {

    enum IdentityPoolCredentialSourceType {
      FILE,
      URL
    }

    enum CredentialFormatType {
      TEXT,
      JSON
    }

    private IdentityPoolCredentialSourceType credentialSourceType;
    private CredentialFormatType credentialFormatType;
    private String credentialLocation;

    @Nullable private String subjectTokenFieldName;
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
     * <p>The third party credential can be provided in different formats, such as text or JSON. The
     * format can be specified using the `format` header, which will return a map with keys `type`
     * and `subject_token_field_name`. If the `type` is json, the `subject_token_field_name` must be
     * provided. If no format is provided, we expect the token to be in the raw text format.
     *
     * <p>Optional headers can be present, and should be keyed by `headers`.
     */
    public IdentityPoolCredentialSource(Map<String, Object> credentialSourceMap) {
      super(credentialSourceMap);

      if (credentialSourceMap.containsKey("file")) {
        credentialLocation = (String) credentialSourceMap.get("file");
        credentialSourceType = IdentityPoolCredentialSourceType.FILE;
      } else if (credentialSourceMap.containsKey("url")) {
        credentialLocation = (String) credentialSourceMap.get("url");
        credentialSourceType = IdentityPoolCredentialSourceType.URL;
      } else {
        throw new IllegalArgumentException(
            "Missing credential source file location or URL. At least one must be specified.");
      }

      Map<String, String> headersMap = (Map<String, String>) credentialSourceMap.get("headers");
      if (headersMap != null && !headersMap.isEmpty()) {
        headers = new HashMap<>();
        headers.putAll(headersMap);
      }

      // If the format is not provided, we will expect the token to be in the raw text format.
      credentialFormatType = CredentialFormatType.TEXT;

      Map<String, String> formatMap = (Map<String, String>) credentialSourceMap.get("format");
      if (formatMap != null && formatMap.containsKey("type")) {
        String type = formatMap.get("type");
        if (type == null || (!type.equals("text") && !type.equals("json"))) {
          throw new IllegalArgumentException(
              String.format("Invalid credential source format type: %s.", type));
        }
        credentialFormatType =
            type.equals("text") ? CredentialFormatType.TEXT : CredentialFormatType.JSON;

        if (!formatMap.containsKey("subject_token_field_name")) {
          throw new IllegalArgumentException(
              "When specifying a JSON credential type, the subject_token_field_name must be set.");
        }
        subjectTokenFieldName = formatMap.get("subject_token_field_name");
      }
    }

    private boolean hasHeaders() {
      return headers != null && !headers.isEmpty();
    }
  }

  private final IdentityPoolCredentialSource identityPoolCredentialSource;

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
    this.identityPoolCredentialSource = credentialSource;
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
    if (identityPoolCredentialSource.credentialSourceType
        == IdentityPoolCredentialSource.IdentityPoolCredentialSourceType.FILE) {
      return retrieveSubjectTokenFromCredentialFile();
    }
    return getSubjectTokenFromMetadataServer();
  }

  private String retrieveSubjectTokenFromCredentialFile() throws IOException {
    String credentialFilePath = identityPoolCredentialSource.credentialLocation;
    if (!Files.exists(Paths.get(credentialFilePath), LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException(
          String.format(
              "Invalid credential location. The file at %s does not exist.", credentialFilePath));
    }
    try {
      return parseToken(new FileInputStream(new File(credentialFilePath)));
    } catch (IOException e) {
      throw new IOException(
          "Error when attempting to read the subject token from the credential file.", e);
    }
  }

  private String parseToken(InputStream inputStream) throws IOException {
    if (identityPoolCredentialSource.credentialFormatType == CredentialFormatType.TEXT) {
      BufferedReader reader =
          new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
      return CharStreams.toString(reader);
    }

    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    JsonObjectParser parser = new JsonObjectParser(jsonFactory);
    GenericJson fileContents =
        parser.parseAndClose(inputStream, StandardCharsets.UTF_8, GenericJson.class);

    if (!fileContents.containsKey(identityPoolCredentialSource.subjectTokenFieldName)) {
      throw new IOException("Invalid subject token field name. No subject token was found.");
    }
    return (String) fileContents.get(identityPoolCredentialSource.subjectTokenFieldName);
  }

  private String getSubjectTokenFromMetadataServer() throws IOException {
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
      return parseToken(response.getContent());
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
