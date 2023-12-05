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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.IdentityPoolCredentialSource.CredentialFormatType;
import com.google.auth.oauth2.IdentityPoolCredentialSource.IdentityPoolCredentialSourceType;
import com.google.common.io.CharStreams;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
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
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nullable;

/**
 * Url-sourced and file-sourced external account credentials.
 *
 * <p>By default, attempts to exchange the external credential for a GCP access token.
 */
public class IdentityPoolCredentials extends ExternalAccountCredentials {

  private static final long serialVersionUID = 2471046175477275881L;

  @Nullable private final IdentityPoolCredentialSource identityPoolCredentialSource;

  @Nullable private final Supplier<String> subjectTokenSupplier;

  /** Internal constructor. See {@link Builder}. */
  IdentityPoolCredentials(Builder builder) {
    super(builder);
    // Check that one and only one of supplier or credential source are provided.
    if (builder.subjectTokenSupplier != null && builder.credentialSource != null) {
      throw new IllegalArgumentException(
          "IdentityPoolCredentials cannot have both a subjectTokenSupplier and a credentialSource.");
    }
    if (builder.subjectTokenSupplier == null && builder.credentialSource == null) {
      throw new IllegalArgumentException(
          "A subjectTokenSupplier or a credentialSource must be provided.");
    }
    if (builder.subjectTokenSupplier != null) {
      this.subjectTokenSupplier = builder.subjectTokenSupplier;
      this.identityPoolCredentialSource = null;
    } else {
      this.identityPoolCredentialSource = (IdentityPoolCredentialSource) builder.credentialSource;
      this.subjectTokenSupplier = null;
    }
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    String credential = retrieveSubjectToken();
    StsTokenExchangeRequest.Builder stsTokenExchangeRequest =
        StsTokenExchangeRequest.newBuilder(credential, getSubjectTokenType())
            .setAudience(getAudience());

    Collection<String> scopes = getScopes();
    if (scopes != null && !scopes.isEmpty()) {
      stsTokenExchangeRequest.setScopes(new ArrayList<>(scopes));
    }

    return exchangeExternalCredentialForAccessToken(stsTokenExchangeRequest.build());
  }

  @Override
  public String retrieveSubjectToken() throws IOException {
    if (this.subjectTokenSupplier != null) {
      try {
        return this.subjectTokenSupplier.get();
      } catch (Throwable e) {
        throw new GoogleAuthException(
            false, 0, "Error retrieving token from subject token supplier.", e);
      }
    } else if (identityPoolCredentialSource.credentialSourceType
        == IdentityPoolCredentialSource.IdentityPoolCredentialSourceType.FILE) {
      return retrieveSubjectTokenFromCredentialFile();
    }
    return getSubjectTokenFromMetadataServer();
  }

  @Override
  String getCredentialSourceType() {
    if (this.subjectTokenSupplier != null) {
      return "programmatic";
    }
    if (((IdentityPoolCredentialSource) this.getCredentialSource()).credentialSourceType
        == IdentityPoolCredentialSourceType.FILE) {
      return "file";
    } else {
      return "url";
    }
  }

  public Supplier<String> getSubjectTokenSupplier() {
    return this.subjectTokenSupplier;
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

    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
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
  public IdentityPoolCredentials createScoped(Collection<String> newScopes) {
    return new IdentityPoolCredentials(
        (IdentityPoolCredentials.Builder) newBuilder(this).setScopes(newScopes));
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static Builder newBuilder(IdentityPoolCredentials identityPoolCredentials) {
    return new Builder(identityPoolCredentials);
  }

  public static class Builder extends ExternalAccountCredentials.Builder {

    private Supplier<String> subjectTokenSupplier;

    Builder() {}

    Builder(IdentityPoolCredentials credentials) {
      super(credentials);
      this.setSubjectTokenSupplier(credentials.subjectTokenSupplier);
    }

    /**
     * Sets the subject token supplier. The supplier should return a valid subject token string.
     *
     * @param subjectTokenSupplier the supplier method to be called.
     * @return this {@code Builder} object
     */
    @CanIgnoreReturnValue
    public Builder setSubjectTokenSupplier(Supplier<String> subjectTokenSupplier) {
      this.subjectTokenSupplier = subjectTokenSupplier;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      super.setHttpTransportFactory(transportFactory);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAudience(String audience) {
      super.setAudience(audience);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setSubjectTokenType(String subjectTokenType) {
      super.setSubjectTokenType(subjectTokenType);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setSubjectTokenType(SubjectTokenTypes subjectTokenType) {
      super.setSubjectTokenType(subjectTokenType);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setTokenUrl(String tokenUrl) {
      super.setTokenUrl(tokenUrl);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setCredentialSource(IdentityPoolCredentialSource credentialSource) {
      super.setCredentialSource(credentialSource);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setServiceAccountImpersonationUrl(String serviceAccountImpersonationUrl) {
      super.setServiceAccountImpersonationUrl(serviceAccountImpersonationUrl);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setTokenInfoUrl(String tokenInfoUrl) {
      super.setTokenInfoUrl(tokenInfoUrl);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setQuotaProjectId(String quotaProjectId) {
      super.setQuotaProjectId(quotaProjectId);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setClientId(String clientId) {
      super.setClientId(clientId);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setClientSecret(String clientSecret) {
      super.setClientSecret(clientSecret);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setScopes(Collection<String> scopes) {
      super.setScopes(scopes);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setWorkforcePoolUserProject(String workforcePoolUserProject) {
      super.setWorkforcePoolUserProject(workforcePoolUserProject);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setServiceAccountImpersonationOptions(Map<String, Object> optionsMap) {
      super.setServiceAccountImpersonationOptions(optionsMap);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setUniverseDomain(String universeDomain) {
      super.setUniverseDomain(universeDomain);
      return this;
    }

    @CanIgnoreReturnValue
    Builder setEnvironmentProvider(EnvironmentProvider environmentProvider) {
      super.setEnvironmentProvider(environmentProvider);
      return this;
    }

    @Override
    public IdentityPoolCredentials build() {
      return new IdentityPoolCredentials(this);
    }
  }
}
