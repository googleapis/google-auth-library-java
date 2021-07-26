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

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.util.Arrays;

/**
 * DownscopedCredentials enables the ability to downscope, or restrict, the Identity and Access
 * Management (IAM) permissions that a short-lived credential can use for Cloud Storage.
 *
 * <p>To downscope permissions you must define a {@link CredentialAccessBoundary} which specifies
 * the upper bound of permissions that the credential can access. You must also provide a source
 * credential which will be used to acquire the downscoped credential.
 *
 * <p>See <a href='https://cloud.google.com/iam/docs/downscoping-short-lived-credentials'>for more
 * information.</a>
 *
 * <p>Usage:
 *
 * <pre><code>
 * GoogleCredentials sourceCredentials = GoogleCredentials.getApplicationDefault();
 *
 * CredentialAccessBoundary.AccessBoundaryRule rule =
 *     CredentialAccessBoundary.AccessBoundaryRule.newBuilder()
 *         .setAvailableResource(
 *             "//storage.googleapis.com/projects/_/buckets/bucket")
 *         .addAvailablePermission("inRole:roles/storage.objectViewer")
 *         .build();
 *
 * DownscopedCredentials downscopedCredentials =
 *     DownscopedCredentials.newBuilder()
 *         .setSourceCredential(credentials)
 *         .setCredentialAccessBoundary(
 *             CredentialAccessBoundary.newBuilder().addRule(rule).build())
 *         .build();
 *
 * AccessToken accessToken = downscopedCredentials.refreshAccessToken();
 *
 * OAuth2Credentials credentials = OAuth2Credentials.create(accessToken);
 *
 * Storage storage =
 * StorageOptions.newBuilder().setCredentials(credentials).build().getService();
 *
 * Blob blob = storage.get(BlobId.of("bucket", "object"));
 * System.out.printf("Blob %s retrieved.", blob.getBlobId());
 * </code></pre>
 *
 * Note that {@link OAuth2CredentialsWithRefresh} can instead be used to consume the downscoped
 * token, allowing for automatic token refreshes by providing a {@link
 * OAuth2CredentialsWithRefresh.OAuth2RefreshHandler}.
 */
public final class DownscopedCredentials extends OAuth2Credentials {

  private static final String TOKEN_EXCHANGE_ENDPOINT = "https://sts.googleapis.com/v1/token";

  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";

  private final GoogleCredentials sourceCredential;
  private final CredentialAccessBoundary credentialAccessBoundary;
  private final transient HttpTransportFactory transportFactory;

  private DownscopedCredentials(
      GoogleCredentials sourceCredential,
      CredentialAccessBoundary credentialAccessBoundary,
      HttpTransportFactory transportFactory) {
    this.transportFactory =
        firstNonNull(
            transportFactory,
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.sourceCredential =
        checkNotNull(sourceCredential.createScoped(Arrays.asList(CLOUD_PLATFORM_SCOPE)));
    this.credentialAccessBoundary = checkNotNull(credentialAccessBoundary);
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    try {
      this.sourceCredential.refreshIfExpired();
    } catch (IOException e) {
      throw new IOException("Unable to refresh the provided source credential.", e);
    }

    StsTokenExchangeRequest request =
        StsTokenExchangeRequest.newBuilder(
                sourceCredential.getAccessToken().getTokenValue(),
                OAuth2Utils.TOKEN_TYPE_ACCESS_TOKEN)
            .setRequestTokenType(OAuth2Utils.TOKEN_TYPE_ACCESS_TOKEN)
            .build();

    StsRequestHandler handler =
        StsRequestHandler.newBuilder(
                TOKEN_EXCHANGE_ENDPOINT, request, transportFactory.create().createRequestFactory())
            .setInternalOptions(credentialAccessBoundary.toJson())
            .build();

    return handler.exchangeToken().getAccessToken();
  }

  public GoogleCredentials getSourceCredentials() {
    return sourceCredential;
  }

  public CredentialAccessBoundary getCredentialAccessBoundary() {
    return credentialAccessBoundary;
  }

  @VisibleForTesting
  HttpTransportFactory getTransportFactory() {
    return transportFactory;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends OAuth2Credentials.Builder {

    private GoogleCredentials sourceCredential;
    private CredentialAccessBoundary credentialAccessBoundary;
    private HttpTransportFactory transportFactory;

    private Builder() {}

    public Builder setSourceCredential(GoogleCredentials sourceCredential) {
      this.sourceCredential = sourceCredential;
      return this;
    }

    public Builder setCredentialAccessBoundary(CredentialAccessBoundary credentialAccessBoundary) {
      this.credentialAccessBoundary = credentialAccessBoundary;
      return this;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public DownscopedCredentials build() {
      return new DownscopedCredentials(
          sourceCredential, credentialAccessBoundary, transportFactory);
    }
  }
}
