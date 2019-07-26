/*
 * Copyright 2019, Google LLC
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

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.MoreObjects;

/**
 * IdTokenCredentials provides a Google Issued OpenIdConnect token. <br>
 * Use an ID token to access services that require presenting an ID token for
 * authentication such as Cloud Functions or Cloud Run.<br>
 * 
 * The following Credential subclasses support IDTokens:
 * ServiceAccountCredentials, ComputeEngineCredentials, ImpersonatedCredentials.
 * 
 * For more information see <br>
 * Usage:<br>
 * 
 * <pre>
 * String credPath = "/path/to/svc_account.json";
 * String targetAudience = "https://example.com";
 * 
 * // For Application Default Credentials (as ServiceAccountCredentials)
 * // export GOOGLE_APPLICATION_CREDENTIALS=/path/to/svc.json
 * GoogleCredentials adcCreds = GoogleCredentials.getApplicationDefault();
 * IdTokenCredentials tokenCredential = IdTokenCredentials.create(adcCreds, targetAudience);
 * 
 * // for ServiceAccountCredentials
 * ServiceAccountCredentials saCreds = ServiceAccountCredentials.fromStream(new FileInputStream(credPath));
 * saCreds = (ServiceAccountCredentials) saCreds.createScoped(Arrays.asList("https://www.googleapis.com/auth/iam"));
 * IdTokenCredentials tokenCredential = IdTokenCredentials.create(saCreds, targetAudience);
 * 
 * // for ComputeEngineCredentials
 * ComputeEngineCredentials caCreds = ComputeEngineCredentials.create();
 * IdTokenCredentials tokenCredential = IdTokenCredentials.create(caCreds, targetAudience,
 *     Arrays.asList(ComputeEngineCredentials.ID_TOKEN_FORMAT_FULL));
 *
 * // for ImpersonatedCredentials
 * ImpersonatedCredentials imCreds = ImpersonatedCredentials.create(saCreds,
 *     "impersonated-account@project.iam.gserviceaccount.com", null,
 *     Arrays.asList("https://www.googleapis.com/auth/cloud-platform"), 300);
 * IdTokenCredentials tokenCredential = IdTokenCredentials.create(imCreds, targetAudience,
 *     Arrays.asList(ImpersonatedCredentials.INCLUDE_EMAIL));
 * 
 * // Use the IdTokenCredential in an authorized transport
 * GenericUrl genericUrl = new GenericUrl("https://example.com");
 * HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(tokenCredential);
 * HttpTransport transport = new NetHttpTransport();
 * HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
 * HttpResponse response = request.execute();
 *
 * // Print the token, expiration and the audience
 * System.out.println(tokenCredential.getIdToken().getTokenValue());
 * System.out.println(tokenCredential.getIdToken().getJsonWebSignature().getPayload().getAudienceAsList());
 * System.out.println(tokenCredential.getIdToken().getJsonWebSignature().getPayload().getExpirationTimeSeconds());
 * </pre>
 */
public class IdTokenCredentials extends OAuth2Credentials {

  private static final long serialVersionUID = -2133257318957588431L;
  private static final String CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

  private GoogleCredentials sourceCredentials;
  private final String transportFactoryClassName;
  private String targetAudience;
  private List<IdTokenProvider.Option> options;

  private transient HttpTransportFactory transportFactory;

  /**
   * Returns IdToken credentials associated with the sourceCredentials and with an
   * audience specified. Specify extensions and additional claims for the IdToken
   * by applying any approprite Options for the given credential type.
   * 
   * @param sourceCredentials The source credential for the Id Token
   * @param targetAudience    The audience field for the issued ID Token
   * @param options           List of Credential specific options for for the
   *                          token. For example, an IDToken for a
   *                          ComputeEngineCredential can return platform specific
   *                          claims if
   *                          "ComputeEngineCredentials.ID_TOKEN_FORMAT_FULL" is
   *                          provided as a list option.
   * @param transportFactory  HTTP transport factory, creates the transport used
   *                          to get access tokens.
   * @return IdTokenCredential
   */
  public static IdTokenCredentials create(GoogleCredentials sourceCredentials, String targetAudience,
      HttpTransportFactory transportFactory, List<IdTokenProvider.Option> options) {
    return IdTokenCredentials.newBuilder().setSourceCredentials(sourceCredentials).setTargetAudience(targetAudience)
        .setOptions(options).setHttpTransportFactory(transportFactory).build();
  }

  /**
   * Returns an Google Id Token from the metadata server on ComputeEngine.
   * 
   * @param sourceCredentials The source credential for the Id Token
   * @param targetAudience    List aud: field the IdToken should include.
   * @param options           List of Credential specific options for for the
   *                          token. For example, an IDToken for a
   *                          ComputeEngineCredential could include the full
   *                          formated claims returned if
   *                          "ComputeEngineCredential.ID_TOKEN_FORMAT_FULL" is
   *                          specified. Refer to the Credential type for specific
   *                          extensions.
   * @return IdToken object which includes the raw id_token, expirationn and
   *         audience.
   */
  public static IdTokenCredentials create(GoogleCredentials sourceCredentials, String targetAudience,
      List<IdTokenProvider.Option> options) {
    return IdTokenCredentials.newBuilder().setSourceCredentials(sourceCredentials).setTargetAudience(targetAudience)
        .setOptions(options).build();
  }

  /**
   * Returns IdToken credentials associated with the sourceCredentials and with an
   * audience specified.
   * 
   * @param sourceCredentials The source credential for the Id Token
   * @param targetAudience    The audience field for the issued ID Token
   * @return IdTokenCredential
   */
  public static IdTokenCredentials create(GoogleCredentials sourceCredentials, String targetAudience) {
    return IdTokenCredentials.newBuilder().setSourceCredentials(sourceCredentials).setTargetAudience(targetAudience)
        .build();
  }

  private IdTokenCredentials(Builder builder) {
    this.sourceCredentials = builder.getSourceCredentials();
    this.targetAudience = builder.getTargetAudience();
    this.options = builder.getOptions();
    this.transportFactory = firstNonNull(builder.getHttpTransportFactory(),
        getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (!(this.sourceCredentials instanceof IdTokenProvider)) {
      throw new IOException("Provided sourceToken does not implement IdTokenProvider");
    }
    if (this.sourceCredentials.getAccessToken() == null) {
      this.sourceCredentials = this.sourceCredentials.createScoped(Arrays.asList(CLOUD_PLATFORM_SCOPE));
    }
    
    return ((IdTokenProvider) this.sourceCredentials).idTokenWithAudience(targetAudience, options);
  }

  public IdToken getIdToken() {
    return (IdToken) getAccessToken();
  }

  @Override
  public int hashCode() {
    return Objects.hash(sourceCredentials);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this).toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof IdTokenCredentials)) {
      return false;
    }
    IdTokenCredentials other = (IdTokenCredentials) obj;
    return Objects.equals(this.sourceCredentials, other.sourceCredentials)
        && Objects.equals(this.targetAudience, other.targetAudience)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName);
  }

  public Builder toBuilder() {
    return new Builder();
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends OAuth2Credentials.Builder {

    private GoogleCredentials sourceCredentials;
    private String targetAudience;
    private List<IdTokenProvider.Option> options;
    private HttpTransportFactory transportFactory;

    protected Builder() {
    }

    public Builder setSourceCredentials(GoogleCredentials sourceCredentials) {
      this.sourceCredentials = sourceCredentials;
      return this;
    }

    public GoogleCredentials getSourceCredentials() {
      return this.sourceCredentials;
    }

    public Builder setTargetAudience(String targetAudience) {
      this.targetAudience = targetAudience;
      return this;
    }

    public String getTargetAudience() {
      return this.targetAudience;
    }

    public Builder setOptions(List<IdTokenProvider.Option> options) {
      this.options = options;
      return this;
    }

    public List<IdTokenProvider.Option> getOptions() {
      return this.options;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public IdTokenCredentials build() {
      return new IdTokenCredentials(this);
    }

  }
}
