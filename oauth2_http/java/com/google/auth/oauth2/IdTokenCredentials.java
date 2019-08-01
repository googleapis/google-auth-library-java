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


import com.google.common.base.MoreObjects;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * IdTokenCredentials provides a Google Issued OpenIdConnect token. <br>
 * Use an ID token to access services that require presenting an ID token for authentication such as
 * Cloud Functions or Cloud Run.<br>
 * The following Credential subclasses support IDTokens: ServiceAccountCredentials,
 * ComputeEngineCredentials, ImpersonatedCredentials.
 *
 * <p>For more information see <br>
 * Usage:<br>
 *
 * <pre>
 * String credPath = "/path/to/svc_account.json";
 * String targetAudience = "https://example.com";
 *
 * // For Application Default Credentials (as ServiceAccountCredentials)
 * // export GOOGLE_APPLICATION_CREDENTIALS=/path/to/svc.json
 * GoogleCredentials adcCreds = GoogleCredentials.getApplicationDefault();
 * if (!adcCreds instanceof IdTokenProvider) {
 *   // handle error message
 * }
 * IdTokenCredentials tokenCredential = IdTokenCredentials.create((IdTokenProvider) adcCreds, targetAudience);
 * // or
 * IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder()
 *     .setIdTokenProvider((IdTokenProvider) adcCreds)
 *     .setTargetAudience(targetAudience).build();
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

  private IdTokenProvider idTokenProvider;
  private String targetAudience;
  private List<IdTokenProvider.Option> options;


  /**
   * Returns IdToken credentials associated with the sourceCredentials and with an audience
   * specified. Specify extensions and additional claims for the IdToken by applying any approprite
   * Options for the given credential type.
   *
   * @param idTokenProvider The source credential for the Id Token that implements IdTokenProvider 
   * @param targetAudience The audience field for the issued ID Token
   * @param options List of Credential specific options for for the token. For example, an IDToken
   *     for a ComputeEngineCredential can return platform specific claims if
   *     "ComputeEngineCredentials.ID_TOKEN_FORMAT_FULL" is provided as a list option.
   *     tokens.
   * @return IdTokenCredential
   */
  public static IdTokenCredentials create(
      IdTokenProvider idTokenProvider,
      String targetAudience,
      List<IdTokenProvider.Option> options) {
    return IdTokenCredentials.newBuilder()
        .setIdTokenProvider(idTokenProvider)
        .setTargetAudience(targetAudience)
        .setOptions(options)
        .build();
  }

  /**
   * Returns IdToken credentials associated with the sourceCredentials and with an audience
   * specified.
   *
   * @param idTokenProvider The source credential for the Id Token that implements IdTokenProvider 
   * @param targetAudience The audience field for the issued ID Token
   * @return IdTokenCredential
   */
  public static IdTokenCredentials create(
      IdTokenProvider idTokenProvider, String targetAudience) {
    return IdTokenCredentials.newBuilder()
        .setIdTokenProvider(idTokenProvider)
        .setTargetAudience(targetAudience)
        .build();
  }

  private IdTokenCredentials(Builder builder) {
    this.idTokenProvider = builder.getIdTokenProvider();
    this.targetAudience = builder.getTargetAudience();
    this.options = builder.getOptions();
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    return this.idTokenProvider.idTokenWithAudience(targetAudience, options);
  }

  public IdToken getIdToken() {
    return (IdToken) getAccessToken();
  }

  @Override
  public int hashCode() {
    return Objects.hash(idTokenProvider);
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
    return Objects.equals(this.idTokenProvider, other.idTokenProvider)
        && Objects.equals(this.targetAudience, other.targetAudience);
  }

  public Builder toBuilder() {
    return new Builder();
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends OAuth2Credentials.Builder {

    private IdTokenProvider idTokenProvider;
    private String targetAudience;
    private List<IdTokenProvider.Option> options;

    protected Builder() {}

    public Builder setIdTokenProvider(IdTokenProvider idTokenProvider) {
      this.idTokenProvider = idTokenProvider;
      return this;
    }

    public IdTokenProvider getIdTokenProvider() {
      return this.idTokenProvider;
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

    public IdTokenCredentials build() {
      return new IdTokenCredentials(this);
    }
  }
}
