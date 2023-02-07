package com.google.auth.oauth2;

import com.google.api.client.googleapis.mtls.MtlsProvider;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.JsonObjectParser;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.http.MtlsHttpTransportFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * MtlsIdentityBoundCredentials .
 *
 * <p>Usage:
 *
 * <pre>

 * </pre>
 */

public class MtlsIdentityBoundCredentials extends GoogleCredentials{
  static final String EMAIL_METADATA_SERVICE_ADDRESS =
      "http://metadata/computeMetadata/v1/instance/service-accounts/default/email";
  private static final String STS_ADDRESS = "https://sts.mtls.googleapis.com/v1/token";
  private static final String IAM_CREDENTIALS_SCOPE = "https://www.googleapis.com/auth/iam";
  public static final String SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:mtls";
  private static final String METADATA_FLAVOR = "Metadata-Flavor";
  private static final String GOOGLE = "Google";

  private final String workloadProviderPool;
  private final String serviceAccountEmail;
  private final String authenticateAsIdentityType;

  private final List<String> scopes;
  private final MtlsProvider mtlsProvider;
  private final MtlsHttpTransportFactory mtlsHttpTransportFactory;

  public MtlsIdentityBoundCredentials(String workloadProviderPool,
      String serviceAccountEmail, String authenticateAsIdentityType,
      List<String> scopes, MtlsProvider mtlsProvider,
      MtlsHttpTransportFactory mtlsHttpTransportFactory) {
    this.workloadProviderPool = workloadProviderPool;
    this.serviceAccountEmail = serviceAccountEmail;
    this.authenticateAsIdentityType = authenticateAsIdentityType;
    this.scopes = scopes;
    this.mtlsProvider = mtlsProvider;
    this.mtlsHttpTransportFactory = mtlsHttpTransportFactory;
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    List<String> stsScope =
        Objects.equals(authenticateAsIdentityType, "gsa")? Arrays.asList(IAM_CREDENTIALS_SCOPE): scopes;

    StsTokenExchangeRequest request =
        StsTokenExchangeRequest.newBuilder(
                " ", SUBJECT_TOKEN_TYPE)
            .setScopes(stsScope)
            .setAudience(workloadProviderPool)
            .setRequestTokenType(OAuth2Utils.TOKEN_TYPE_ACCESS_TOKEN)
            .build();

    AccessToken mtlsIdentityBoundToken = null;
    try {
      StsRequestHandler handler = StsRequestHandler.newBuilder(
              STS_ADDRESS, request, mtlsHttpTransportFactory.newTrustedTransport(mtlsProvider).createRequestFactory())
          .build();
      mtlsIdentityBoundToken = handler.exchangeToken().getAccessToken();
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }

    if (Objects.equals(authenticateAsIdentityType, "gsa") && mtlsIdentityBoundToken != null) {
      AccessToken staticMtlsIdentityBoundToken = mtlsIdentityBoundToken;
      OAuth2Credentials sourceCredentials =
          OAuth2CredentialsWithRefresh.newBuilder()
              .setAccessToken(mtlsIdentityBoundToken)
              .setRefreshHandler(
                  new OAuth2CredentialsWithRefresh.OAuth2RefreshHandler() {
                    @Override
                    public AccessToken refreshAccessToken() {
                      return staticMtlsIdentityBoundToken;
                    }
                  })
              .build();

      MtlsFederatedCredentials federatedCredentials =
          (MtlsFederatedCredentials) MtlsFederatedCredentials.newBuilder()
              .setSourceCredentials(sourceCredentials)
              .setServiceAccountEmail(serviceAccountEmail)
              .setMtlsProvider(mtlsProvider)
              .setMtlsHttpTransportFactory(mtlsHttpTransportFactory)
              .setScopes(scopes)
              .build();
      return federatedCredentials.refreshAccessToken();
    }

    return mtlsIdentityBoundToken;
  }

  public static String getMetadataResource(HttpTransportFactory transportFactory, String url) throws IOException {
    GenericUrl genericUrl = new GenericUrl(url);
    HttpRequest request =
        transportFactory.create().createRequestFactory().buildGetRequest(genericUrl);
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.getHeaders().set(METADATA_FLAVOR, GOOGLE);
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response;
    try {
      response = request.execute();
    } catch (UnknownHostException exception) {
      throw new IOException(
          "MtlsIdentityBoundCredentials cannot find the metadata server.",
          exception);
    }
    String metadataResource = response.parseAsString();
    if (metadataResource.isEmpty()) {
      throw new IOException("Response body was unexpectedly empty.");
    }
    return metadataResource;
  }

  public static BuilderFromFile newBuilder() {
    return new BuilderFromFile();
  }

  public static class BuilderFromFile extends GoogleCredentials.Builder {

    private InputStream certAndKey;
    private String workloadProviderPool;
    private String serviceAccountEmail;
    private String authenticateAsIdentityType;

    private List<String> scopes;
    private MtlsHttpTransportFactory mtlsHttpTransportFactory;
    private MtlsProvider mtlsProvider;

    protected BuilderFromFile() {}

    public BuilderFromFile setCertAndKey(InputStream certAndKey) {
      this.certAndKey = certAndKey;
      return this;
    }

    public BuilderFromFile setWorkloadProviderPool(String workloadProviderPool) {
      this.workloadProviderPool = workloadProviderPool;
      return this;
    }

    public BuilderFromFile setAuthenticateAsIdentityType(String authenticateAsIdentityType) {
      this.authenticateAsIdentityType = authenticateAsIdentityType;
      return this;
    }

    public BuilderFromFile setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public BuilderFromFile setServiceAccountEmail(String serviceAccountEmail) {
      this.serviceAccountEmail = serviceAccountEmail;
      return this;
    }

    public BuilderFromFile setMtlsProvider(MtlsProvider mtlsProvider) {
      this.mtlsProvider = mtlsProvider;
      return this;
    }

    public BuilderFromFile setMtlsHttpTransportFactory(MtlsHttpTransportFactory mtlsHttpTransportFactory) {
      this.mtlsHttpTransportFactory = mtlsHttpTransportFactory;
      return this;
    }

    public MtlsIdentityBoundCredentials build() {
      if (this.certAndKey == null || this.workloadProviderPool == null) {
        return null;
      }
      if (mtlsProvider == null) {
        mtlsProvider = new OAuth2Utils.FromFileMtlsProvider(this.certAndKey);
      }
      if (mtlsHttpTransportFactory == null) {
        mtlsHttpTransportFactory =
            getFromServiceLoader(MtlsHttpTransportFactory.class,
                new OAuth2Utils.DefaultMtlsHttpTransportFactory());
      }
      if (authenticateAsIdentityType == null) {
        authenticateAsIdentityType = "gsa";
      }
      if (serviceAccountEmail == null && Objects.equals(authenticateAsIdentityType, "gsa")) {
        try {
          serviceAccountEmail = getMetadataResource(
              getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY), EMAIL_METADATA_SERVICE_ADDRESS);
        } catch (IOException e) {
          e.printStackTrace();
        }
      }

      return new MtlsIdentityBoundCredentials(
          workloadProviderPool, serviceAccountEmail,
          authenticateAsIdentityType, scopes, mtlsProvider, mtlsHttpTransportFactory);
    }
  }
}
