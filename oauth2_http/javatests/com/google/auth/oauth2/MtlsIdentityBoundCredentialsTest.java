package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.google.api.client.googleapis.mtls.MtlsProvider;
import com.google.api.client.http.HttpTransport;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.http.MtlsHttpTransportFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Map;
import org.junit.Test;

public class MtlsIdentityBoundCredentialsTest {
  private static final String MTLS_CERT_AND_KEY_FILE = "testresources/mtlsCertAndKey.pem";
  private static final String WORKLOAD_IDENTITY_PROVIDER = "//iam.googleapis.com/projects/1234567890123/locations/global/workloadIdentityPools/my-pool/providers/my-provider";
  private static final String SERVICE_ACCOUNT_EMAIL = "my-app@appspot.gserviceaccount.com";

  static class MockMtlsTransportFactory implements MtlsHttpTransportFactory {

    MockMtlsStsTransport transport = new MockMtlsStsTransport();;

    @Override
    public HttpTransport newTrustedTransport(MtlsProvider mtlsProvider)
        throws GeneralSecurityException, IOException {
      transport.addMtlsProvider(mtlsProvider);
      return transport;
    }
  }

  static class MockMetadataServerTransportFactory implements HttpTransportFactory {

    MockMetadataServerTransport transport = new MockMetadataServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void getMetadataResource_serviceAccountEmail() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setServiceAccountEmail(SERVICE_ACCOUNT_EMAIL);

    assertEquals(SERVICE_ACCOUNT_EMAIL, MtlsIdentityBoundCredentials.getMetadataResource
        (transportFactory, MtlsIdentityBoundCredentials.EMAIL_METADATA_SERVICE_ADDRESS));
  }

  @Test
  public void refreshAccessToken_success() throws IOException {
    InputStream certAndKey = new FileInputStream(MTLS_CERT_AND_KEY_FILE);
    MockMtlsTransportFactory transportFactory = new MockMtlsTransportFactory();

    transportFactory.transport.addExpectedWorkloadProviderPool(WORKLOAD_IDENTITY_PROVIDER);

    MtlsIdentityBoundCredentials credentials = MtlsIdentityBoundCredentials.newBuilder()
        .setCertAndKey(certAndKey)
        .setWorkloadProviderPool(WORKLOAD_IDENTITY_PROVIDER)
        .setAuthenticateAsIdentityType("native")
        .setMtlsHttpTransportFactory(transportFactory)
        .build();

    AccessToken accessToken = credentials.refreshAccessToken();

    assertEquals(transportFactory.transport.getAccessToken(), accessToken.getTokenValue());

    Map<String, String> query =
        TestUtils.parseQuery(transportFactory.transport.getRequest().getContentAsString());
    assertEquals(
        "urn:ietf:params:oauth:token-type:access_token", query.get("requested_token_type"));
  }

  @Test
  public void credential_missing_workloadIdentityProvider() throws IOException {
    InputStream certAndKey = new FileInputStream(MTLS_CERT_AND_KEY_FILE);
    MockMtlsTransportFactory transportFactory = new MockMtlsTransportFactory();

    transportFactory.transport.addExpectedWorkloadProviderPool(WORKLOAD_IDENTITY_PROVIDER);

    MtlsIdentityBoundCredentials credentials = MtlsIdentityBoundCredentials.newBuilder()
        .setCertAndKey(certAndKey)
        .setAuthenticateAsIdentityType("native")
        .setMtlsHttpTransportFactory(transportFactory)
        .build();

    assertNull(credentials);
  }

  @Test
  public void credential_missing_certAndKey() throws IOException {
    InputStream certAndKey = new FileInputStream(MTLS_CERT_AND_KEY_FILE);
    MockMtlsTransportFactory transportFactory = new MockMtlsTransportFactory();

    transportFactory.transport.addExpectedWorkloadProviderPool(WORKLOAD_IDENTITY_PROVIDER);

    MtlsIdentityBoundCredentials credentials = MtlsIdentityBoundCredentials.newBuilder()
        .setWorkloadProviderPool(WORKLOAD_IDENTITY_PROVIDER)
        .setAuthenticateAsIdentityType("native")
        .setMtlsHttpTransportFactory(transportFactory)
        .build();

    assertNull(credentials);
  }
}
