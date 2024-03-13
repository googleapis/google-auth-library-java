package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpStatusCodes;
import com.google.auth.oauth2.ComputeEngineCredentialsTest.MockMetadataServerTransportFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test cases for {@link S2A}. */
@RunWith(JUnit4.class)
public class S2ATest {

  private static final String S2A_PLAINTEXT_ADDRESS = "plaintext";
  private static final String S2A_MTLS_ADDRESS = "mtls";

  @Test
  public void getS2AAddress_validAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setPlaintextS2AAddress(S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setMtlsS2AAddress(S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);

    S2A s2aUtils = new S2A();
    s2aUtils.setHttpTransportFactory(transportFactory);
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertEquals(S2A_PLAINTEXT_ADDRESS, plaintextS2AAddress);
    assertEquals(S2A_MTLS_ADDRESS, mtlsS2AAddress);
  }

  @Test
  public void getS2AAddress_queryEndpointResponseErrorCode_emptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setPlaintextS2AAddress(S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setMtlsS2AAddress(S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(
        HttpStatusCodes.STATUS_CODE_SERVICE_UNAVAILABLE);

    S2A s2aUtils = new S2A();
    s2aUtils.setHttpTransportFactory(transportFactory);
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertTrue(plaintextS2AAddress.isEmpty());
    assertTrue(mtlsS2AAddress.isEmpty());
  }

  @Test
  public void getS2AAddress_queryEndpointResponseEmpty_emptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setPlaintextS2AAddress(S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setMtlsS2AAddress(S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);
    transportFactory.transport.setEmptyContent(true);

    S2A s2aUtils = new S2A();
    s2aUtils.setHttpTransportFactory(transportFactory);
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertTrue(plaintextS2AAddress.isEmpty());
    assertTrue(mtlsS2AAddress.isEmpty());
  }
}
