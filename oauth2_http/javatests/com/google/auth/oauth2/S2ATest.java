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

  private static final String S2A_ADDRESS_A = "addr_a";

  @Test
  public void getS2AAddress_validAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AAddress(S2A_ADDRESS_A);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);

    S2A s2aUtils = new S2A();
    s2aUtils.setHttpTransportFactory(transportFactory);
    String s2aAddress = s2aUtils.getS2AAddress();
    assertEquals(S2A_ADDRESS_A, s2aAddress);
  }

  @Test
  public void getS2AAddress_queryEndpointResponseErrorCode_emptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AAddress(S2A_ADDRESS_A);
    transportFactory.transport.setRequestStatusCode(
        HttpStatusCodes.STATUS_CODE_SERVICE_UNAVAILABLE);

    S2A s2aUtils = new S2A();
    s2aUtils.setHttpTransportFactory(transportFactory);
    String s2aAddress = s2aUtils.getS2AAddress();
    assertTrue(s2aAddress.isEmpty());
  }

  @Test
  public void getS2AAddress_queryEndpointResponseEmpty_emptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AAddress(S2A_ADDRESS_A);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);
    transportFactory.transport.setEmptyContent(true);

    S2A s2aUtils = new S2A();
    s2aUtils.setHttpTransportFactory(transportFactory);
    String s2aAddress = s2aUtils.getS2AAddress();
    assertTrue(s2aAddress.isEmpty());
  }
}
