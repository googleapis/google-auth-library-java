package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ComputeEngineCredentialsTest.MockMetadataServerTransportFactory;
import java.util.concurrent.ExecutorService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test cases for {@link S2A}.*/
@RunWith(JUnit4.class)
public class S2ATest {

	private static final String S2A_ADDRESS_A = "addr_a";
	private static final String S2A_ADDRESS_B = "addr_b";

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
		transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_SERVICE_UNAVAILABLE);

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
	
	@Test
	public void getS2AAdress_multipleThreads_validAddress() throws Exception{
		MockMetadataServerTransportFactory transportFactoryA = new MockMetadataServerTransportFactory();
		transportFactoryA.transport.setS2AAddress(S2A_ADDRESS_A);
		transportFactoryA.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);

		MockMetadataServerTransportFactory transportFactoryB = new MockMetadataServerTransportFactory();
		transportFactoryB.transport.setS2AAddress(S2A_ADDRESS_B);
		transportFactoryB.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);
	
		S2A s2aUtils = new S2A();

		DoGetS2AAddress doGetS2AAddressA = new DoGetS2AAddress(transportFactoryA, S2A_ADDRESS_A, s2aUtils);
		DoGetS2AAddress doGetS2AAddressB = new DoGetS2AAddress(transportFactoryB, S2A_ADDRESS_A, s2aUtils);

		doGetS2AAddressA.start();
		Thread.sleep(2000);
		doGetS2AAddressB.start();

		doGetS2AAddressA.join();
		doGetS2AAddressB.join();
	}

	private class DoGetS2AAddress extends Thread {
		HttpTransportFactory transportFactory;
		String exp_addr;
		S2A s2aUtils;
		public DoGetS2AAddress(HttpTransportFactory transportFactory, String addr, S2A s2aUtils) {
			super();
			this.transportFactory = transportFactory;
			this.exp_addr = addr;
			this.s2aUtils = s2aUtils;
		}

		@Override
		public void run() {	
			s2aUtils.setHttpTransportFactory(transportFactory);
			String s2aAddress = s2aUtils.getS2AAddress();
			assertEquals(exp_addr, s2aAddress);
		}
	}
}


