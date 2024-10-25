/*
 * Copyright 2024, Google Inc. All rights reserved.
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

  private static final String INVALID_JSON_KEY = "invalid_key";
  private static final String S2A_PLAINTEXT_ADDRESS = "plaintext";
  private static final String S2A_MTLS_ADDRESS = "mtls";

  @Test
  public void getS2AAddress_validAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AContentMap(
        "plaintextS2AAddressJsonKey", S2A.S2A_PLAINTEXT_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("plaintextS2AAddress", S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setS2AContentMap(
        "mtlsS2AAddressJsonKey", S2A.S2A_MTLS_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("mtlsS2AAddress", S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);

    S2A s2aUtils = S2A.newBuilder().setHttpTransportFactory(transportFactory).build();
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertEquals(S2A_PLAINTEXT_ADDRESS, plaintextS2AAddress);
    assertEquals(S2A_MTLS_ADDRESS, mtlsS2AAddress);
  }

  @Test
  public void getS2AAddress_queryEndpointResponseErrorCode_emptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AContentMap(
        "plaintextS2AAddressJsonKey", S2A.S2A_PLAINTEXT_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("plaintextS2AAddress", S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setS2AContentMap(
        "mtlsS2AAddressJsonKey", S2A.S2A_MTLS_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("mtlsS2AAddress", S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(
        HttpStatusCodes.STATUS_CODE_SERVICE_UNAVAILABLE);

    S2A s2aUtils = S2A.newBuilder().setHttpTransportFactory(transportFactory).build();
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertTrue(plaintextS2AAddress.isEmpty());
    assertTrue(mtlsS2AAddress.isEmpty());
  }

  @Test
  public void getS2AAddress_queryEndpointResponseEmpty_emptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AContentMap(
        "plaintextS2AAddressJsonKey", S2A.S2A_PLAINTEXT_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("plaintextS2AAddress", S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setS2AContentMap(
        "mtlsS2AAddressJsonKey", S2A.S2A_MTLS_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("mtlsS2AAddress", S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);
    transportFactory.transport.setEmptyContent(true);

    S2A s2aUtils = S2A.newBuilder().setHttpTransportFactory(transportFactory).build();
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertTrue(plaintextS2AAddress.isEmpty());
    assertTrue(mtlsS2AAddress.isEmpty());
  }

  @Test
  public void getS2AAddress_queryEndpointResponseInvalidPlaintextJsonKey_plaintextEmptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AContentMap("plaintextS2AAddressJsonKey", INVALID_JSON_KEY);
    transportFactory.transport.setS2AContentMap("plaintextS2AAddress", S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setS2AContentMap(
        "mtlsS2AAddressJsonKey", S2A.S2A_MTLS_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("mtlsS2AAddress", S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);

    S2A s2aUtils = S2A.newBuilder().setHttpTransportFactory(transportFactory).build();
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertTrue(plaintextS2AAddress.isEmpty());
    assertEquals(S2A_MTLS_ADDRESS, mtlsS2AAddress);
  }

  @Test
  public void getS2AAddress_queryEndpointResponseInvalidMtlsJsonKey_mtlsEmptyAddress() {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setS2AContentMap(
        "plaintextS2AAddressJsonKey", S2A.S2A_PLAINTEXT_ADDRESS_JSON_KEY);
    transportFactory.transport.setS2AContentMap("plaintextS2AAddress", S2A_PLAINTEXT_ADDRESS);
    transportFactory.transport.setS2AContentMap("mtlsS2AAddressJsonKey", INVALID_JSON_KEY);
    transportFactory.transport.setS2AContentMap("mtlsS2AAddress", S2A_MTLS_ADDRESS);
    transportFactory.transport.setRequestStatusCode(HttpStatusCodes.STATUS_CODE_OK);

    S2A s2aUtils = S2A.newBuilder().setHttpTransportFactory(transportFactory).build();
    String plaintextS2AAddress = s2aUtils.getPlaintextS2AAddress();
    String mtlsS2AAddress = s2aUtils.getMtlsS2AAddress();
    assertEquals(S2A_PLAINTEXT_ADDRESS, plaintextS2AAddress);
    assertTrue(mtlsS2AAddress.isEmpty());
  }
}
