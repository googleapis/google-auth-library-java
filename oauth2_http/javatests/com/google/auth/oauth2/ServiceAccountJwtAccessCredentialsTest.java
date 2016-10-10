/*
 * Copyright 2015, Google Inc. All rights reserved.
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.http.AuthHttpConstants;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

/**
 * Test case for {@link ServiceAccountCredentials}.
 */
@RunWith(JUnit4.class)
public class ServiceAccountJwtAccessCredentialsTest extends BaseSerializationTest {

  private final static String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private final static String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private final static String SA_PRIVATE_KEY_ID =
      "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  static final String SA_PRIVATE_KEY_PKCS8 = "-----BEGIN PRIVATE KEY-----\n"
      + "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALX0PQoe1igW12i"
      + "kv1bN/r9lN749y2ijmbc/mFHPyS3hNTyOCjDvBbXYbDhQJzWVUikh4mvGBA07qTj79Xc3yBDfKP2IeyYQIFe0t0"
      + "zkd7R9Zdn98Y2rIQC47aAbDfubtkU1U72t4zL11kHvoa0/RuFZjncvlr42X7be7lYh4p3NAgMBAAECgYASk5wDw"
      + "4Az2ZkmeuN6Fk/y9H+Lcb2pskJIXjrL533vrDWGOC48LrsThMQPv8cxBky8HFSEklPpkfTF95tpD43iVwJRB/Gr"
      + "CtGTw65IfJ4/tI09h6zGc4yqvIo1cHX/LQ+SxKLGyir/dQM925rGt/VojxY5ryJR7GLbCzxPnJm/oQJBANwOCO6"
      + "D2hy1LQYJhXh7O+RLtA/tSnT1xyMQsGT+uUCMiKS2bSKx2wxo9k7h3OegNJIu1q6nZ6AbxDK8H3+d0dUCQQDTrP"
      + "SXagBxzp8PecbaCHjzNRSQE2in81qYnrAFNB4o3DpHyMMY6s5ALLeHKscEWnqP8Ur6X4PvzZecCWU9BKAZAkAut"
      + "LPknAuxSCsUOvUfS1i87ex77Ot+w6POp34pEX+UWb+u5iFn2cQacDTHLV1LtE80L8jVLSbrbrlH43H0DjU5AkEA"
      + "gidhycxS86dxpEljnOMCw8CKoUBd5I880IUahEiUltk7OLJYS/Ts1wbn3kPOVX3wyJs8WBDtBkFrDHW2ezth2QJ"
      + "ADj3e1YhMVdjJW5jqwlD/VNddGjgzyunmiZg0uOXsHXbytYmsA545S8KRQFaJKFXYYFo2kOjqOiC1T2cAzMDjCQ"
      + "==\n-----END PRIVATE KEY-----\n";
  private static final String JWT_ACCESS_PREFIX =
      ServiceAccountJwtAccessCredentials.JWT_ACCESS_PREFIX;
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");
  private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
  
  @Test 
  public void constructor_allParameters_constructs() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID);
    
    assertEquals(SA_CLIENT_ID, credentials.getClientId());
    assertEquals(SA_CLIENT_EMAIL, credentials.getClientEmail());
    assertEquals(privateKey, credentials.getPrivateKey());
    assertEquals(SA_PRIVATE_KEY_ID, credentials.getPrivateKeyId());
  }

  @Test 
  public void constructor_noClientId_constructs() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    new ServiceAccountJwtAccessCredentials(null, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID);    
  }

  @Test 
  public void constructor_noPrivateKeyId_constructs() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    new ServiceAccountJwtAccessCredentials(SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, null);    
  }

  @Test 
  public void constructor_noEmail_throws() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    try {
          new ServiceAccountJwtAccessCredentials(SA_CLIENT_ID, null, privateKey, SA_PRIVATE_KEY_ID);
      fail("exception expected");
    } catch (NullPointerException e) {
      // Expected
    }
  }

  @Test 
  public void constructor_noPrivateKey_throws() {
    try {
      new ServiceAccountJwtAccessCredentials(
          SA_CLIENT_ID, SA_CLIENT_EMAIL, null , SA_PRIVATE_KEY_ID);
      fail("exception expected");
    } catch (NullPointerException e) {
      // Expected
    }
  }
  
  @Test
  public void getAuthenticationType_returnsJwtAccess() throws IOException {
    Credentials credentials = ServiceAccountJwtAccessCredentials
        .fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);
    assertEquals(credentials.getAuthenticationType(), "JWTAccess");
  }

  @Test
  public void hasRequestMetadata_returnsTrue() throws IOException {
    Credentials credentials = ServiceAccountJwtAccessCredentials
        .fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);
    assertTrue(credentials.hasRequestMetadata());
  }

  @Test
  public void hasRequestMetadataOnly_returnsTrue() throws IOException {
    Credentials credentials = ServiceAccountJwtAccessCredentials
        .fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);
    assertTrue(credentials.hasRequestMetadataOnly());
  }

  @Test
  public void getRequestMetadata_blocking_hasJwtAccess() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    Credentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    verifyJwtAccess(metadata, SA_CLIENT_EMAIL, CALL_URI, SA_PRIVATE_KEY_ID);
  }

  @Test
  public void getRequestMetadata_blocking_defaultURI_hasJwtAccess() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    Credentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);

    Map<String, List<String>> metadata = credentials.getRequestMetadata();

    verifyJwtAccess(metadata, SA_CLIENT_EMAIL, CALL_URI, SA_PRIVATE_KEY_ID);
  }

  @Test
  public void getRequestMetadata_blocking_noURI_throws() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    Credentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID);

    try {
      credentials.getRequestMetadata();
      fail("exception expected");
    } catch (IOException e) {
      // Expected
    }
  }

  @Test
  public void getRequestMetadata_async_hasJwtAccess() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    Credentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID);
    MockExecutor executor = new MockExecutor();
    MockRequestMetadataCallback callback = new MockRequestMetadataCallback();

    credentials.getRequestMetadata(CALL_URI, executor, callback);
    assertEquals(0, executor.numTasks());
    assertNotNull(callback.metadata);
    verifyJwtAccess(callback.metadata, SA_CLIENT_EMAIL, CALL_URI, SA_PRIVATE_KEY_ID);
  }

  @Test
  public void getRequestMetadata_async_defaultURI_hasJwtAccess() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    Credentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    MockExecutor executor = new MockExecutor();
    MockRequestMetadataCallback callback = new MockRequestMetadataCallback();

    credentials.getRequestMetadata(null, executor, callback);
    assertEquals(0, executor.numTasks());
    assertNotNull(callback.metadata);
    verifyJwtAccess(callback.metadata, SA_CLIENT_EMAIL, CALL_URI, SA_PRIVATE_KEY_ID);
  }

  @Test
  public void getRequestMetadata_async_noURI_exception() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    Credentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID);
    MockExecutor executor = new MockExecutor();
    MockRequestMetadataCallback callback = new MockRequestMetadataCallback();

    credentials.getRequestMetadata(null, executor, callback);
    assertEquals(0, executor.numTasks());
    assertNotNull(callback.exception);
  }

  @Test
  public void equals_true() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials otherCredentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_clientId() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials otherCredentials = new ServiceAccountJwtAccessCredentials(
        "otherClientId", SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_email() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials otherCredentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, "otherClientEmail", privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_keyId() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials otherCredentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, "otherKeyId", CALL_URI);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false_callUri() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    final URI otherCallUri = URI.create("https://foo.com/bar");
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials otherCredentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, otherCallUri);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    String expectedToString = String.format(
        "ServiceAccountJwtAccessCredentials{clientId=%s, clientEmail=%s, privateKeyId=%s, "
            + "defaultAudience=%s}",
        SA_CLIENT_ID,
        SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_ID,
        CALL_URI);
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials otherCredentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    ServiceAccountJwtAccessCredentials credentials = new ServiceAccountJwtAccessCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, CALL_URI);
    ServiceAccountJwtAccessCredentials deserializedCredentials =
        serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  private void verifyJwtAccess(Map<String, List<String>> metadata, String expectedEmail,
      URI expectedAudience, String expectedKeyId) throws IOException {
    assertNotNull(metadata);
    List<String> authorizations = metadata.get(AuthHttpConstants.AUTHORIZATION);
    assertNotNull("Authorization headers not found", authorizations);
    String assertion = null;
    for (String authorization : authorizations) {
      if (authorization.startsWith(JWT_ACCESS_PREFIX)) {
        assertNull("Multiple bearer assertions found", assertion);
        assertion = authorization.substring(JWT_ACCESS_PREFIX.length());
      }
    }
    assertNotNull("Bearer assertion not found", assertion);
    JsonWebSignature signature = JsonWebSignature.parse(JSON_FACTORY, assertion);
    assertEquals(expectedEmail, signature.getPayload().getIssuer());
    assertEquals(expectedEmail, signature.getPayload().getSubject());
    assertEquals(expectedAudience.toString(), signature.getPayload().getAudience());
    assertEquals(expectedKeyId, signature.getHeader().getKeyId());
  }
}
