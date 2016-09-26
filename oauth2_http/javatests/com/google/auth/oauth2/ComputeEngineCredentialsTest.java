package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Test case for {@link ComputeEngineCredentials}.
 */
@RunWith(JUnit4.class)
public class ComputeEngineCredentialsTest extends BaseSerializationTest {

  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  static class MockMetadataServerTransportFactory implements HttpTransportFactory {

    MockMetadataServerTransport transport = new MockMetadataServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void getRequestMetadata_hasAccessToken() throws IOException {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(transportFactory);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, accessToken);
  }

  @Test
  public void getRequestMetadata_missingServiceAccount_throws() {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(transportFactory);

    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Expected error refreshing token.");
    } catch (IOException expected) {
      String message = expected.getMessage();
      assertTrue(message.contains(Integer.toString(HttpStatusCodes.STATUS_CODE_NOT_FOUND)));
      // Message should mention scopes are missing on the VM.
      assertTrue(message.contains("scope"));
    }
  }

  public void getRequestMetadata_serverError_throws() {
    final String accessToken = "1/MkSJoj1xsli0AccessToken_NKPY2";
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    transportFactory.transport.setAccessToken(accessToken);
    transportFactory.transport.setTokenRequestStatusCode(HttpStatusCodes.STATUS_CODE_NOT_FOUND);
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(transportFactory);

    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Expected error refreshing token.");
    } catch (IOException expected) {
      String message = expected.getMessage();
      assertTrue(message.contains(Integer.toString(HttpStatusCodes.STATUS_CODE_SERVER_ERROR)));
      assertTrue(message.contains("Unexpected"));
    }
  }

  @Test
  public void equals_true() throws IOException {
    MockMetadataServerTransportFactory transportFactory = new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(transportFactory);
    ComputeEngineCredentials otherCredentials = new ComputeEngineCredentials(transportFactory);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false() throws IOException {
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(serverTransportFactory);
    ComputeEngineCredentials otherCredentials = new ComputeEngineCredentials(httpTransportFactory);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    String expectedToString =
        String.format("ComputeEngineCredentials{transportFactoryClassName=%s}",
            MockMetadataServerTransportFactory.class.getName());
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(serverTransportFactory);
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(serverTransportFactory);
    ComputeEngineCredentials otherCredentials =
        new ComputeEngineCredentials(serverTransportFactory);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void hashCode_notEquals() throws IOException {
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(serverTransportFactory);
    ComputeEngineCredentials otherCredentials = new ComputeEngineCredentials(httpTransportFactory);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    MockMetadataServerTransportFactory serverTransportFactory =
        new MockMetadataServerTransportFactory();
    ComputeEngineCredentials credentials = new ComputeEngineCredentials(serverTransportFactory);
    GoogleCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
    credentials = new ComputeEngineCredentials();
    deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }
}
