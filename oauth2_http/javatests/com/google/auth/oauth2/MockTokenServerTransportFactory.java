package com.google.auth.oauth2;

import com.google.api.client.http.HttpTransport;
import com.google.auth.http.HttpTransportFactory;

public class MockTokenServerTransportFactory implements HttpTransportFactory {

  public MockTokenServerTransport transport;

  public MockTokenServerTransportFactory() {
    this(new MockTokenServerTransport());
  }

  MockTokenServerTransportFactory(MockTokenServerTransport transport) {
    this.transport = transport;
  }

  @Override
  public HttpTransport create() {
    return transport;
  }
}
