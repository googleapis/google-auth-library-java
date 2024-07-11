package com.google.auth.oauth2;

import com.google.api.client.http.HttpTransport;
import com.google.auth.http.HttpTransportFactory;

public class MockTokenServerTransportFactory implements HttpTransportFactory {

  MockTokenServerTransport transport;

  public MockTokenServerTransportFactory() {
    this.transport = new MockTokenServerTransport();
  }

  public MockTokenServerTransport getTransport() {
    return transport;
  }

  @Override
  public HttpTransport create() {
    return transport;
  }
}
