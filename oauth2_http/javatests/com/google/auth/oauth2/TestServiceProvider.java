package com.google.auth.oauth2;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.slf4j.ILoggerFactory;
import org.slf4j.IMarkerFactory;
import org.slf4j.spi.MDCAdapter;
import org.slf4j.spi.SLF4JServiceProvider;

/**
 * This provider is made discoverable to SFL4J's LoggerFactory in
 * resources/META-INF/services/org.slf4j.spi.SLF4JServiceProvider
 */
public class TestServiceProvider implements SLF4JServiceProvider {

  @Override
  public ILoggerFactory getLoggerFactory() {
    // mock behavior when provider present
    ILoggerFactory mockLoggerFactory = mock(ILoggerFactory.class);
    when(mockLoggerFactory.getLogger(anyString())).thenReturn(new TestLogger("test-logger"));
    return mockLoggerFactory;
  }

  @Override
  public IMarkerFactory getMarkerFactory() {
    return null;
  }

  @Override
  public MDCAdapter getMDCAdapter() {
    return new TestMDCAdapter();
  }

  @Override
  public String getRequestedApiVersion() {
    return "";
  }

  @Override
  public void initialize() {}
}
