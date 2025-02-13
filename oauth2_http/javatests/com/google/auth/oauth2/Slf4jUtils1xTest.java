package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

import com.google.api.client.util.GenericData;
import java.util.Map;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Slf4jUtils1xTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(Slf4jUtilsTest.class);

  private TestAppender setupTestLogger() {
    TestAppender testAppender = new TestAppender();
    testAppender.start();
    ((ch.qos.logback.classic.Logger) LOGGER).addAppender(testAppender);
    return testAppender;
  }

  @Test
  @Ignore("This test needs slf4j1.x")
  public void testLogGenericData() {
    TestAppender testAppender = setupTestLogger();
    GenericData genericData = Mockito.mock(GenericData.class);

    GenericData data = new GenericData();
    data.put("key1", "value1");
    data.put("token", "value2");

    LoggerProvider loggerProvider = Mockito.mock(LoggerProvider.class);
    when(loggerProvider.getLogger()).thenReturn(LOGGER);
    LoggingUtils.logGenericData(data, loggerProvider, "test generic data");

    assertEquals(1, testAppender.events.size());
    Map<String, String> mdcPropertyMap = testAppender.events.get(0).getMDCPropertyMap();
    assertEquals(2, mdcPropertyMap.size());
    assertEquals("value1", mdcPropertyMap.get("key1"));
    assertNotNull(mdcPropertyMap.get("token"));
    assertNotEquals("value2", mdcPropertyMap.get("token"));

    testAppender.stop();
  }
}
