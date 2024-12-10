/*
 * Copyright 2024 Google LLC
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
 *    * Neither the name of Google LLC nor the names of its
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

import static org.junit.Assert.*;

import ch.qos.logback.classic.spi.ILoggingEvent;
import com.google.api.client.util.GenericData;
import com.google.auth.TestAppender;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

public class LoggingUtilsTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(LoggingUtilsTest.class);

  private TestAppender setupTestLogger() {
    TestAppender testAppender = new TestAppender();
    testAppender.start();
    ((ch.qos.logback.classic.Logger) LOGGER).addAppender(testAppender);
    return testAppender;
  }

  @Test
  public void testLogWithMDC_slf4jLogger() {

    TestAppender testAppender = setupTestLogger();

    Map<String, String> contextMap = new HashMap<>();
    contextMap.put("key1", "value1");
    contextMap.put("key2", "value2");
    LoggingUtils.logWithMDC(LOGGER, Level.DEBUG, contextMap, "test message");

    assertEquals(1, testAppender.events.size());
    assertEquals("test message", testAppender.events.get(0).getFormattedMessage());

    // Verify MDC content
    ILoggingEvent event = testAppender.events.get(0);
    assertEquals(2, event.getMDCPropertyMap().size());
    assertEquals(ch.qos.logback.classic.Level.DEBUG, event.getLevel());
    assertEquals("value1", event.getMDCPropertyMap().get("key1"));
    assertEquals("value2", event.getMDCPropertyMap().get("key2"));

    testAppender.stop();
  }

  @Test
  public void testLogWithMDC_INFO() {
    TestAppender testAppender = setupTestLogger();
    LoggingUtils.logWithMDC(LOGGER, Level.INFO, new HashMap<>(), "test message");

    assertEquals(1, testAppender.events.size());
    assertEquals(ch.qos.logback.classic.Level.INFO, testAppender.events.get(0).getLevel());
    testAppender.stop();
  }

  @Test
  public void testLogWithMDC_TRACE() {
    TestAppender testAppender = setupTestLogger();
    LoggingUtils.logWithMDC(LOGGER, Level.TRACE, new HashMap<>(), "test message");

    assertEquals(0, testAppender.events.size());
    testAppender.stop();
  }

  @Test
  public void testLogWithMDC_WARN() {
    TestAppender testAppender = setupTestLogger();
    LoggingUtils.logWithMDC(LOGGER, Level.WARN, new HashMap<>(), "test message");

    assertEquals(1, testAppender.events.size());
    assertEquals(ch.qos.logback.classic.Level.WARN, testAppender.events.get(0).getLevel());
    testAppender.stop();
  }

  @Test
  public void testLogWithMDC_ERROR() {
    TestAppender testAppender = setupTestLogger();
    LoggingUtils.logWithMDC(LOGGER, Level.ERROR, new HashMap<>(), "test message");

    assertEquals(1, testAppender.events.size());
    assertEquals(ch.qos.logback.classic.Level.ERROR, testAppender.events.get(0).getLevel());
    testAppender.stop();
  }

  @Test
  public void testLogGenericData() {
    TestAppender testAppender = setupTestLogger();
    GenericData genericData = Mockito.mock(GenericData.class);

    GenericData data = new GenericData();
    data.put("key1", "value1");
    data.put("token", "value2");

    LoggingUtils.logGenericData(data, LOGGER, "test generic data");

    assertEquals(1, testAppender.events.size());
    Map<String, String> mdcPropertyMap = testAppender.events.get(0).getMDCPropertyMap();
    assertEquals(2, mdcPropertyMap.size());
    assertEquals("value1", mdcPropertyMap.get("key1"));
    assertNotNull(mdcPropertyMap.get("token"));
    assertNotEquals("value2", mdcPropertyMap.get("token"));

    testAppender.stop();
  }

  private TestAppender setupTestLogger(Class<?> clazz) {
    TestAppender testAppender = new TestAppender();
    testAppender.start();
    Logger logger = LoggerFactory.getLogger(clazz);
    ((ch.qos.logback.classic.Logger) logger).addAppender(testAppender);
    return testAppender;
  }
}
