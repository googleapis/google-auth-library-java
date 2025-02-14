/*
 * Copyright 2025 Google LLC
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
    LoggingUtils.logResponsePayload(data, loggerProvider, "test generic data");

    assertEquals(1, testAppender.events.size());
    Map<String, String> mdcPropertyMap = testAppender.events.get(0).getMDCPropertyMap();
    assertEquals(2, mdcPropertyMap.size());
    assertEquals("value1", mdcPropertyMap.get("key1"));
    assertNotNull(mdcPropertyMap.get("token"));
    assertNotEquals("value2", mdcPropertyMap.get("token"));

    testAppender.stop();
  }
}
