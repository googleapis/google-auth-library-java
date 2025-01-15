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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.LoggerContext;
import com.google.auth.oauth2.LoggingConfigs.LoggerFactoryProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.NOPLogger;

public class LoggingConfigsTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(LoggingConfigsTest.class);

  private TestEnvironmentProvider testEnvironmentProvider;

  @Before
  public void setup() {
    testEnvironmentProvider = new TestEnvironmentProvider();
  }

  @After
  public void tearDown() {
    LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
    loggerContext.getLogger(Logger.ROOT_LOGGER_NAME).detachAppender("CONSOLE");
  }

  @Test
  public void testGetLogger_loggingEnabled_slf4jBindingPresent() {
    testEnvironmentProvider.setEnv(LoggingConfigs.GOOGLE_SDK_JAVA_LOGGING_ENV, "true");
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);
    Logger logger = LoggingConfigs.getLogger(LoggingConfigsTest.class);
    assertNotNull(logger);
    assertNotEquals(NOPLogger.class, logger.getClass());
  }

  @Test
  public void testGetLogger_loggingDisabled() {
    testEnvironmentProvider.setEnv(LoggingConfigs.GOOGLE_SDK_JAVA_LOGGING_ENV, "false");
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);

    Logger logger = LoggingConfigs.getLogger(LoggingConfigsTest.class);
    assertEquals(NOPLogger.class, logger.getClass());
  }

  @Test
  public void testGetLogger_loggingEnabled_noBinding() {
    testEnvironmentProvider.setEnv(LoggingConfigs.GOOGLE_SDK_JAVA_LOGGING_ENV, "true");
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);
    // Create a mock LoggerFactoryProvider
    LoggerFactoryProvider mockLoggerFactoryProvider = mock(LoggerFactoryProvider.class);
    ILoggerFactory mockLoggerFactory = mock(ILoggerFactory.class);
    when(mockLoggerFactoryProvider.getLoggerFactory()).thenReturn(mockLoggerFactory);
    when(mockLoggerFactory.getLogger(anyString()))
        .thenReturn(org.slf4j.helpers.NOPLogger.NOP_LOGGER);

    // Use the mock LoggerFactoryProvider in getLogger()
    Logger logger = LoggingConfigs.getLogger(LoggingConfigsTest.class, mockLoggerFactoryProvider);

    // Assert that the returned logger is a NOPLogger
    assertTrue(logger instanceof org.slf4j.helpers.NOPLogger);
  }

  @Test
  public void testIsLoggingEnabled_true() {
    testEnvironmentProvider.setEnv(LoggingConfigs.GOOGLE_SDK_JAVA_LOGGING_ENV, "true");
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);
    assertTrue(LoggingConfigs.isLoggingEnabled());
    testEnvironmentProvider.setEnv(LoggingConfigs.GOOGLE_SDK_JAVA_LOGGING_ENV, "TRUE");
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);
    assertTrue(LoggingConfigs.isLoggingEnabled());
    testEnvironmentProvider.setEnv(LoggingConfigs.GOOGLE_SDK_JAVA_LOGGING_ENV, "True");
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);
    assertTrue(LoggingConfigs.isLoggingEnabled());
  }

  @Test
  public void testIsLoggingEnabled_defaultToFalse() {
    LoggingConfigs.setEnvironmentProvider(testEnvironmentProvider);
    assertFalse(LoggingConfigs.isLoggingEnabled());
  }
}
