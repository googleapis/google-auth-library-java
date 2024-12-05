package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import com.google.auth.TestAppender;
import com.google.auth.oauth2.LoggingUtils.LoggerFactoryProvider;
import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.NOPLogger;

public class LoggingUtilsTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(LoggingUtilsTest.class);

  private TestEnvironmentProvider testEnvironmentProvider;

  @Before
  public void setup() {
    testEnvironmentProvider = new TestEnvironmentProvider();
    LoggingUtils.setEnvironmentProvider(testEnvironmentProvider);

    // need to setup a ConsoleAppender and attach to root logger because TestAppender
    // does not correctly capture MDC info
    LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

    PatternLayoutEncoder patternLayoutEncoder = new PatternLayoutEncoder();
    patternLayoutEncoder.setPattern("%-4relative [%thread] %-5level %logger{35} - %msg%n");
    patternLayoutEncoder.setContext(loggerContext);

    patternLayoutEncoder.start();

    ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
    consoleAppender.setEncoder(patternLayoutEncoder);

    consoleAppender.setContext(loggerContext);
    consoleAppender.setName("CONSOLE");

    consoleAppender.start();

    ch.qos.logback.classic.Logger rootLogger = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);
    rootLogger.addAppender(consoleAppender);
  }

  @After
  public void tearDown() {
    LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
    loggerContext.getLogger(Logger.ROOT_LOGGER_NAME).detachAppender("CONSOLE");
  }

  @Test
  public void testGetLogger_loggingEnabled_slf4jBindingPresent() {
    testEnvironmentProvider.setEnv("GOOGLE_SDK_JAVA_LOGGING", "true");
    Logger logger = LoggingUtils.getLogger(LoggingUtilsTest.class);
    assertTrue(logger instanceof org.slf4j.Logger);
    assertNotEquals(logger.getClass(), NOPLogger.class);
  }

  @Test
  public void testGetLogger_loggingDisabled() {
    testEnvironmentProvider.setEnv("GOOGLE_SDK_JAVA_LOGGING", "false");

    Logger logger = LoggingUtils.getLogger(LoggingUtilsTest.class);
    assertEquals(NOPLogger.class, logger.getClass());
  }

  @Test
  public void testGetLogger_loggingEnabled_noBinding() {
    testEnvironmentProvider.setEnv("GOOGLE_SDK_JAVA_LOGGING", "true");
    // Create a mock LoggerFactoryProvider
    LoggerFactoryProvider mockLoggerFactoryProvider = mock(LoggerFactoryProvider.class);
    ILoggerFactory mockLoggerFactory = mock(ILoggerFactory.class);
    when(mockLoggerFactoryProvider.getLoggerFactory()).thenReturn(mockLoggerFactory);
    when(mockLoggerFactory.getLogger(anyString()))
        .thenReturn(org.slf4j.helpers.NOPLogger.NOP_LOGGER);

    // Use the mock LoggerFactoryProvider in getLogger()
    Logger logger = LoggingUtils.getLogger(LoggingUtilsTest.class, mockLoggerFactoryProvider);

    // Assert that the returned logger is a NOPLogger
    assertTrue(logger instanceof org.slf4j.helpers.NOPLogger);
  }

  @Test
  public void testIsLoggingEnabled_true() {
    testEnvironmentProvider.setEnv("GOOGLE_SDK_JAVA_LOGGING", "true");
    assertTrue(LoggingUtils.isLoggingEnabled());
    testEnvironmentProvider.setEnv("GOOGLE_SDK_JAVA_LOGGING", "TRUE");
    assertTrue(LoggingUtils.isLoggingEnabled());
    testEnvironmentProvider.setEnv("GOOGLE_SDK_JAVA_LOGGING", "True");
    assertTrue(LoggingUtils.isLoggingEnabled());
  }

  @Test
  public void testIsLoggingEnabled_defaultToFalse() {
    assertFalse(LoggingUtils.isLoggingEnabled());
  }

  @Test
  public void testLogWithMDC_slf4jLogger() {
    TestAppender.clearEvents();
    Map<String, String> contextMap = new HashMap<>();
    contextMap.put("key", "value");
    LoggingUtils.logWithMDC(LOGGER, org.slf4j.event.Level.DEBUG, contextMap, "test message");

    assertEquals(1, TestAppender.events.size());
    assertEquals("test message", TestAppender.events.get(0).getFormattedMessage());

    // Verify MDC content
    ILoggingEvent event = TestAppender.events.get(0);
    assertEquals("value", event.getMDCPropertyMap().get("key"));
  }
}
