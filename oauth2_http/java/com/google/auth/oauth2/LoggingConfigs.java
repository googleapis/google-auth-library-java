package com.google.auth.oauth2;

import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class LoggingConfigs {

  private static EnvironmentProvider environmentProvider = SystemEnvironmentProvider.getInstance();
  private static final Logger NO_OP_LOGGER = org.slf4j.helpers.NOPLogger.NOP_LOGGER;
  private static boolean loggingEnabled = isLoggingEnabled();
  // expose this setter only for testing purposes
  static void setEnvironmentProvider(EnvironmentProvider provider) {
    environmentProvider = provider;
    // Recalculate LOGGING_ENABLED after setting the new provider
    loggingEnabled = isLoggingEnabled();
  }

  private LoggingConfigs() {}

  static Logger getLogger(Class<?> clazz) {
    return getLogger(clazz, new DefaultLoggerFactoryProvider());
  }

  // constructor with LoggerFactoryProvider to make testing easier
  static Logger getLogger(Class<?> clazz, LoggerFactoryProvider factoryProvider) {
    if (loggingEnabled) {
      return factoryProvider.getLoggerFactory().getLogger(clazz.getName());
    } else {
      //  use SLF4j's NOP logger regardless of bindings
      return NO_OP_LOGGER;
    }
  }

  static boolean isLoggingEnabled() {
    String enableLogging = environmentProvider.getEnv("GOOGLE_SDK_JAVA_LOGGING");
    return "true".equalsIgnoreCase(enableLogging);
  }

  interface LoggerFactoryProvider {
    ILoggerFactory getLoggerFactory();
  }

  static class DefaultLoggerFactoryProvider implements LoggerFactoryProvider {
    @Override
    public ILoggerFactory getLoggerFactory() {
      return LoggerFactory.getILoggerFactory();
    }
  }
}
