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

import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class LoggingConfigs {

  private static final Logger NO_OP_LOGGER = org.slf4j.helpers.NOPLogger.NOP_LOGGER;
  static final String GOOGLE_SDK_JAVA_LOGGING_ENV = "GOOGLE_SDK_JAVA_LOGGING";
  private static EnvironmentProvider environmentProvider =
      SystemEnvironmentProvider.getInstance(); // this may be reset for testing purpose
  private static boolean loggingEnabled =
      isLoggingEnabled(); // this may be recalculated for testing purposes
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
    if (!loggingEnabled) {
      //  use SLF4j's NOP logger regardless of bindings
      return NO_OP_LOGGER;
    }
    return factoryProvider.getLoggerFactory().getLogger(clazz.getName());
  }

  static boolean isLoggingEnabled() {
    String enableLogging = environmentProvider.getEnv(GOOGLE_SDK_JAVA_LOGGING_ENV);
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
