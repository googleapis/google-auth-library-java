package com.google.auth.oauth2;

import org.slf4j.Logger;

class LoggerProvider {

  private Logger logger;
  private final Class<?> clazz;

  private LoggerProvider(Class<?> clazz) {
    this.clazz = clazz;
  }

  public static LoggerProvider forClazz(Class<?> clazz) {
    return new LoggerProvider(clazz);
  }

  public Logger getLogger() {
    if (logger == null) {
      this.logger = Slf4jUtils.getLogger(clazz);
    }
    return logger;
  }
}
