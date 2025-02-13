package com.google.auth.oauth2;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.util.GenericData;

class LoggingUtils {

  static final String GOOGLE_SDK_JAVA_LOGGING = "GOOGLE_SDK_JAVA_LOGGING";
  private static EnvironmentProvider environmentProvider =
      SystemEnvironmentProvider.getInstance(); // this may be reset for testing purpose

  private static boolean loggingEnabled = isLoggingEnabled();
  // expose this setter only for testing purposes
  static void setEnvironmentProvider(EnvironmentProvider provider) {
    environmentProvider = provider;
    // Recalculate LOGGING_ENABLED after setting the new provider
    loggingEnabled = isLoggingEnabled();
  }

  static boolean isLoggingEnabled() {
    String enableLogging = environmentProvider.getEnv(GOOGLE_SDK_JAVA_LOGGING);
    return "true".equalsIgnoreCase(enableLogging);
  }

  static void logRequest(HttpRequest request, LoggerProvider loggerProvider, String message) {
    if (loggingEnabled) {
      Slf4jUtils.logRequest(request, loggerProvider, message);
    }
  }

  static void logResponse(HttpResponse response, LoggerProvider loggerProvider, String message) {
    if (loggingEnabled) {
      Slf4jUtils.logResponse(response, loggerProvider, message);
    }
  }

  static void logGenericData(
      GenericData genericData, LoggerProvider loggerProvider, String message) {
    if (loggingEnabled) {
      Slf4jUtils.logGenericData(genericData, loggerProvider, message);
    }
  }
}
