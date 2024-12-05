package com.google.auth.oauth2;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.util.GenericData;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.Marker;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MessageFormatter;

public class LoggingUtils {

  private static final java.util.logging.Logger LOGGER =
      java.util.logging.Logger.getLogger(LoggingUtils.class.getName());
  private static EnvironmentProvider environmentProvider = SystemEnvironmentProvider.getInstance();

  static void setEnvironmentProvider(EnvironmentProvider provider) {
    environmentProvider = provider;
  }

  private LoggingUtils() {}

  interface LoggerFactoryProvider {
    ILoggerFactory getLoggerFactory();
  }

  static class DefaultLoggerFactoryProvider implements LoggerFactoryProvider {
    @Override
    public ILoggerFactory getLoggerFactory() {
      return LoggerFactory.getILoggerFactory();
    }
  }

  public static Logger getLogger(Class<?> clazz) {
    return getLogger(clazz, new DefaultLoggerFactoryProvider());
  }

  public static Logger getLogger(Class<?> clazz, LoggerFactoryProvider factoryProvider) {
    if (!isLoggingEnabled()) {
      //  use SLF4j's NOP logger regardless of bindings
      return org.slf4j.helpers.NOPLogger.NOP_LOGGER;
    }

    ILoggerFactory loggerFactory = factoryProvider.getLoggerFactory();
    if (loggerFactory != null && !(loggerFactory instanceof org.slf4j.helpers.NOPLoggerFactory)) {
      // Use SLF4j binding when present
      return LoggerFactory.getLogger(clazz);
    }
    // No SLF4j binding found, use JUL as fallback
    Logger logger = new JulWrapperLogger(clazz.getName());
    logger.info("No SLF4J providers were found, fall back to JUL.");
    return logger;
  }

  public static boolean isLoggingEnabled() {
    String enableLogging = environmentProvider.getEnv("GOOGLE_SDK_JAVA_LOGGING");
    // String enableLogging = System.getenv("GOOGLE_SDK_JAVA_LOGGING");
    LOGGER.info("GOOGLE_SDK_JAVA_LOGGING=" + enableLogging); // log for debug now, remove it.
    return "true".equalsIgnoreCase(enableLogging);
  }

  public static JsonObject mergeJsonObject(JsonObject jsonObject1, JsonObject jsonObject2) {
    JsonObject mergedObject = jsonObject1.deepCopy();
    jsonObject2.entrySet().forEach(entry -> mergedObject.add(entry.getKey(), entry.getValue()));
    return mergedObject;
  }

  public static Level mapToJulLevel(org.slf4j.event.Level slf4jLevel) {
    switch (slf4jLevel) {
      case ERROR:
        return Level.SEVERE;
      case WARN:
        return Level.WARNING;
      case INFO:
        return Level.INFO;
      case DEBUG:
        return Level.FINE;
      case TRACE:
        return Level.FINEST;
      default:
        return Level.INFO;
    }
  }

  public static void logWithMDC(
      Logger logger, org.slf4j.event.Level level, Map<String, String> contextMap, String message) {

    if (logger instanceof JulWrapperLogger) {
      // Simulate MDC behavior for JUL
      LogRecord record = new LogRecord(mapToJulLevel(level), message);
      // Add context map to the LogRecord
      record.setParameters(new Object[] {contextMap});
      ((JulWrapperLogger) logger).getJulLogger().log(record);
      return;
    }
    contextMap.forEach(MDC::put);

    switch (level) {
      case TRACE:
        logger.trace(message);
        break;
      case DEBUG:
        logger.debug(message);
        break;
      case INFO:
        logger.info(message);
        break;
      case WARN:
        logger.warn(message);
        break;
      case ERROR:
        logger.error(message);
        break;
      default:
        logger.info(message);
        // Default to INFO level
    }

    MDC.clear();
  }

  static void logRequest(HttpRequest request, Logger logger, String message) {
    if (logger.isInfoEnabled()) {
      Map<String, String> loggingDataMap = new HashMap<>();
      loggingDataMap.put("request.method", request.getRequestMethod());
      loggingDataMap.put("request.url", request.getUrl().toString());

      Map<String, Object> headers = new HashMap<>();
      request
          .getHeaders()
          .forEach(
              (key, val) -> {
                if ("authorization".equals(key)) {

                  String tokenString = String.valueOf(val);

                  String maskedToken =
                      tokenString.substring(0, 5)
                          + "*****"
                          + tokenString.substring(tokenString.length() - 4);
                  // String maskedToken = calculateSHA256Hash(tokenString);
                  headers.put(key, String.valueOf(maskedToken));
                } else {
                  headers.put(key, val);
                }
              });
      loggingDataMap.put("request.headers", headers.toString());

      if (request.getContent() != null && logger.isDebugEnabled()) {
        // are payload always GenericData? If so, can parse and store in json
        GenericData data = (GenericData) ((UrlEncodedContent) request.getContent()).getData();

        Map<String, String> contextMap = parseGenericData(data);
        loggingDataMap.put("request.payload", contextMap.toString());

        LoggingUtils.logWithMDC(logger, org.slf4j.event.Level.DEBUG, loggingDataMap, message);
      } else {

        LoggingUtils.logWithMDC(logger, org.slf4j.event.Level.INFO, loggingDataMap, message);
      }
    }
  }

  static void logResponse(HttpResponse response, Logger logger, String message) {
    if (logger.isInfoEnabled()) {
      Map<String, String> responseLogDataMap = new HashMap<>();
      responseLogDataMap.put("response.status", String.valueOf(response.getStatusCode()));
      responseLogDataMap.put("response.status.message", response.getStatusMessage());

      Map<String, Object> headers = new HashMap<>();
      response.getHeaders().forEach((key, val) -> headers.put(key, val));
      responseLogDataMap.put("response.headers", headers.toString());
      LoggingUtils.logWithMDC(logger, org.slf4j.event.Level.INFO, responseLogDataMap, message);
    }
  }

  static void logGenericData(GenericData genericData, Logger logger, String message) {
    if (logger.isDebugEnabled()) {
      Map<String, String> contextMap = parseGenericData(genericData);
      LoggingUtils.logWithMDC(logger, org.slf4j.event.Level.DEBUG, contextMap, message);
    }
  }

  private static Map<String, String> parseGenericData(GenericData genericData) {
    Map<String, String> contextMap = new HashMap<>();
    genericData.forEach(
        (key, val) -> {
          if ("token".equals(key)
              || "assertion".equals(key)
              || "access_token".equals(key)
              || "client_secret".equals(key)
              || "refresh_token".equals(key)) {
            String tokenString = String.valueOf(val);
            // String maskedToken = calculateSHA256Hash(tokenString);
            String maskedToken =
                tokenString.substring(0, 5)
                    + "*****"
                    + tokenString.substring(tokenString.length() - 4);
            contextMap.put(key, String.valueOf(maskedToken));
          } else {
            contextMap.put(key, val.toString());
          }
        });
    return contextMap;
  }

  private static String calculateSHA256Hash(String data) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] inputBytes = data.getBytes(StandardCharsets.UTF_8);
      byte[] hashBytes = digest.digest(inputBytes);
      return bytesToHex(hashBytes);
    } catch (NoSuchAlgorithmException e) {
      System.err.println("Error calculating SHA-256 hash: " + e.getMessage());
      return ""; // Or throw an exception, depending on your error handling strategy
    }
  }

  private static String bytesToHex(byte[] hash) {
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (byte b : hash) {
      String hex = Integer.toHexString(0xff & b);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }

  // JulWrapperLogger implementation
  static class JulWrapperLogger implements Logger {

    private final java.util.logging.Logger julLogger;

    public JulWrapperLogger(String name) {
      this.julLogger = java.util.logging.Logger.getLogger(name);
    }

    public java.util.logging.Logger getJulLogger() {
      return julLogger;
    }

    @Override
    public String getName() {
      return julLogger.getName();
    }

    @Override
    public boolean isTraceEnabled() {
      return julLogger.isLoggable(java.util.logging.Level.FINEST);
    }

    @Override
    public void trace(String msg) {
      julLogger.log(java.util.logging.Level.FINEST, msg);
    }

    @Override
    public void trace(String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isTraceEnabled(Marker marker) {
      return false;
    }

    @Override
    public void trace(Marker marker, String s) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(Marker marker, String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(Marker marker, String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(Marker marker, String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void trace(Marker marker, String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isDebugEnabled() {
      return julLogger.isLoggable(Level.FINE);
    }

    @Override
    public void debug(String msg) {

      if (isDebugEnabled()) {
        julLogger.log(java.util.logging.Level.FINE, msg);
      }
    }

    @Override
    public void debug(String format, Object arg) {
      if (isDebugEnabled()) {
        FormattingTuple ft = MessageFormatter.format(format, arg);
        julLogger.log(Level.FINE, ft.getMessage());
      }
    }

    @Override
    public void debug(String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isDebugEnabled(Marker marker) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(Marker marker, String s) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(Marker marker, String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(Marker marker, String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(Marker marker, String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void debug(Marker marker, String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isInfoEnabled() {
      return julLogger.isLoggable(Level.INFO);
    }

    @Override
    public void info(String msg) {
      if (isInfoEnabled()) {
        julLogger.log(java.util.logging.Level.INFO, msg);
      }
    }

    @Override
    public void info(String format, Object arg) {
      if (isInfoEnabled()) {
        FormattingTuple ft = MessageFormatter.format(format, arg);
        julLogger.log(java.util.logging.Level.INFO, ft.getMessage());
      }
    }

    @Override
    public void info(String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void info(String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void info(String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isInfoEnabled(Marker marker) {
      return true;
    }

    @Override
    public void info(Marker marker, String s) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void info(Marker marker, String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void info(Marker marker, String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void info(Marker marker, String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void info(Marker marker, String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isWarnEnabled() {
      return true;
    }

    @Override
    public void warn(String msg) {
      julLogger.log(Level.WARNING, msg);
    }

    @Override
    public void warn(String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isWarnEnabled(Marker marker) {
      return false;
    }

    @Override
    public void warn(Marker marker, String s) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(Marker marker, String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(Marker marker, String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(Marker marker, String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void warn(Marker marker, String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isErrorEnabled() {
      return false;
    }

    @Override
    public void error(String s) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public boolean isErrorEnabled(Marker marker) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(Marker marker, String s) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(Marker marker, String s, Object o) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(Marker marker, String s, Object o, Object o1) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(Marker marker, String s, Object... objects) {
      throw new UnsupportedOperationException("This method is not supported.");
    }

    @Override
    public void error(Marker marker, String s, Throwable throwable) {
      throw new UnsupportedOperationException("This method is not supported.");
    }
  }
}
