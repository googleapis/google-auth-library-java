package com.google.auth.oauth2;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.util.GenericData;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.MDC;

class LoggingUtils {

  private LoggingUtils() {}

  static void logWithMDC(
      Logger logger, org.slf4j.event.Level level, Map<String, String> contextMap, String message) {
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
      try {
        Map<String, String> loggingDataMap = new HashMap<>();
        loggingDataMap.put("request.method", request.getRequestMethod());
        loggingDataMap.put("request.url", request.getUrl().toString());

        Map<String, Object> headers = new HashMap<>();
        request
            .getHeaders()
            .forEach(
                (key, val) -> {
                  if ("authorization".equals(key)) {
                    String hashedVal = calculateSHA256Hash(String.valueOf(val));
                    headers.put(key, hashedVal);
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

          logWithMDC(logger, org.slf4j.event.Level.DEBUG, loggingDataMap, message);
        } else {

          logWithMDC(logger, org.slf4j.event.Level.INFO, loggingDataMap, message);
        }
      } catch (Exception e) {
        logger.error("Error logging request: ", e);
      }
    }
  }

  static void logResponse(HttpResponse response, Logger logger, String message) {
    if (logger.isInfoEnabled()) {
      try {
        Map<String, String> responseLogDataMap = new HashMap<>();
        responseLogDataMap.put("response.status", String.valueOf(response.getStatusCode()));
        responseLogDataMap.put("response.status.message", response.getStatusMessage());

        Map<String, Object> headers = new HashMap<>();
        response.getHeaders().forEach((key, val) -> headers.put(key, val));
        responseLogDataMap.put("response.headers", headers.toString());
        logWithMDC(logger, org.slf4j.event.Level.INFO, responseLogDataMap, message);
      } catch (Exception e) {

        logger.error("Error logging response: ", e);
      }
    }
  }

  static void logGenericData(GenericData genericData, Logger logger, String message) {
    if (logger.isDebugEnabled()) {
      try {

        Map<String, String> contextMap = parseGenericData(genericData);
        logWithMDC(logger, org.slf4j.event.Level.DEBUG, contextMap, message);
      } catch (Exception e) {
        logger.error("Error logging GenericData: ", e);
      }
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
            String secretString = String.valueOf(val);
            String hashedVal = calculateSHA256Hash(secretString);
            contextMap.put(key, hashedVal);
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
      return "Error calculating SHA-256 hash."; // do not fail for logging failures
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
}
