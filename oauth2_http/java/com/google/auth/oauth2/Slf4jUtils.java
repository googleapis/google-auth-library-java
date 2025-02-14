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

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.util.GenericData;
import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.spi.LoggingEventBuilder;

class Slf4jUtils {

  private static final Logger NO_OP_LOGGER = org.slf4j.helpers.NOPLogger.NOP_LOGGER;
  private static final Gson gson = new Gson();
  private static final Set<String> SENSITIVE_KEYS = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
  private static boolean hasAddKeyValue;

  static {
    hasAddKeyValue = checkIfClazzAvailable("org.slf4j.event.KeyValuePair");
  }

  static {
    SENSITIVE_KEYS.addAll(
        Arrays.asList(
            "token",
            "assertion",
            "access_token",
            "client_secret",
            "refresh_token",
            "signedBlob",
            "authorization"));
  }

  static boolean checkIfClazzAvailable(String clazzName) {
    try {
      Class.forName(clazzName);
      return true; // SLF4j 2.x or later
    } catch (ClassNotFoundException e) {
      return false; // SLF4j 1.x or earlier
    }
  }

  private Slf4jUtils() {}

  static Logger getLogger(Class<?> clazz) {
    return getLogger(clazz, new DefaultLoggerFactoryProvider());
  }

  // constructor with LoggerFactoryProvider to make testing easier
  static Logger getLogger(Class<?> clazz, LoggerFactoryProvider factoryProvider) {
    if (LoggingUtils.isLoggingEnabled()) {
      ILoggerFactory loggerFactory = factoryProvider.getLoggerFactory();
      return loggerFactory.getLogger(clazz.getName());
    } else {
      //  use SLF4j's NOP logger regardless of bindings
      return NO_OP_LOGGER;
    }
  }

  static void log(
      Logger logger, org.slf4j.event.Level level, Map<String, Object> contextMap, String message) {
    if (hasAddKeyValue) {
      logWithKeyValuePair(logger, level, contextMap, message);
    } else {
      logWithMDC(logger, level, contextMap, message);
    }
  }

  // exposed for testing
  static void logWithMDC(
      Logger logger, org.slf4j.event.Level level, Map<String, Object> contextMap, String message) {
    if (!contextMap.isEmpty()) {
      for (Entry<String, Object> entry : contextMap.entrySet()) {
        String key = entry.getKey();
        Object value = entry.getValue();

        MDC.put(key, value instanceof String ? (String) value : gson.toJson(value));
      }
    }
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
        logger.debug(message);
        // Default to DEBUG level
    }
    if (!contextMap.isEmpty()) {
      MDC.clear();
    }
  }

  private static void logWithKeyValuePair(
      Logger logger, org.slf4j.event.Level level, Map<String, Object> contextMap, String message) {
    LoggingEventBuilder loggingEventBuilder;
    switch (level) {
      case TRACE:
        loggingEventBuilder = logger.atTrace();
        break;
      case DEBUG:
        loggingEventBuilder = logger.atDebug();
        break;
      case INFO:
        loggingEventBuilder = logger.atInfo();
        break;
      case WARN:
        loggingEventBuilder = logger.atWarn();
        break;
      case ERROR:
        loggingEventBuilder = logger.atError();
        break;
      default:
        loggingEventBuilder = logger.atDebug();
        // Default to DEBUG level
    }
    contextMap.forEach(loggingEventBuilder::addKeyValue);
    loggingEventBuilder.log(message);
  }

  static void logRequest(HttpRequest request, LoggerProvider loggerProvider, String message) {
    try {
      Logger logger = loggerProvider.getLogger();
      if (logger.isInfoEnabled()) {
        Map<String, Object> loggingDataMap = new HashMap<>();
        loggingDataMap.put("request.method", request.getRequestMethod());
        loggingDataMap.put("request.url", request.getUrl().toString());

        Map<String, Object> headers = new HashMap<>();
        request
            .getHeaders()
            .forEach(
                (key, val) -> {
                  if (SENSITIVE_KEYS.contains(key)) {
                    String hashedVal = calculateSHA256Hash(String.valueOf(val));
                    headers.put(key, hashedVal);
                  } else {
                    headers.put(key, val);
                  }
                });
        loggingDataMap.put("request.headers", gson.toJson(headers));

        if (request.getContent() != null && logger.isDebugEnabled()) {
          // are payload always GenericData? If so, can parse and store in json
          if (request.getContent() instanceof UrlEncodedContent) {
            // this is parsed to GenericData because that is how it is constructed.
            GenericData data = (GenericData) ((UrlEncodedContent) request.getContent()).getData();
            Map<String, Object> contextMap = parseGenericData(data);
            loggingDataMap.put("request.payload", gson.toJson(contextMap));
          } else if (request.getContent() instanceof JsonHttpContent) {
            String jsonData = gson.toJson(((JsonHttpContent) request.getContent()).getData());
            loggingDataMap.put("request.payload", jsonData);
          }

          log(logger, org.slf4j.event.Level.DEBUG, loggingDataMap, message);
        } else {

          log(logger, org.slf4j.event.Level.INFO, loggingDataMap, message);
        }
      }
    } catch (Exception e) {
      // let logging fail silently
    }
  }

  static void logResponse(HttpResponse response, LoggerProvider loggerProvider, String message) {
    try {
      Logger logger = loggerProvider.getLogger();
      if (logger.isInfoEnabled()) {
        Map<String, Object> responseLogDataMap = new HashMap<>();
        responseLogDataMap.put("response.status", String.valueOf(response.getStatusCode()));
        responseLogDataMap.put("response.status.message", response.getStatusMessage());

        Map<String, Object> headers = new HashMap<>(response.getHeaders());
        responseLogDataMap.put("response.headers", headers.toString());
        log(logger, org.slf4j.event.Level.INFO, responseLogDataMap, message);
      }
    } catch (Exception e) {
      // let logging fail silently
    }
  }

  static void logResponsePayload(
      GenericData genericData, LoggerProvider loggerProvider, String message) {
    try {

      Logger logger = loggerProvider.getLogger();
      if (logger.isDebugEnabled()) {
        Map<String, Object> contextMap = parseGenericData(genericData);
        log(logger, org.slf4j.event.Level.DEBUG, contextMap, message);
      }
    } catch (Exception e) {
      // let logging fail silently
    }
  }

  private static Map<String, Object> parseGenericData(GenericData genericData) {
    Map<String, Object> contextMap = new HashMap<>();
    genericData.forEach(
        (key, val) -> {
          if (SENSITIVE_KEYS.contains(key)) {
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
