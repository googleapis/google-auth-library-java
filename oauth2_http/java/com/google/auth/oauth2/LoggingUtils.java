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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.MDC;

class LoggingUtils {

  private static final Gson gson = new Gson();
  private static final Set<String> sensitiveKeys =
      new HashSet<>(
          Arrays.asList(
              "token",
              "assertion",
              "access_token",
              "client_secret",
              "refresh_token",
              "signedBlob"));

  private LoggingUtils() {}

  static void logWithMDC(
      Logger logger, org.slf4j.event.Level level, Map<String, String> contextMap, String message) {
    if (!contextMap.isEmpty()) {
      contextMap.forEach(MDC::put);
      contextMap.put("message", message);
      message = gson.toJson(contextMap);
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
        logger.info(message);
        // Default to INFO level
    }
    if (!contextMap.isEmpty()) {
      MDC.clear();
    }
  }

  static void logRequest(HttpRequest request, Logger logger, String message) {
    try {
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
                    String hashedVal = calculateSHA256Hash(String.valueOf(val));
                    headers.put(key, hashedVal);
                  } else {
                    headers.put(key, val);
                  }
                });
        loggingDataMap.put("request.headers", headers.toString());

        if (request.getContent() != null && logger.isDebugEnabled()) {
          // are payload always GenericData? If so, can parse and store in json
          if (request.getContent() instanceof UrlEncodedContent) {
            // this is parsed to GenericData because that is how it is constructed.
            GenericData data = (GenericData) ((UrlEncodedContent) request.getContent()).getData();
            Map<String, String> contextMap = parseGenericData(data);
            loggingDataMap.put("request.payload", contextMap.toString());
          } else if (request.getContent() instanceof JsonHttpContent) {
            String data = ((JsonHttpContent) request.getContent()).getData().toString();
            loggingDataMap.put("request.payload", data);
          }

          logWithMDC(logger, org.slf4j.event.Level.DEBUG, loggingDataMap, message);
        } else {

          logWithMDC(logger, org.slf4j.event.Level.INFO, loggingDataMap, message);
        }
      }
    } catch (Exception e) {
      logger.error("Error logging request: ", e);
    }
  }

  static void logResponse(HttpResponse response, Logger logger, String message) {
    try {
      if (logger.isInfoEnabled()) {
        Map<String, String> responseLogDataMap = new HashMap<>();
        responseLogDataMap.put("response.status", String.valueOf(response.getStatusCode()));
        responseLogDataMap.put("response.status.message", response.getStatusMessage());

        Map<String, Object> headers = new HashMap<>(response.getHeaders());
        responseLogDataMap.put("response.headers", headers.toString());
        logWithMDC(logger, org.slf4j.event.Level.INFO, responseLogDataMap, message);
      }
    } catch (Exception e) {

      logger.error("Error logging response: ", e);
    }
  }

  static void logGenericData(GenericData genericData, Logger logger, String message) {
    try {
      if (logger.isDebugEnabled()) {
        Map<String, String> contextMap = parseGenericData(genericData);
        logWithMDC(logger, org.slf4j.event.Level.DEBUG, contextMap, message);
      }
    } catch (Exception e) {
      logger.error("Error logging GenericData: ", e);
    }
  }

  private static Map<String, String> parseGenericData(GenericData genericData) {
    Map<String, String> contextMap = new HashMap<>();
    genericData.forEach(
        (key, val) -> {
          if (sensitiveKeys.contains(key)) {
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
