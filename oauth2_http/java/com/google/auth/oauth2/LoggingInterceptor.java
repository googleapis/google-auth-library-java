package com.google.auth.oauth2;

import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseInterceptor;
import com.google.api.client.http.UrlEncodedContent;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.event.Level;

public class LoggingInterceptor
    implements HttpExecuteInterceptor, HttpRequestInitializer, HttpResponseInterceptor {

  private static final Logger logger = LoggingUtils.getLogger(LoggingInterceptor.class);

  @Override
  public void intercept(HttpRequest request) throws IOException {
    // Log the request
    // StringBuilder requestLog = new StringBuilder("Sending request.");
    Map<String, String> loggingDataMap = new HashMap<>();
    loggingDataMap.put("request.method", request.getRequestMethod());
    loggingDataMap.put("request.url", request.getUrl().toString());
    // requestLog.append(request.getRequestMethod()).append(" ").append(request.getUrl());

    Map<String, Object> headers = new HashMap<>();
    request.getHeaders().forEach((key, val) -> headers.put(key, val));
    loggingDataMap.put("request.headers", headers.toString());
    if (request.getContent() != null && logger.isDebugEnabled()) {
      loggingDataMap.put(
          "request.payload", ((UrlEncodedContent) request.getContent()).getData().toString());

      LoggingUtils.logWithMDC(logger, Level.DEBUG, loggingDataMap, "Sending auth request");
    } else {

      LoggingUtils.logWithMDC(logger, Level.INFO, loggingDataMap, "Sending auth request");
    }
  }

  @Override
  public void interceptResponse(HttpResponse response) throws IOException {
    // Log the response
    // StringBuilder responseLog = new StringBuilder("Received response: ");
    // responseLog.append(response.getStatusCode()).append(" ").append(response.getStatusMessage());

    Map<String, String> responseLogDataMap = new HashMap<>();
    responseLogDataMap.put("response.status", String.valueOf(response.getStatusCode()));
    responseLogDataMap.put("response.status.message", response.getStatusMessage());

    Map<String, Object> headers = new HashMap<>();
    response.getHeaders().forEach((key, val) -> headers.put(key, val));
    responseLogDataMap.put("response.headers", headers.toString());

    LoggingUtils.logWithMDC(logger, Level.INFO, responseLogDataMap, "Auth response.");
  }

  @Override
  public void initialize(HttpRequest request) throws IOException {
    request.setInterceptor(this);
    request.setResponseInterceptor(this);
  }
}
