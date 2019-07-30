/*
 * Copyright 2015, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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

import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.auth.http.AuthHttpConstants;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.io.ByteStreams;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;

/** Internal utilities for the com.google.auth.oauth2 namespace. */
class OAuth2Utils {
  static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

  static final URI TOKEN_SERVER_URI = URI.create("https://oauth2.googleapis.com/token");
  static final URI TOKEN_REVOKE_URI = URI.create("https://oauth2.googleapis.com/revoke");
  static final URI USER_AUTH_URI = URI.create("https://accounts.google.com/o/oauth2/auth");

  static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

  static final HttpTransportFactory HTTP_TRANSPORT_FACTORY = new DefaultHttpTransportFactory();

  static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

  static final Charset UTF_8 = Charset.forName("UTF-8");

  private static String VALUE_NOT_FOUND_MESSAGE = "%sExpected value %s not found.";
  private static String VALUE_WRONG_TYPE_MESSAGE = "%sExpected %s value %s of wrong type.";

  static final String BEARER_PREFIX = AuthHttpConstants.BEARER + " ";

  static class DefaultHttpTransportFactory implements HttpTransportFactory {

    public HttpTransport create() {
      return HTTP_TRANSPORT;
    }
  }

  /**
   * Returns whether the headers contain the specified value as one of the entries in the specified
   * header.
   */
  static boolean headersContainValue(HttpHeaders headers, String headerName, String value) {
    Object values = headers.get(headerName);
    if (values instanceof Collection) {
      @SuppressWarnings("unchecked")
      Collection<Object> valuesCollection = (Collection<Object>) values;
      return valuesCollection.contains(value);
    }
    return false;
  }

  /** Parses the specified JSON text. */
  static GenericJson parseJson(String json) throws IOException {
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    InputStream stateStream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
    GenericJson stateJson =
        parser.parseAndClose(stateStream, StandardCharsets.UTF_8, GenericJson.class);
    return stateJson;
  }

  /** Return the specified string from JSON or throw a helpful error message. */
  static String validateString(Map<String, Object> map, String key, String errorPrefix)
      throws IOException {
    Object value = map.get(key);
    if (value == null) {
      throw new IOException(String.format(VALUE_NOT_FOUND_MESSAGE, errorPrefix, key));
    }
    if (!(value instanceof String)) {
      throw new IOException(String.format(VALUE_WRONG_TYPE_MESSAGE, errorPrefix, "string", key));
    }
    return (String) value;
  }

  /**
   * Saves the end user credentials into the given file path.
   *
   * @param credentials InputStream containing user credentials in JSON format
   * @param filePath Path to file where to store the credentials
   * @throws IOException An error saving the credentials.
   */
  static void writeInputStreamToFile(InputStream credentials, String filePath) throws IOException {
    final OutputStream outputStream = new FileOutputStream(new File(filePath));
    try {
      ByteStreams.copy(credentials, outputStream);
    } finally {
      outputStream.close();
    }
  }

  /** Return the specified optional string from JSON or throw a helpful error message. */
  static String validateOptionalString(Map<String, Object> map, String key, String errorPrefix)
      throws IOException {
    Object value = map.get(key);
    if (value == null) {
      return null;
    }
    if (!(value instanceof String)) {
      throw new IOException(String.format(VALUE_WRONG_TYPE_MESSAGE, errorPrefix, "string", key));
    }
    return (String) value;
  }

  /** Return the specified integer from JSON or throw a helpful error message. */
  static int validateInt32(Map<String, Object> map, String key, String errorPrefix)
      throws IOException {
    Object value = map.get(key);
    if (value == null) {
      throw new IOException(String.format(VALUE_NOT_FOUND_MESSAGE, errorPrefix, key));
    }
    if (value instanceof BigDecimal) {
      BigDecimal bigDecimalValue = (BigDecimal) value;
      return bigDecimalValue.intValueExact();
    }
    if (!(value instanceof Integer)) {
      throw new IOException(String.format(VALUE_WRONG_TYPE_MESSAGE, errorPrefix, "integer", key));
    }
    return (Integer) value;
  }

  /** Return the specified long from JSON or throw a helpful error message. */
  static long validateLong(Map<String, Object> map, String key, String errorPrefix)
      throws IOException {
    Object value = map.get(key);
    if (value == null) {
      throw new IOException(String.format(VALUE_NOT_FOUND_MESSAGE, errorPrefix, key));
    }
    if (value instanceof BigDecimal) {
      BigDecimal bigDecimalValue = (BigDecimal) value;
      return bigDecimalValue.longValueExact();
    }
    if (!(value instanceof Long)) {
      throw new IOException(String.format(VALUE_WRONG_TYPE_MESSAGE, errorPrefix, "long", key));
    }
    return (Long) value;
  }

  /** Return the specified map from JSON or throw a helpful error message. */
  @SuppressWarnings({"unchecked", "rawtypes"})
  static Map<String, Object> validateMap(Map<String, Object> map, String key, String errorPrefix)
      throws IOException {
    Object value = map.get(key);
    if (value == null) {
      throw new IOException(String.format(VALUE_NOT_FOUND_MESSAGE, errorPrefix, key));
    }
    if (!(value instanceof Map)) {
      throw new IOException(String.format(VALUE_WRONG_TYPE_MESSAGE, errorPrefix, "Map", key));
    }
    return (Map) value;
  }

  private OAuth2Utils() {}
}
