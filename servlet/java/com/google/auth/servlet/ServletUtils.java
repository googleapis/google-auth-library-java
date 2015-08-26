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

package com.google.auth.servlet;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Utilities for the com.google.auth.servlet namespace.
 */
class ServletUtils {

  private static String VALUE_WRONG_TYPE_MESSAGE = "%sExpected %s value %s of wrong type.";  

  static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();  
  
  /**
   * Returns the URI of the request.
   */
  static URI getURI(HttpServletRequest request) {
    try {
      return new URI(request.getRequestURI());
    } catch (URISyntaxException e) {
      throw new RuntimeException("Unexpected exception converting servlet URI to URI type", e);
    }
  }  

  /**
   * Returns the URL of the request.
   */
  static URL getURL(HttpServletRequest request) {
    try {
      return new URL(request.getRequestURL().toString());
    } catch (MalformedURLException e) {
      throw new RuntimeException("Unexpected exception converting servlet URL to URL type", e);
    }
  }  
  
  /**
   * Parses the specified JSON text.
   */
  static GenericJson parseJson(String json) throws IOException {
    JsonObjectParser parser = new JsonObjectParser(JSON_FACTORY);
    InputStream stateStream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));      
    GenericJson stateJson = parser.parseAndClose(
        stateStream, StandardCharsets.UTF_8, GenericJson.class);
    return stateJson;
  }  

  /**
   * URL encodes the specified text.
   */
  static String urlEncode(String text) {
    try {
      return URLEncoder.encode(text, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("Unexpected UTF-8 encoding error");
    }
  }  
    
  /**
   * URL decodes the specified text.
   */
  static String urlDecode(String encoded) {
    try {
      return URLDecoder.decode(encoded, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("Unexpected UTF-8 encoding error");
    }
  }
  
  /**
   * Return the specified optional string from JSON or throw a helpful error message.
   */
  static String validateOptionalString(Map<String, Object> map, String key, String errorPrefix)
      throws IOException {
    Object value = map.get(key);
    if (value == null) {
      return null;
    }
    if (!(value instanceof String)) {
      throw new IOException(
          String.format(VALUE_WRONG_TYPE_MESSAGE, errorPrefix, "string", key));
    }
    return (String) value;
  }  
}
