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

package com.google.auth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.auth.http.AuthHttpConstants;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Utilities for test code under com.google.auth. */
public class TestUtils {

  public static final String UTF_8 = "UTF-8";

  private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

  public static void assertContainsBearerToken(Map<String, List<String>> metadata, String token) {
    assertNotNull(metadata);
    assertNotNull(token);
    assertTrue("Bearer token not found", hasBearerToken(metadata, token));
  }

  public static void assertNotContainsBearerToken(
      Map<String, List<String>> metadata, String token) {
    assertNotNull(metadata);
    assertNotNull(token);
    assertTrue("Bearer token found", !hasBearerToken(metadata, token));
  }

  private static boolean hasBearerToken(Map<String, List<String>> metadata, String token) {
    String expectedValue = AuthHttpConstants.BEARER + " " + token;
    List<String> authorizations = metadata.get(AuthHttpConstants.AUTHORIZATION);
    assertNotNull("Authorization headers not found", authorizations);
    for (String authorization : authorizations) {
      if (expectedValue.equals(authorization)) {
        return true;
      }
    }
    return false;
  }

  public static InputStream jsonToInputStream(GenericJson json) throws IOException {
    json.setFactory(JSON_FACTORY);
    String text = json.toPrettyString();
    return new ByteArrayInputStream(text.getBytes(UTF_8));
  }

  public static InputStream stringToInputStream(String text) {
    try {
      return new ByteArrayInputStream(text.getBytes(TestUtils.UTF_8));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("Unexpected encoding exception", e);
    }
  }

  public static Map<String, String> parseQuery(String query) throws IOException {
    Map<String, String> map = new HashMap<>();
    Iterable<String> entries = Splitter.on('&').split(query);
    for (String entry : entries) {
      List<String> sides = Lists.newArrayList(Splitter.on('=').split(entry));
      if (sides.size() != 2) {
        throw new IOException("Invalid Query String");
      }
      String key = URLDecoder.decode(sides.get(0), UTF_8);
      String value = URLDecoder.decode(sides.get(1), UTF_8);
      map.put(key, value);
    }
    return map;
  }

  public static String errorJson(String message) throws IOException {
    GenericJson errorResponse = new GenericJson();
    errorResponse.setFactory(JSON_FACTORY);
    GenericJson errorObject = new GenericJson();
    errorObject.put("message", message);
    errorResponse.put("error", errorObject);
    return errorResponse.toPrettyString();
  }

  private TestUtils() {}
}
