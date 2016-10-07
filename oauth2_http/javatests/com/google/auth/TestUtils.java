package com.google.auth;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.auth.http.AuthHttpConstants;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utilities for test code under com.google.auth.
 */
public class TestUtils {

  public static final String UTF_8 = "UTF-8";

  private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

  public static void assertContainsBearerToken(Map<String, List<String>> metadata, String token) {
    assertNotNull(metadata);
    assertNotNull(token);
    String expectedValue = AuthHttpConstants.BEARER + " " + token;
    List<String> authorizations = metadata.get(AuthHttpConstants.AUTHORIZATION);
    assertNotNull("Authorization headers not found", authorizations);
    boolean found = false;
    for (String authorization : authorizations) {
      if (expectedValue.equals(authorization)) {
        found = true;
        break;
      }
    }
    assertTrue("Bearer token not found", found);
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

  private TestUtils() {
  }
}
