package com.google.auth.oauth2;

import java.util.HashMap;
import java.util.Map;

public class TestPropertyProvider implements PropertyProvider {
  private final Map<String, String> properties = new HashMap<>();

  public TestPropertyProvider() {}

  public void setProperty(String property, String value) {
    properties.put(property, value);
  }

  @Override
  public String getProperty(String property, String def) {
    if (properties.containsKey(property)) {
      return properties.get(property);
    }
    return def;
  }
}
