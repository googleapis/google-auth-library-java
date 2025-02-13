package com.google.auth.oauth2;

import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.spi.MDCAdapter;

/**
 * this adapter is for unit test only. It is set up via TestServiceProvider to test behavior when
 * LogWithMDC
 */
public class TestMDCAdapter implements MDCAdapter {
  Map<String, String> mdcValues = new HashMap<>();

  @Override
  public void put(String key, String val) {
    mdcValues.put(key, val);
  }

  @Override
  public String get(String key) {
    return "";
  }

  @Override
  public void remove(String key) {}

  @Override
  public void clear() {
    mdcValues.clear();
  }

  @Override
  public Map<String, String> getCopyOfContextMap() {
    return mdcValues;
  }

  @Override
  public void setContextMap(Map<String, String> contextMap) {}

  @Override
  public void pushByKey(String key, String value) {}

  @Override
  public String popByKey(String key) {
    return "";
  }

  @Override
  public Deque<String> getCopyOfDequeByKey(String key) {
    return null;
  }

  @Override
  public void clearDequeByKey(String key) {}
}
