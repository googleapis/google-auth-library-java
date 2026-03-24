package com.google.auth.oauth2;

import java.io.Serializable;

/**
 * Represents the default system property provider.
 *
 * <p>For internal use only.
 */
public class SystemPropertyProvider implements PropertyProvider, Serializable {
  public static final SystemPropertyProvider INSTANCE = new SystemPropertyProvider();
  private static final long serialVersionUID = 1L;

  private SystemPropertyProvider() {}

  @Override
  public String getProperty(String property, String def) {
    return System.getProperty(property, def);
  }

  public static SystemPropertyProvider getInstance() {
    return INSTANCE;
  }
}
