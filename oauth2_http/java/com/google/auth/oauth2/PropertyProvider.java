package com.google.auth.oauth2;

/**
 * Interface for a system property provider.
 * 
 * <p>For internal use only.
 */
public interface PropertyProvider {
  String getProperty(String property, String def);
}
