package com.google.auth.oauth2;

/**
 * Interface for an environment provider.
 * 
 * <p>For internal use only.
 */
public interface EnvironmentProvider {
  String getEnv(String name);
}
