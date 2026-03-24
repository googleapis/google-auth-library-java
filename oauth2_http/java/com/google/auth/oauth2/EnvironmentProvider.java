package com.google.auth.oauth2;

import com.google.api.core.InternalApi;

/**
 * Interface for an environment provider.
 *
 * <p>For internal use only.
 */
@InternalApi
public interface EnvironmentProvider {
  String getEnv(String name);
}
