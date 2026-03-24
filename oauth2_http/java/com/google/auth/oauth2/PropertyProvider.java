package com.google.auth.oauth2;

import com.google.api.core.InternalApi;

/**
 * Interface for a system property provider.
 *
 * <p>For internal use only.
 */
@InternalApi
public interface PropertyProvider {
  String getProperty(String property, String def);
}
