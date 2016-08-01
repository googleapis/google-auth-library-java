package com.google.auth;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * The callback that receives the result of the asynchronous {@link
 * Credentials#getRequestMetadata(java.net.URI, java.util.concurrent.Executor,
 * RequestMetadataCallback)}. Exactly one method should be called.
 */
public interface RequestMetadataCallback {
  /**
   * Called when metadata is successfully produced.
   */
  void onSuccess(Map<String, List<String>> metadata);

  /**
   * Called when metadata generation failed.
   */
  void onFailure(Throwable exception);
}
