package com.google.auth.oauth2;

import com.google.auth.RequestMetadataCallback;
import com.google.common.base.Preconditions;

import java.util.List;
import java.util.Map;

/**
 * Mock RequestMetadataCallback
 */
public final class MockRequestMetadataCallback implements RequestMetadataCallback {
  Map<String, List<String>> metadata;
  Throwable exception;

  /**
   * Called when metadata is successfully produced.
   */
  @Override
  public void onSuccess(Map<String, List<String>> metadata) {
    checkNotSet();
    this.metadata = metadata;
  }

  /**
   * Called when metadata generation failed.
   */
  @Override
  public void onFailure(Throwable exception) {
    checkNotSet();
    this.exception = exception;
  }

  public void reset() {
    this.metadata = null;
    this.exception = null;
  }

  private void checkNotSet() {
    Preconditions.checkState(this.metadata == null);
    Preconditions.checkState(this.exception == null);
  }
}
