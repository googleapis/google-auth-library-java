/*
 * Copyright 2021 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth;

import java.io.IOException;

/**
 * Base class for the standard Auth error response. 
 * It extends a default exception while keeping Json response format 
 */
public class GoogleAuthException extends IOException implements Retryable {

  private final boolean isRetryable;
  private final int retryCount;

  /**
   * Constructor with all parameters
   * 
   * @param isRetryable 
   *        A retry status for the related HTTP request
   * 
   * @param retryCount
   *        A number of retries performed for the related HTTP request
   * 
   * @param message
   *        The detail message (which is saved for later retrieval
   *        by the {@link #getMessage()} method)
   *
   * @param cause
   *        The cause (which is saved for later retrieval by the
   *        {@link #getCause()} method).  (A null value is permitted,
   *        and indicates that the cause is nonexistent or unknown.)
   */
  public GoogleAuthException(boolean isRetryable, int retryCount, String message, Throwable cause) {
    super(message, cause);
    this.isRetryable = isRetryable;
    this.retryCount = retryCount;
  }

  /**
   * Constructor with message defaulted to the cause
   * 
   * @param isRetryable
   *        A retry status for the related HTTP request
   * @param retryCount
   *        A number of retries performed for the related HTTP request
   * @param cause
   *        The cause (which is saved for later retrieval by the
   *        {@link #getCause()} method).  (A null value is permitted,
   *        and indicates that the cause is nonexistent or unknown.)
   */
  public GoogleAuthException(boolean isRetryable, int retryCount, Throwable cause) {
    super(cause);
    this.isRetryable = isRetryable;
    this.retryCount = retryCount;
  }

  /**
   * Constructor without retry count
   * 
   * @param isRetryable
   *        A retry status for the related HTTP request
   * @param cause
   *        The cause (which is saved for later retrieval by the
   *        {@link #getCause()} method).  (A null value is permitted,
   *        and indicates that the cause is nonexistent or unknown.)
   */
  public GoogleAuthException(boolean isRetryable, Throwable cause) {
    super(cause);
    this.isRetryable = isRetryable;
    this.retryCount = 0;
  }

  /**
   * Constructor without retry info
   *
   * @param cause
   *        The cause (which is saved for later retrieval by the
   *        {@link #getCause()} method).  (A null value is permitted,
   *        and indicates that the cause is nonexistent or unknown.)
   */
  public GoogleAuthException(Throwable cause) {
    super(cause);
    this.isRetryable = false;
    this.retryCount = 0;
  }

  /** 
   * Returns true if the error is retryable, false otherwise
   */
  @Override
  public boolean isRetryable() {
    return isRetryable;
  }

  /** 
   * Retruns number of reties performed for the related HTTP request
   */
  @Override
  public int getRetryCount() {
    return retryCount;
  }
}
