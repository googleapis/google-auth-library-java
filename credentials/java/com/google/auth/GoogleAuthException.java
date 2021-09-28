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

  private final RetryStatus retryStatus;

  /**
   * Constructor with all parameters
   * 
   * @param responseStatus 
   *        A response status from the related HTTP request
   * 
   * @param retryCount 
   *        A number of retries performed
   * 
   * @param message
   *        The detail message (which is saved for later retrieval
   *        by the {@link #getMessage()} method)
   *
   * @param cause
   *        The cause (which is saved for later retrieval by the
   *        {@link #getCause()} method).  (A null value is permitted,
   *        and indicates that the cause is nonexistent or unknown.)
   * 
   */
  public GoogleAuthException(int responseStatus, int retryCount, String message, Throwable cause) {
    super(message, cause);
    retryStatus = getRetryStatus(responseStatus, retryCount);
  }

  /**
   * Constructor with message defaulted to the cause
   * 
   * @param responseStatus A response status from the related HTTP request
   * @param retryCount A number of retries performed
   */
  public GoogleAuthException(int responseStatus, int retryCount, Throwable cause) {
    super(cause);
    retryStatus = getRetryStatus(responseStatus, retryCount);
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
    retryStatus = RetryStatus.NON_RETRYABLE;
  }

  /**
   * Returns retry status of the error
   * @return
   */
  @Override
  public RetryStatus getRetryStatus() {
    return retryStatus;
  }

  /**
   * Calculates retry status based on HTTP response status and number of performed retries
   * @param responseStatus A response status from the related HTTP request
   * @param retryCount A number of retries performed
   * @return a retry status
   */
  private RetryStatus getRetryStatus(int responseStatus, int retryCount) {
    if (responseStatus == 500 || responseStatus == 503) {
      return retryCount > 0 ? RetryStatus.RETRIED : RetryStatus.RETRYABLE;
    } else {
      return RetryStatus.NON_RETRYABLE;
    }
  }
}
