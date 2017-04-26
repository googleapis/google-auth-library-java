/*
 * Copyright 2017, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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

package com.google.auth.oauth2;

import org.joda.time.Duration;

/**
 * Timed attempt execution settings. Defines time-specific properties of a retry attempt.
 */
public class TimedAttemptSettings {

  private final RetrySettings globalSettings;
  private final Duration retryDelay;
  private final Duration rpcTimeout;
  private final Duration randomizedRetryDelay;
  private final int attemptCount;
  private final long firstAttemptStartTime;

  public TimedAttemptSettings(
      RetrySettings globalSettings,
      Duration retryDelay,
      Duration rpcTimeout,
      Duration randomizedRetryDelay,
      int attemptCount,
      long firstAttemptStartTime) {
    this.globalSettings = globalSettings;
    this.retryDelay = retryDelay;
    this.rpcTimeout = rpcTimeout;
    this.randomizedRetryDelay = randomizedRetryDelay;
    this.attemptCount = attemptCount;
    this.firstAttemptStartTime = firstAttemptStartTime;
  }

  /**
   * Returns global (attempt-independent) retry settings.
   */
  public RetrySettings getGlobalSettings() {
    return globalSettings;
  }

  /**
   * Returns the calculated retry delay. Note that the actual delay used for retry scheduling may be
   * different (randomized, based on this value).
   */
  public Duration getRetryDelay() {
    return retryDelay;
  }

  /**
   * Returns rpc timeout used for this attempt.
   */
  public Duration getRpcTimeout() {
    return rpcTimeout;
  }

  /**
   * Returns randomized attempt delay. By default this value is calculated based on the
   * {@code retryDelay} value, and is used as the actual attempt execution delay.
   */
  public Duration getRandomizedRetryDelay() {
    return randomizedRetryDelay;
  }

  /**
   * The attempt count. It is a zero-based value (first attempt will have this value set to 0).
   */
  public int getAttemptCount() {
    return attemptCount;
  }

  /**
   * The start time of the first attempt. Note that this value is dependent on the actual
   * clock used during the process.
   */
  public long getFirstAttemptStartTime() {
    return firstAttemptStartTime;
  }
}
