/*
 * Copyright 2026, Google LLC
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

package com.google.auth.oauth2;

import com.google.api.client.util.Clock;
import com.google.api.core.InternalApi;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.annotations.VisibleForTesting;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nullable;

/**
 * Manages the lifecycle of Regional Access Boundaries (RAB) for a credential.
 *
 * <p>This class handles caching, asynchronous refreshing, and cooldown logic to ensure that API
 * requests are not blocked by lookup failures and that the lookup service is not overwhelmed.
 */
@InternalApi
final class RegionalAccessBoundaryManager {

  private static final Logger LOGGER = Logger.getLogger(RegionalAccessBoundaryManager.class.getName());
  private static final LoggerProvider LOGGER_PROVIDER = LoggerProvider.forClazz(RegionalAccessBoundaryManager.class);

  static final long INITIAL_COOLDOWN_MILLIS = 15 * 60 * 1000L; // 15 minutes
  static final long MAX_COOLDOWN_MILLIS = 24 * 60 * 60 * 1000L; // 24 hours

  /**
   * cachedRAB uses AtomicReference to provide thread-safe, lock-free access to the cached data for
   * high-concurrency request threads.
   */
  private final AtomicReference<RegionalAccessBoundary> cachedRAB = new AtomicReference<>();

  /**
   * refreshFuture acts as an atomic gate for request de-duplication. If a future is present, it
   * indicates a background refresh is already in progress. It also provides a handle for
   * observability and unit testing to track the background task's lifecycle.
   */
  private final AtomicReference<CompletableFuture<RegionalAccessBoundary>> refreshFuture =
      new AtomicReference<>();

  private long cooldownStartTime = 0;
  private long currentCooldownMillis = INITIAL_COOLDOWN_MILLIS;
  private static Clock clock = Clock.SYSTEM;

  /**
   * Returns the currently cached RegionalAccessBoundary, or null if none is available or if it has
   * expired.
   *
   * @return The cached RAB, or null.
   */
  @Nullable
  RegionalAccessBoundary getCachedRAB() {
    RegionalAccessBoundary rab = cachedRAB.get();
    if (rab != null && !rab.isExpired()) {
      return rab;
    }
    return null;
  }

  /**
   * Sets a manual override for the Regional Access Boundary. This seeds the cache.
   *
   * @param rab The Regional Access Boundary to cache.
   */
  void setManualOverride(RegionalAccessBoundary rab) {
    cachedRAB.set(rab);
  }

  /**
   * Triggers an asynchronous refresh of the RegionalAccessBoundary if it is not already being
   * refreshed and if the cooldown period is not active.
   *
   * <p>This method is entirely non-blocking for the calling thread. If a refresh is already in
   * progress or a cooldown is active, it returns immediately.
   *
   * @param transportFactory The HTTP transport factory to use for the lookup.
   * @param url The lookup endpoint URL.
   * @param accessToken The access token for authentication.
   */
  void triggerAsyncRefresh(
      final HttpTransportFactory transportFactory,
      final String url,
      final AccessToken accessToken) {
    if (isCooldownActive()) {
      return;
    }

    RegionalAccessBoundary currentRab = cachedRAB.get();
    if (currentRab != null && !currentRab.isExpired()) {
      return;
    }

    CompletableFuture<RegionalAccessBoundary> future = new CompletableFuture<>();
    // Atomically check if a refresh is already running. If compareAndSet returns true,
    // this thread "won the race" and is responsible for starting the background task.
    // All other concurrent threads will return false and exit immediately.
    if (refreshFuture.compareAndSet(null, future)) {
      CompletableFuture.runAsync(
          () -> {
            try {
              RegionalAccessBoundary newRAB =
                  RegionalAccessBoundary.refresh(
                      transportFactory, url, accessToken, cachedRAB.get());
              cachedRAB.set(newRAB);
              resetCooldown();
              // Complete the future so monitors (like unit tests) know we are done.
              future.complete(newRAB);
            } catch (Exception e) {
              handleRefreshFailure(e);
              future.completeExceptionally(e);
            } finally {
              // Open the gate again for future refresh requests.
              refreshFuture.set(null);
            }
          });
    }
  }

  /** Invalidates the current cache. Useful for reactive refresh on stale error. */
  void invalidateCache() {
    cachedRAB.set(null);
  }

  /**
   * Invalidates the cache and triggers an immediate asynchronous refresh.
   *
   * @param transportFactory The HTTP transport factory to use for the lookup.
   * @param url The lookup endpoint URL.
   * @param accessToken The access token for authentication.
   */
  void reactiveRefresh(
      final HttpTransportFactory transportFactory,
      final String url,
      final AccessToken accessToken) {
    invalidateCache();
    triggerAsyncRefresh(transportFactory, url, accessToken);
  }

  private synchronized void handleRefreshFailure(Exception e) {
    if (cooldownStartTime == 0) {
      cooldownStartTime = clock.currentTimeMillis();
      currentCooldownMillis = INITIAL_COOLDOWN_MILLIS;
      LoggingUtils.log(
          LOGGER_PROVIDER,
          Level.INFO,
          null,
          "RAB lookup failed; entering cooldown for "
              + (currentCooldownMillis / 60000)
              + "m. Error: "
              + e.getMessage());
    } else {
      // Extend cooldown
      currentCooldownMillis = Math.min(currentCooldownMillis * 2, MAX_COOLDOWN_MILLIS);
      cooldownStartTime = clock.currentTimeMillis();
      LoggingUtils.log(
          LOGGER_PROVIDER,
          Level.INFO,
          null,
          "RAB lookup failed again; extending cooldown to "
              + (currentCooldownMillis / 60000)
              + "m. Error: "
              + e.getMessage());
    }
  }

  private synchronized void resetCooldown() {
    cooldownStartTime = 0;
    currentCooldownMillis = INITIAL_COOLDOWN_MILLIS;
  }

  synchronized boolean isCooldownActive() {
    if (cooldownStartTime == 0) {
      return false;
    }
    return clock.currentTimeMillis() < cooldownStartTime + currentCooldownMillis;
  }

  @VisibleForTesting
  synchronized long getCurrentCooldownMillis() {

    return currentCooldownMillis;
  }

  @VisibleForTesting
  static void setClockForTest(Clock testClock) {
    clock = testClock;
  }
}
