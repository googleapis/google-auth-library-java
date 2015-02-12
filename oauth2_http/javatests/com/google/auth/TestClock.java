package com.google.auth;

import com.google.api.client.util.Clock;

/**
 * A mock clock for testing time-sensitive operations.
 */
public class TestClock implements Clock {

  long currentTime;

  public long currentTimeMillis() {
    return currentTime;
  }

  public void addToCurrentTime(long milliseconds) {
    currentTime = currentTime + milliseconds;
  }

  public void setCurrentTime(long currentTime) {
    this.currentTime = currentTime;
  }

}
