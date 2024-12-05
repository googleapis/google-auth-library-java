package com.google.auth;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import java.util.ArrayList;
import java.util.List;

public class TestAppender extends AppenderBase<ILoggingEvent> {
  public static List<ILoggingEvent> events = new ArrayList<>();

  @Override
  protected void append(ILoggingEvent eventObject) {
    events.add(eventObject);
  }

  public static void clearEvents() {
    events.clear();
  }
}
