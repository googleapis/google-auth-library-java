package com.google.auth.oauth2;

import java.util.LinkedList;
import java.util.concurrent.Executor;

/**
 * Mock thread-less executor.
 */
public final class MockExecutor implements Executor {
  private LinkedList<Runnable> tasks = new LinkedList<Runnable>();

  @Override
  public void execute(Runnable task) {
    tasks.add(task);
  }

  int runTasks() {
    LinkedList<Runnable> savedTasks = tasks;
    tasks = new LinkedList<Runnable>();
    for (Runnable task : savedTasks) {
      task.run();
    }
    return savedTasks.size();
  }

  int runTasksExhaustively() {
    int num = 0;
    while (true) {
      int thisNum = runTasks();
      if (thisNum == 0) {
        return num;
      }
      num += thisNum;
    }
  }

  int numTasks() {
    return tasks.size();
  }
}
