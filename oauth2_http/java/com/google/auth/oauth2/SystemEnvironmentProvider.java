package com.google.auth.oauth2;

/** Represents the default system environment provider. */
class SystemEnvironmentProvider implements EnvironmentProvider {
  static final SystemEnvironmentProvider INSTANCE = new SystemEnvironmentProvider();

  private SystemEnvironmentProvider() {}

  @Override
  public String getEnv(String name) {
    return System.getenv(name);
  }

  public static SystemEnvironmentProvider getInstance() {
    return INSTANCE;
  }
}
