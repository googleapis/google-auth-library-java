package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import org.junit.Test;

public class GoogleAuthUtilsTest {
  @Test
  public void getWellKnownCredentialsPath_correct() {
    File homeDir = DefaultCredentialsProviderTest.getTempDirectory();
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, DefaultCredentialsProvider.CLOUDSDK_CONFIG_DIRECTORY);
    File wellKnownFile =
        new File(cloudConfigDir, DefaultCredentialsProvider.WELL_KNOWN_CREDENTIALS_FILE);

    String obtainedPath = GoogleAuthUtils.getWellKnownCredentialsPath();

    assertNotNull(obtainedPath);
    assertEquals(obtainedPath, wellKnownFile.getAbsolutePath());
  }
}
