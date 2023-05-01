package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import org.junit.Test;

public class GoogleAuthUtilsTest {

  @Test
  public void getWellKnownCredentialsPath_correct() {
    DefaultCredentialsProvider provider =
        new DefaultCredentialsProviderTest.TestDefaultCredentialsProvider();
    // since the TestDefaultCredentialsProvider properties and envs are not set,
    // the base folder will be an empty string using.
    File homeDir = new File("");
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, provider.CLOUDSDK_CONFIG_DIRECTORY);
    File wellKnownFile = new File(cloudConfigDir, provider.WELL_KNOWN_CREDENTIALS_FILE);

    String obtainedPath = GoogleAuthUtils.getWellKnownCredentialsPath(provider);

    assertNotNull(obtainedPath);
    assertEquals(obtainedPath, wellKnownFile.getAbsolutePath());
  }
}
