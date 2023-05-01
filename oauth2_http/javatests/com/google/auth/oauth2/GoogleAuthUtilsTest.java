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
    File homeDir = new File(System.getProperty("java.io.tmpdir"));
    File configDir = new File(homeDir, ".config");
    File cloudConfigDir = new File(configDir, provider.CLOUDSDK_CONFIG_DIRECTORY);
    File wellKnownFile = new File(cloudConfigDir, provider.WELL_KNOWN_CREDENTIALS_FILE);

    String obtainedPath = GoogleAuthUtils.getWellKnownCredentialsPath(provider);

    assertNotNull(obtainedPath);
    assertEquals(obtainedPath, wellKnownFile.getAbsolutePath());
  }
}
