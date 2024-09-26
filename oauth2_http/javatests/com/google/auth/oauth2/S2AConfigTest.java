package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test cases for {@link S2AConfig}. */
@RunWith(JUnit4.class)
public class S2AConfigTest {
  private static final String S2A_PLAINTEXT_ADDRESS = "plaintext";
  private static final String S2A_MTLS_ADDRESS = "mtls";

  @Test
  public void createS2AConfig_success() {
    S2AConfig config =
        S2AConfig.createBuilder()
            .setPlaintextAddress(S2A_PLAINTEXT_ADDRESS)
            .setMtlsAddress(S2A_MTLS_ADDRESS)
            .build();
    assertEquals(S2A_PLAINTEXT_ADDRESS, config.getPlaintextAddress());
    assertEquals(S2A_MTLS_ADDRESS, config.getMtlsAddress());
  }

  @Test
  public void createEmptyS2AConfig_success() {
    S2AConfig config = S2AConfig.createBuilder().build();
    assertTrue(config.getPlaintextAddress().isEmpty());
    assertTrue(config.getMtlsAddress().isEmpty());
  }
}
