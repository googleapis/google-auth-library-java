package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test cases for {@link MtlsConfig}. */
@RunWith(JUnit4.class)
public class MtlsConfigTest {
  private static final String S2A_PLAINTEXT_ADDRESS = "plaintext";
  private static final String S2A_MTLS_ADDRESS = "mtls";

  @Test
  public void createMtlsConfig_success() {
    MtlsConfig config =
        MtlsConfig.createBuilder()
            .setPlaintextS2AAddress(S2A_PLAINTEXT_ADDRESS)
            .setMtlsS2AAddress(S2A_MTLS_ADDRESS)
            .build();
    assertEquals(S2A_PLAINTEXT_ADDRESS, config.getPlaintextS2AAddress());
    assertEquals(S2A_MTLS_ADDRESS, config.getMtlsS2AAddress());
  }

  @Test
  public void createEmptyMtlsConfig_success() {
    MtlsConfig config = MtlsConfig.createBuilder().build();
    assertTrue(config.getPlaintextS2AAddress().isEmpty());
    assertTrue(config.getMtlsS2AAddress().isEmpty());
  }
}
