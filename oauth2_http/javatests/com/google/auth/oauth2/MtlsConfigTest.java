package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test cases for {@link MtlsConfig}. */
@RunWith(JUnit4.class)
public class MtlsConfigTest {
  private static final String S2A_ADDRESS_A = "addr_a";

  @Test
  public void createMtlsConfig_success() {
    MtlsConfig config = MtlsConfig.createMtlsConfig(S2A_ADDRESS_A);
    assertEquals(S2A_ADDRESS_A, config.getS2AAddress());
  }
}
