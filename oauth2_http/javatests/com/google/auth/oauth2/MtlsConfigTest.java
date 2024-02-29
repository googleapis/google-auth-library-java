package com.google.auth.oauth2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.joda.time.MutableDateTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test cases for {@link MtlsConfig}. */
@RunWith(JUnit4.class)
public class MtlsConfigTest {
  private static final String S2A_ADDRESS_A = "addr_a";
  private static final String S2A_ADDRESS_B = "addr_b";

  @Test
  public void NullMtlsConfig_invalid() {
    MtlsConfig config = MtlsConfig.createNullMtlsConfig();
    assertEquals("", config.getS2AAddress());
    assertFalse(config.isValid());
  }

  @Test
  public void NonNullMtlsConfig_valid() {
    MtlsConfig config = MtlsConfig.createMtlsConfig(S2A_ADDRESS_A);
    assertEquals(S2A_ADDRESS_A, config.getS2AAddress());
    assertTrue(config.isValid());
  }

  @Test
  public void resetAddress_newExpiryGreater() throws Exception {
    MtlsConfig config = MtlsConfig.createMtlsConfig(S2A_ADDRESS_A);
    MutableDateTime e1 = config.getExpiry();
    assertEquals(S2A_ADDRESS_A, config.getS2AAddress());
    Thread.sleep(2000);
    config.reset(S2A_ADDRESS_B);
    assertEquals(S2A_ADDRESS_B, config.getS2AAddress());
    MutableDateTime e2 = config.getExpiry();
    int value = e2.compareTo(e1);
    assertTrue(value > 0);
  }
}
