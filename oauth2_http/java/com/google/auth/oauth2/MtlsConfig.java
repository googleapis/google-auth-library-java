package com.google.auth.oauth2;

/** Holds an mTLS configuration (consists of address of S2A) retrieved from the Metadata Server. */
public final class MtlsConfig {
  private final String s2aAddress;

  public static MtlsConfig createMtlsConfig(String addr) {
    return new MtlsConfig(addr);
  }

  public String getS2AAddress() {
    return s2aAddress;
  }

  private MtlsConfig(String addr) {
    this.s2aAddress = addr;
  }
}
