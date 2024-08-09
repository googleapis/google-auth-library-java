package com.google.auth.oauth2;

import com.google.errorprone.annotations.CanIgnoreReturnValue;

/** Holds an mTLS configuration (consists of address of S2A) retrieved from the Metadata Server. */
public final class MtlsConfig {
  // plaintextS2AAddress is the plaintext address to reach the S2A.
  private final String plaintextS2AAddress;

  // mtlsS2AAddress is the mTLS address to reach the S2A.
  private final String mtlsS2AAddress;

  public static Builder createBuilder() {
    return new Builder();
  }

  public String getPlaintextS2AAddress() {
    return plaintextS2AAddress;
  }

  public String getMtlsS2AAddress() {
    return mtlsS2AAddress;
  }

  public static final class Builder {
    // plaintextS2AAddress is the plaintext address to reach the S2A.
    private String plaintextS2AAddress;

    // mtlsS2AAddress is the mTLS address to reach the S2A.
    private String mtlsS2AAddress;

    Builder() {
      plaintextS2AAddress = "";
      mtlsS2AAddress = "";
    }

    @CanIgnoreReturnValue
    public Builder setPlaintextS2AAddress(String plaintextS2AAddress) {
      this.plaintextS2AAddress = plaintextS2AAddress;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setMtlsS2AAddress(String mtlsS2AAddress) {
      this.mtlsS2AAddress = mtlsS2AAddress;
      return this;
    }

    public MtlsConfig build() {
      return new MtlsConfig(plaintextS2AAddress, mtlsS2AAddress);
    }
  }

  private MtlsConfig(String plaintextS2AAddress, String mtlsS2AAddress) {
    this.plaintextS2AAddress = plaintextS2AAddress;
    this.mtlsS2AAddress = mtlsS2AAddress;
  }
}
