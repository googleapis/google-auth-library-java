package com.google.auth.oauth2;

import com.google.errorprone.annotations.CanIgnoreReturnValue;

/** Holds an mTLS configuration (consists of address of S2A) retrieved from the Metadata Server. */
public final class S2AConfig {
  // plaintextAddress is the plaintext address to reach the S2A.
  private final String plaintextAddress;

  // mtlsAddress is the mTLS address to reach the S2A.
  private final String mtlsAddress;

  public static Builder createBuilder() {
    return new Builder();
  }

  public String getPlaintextAddress() {
    return plaintextAddress;
  }

  public String getMtlsAddress() {
    return mtlsAddress;
  }

  public static final class Builder {
    // plaintextAddress is the plaintext address to reach the S2A.
    private String plaintextAddress;

    // mtlsAddress is the mTLS address to reach the S2A.
    private String mtlsAddress;

    Builder() {
      plaintextAddress = "";
      mtlsAddress = "";
    }

    @CanIgnoreReturnValue
    public Builder setPlaintextAddress(String plaintextAddress) {
      this.plaintextAddress = plaintextAddress;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setMtlsAddress(String mtlsAddress) {
      this.mtlsAddress = mtlsAddress;
      return this;
    }

    public S2AConfig build() {
      return new S2AConfig(plaintextAddress, mtlsAddress);
    }
  }

  private S2AConfig(String plaintextAddress, String mtlsAddress) {
    this.plaintextAddress = plaintextAddress;
    this.mtlsAddress = mtlsAddress;
  }
}
