/*
 * Copyright 2016, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.google.auth.oauth2;

import com.google.errorprone.annotations.CanIgnoreReturnValue;

/** Holds an mTLS configuration (consists of address of S2A) retrieved from the Metadata Server. */
final class S2AConfig {
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
