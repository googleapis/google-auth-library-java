/*
 * Copyright 2024 Google LLC
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
 *    * Neither the name of Google LLC nor the names of its
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

import static com.google.auth.oauth2.ExternalAccountCredentials.PROGRAMMATIC_METRICS_HEADER_VALUE;

import java.util.function.Supplier;

/**
 * Provider for retrieving AWS security credentials for {@Link AwsCredentials} to exchange for GCP
 * access tokens. The credentials are retrieved by calling a Supplier that has been defined by users
 * when creating the AwsCredential.
 */
class ProgrammaticAwsSecurityCredentialsProvider extends AwsSecurityCredentialsProvider {
  private static final long serialVersionUID = 6699948149655089007L;

  private final String region;
  private final transient Supplier<AwsSecurityCredentials> awsSecurityCredentialsSupplier;

  /**
   * Constructor for ProgrammaticAwsSecurityCredentialsProvider
   *
   * @param supplier the user defined supplier that returns AWS security credentials.
   * @param region the AWS region that should be returned by getRegion().
   */
  ProgrammaticAwsSecurityCredentialsProvider(
      Supplier<AwsSecurityCredentials> supplier, String region) {
    if (region == null || region.trim().isEmpty()) {
      throw new IllegalArgumentException(
          "An AWS region must be specified when using an aws security credential supplier.");
    }
    this.region = region;
    this.awsSecurityCredentialsSupplier = supplier;
  }

  @Override
  String getRegion() {
    return this.region;
  }

  @Override
  AwsSecurityCredentials getCredentials() throws GoogleAuthException {
    try {
      return this.awsSecurityCredentialsSupplier.get();
    } catch (RuntimeException e) {
      throw new GoogleAuthException(
          /* isRetryable= */ false,
          /* retryCount= */ 0,
          "Error retrieving token from AWS security credentials supplier.",
          e);
    }
  }

  @Override
  String getMetricsHeaderValue() {
    return PROGRAMMATIC_METRICS_HEADER_VALUE;
  }

  public Supplier<AwsSecurityCredentials> getSupplier() {
    return this.awsSecurityCredentialsSupplier;
  }
}
