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

import java.io.IOException;
import java.io.Serializable;
import java.util.function.Supplier;

/**
 * Provider for retrieving AWS Security credentials for {@Link AwsCredentials} to exchange for GCP
 * access tokens.
 */
abstract class AwsSecurityCredentialsProvider implements Serializable {

  /**
   * Gets the AWS region to use.
   *
   * @return the AWS region that should be used for the credential.
   * @throws IOException
   */
  abstract String getRegion() throws IOException;

  /**
   * Gets AWS security credentials.
   *
   * @return valid AWS security credentials that can be exchanged for a GCP access token.
   * @throws IOException
   */
  abstract AwsSecurityCredentials getCredentials() throws IOException;

  /**
   * Gets the metrics header value that should be used for the sts request.
   *
   * @return the metrics header value.
   */
  abstract String getMetricsHeaderValue();

  /**
   * Gets the Aws security credential supplier.
   *
   * @return the Supplier used to retrieve the AWS security credentials.
   */
  abstract Supplier<AwsSecurityCredentials> getSupplier();
}
