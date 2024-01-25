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

import static com.google.auth.oauth2.AwsCredentialsTest.buildAwsImdsv2CredentialSource;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.auth.oauth2.ExternalAccountCredentialsTest.MockExternalAccountCredentialsTransportFactory;
import com.google.common.collect.ImmutableList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link InternalAwsSecurityCredentialsSupplier}. */
@RunWith(JUnit4.class)
public class InternalAwsSecurityCredentialsSupplierTest {
  @Test
  public void shouldUseMetadataServer_withRequiredEnvironmentVariables() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    // Add required environment variables.
    List<String> regionKeys = ImmutableList.of("AWS_REGION", "AWS_DEFAULT_REGION");
    for (String regionKey : regionKeys) {
      TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
      // AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are always required.
      environmentProvider
          .setEnv(regionKey, "awsRegion")
          .setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId")
          .setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey");
      InternalAwsSecurityCredentialsSupplier supplier =
          new InternalAwsSecurityCredentialsSupplier(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory);
      assertFalse(supplier.shouldUseMetadataServer());
    }
  }

  @Test
  public void shouldUseMetadataServer_missingRegion() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    environmentProvider
        .setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId")
        .setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey");
    InternalAwsSecurityCredentialsSupplier supplier =
        new InternalAwsSecurityCredentialsSupplier(
            buildAwsImdsv2CredentialSource(transportFactory),
            environmentProvider,
            transportFactory);
    assertTrue(supplier.shouldUseMetadataServer());
  }

  @Test
  public void shouldUseMetadataServer_missingAwsAccessKeyId() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    // Add required environment variables.
    List<String> regionKeys = ImmutableList.of("AWS_REGION", "AWS_DEFAULT_REGION");
    for (String regionKey : regionKeys) {
      TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
      // AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are always required.
      environmentProvider
          .setEnv(regionKey, "awsRegion")
          .setEnv("AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey");
      InternalAwsSecurityCredentialsSupplier supplier =
          new InternalAwsSecurityCredentialsSupplier(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory);
      assertTrue(supplier.shouldUseMetadataServer());
    }
  }

  @Test
  public void shouldUseMetadataServer_missingAwsSecretAccessKey() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    // Add required environment variables.
    List<String> regionKeys = ImmutableList.of("AWS_REGION", "AWS_DEFAULT_REGION");
    for (String regionKey : regionKeys) {
      TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
      // AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are always required.
      environmentProvider
          .setEnv(regionKey, "awsRegion")
          .setEnv("AWS_ACCESS_KEY_ID", "awsAccessKeyId");
      InternalAwsSecurityCredentialsSupplier supplier =
          new InternalAwsSecurityCredentialsSupplier(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory);
      assertTrue(supplier.shouldUseMetadataServer());
    }
  }

  @Test
  public void shouldUseMetadataServer_missingAwsSecurityCreds() {
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();

    // Add required environment variables.
    List<String> regionKeys = ImmutableList.of("AWS_REGION", "AWS_DEFAULT_REGION");
    for (String regionKey : regionKeys) {
      TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
      // AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are always required.
      // Not set here.
      environmentProvider.setEnv(regionKey, "awsRegion");
      InternalAwsSecurityCredentialsSupplier supplier =
          new InternalAwsSecurityCredentialsSupplier(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory);
      assertTrue(supplier.shouldUseMetadataServer());
    }
  }

  @Test
  public void shouldUseMetadataServer_noEnvironmentVars() {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    InternalAwsSecurityCredentialsSupplier supplier =
        new InternalAwsSecurityCredentialsSupplier(
            buildAwsImdsv2CredentialSource(transportFactory),
            environmentProvider,
            transportFactory);
    assertTrue(supplier.shouldUseMetadataServer());
  }
}
