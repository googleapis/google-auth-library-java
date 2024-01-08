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

/** Tests for {@link InternalAwsSecurityCredentialsProvider}. */
@RunWith(JUnit4.class)
public class InternalAwsSecurityCredentialsProviderTest {
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
      InternalAwsSecurityCredentialsProvider provider =
          new InternalAwsSecurityCredentialsProvider(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory,
              null);
      assertFalse(provider.shouldUseMetadataServer());
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
    InternalAwsSecurityCredentialsProvider provider =
        new InternalAwsSecurityCredentialsProvider(
            buildAwsImdsv2CredentialSource(transportFactory),
            environmentProvider,
            transportFactory,
            null);
    assertTrue(provider.shouldUseMetadataServer());
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
      InternalAwsSecurityCredentialsProvider provider =
          new InternalAwsSecurityCredentialsProvider(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory,
              null);
      assertTrue(provider.shouldUseMetadataServer());
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
      InternalAwsSecurityCredentialsProvider provider =
          new InternalAwsSecurityCredentialsProvider(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory,
              null);
      assertTrue(provider.shouldUseMetadataServer());
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
      InternalAwsSecurityCredentialsProvider provider =
          new InternalAwsSecurityCredentialsProvider(
              buildAwsImdsv2CredentialSource(transportFactory),
              environmentProvider,
              transportFactory,
              null);
      assertTrue(provider.shouldUseMetadataServer());
    }
  }

  @Test
  public void shouldUseMetadataServer_noEnvironmentVars() {
    TestEnvironmentProvider environmentProvider = new TestEnvironmentProvider();
    MockExternalAccountCredentialsTransportFactory transportFactory =
        new MockExternalAccountCredentialsTransportFactory();
    InternalAwsSecurityCredentialsProvider provider =
        new InternalAwsSecurityCredentialsProvider(
            buildAwsImdsv2CredentialSource(transportFactory),
            environmentProvider,
            transportFactory,
            null);
    assertTrue(provider.shouldUseMetadataServer());
  }
}
