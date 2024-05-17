package com.google.auth.oauth2;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.collect.Iterables;
import java.io.IOException;
import java.io.InputStream;
import java.util.ServiceLoader;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Utilities to fetch the S2A (Secure Session Agent) address from the mTLS configuration.
 *
 * <p>mTLS configuration is queried from the MDS MTLS Autoconfiguration endpoint.
 */
@ThreadSafe
public final class S2A {
  public static final String MTLS_CONFIG_ENDPOINT =
      "/computeMetadata/v1/instance/platform-security/auto-mtls-configuration";

  public static final String METADATA_FLAVOR = "Metadata-Flavor";
  public static final String GOOGLE = "Google";
  private static final String PARSE_ERROR_S2A = "Error parsing Mtls Auto Config response.";

  private MtlsConfig config;

  private transient HttpTransportFactory transportFactory;

  public S2A() {}

  public void setHttpTransportFactory(HttpTransportFactory tf) {
    this.transportFactory = tf;
  }

  /** @return the mTLS S2A Address from the mTLS config. */
  public synchronized String getMtlsS2AAddress() {
    if (config == null) {
      config = getMdsMtlsConfig();
    }
    return config.getMtlsS2AAddress();
  }

  /** @return the plaintext S2A Address from the mTLS config. */
  public synchronized String getPlaintextS2AAddress() {
    if (config == null) {
      config = getMdsMtlsConfig();
    }
    return config.getPlaintextS2AAddress();
  }

  /**
   * Queries the MDS mTLS Autoconfiguration endpoint and returns the {@link MtlsConfig}.
   *
   * <p>Returns {@link MtlsConfig} with empty addresses on error.
   *
   * @return the {@link MtlsConfig}.
   */
  private MtlsConfig getMdsMtlsConfig() {
    String plaintextS2AAddress = "";
    String mtlsS2AAddress = "";
    try {
      if (transportFactory == null) {
        transportFactory =
            Iterables.getFirst(
                ServiceLoader.load(HttpTransportFactory.class), OAuth2Utils.HTTP_TRANSPORT_FACTORY);
      }
      String url = getMdsMtlsEndpoint();
      GenericUrl genericUrl = new GenericUrl(url);
      HttpRequest request =
          transportFactory.create().createRequestFactory().buildGetRequest(genericUrl);
      JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
      request.setParser(parser);
      request.getHeaders().set(METADATA_FLAVOR, GOOGLE);
      request.setThrowExceptionOnExecuteError(false);
      HttpResponse response = request.execute();

      if (!response.isSuccessStatusCode()) {
        return MtlsConfig.createBuilder().build();
      }

      InputStream content = response.getContent();
      if (content == null) {
        return MtlsConfig.createBuilder().build();
      }
      GenericData responseData = response.parseAs(GenericData.class);
      plaintextS2AAddress =
          OAuth2Utils.validateString(responseData, "plaintext_address", PARSE_ERROR_S2A);
      mtlsS2AAddress = OAuth2Utils.validateString(responseData, "mtls_address", PARSE_ERROR_S2A);
    } catch (IOException e) {
      return MtlsConfig.createBuilder().build();
    }
    return MtlsConfig.createBuilder()
        .setPlaintextS2AAddress(plaintextS2AAddress)
        .setMtlsS2AAddress(mtlsS2AAddress)
        .build();
  }

  /** @return MDS mTLS autoconfig endpoint. */
  private String getMdsMtlsEndpoint() {
    return ComputeEngineCredentials.getMetadataServerUrl() + MTLS_CONFIG_ENDPOINT;
  }
}
