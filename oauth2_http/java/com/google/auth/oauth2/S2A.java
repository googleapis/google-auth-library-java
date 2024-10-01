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
  public static final String S2A_CONFIG_ENDPOINT_POSTFIX =
      "/computeMetadata/v1/instance/platform-security/auto-mtls-configuration";

  public static final String METADATA_FLAVOR = "Metadata-Flavor";
  public static final String GOOGLE = "Google";
  private static final int MAX_MDS_PING_TRIES = 3;
  private static final String PARSE_ERROR_S2A = "Error parsing S2A Config from MDS JSON response.";

  private S2AConfig config;

  private transient HttpTransportFactory transportFactory;

  public S2A() {}

  public void setHttpTransportFactory(HttpTransportFactory tf) {
    this.transportFactory = tf;
    this.config = getS2AConfigFromMDS();
  }

  /** @return the mTLS S2A Address from the mTLS config. */
  public String getMtlsS2AAddress() {
    return config.getMtlsAddress();
  }

  /** @return the plaintext S2A Address from the mTLS config. */
  public String getPlaintextS2AAddress() {
    return config.getPlaintextAddress();
  }

  /**
   * Queries the MDS mTLS Autoconfiguration endpoint and returns the {@link S2AConfig}.
   *
   * <p>Returns {@link S2AConfig} with empty addresses on error.
   *
   * @return the {@link S2AConfig}.
   */
  private S2AConfig getS2AConfigFromMDS() {
    String plaintextS2AAddress = "";
    String mtlsS2AAddress = "";

    String url = getMdsMtlsEndpoint();
    GenericUrl genericUrl = new GenericUrl(url);
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY); 
    if (transportFactory == null) {
      transportFactory =
          Iterables.getFirst(
              ServiceLoader.load(HttpTransportFactory.class), OAuth2Utils.HTTP_TRANSPORT_FACTORY);
    }  

    for (int i = 0; i < MAX_MDS_PING_TRIES; i++) {
      try {
        HttpRequest request =
            transportFactory.create().createRequestFactory().buildGetRequest(genericUrl);
        request.setParser(parser);
        request.getHeaders().set(METADATA_FLAVOR, GOOGLE);
        request.setThrowExceptionOnExecuteError(false);
        HttpResponse response = request.execute();

        if (!response.isSuccessStatusCode()) {
          continue;
        }

        InputStream content = response.getContent();
        if (content == null) {
          continue;
        }
        GenericData responseData = response.parseAs(GenericData.class);
        plaintextS2AAddress =
            OAuth2Utils.validateString(responseData, "plaintext_address", PARSE_ERROR_S2A);
        mtlsS2AAddress = OAuth2Utils.validateString(responseData, "mtls_address", PARSE_ERROR_S2A);
      } catch (IOException e) {
        continue;
      }
      return S2AConfig.createBuilder()
          .setPlaintextAddress(plaintextS2AAddress)
          .setMtlsAddress(mtlsS2AAddress)
          .build();
    }
    return S2AConfig.createBuilder().build();
  }

  /** @return MDS mTLS autoconfig endpoint. */
  private String getMdsMtlsEndpoint() {
    return ComputeEngineCredentials.getMetadataServerUrl() + S2A_CONFIG_ENDPOINT_POSTFIX;
  }
}
