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
  public static final String DEFAULT_METADATA_SERVER_URL = "http://metadata.google.internal";
  public static final String MTLS_CONFIG_ENDPOINT =
      "/instance/platform-security/auto-mtls-configuration";

  public static final String METADATA_FLAVOR = "Metadata-Flavor";
  public static final String GOOGLE = "Google";
  private static final String PARSE_ERROR_S2A = "Error parsing Mtls Auto Config response.";

  private MtlsConfig config;

  private transient HttpTransportFactory transportFactory;

  public S2A() {}

  public void setHttpTransportFactory(HttpTransportFactory tf) {
    this.transportFactory = tf;
  }

  /**
   * Returns the S2A Address from the mTLS config.
   *
   * @return the S2A address.
   */
  public synchronized String getS2AAddress() {
    if (config == null) {
      String addr = getMdsMtlsConfigData();
      config = MtlsConfig.createMtlsConfig(addr);
    }
    return config.getS2AAddress();
  }

  /**
   * Queries the MDS mTLS Autoconfiguration endpoint and returns the S2A address.
   *
   * <p>Returns an empty address on error.
   *
   * @return the S2A address.
   */
  private String getMdsMtlsConfigData() {
    String s2aAddress = "";
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
        return "";
      }

      InputStream content = response.getContent();
      if (content == null) {
        return "";
      }
      GenericData responseData = response.parseAs(GenericData.class);
      s2aAddress = OAuth2Utils.validateString(responseData, "s2a", PARSE_ERROR_S2A);
    } catch (IOException e) {
      return "";
    }
    return s2aAddress;
  }

  /** @return MDS mTLS autoconfig endpoint. */
  private String getMdsMtlsEndpoint() {
    return DEFAULT_METADATA_SERVER_URL + MTLS_CONFIG_ENDPOINT;
  }
}
