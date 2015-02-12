package com.google.auth.oauth2;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;

import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;
import java.util.Date;

/**
 * OAuth2 credentials representing the built-in service account for a Google Compute Engine VM.
 *
 * <p>Fetches access tokens from the Google Compute Engine metadata server.
 */
public class ComputeEngineCredentials extends GoogleCredentials {

  static final String TOKEN_SERVER_ENCODED_URL =
      "http://metadata/computeMetadata/v1/instance/service-accounts/default/token";
  static final String METADATA_SERVER_URL = "http://metadata.google.internal";

  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";

  private final HttpTransport transport;

  /**
   * Constructor with minimum information and default behavior.
   */
  public ComputeEngineCredentials() {
    this(null);
  }

  /**
   * Constructor with overridden transport.
   *
   * @param transport HTTP object used to get access tokens.
   */
  public ComputeEngineCredentials(HttpTransport transport) {
    this.transport = (transport == null) ? OAuth2Utils.HTTP_TRANSPORT : transport;
  }

  /**
   * Refresh the access token by getting it from the GCE metadata server
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    GenericUrl tokenUrl = new GenericUrl(TOKEN_SERVER_ENCODED_URL);
    HttpRequest request = transport.createRequestFactory().buildGetRequest(tokenUrl);
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.getHeaders().set("X-Google-Metadata-Request", true);
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response = null;
    try {
      response = request.execute();
    } catch (UnknownHostException exception) {
      throw OAuth2Utils.exceptionWithCause(new IOException("ComputeEngineCredentials cannot find"
          + " the metadata server. This is likely because code is not running on Google Compute"
          + " Engine."), exception);
    }
    int statusCode = response.getStatusCode();
    if (statusCode == HttpStatusCodes.STATUS_CODE_NOT_FOUND) {
      throw new IOException(String.format("Error code %s trying to get security access token from"
          + " Compute Engine metadata for the default service account. This may be because"
          + " the virtual machine instance does not have permission scopes specified.",
          statusCode));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(String.format("Unexpected Error code %s trying to get security access"
          + " token from Compute Engine metadata for the default service account: %s", statusCode,
          response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from metadata token server request.");
    }
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken = OAuth2Utils.validateString(
        responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds = OAuth2Utils.validateInt32(
        responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000;
    AccessToken access = new AccessToken(accessToken, new Date(expiresAtMilliseconds));
    return access;
  }

  /**
   * Return whether code is running on Google Compute Engine.
   */
  static boolean runningOnComputeEngine(HttpTransport transport) {
    try {
      GenericUrl tokenUrl = new GenericUrl(METADATA_SERVER_URL);
      HttpRequest request = transport.createRequestFactory().buildGetRequest(tokenUrl);
      HttpResponse response = request.execute();
      // Internet providers can return a generic response to all requests, so it is necessary
      // to check that metadata header is present also.
      HttpHeaders headers = response.getHeaders();
      if (OAuth2Utils.headersContainValue(headers, "Metadata-Flavor", "Google")) {
        return true;
      }
    } catch (IOException expected) {
    }
    return false;
  }
}
