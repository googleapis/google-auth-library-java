package com.google.auth.oauth2;

import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.http.AuthHttpConstants;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Base type for Credentials using OAuth2.
 */
public class OAuth2Credentials extends Credentials {

  private static final int MINIMUM_TOKEN_MILLISECONDS = 60000;

  private final Object lock = new Object();
  private Map<String, List<String>> requestMetadata;
  private AccessToken temporaryAccess;

  // Allow clock to be overridden by test code
  Clock clock = Clock.SYSTEM;

  /**
   * Default constructor.
   **/
  protected OAuth2Credentials() {
    this(null);
  }

  /**
   * Constructor with explicit access token.
   *
   * @param accessToken Initial or temporary access token.
   **/
  public OAuth2Credentials(AccessToken accessToken) {
    this.temporaryAccess = accessToken;
  }

  @Override
  public String getAuthenticationType() {
    return "OAuth2";
  }

  @Override
  public boolean hasRequestMetadata() {
    return true;
  }

  @Override
  public boolean hasRequestMetadataOnly() {
    return true;
  }

  public final AccessToken getAccessToken() {
    return temporaryAccess;
  }

  /**
   * Provide the request metadata by ensuring there is a current access token and providing it
   * as an authorization bearer token.
   */
  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    synchronized(lock) {
      Long expiresIn = getExpiresInMilliseconds();
      if (temporaryAccess == null || expiresIn != null && expiresIn <= MINIMUM_TOKEN_MILLISECONDS) {
        refresh();
      }
      assert(temporaryAccess != null);
      if (requestMetadata == null) {
        Map<String, List<String>> newRequestMetadata = new HashMap<String, List<String>>();
        List<String> newAuthorizationHeaders = new ArrayList<String>();
        String authorizationHeader = OAuth2Utils.BEARER_PREFIX + temporaryAccess.getTokenValue();
        newAuthorizationHeaders.add(authorizationHeader);
        newRequestMetadata.put(AuthHttpConstants.AUTHORIZATION, newAuthorizationHeaders);
        requestMetadata = newRequestMetadata;
      }
      return requestMetadata;
    }
  }

  /**
   * Refresh the token by discarding the cached token and metadata.
   */
  @Override
  public void refresh() throws IOException {
    synchronized(lock) {
      requestMetadata = null;
      temporaryAccess = null;
      temporaryAccess = refreshAccessToken();
    }
  }

  /**
   * Method to refresh the access token according to the specific type of credentials.
   *
   * Throws IllegalStateException if not overridden since direct use of OAuth2Credentials is only
   * for temporary or non-refreshing access tokens.
   *
   * @throws IOException from derived implementations
   */
  public AccessToken refreshAccessToken() throws IOException {
    throw new IllegalStateException("OAuth2Credentials instance does not support refreshing the"
        + " access token. An instance with a new access token should be used, or a derived type"
        + " that supports refreshing should be used.");
  }

  /**
   * Return the remaining time the current access token will be valid, or null if there is no
   * token or expiry information.
   */
  private final Long getExpiresInMilliseconds() {
    synchronized(lock) {
      if (temporaryAccess == null) {
        return null;
      }
      Date expirationTime = temporaryAccess.getExpirationTime();
      if (expirationTime == null) {
        return null;
      }
      return (expirationTime.getTime() - clock.currentTimeMillis());
    }
  }
}
