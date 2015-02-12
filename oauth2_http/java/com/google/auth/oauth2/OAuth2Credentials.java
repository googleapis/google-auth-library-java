package com.google.auth.oauth2;

import com.google.api.client.util.Clock;
import com.google.auth.Credentials;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Base type for Credentials using OAuth2.
 */
public abstract class OAuth2Credentials extends Credentials {

  private static final int MINIMUM_TOKEN_MILLISECONDS = 60000;

  private final Object lock = new Object();
  private Map<String, List<String>> requestMetadata;
  private AccessToken temporaryAccess;

  // Allow clock to be overriden by test code
  Clock clock = Clock.SYSTEM;

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

  /**
   * Provide the request metadata by ensuring there is a current access token and providing it
   * as an authorization bearer token.
   */
  @Override
  public Map<String, List<String>> getRequestMetadata() throws IOException {
    synchronized(lock) {
      Long expiresIn = getExpiresInMilliseconds();
      if (temporaryAccess == null || expiresIn != null && expiresIn <= MINIMUM_TOKEN_MILLISECONDS) {
        refresh();
      }
      assert(temporaryAccess != null);
      if (requestMetadata == null) {
        Map<String, List<String>> newRequestMetadata = new HashMap<String, List<String>>();
        List<String> newAuthorizationHeaders = new ArrayList<String>();
        String authorizationHeader = "Bearer " + temporaryAccess.getTokenValue();
        newAuthorizationHeaders.add(authorizationHeader);
        newRequestMetadata.put("Authorization", newAuthorizationHeaders);
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
   * Abstract method to refresh the access token according to the specific type of credentials.
   */
  public abstract AccessToken refreshAccessToken() throws IOException;

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
