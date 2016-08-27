package com.google.auth.oauth2;

import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.RequestMetadataCallback;
import com.google.auth.http.AuthHttpConstants;
import com.google.common.base.Preconditions;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * Base type for Credentials using OAuth2.
 */
public class OAuth2Credentials extends Credentials {

  private static final int MINIMUM_TOKEN_MILLISECONDS = 60000;

  private final Object lock = new Object();
  private Map<String, List<String>> requestMetadata;
  private AccessToken temporaryAccess;
  private List<CredentialsChangedListener> changeListeners;

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
    if (accessToken != null) {
      useAccessToken(accessToken);
    }
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

  @Override
  public void getRequestMetadata(final URI uri, Executor executor,
      final RequestMetadataCallback callback) {
    Map<String, List<String>> metadata;
    synchronized(lock) {
      if (shouldRefresh()) {
        // The base class implementation will do a blocking get in the executor.
        super.getRequestMetadata(uri, executor, callback);
        return;
      }
      metadata = Preconditions.checkNotNull(requestMetadata, "cached requestMetadata");
    }
    callback.onSuccess(metadata);
  }

  /**
   * Provide the request metadata by ensuring there is a current access token and providing it
   * as an authorization bearer token.
   */
  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    synchronized(lock) {
      if (shouldRefresh()) {
        refresh();
      }
      return Preconditions.checkNotNull(requestMetadata, "requestMetadata");
    }
  }

  /**
   * Refresh the token by discarding the cached token and metadata and requesting the new ones.
   */
  @Override
  public void refresh() throws IOException {
    synchronized(lock) {
      requestMetadata = null;
      temporaryAccess = null;
      useAccessToken(Preconditions.checkNotNull(refreshAccessToken(), "new access token"));
      if (changeListeners != null) {
        for (CredentialsChangedListener listener : changeListeners) {
          listener.onChanged(this);
        }
      }
    }
  }

  // Must be called under lock
  private void useAccessToken(AccessToken token) {
    this.temporaryAccess = token;
    this.requestMetadata = Collections.singletonMap(
        AuthHttpConstants.AUTHORIZATION,
        Collections.singletonList(OAuth2Utils.BEARER_PREFIX + token.getTokenValue()));
  }

  // Must be called under lock
  // requestMetadata will never be null if false is returned.
  private boolean shouldRefresh() {
    Long expiresIn = getExpiresInMilliseconds();
    return requestMetadata == null || expiresIn != null && expiresIn <= MINIMUM_TOKEN_MILLISECONDS;
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
   * Adds a listener that is notified when the Credentials data changes.
   *
   * <p>This is called when token content changes, such as when the access token is refreshed. This
   * is typically used by code caching the access token.
   *
   * @param listener The listener to be added.
   */
  public final void addChangeListener(CredentialsChangedListener listener) {
    synchronized(lock) {
      if (changeListeners == null) {
        changeListeners = new ArrayList<CredentialsChangedListener>();
      }
      changeListeners.add(listener);
    }
  }

  /**
   * Return the remaining time the current access token will be valid, or null if there is no
   * token or expiry information. Must be called under lock.
   */
  private Long getExpiresInMilliseconds() {
    if (temporaryAccess == null) {
      return null;
    }
    Date expirationTime = temporaryAccess.getExpirationTime();
    if (expirationTime == null) {
      return null;
    }
    return (expirationTime.getTime() - clock.currentTimeMillis());
  }

  /**
   * Listener for changes to credentials.
   *
   * <p>This is called when token content changes, such as when the access token is refreshed. This
   * is typically used by code caching the access token.
   */
  public interface CredentialsChangedListener {

    /**
     * Notifies that the credentials have changed.
     *
     * <p>This is called when token content changes, such as when the access token is refreshed.
     * This is typically used by code caching the access token.
     *
     * @param credentials The updated credentials instance
     * @throws IOException My be thrown by listeners if saving credentials fails.
     */
    void onChanged(OAuth2Credentials credentials) throws IOException;
  }
}
