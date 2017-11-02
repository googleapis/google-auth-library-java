/*
 * Copyright 2015, Google Inc. All rights reserved.
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
 *    * Neither the name of Google Inc. nor the names of its
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

import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.RequestMetadataCallback;
import com.google.auth.http.AuthHttpConstants;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.base.MoreObjects.ToStringHelper;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.concurrent.Executor;

/**
 * Base type for Credentials using OAuth2.
 */
public class OAuth2Credentials extends Credentials {

  private static final long serialVersionUID = 4556936364828217687L;
  private static final long MINIMUM_TOKEN_MILLISECONDS = 60000L * 5L;

  // byte[] is serializable, so the lock variable can be final
  private final Object lock = new byte[0];
  private Map<String, List<String>> requestMetadata;
  private AccessToken temporaryAccess;

  // Change listeners are not serialized
  private transient List<CredentialsChangedListener> changeListeners;
  // Until we expose this to the users it can remain transient and non-serializable
  @VisibleForTesting
  transient Clock clock = Clock.SYSTEM;

  /**
   * Returns the credentials instance from the given access token.
   *
   * @param accessToken the access token
   * @return the credentials instance
   * @deprecated Use {@link #create(AccessToken)} instead. This method will be deleted in a later
   *             version.
   */
  @Deprecated
  public static OAuth2Credentials of(AccessToken accessToken) {
    return create(accessToken);
  }

  /**
   * Returns the credentials instance from the given access token.
   *
   * @param accessToken the access token
   * @return the credentials instance
   */
  public static OAuth2Credentials create(AccessToken accessToken) {
    return OAuth2Credentials.newBuilder().setAccessToken(accessToken).build();
  }

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
   * @deprecated Use {@link #create(AccessToken)} instead. This constructor will either be deleted
   *             or made private in a later version.
   **/
  @Deprecated
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
        + " that supports refreshing.");
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
        changeListeners = new ArrayList<>();
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

  @Override
  public int hashCode() {
    return Objects.hash(requestMetadata, temporaryAccess);
  }

  protected Map<String, List<String>> getRequestMetadataInternal() {
    return requestMetadata;
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("requestMetadata", requestMetadata)
        .add("temporaryAccess", temporaryAccess).toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof OAuth2Credentials)) {
      return false;
    }
    OAuth2Credentials other = (OAuth2Credentials) obj;
    return Objects.equals(this.requestMetadata, other.requestMetadata)
        && Objects.equals(this.temporaryAccess, other.temporaryAccess);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    clock = Clock.SYSTEM;
  }

  @SuppressWarnings("unchecked")
  protected static <T> T newInstance(String className) throws IOException, ClassNotFoundException {
    try {
      return (T) Class.forName(className).newInstance();
    } catch (InstantiationException | IllegalAccessException e) {
      throw new IOException(e);
    }
  }

  protected static <T> T getFromServiceLoader(Class<? extends T> clazz, T defaultInstance) {
    return Iterables.getFirst(ServiceLoader.load(clazz), defaultInstance);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static class Builder {

    private AccessToken accessToken;

    protected Builder() {}

    protected Builder(OAuth2Credentials credentials) {
      this.accessToken = credentials.getAccessToken();
    }

    public Builder setAccessToken(AccessToken token) {
      this.accessToken = token;
      return this;
    }

    public AccessToken getAccessToken() {
      return accessToken;
    }

    public OAuth2Credentials build() {
      return new OAuth2Credentials(accessToken);
    }
  }
}
