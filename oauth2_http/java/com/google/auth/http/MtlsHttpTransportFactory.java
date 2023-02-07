package com.google.auth.http;

import com.google.api.client.googleapis.mtls.MtlsProvider;
import com.google.api.client.http.HttpTransport;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A base interface for mTLS {@link HttpTransport}.
 *
 */
public interface MtlsHttpTransportFactory {
  /**
   * Creates an mTLS enabled {@code HttpTransport} instance.
   *
   * @return The HttpTransport instance.
   */
  HttpTransport newTrustedTransport(MtlsProvider mtlsProvider) throws GeneralSecurityException, IOException;
}
