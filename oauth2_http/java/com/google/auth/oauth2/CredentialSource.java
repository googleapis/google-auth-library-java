package com.google.auth.oauth2;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.Serializable;
import java.util.Map;

/** Base credential source class. Dictates the retrieval method of the external credential. */
abstract class CredentialSource implements Serializable {

  private static final long serialVersionUID = 8204657811562399944L;

  CredentialSource(Map<String, Object> credentialSourceMap) {
    checkNotNull(credentialSourceMap);
  }
}
