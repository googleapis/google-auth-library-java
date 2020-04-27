/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.auth.oauth2;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Base64;
import com.google.api.client.util.Clock;
import com.google.api.client.util.Key;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.UncheckedExecutionException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class TokenVerifier {
  private static final String IAP_CERT_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
  private static final String FEDERATED_SIGNON_CERT_URL =
      "https://www.googleapis.com/oauth2/v3/certs";
  private static final Set<String> SUPPORTED_ALGORITMS = ImmutableSet.of("RS256", "ES256");

  private final String audience;
  private final String certificatesLocation;
  private final String issuer;
  private final PublicKey publicKey;
  private final Clock clock;
  private final LoadingCache<String, Map<String, PublicKey>> publicKeyCache;

  public TokenVerifier() {
    this(newBuilder());
  }

  private TokenVerifier(Builder builder) {
    this.audience = builder.audience;
    this.certificatesLocation = builder.certificatesLocation;
    this.issuer = builder.issuer;
    this.publicKey = builder.publicKey;
    this.clock = builder.clock;
    this.publicKeyCache =
        CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build(new PublicKeyLoader(builder.httpTransportFactory));
  }

  public static Builder newBuilder() {
    return new Builder()
        .setClock(Clock.SYSTEM)
        .setHttpTransportFactory(OAuth2Utils.HTTP_TRANSPORT_FACTORY);
  }

  public boolean verify(String token) throws VerificationException {
    JsonWebSignature jsonWebSignature;
    try {
      jsonWebSignature = JsonWebSignature.parse(OAuth2Utils.JSON_FACTORY, token);
    } catch (IOException e) {
      throw new VerificationException("Error parsing JsonWebSignature token", e);
    }

    // Verify the expected audience if an audience is provided in the verifyOptions
    if (audience != null && !audience.equals(jsonWebSignature.getPayload().getAudience())) {
      throw new VerificationException("Expected audience does not match");
    }

    // Verify the expected issuer if an issuer is provided in the verifyOptions
    if (issuer != null && !issuer.equals(jsonWebSignature.getPayload().getIssuer())) {
      throw new VerificationException("Expected issuer does not match");
    }

    Long expiresAt = jsonWebSignature.getPayload().getExpirationTimeSeconds();
    if (expiresAt != null && expiresAt <= clock.currentTimeMillis() / 1000) {
      throw new VerificationException("Token is expired");
    }

    // Short-circuit signature types
    if (!SUPPORTED_ALGORITMS.contains(jsonWebSignature.getHeader().getAlgorithm())) {
      throw new VerificationException(
          "Unexpected signing algorithm: expected either RS256 or ES256");
    }

    PublicKey publicKeyToUse = publicKey;
    if (publicKeyToUse == null) {
      try {
        String certificateLocation = getCertificateLocation(jsonWebSignature);
        publicKeyToUse = publicKeyCache.get(certificateLocation).get(jsonWebSignature.getHeader().getKeyId());
      } catch (ExecutionException | UncheckedExecutionException e) {
        throw new VerificationException("Error fetching PublicKey from certificate location", e);
      }
    }

    if (publicKeyToUse == null) {
      throw new VerificationException("Could not find PublicKey for provided keyId: "
          + jsonWebSignature.getHeader().getKeyId());
    }

    try {
      return jsonWebSignature.verifySignature(publicKeyToUse);
    } catch (GeneralSecurityException e) {
      throw new VerificationException("Error validating token", e);
    }
  }

  private String getCertificateLocation(JsonWebSignature jsonWebSignature) throws VerificationException {
    if (certificatesLocation != null) return certificatesLocation;

    switch(jsonWebSignature.getHeader().getAlgorithm()) {
      case "RS256":
        return FEDERATED_SIGNON_CERT_URL;
      case "ES256":
        return IAP_CERT_URL;
    }

    throw new VerificationException("Unknown algorithm");
  }

  public static class Builder {
    private String audience;
    private String certificatesLocation;
    private String issuer;
    private PublicKey publicKey;
    private Clock clock;
    private HttpTransportFactory httpTransportFactory;

    public Builder setAudience(String audience) {
      this.audience = audience;
      return this;
    }

    public Builder setCertificatesLocation(String certificatesLocation) {
      this.certificatesLocation = certificatesLocation;
      return this;
    }

    public Builder setIssuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    public Builder setPublicKey(PublicKey publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    public Builder setClock(Clock clock) {
      this.clock = clock;
      return this;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory httpTransportFactory) {
      this.httpTransportFactory = httpTransportFactory;
      return this;
    }

    public TokenVerifier build() {
      return new TokenVerifier(this);
    }
  }

  static class PublicKeyLoader extends CacheLoader<String, Map<String, PublicKey>> {
    private final HttpTransportFactory httpTransportFactory;

    public static class JsonWebKeySet extends GenericJson {
      @Key public List<JsonWebKey> keys;
    }

    public static class JsonWebKey {
      @Key public String alg;

      @Key public String crv;

      @Key public String kid;

      @Key public String kty;

      @Key public String use;

      @Key public String x;

      @Key public String y;

      @Key public String e;

      @Key public String n;
    }

    PublicKeyLoader(HttpTransportFactory httpTransportFactory) {
      super();
      this.httpTransportFactory = httpTransportFactory;
    }

    @Override
    public Map<String, PublicKey> load(String certificateUrl) throws Exception {
      HttpTransport httpTransport = httpTransportFactory.create();
      JsonWebKeySet jwks;
      try {
        HttpRequest request =
            httpTransport
                .createRequestFactory()
                .buildGetRequest(new GenericUrl(certificateUrl))
                .setParser(OAuth2Utils.JSON_FACTORY.createJsonObjectParser());
        HttpResponse response = request.execute();
        jwks = response.parseAs(JsonWebKeySet.class);
      } catch (IOException io) {
        return ImmutableMap.of();
      }

      ImmutableMap.Builder<String, PublicKey> keyCacheBuilder = new ImmutableMap.Builder<>();
      if (jwks.keys == null) {
        // Fall back to x509 formatted specification
        for (String keyId : jwks.keySet()) {
          String publicKeyPem = (String) jwks.get(keyId);
          keyCacheBuilder.put(keyId, buildPublicKey(publicKeyPem));
        }
      } else {
        for (JsonWebKey key : jwks.keys) {
          try {
            keyCacheBuilder.put(key.kid, buildPublicKey(key));
          } catch (NoSuchAlgorithmException
              | InvalidKeySpecException
              | InvalidParameterSpecException ignored) {
            ignored.printStackTrace();
          }
        }
      }

      return keyCacheBuilder.build();
    }

    private PublicKey buildPublicKey(JsonWebKey key)
        throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
      if ("ES256".equals(key.alg)) {
        return buildEs256PublicKey(key);
      } else if ("RS256".equals((key.alg))) {
        return buildRs256PublicKey(key);
      } else {
        return null;
      }
    }

    private PublicKey buildPublicKey(String publicPem)
        throws CertificateException, UnsupportedEncodingException {
      return CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(publicPem.getBytes("UTF-8")))
          .getPublicKey();
    }

    private PublicKey buildRs256PublicKey(JsonWebKey key)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
      Preconditions.checkArgument("RSA".equals(key.kty));
      Preconditions.checkNotNull(key.e);
      Preconditions.checkNotNull(key.n);

      BigInteger modulus = new BigInteger(1, Base64.decodeBase64(key.n));
      BigInteger exponent = new BigInteger(1, Base64.decodeBase64(key.e));

      RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      return factory.generatePublic(spec);
    }

    private PublicKey buildEs256PublicKey(JsonWebKey key)
        throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
      Preconditions.checkArgument("EC".equals(key.kty));
      Preconditions.checkArgument("P-256".equals(key.crv));

      BigInteger x = new BigInteger(1, Base64.decodeBase64(key.x));
      BigInteger y = new BigInteger(1, Base64.decodeBase64(key.y));
      ECPoint pubPoint = new ECPoint(x, y);
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
      ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
      KeyFactory kf = KeyFactory.getInstance("EC");
      return kf.generatePublic(pubSpec);
    }
  }

  public static class VerificationException extends Exception {
    public VerificationException(String message) {
      super(message);
    }

    public VerificationException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
