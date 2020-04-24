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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class TokenVerifier {
  private static final String IAP_CERT_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
  private static final String FEDERATED_SIGNON_CERT_URL =
      "https://www.googleapis.com/oauth2/v3/certs";

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
        CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).build(new PublicKeyLoader());
  }

  public static Builder newBuilder() {
    return new Builder().setClock(Clock.SYSTEM);
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

    switch (jsonWebSignature.getHeader().getAlgorithm()) {
      case "RS256":
        return verifyRs256(jsonWebSignature);
      case "ES256":
        return verifyEs256(jsonWebSignature);
      default:
        throw new VerificationException(
            "Unexpected signing algorithm: expected either RS256 or ES256");
    }
  }

  public static class Builder {
    private String audience;
    private String certificatesLocation;
    private String issuer;
    private PublicKey publicKey;
    private Clock clock;

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

    public TokenVerifier build() {
      return new TokenVerifier(this);
    }
  }

  static class PublicKeyLoader extends CacheLoader<String, Map<String, PublicKey>> {
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

    @Override
    public Map<String, PublicKey> load(String certificateUrl) throws Exception {
      HttpTransportFactory httpTransportFactory = OAuth2Utils.HTTP_TRANSPORT_FACTORY;
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

  private boolean verifyEs256(JsonWebSignature jsonWebSignature) throws VerificationException {
    String certsUrl = certificatesLocation == null ? IAP_CERT_URL : certificatesLocation;
    PublicKey verifyPublicKey = publicKey;
    if (verifyPublicKey == null) {
      try {
        verifyPublicKey = publicKeyCache.get(certsUrl).get(jsonWebSignature.getHeader().getKeyId());
      } catch (ExecutionException e) {
        throw new VerificationException("Error fetching PublicKey for ES256 token", e);
      }
    }
    if (verifyPublicKey == null) {
      throw new VerificationException(
          "Could not find publicKey for provided keyId: "
              + jsonWebSignature.getHeader().getKeyId());
    }
    try {
      Signature signatureAlgorithm = Signature.getInstance("SHA256withECDSA");
      signatureAlgorithm.initVerify(verifyPublicKey);
      signatureAlgorithm.update(jsonWebSignature.getSignedContentBytes());
      byte[] derBytes = convertDerBytes(jsonWebSignature.getSignatureBytes());
      return signatureAlgorithm.verify(derBytes);
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new VerificationException("Error validating ES256 token", e);
    }
  }

  private boolean verifyRs256(JsonWebSignature jsonWebSignature) throws VerificationException {
    String certsUrl =
        certificatesLocation == null ? FEDERATED_SIGNON_CERT_URL : certificatesLocation;
    PublicKey verifyPublicKey = publicKey;
    if (verifyPublicKey == null) {
      try {
        verifyPublicKey = publicKeyCache.get(certsUrl).get(jsonWebSignature.getHeader().getKeyId());
      } catch (ExecutionException e) {
        throw new VerificationException("Error fetching PublicKey for ES256 token", e);
      }
    }
    if (verifyPublicKey == null) {
      throw new VerificationException(
          "Could not find publicKey for provided keyId: "
              + jsonWebSignature.getHeader().getKeyId());
    }
    try {
      return jsonWebSignature.verifySignature(verifyPublicKey);
    } catch (GeneralSecurityException e) {
      throw new VerificationException("Error validating RS256 token", e);
    }
  }

  private static byte DER_TAG_SIGNATURE_OBJECT = 0x30;
  private static byte DER_TAG_ASN1_INTEGER = 0x02;

  private static byte[] convertDerBytes(byte[] signature) {
    // expect the signature to be 64 bytes long
    Preconditions.checkState(signature.length == 64);

    byte[] int1 = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32)).toByteArray();
    byte[] int2 = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64)).toByteArray();
    byte[] der = new byte[6 + int1.length + int2.length];

    // Mark that this is a signature object
    der[0] = DER_TAG_SIGNATURE_OBJECT;
    der[1] = (byte) (der.length - 2);

    // Start ASN1 integer and write the first 32 bits
    der[2] = DER_TAG_ASN1_INTEGER;
    der[3] = (byte) int1.length;
    System.arraycopy(int1, 0, der, 4, int1.length);

    // Start ASN1 integer and write the second 32 bits
    int offset = int1.length + 4;
    der[offset] = DER_TAG_ASN1_INTEGER;
    der[offset + 1] = (byte) int2.length;
    System.arraycopy(int2, 0, der, offset + 2, int2.length);

    return der;
  }
}
