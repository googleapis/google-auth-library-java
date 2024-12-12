package com.google.auth.credentialaccessboundary;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpTransport;
import com.google.auth.credentialaccessboundary.protobuf.ClientSideAccessBoundaryProto.ClientSideAccessBoundary;
import com.google.auth.credentialaccessboundary.protobuf.ClientSideAccessBoundaryProto.ClientSideAccessBoundaryRule;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.CredentialAccessBoundary;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.MockStsTransport;
import com.google.auth.oauth2.MockTokenServerTransportFactory;
import com.google.auth.oauth2.OAuth2Utils;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.common.collect.ImmutableList;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import dev.cel.expr.Expr;
import java.io.IOException;
import java.util.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ClientSideCredentialAccessBoundaryFactory} **/
@RunWith(JUnit4.class)
public class ClientSideCredentialAccessBoundaryFactoryTest {
  private static final String SA_PRIVATE_KEY_PKCS8 =
      "-----BEGIN PRIVATE KEY-----\n"
      + "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALX0PQoe1igW12i"
      + "kv1bN/r9lN749y2ijmbc/"
      + "mFHPyS3hNTyOCjDvBbXYbDhQJzWVUikh4mvGBA07qTj79Xc3yBDfKP2IeyYQIFe0t0"
      + "zkd7R9Zdn98Y2rIQC47aAbDfubtkU1U72t4zL11kHvoa0/"
      + "RuFZjncvlr42X7be7lYh4p3NAgMBAAECgYASk5wDw"
      + "4Az2ZkmeuN6Fk/"
      + "y9H+"
      + "Lcb2pskJIXjrL533vrDWGOC48LrsThMQPv8cxBky8HFSEklPpkfTF95tpD43iVwJRB/Gr"
      + "CtGTw65IfJ4/tI09h6zGc4yqvIo1cHX/LQ+SxKLGyir/dQM925rGt/"
      + "VojxY5ryJR7GLbCzxPnJm/oQJBANwOCO6"
      + "D2hy1LQYJhXh7O+RLtA/"
      + "tSnT1xyMQsGT+uUCMiKS2bSKx2wxo9k7h3OegNJIu1q6nZ6AbxDK8H3+d0dUCQQDTrP"
      + "SXagBxzp8PecbaCHjzNRSQE2in81qYnrAFNB4o3DpHyMMY6s5ALLeHKscEWnqP8Ur6X4"
      + "PvzZecCWU9BKAZAkAut"
      + "LPknAuxSCsUOvUfS1i87ex77Ot+w6POp34pEX+UWb+"
      + "u5iFn2cQacDTHLV1LtE80L8jVLSbrbrlH43H0DjU5AkEA"
      + "gidhycxS86dxpEljnOMCw8CKoUBd5I880IUahEiUltk7OLJYS/"
      + "Ts1wbn3kPOVX3wyJs8WBDtBkFrDHW2ezth2QJ"
      + "ADj3e1YhMVdjJW5jqwlD/"
      + "VNddGjgzyunmiZg0uOXsHXbytYmsA545S8KRQFaJKFXYYFo2kOjqOiC1T2cAzMDjCQ"
      + "==\n-----END PRIVATE KEY-----\n";

  static class MockStsTransportFactory implements HttpTransportFactory {

    MockStsTransport transport = new MockStsTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  private static GoogleCredentials
  getServiceAccountSourceCredentials(boolean canRefresh) throws IOException {
    MockTokenServerTransportFactory transportFactory =
        new MockTokenServerTransportFactory();

    String email = "service-account@google.com";

    ServiceAccountCredentials sourceCredentials =
        ServiceAccountCredentials.newBuilder()
            .setClientEmail(email)
            .setPrivateKey(
                OAuth2Utils.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8))
            .setPrivateKeyId("privateKeyId")
            .setProjectId("projectId")
            .setHttpTransportFactory(transportFactory)
            .build();

    transportFactory.transport.addServiceAccount(email, "accessToken");

    if (!canRefresh) {
      transportFactory.transport.setError(new IOException());
    }

    return sourceCredentials.createScoped(
        "https://www.googleapis.com/auth/cloud-platform");
  }

  @Test
  public void generateToken() throws Exception {
    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    transportFactory.transport.setReturnAccessBoundarySessionKey(true);

    ClientSideCredentialAccessBoundaryFactory.Builder builder =
        ClientSideCredentialAccessBoundaryFactory.newBuilder();

    ClientSideCredentialAccessBoundaryFactory factory =
        builder.setSourceCredential(getServiceAccountSourceCredentials(true))
            .setHttpTransportFactory(transportFactory)
            .build();

    CredentialAccessBoundary.Builder cabBuilder =
        CredentialAccessBoundary.newBuilder();
    CredentialAccessBoundary accessBoundary =
        cabBuilder
            .addRule(
                CredentialAccessBoundary.AccessBoundaryRule.newBuilder()
                    .setAvailableResource("//storage.googleapis.com/projects/"
                                          + "_/buckets/example-bucket")
                    .setAvailablePermissions(
                        ImmutableList.of("inRole:roles/storage.objectViewer"))
                    .setAvailabilityCondition(
                        CredentialAccessBoundary.AccessBoundaryRule
                            .AvailabilityCondition.newBuilder()
                            .setExpression(
                                "resource.name.startsWith('projects/_/"
                                + "buckets/example-bucket/objects/customer-a')")
                            .build())
                    .build())
            .build();

    AccessToken token = factory.generateToken(accessBoundary);

    String[] parts = token.getTokenValue().split("\\.");
    assertEquals(parts.length, 2);
    assertEquals(parts[0], "accessToken");

    byte[] rawKey = Base64.getDecoder().decode(
        transportFactory.transport.getAccessBoundarySessionKey());

    KeysetHandle keysetHandle = TinkProtoKeysetFormat.parseKeyset(
        rawKey, InsecureSecretKeyAccess.get());

    Aead aead =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    byte[] rawRestrictions =
        aead.decrypt(Base64.getUrlDecoder().decode(parts[1]), new byte[0]);
    ClientSideAccessBoundary clientSideAccessBoundary =
        ClientSideAccessBoundary.parseFrom(rawRestrictions);
    assertEquals(clientSideAccessBoundary.getAccessBoundaryRulesCount(), 1);
    ClientSideAccessBoundaryRule rule =
        clientSideAccessBoundary.getAccessBoundaryRules(0);
    assertEquals(rule.getAvailableResource(),
                 "//storage.googleapis.com/projects/_/buckets/example-bucket");
    assertEquals(rule.getAvailablePermissions(0),
                 "inRole:roles/storage.objectViewer");
    Expr expr = rule.getCompiledAvailabilityCondition();
    assertEquals(expr.getCallExpr()
                     .getTarget()
                     .getSelectExpr()
                     .getOperand()
                     .getIdentExpr()
                     .getName(),
                 "resource");
    assertEquals(expr.getCallExpr().getFunction(), "startsWith");
    assertEquals(expr.getCallExpr().getArgs(0).getConstExpr().getStringValue(),
                 "projects/_/buckets/example-bucket/objects/customer-a");
  }

  @Test
  public void generateToken_withoutAvailabilityCondition() throws Exception {
    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    transportFactory.transport.setReturnAccessBoundarySessionKey(true);

    ClientSideCredentialAccessBoundaryFactory.Builder builder =
        ClientSideCredentialAccessBoundaryFactory.newBuilder();

    ClientSideCredentialAccessBoundaryFactory factory =
        builder.setSourceCredential(getServiceAccountSourceCredentials(true))
            .setHttpTransportFactory(transportFactory)
            .build();

    CredentialAccessBoundary.Builder cabBuilder =
        CredentialAccessBoundary.newBuilder();
    CredentialAccessBoundary accessBoundary =
        cabBuilder
            .addRule(
                CredentialAccessBoundary.AccessBoundaryRule.newBuilder()
                    .setAvailableResource("//storage.googleapis.com/projects/"
                                          + "_/buckets/example-bucket")
                    .setAvailablePermissions(
                        ImmutableList.of("inRole:roles/storage.objectViewer"))
                    .build())
            .build();

    AccessToken token = factory.generateToken(accessBoundary);

    String[] parts = token.getTokenValue().split("\\.");
    assertEquals(parts.length, 2);
    assertEquals(parts[0], "accessToken");

    byte[] rawKey = Base64.getDecoder().decode(
        transportFactory.transport.getAccessBoundarySessionKey());

    KeysetHandle keysetHandle = TinkProtoKeysetFormat.parseKeyset(
        rawKey, InsecureSecretKeyAccess.get());

    Aead aead =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    byte[] rawRestrictions =
        aead.decrypt(Base64.getUrlDecoder().decode(parts[1]), new byte[0]);
    ClientSideAccessBoundary clientSideAccessBoundary =
        ClientSideAccessBoundary.parseFrom(rawRestrictions);
    assertEquals(clientSideAccessBoundary.getAccessBoundaryRulesCount(), 1);
    ClientSideAccessBoundaryRule rule =
        clientSideAccessBoundary.getAccessBoundaryRules(0);
    assertEquals(rule.getAvailableResource(),
                 "//storage.googleapis.com/projects/_/buckets/example-bucket");
    assertEquals(rule.getAvailablePermissions(0),
                 "inRole:roles/storage.objectViewer");
    assertTrue(rule.getCompiledAvailabilityCondition().equals(
        Expr.getDefaultInstance()));
  }

  @Test
  public void generateToken_withInvalidCelExpression() throws Exception {
    MockStsTransportFactory transportFactory = new MockStsTransportFactory();
    transportFactory.transport.setReturnAccessBoundarySessionKey(true);

    ClientSideCredentialAccessBoundaryFactory.Builder builder =
        ClientSideCredentialAccessBoundaryFactory.newBuilder();

    ClientSideCredentialAccessBoundaryFactory factory =
        builder.setSourceCredential(getServiceAccountSourceCredentials(true))
            .setHttpTransportFactory(transportFactory)
            .build();

    CredentialAccessBoundary.Builder cabBuilder =
        CredentialAccessBoundary.newBuilder();
    CredentialAccessBoundary accessBoundary =
        cabBuilder
            .addRule(
                CredentialAccessBoundary.AccessBoundaryRule.newBuilder()
                    .setAvailableResource("//storage.googleapis.com/projects/"
                                          + "_/buckets/example-bucket")
                    .setAvailablePermissions(
                        ImmutableList.of("inRole:roles/storage.objectViewer"))
                    .setAvailabilityCondition(
                        CredentialAccessBoundary.AccessBoundaryRule
                            .AvailabilityCondition.newBuilder()
                            .setExpression(
                                "resource.name.startsWith('projects/_/"
                                + "buckets/example-bucket/objects/customer-a'")
                            .build())
                    .build())
            .build();

    assertThrows(IOException.class,
                 () -> { factory.generateToken(accessBoundary); });
  }
}
