# Google Auth Library

Open source authentication client library for Java.

[![unstable](http://badges.github.io/stability-badges/dist/unstable.svg)](http://github.com/badges/stability-badges)
[![codecov](https://codecov.io/gh/googleapis/google-auth-library-java/branch/master/graph/badge.svg)](https://codecov.io/gh/googleapis/google-auth-library-java)
[![Maven](https://img.shields.io/maven-central/v/com.google.auth/google-auth-library-credentials.svg)](https://img.shields.io/maven-central/v/com.google.auth/google-auth-library-credentials.svg)

-  [API Documentation](https://googleapis.dev/java/google-auth-library/latest)

This project consists of 3 artifacts:

-  [*google-auth-library-credentials*](#google-auth-library-credentials): contains base classes and
interfaces for Google credentials
-  [*google-auth-library-appengine*](#google-auth-library-appengine): contains App Engine
credentials. This artifact depends on the App Engine SDK.
-  [*google-auth-library-oauth2-http*](#google-auth-library-oauth2-http): contains a wide variety of
credentials as well as utility methods to create them and to get Application Default Credentials

> Note: This client is a work-in-progress, and may occasionally
> make backwards-incompatible changes.

## Quickstart

If you are using Maven, add this to your pom.xml file (notice that you can replace
`google-auth-library-oauth2-http` with any of `google-auth-library-credentials` and
`google-auth-library-appengine`, depending on your application needs):

[//]: # ({x-version-update-start:google-auth-library-oauth2-http:released})

```xml
<dependency>
  <groupId>com.google.auth</groupId>
  <artifactId>google-auth-library-oauth2-http</artifactId>
  <version>0.22.0</version>
</dependency>
```
[//]: # ({x-version-update-end})


If you are using Gradle, add this to your dependencies

[//]: # ({x-version-update-start:google-auth-library-oauth2-http:released})
```Groovy
compile 'com.google.auth:google-auth-library-oauth2-http:0.22.0'
```
[//]: # ({x-version-update-end})

If you are using SBT, add this to your dependencies

[//]: # ({x-version-update-start:google-auth-library-oauth2-http:released})
```Scala
libraryDependencies += "com.google.auth" % "google-auth-library-oauth2-http" % "0.22.0"
```
[//]: # ({x-version-update-end})

## google-auth-library-credentials

This artifact contains base classes and interfaces for Google credentials:
- `Credentials`: base class for an authorized identity. Implementations of this class can be used to
authorize your application
- `RequestMetadataCallback`: interface for the callback that receives the result of the asynchronous
`Credentials.getRequestMetadata(URI, Executor, RequestMetadataCallback)`
- `ServiceAccountSigner`: interface for a service account signer. Implementations of this class are
capable of signing byte arrays using the credentials associated to a Google Service Account

## google-auth-library-appengine

This artifact depends on the App Engine SDK (`appengine-api-1.0-sdk`) and should be used only by
applications running on App Engine environments that use urlfetch. The `AppEngineCredentials` class
allows you to authorize your App Engine application given an instance of
[AppIdentityService][appengine-app-identity-service].

Usage:

```java
import com.google.appengine.api.appidentity.AppIdentityService;
import com.google.appengine.api.appidentity.AppIdentityServiceFactory;
import com.google.auth.Credentials;
import com.google.auth.appengine.AppEngineCredentials;

AppIdentityService appIdentityService = AppIdentityServiceFactory.getAppIdentityService();

Credentials credentials =
    AppEngineCredentials.newBuilder()
        .setScopes(...)
        .setAppIdentityService(appIdentityService)
        .build();
```

**Important: `com.google.auth.appengine.AppEngineCredentials` is a separate class from
`com.google.auth.oauth2.AppEngineCredentials`.**

## google-auth-library-oauth2-http

### Application Default Credentials

This artifact contains a wide variety of credentials as well as utility methods to create them and
to get Application Default Credentials.
Credentials classes contained in this artifact are:
- `CloudShellCredentials`: credentials for Google Cloud Shell built-in service account
- `ComputeEngineCredentials`: credentials for Google Compute Engine built-in service account
- `OAuth2Credentials`: base class for OAuth2-based credentials
- `ServiceAccountCredentials`: credentials for a Service Account - use a JSON Web Token (JWT) to get
access tokens
- `ServiceAccountJwtAccessCredentials`: credentials for a Service Account - use JSON Web Token (JWT)
directly in the request metadata to provide authorization
- `UserCredentials`: credentials for a user identity and consent

To get Application Default Credentials use `GoogleCredentials.getApplicationDefault()` or
`GoogleCredentials.getApplicationDefault(HttpTransportFactory)`. These methods return the
Application Default Credentials which are used to identify and authorize the whole application. The
following are searched (in order) to find the Application Default Credentials:

1. Credentials file pointed to by the `GOOGLE_APPLICATION_CREDENTIALS` environment variable
2. Credentials provided by the Google Cloud SDK `gcloud auth application-default login` command
3. Google App Engine built-in credentials
4. Google Cloud Shell built-in credentials
5. Google Compute Engine built-in credentials
   - Skip this check by setting the environment variable `NO_GCE_CHECK=true`
   - Customize the GCE metadata server address by setting the environment variable `GCE_METADATA_HOST=<hostname>`

### Explicit Credential Loading

To get Credentials from a Service Account JSON key use `GoogleCredentials.fromStream(InputStream)`
or `GoogleCredentials.fromStream(InputStream, HttpTransportFactory)`. Note that the credentials must
be refreshed before the access token is available.

```java
GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("/path/to/credentials.json"));
credentials.refreshIfExpired();
AccessToken token = credentials.getAccessToken();
// OR
AccessToken token = credentials.refreshAccessToken();
```

### ImpersonatedCredentials

Allows a credentials issued to a user or service account to
impersonate another.  The source project using ImpersonatedCredentials must enable the
"IAMCredentials" API.  Also, the target service account must grant the orginating principal
the "Service Account Token Creator" IAM role.

```java
String credPath = "/path/to/svc_account.json";
ServiceAccountCredentials sourceCredentials = ServiceAccountCredentials
     .fromStream(new FileInputStream(credPath));
sourceCredentials = (ServiceAccountCredentials) sourceCredentials
    .createScoped(Arrays.asList("https://www.googleapis.com/auth/iam"));

ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
    "impersonated-account@project.iam.gserviceaccount.com", null,
    Arrays.asList("https://www.googleapis.com/auth/devstorage.read_only"), 300);

Storage storage_service = StorageOptions.newBuilder().setProjectId("project-id")
    .setCredentials(targetCredentials).build().getService();

for (Bucket b : storage_service.list().iterateAll())
    System.out.println(b); 
```

## Configuring a Proxy

For HTTP clients, a basic proxy can be configured by using `http.proxyHost` and related system properties as documented
by [Java Networking and Proxies](https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html).

For a more custom proxy (e.g. for an authenticated proxy), provide a custom 
[`HttpTransportFactory`][http-transport-factory] to [`GoogleCredentials`][google-credentials]:

```java
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentials;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;

import java.io.IOException;

public class ProxyExample {
  public GoogleCredentials getCredentials() throws IOException {
    HttpTransportFactory httpTransportFactory = getHttpTransportFactory(
        "some-host", 8080, "some-username", "some-password"
    );

    return GoogleCredentials.getApplicationDefault(httpTransportFactory);
  }

  public HttpTransportFactory getHttpTransportFactory(String proxyHost, int proxyPort, String proxyUsername, String proxyPassword) {
    HttpHost proxyHostDetails = new HttpHost(proxyHost, proxyPort);
    HttpRoutePlanner httpRoutePlanner = new DefaultProxyRoutePlanner(proxyHostDetails);

    CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    credentialsProvider.setCredentials(
        new AuthScope(proxyHostDetails.getHostName(), proxyHostDetails.getPort()),
        new UsernamePasswordCredentials(proxyUsername, proxyPassword)
    );

    HttpClient httpClient = ApacheHttpTransport.newDefaultHttpClientBuilder()
        .setRoutePlanner(httpRoutePlanner)
        .setProxyAuthenticationStrategy(ProxyAuthenticationStrategy.INSTANCE)
        .setDefaultCredentialsProvider(credentialsProvider)
        .build();

    final HttpTransport httpTransport = new ApacheHttpTransport(httpClient);
    return new HttpTransportFactory() {
      @Override
      public HttpTransport create() {
        return httpTransport;
      }
    };
  }
}
```

The above example requires `com.google.http-client:google-http-client-apache-v2`.

## Using Credentials with `google-http-client`

Credentials provided by `google-auth-library` can be used with Google's 
[HTTP-based clients][apiary-clients]. We provide a 
[`HttpCredentialsAdapter`][http-credentials-adapter] which can be used as an 
[`HttpRequestInitializer`][http-request-initializer].

```java
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.services.bigquery.Bigquery;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();
HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);

Bigquery bq = new Bigquery.Builder(HTTP_TRANSPORT, JSON_FACTORY, requestInitializer)
    .setApplicationName(APPLICATION_NAME)
    .build();
```

## Verifying JWT Tokens (Beta)

To verify a JWT token, use the [`TokenVerifier`][token-verifier] class.

### Verifying a Signature

To verify a signature, use the default [`TokenVerifier`][token-verifier]:

```java
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.oauth2.TokenVerifier;

TokenVerifier tokenVerifier = TokenVerifier.newBuilder().build();
try {
  JsonWebSignature jsonWebSignature = tokenVerifier.verify(tokenString);
  // optionally verify additional claims
  if (!"expected-value".equals(jsonWebSignature.getPayload().get("additional-claim"))) {
    // handle custom verification error
  }
} catch (TokenVerifier.VerificationException e) {
  // invalid token
}
```

### Customizing the TokenVerifier

To customize a [`TokenVerifier`][token-verifier], instantiate it via its builder:

```java
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.oauth2.TokenVerifier;

TokenVerifier tokenVerifier = TokenVerifier.newBuilder()
  .setAudience("audience-to-verify")
  .setIssuer("issuer-to-verify")
  .build();
try {
  JsonWebSignature jsonWebSignature = tokenVerifier.verify(tokenString);
  // optionally verify additional claims
  if (!"expected-value".equals(jsonWebSignature.getPayload().get("additional-claim"))) {
    // handle custom verification error
  }
} catch (TokenVerifier.VerificationException e) {
  // invalid token
}
```

For more options, see the [`TokenVerifier.Builder`][token-verifier-builder] documentation.

## CI Status

Java Version | Status
------------ | ------
Java 7 | [![Kokoro CI](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java7.svg)](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java7.html)
Java 8 | [![Kokoro CI](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java8.svg)](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java8.html)
Java 8 OSX | [![Kokoro CI](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java8-osx.svg)](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java8-osx.html)
Java 8 Windows | [![Kokoro CI](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java8-win.svg)](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java8-win.html)
Java 11 | [![Kokoro CI](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java11.svg)](http://storage.googleapis.com/cloud-devrel-public/java/badges/google-auth-library-java/java11.html)

## Contributing

Contributions to this library are always welcome and highly encouraged.

See [CONTRIBUTING](CONTRIBUTING.md) documentation for more information on how to get started.

Please note that this project is released with a Contributor Code of Conduct. By participating in
this project you agree to abide by its terms. See [Code of Conduct](CODE_OF_CONDUCT.md) for more
information.

## Running the Tests

To run the tests you will need:

* Maven 3+

```bash
$ mvn test
```

## License

BSD 3-Clause - See [LICENSE](LICENSE) for more information.

[appengine-sdk-versions]: https://search.maven.org/search?q=g:com.google.appengine%20AND%20a:appengine-api-1.0-sdk&core=gav
[appengine-sdk-install]: https://github.com/googleapis/google-auth-library-java/blob/master/README.md#google-auth-library-appengine
[appengine-app-identity-service]: https://cloud.google.com/appengine/docs/java/javadoc/com/google/appengine/api/appidentity/AppIdentityService
[apiary-clients]: https://search.maven.org/search?q=g:com.google.apis
[http-credentials-adapter]: https://googleapis.dev/java/google-auth-library/latest/index.html?com/google/auth/http/HttpCredentialsAdapter.html
[http-request-initializer]: https://googleapis.dev/java/google-http-client/latest/index.html?com/google/api/client/http/HttpRequestInitializer.html
[token-verifier]: https://googleapis.dev/java/google-auth-library/latest/index.html?com/google/auth/oauth2/TokenVerifier.html
[token-verifier-builder]: https://googleapis.dev/java/google-auth-library/latest/index.html?com/google/auth/oauth2/TokenVerifier.Builder.html
[http-transport-factory]: https://googleapis.dev/java/google-auth-library/latest/index.html?com/google/auth/http/HttpTransportFactory.html
[google-credentials]: https://googleapis.dev/java/google-auth-library/latest/index.html?com/google/auth/oauth2/GoogleCredentials.html
