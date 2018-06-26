# Google Auth Library


Open source authentication client library for Java.

[![Build Status](https://travis-ci.org/google/google-auth-library-java.svg?branch=master)](https://travis-ci.org/google/google-auth-library-java.svg)
[![Maven](https://img.shields.io/maven-central/v/com.google.auth/google-auth-library-credentials.svg)](https://img.shields.io/maven-central/v/com.google.auth/google-auth-library-credentials.svg)

-  [API Documentation] (https://google.github.io/google-auth-library-java/releases/latest/apidocs)

This project consists of 3 artifacts:

-  [*google-auth-library-credentials*](#google-auth-library-credentials): contains base classes and
interfaces for Google credentials
-  [*google-auth-library-appengine*](#google-auth-library-appengine): contains App Engine
credentials. This artifacts depends on the App Engine SDK
-  [*google-auth-library-oauth2-http*](#google-auth-library-oauth2-http): contains a wide variety of
credentials as well as utility methods to create them and to get Application Default Credentials

> Note: This client is a work-in-progress, and may occasionally
> make backwards-incompatible changes.

## Quickstart

If you are using Maven, add this to your pom.xml file (notice that you can replace
`google-auth-library-oauth2-http` with any of `google-auth-library-credentials` and
`google-auth-library-appengine`, depending on your application needs):
```xml
<dependency>
  <groupId>com.google.auth</groupId>
  <artifactId>google-auth-library-oauth2-http</artifactId>
  <version>0.9.1</version>
</dependency>
```
If you are using Gradle, add this to your dependencies
```Groovy
compile 'com.google.auth:google-auth-library-oauth2-http:0.9.1'
```
If you are using SBT, add this to your dependencies
```Scala
libraryDependencies += "com.google.auth" % "google-auth-library-oauth2-http" % "0.9.1"
```

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
applications running on App Engine. The `AppEngineCredentials` class allows to authorize your App
Engine application given an instance of [AppIdentityService](https://cloud.google.com/appengine/docs/java/javadoc/com/google/appengine/api/appidentity/AppIdentityService).

## google-auth-library-oauth2-http

### Application Default Credentials

This artifact contains a wide variety of credentials as well as utility methods to create them and
to get Application Default Credentials.
Credentials classes contained in this artifact are:
- `CloudShellCredentials`: credentials for Google Cloud Shell built-in service account
- `CloudShellCredentials`: credentials for Google Compute Engine built-in service account
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

## Contributing

Contributions to this library are always welcome and highly encouraged.

See [CONTRIBUTING](CONTRIBUTING.md) documentation for more information on how to get started.

Please note that this project is released with a Contributor Code of Conduct. By participating in
this project you agree to abide by its terms. See [Code of Conduct](CODE_OF_CONDUCT.md) for more
information.

## License

BSD 3-Clause - See [LICENSE](LICENSE) for more information.
