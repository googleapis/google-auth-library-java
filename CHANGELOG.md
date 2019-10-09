# Changelog

### [0.18.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.17.2...v0.18.0) (2019-10-09)


### Bug Fixes

* make JwtClaims.newBuilder() public ([#350](https://www.github.com/googleapis/google-auth-library-java/issues/350)) ([6ab8758](https://www.github.com/googleapis/google-auth-library-java/commit/6ab8758))
* move autovalue into annotation processor path instead of classpath ([#358](https://www.github.com/googleapis/google-auth-library-java/issues/358)) ([a82d348](https://www.github.com/googleapis/google-auth-library-java/commit/a82d348))


### Dependencies

* update Guava to 28.1 ([#353](https://www.github.com/googleapis/google-auth-library-java/issues/353)) ([f4f05be](https://www.github.com/googleapis/google-auth-library-java/commit/f4f05be))


### Documentation

* fix include instructions in google-auth-library-bom README ([#352](https://www.github.com/googleapis/google-auth-library-java/issues/352)) ([f649735](https://www.github.com/googleapis/google-auth-library-java/commit/f649735))

### [0.17.4](https://www.github.com/googleapis/google-auth-library-java/compare/v0.18.0...v0.17.4) (2019-10-08)


### Bug Fixes

* make JwtClaims.newBuilder() public ([#350](https://www.github.com/googleapis/google-auth-library-java/issues/350)) ([6ab8758](https://www.github.com/googleapis/google-auth-library-java/commit/6ab8758))
* move autovalue into annotation processor path instead of classpath ([#358](https://www.github.com/googleapis/google-auth-library-java/issues/358)) ([a82d348](https://www.github.com/googleapis/google-auth-library-java/commit/a82d348))


### Dependencies

* update Guava to 28.1 ([#353](https://www.github.com/googleapis/google-auth-library-java/issues/353)) ([f4f05be](https://www.github.com/googleapis/google-auth-library-java/commit/f4f05be))


### Documentation

* fix include instructions in google-auth-library-bom README ([#352](https://www.github.com/googleapis/google-auth-library-java/issues/352)) ([f649735](https://www.github.com/googleapis/google-auth-library-java/commit/f649735))

### [0.17.2](https://www.github.com/googleapis/google-auth-library-java/compare/v0.17.1...v0.17.2) (2019-09-24)


### Bug Fixes

* typo in BOM dependency ([#345](https://www.github.com/googleapis/google-auth-library-java/issues/345)) ([a1d63bb](https://www.github.com/googleapis/google-auth-library-java/commit/a1d63bb))

### [0.17.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.17.0...v0.17.1) (2019-08-22)


### Bug Fixes

* allow unset/null privateKeyId for JwtCredentials ([#336](https://www.github.com/googleapis/google-auth-library-java/issues/336)) ([d28a6ed](https://www.github.com/googleapis/google-auth-library-java/commit/d28a6ed))

## [0.17.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.16.2...v0.17.0) (2019-08-16)


### Bug Fixes

* cleanup unused code and deprecation warnings ([#315](https://www.github.com/googleapis/google-auth-library-java/issues/315)) ([7fd94c0](https://www.github.com/googleapis/google-auth-library-java/commit/7fd94c0))
* Fix declared dependencies from merge issue ([#291](https://www.github.com/googleapis/google-auth-library-java/issues/291)) ([35abf13](https://www.github.com/googleapis/google-auth-library-java/commit/35abf13))
* throw SigningException as documented ([#316](https://www.github.com/googleapis/google-auth-library-java/issues/316)) ([a1ab97c](https://www.github.com/googleapis/google-auth-library-java/commit/a1ab97c))
* typo in ComputeEngineCredentials exception message ([#313](https://www.github.com/googleapis/google-auth-library-java/issues/313)) ([1a16f38](https://www.github.com/googleapis/google-auth-library-java/commit/1a16f38))


### Features

* add Automatic-Module-Name to manifest ([#326](https://www.github.com/googleapis/google-auth-library-java/issues/326)) ([29f58b4](https://www.github.com/googleapis/google-auth-library-java/commit/29f58b4)), closes [#324](https://www.github.com/googleapis/google-auth-library-java/issues/324) [#324](https://www.github.com/googleapis/google-auth-library-java/issues/324)
* add IDTokenCredential support ([#303](https://www.github.com/googleapis/google-auth-library-java/issues/303)) ([a87e3fd](https://www.github.com/googleapis/google-auth-library-java/commit/a87e3fd))
* add JwtCredentials with custom claims ([#290](https://www.github.com/googleapis/google-auth-library-java/issues/290)) ([3f37172](https://www.github.com/googleapis/google-auth-library-java/commit/3f37172))
* allow arbitrary additional claims for JwtClaims ([#331](https://www.github.com/googleapis/google-auth-library-java/issues/331)) ([888c61c](https://www.github.com/googleapis/google-auth-library-java/commit/888c61c))
* Implement ServiceAccountSigner for ImpersonatedCredentials ([#279](https://www.github.com/googleapis/google-auth-library-java/issues/279)) ([70767e3](https://www.github.com/googleapis/google-auth-library-java/commit/70767e3))


### Reverts

* "build: run in debug mode ([#319](https://www.github.com/googleapis/google-auth-library-java/issues/319))" ([#320](https://www.github.com/googleapis/google-auth-library-java/issues/320)) ([de79e14](https://www.github.com/googleapis/google-auth-library-java/commit/de79e14))

## [0.16.2](https://www.github.com/googleapis/google-auth-library-java/compare/v0.16.1...v0.16.2) (2019-06-26)


### Bug Fixes

* Add metadata-flavor header to metadata server ping for compute engine ([#283](https://github.com/googleapis/google-auth-library-java/pull/283))


### Dependencies

* Import http client bom for dependency management ([#268](https://github.com/googleapis/google-auth-library-java/pull/268))


### Documentation

* README section for interop with google-http-client ([#275](https://github.com/googleapis/google-auth-library-java/pull/275))


## [0.16.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.16.0...v0.16.1) (2019-06-06)


### Dependencies

* Update dependency com.google.http-client:google-http-client to v1.30.1 ([#265](https://github.com/googleapis/google-auth-library-java/pull/265))


## [0.16.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.15.0...v0.16.0) (2019-06-04)


### Features

* Add google-auth-library-bom artifact ([#256](https://github.com/googleapis/google-auth-library-java/pull/256))


### Dependencies

* Update dependency com.google.http-client:google-http-client to v1.30.0 ([#261](https://github.com/googleapis/google-auth-library-java/pull/261))
* Update dependency com.google.http-client:google-http-client to v1.29.2 ([#259](https://github.com/googleapis/google-auth-library-java/pull/259))
* Update dependency org.sonatype.plugins:nexus-staging-maven-plugin to v1.6.8 ([#257](https://github.com/googleapis/google-auth-library-java/pull/257))
* Update to latest app engine SDK version ([#258](https://github.com/googleapis/google-auth-library-java/pull/258))
* Update dependency org.apache.maven.plugins:maven-source-plugin to v3.1.0 ([#254](https://github.com/googleapis/google-auth-library-java/pull/254))
* Update dependency org.jacoco:jacoco-maven-plugin to v0.8.4 ([#255](https://github.com/googleapis/google-auth-library-java/pull/255))
* Update dependency org.apache.maven.plugins:maven-jar-plugin to v3.1.2 ([#252](https://github.com/googleapis/google-auth-library-java/pull/252))
* Update dependency org.apache.maven.plugins:maven-source-plugin to v2.4 ([#253](https://github.com/googleapis/google-auth-library-java/pull/253))


### Documentation

* Javadoc publish kokoro job uses docpublisher ([#243](https://github.com/googleapis/google-auth-library-java/pull/243))


## [0.15.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.14.0...v0.15.0) (2019-03-27)


### Bug Fixes

* createScoped: make overload call implementation ([#229](https://github.com/googleapis/google-auth-library-java/pull/229))


### Reverts

* Add back in deprecated methods in ServiceAccountJwtAccessCredentials ([#238](https://github.com/googleapis/google-auth-library-java/pull/238))


## [0.14.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.13.0...v0.14.0) (2019-03-26)


### Bug Fixes

* update default metadata url ([#230](https://github.com/googleapis/google-auth-library-java/pull/230))
* Remove deprecated methods ([#190](https://github.com/googleapis/google-auth-library-java/pull/190))
* Update Sign Blob API ([#232](https://github.com/googleapis/google-auth-library-java/pull/232))


### Dependencies

* Upgrade http client to 1.29.0. ([#235](https://github.com/googleapis/google-auth-library-java/pull/235))
* update deps ([#234](https://github.com/googleapis/google-auth-library-java/pull/234))


## [0.13.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.12.0...v0.13.0) (2019-01-17)


### Bug Fixes

* Use OutputStream directly instead of PrintWriter ([#220](https://github.com/googleapis/google-auth-library-java/pull/220))
* Improve log output when detecting GCE ([#214](https://github.com/googleapis/google-auth-library-java/pull/214))


### Features

* Overload GoogleCredentials.createScoped with variadic arguments ([#218](https://github.com/googleapis/google-auth-library-java/pull/218))


### Dependencies

* Update google-http-client version, guava, and maven surefire plugin ([#221](https://github.com/googleapis/google-auth-library-java/pull/221))


## [0.12.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.11.0...v0.12.0) (2018-12-19)


### Bug Fixes

* Show error message in case of problems with getting access token ([#206](https://github.com/googleapis/google-auth-library-java/pull/206))
* Add note about `NO_GCE_CHECK` to metadata 404 error message ([#205](https://github.com/googleapis/google-auth-library-java/pull/205))


### Features

* Add ImpersonatedCredentials ([#211](https://github.com/googleapis/google-auth-library-java/pull/211))
* Add option to suppress end user credentials warning. ([#207](https://github.com/googleapis/google-auth-library-java/pull/207))


### Dependencies

* Update google-http-java-client dependency to 1.27.0 ([#208](https://github.com/googleapis/google-auth-library-java/pull/208))


### Documentation

* README grammar fix ([#192](https://github.com/googleapis/google-auth-library-java/pull/192))
* Add unstable badge to README ([#184](https://github.com/googleapis/google-auth-library-java/pull/184))
* Update README with instructions on installing the App Engine SDK and running the tests ([#209](https://github.com/googleapis/google-auth-library-java/pull/209))


## [0.11.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.10.0...v0.11.0) (2018-08-23)


### Bug Fixes

* Update auth token urls (#174)


### Dependencies

* Update dependencies (guava) (#170)
* Bumping google-http-client version to 1.24.1 (#171)


### Documentation

* Documentation for ComputeEngineCredential signing. (#176)
* Fix README link (#169)


## [0.10.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.9.1...v0.10.0) (2018-06-12)


### Bug Fixes

* Read token_uri from service account JSON (#160)
* Log warning if default credentials uses a user token from gcloud sdk (#166)


### Features

* Add OAuth2Credentials#refreshIfExpired() (#163)
* ComputeEngineCredentials implements ServiceAccountSigner (#141)


### Documentation

* Versionless Javadocs (#164)
* Fix documentation for `getAccessToken()` returning cached value (#162)


## [0.9.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.9.0...v0.9.1) (2018-04-09)


### Features

* Add caching for JWT tokens (#151)


## [0.9.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.8.0...v0.9.0) (2017-11-02)


### Bug Fixes

* Fix NPE deserializing ServiceAccountCredentials (#132)


### Features

* Surface cleanup (#136)
* Providing a method to remove CredentialsChangedListeners (#130)
* Implemented in-memory TokenStore and added opportunity to save user credentials into file (#129)


### Documentation

* Fixes comment typos. (#131)


## [0.8.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.7.1...v0.8.0) (2017-09-08)


### Bug Fixes

* Extracting the project_id field from service account JSON files (#118)
* Fixing an Integer Overflow Issue (#121)
* use metadata server to get credentials for GAE 8 standard environment (#122)


### Features

* Switch OAuth2 HTTP surface to use builder pattern (#123)
* Add builder pattern to AppEngine credentials (#125)


### Documentation

* Fix API Documentation link rendering (#112)


## [0.7.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.7.0...v0.7.1) (2017-07-14)


### Bug Fixes

* Mitigate occasional failures in looking up Application Default Credentials on a Google Compute Engine (GCE) Virtual Machine (#110)


## [0.7.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.6.1...v0.7.0) (2017-06-06)


### Bug Fixes

* Retry HTTP errors in `ServiceAccountCredentials.refreshAccessToken()` to avoid propagating failures (#100 addresses #91)


### Features

* Add `GoogleCredentials.createDelegated()` method to allow using domain-wide delegation with service accounts (#102)
* Allow bypassing App Engine credential check using environment variable, to allow Application Default Credentials to detect GCE when running on GAE Flex (#103)
