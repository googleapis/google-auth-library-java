# Changelog

## [1.7.0](https://github.com/googleapis/google-auth-library-java/compare/v1.6.0...v1.7.0) (2022-05-12)


### Features

* Add ability to provide PrivateKey as Pkcs8 encoded string [#883](https://github.com/googleapis/google-auth-library-java/issues/883) ([#889](https://github.com/googleapis/google-auth-library-java/issues/889)) ([e0d6996](https://github.com/googleapis/google-auth-library-java/commit/e0d6996ac0db1bf75d92e5aba3eaab512affafe4))
* Add iam endpoint override to ImpersonatedCredentials ([#910](https://github.com/googleapis/google-auth-library-java/issues/910)) ([97bfc4c](https://github.com/googleapis/google-auth-library-java/commit/97bfc4c8ceb199e775784ac3ed4fa992d4d2dcbf))


### Bug Fixes

* update branding in ExternalAccountCredentials ([#893](https://github.com/googleapis/google-auth-library-java/issues/893)) ([0200dbb](https://github.com/googleapis/google-auth-library-java/commit/0200dbb05cff06a333879cf99bac64adaada3239))

## [1.6.0](https://github.com/googleapis/google-auth-library-java/compare/v1.5.3...v1.6.0) (2022-03-15)


### Features

* Add AWS Session Token to Metadata Requests ([#850](https://github.com/googleapis/google-auth-library-java/issues/850)) ([577e9a5](https://github.com/googleapis/google-auth-library-java/commit/577e9a52204b0d6026a302bb7efe2c6162d57945))


### Bug Fixes

* ImmutableSet converted to List for Impersonated Credentials ([#732](https://github.com/googleapis/google-auth-library-java/issues/732)) ([7dcd549](https://github.com/googleapis/google-auth-library-java/commit/7dcd549c4ef0617e657315b7a718368fbd162997))
* update library docs ([#868](https://github.com/googleapis/google-auth-library-java/issues/868)) ([a081015](https://github.com/googleapis/google-auth-library-java/commit/a081015cb72ade91c022b58261c8d253e46a7793))

### [1.5.3](https://github.com/googleapis/google-auth-library-java/compare/v1.5.2...v1.5.3) (2022-02-24)


### Bug Fixes

* **ci:** downgrade nexus-staging-maven-plugin to 1.6.8 ([#874](https://github.com/googleapis/google-auth-library-java/issues/874)) ([fc331d4](https://github.com/googleapis/google-auth-library-java/commit/fc331d466286d99cb3c6aa8977d34fd5f224eff7))

### [1.5.2](https://github.com/googleapis/google-auth-library-java/compare/v1.5.1...v1.5.2) (2022-02-24)


### Bug Fixes

* downgrading nexus staging plugin 1.6.8 ([#871](https://github.com/googleapis/google-auth-library-java/issues/871)) ([e87224c](https://github.com/googleapis/google-auth-library-java/commit/e87224cca10d5d24523a5c3ac1e829fd51089f0c))

### [1.5.1](https://github.com/googleapis/google-auth-library-java/compare/v1.5.0...v1.5.1) (2022-02-22)


### Bug Fixes

* **deps:** update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.3.2 ([#852](https://github.com/googleapis/google-auth-library-java/issues/852)) ([aa557c7](https://github.com/googleapis/google-auth-library-java/commit/aa557c7545941d712339b4b62a413997a54bcccc))

## [1.5.0](https://github.com/googleapis/google-auth-library-java/compare/v1.4.0...v1.5.0) (2022-02-14)


### Features

* update retries and implement Retryable ([#750](https://github.com/googleapis/google-auth-library-java/issues/750)) ([f9a9b8a](https://github.com/googleapis/google-auth-library-java/commit/f9a9b8ace0199e6b75ed42c7bacfa3be30c34111))


### Dependencies

* **java:** update actions/github-script action to v5 ([#1339](https://github.com/googleapis/google-auth-library-java/issues/1339)) ([#843](https://github.com/googleapis/google-auth-library-java/issues/843)) ([ce44591](https://github.com/googleapis/google-auth-library-java/commit/ce445910198e7b78c9500ab148a1b6b99268185e))

## [1.4.0](https://github.com/googleapis/google-auth-library-java/compare/v1.3.0...v1.4.0) (2022-01-19)


### Features

* setting the audience to always point to google token endpoint ([#833](https://github.com/googleapis/google-auth-library-java/issues/833)) ([33bfe7a](https://github.com/googleapis/google-auth-library-java/commit/33bfe7a788a524324cd9b0a54acc8917f6b75556))


### Bug Fixes

* (WIF) remove erroneous check for the subject token field name for text credential source ([#822](https://github.com/googleapis/google-auth-library-java/issues/822)) ([6d35c68](https://github.com/googleapis/google-auth-library-java/commit/6d35c681cf397ff2a90363184e26ee5850294c41))
* **java:** add -ntp flag to native image testing command ([#1299](https://github.com/googleapis/google-auth-library-java/issues/1299)) ([#807](https://github.com/googleapis/google-auth-library-java/issues/807)) ([aa6654a](https://github.com/googleapis/google-auth-library-java/commit/aa6654a639ea15bcce7c7a6e86f170b1345895f0))
* **java:** run Maven in plain console-friendly mode ([#1301](https://github.com/googleapis/google-auth-library-java/issues/1301)) ([#818](https://github.com/googleapis/google-auth-library-java/issues/818)) ([4df45d0](https://github.com/googleapis/google-auth-library-java/commit/4df45d0d03a973f1beff43d8965c26289f217f22))

## [1.3.0](https://www.github.com/googleapis/google-auth-library-java/compare/v1.2.2...v1.3.0) (2021-11-10)


### Features

* next release from main branch is 1.3.0 ([#780](https://www.github.com/googleapis/google-auth-library-java/issues/780)) ([1149581](https://www.github.com/googleapis/google-auth-library-java/commit/1149581e63267e3553c74ba2114d849c5b24f27b))


### Bug Fixes

* **java:** java 17 dependency arguments ([#1266](https://www.github.com/googleapis/google-auth-library-java/issues/1266)) ([#779](https://www.github.com/googleapis/google-auth-library-java/issues/779)) ([9160a53](https://www.github.com/googleapis/google-auth-library-java/commit/9160a53e6507c1c938795e181c65ad80db1bcf11))
* service account impersonation with workforce credentials ([#770](https://www.github.com/googleapis/google-auth-library-java/issues/770)) ([6449ef0](https://www.github.com/googleapis/google-auth-library-java/commit/6449ef0922053121a6732933ab9e246965fde3b7))

### [1.2.2](https://www.github.com/googleapis/google-auth-library-java/compare/v1.2.1...v1.2.2) (2021-10-20)


### Bug Fixes

* environment variable is "AWS_SESSION_TOKEN" and not "Token" ([#772](https://www.github.com/googleapis/google-auth-library-java/issues/772)) ([c8c3073](https://www.github.com/googleapis/google-auth-library-java/commit/c8c3073790ca2f660eabd2c410b0e295f693040b))

### [1.2.1](https://www.github.com/googleapis/google-auth-library-java/compare/v1.2.0...v1.2.1) (2021-10-11)


### Bug Fixes

* disabling self-signed jwt for domain wide delegation ([#754](https://www.github.com/googleapis/google-auth-library-java/issues/754)) ([ac70a27](https://www.github.com/googleapis/google-auth-library-java/commit/ac70a279bdaf681507d7815264a3f5e92fd2aaa6))

## [1.2.0](https://www.github.com/googleapis/google-auth-library-java/compare/v1.1.0...v1.2.0) (2021-09-30)


### Features

* add support for Workforce Pools ([#729](https://www.github.com/googleapis/google-auth-library-java/issues/729)) ([5f3fed7](https://www.github.com/googleapis/google-auth-library-java/commit/5f3fed79e22f3c2d585c5b03c01791b0f8109929))


### Bug Fixes

* allow empty workforce_pool_user_project ([#752](https://www.github.com/googleapis/google-auth-library-java/issues/752)) ([e1cbce1](https://www.github.com/googleapis/google-auth-library-java/commit/e1cbce1a5cb269c6613bc6d40f06145bd45099c0))
* timing of stale token refreshes on ComputeEngine ([#749](https://www.github.com/googleapis/google-auth-library-java/issues/749)) ([c813d55](https://www.github.com/googleapis/google-auth-library-java/commit/c813d55a78053ecbec1a9640e6c9814da87319eb))
* workforce audience ([#741](https://www.github.com/googleapis/google-auth-library-java/issues/741)) ([a08cacc](https://www.github.com/googleapis/google-auth-library-java/commit/a08cacc7990b9058c8f1af3f9d8d816119562cc4))

## [1.1.0](https://www.github.com/googleapis/google-auth-library-java/compare/v1.0.0...v1.1.0) (2021-08-17)


### Features

* downscoping with credential access boundaries ([#702](https://www.github.com/googleapis/google-auth-library-java/issues/702)) ([aa7ede1](https://www.github.com/googleapis/google-auth-library-java/commit/aa7ede1d1c688ba437798f4204820c0506d5d969))


### Bug Fixes

* add validation for the token URL and service account impersonation URL for Workload Identity Federation ([#717](https://www.github.com/googleapis/google-auth-library-java/issues/717)) ([23cb8ef](https://www.github.com/googleapis/google-auth-library-java/commit/23cb8ef778d012bbd452c1dfdac5f096d1af6c95))


### Documentation

* updates README for downscoping with CAB ([#716](https://www.github.com/googleapis/google-auth-library-java/issues/716)) ([68bceba](https://www.github.com/googleapis/google-auth-library-java/commit/68bceba21c05870f6eb616cc057ddf0521c581b8))

## [1.0.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.27.0...v1.0.0) (2021-07-28)


### ⚠ BREAKING CHANGES

* updating google-auth-library-java min Java version to 1.8

### Features

* GA release of google-auth-library-java (ver 1.0.0) ([#704](https://www.github.com/googleapis/google-auth-library-java/issues/704)) ([3d9874f](https://www.github.com/googleapis/google-auth-library-java/commit/3d9874f1c91dfa10d6f72d41e922b3f1ec654943))
* updating google-auth-library-java min Java version to 1.8 ([3d9874f](https://www.github.com/googleapis/google-auth-library-java/commit/3d9874f1c91dfa10d6f72d41e922b3f1ec654943))


### Bug Fixes

* Add shopt -s nullglob to dependencies script ([#693](https://www.github.com/googleapis/google-auth-library-java/issues/693)) ([c5aa708](https://www.github.com/googleapis/google-auth-library-java/commit/c5aa7084d9ca817a53cf6bac14d442adeeaeb310))
* Update dependencies.sh to not break on mac ([c5aa708](https://www.github.com/googleapis/google-auth-library-java/commit/c5aa7084d9ca817a53cf6bac14d442adeeaeb310))

## [0.27.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.26.0...v0.27.0) (2021-07-14)


### Features

* add Id token support for UserCredentials ([#650](https://www.github.com/googleapis/google-auth-library-java/issues/650)) ([5a8f467](https://www.github.com/googleapis/google-auth-library-java/commit/5a8f4676630854c53aa708a9c8b960770067f858))
* add impersonation credentials to ADC  ([#613](https://www.github.com/googleapis/google-auth-library-java/issues/613)) ([b9823f7](https://www.github.com/googleapis/google-auth-library-java/commit/b9823f70d7f3f7461b7de40bee06f5e7ba0e797c))
* Adding functional tests for Service Account  ([#685](https://www.github.com/googleapis/google-auth-library-java/issues/685)) ([dfe118c](https://www.github.com/googleapis/google-auth-library-java/commit/dfe118c261aadf137a3cf47a7acb9892c7a6db4d))
* allow scopes for self signed jwt ([#689](https://www.github.com/googleapis/google-auth-library-java/issues/689)) ([f4980c7](https://www.github.com/googleapis/google-auth-library-java/commit/f4980c77566bbd5ef4c532acb199d7d484dbcd01))

## [0.26.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.25.5...v0.26.0) (2021-05-20)


### Features

* add `gcf-owl-bot[bot]` to `ignoreAuthors` ([#674](https://www.github.com/googleapis/google-auth-library-java/issues/674)) ([359b20f](https://www.github.com/googleapis/google-auth-library-java/commit/359b20f24f88e09b6b104c61ca63a1b604ea64d2))
* added getter for credentials object in HttpCredentialsAdapter ([#658](https://www.github.com/googleapis/google-auth-library-java/issues/658)) ([5a946ea](https://www.github.com/googleapis/google-auth-library-java/commit/5a946ea5e0d974611f2205f468236db4b931e486))
* enable pre-emptive async oauth token refreshes ([#646](https://www.github.com/googleapis/google-auth-library-java/issues/646)) ([e3f4c7e](https://www.github.com/googleapis/google-auth-library-java/commit/e3f4c7eac0417705553ef8259599ec29fc8ad9b4))
* Returning an issuer claim on request errors ([#656](https://www.github.com/googleapis/google-auth-library-java/issues/656)) ([95d70ae](https://www.github.com/googleapis/google-auth-library-java/commit/95d70ae0f5f4c985455f913ddef14ebe75500656))


### Bug Fixes

* use orginal url as audience for self signed jwt if scheme or host is null ([#642](https://www.github.com/googleapis/google-auth-library-java/issues/642)) ([b4e6f1a](https://www.github.com/googleapis/google-auth-library-java/commit/b4e6f1a0bd17dd31edc85ed4879cea75857fd747))

### [0.25.5](https://www.github.com/googleapis/google-auth-library-java/compare/v0.25.4...v0.25.5) (2021-04-22)


### Dependencies

* update autovalue to 1.8.1 ([#638](https://www.github.com/googleapis/google-auth-library-java/issues/638)) ([62cd356](https://www.github.com/googleapis/google-auth-library-java/commit/62cd3564a93abe3cbbe083ac9b7aaebe4608b4bd))

### [0.25.4](https://www.github.com/googleapis/google-auth-library-java/compare/v0.25.3...v0.25.4) (2021-04-15)


### Bug Fixes

* release scripts from issuing overlapping phases ([#634](https://www.github.com/googleapis/google-auth-library-java/issues/634)) ([b8d851e](https://www.github.com/googleapis/google-auth-library-java/commit/b8d851e1ac97b71e986c9afccca42021be3f9dd1))
* typo ([#632](https://www.github.com/googleapis/google-auth-library-java/issues/632)) ([d860608](https://www.github.com/googleapis/google-auth-library-java/commit/d8606083b6632e26463aac0a0d1e92835d2fbcd0))

### [0.25.3](https://www.github.com/googleapis/google-auth-library-java/compare/v0.25.2...v0.25.3) (2021-04-12)


### Dependencies

* update guava patch ([#628](https://www.github.com/googleapis/google-auth-library-java/issues/628)) ([8ff3207](https://www.github.com/googleapis/google-auth-library-java/commit/8ff320755e44f937590196bcbefa8c9537244af6))

### [0.25.2](https://www.github.com/googleapis/google-auth-library-java/compare/v0.25.1...v0.25.2) (2021-03-18)


### Bug Fixes

* follow up fix service account credentials createScopedRequired ([#605](https://www.github.com/googleapis/google-auth-library-java/issues/605)) ([7ddac43](https://www.github.com/googleapis/google-auth-library-java/commit/7ddac43c418bb8b0cc3fd8d4f9d8752ad65bd842))
* support AWS_DEFAULT_REGION env var ([#599](https://www.github.com/googleapis/google-auth-library-java/issues/599)) ([3d066ee](https://www.github.com/googleapis/google-auth-library-java/commit/3d066ee4755c20e2bd44b234dff71df1c4815aec))

### [0.25.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.25.0...v0.25.1) (2021-03-18)


### Bug Fixes

* fix service account credentials createScopedRequired ([#601](https://www.github.com/googleapis/google-auth-library-java/issues/601)) ([0614482](https://www.github.com/googleapis/google-auth-library-java/commit/061448209da05ddfc75b40aae495c33d0ee7f1ee))

## [0.25.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.24.1...v0.25.0) (2021-03-16)


### Features

* add self signed jwt support ([#572](https://www.github.com/googleapis/google-auth-library-java/issues/572)) ([efe103a](https://www.github.com/googleapis/google-auth-library-java/commit/efe103a2e688ca915ec9925a72c49bb2a1b3c3b5))

### [0.24.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.24.0...v0.24.1) (2021-02-25)


### Dependencies

* update dependency com.google.http-client:google-http-client-bom to v1.39.0 ([#580](https://www.github.com/googleapis/google-auth-library-java/issues/580)) ([88718b0](https://www.github.com/googleapis/google-auth-library-java/commit/88718b0185ee6a3ff1168ac68621be0c5ff0efab))

## [0.24.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.23.0...v0.24.0) (2021-02-19)


### Features

* add workload identity federation support ([#547](https://www.github.com/googleapis/google-auth-library-java/issues/547)) ([b8dde1e](https://www.github.com/googleapis/google-auth-library-java/commit/b8dde1e43f86a0a00741790c12d73f6cbda6251d))


### Bug Fixes

* don't log downloads ([#576](https://www.github.com/googleapis/google-auth-library-java/issues/576)) ([6181030](https://www.github.com/googleapis/google-auth-library-java/commit/61810306dc0e18500a4a6b2704e00842fbecd879))


### Documentation

* add instructions for using workload identity federation ([#564](https://www.github.com/googleapis/google-auth-library-java/issues/564)) ([2142db3](https://www.github.com/googleapis/google-auth-library-java/commit/2142db314666f298071ae30a7419b00d48d87476))

## [0.23.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.22.2...v0.23.0) (2021-01-26)


### ⚠ BREAKING CHANGES

* privatize deprecated constructor (#473)

### Features

* allow custom lifespan for impersonated creds ([#515](https://www.github.com/googleapis/google-auth-library-java/issues/515)) ([0707ed4](https://www.github.com/googleapis/google-auth-library-java/commit/0707ed4bbb40fb775f196004ee30f8c695fe662b))
* allow custom scopes for compute engine creds ([#514](https://www.github.com/googleapis/google-auth-library-java/issues/514)) ([edc8d6e](https://www.github.com/googleapis/google-auth-library-java/commit/edc8d6e0e7ca2c6749d026ba42854a09c4879fd6))
* allow set lifetime for service account creds ([#516](https://www.github.com/googleapis/google-auth-library-java/issues/516)) ([427f2d5](https://www.github.com/googleapis/google-auth-library-java/commit/427f2d5610f0e8184a21b24531d2549a68c0b546))
* promote IdToken and JWT features ([#538](https://www.github.com/googleapis/google-auth-library-java/issues/538)) ([b514fe0](https://www.github.com/googleapis/google-auth-library-java/commit/b514fe0cebe5a294e0cf97b7b5349e6a523dc7b2))


### Bug Fixes

* per google style, logger is lower case ([#529](https://www.github.com/googleapis/google-auth-library-java/issues/529)) ([ecfc6a2](https://www.github.com/googleapis/google-auth-library-java/commit/ecfc6a2ea6060e06629b5d422b23b842b917f55e))
* privatize deprecated constructor ([#473](https://www.github.com/googleapis/google-auth-library-java/issues/473)) ([5804ff0](https://www.github.com/googleapis/google-auth-library-java/commit/5804ff03a531268831ac797ab262638a3119c14f))
* remove deprecated methods ([#537](https://www.github.com/googleapis/google-auth-library-java/issues/537)) ([427963e](https://www.github.com/googleapis/google-auth-library-java/commit/427963e04702d8b73eca5ed555539b11bbe97342))
* replace non-precondition use of Preconditions ([#539](https://www.github.com/googleapis/google-auth-library-java/issues/539)) ([f2ab4f1](https://www.github.com/googleapis/google-auth-library-java/commit/f2ab4f14262d54de0fde85494cfd92cf01a30cbe))
* switch to GSON ([#531](https://www.github.com/googleapis/google-auth-library-java/issues/531)) ([1b98d5c](https://www.github.com/googleapis/google-auth-library-java/commit/1b98d5c86fc5e56187c977e7f43c39bb62483d40))
* use default timeout if given 0 for ImpersonatedCredentials ([#527](https://www.github.com/googleapis/google-auth-library-java/issues/527)) ([ec74870](https://www.github.com/googleapis/google-auth-library-java/commit/ec74870c372a33d4157b45bb5d59ad7464fb2238))


### Dependencies

* update dependency com.google.appengine:appengine-api-1.0-sdk to v1.9.84 ([#422](https://www.github.com/googleapis/google-auth-library-java/issues/422)) ([b262c45](https://www.github.com/googleapis/google-auth-library-java/commit/b262c4587b058e6837429ee05f1b6a63620ee598))
* update dependency com.google.guava:guava to v30.1-android ([#522](https://www.github.com/googleapis/google-auth-library-java/issues/522)) ([4090d1c](https://www.github.com/googleapis/google-auth-library-java/commit/4090d1cb50041bceb1cd975d1a9249a412df936f))


### Documentation

* fix wording in jwtWithClaims Javadoc ([#536](https://www.github.com/googleapis/google-auth-library-java/issues/536)) ([af21727](https://www.github.com/googleapis/google-auth-library-java/commit/af21727815263fb5ffc07ede953cf042fac3ac2b))

### [0.22.2](https://www.github.com/googleapis/google-auth-library-java/compare/v0.22.1...v0.22.2) (2020-12-11)


### Bug Fixes

* quotaProjectId should be applied for cached `getRequestMetadata(URI, Executor, RequestMetadataCallback)` ([#509](https://www.github.com/googleapis/google-auth-library-java/issues/509)) ([0a8412f](https://www.github.com/googleapis/google-auth-library-java/commit/0a8412fcf9de4ac568b9f88618e44087dd31b144))

### [0.22.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.22.0...v0.22.1) (2020-11-05)


### Bug Fixes

* remove 1 hour limit for impersonated token ([#490](https://www.github.com/googleapis/google-auth-library-java/issues/490)) ([927e3d5](https://www.github.com/googleapis/google-auth-library-java/commit/927e3d5598e2d2b06512b27f4210994c65b26f59))


### Dependencies

* update dependency com.google.guava:guava to v30 ([#497](https://www.github.com/googleapis/google-auth-library-java/issues/497)) ([0551649](https://www.github.com/googleapis/google-auth-library-java/commit/055164969d175718ee8f2c0369b84bcddc1d7134))
* update dependency com.google.http-client:google-http-client-bom to v1.38.0 ([#503](https://www.github.com/googleapis/google-auth-library-java/issues/503)) ([46f20bc](https://www.github.com/googleapis/google-auth-library-java/commit/46f20bca8b5951ebea6a963b3affde2b92d403c7))

## [0.22.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.21.1...v0.22.0) (2020-10-13)


### Features

* add logging at FINE level for each step of ADC ([#435](https://www.github.com/googleapis/google-auth-library-java/issues/435)) ([7d145b2](https://www.github.com/googleapis/google-auth-library-java/commit/7d145b2371033093ea13fd05520c90970a5ef363))


### Documentation

* remove bad javadoc tags ([#478](https://www.github.com/googleapis/google-auth-library-java/issues/478)) ([a329c41](https://www.github.com/googleapis/google-auth-library-java/commit/a329c4171735c3d4ee574978e6c3742b96c01f74))


### Dependencies

* update dependency com.google.http-client:google-http-client-bom to v1.37.0 ([#486](https://www.github.com/googleapis/google-auth-library-java/issues/486)) ([3027fbf](https://www.github.com/googleapis/google-auth-library-java/commit/3027fbfaf017f5aa5a22cc51cd38a522597729c0))

### [0.21.1](https://www.github.com/googleapis/google-auth-library-java/compare/v0.21.0...v0.21.1) (2020-07-07)


### Dependencies

* update google-http-client to 1.36.0 ([#447](https://www.github.com/googleapis/google-auth-library-java/issues/447)) ([b913d19](https://www.github.com/googleapis/google-auth-library-java/commit/b913d194259e4f93bb401a844480f56b48dad3bd)), closes [#446](https://www.github.com/googleapis/google-auth-library-java/issues/446)

## [0.21.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.20.0...v0.21.0) (2020-06-24)


### Features

* add TokenVerifier class that can verify RS256/ES256 tokens ([#420](https://www.github.com/googleapis/google-auth-library-java/issues/420)) ([5014ac7](https://www.github.com/googleapis/google-auth-library-java/commit/5014ac72a59d877ef95c616d0b33792b9fc70c25))


### Dependencies

* update autovalue packages to v1.7.2 ([#429](https://www.github.com/googleapis/google-auth-library-java/issues/429)) ([5758364](https://www.github.com/googleapis/google-auth-library-java/commit/575836405bd5803d6202bd0018609184d6a15831))
* update dependency com.google.http-client:google-http-client-bom to v1.35.0 ([#427](https://www.github.com/googleapis/google-auth-library-java/issues/427)) ([5494ec0](https://www.github.com/googleapis/google-auth-library-java/commit/5494ec0a73319fb955b3d7ba025aea9607020c4e))
* update Guava to 29.0-android ([#426](https://www.github.com/googleapis/google-auth-library-java/issues/426)) ([0cd3c2e](https://www.github.com/googleapis/google-auth-library-java/commit/0cd3c2ec0aef3ff0f0379b32f9d05126442219b6))

## [0.20.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.19.0...v0.20.0) (2020-01-15)


### Features

* updated `JwtClaims.Builder` methods to `public` ([#396](https://www.github.com/googleapis/google-auth-library-java/issues/396)) ([9e5de14](https://www.github.com/googleapis/google-auth-library-java/commit/9e5de14263a01d746af2fc192cf1b82a2acff35c))


### Dependencies

* update guava to 28.2-android ([#389](https://www.github.com/googleapis/google-auth-library-java/issues/389)) ([70bd8ff](https://www.github.com/googleapis/google-auth-library-java/commit/70bd8ff15a9b0cb1dab9f350bd49dd60b2da33c7))

## [0.19.0](https://www.github.com/googleapis/google-auth-library-java/compare/v0.18.0...v0.19.0) (2019-12-13)


### Features

* support reading in quotaProjectId for billing ([#383](https://www.github.com/googleapis/google-auth-library-java/issues/383)) ([f38c3c8](https://www.github.com/googleapis/google-auth-library-java/commit/f38c3c84748fadc1591f092edd1974539cf7b644))


### Dependencies

* update appengine-sdk to 1.9.76 ([#366](https://www.github.com/googleapis/google-auth-library-java/issues/366)) ([590883d](https://www.github.com/googleapis/google-auth-library-java/commit/590883d57158275b988b5e6c7f6d608eaa3c08ad))
* update autovalue packages to v1.7 ([#365](https://www.github.com/googleapis/google-auth-library-java/issues/365)) ([42a1694](https://www.github.com/googleapis/google-auth-library-java/commit/42a169463ab3c36552e2eea605571ee9808f346c))
* update dependency com.google.appengine:appengine to v1.9.77 ([#377](https://www.github.com/googleapis/google-auth-library-java/issues/377)) ([c3c950e](https://www.github.com/googleapis/google-auth-library-java/commit/c3c950e7d906aaa4187305a5fd9b05785e19766a))
* update dependency com.google.http-client:google-http-client-bom to v1.33.0 ([#374](https://www.github.com/googleapis/google-auth-library-java/issues/374)) ([af0af50](https://www.github.com/googleapis/google-auth-library-java/commit/af0af5061f4544b8b5bb43c82d2ab66c08143b90))


### Documentation

* remove outdated comment on explicit IP address ([#370](https://www.github.com/googleapis/google-auth-library-java/issues/370)) ([71faa5f](https://www.github.com/googleapis/google-auth-library-java/commit/71faa5f6f26ef2f267743248b828d636d99a9d50))
* xml syntax error in bom/README.md ([#372](https://www.github.com/googleapis/google-auth-library-java/issues/372)) ([ff8606a](https://www.github.com/googleapis/google-auth-library-java/commit/ff8606a608f9261a9714ceda823479f156f65643)), closes [#371](https://www.github.com/googleapis/google-auth-library-java/issues/371)

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
