/*
 * Copyright 2017 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google LLC nor the names of its
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

/**
 * ### Application Default Credentials
 *
 * This library provides an implementation of [Application Default Credentials](https://google.aip.dev/auth/4110)
 * for Java. The [Application Default Credentials](https://google.aip.dev/auth/4110)
 * provide a simple way to get authorization credentials for use in calling Google APIs.
 *
 * They are best suited for cases when the call needs to have the same identity and
 * authorization level for the application independent of the user. This is the recommended
 * approach to authorize calls to Cloud APIs, particularly when you're building an application
 * that uses Google Cloud Platform.
 *
 * Application Default Credentials also support workload identity federation to access
 * Google Cloud resources from non-Google Cloud platforms including Amazon Web Services (AWS),
 * Microsoft Azure or any identity provider that supports OpenID Connect (OIDC). Workload
 * identity federation is recommended for non-Google Cloud environments as it avoids the
 * need to download, manage and store service account private keys locally, see:
 * [Workload Identity Federation](#workload-identity-federation).
 *
 * #### Getting Application Default Credentials
 *
 * To get Application Default Credentials use `GoogleCredentials.getApplicationDefault()` or
 * `GoogleCredentials.getApplicationDefault(HttpTransportFactory)`. These methods return the
 * Application Default Credentials which are used to identify and authorize the whole application. The
 * following are searched (in order) to find the Application Default Credentials:
 *
 * 1. Credentials file pointed to by the `GOOGLE_APPLICATION_CREDENTIALS` environment variable
 * 2. Credentials provided by the Google Cloud SDK `gcloud auth application-default login` command
 * 3. Google App Engine built-in credentials
 * 4. Google Cloud Shell built-in credentials
 * 5. Google Compute Engine built-in credentials
 *    - Skip this check by setting the environment variable `NO_GCE_CHECK=true`
 *    - Customize the GCE metadata server address by setting the environment variable `GCE_METADATA_HOST=<hostname>`
 *
 * #### Explicit Credential Loading
 *
 * To get Credentials from a Service Account JSON key use `GoogleCredentials.fromStream(InputStream)`
 * or `GoogleCredentials.fromStream(InputStream, HttpTransportFactory)`. Note that the credentials must
 * be refreshed before the access token is available.
 *
 * ```java
 * GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("/path/to/credentials.json"));
 * credentials.refreshIfExpired();
 * AccessToken token = credentials.getAccessToken();
 * // OR
 * AccessToken token = credentials.refreshAccessToken();
 * ```
 *
 * ### ImpersonatedCredentials
 *
 * Allows a credentials issued to a user or service account to
 * impersonate another.  The source project using ImpersonatedCredentials must enable the
 * "IAMCredentials" API.  Also, the target service account must grant the orginating principal
 * the "Service Account Token Creator" IAM role.
 *
 * ```java
 * String credPath = "/path/to/svc_account.json";
 * ServiceAccountCredentials sourceCredentials = ServiceAccountCredentials
 *      .fromStream(new FileInputStream(credPath));
 * sourceCredentials = (ServiceAccountCredentials) sourceCredentials
 *     .createScoped(Arrays.asList("https://www.googleapis.com/auth/iam"));
 *
 * ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
 *     "impersonated-account@project.iam.gserviceaccount.com", null,
 *     Arrays.asList("https://www.googleapis.com/auth/devstorage.read_only"), 300);
 *
 * Storage storage_service = StorageOptions.newBuilder().setProjectId("project-id")
 *     .setCredentials(targetCredentials).build().getService();
 *
 * for (Bucket b : storage_service.list().iterateAll())
 *     System.out.println(b);
 * ```
 *
 * ### Workload Identity Federation
 *
 * Using workload identity federation, your application can access Google Cloud resources from
 * Amazon Web Services (AWS), Microsoft Azure, or any identity provider that supports OpenID Connect
 * (OIDC).
 *
 * Traditionally, applications running outside Google Cloud have used service account keys to access
 * Google Cloud resources. Using identity federation, your workload can impersonate a service account.
 * This lets the external workload access Google Cloud resources directly, eliminating the maintenance
 * and security burden associated with service account keys.
 *
 * #### Accessing resources from AWS
 *
 * In order to access Google Cloud resources from Amazon Web Services (AWS), the following requirements
 * are needed:
 * - A workload identity pool needs to be created.
 * - AWS needs to be added as an identity provider in the workload identity pool (the Google [organization policy](https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers#restrict) needs to allow federation from AWS).
 * - Permission to impersonate a service account needs to be granted to the external identity.
 *
 * Follow the detailed [instructions](https://cloud.google.com/iam/docs/access-resources-aws) on how to
 * configure workload identity federation from AWS.
 *
 * After configuring the AWS provider to impersonate a service account, a credential configuration file
 * needs to be generated. Unlike service account credential files, the generated credential
 * configuration file contains non-sensitive metadata to instruct the library on how to
 * retrieve external subject tokens and exchange them for service account access tokens.
 * The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).
 *
 * To generate the AWS workload identity configuration, run the following command:
 *
 * ```bash
 * # Generate an AWS configuration file.
 * gcloud iam workload-identity-pools create-cred-config \
 *     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$AWS_PROVIDER_ID \
 *     --service-account $SERVICE_ACCOUNT_EMAIL \
 *     --aws \
 *     --output-file /path/to/generated/config.json
 * ```
 *
 * Where the following variables need to be substituted:
 * - `$PROJECT_NUMBER`: The Google Cloud project number.
 * - `$POOL_ID`: The workload identity pool ID.
 * - `$AWS_PROVIDER_ID`: The AWS provider ID.
 * - `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
 *
 * This generates the configuration file in the specified output file.
 *
 * If you are using [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), an additional flag `--enable-imdsv2` needs to be added to the `gcloud iam workload-identity-pools create-cred-config` command:
 *
 * ```bash
 * gcloud iam workload-identity-pools create-cred-config \
 *     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$AWS_PROVIDER_ID \
 *     --service-account $SERVICE_ACCOUNT_EMAIL \
 *     --aws \
 *     --output-file /path/to/generated/config.json \
 *     --enable-imdsv2
 * ```
 *
 * You can now [use the Auth library](#using-external-identities) to call Google Cloud
 * resources from AWS.
 *
 * #### Access resources from Microsoft Azure
 *
 * In order to access Google Cloud resources from Microsoft Azure, the following requirements are
 * needed:
 * - A workload identity pool needs to be created.
 * - Azure needs to be added as an identity provider in the workload identity pool (the Google [organization policy](https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers#restrict) needs to allow federation from Azure).
 * - The Azure tenant needs to be configured for identity federation.
 * - Permission to impersonate a service account needs to be granted to the external identity.
 *
 * Follow the detailed [instructions](https://cloud.google.com/iam/docs/access-resources-azure) on how
 * to configure workload identity federation from Microsoft Azure.
 *
 * After configuring the Azure provider to impersonate a service account, a credential configuration
 * file needs to be generated. Unlike service account credential files, the generated credential
 * configuration file contains non-sensitive metadata to instruct the library on how to
 * retrieve external subject tokens and exchange them for service account access tokens.
 * The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).
 *
 * To generate the Azure workload identity configuration, run the following command:
 *
 * ```bash
 * # Generate an Azure configuration file.
 * gcloud iam workload-identity-pools create-cred-config \
 *     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$AZURE_PROVIDER_ID \
 *     --service-account $SERVICE_ACCOUNT_EMAIL \
 *     --azure \
 *     --output-file /path/to/generated/config.json
 * ```
 *
 * Where the following variables need to be substituted:
 * - `$PROJECT_NUMBER`: The Google Cloud project number.
 * - `$POOL_ID`: The workload identity pool ID.
 * - `$AZURE_PROVIDER_ID`: The Azure provider ID.
 * - `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
 *
 * This generates the configuration file in the specified output file.
 *
 * You can now [use the Auth library](#using-external-identities) to call Google Cloud
 * resources from Azure.
 *
 * #### Accessing resources from an OIDC identity provider
 *
 * In order to access Google Cloud resources from an identity provider that supports [OpenID Connect (OIDC)](https://openid.net/connect/), the following requirements are needed:
 * - A workload identity pool needs to be created.
 * - An OIDC identity provider needs to be added in the workload identity pool (the Google [organization policy](https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers#restrict) needs to allow federation from the identity provider).
 * - Permission to impersonate a service account needs to be granted to the external identity.
 *
 * Follow the detailed [instructions](https://cloud.google.com/iam/docs/access-resources-oidc) on how
 * to configure workload identity federation from an OIDC identity provider.
 *
 * After configuring the OIDC provider to impersonate a service account, a credential configuration
 * file needs to be generated. Unlike service account credential files, the generated credential
 * configuration file contains non-sensitive metadata to instruct the library on how to
 * retrieve external subject tokens and exchange them for service account access tokens.
 * The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).
 *
 * For OIDC providers, the Auth library can retrieve OIDC tokens either from a local file location
 * (file-sourced credentials) or from a local server (URL-sourced credentials).
 *
 * **File-sourced credentials**
 * For file-sourced credentials, a background process needs to be continuously refreshing the file
 * location with a new OIDC token prior to expiration. For tokens with one hour lifetimes, the token
 * needs to be updated in the file every hour. The token can be stored directly as plain text or in
 * JSON format.
 *
 * To generate a file-sourced OIDC configuration, run the following command:
 *
 * ```bash
 * # Generate an OIDC configuration file for file-sourced credentials.
 * gcloud iam workload-identity-pools create-cred-config \
 *     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$OIDC_PROVIDER_ID \
 *     --service-account $SERVICE_ACCOUNT_EMAIL \
 *     --credential-source-file $PATH_TO_OIDC_ID_TOKEN \
 *     # Optional arguments for file types. Default is "text":
 *     # --credential-source-type "json" \
 *     # Optional argument for the field that contains the OIDC credential.
 *     # This is required for json.
 *     # --credential-source-field-name "id_token" \
 *     --output-file /path/to/generated/config.json
 * ```
 *
 * Where the following variables need to be substituted:
 * - `$PROJECT_NUMBER`: The Google Cloud project number.
 * - `$POOL_ID`: The workload identity pool ID.
 * - `$OIDC_PROVIDER_ID`: The OIDC provider ID.
 * - `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
 * - `$PATH_TO_OIDC_ID_TOKEN`: The file path used to retrieve the OIDC token.
 *
 * This generates the configuration file in the specified output file.
 *
 * **URL-sourced credentials**
 * For URL-sourced credentials, a local server needs to host a GET endpoint to return the OIDC token.
 * The response can be in plain text or JSON. Additional required request headers can also be
 * specified.
 *
 * To generate a URL-sourced OIDC workload identity configuration, run the following command:
 *
 * ```bash
 * # Generate an OIDC configuration file for URL-sourced credentials.
 * gcloud iam workload-identity-pools create-cred-config \
 *     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$OIDC_PROVIDER_ID \
 *     --service-account $SERVICE_ACCOUNT_EMAIL \
 *     --credential-source-url $URL_TO_GET_OIDC_TOKEN \
 *     --credential-source-headers $HEADER_KEY=$HEADER_VALUE \
 *     # Optional arguments for file types. Default is "text":
 *     # --credential-source-type "json" \
 *     # Optional argument for the field that contains the OIDC credential.
 *     # This is required for json.
 *     # --credential-source-field-name "id_token" \
 *     --output-file /path/to/generated/config.json
 * ```
 *
 * Where the following variables need to be substituted:
 * - `$PROJECT_NUMBER`: The Google Cloud project number.
 * - `$POOL_ID`: The workload identity pool ID.
 * - `$OIDC_PROVIDER_ID`: The OIDC provider ID.
 * - `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
 * - `$URL_TO_GET_OIDC_TOKEN`: The URL of the local server endpoint to call to retrieve the OIDC token.
 * - `$HEADER_KEY` and `$HEADER_VALUE`: The additional header key/value pairs to pass along the GET
 * request to `$URL_TO_GET_OIDC_TOKEN`, e.g. `Metadata-Flavor=Google`.
 *
 * You can now [use the Auth library](#using-external-identities) to call Google Cloud
 * resources from an OIDC provider.
 *
 * #### Using Executable-sourced credentials with OIDC and SAML
 *
 * **Executable-sourced credentials**
 * For executable-sourced credentials, a local executable is used to retrieve the 3rd party token.
 * The executable must handle providing a valid, unexpired OIDC ID token or SAML assertion in JSON format
 * to stdout.
 *
 * To use executable-sourced credentials, the `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`
 * environment variable must be set to `1`.
 *
 * To generate an executable-sourced workload identity configuration, run the following command:
 *
 * ```bash
 * # Generate a configuration file for executable-sourced credentials.
 * gcloud iam workload-identity-pools create-cred-config \
 *     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID \
 *     --service-account=$SERVICE_ACCOUNT_EMAIL \
 *     --subject-token-type=$SUBJECT_TOKEN_TYPE \
 *     # The absolute path for the program, including arguments.
 *     # e.g. --executable-command="/path/to/command --foo=bar"
 *     --executable-command=$EXECUTABLE_COMMAND \
 *     # Optional argument for the executable timeout. Defaults to 30s.
 *     # --executable-timeout-millis=$EXECUTABLE_TIMEOUT \
 *     # Optional argument for the absolute path to the executable output file.
 *     # See below on how this argument impacts the library behaviour.
 *     # --executable-output-file=$EXECUTABLE_OUTPUT_FILE \
 *     --output-file /path/to/generated/config.json
 * ```
 * Where the following variables need to be substituted:
 * - `$PROJECT_NUMBER`: The Google Cloud project number.
 * - `$POOL_ID`: The workload identity pool ID.
 * - `$PROVIDER_ID`: The OIDC or SAML provider ID.
 * - `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
 * - `$SUBJECT_TOKEN_TYPE`: The subject token type.
 * - `$EXECUTABLE_COMMAND`: The full command to run, including arguments. Must be an absolute path to the program.
 *
 * The `--executable-timeout-millis` flag is optional. This is the duration for which
 * the auth library will wait for the executable to finish, in milliseconds.
 * Defaults to 30 seconds when not provided. The maximum allowed value is 2 minutes.
 * The minimum is 5 seconds.
 *
 * The `--executable-output-file` flag is optional. If provided, the file path must
 * point to the 3PI credential response generated by the executable. This is useful
 * for caching the credentials. By specifying this path, the Auth libraries will first
 * check for its existence before running the executable. By caching the executable JSON
 * response to this file, it improves performance as it avoids the need to run the executable
 * until the cached credentials in the output file are expired. The executable must
 * handle writing to this file - the auth libraries will only attempt to read from
 * this location. The format of contents in the file should match the JSON format
 * expected by the executable shown below.
 *
 * To retrieve the 3rd party token, the library will call the executable
 * using the command specified. The executable's output must adhere to the response format
 * specified below. It must output the response to stdout.
 *
 * A sample successful executable OIDC response:
 * ```json
 * {
 *   "version": 1,
 *   "success": true,
 *   "token_type": "urn:ietf:params:oauth:token-type:id_token",
 *   "id_token": "HEADER.PAYLOAD.SIGNATURE",
 *   "expiration_time": 1620499962
 * }
 * ```
 *
 * A sample successful executable SAML response:
 * ```json
 * {
 *   "version": 1,
 *   "success": true,
 *   "token_type": "urn:ietf:params:oauth:token-type:saml2",
 *   "saml_response": "...",
 *   "expiration_time": 1620499962
 * }
 * ```
 * A sample executable error response:
 * ```json
 * {
 *   "version": 1,
 *   "success": false,
 *   "code": "401",
 *   "message": "Caller not authorized."
 * }
 * ```
 * These are all required fields for an error response. The code and message
 * fields will be used by the library as part of the thrown exception.
 *
 * For successful responses, the `expiration_time` field is only required
 * when an output file is specified in the credential configuration.
 *
 * Response format fields summary:
 *   * `version`: The version of the JSON output. Currently only version 1 is supported.
 *   * `success`: When true, the response must contain the 3rd party token and token type. The response must also contain
 *     the expiration_time field if an output file was specified in the credential configuration. The executable must also
 *     exit with exit code 0. When false, the response must contain the error code and message fields and exit with a
 *     non-zero value.
 *   * `token_type`: The 3rd party subject token type. Must be *urn:ietf:params:oauth:token-type:jwt*,
 *      *urn:ietf:params:oauth:token-type:id_token*, or *urn:ietf:params:oauth:token-type:saml2*.
 *   * `id_token`: The 3rd party OIDC token.
 *   * `saml_response`: The 3rd party SAML response.
 *   * `expiration_time`: The 3rd party subject token expiration time in seconds (unix epoch time).
 *   * `code`: The error code string.
 *   * `message`: The error message.
 *
 * All response types must include both the `version` and `success` fields.
 *  * Successful responses must include the `token_type` and one of
 *    `id_token` or `saml_response`. The `expiration_time` field must also be present if an output file was specified in
 *     the credential configuration.
 *  * Error responses must include both the `code` and `message` fields.
 *
 * The library will populate the following environment variables when the executable is run:
 *   * `GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE`: The audience field from the credential configuration. Always present.
 *   * `GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE`: This expected subject token type. Always present.
 *   * `GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL`: The service account email. Only present when service account impersonation is used.
 *   * `GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE`: The output file location from the credential configuration. Only present when specified in the credential configuration.
 *
 * These environment variables can be used by the executable to avoid hard-coding these values.
 *
 * ##### Security considerations
 * The following security practices are highly recommended:
 *   * Access to the script should be restricted as it will be displaying credentials to stdout. This ensures that rogue processes do not gain access to the script.
 *   * The configuration file should not be modifiable. Write access should be restricted to avoid processes modifying the executable command portion.
 *
 * Given the complexity of using executable-sourced credentials, it is recommended to use
 * the existing supported mechanisms (file-sourced/URL-sourced) for providing 3rd party
 * credentials unless they do not meet your specific requirements.
 *
 * You can now [use the Auth library](#using-external-identities) to call Google Cloud
 * resources from an OIDC or SAML provider.
 *
 * #### Configurable Token Lifetime
 * When creating a credential configuration with workload identity federation using service account impersonation, you can provide an optional argument to configure the service account access token lifetime.
 *
 * To generate the configuration with configurable token lifetime, run the following command (this example uses an AWS configuration, but the token lifetime can be configured for all workload identity federation providers):
 *   ```bash
 *   # Generate an AWS configuration file with configurable token lifetime.
 *   gcloud iam workload-identity-pools create-cred-config \
 *       projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$AWS_PROVIDER_ID \
 *       --service-account $SERVICE_ACCOUNT_EMAIL \
 *       --aws \
 *       --output-file /path/to/generated/config.json \
 *       --service-account-token-lifetime-seconds $TOKEN_LIFETIME
 *   ```
 *
 * Where the following variables need to be substituted:
 * - `$PROJECT_NUMBER`: The Google Cloud project number.
 * - `$POOL_ID`: The workload identity pool ID.
 * - `$AWS_PROVIDER_ID`: The AWS provider ID.
 * - `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
 * - `$TOKEN_LIFETIME`: The desired lifetime duration of the service account access token in seconds.
 *
 * The `service-account-token-lifetime-seconds` flag is optional. If not provided, this defaults to one hour.
 * The minimum allowed value is 600 (10 minutes) and the maximum allowed value is 43200 (12 hours).
 * If a lifetime greater than one hour is required, the service account must be added as an allowed value in an Organization Policy that enforces the `constraints/iam.allowServiceAccountCredentialLifetimeExtension` constraint.
 *
 * Note that configuring a short lifetime (e.g. 10 minutes) will result in the library initiating the entire token exchange flow every 10 minutes, which will call the 3rd party token provider even if the 3rd party token is not expired.
 *
 * ###  Workforce Identity Federation
 *
 * [Workforce identity federation](https://cloud.google.com/iam/docs/workforce-identity-federation) lets you use an
 * external identity provider (IdP) to authenticate and authorize a workforce—a group of users, such as employees,
 * partners, and contractors—using IAM, so that the users can access Google Cloud services. Workforce identity federation
 * extends Google Cloud's identity capabilities to support syncless, attribute-based single sign on.
 *
 * With workforce identity federation, your workforce can access Google Cloud resources using an external
 * identity provider (IdP) that supports OpenID Connect (OIDC) or SAML 2.0 such as Azure Active Directory (Azure AD),
 * Active Directory Federation Services (AD FS), Okta, and others.
 *
 * #### Accessing resources using an OIDC or SAML 2.0 identity provider
 *
 * In order to access Google Cloud resources from an identity provider that supports [OpenID Connect (OIDC)](https://openid.net/connect/),
 * the following requirements are needed:
 * - A workforce identity pool needs to be created.
 * - An OIDC or SAML 2.0 identity provider needs to be added in the workforce pool.
 *
 * Follow the detailed [instructions](https://cloud.google.com/iam/docs/configuring-workforce-identity-federation) on how
 * to configure workforce identity federation.
 *
 * After configuring an OIDC or SAML 2.0 provider, a credential configuration
 * file needs to be generated. The generated credential configuration file contains non-sensitive metadata to instruct the
 * library on how to retrieve external subject tokens and exchange them for GCP access tokens.
 * The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).
 *
 * The Auth library can retrieve external subject tokens from a local file location
 * (file-sourced credentials), from a local server (URL-sourced credentials) or by calling an executable
 * (executable-sourced credentials).
 *
 * **File-sourced credentials**
 * For file-sourced credentials, a background process needs to be continuously refreshing the file
 * location with a new subject token prior to expiration. For tokens with one hour lifetimes, the token
 * needs to be updated in the file every hour. The token can be stored directly as plain text or in
 * JSON format.
 *
 * To generate a file-sourced OIDC configuration, run the following command:
 *
 * ```bash
 * # Generate an OIDC configuration file for file-sourced credentials.
 * gcloud iam workforce-pools create-cred-config \
 *     locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID \
 *     --subject-token-type=urn:ietf:params:oauth:token-type:id_token \
 *     --credential-source-file=$PATH_TO_OIDC_ID_TOKEN \
 *     --workforce-pool-user-project=$WORKFORCE_POOL_USER_PROJECT \
 *     # Optional arguments for file types. Default is "text":
 *     # --credential-source-type "json" \
 *     # Optional argument for the field that contains the OIDC credential.
 *     # This is required for json.
 *     # --credential-source-field-name "id_token" \
 *     --output-file=/path/to/generated/config.json
 * ```
 * Where the following variables need to be substituted:
 * - `$WORKFORCE_POOL_ID`: The workforce pool ID.
 * - `$PROVIDER_ID`: The provider ID.
 * - `$PATH_TO_OIDC_ID_TOKEN`: The file path used to retrieve the OIDC token.
 * - `$WORKFORCE_POOL_USER_PROJECT`: The project number associated with the [workforce pools user project](https://cloud.google.com/iam/docs/workforce-identity-federation#workforce-pools-user-project).
 *
 * To generate a file-sourced SAML configuration, run the following command:
 *
 * ```bash
 * # Generate a SAML configuration file for file-sourced credentials.
 * gcloud iam workforce-pools create-cred-config \
 *     locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID \
 *     --credential-source-file=$PATH_TO_SAML_ASSERTION \
 *     --subject-token-type=urn:ietf:params:oauth:token-type:saml2 \
 *     --workforce-pool-user-project=$WORKFORCE_POOL_USER_PROJECT \
 *     --output-file=/path/to/generated/config.json
 * ```
 *
 * Where the following variables need to be substituted:
 * - `$WORKFORCE_POOL_ID`: The workforce pool ID.
 * - `$PROVIDER_ID`: The provider ID.
 * - `$PATH_TO_SAML_ASSERTION`: The file path used to retrieve the base64-encoded SAML assertion.
 * - `$WORKFORCE_POOL_USER_PROJECT`: The project number associated with the [workforce pools user project](https://cloud.google.com/iam/docs/workforce-identity-federation#workforce-pools-user-project).
 *
 * These commands generate the configuration file in the specified output file.
 *
 * **URL-sourced credentials**
 * For URL-sourced credentials, a local server needs to host a GET endpoint to return the OIDC token.
 * The response can be in plain text or JSON. Additional required request headers can also be
 * specified.
 *
 * To generate a URL-sourced OIDC workforce identity configuration, run the following command:
 *
 * ```bash
 * # Generate an OIDC configuration file for URL-sourced credentials.
 * gcloud iam workforce-pools create-cred-config \
 *     locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID \
 *     --subject-token-type=urn:ietf:params:oauth:token-type:id_token \
 *     --credential-source-url=$URL_TO_RETURN_OIDC_ID_TOKEN \
 *     --credential-source-headers $HEADER_KEY=$HEADER_VALUE \
 *     --workforce-pool-user-project=$WORKFORCE_POOL_USER_PROJECT \
 *     --output-file=/path/to/generated/config.json
 * ```
 *
 * Where the following variables need to be substituted:
 * - `$WORKFORCE_POOL_ID`: The workforce pool ID.
 * - `$PROVIDER_ID`: The provider ID.
 * - `$URL_TO_RETURN_OIDC_ID_TOKEN`: The URL of the local server endpoint.
 * - `$HEADER_KEY` and `$HEADER_VALUE`: The additional header key/value pairs to pass along the GET request to
 *   `$URL_TO_GET_OIDC_TOKEN`, e.g. `Metadata-Flavor=Google`.
 * - `$WORKFORCE_POOL_USER_PROJECT`: The project number associated with the [workforce pools user project](https://cloud.google.com/iam/docs/workforce-identity-federation#workforce-pools-user-project).
 *
 * To generate a URL-sourced SAML configuration, run the following command:
 *
 * ```bash
 * # Generate a SAML configuration file for file-sourced credentials.
 * gcloud iam workforce-pools create-cred-config \
 *     locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID \
 *     --subject-token-type=urn:ietf:params:oauth:token-type:saml2 \
 *     --credential-source-url=$URL_TO_GET_SAML_ASSERTION \
 *     --credential-source-headers $HEADER_KEY=$HEADER_VALUE \
 *     --workforce-pool-user-project=$WORKFORCE_POOL_USER_PROJECT \
 *     --output-file=/path/to/generated/config.json
 * ```
 *
 * These commands generate the configuration file in the specified output file.
 *
 * Where the following variables need to be substituted:
 * - `$WORKFORCE_POOL_ID`: The workforce pool ID.
 * - `$PROVIDER_ID`: The provider ID.
 * - `$URL_TO_GET_SAML_ASSERTION`: The URL of the local server endpoint.
 * - `$HEADER_KEY` and `$HEADER_VALUE`: The additional header key/value pairs to pass along the GET request to
 *   `$URL_TO_GET_SAML_ASSERTION`, e.g. `Metadata-Flavor=Google`.
 * - `$WORKFORCE_POOL_USER_PROJECT`: The project number associated with the [workforce pools user project](https://cloud.google.com/iam/docs/workforce-identity-federation#workforce-pools-user-project).
 *
 * #### Using external account authorized user workforce credentials
 *
 * [External account authorized user credentials](https://cloud.google.com/iam/docs/workforce-obtaining-short-lived-credentials#browser-based-sign-in) allow you to sign in with a web browser to an external identity provider account via the
 * gcloud CLI and create a configuration for the auth library to use.
 *
 * To generate an external account authorized user workforce identity configuration, run the following command:
 *
 * ```bash
 * gcloud auth application-default login --login-config=$LOGIN_CONFIG
 * ```
 *
 * Where the following variable needs to be substituted:
 * - `$LOGIN_CONFIG`: The login config file generated with the cloud console or
 *   [gcloud iam workforce-pools create-login-config](https://cloud.google.com/sdk/gcloud/reference/iam/workforce-pools/create-login-config)
 *
 * This will open a browser flow for you to sign in via the configured third party identity provider
 * and then will store the external account authorized user configuration at the well known ADC location.
 * The auth library will then use the provided refresh token from the configuration to generate and refresh
 * an access token to call Google Cloud services.
 *
 * Note that the default lifetime of the refresh token is one hour, after which a new configuration will need to be generated from the gcloud CLI.
 * The lifetime can be modified by changing the [session duration of the workforce pool](https://cloud.google.com/iam/docs/reference/rest/v1/locations.workforcePools), and can be set as high as 12 hours.
 *
 * #### Using Executable-sourced workforce credentials with OIDC and SAML
 *
 * **Executable-sourced credentials**
 * For executable-sourced credentials, a local executable is used to retrieve the 3rd party token.
 * The executable must handle providing a valid, unexpired OIDC ID token or SAML assertion in JSON format
 * to stdout.
 *
 * To use executable-sourced credentials, the `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`
 * environment variable must be set to `1`.
 *
 * To generate an executable-sourced workforce identity configuration, run the following command:
 *
 * ```bash
 * # Generate a configuration file for executable-sourced credentials.
 * gcloud iam workforce-pools create-cred-config \
 *     locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID \
 *     --subject-token-type=$SUBJECT_TOKEN_TYPE \
 *     # The absolute path for the program, including arguments.
 *     # e.g. --executable-command="/path/to/command --foo=bar"
 *     --executable-command=$EXECUTABLE_COMMAND \
 *     # Optional argument for the executable timeout. Defaults to 30s.
 *     # --executable-timeout-millis=$EXECUTABLE_TIMEOUT \
 *     # Optional argument for the absolute path to the executable output file.
 *     # See below on how this argument impacts the library behaviour.
 *     # --executable-output-file=$EXECUTABLE_OUTPUT_FILE \
 *     --workforce-pool-user-project=$WORKFORCE_POOL_USER_PROJECT \
 *     --output-file /path/to/generated/config.json
 * ```
 * Where the following variables need to be substituted:
 * - `$WORKFORCE_POOL_ID`: The workforce pool ID.
 * - `$PROVIDER_ID`: The provider ID.
 * - `$SUBJECT_TOKEN_TYPE`: The subject token type.
 * - `$EXECUTABLE_COMMAND`: The full command to run, including arguments. Must be an absolute path to the program.
 * - `$WORKFORCE_POOL_USER_PROJECT`: The project number associated with the [workforce pools user project](https://cloud.google.com/iam/docs/workforce-identity-federation#workforce-pools-user-project).
 *
 * The `--executable-timeout-millis` flag is optional. This is the duration for which
 * the auth library will wait for the executable to finish, in milliseconds.
 * Defaults to 30 seconds when not provided. The maximum allowed value is 2 minutes.
 * The minimum is 5 seconds.
 *
 * The `--executable-output-file` flag is optional. If provided, the file path must
 * point to the 3rd party credential response generated by the executable. This is useful
 * for caching the credentials. By specifying this path, the Auth libraries will first
 * check for its existence before running the executable. By caching the executable JSON
 * response to this file, it improves performance as it avoids the need to run the executable
 * until the cached credentials in the output file are expired. The executable must
 * handle writing to this file - the auth libraries will only attempt to read from
 * this location. The format of contents in the file should match the JSON format
 * expected by the executable shown below.
 *
 * To retrieve the 3rd party token, the library will call the executable
 * using the command specified. The executable's output must adhere to the response format
 * specified below. It must output the response to stdout.
 *
 * Refer to the [using executable-sourced credentials with Workload Identity Federation](#using-executable-sourced-credentials-with-oidc-and-saml)
 * above for the executable response specification.
 *
 * ##### Security considerations
 * The following security practices are highly recommended:
 * * Access to the script should be restricted as it will be displaying credentials to stdout. This ensures that rogue processes do not gain access to the script.
 * * The configuration file should not be modifiable. Write access should be restricted to avoid processes modifying the executable command portion.
 *
 * Given the complexity of using executable-sourced credentials, it is recommended to use
 * the existing supported mechanisms (file-sourced/URL-sourced) for providing 3rd party
 * credentials unless they do not meet your specific requirements.
 *
 * You can now [use the Auth library](#using-external-identities) to call Google Cloud
 * resources from an OIDC or SAML provider.
 *
 * ### Using External Identities
 *
 * External identities can be used with `Application Default Credentials`. In order to use external identities with
 * Application Default Credentials, you need to generate the JSON credentials configuration file for your external identity
 * as described above. Once generated, store the path to this file in the`GOOGLE_APPLICATION_CREDENTIALS` environment variable.
 *
 * ```bash
 * export GOOGLE_APPLICATION_CREDENTIALS=/path/to/config.json
 * ```
 *
 * The library can now choose the right type of client and initialize credentials from the context
 * provided in the configuration file.
 *
 * ```java
 * GoogleCredentials googleCredentials = GoogleCredentials.getApplicationDefault();
 *
 * String projectId = "your-project-id";
 * String url = "https://storage.googleapis.com/storage/v1/b?project=" + projectId;
 *
 * HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(googleCredentials);
 * HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory(credentialsAdapter);
 * HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));
 *
 * JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
 * request.setParser(parser);
 *
 * HttpResponse response = request.execute();
 * System.out.println(response.parseAsString());
 * ```
 *
 * You can also explicitly initialize external account clients using the generated configuration file.
 *
 * ```java
 * ExternalAccountCredentials credentials =
 *     ExternalAccountCredentials.fromStream(new FileInputStream("/path/to/credentials.json"));
 * ```
 *
 * ##### Security Considerations
 * Note that this library does not perform any validation on the token_url, token_info_url,
 * or service_account_impersonation_url fields of the credential configuration.
 * It is not recommended to use a credential configuration that you did not
 * generate with the gcloud CLI unless you verify that the URL fields point to a
 * googleapis.com domain.
 *
 * ### Downscoping with Credential Access Boundaries
 *
 * [Downscoping with Credential Access Boundaries](https://cloud.google.com/iam/docs/downscoping-short-lived-credentials)
 * enables the ability to downscope, or restrict, the Identity and Access Management (IAM) permissions
 * that a short-lived credential can use for Cloud Storage.
 *
 * The `DownscopedCredentials` class can be used to produce a downscoped access token from a
 * `CredentialAccessBoundary` and a source credential. The Credential Access Boundary specifies which
 * resources the newly created credential can access, as well as an upper bound on the permissions that
 * are available on each resource. Using downscoped credentials ensures tokens in flight always have
 * the least privileges (Principle of Least Privilege).
 *
 * The snippet below shows how to initialize a CredentialAccessBoundary with one AccessBoundaryRule
 * which specifies that the downscoped token will have readonly access to objects starting with
 * "customer-a" in bucket "bucket-123":
 * ```java
 * // Create the AccessBoundaryRule.
 * String availableResource = "//storage.googleapis.com/projects/_/buckets/bucket-123";
 * String availablePermission = "inRole:roles/storage.objectViewer";
 * String expression =  "resource.name.startsWith('projects/_/buckets/bucket-123/objects/customer-a')";
 *
 * CredentialAccessBoundary.AccessBoundaryRule rule =
 *     CredentialAccessBoundary.AccessBoundaryRule.newBuilder()
 *         .setAvailableResource(availableResource)
 *         .addAvailablePermission(availablePermission)
 *         .setAvailabilityCondition(
 *         CredentialAccessBoundary.AccessBoundaryRule.AvailabilityCondition.newBuilder().setExpression(expression).build())
 *         .build();
 *
 * // Create the CredentialAccessBoundary with the rule.
 * CredentialAccessBoundary credentialAccessBoundary =
 *         CredentialAccessBoundary.newBuilder().addRule(rule).build();
 * ```
 *
 * The common pattern of usage is to have a token broker with elevated access generate these downscoped
 * credentials from higher access source credentials and pass the downscoped short-lived access tokens
 * to a token consumer via some secure authenticated channel for limited access to Google Cloud Storage
 * resources.
 *
 * Using the CredentialAccessBoundary created above in the Token Broker:
 * ```java
 * // Retrieve the source credentials from ADC.
 * GoogleCredentials sourceCredentials = GoogleCredentials.getApplicationDefault()
 *         .createScoped("https://www.googleapis.com/auth/cloud-platform");
 *
 * // Initialize the DownscopedCredentials class.
 * DownscopedCredentials downscopedCredentials =
 *     DownscopedCredentials.newBuilder()
 *         .setSourceCredential(credentials)
 *         .setCredentialAccessBoundary(credentialAccessBoundary)
 *         .build();
 *
 * // Retrieve the downscoped access token.
 * // This will need to be passed to the Token Consumer.
 * AccessToken downscopedAccessToken = downscopedCredentials.refreshAccessToken();
 * ```
 *
 * A token broker can be set up on a server in a private network. Various workloads
 * (token consumers) in the same network will send authenticated requests to that broker for downscoped
 * tokens to access or modify specific google cloud storage buckets.
 *
 * The broker will instantiate downscoped credentials instances that can be used to generate short
 * lived downscoped access tokens which will be passed to the token consumer.
 *
 * Putting it all together:
 * ```java
 * // Retrieve the source credentials from ADC.
 * GoogleCredentials sourceCredentials = GoogleCredentials.getApplicationDefault()
 *         .createScoped("https://www.googleapis.com/auth/cloud-platform");
 *
 * // Create an Access Boundary Rule which will restrict the downscoped token to having readonly
 * // access to objects starting with "customer-a" in bucket "bucket-123".
 * String availableResource = "//storage.googleapis.com/projects/_/buckets/bucket-123";
 * String availablePermission = "inRole:roles/storage.objectViewer";
 * String expression =  "resource.name.startsWith('projects/_/buckets/bucket-123/objects/customer-a')";
 */


package com.google.auth.oauth2;