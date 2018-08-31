#!/bin/bash
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

GPG_PASSPHRASE=$(cat ${KOKORO_ROOT}/src/keystore/70247_maven-gpg-passphrase)

# Set up gpg-agent
GPG_HOME=$(mktemp -d -t gpg)
cp {KOKORO_ROOT}/src/keystore/70247_maven-gpg-pubkeyring $GPG_HOME/pubring.gpg
cp {KOKORO_ROOT}/src/keystore/70247_maven-gpg-keyring $GPG_HOME/secring.gpg
eval $(gpg-agent --homedir=$GPG_HOME --daemon)

# setup Sonatype credentials

cd github/google-auth-library-java/

mvn clean install deploy -DperformRelease=true -Dgpg.passphrase=$GPG_PASSPHRASE
