#!/bin/bash
# Copyright 2018, Google Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#
#    * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set -e

if [[ -z "${BUCKET}" ]]; then
    echo "Must set BUCKET environment variable"
    exit 1
fi

pushd $(dirname "$0")/../../

# Pull the library version from project properties
VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=project.version | grep -Ev '(^\[|\w+:)')

case "${VERSION}" in
    *-SNAPSHOT)
        echo "Cannot publish javadoc for -SNAPSHOT versions"
        exit 1
        ;;
    "")
        echo "Could not obtain version number from maven-help-plugin."
        exit 1
        ;;
esac

# Generate the javadoc from scratch
mvn clean install javadoc:aggregate -DskipTests=true -B

# Sync the current version to gCS
gsutil -m rsync -d target/site gs://${BUCKET}/java/google-auth-library-java/${VERSION}

if [[ "${LINK_LATEST}" == "true" ]]; then
    # Sync the current content to latest
    gsutil -m rsync gs://${BUCKET}/java/google-auth-library-java/${VERSION} gs://${BUCKET}/java/google-auth-library-java/latest
fi

popd
