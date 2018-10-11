#!/bin/bash

set -e pipefail

# Don't fail the build if the token isn't there. Log a warning.
if [ ! -f $KOKORO_KEYSTORE_DIR/73713_dpebot_codecov_token ]; then
  echo "Missing codecov token - skipping codecov upload"
  exit 0
fi

CODECOV_MASTER_TOKEN=$(cat $KOKORO_KEYSTORE_DIR/73713_dpebot_codecov_token)
# CODECOV_MASTER_TOKEN=$(cat $KOKORO_GFILE_DIR/dpe_codecov_token)
CI_BUILD_ID=$KOKORO_BUILD_NUMBER
CI_JOB_ID=$KOKORO_BUILD_NUMBER

VCS_PULL_REQUEST=$KOKORO_GITHUB_PULL_REQUEST_NUMBER
VCS_COMMIT_ID=${KOKORO_GITHUB_PULL_REQUEST_COMMIT-$KOKORO_GIT_COMMIT-$(git rev-parse HEAD)}

if [ -z $VCS_PULL_REQUEST ]; then
  VCS_BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
fi

# Get repo slug using `git remote`
remote_addr=$(git config --get remote.origin.url)
if echo "$remote_addr" | grep -q "//"; then
  # https
  slug=$(echo "$remote_addr" | cut -d / -f 4,5 | sed -e 's/\.git$//')
else
  # ssh
  slug=$(echo "$remote_addr" | cut -d : -f 2 | sed -e 's/\.git$//')
fi

# Access codecov.io API to get repo token
CODECOV_TOKEN=$(curl \
  -s https://codecov.io/api/gh/$slug\?access_token\=$CODECOV_MASTER_TOKEN \
  | sed -n 's/.*"upload_token": "\([^"]*\)".*/\1/p')

echo $CODECOV_TOKEN | cut -c1-5

CODECOV_TOKEN=$CODECOV_TOKEN \
   CI_BUILD_ID=$CI_BUILD_ID \
   CI_JOB_ID=$CI_JOB_ID \
   VCS_PULL_REQUEST=$VCS_PULL_REQUEST \
   VCS_COMMIT_ID=$VCS_COMMIT_ID \
   VCS_BRANCH_NAME=$VCS_BRANCH_NAME \
   bash <(curl -s https://codecov.io/bash)
