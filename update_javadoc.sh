#!/bin/bash

set -e

VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=project.version | grep -Ev '(^\[|\w+:)')

if [ -z "$VERSION" ]; then
    echo "Error updating Javadoc: could not obtain version number from maven-help-plugin."
    exit 1
fi

git clone --branch gh-pages --single-branch https://github.com/google/google-auth-library-java/ tmp_gh-pages
mkdir -p tmp_gh-pages/releases/$VERSION

mvn javadoc:aggregate

pushd tmp_gh-pages/
cp -r ../target/site/* releases/$VERSION/
git add releases/$VERSION

echo "<html><head><meta http-equiv=\"refresh\" content=\"0; URL='http://google.github.io/google-auth-library-java/releases/${VERSION}/apidocs/index.html'\" /></head><body></body></html>" > index.html
git add index.html

git commit --quiet -m "Add version $VERSION and update root redirect [ci skip]"
git push

popd
rm -rf tmp_gh-pages
