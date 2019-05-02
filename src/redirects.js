// Copyright 2019, Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

module.exports.redirectUrl = function(url) {
  var uri = new URL(url);
  var pattern = /^\/google-auth-library-java\/releases\/(\d+\.\d+\.\d+|latest)\/apidocs\/(.*)/;
  var match = pattern.exec(uri.pathname);
  if (match == null) {
    return null;
  }
  return 'https://googleapis.dev/java/google-auth-library/' + match[1] + '/' + match[2] + uri.search + uri.hash;
};
