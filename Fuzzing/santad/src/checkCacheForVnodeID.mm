/// Copyright 2018 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include <cstdint>
#include <iostream>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommandController.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size > 16) {
    std::cerr << "Invalid buffer size of " << size << " (should be <= 16)" << std::endl;

    return 1;
  }

  SantaVnode vnodeID = {};
  std::memcpy(&vnodeID, data, size);

  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  daemonConn.invalidationHandler = ^{
    printf("An error occurred communicating with the daemon, is it running?\n");
    exit(1);
  };

  [daemonConn resume];

  [[daemonConn remoteObjectProxy]
      checkCacheForVnodeID:vnodeID
                 withReply:^(SNTAction action) {
                   if (action == SNTActionRespondAllow) {
                     std::cerr << "File exists in [whitelist] kernel cache" << std::endl;
                     ;
                   } else if (action == SNTActionRespondDeny) {
                     std::cerr << "File exists in [blacklist] kernel cache" << std::endl;
                     ;
                   } else if (action == SNTActionUnset) {
                     std::cerr << "File does not exist in cache" << std::endl;
                     ;
                   }
                 }];

  return 0;
}
