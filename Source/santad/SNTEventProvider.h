/// Copyright 2019 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#include "Source/common/SNTKernelCommon.h"

@protocol SNTEventProvider <NSObject>

- (void)listenForDecisionRequests:(void (^)(santa_message_t message))callback;
- (void)listenForLogRequests:(void (^)(santa_message_t message))callback;
- (int)postAction:(santa_action_t)action forID:(santa_post_id_t)i;
- (BOOL)flushCacheNonRootOnly:(BOOL)nonRootOnly;

@end
