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

#import "Source/santad/SNTEndpointSecurityManager.h"

#import "Source/common/SNTLogging.h"

#include <EndpointSecurity/EndpointSecurity.h>

@interface SNTEndpointSecurityManager ()

@property(nonatomic) es_client_t *decisionClient;
@property(nonatomic) es_client_t *logClient;

@end

@implementation SNTEndpointSecurityManager

// TODO(bur/rah): Make storing es_client_t better.
- (void)listenForDecisionRequests:(void (^)(santa_message_t))callback {
  es_client_t *client = NULL;
  es_new_client_result_t ret = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
    // TODO(bur/rah): Check message type and fill in santa_message_t.
    es_message_t *mm = es_copy_message(m);
    santa_message_t vdata;
    vdata.client = (void *)c;
    vdata.message = (void *)mm;
    vdata.ppid = mm->proc.ppid;
    callback(vdata);
  });
  if (ret != ES_NEW_CLIENT_RESULT_SUCCESS) LOGE(@"Unable to create es client: %d", ret);
  self.decisionClient = client;
}

- (void)listenForLogRequests:(void (^)(santa_message_t))callback {
}

- (int)postAction:(santa_action_t)action forID:(santa_post_id_t)i {
  switch (action) {
    case ACTION_RESPOND_ALLOW:
      return es_respond_auth_result((es_client_t *)i.m.client, (es_message_t *)i.m.message,
                                    ES_AUTH_RESULT_ALLOW, true);
    case ACTION_RESPOND_DENY:
      return es_respond_auth_result((es_client_t *)i.m.client, (es_message_t *)i.m.message,
                                    ES_AUTH_RESULT_DENY, true);
    default:
      return ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
  }
  return 0;
}

- (BOOL)flushCacheNonRootOnly:(BOOL)nonRootOnly {
  return es_clear_cache(self.decisionClient) == ES_CLEAR_CACHE_RESULT_SUCCESS;
}

@end
