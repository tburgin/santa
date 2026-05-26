/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/santasyncservice/SNTSyncCommands.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#include "Source/common/String.h"
#import "Source/santasyncservice/SNTCommandHandlers.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include <google/protobuf/arena.h>

#include "commands/v1.pb.h"
#include "syncv2/v2.pb.h"

namespace pbv1 = ::santa::commands::v1;
namespace pbv2 = ::santa::sync::v2;

using santa::NSStringToUTF8String;
using santa::StringToNSString;

// Semi-arbitrary number of seconds to wait for santad to finish killing
// processes. Matches the value the NATS path uses.
static constexpr int64_t kKillResponseTimeoutSeconds = 90;

@interface SNTSyncCommands ()
- (void)executeAndPostBack:(NSArray<NSData*>*)serializedCommands;
@end

namespace {

// ExecuteOneCommand dispatches a single QueuedCommand through the shared
// handler module and writes the corresponding CommandResult into `result`.
// Lives as a file-static helper rather than an Objective-C method because
// ObjC parameter parsing is finicky about leading `::` C++ type names.
// The caller supplies prebuilt executor blocks for kill and event-upload;
// either may be nil, which the underlying handler maps to ERROR_INTERNAL.
void ExecuteOneCommand(const ::pbv1::QueuedCommand& cmd, ::pbv1::CommandResult* result,
                       google::protobuf::Arena* arena,
                       santa::SNTKillRequestExecutorBlock killExecutor,
                       santa::SNTEventUploadExecutorBlock eventUploadExecutor) {
  result->set_command_id(cmd.command_id());

  // Allowed-commands gate — mirrors the NATS dispatcher's behaviour.
  NSString* commandName = nil;
  switch (cmd.command_case()) {
    case ::pbv1::QueuedCommand::kKill: commandName = @"kill"; break;
    case ::pbv1::QueuedCommand::kEventUpload: commandName = @"event_upload"; break;
    case ::pbv1::QueuedCommand::COMMAND_NOT_SET: break;
  }
  if (commandName) {
    NSArray<NSString*>* allowed = [[SNTConfigurator configurator] allowedSantaCommands];
    if (allowed && ![allowed containsObject:commandName]) {
      LOGW(@"Commands: '%@' rejected — not in AllowedSantaCommands", commandName);
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_REJECTED);
      result->set_error_message(NSStringToUTF8String([NSString
          stringWithFormat:@"Command '%@' is not in AllowedSantaCommands", commandName]));
      return;
    }
  }

  // The shared handlers expect a UUID for logging; the HTTP channel has no
  // transport-level uuid so synthesize one per execution.
  NSString* uuid = [[NSUUID UUID] UUIDString];

  switch (cmd.command_case()) {
    case ::pbv1::QueuedCommand::kKill: {
      auto* killResp = santa::HandleKillRequest(cmd.kill(), uuid, arena, killExecutor);
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_COMPLETE);
      result->unsafe_arena_set_allocated_kill(killResp);
      return;
    }
    case ::pbv1::QueuedCommand::kEventUpload: {
      auto* euResp =
          santa::HandleEventUploadRequest(cmd.event_upload(), uuid, arena, eventUploadExecutor);
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_COMPLETE);
      result->unsafe_arena_set_allocated_event_upload(euResp);
      return;
    }
    case ::pbv1::QueuedCommand::COMMAND_NOT_SET:
    default:
      LOGE(@"Commands: unknown or unset command type for command_id=%lld", cmd.command_id());
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_FAILED);
      result->set_error_message("Unknown or unset command type");
      return;
  }
}

}  // namespace

@implementation SNTSyncCommands

- (NSURL*)stageURL {
  NSString* stageName = [@"commands" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  // First request is pull-only — empty results. Workshop responds with any
  // commands currently queued for this host.
  google::protobuf::Arena arena;
  auto* req = google::protobuf::Arena::Create<::pbv2::CommandsRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));

  auto* resp = google::protobuf::Arena::Create<::pbv2::CommandsResponse>(&arena);
  NSError* err = [self performRequest:[self requestWithMessage:req] intoMessage:resp timeout:30];
  if (err) {
    SLOGE(@"Commands stage POST failed: %@", err);
    return NO;
  }

  if (resp->commands_size() == 0) {
    return YES;
  }

  // Serialize the queued commands so we can hand them off to a background
  // queue without sharing arena-allocated proto pointers. Each NSData holds
  // one wire-format QueuedCommand.
  NSMutableArray<NSData*>* serialized = [NSMutableArray arrayWithCapacity:resp->commands_size()];
  for (int i = 0; i < resp->commands_size(); i++) {
    std::string buf;
    if (!resp->commands(i).SerializeToString(&buf)) {
      LOGW(@"Skipping malformed QueuedCommand at index %d", i);
      continue;
    }
    [serialized addObject:[NSData dataWithBytes:buf.data() length:buf.size()]];
  }

  if (serialized.count == 0) {
    return YES;
  }

  SLOGI(@"Commands stage received %lu queued command(s); dispatching async",
        (unsigned long)serialized.count);

  // Hand the executions off to a background queue so the rest of the sync
  // flow isn't blocked. Capturing `self` keeps the stage (and its sync
  // state) alive until the block completes — `_syncState` carries the
  // sync delegate, daemon connection, URL session, etc.
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    [self executeAndPostBack:serialized];
  });

  return YES;
}

// executeAndPostBack runs every queued command serially through the shared
// handlers, then POSTs a single CommandsRequest carrying every result back
// to /commands. The post-back is best-effort: a failure is logged and
// dropped, never retried.
- (void)executeAndPostBack:(NSArray<NSData*>*)serializedCommands {
  google::protobuf::Arena arena;
  auto* req = google::protobuf::Arena::Create<::pbv2::CommandsRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));

  MOLXPCConnection* daemonConn = self.daemonConn;
  santa::SNTKillRequestExecutorBlock killExecutor = ^SNTKillResponse*(SNTKillRequest* killReq) {
    if (!daemonConn) {
      return nil;
    }
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block SNTKillResponse* resp;
    [[daemonConn remoteObjectProxy] killProcesses:killReq
                                            reply:^(SNTKillResponse* killResponse) {
                                              resp = killResponse;
                                              dispatch_semaphore_signal(sema);
                                            }];
    if (dispatch_semaphore_wait(
            sema, dispatch_time(DISPATCH_TIME_NOW,
                                kKillResponseTimeoutSeconds * NSEC_PER_SEC)) != 0) {
      return nil;
    }
    return resp;
  };

  id<SNTSyncStageDelegate> delegate = self.delegate;
  santa::SNTEventUploadExecutorBlock eventUploadExecutor = nil;
  if (delegate) {
    eventUploadExecutor = ^(NSString* path) {
      [delegate eventUploadForPath:path
                             reply:^(NSError* error) {
                               if (error) {
                                 LOGE(@"EventUploadRequest failed for path %@: %@", path, error);
                               } else {
                                 LOGI(@"EventUploadRequest completed for path %@", path);
                               }
                             }];
    };
  }

  for (NSData* data in serializedCommands) {
    ::pbv1::QueuedCommand cmd;
    if (!cmd.ParseFromArray(data.bytes, static_cast<int>(data.length))) {
      LOGW(@"Skipping QueuedCommand that failed to parse");
      continue;
    }
    auto* result = req->add_results();
    ExecuteOneCommand(cmd, result, &arena, killExecutor, eventUploadExecutor);
  }

  SLOGI(@"Posting back %d command result(s)", req->results_size());

  auto* resp = google::protobuf::Arena::Create<::pbv2::CommandsResponse>(&arena);
  NSError* err = [self performRequest:[self requestWithMessage:req] intoMessage:resp timeout:30];
  if (err) {
    // Best-effort: log and move on. The next regular /commands sync will
    // re-receive any commands that are still QUEUED on the server.
    SLOGW(@"Failed to post back command results (%d result(s) dropped): %@", req->results_size(),
          err);
    return;
  }

  if (resp->commands_size() > 0) {
    // Newly queued commands in the post-back response are intentionally
    // ignored — they'll be picked up by the next regular sync cycle. Keeps
    // the stage simple and avoids recursion.
    SLOGD(@"Post-back response carried %d newly queued command(s); will pick up next sync",
          resp->commands_size());
  }
}

@end
