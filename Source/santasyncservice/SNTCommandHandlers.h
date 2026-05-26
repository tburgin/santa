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

#ifndef SANTA_SANTASYNCSERVICE_SNTCOMMANDHANDLERS_H
#define SANTA_SANTASYNCSERVICE_SNTCOMMANDHANDLERS_H

#import <Foundation/Foundation.h>

#include <google/protobuf/arena.h>

#import "Source/common/SNTKillCommand.h"
#include "commands/v1.pb.h"

namespace santa {

// Block invoked by HandleKillRequest to actually dispatch the built
// SNTKillRequest to santad. The caller owns the XPC connection and the
// timeout policy: returning nil signals that no response was obtained
// (treated as ERROR_TIMEOUT by HandleKillRequest).
typedef SNTKillResponse* (^SNTKillRequestExecutorBlock)(SNTKillRequest* request);

// HandleKillRequest implements the agent-side Kill command: builds the
// appropriate SNTKillRequest subclass from the proto oneof, hands it to
// `executor` for delivery to santad, and translates the response back into
// the typed proto. The executor owns the XPC call and any timeout — return
// nil to signal a timeout/no-reply (mapped to ERROR_TIMEOUT in the proto).
// Owned by the shared command-handlers TU so both the NATS-RPC path
// (SNTPushClientNATS+Commands) and the HTTP /commands stage (SNTSyncCommands)
// can dispatch the same way.
::santa::commands::v1::KillResponse* HandleKillRequest(
    const ::santa::commands::v1::KillRequest& request, NSString* commandUUID,
    google::protobuf::Arena* arena, SNTKillRequestExecutorBlock executor);

// Block invoked by HandleEventUploadRequest to kick off the bundle-walk for
// the validated path. The caller owns the XPC call and any reply handling;
// the handler doesn't wait for completion.
typedef void (^SNTEventUploadExecutorBlock)(NSString* path);

// HandleEventUploadRequest validates the path and hands it to `executor` to
// fire the bundle-walk asynchronously. The discovered events are uploaded
// via the regular sync EventUpload path; this call returns immediately with
// success when the executor was invoked, or with INVALID_PATH / INTERNAL on
// a synchronous failure.
::santa::commands::v1::EventUploadResponse* HandleEventUploadRequest(
    const ::santa::commands::v1::EventUploadRequest& request, NSString* commandUUID,
    google::protobuf::Arena* arena, SNTEventUploadExecutorBlock executor);

// HandlePingRequest is a no-op. Only the legacy NATS path uses it — the
// HTTP /commands channel doesn't carry pings. Kept here for symmetry so the
// NATS dispatcher can call into a single set of shared handlers.
::santa::commands::v1::PingResponse* HandlePingRequest(
    const ::santa::commands::v1::PingRequest& request, NSString* commandUUID,
    google::protobuf::Arena* arena);

}  // namespace santa

#endif  // SANTA_SANTASYNCSERVICE_SNTCOMMANDHANDLERS_H
