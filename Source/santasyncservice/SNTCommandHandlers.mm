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

#import "Source/santasyncservice/SNTCommandHandlers.h"

#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"

namespace pbv1 = ::santa::commands::v1;
using santa::StringToNSString;

namespace {

void SetKillResponseError(SNTKillResponseError error, ::pbv1::KillResponse* pbResponse) {
  switch (error) {
    case SNTKillResponseErrorListPids:
      pbResponse->set_error(::pbv1::KillResponse::ERROR_LIST_PIDS);
      break;
    case SNTKillResponseErrorInvalidRequest:
      pbResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL);
      break;
    case SNTKillResponseErrorNone:
      // Do not set the error if there was none
      break;
    default: pbResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL); break;
  }
}

void SetKilledProcessError(SNTKilledProcessError error, ::pbv1::KillResponse::Process* pbProcess) {
  switch (error) {
    case SNTKilledProcessErrorUnknown:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INTERNAL);
      break;
    case SNTKilledProcessErrorInvalidTarget:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INVALID_TARGET);
      break;
    case SNTKilledProcessErrorNotPermitted:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_OPERATION_NOT_PERMITTED);
      break;
    case SNTKilledProcessErrorNoSuchProcess:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_NO_SUCH_PROCESS);
      break;
    case SNTKilledProcessErrorInvalidArgument:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INVALID_ARGUMENT);
      break;
    case SNTKilledProcessErrorBootSessionMismatch:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_BOOT_SESSION_MISMATCH);
      break;
    case SNTKilledProcessErrorNone:
      // Do not set the error if there was none
      break;
    default: pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INTERNAL); break;
  }
}

}  // namespace

namespace santa {

::pbv1::PingResponse* HandlePingRequest(const ::pbv1::PingRequest& pingRequest, NSString* uuid,
                                        google::protobuf::Arena* arena) {
  return google::protobuf::Arena::Create<::pbv1::PingResponse>(arena);
}

::pbv1::KillResponse* HandleKillRequest(const ::pbv1::KillRequest& pbKillReq, NSString* uuid,
                                        google::protobuf::Arena* arena,
                                        SNTKillRequestExecutorBlock executor) {
  auto pbKillResponse = google::protobuf::Arena::Create<::pbv1::KillResponse>(arena);
  SNTKillRequest* req;
  switch (pbKillReq.process_case()) {
    case ::pbv1::KillRequest::kRunningProcess:
      req = [[SNTKillRequestRunningProcess alloc]
             initWithUUID:uuid
                      pid:pbKillReq.running_process().pid()
               pidversion:pbKillReq.running_process().pidversion()
          bootSessionUUID:StringToNSString(pbKillReq.running_process().boot_session_uuid())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_RUNNING_PROCESS);
      }
      break;
    case ::pbv1::KillRequest::kCdhash:
      req = [[SNTKillRequestCDHash alloc] initWithUUID:uuid
                                                cdHash:StringToNSString(pbKillReq.cdhash())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_CDHASH);
      }
      break;
    case ::pbv1::KillRequest::kSigningId:
      req = [[SNTKillRequestSigningID alloc] initWithUUID:uuid
                                                signingID:StringToNSString(pbKillReq.signing_id())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_SIGNING_ID);
      }
      break;
    case ::pbv1::KillRequest::kTeamId:
      req = [[SNTKillRequestTeamID alloc] initWithUUID:uuid
                                                teamID:StringToNSString(pbKillReq.team_id())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_TEAM_ID);
      }
      break;
    default: pbKillResponse->set_error(::pbv1::KillResponse::ERROR_UNKNOWN_PROCESS_TYPE);
  }

  if (!req) {
    return pbKillResponse;
  }

  if (!executor) {
    pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL);
    return pbKillResponse;
  }

  SNTKillResponse* resp = executor(req);
  if (!resp) {
    pbKillResponse->set_error(::pbv1::KillResponse::ERROR_TIMEOUT);
    return pbKillResponse;
  }

  SetKillResponseError(resp.error, pbKillResponse);

  for (SNTKilledProcess* killedProc in resp.killedProcesses) {
    auto pbProc = google::protobuf::Arena::Create<::pbv1::KillResponse::Process>(arena);

    pbProc->set_pid(killedProc.pid);
    pbProc->set_pidversion(killedProc.pidversion);
    SetKilledProcessError(killedProc.error, pbProc);

    pbKillResponse->mutable_processes()->UnsafeArenaAddAllocated(pbProc);
  }

  return pbKillResponse;
}

::pbv1::EventUploadResponse* HandleEventUploadRequest(
    const ::pbv1::EventUploadRequest& eventUploadRequest, NSString* uuid,
    google::protobuf::Arena* arena, SNTEventUploadExecutorBlock executor) {
  auto pbResponse = google::protobuf::Arena::Create<::pbv1::EventUploadResponse>(arena);

  NSString* path = StringToNSString(eventUploadRequest.path());
  if (path.length == 0) {
    LOGE(@"EventUploadRequest has empty path");
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INVALID_PATH);
    return pbResponse;
  }

  if (!executor) {
    LOGE(@"EventUploadRequest failed - no executor");
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INTERNAL);
    return pbResponse;
  }

  executor(path);
  return pbResponse;
}

}  // namespace santa
