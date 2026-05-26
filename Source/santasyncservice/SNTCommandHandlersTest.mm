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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <google/protobuf/arena.h>

#import "Source/common/SNTKillCommand.h"
#import "Source/santasyncservice/SNTCommandHandlers.h"
#include "commands/v1.pb.h"

namespace pbv1 = ::santa::commands::v1;

// 40 hex characters — a valid CDHash per santa::IsValidCDHash.
static NSString* const kValidCDHash = @"abcdef0123456789abcdef0123456789abcdef01";
// 10 alphanumeric characters — a valid team ID per santa::IsValidTeamID.
static NSString* const kValidTeamID = @"ABCDE12345";
// A valid <teamID>:<signingID> per santa::SplitSigningID.
static NSString* const kValidSigningID = @"ABCDE12345:com.example.app";
// 32-char lowercase hex — a valid short-form bootSessionUUID.
static NSString* const kValidBootSessionUUID = @"abcdef0123456789abcdef0123456789";

@interface SNTCommandHandlersTest : XCTestCase
@property google::protobuf::Arena* arena;
@end

@implementation SNTCommandHandlersTest

- (void)setUp {
  [super setUp];
  self.arena = new google::protobuf::Arena();
}

- (void)tearDown {
  delete self.arena;
  self.arena = nullptr;
  [super tearDown];
}

#pragma mark - HandlePingRequest

- (void)testHandlePingRequestReturnsResponse {
  pbv1::PingRequest pingReq;
  pbv1::PingResponse* resp = santa::HandlePingRequest(pingReq, @"uuid", self.arena);
  XCTAssertNotEqual(resp, nullptr);
}

#pragma mark - HandleKillRequest oneof dispatch

- (void)testHandleKillRequestRunningProcessValidInvokesExecutor {
  pbv1::KillRequest req;
  auto* rp = req.mutable_running_process();
  rp->set_pid(1234);
  rp->set_pidversion(5);
  rp->set_boot_session_uuid([kValidBootSessionUUID UTF8String]);

  __block BOOL invoked = NO;
  __block SNTKillRequest* receivedReq = nil;
  santa::SNTKillRequestExecutorBlock executor =
      ^SNTKillResponse*(SNTKillRequest* sntReq) {
        invoked = YES;
        receivedReq = sntReq;
        return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
      };

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, executor);

  XCTAssertTrue(invoked);
  XCTAssertTrue([receivedReq isKindOfClass:[SNTKillRequestRunningProcess class]]);
  SNTKillRequestRunningProcess* rpReq = (SNTKillRequestRunningProcess*)receivedReq;
  XCTAssertEqual(rpReq.pid, 1234);
  XCTAssertEqual(rpReq.pidversion, 5);
  XCTAssertEqualObjects(rpReq.bootSessionUUID, kValidBootSessionUUID);
  XCTAssertFalse(resp->has_error());
}

- (void)testHandleKillRequestRunningProcessInvalidReturnsError {
  pbv1::KillRequest req;
  auto* rp = req.mutable_running_process();
  rp->set_pid(0);  // SNTKillRequestRunningProcess returns nil for pid==0
  rp->set_pidversion(5);
  rp->set_boot_session_uuid([kValidBootSessionUUID UTF8String]);

  __block BOOL invoked = NO;
  santa::SNTKillRequestExecutorBlock executor =
      ^SNTKillResponse*(SNTKillRequest* sntReq) {
        invoked = YES;
        return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
      };

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, executor);

  XCTAssertFalse(invoked, @"Executor must not run when the request can't be built");
  XCTAssertTrue(resp->has_error());
  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_INVALID_RUNNING_PROCESS);
}

- (void)testHandleKillRequestCDHashValidInvokesExecutor {
  pbv1::KillRequest req;
  req.set_cdhash([kValidCDHash UTF8String]);

  __block SNTKillRequest* receivedReq = nil;
  santa::SNTKillRequestExecutorBlock executor =
      ^SNTKillResponse*(SNTKillRequest* sntReq) {
        receivedReq = sntReq;
        return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
      };

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, executor);

  XCTAssertTrue([receivedReq isKindOfClass:[SNTKillRequestCDHash class]]);
  XCTAssertEqualObjects(((SNTKillRequestCDHash*)receivedReq).cdhash, kValidCDHash);
  XCTAssertFalse(resp->has_error());
}

- (void)testHandleKillRequestCDHashInvalidReturnsError {
  pbv1::KillRequest req;
  req.set_cdhash("not-a-real-hash");

  __block BOOL invoked = NO;
  santa::SNTKillRequestExecutorBlock executor =
      ^SNTKillResponse*(SNTKillRequest* sntReq) {
        invoked = YES;
        return nil;
      };

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, executor);

  XCTAssertFalse(invoked);
  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_INVALID_CDHASH);
}

- (void)testHandleKillRequestSigningIDValidInvokesExecutor {
  pbv1::KillRequest req;
  req.set_signing_id([kValidSigningID UTF8String]);

  __block SNTKillRequest* receivedReq = nil;
  santa::SNTKillRequestExecutorBlock executor =
      ^SNTKillResponse*(SNTKillRequest* sntReq) {
        receivedReq = sntReq;
        return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
      };

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, executor);

  XCTAssertTrue([receivedReq isKindOfClass:[SNTKillRequestSigningID class]]);
  XCTAssertFalse(resp->has_error());
}

- (void)testHandleKillRequestSigningIDInvalidReturnsError {
  pbv1::KillRequest req;
  req.set_signing_id("no-colon-no-team");

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return nil;
      });

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_INVALID_SIGNING_ID);
}

- (void)testHandleKillRequestTeamIDValidInvokesExecutor {
  pbv1::KillRequest req;
  req.set_team_id([kValidTeamID UTF8String]);

  __block SNTKillRequest* receivedReq = nil;
  santa::SNTKillRequestExecutorBlock executor =
      ^SNTKillResponse*(SNTKillRequest* sntReq) {
        receivedReq = sntReq;
        return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
      };

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, executor);

  XCTAssertTrue([receivedReq isKindOfClass:[SNTKillRequestTeamID class]]);
  XCTAssertEqualObjects(((SNTKillRequestTeamID*)receivedReq).teamID, kValidTeamID);
  XCTAssertFalse(resp->has_error());
}

- (void)testHandleKillRequestTeamIDInvalidReturnsError {
  pbv1::KillRequest req;
  req.set_team_id("too-short");

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return nil;
      });

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_INVALID_TEAM_ID);
}

- (void)testHandleKillRequestProcessNotSetReturnsError {
  pbv1::KillRequest req;  // no oneof set

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return nil;
      });

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_UNKNOWN_PROCESS_TYPE);
}

#pragma mark - HandleKillRequest executor edge cases

- (void)testHandleKillRequestNilExecutorReturnsInternal {
  pbv1::KillRequest req;
  req.set_team_id([kValidTeamID UTF8String]);

  pbv1::KillResponse* resp = santa::HandleKillRequest(req, @"uuid", self.arena, nil);

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_INTERNAL);
}

- (void)testHandleKillRequestExecutorReturnsNilMapsToTimeout {
  pbv1::KillRequest req;
  req.set_team_id([kValidTeamID UTF8String]);

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return nil;
      });

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_TIMEOUT);
}

- (void)testHandleKillRequestExecutorErrorPropagates {
  pbv1::KillRequest req;
  req.set_team_id([kValidTeamID UTF8String]);

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorListPids];
      });

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_LIST_PIDS);
}

- (void)testHandleKillRequestExecutorInvalidRequestErrorMapsToInternal {
  pbv1::KillRequest req;
  req.set_team_id([kValidTeamID UTF8String]);

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorInvalidRequest];
      });

  XCTAssertEqual(resp->error(), pbv1::KillResponse::ERROR_INTERNAL);
}

- (void)testHandleKillRequestKilledProcessesCopiedToResponse {
  pbv1::KillRequest req;
  req.set_team_id([kValidTeamID UTF8String]);

  SNTKilledProcess* k1 =
      [[SNTKilledProcess alloc] initWithPid:111
                                 pidversion:1
                                      error:SNTKilledProcessErrorNone];
  SNTKilledProcess* k2 =
      [[SNTKilledProcess alloc] initWithPid:222
                                 pidversion:2
                                      error:SNTKilledProcessErrorNoSuchProcess];

  pbv1::KillResponse* resp = santa::HandleKillRequest(
      req, @"uuid", self.arena, ^SNTKillResponse*(SNTKillRequest* sntReq) {
        return [[SNTKillResponse alloc] initWithKilledProcesses:@[ k1, k2 ]];
      });

  XCTAssertFalse(resp->has_error());
  XCTAssertEqual(resp->processes_size(), 2);
  XCTAssertEqual(resp->processes(0).pid(), 111);
  XCTAssertEqual(resp->processes(0).pidversion(), 1);
  XCTAssertFalse(resp->processes(0).has_error());
  XCTAssertEqual(resp->processes(1).pid(), 222);
  XCTAssertEqual(resp->processes(1).pidversion(), 2);
  XCTAssertEqual(resp->processes(1).error(), pbv1::KillResponse::KILL_ERROR_NO_SUCH_PROCESS);
}

#pragma mark - HandleEventUploadRequest

- (void)testHandleEventUploadRequestEmptyPathReturnsInvalidPath {
  pbv1::EventUploadRequest req;
  // path left empty

  __block BOOL invoked = NO;
  santa::SNTEventUploadExecutorBlock executor = ^(NSString* path) {
    invoked = YES;
  };

  pbv1::EventUploadResponse* resp =
      santa::HandleEventUploadRequest(req, @"uuid", self.arena, executor);

  XCTAssertFalse(invoked);
  XCTAssertEqual(resp->error(), pbv1::EventUploadResponse::ERROR_INVALID_PATH);
}

- (void)testHandleEventUploadRequestNilExecutorReturnsInternal {
  pbv1::EventUploadRequest req;
  req.set_path("/Applications/Safari.app");

  pbv1::EventUploadResponse* resp =
      santa::HandleEventUploadRequest(req, @"uuid", self.arena, nil);

  XCTAssertEqual(resp->error(), pbv1::EventUploadResponse::ERROR_INTERNAL);
}

- (void)testHandleEventUploadRequestSuccessInvokesExecutor {
  pbv1::EventUploadRequest req;
  req.set_path("/Applications/Safari.app");

  __block NSString* receivedPath = nil;
  santa::SNTEventUploadExecutorBlock executor = ^(NSString* path) {
    receivedPath = path;
  };

  pbv1::EventUploadResponse* resp =
      santa::HandleEventUploadRequest(req, @"uuid", self.arena, executor);

  XCTAssertEqualObjects(receivedPath, @"/Applications/Safari.app");
  XCTAssertFalse(resp->has_error());
}

@end
