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

#import "Source/santasyncservice/SNTSyncStage.h"

/// SNTSyncCommands is the HTTP /commands sync stage. It POSTs an empty
/// pull-only request to /commands/{machine_id}, and if the server returns
/// any QueuedCommands the stage dispatches their execution onto a
/// background queue so the rest of the sync flow isn't blocked. Once the
/// commands have all run, a single CommandsRequest with every CommandResult
/// is POSTed back; the post-back is best-effort and won't be retried on
/// failure.
@interface SNTSyncCommands : SNTSyncStage
@end
