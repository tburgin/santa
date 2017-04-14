/// Copyright 2016 Google Inc. All rights reserved.
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

@import Foundation;

@class SNTStoredEvent;
@class SNTXPCConnection;

@interface SNTSyncdQueue : NSObject

@property(nonatomic) SNTXPCConnection *syncdConnection;
@property(copy) void (^invalidationHandler)();
@property(copy) void (^acceptedHandler)();

- (void)addEvent:(SNTStoredEvent *)event;
- (void)addBundleEvents:(NSArray<SNTStoredEvent *> *)events;
- (void)addBundleEvent:(SNTStoredEvent *)event reply:(void (^)(BOOL))reply;
- (void)startSyncingEvents;
- (void)stopSyncingEvents;

@end