/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__SANTAD_MACH_SERVICE_DEAD_WAITER_H
#define SANTA__SANTAD_MACH_SERVICE_DEAD_WAITER_H

#include <mach/mach.h>
#include <servers/bootstrap.h>

#include <string>

class MachServiceDeadWaiter {
 public:
  explicit MachServiceDeadWaiter(std::string service_name);
  MachServiceDeadWaiter(const MachServiceDeadWaiter &) = delete;
  MachServiceDeadWaiter &operator=(const MachServiceDeadWaiter &) = delete;
  ~MachServiceDeadWaiter();

  bool service_seen() { return service_seen_; };

 private:
  std::string service_name_;
  bool service_seen_ = false;
  mach_port_t send_port_;
  mach_port_t receive_port_;
};

#endif