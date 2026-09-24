/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "allocd/alloc_ipv6.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/strings/ascii.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"

#include "allocd/alloc_driver.h"
#include "allocd/alloc_utils.h"
#include "cuttlefish/common/libs/fs/shared_buf.h"
#include "cuttlefish/common/libs/fs/shared_fd.h"
#include "cuttlefish/common/libs/utils/files.h"
#include "cuttlefish/files/file_exists.h"
#include "cuttlefish/host/commands/cvd/utils/common.h"
#include "cuttlefish/process/execute.h"
#include "cuttlefish/result/result.h"

namespace cuttlefish {
namespace {

constexpr std::string_view kDnsmasqComm = "dnsmasq";

std::string Ipv6SysctlPath(std::string_view interface, std::string_view key) {
  return absl::StrCat("/proc/sys/net/ipv6/conf/", interface, "/", key);
}

Result<void> WriteSysctl(const std::string& path, std::string_view value) {
  SharedFD fd = SharedFD::Open(path, O_WRONLY | O_CLOEXEC);
  CF_EXPECTF(fd->IsOpen(), "Failed to open '{}': {}", path, fd->StrError());
  CF_EXPECTF(WriteAll(fd, value) == static_cast<ssize_t>(value.size()),
             "Failed to write '{}' to '{}': {}", value, path, fd->StrError());
  return {};
}

std::string RouterAdvertisementPidFile(std::string_view interface) {
  return absl::StrCat(CvdDir(), "/cuttlefish-dnsmasq6-", interface, ".pid");
}

std::string RouterAdvertisementLeaseFile(std::string_view interface) {
  return absl::StrCat(CvdDir(), "/cuttlefish-dnsmasq6-", interface, ".leases");
}

// Returns the pid of the dnsmasq recorded in `pid_file`, if it is running.
Result<pid_t> RunningDnsmasqPid(const std::string& pid_file) {
  CF_EXPECTF(FileExists(pid_file), "No pid file '{}'", pid_file);
  std::string contents = CF_EXPECT(ReadFileContents(pid_file));
  pid_t pid = 0;
  CF_EXPECTF(
      absl::SimpleAtoi(absl::StripAsciiWhitespace(contents), &pid) && pid > 0,
      "Invalid pid file '{}'", pid_file);
  std::string comm =
      CF_EXPECT(ReadFileContents(absl::StrCat("/proc/", pid, "/comm")));
  CF_EXPECTF(absl::StripAsciiWhitespace(comm) == kDnsmasqComm,
             "Process {} from '{}' is not dnsmasq", pid, pid_file);
  return pid;
}

Result<void> StartRouterAdvertisements(const Ipv6Gateway& gateway) {
  std::string pid_file = RouterAdvertisementPidFile(gateway.interface);
  if (RunningDnsmasqPid(pid_file).has_value()) {
    LOG(INFO) << "Router Advertisements already running on "
              << gateway.interface;
    return {};
  }
  std::string dnsmasq_path = CF_EXPECT(DnsmasqPath());
  std::vector<std::string> args =
      Ipv6RouterAdvertisementArgs(dnsmasq_path, gateway, pid_file);
  CF_EXPECTF(Execute(args) == 0, "Failed to start '{}'",
             absl::StrJoin(args, " "));
  return {};
}

Result<void> StopRouterAdvertisements(std::string_view interface) {
  std::string pid_file = RouterAdvertisementPidFile(interface);
  if (!FileExists(pid_file)) {
    return {};
  }
  Result<pid_t> pid = RunningDnsmasqPid(pid_file);
  if (pid.has_value()) {
    LOG(INFO) << "Stopping Router Advertisements on " << interface;
    CF_EXPECTF(kill(*pid, SIGTERM) == 0, "kill({}): {}", *pid, strerror(errno));
  }
  CF_EXPECTF(unlink(pid_file.c_str()) == 0 || errno == ENOENT,
             "unlink('{}'): {}", pid_file, strerror(errno));
  std::string lease_file = RouterAdvertisementLeaseFile(interface);
  CF_EXPECTF(unlink(lease_file.c_str()) == 0 || errno == ENOENT,
             "unlink('{}'): {}", lease_file, strerror(errno));
  return {};
}

}  // namespace

std::string Ipv6Gateway::Address() const { return prefix + "1"; }

std::string Ipv6Gateway::Cidr() const {
  return absl::StrCat(prefix, "/", prefix_length);
}

std::vector<std::string> Ipv6RouterAdvertisementArgs(
    std::string_view dnsmasq_path, const Ipv6Gateway& gateway,
    std::string_view pid_file) {
  std::vector<std::string> dns_servers;
  for (std::string_view server : kIpv6DnsServers) {
    dns_servers.push_back(absl::StrCat("[", server, "]"));
  }
  return {
      std::string(dnsmasq_path),
      // No DNS service, no configuration file: RA only.
      "--port=0",
      "--conf-file=",
      "--except-interface=lo",
      absl::StrCat("--interface=", gateway.interface),
      "--bind-interfaces",
      "--enable-ra",
      absl::StrCat("--dhcp-range=", gateway.prefix, ",ra-only,",
                   gateway.prefix_length),
      absl::StrCat("--dhcp-option=option6:dns-server,",
                   absl::StrJoin(dns_servers, ",")),
      absl::StrCat("--pid-file=", pid_file),
      absl::StrCat("--dhcp-leasefile=",
                   RouterAdvertisementLeaseFile(gateway.interface)),
  };
}

Result<void> IgnoreRouterAdvertisements(std::string_view interface) {
  CF_EXPECT(WriteSysctl(Ipv6SysctlPath(interface, "accept_ra"), "0"));
  CF_EXPECT(WriteSysctl(Ipv6SysctlPath(interface, "autoconf"), "0"));
  return {};
}

Result<void> SetupIpv6Gateway(const Ipv6Gateway& gateway) {
  LOG(INFO) << "Configuring IPv6 gateway " << gateway.Address() << "/"
            << gateway.prefix_length << " on " << gateway.interface;
  CF_EXPECT(
      WriteSysctl(Ipv6SysctlPath(gateway.interface, "disable_ipv6"), "0"));
  CF_EXPECT(IgnoreRouterAdvertisements(gateway.interface));
  CF_EXPECT(AddIpv6Address(gateway.interface, gateway.Address(),
                           gateway.prefix_length));
  for (const Ipv6Route& route : gateway.routes) {
    CF_EXPECT(AddIpv6Route(gateway.interface, route.prefix, route.prefix_length,
                           route.via));
  }
  if (gateway.advertise) {
    CF_EXPECT(StartRouterAdvertisements(gateway));
  }
  return {};
}

Result<void> TeardownIpv6Gateway(const Ipv6Gateway& gateway) {
  LOG(INFO) << "Removing IPv6 gateway " << gateway.Address() << "/"
            << gateway.prefix_length << " from " << gateway.interface;
  std::vector<Result<void>> results;
  if (gateway.advertise) {
    results.emplace_back(StopRouterAdvertisements(gateway.interface));
  }
  for (const Ipv6Route& route : gateway.routes) {
    results.emplace_back(DeleteIpv6Route(gateway.interface, route.prefix,
                                         route.prefix_length, route.via));
  }
  results.emplace_back(DeleteIpv6Address(gateway.interface, gateway.Address(),
                                         gateway.prefix_length));
  for (Result<void>& result : results) {
    CF_EXPECT(std::move(result));
  }
  return {};
}

Result<bool> BridgeIsUnused(std::string_view bridge_name) {
  if (!CF_EXPECT(BridgeExists(bridge_name))) {
    return false;
  }
  return !CF_EXPECT(BridgeInUse(bridge_name));
}

Result<bool> Ipv6ForwardingEnabled() {
  std::string value =
      CF_EXPECT(ReadFileContents(Ipv6SysctlPath("all", "forwarding")));
  return absl::StripAsciiWhitespace(value) == "1";
}

Result<SharedFD> LockIpv6Configuration() {
  std::string path = absl::StrCat(CvdDir(), "/cuttlefish-ipv6.lock");
  SharedFD fd = SharedFD::Open(path, O_RDONLY | O_CREAT | O_CLOEXEC, 0644);
  CF_EXPECTF(fd->IsOpen(), "Failed to open '{}': {}", path, fd->StrError());
  CF_EXPECT(fd->Flock(LOCK_EX));
  return fd;
}

}  // namespace cuttlefish
