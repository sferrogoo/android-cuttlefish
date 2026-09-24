/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"

#include "allocd/alloc_ipv6.h"
#include "allocd/alloc_utils.h"
#include "allocd/ipv6_firewall.h"
#include "allocd/net/nftables.h"
#include "allocd/net/nftables_nft.h"
#include "cuttlefish/common/libs/fs/shared_fd.h"
#include "cuttlefish/host/commands/cvdalloc/interface.h"
#include "cuttlefish/host/commands/cvdalloc/privilege.h"
#include "cuttlefish/host/commands/cvdalloc/sem.h"
#include "cuttlefish/posix/strerror.h"
#include "cuttlefish/result/expect.h"
#include "cuttlefish/result/result_type.h"

ABSL_FLAG(int, id, 0, "Id");
ABSL_FLAG(int, socket, 0, "Socket");

namespace cuttlefish {
namespace {

void Usage() {
  LOG(ERROR) << "cvdalloc --id=id --socket=fd ";
  LOG(ERROR) << "Should only be invoked from run_cvd.";
}

Ipv6Gateway MobileIpv6Gateway(int id) {
  return Ipv6Gateway{
      .interface = CvdallocInterfaceName("mtap", id),
      .prefix = InstanceToMobileIpv6Prefix(id),
      .prefix_length = kCvdallocIpv6PrefixLength,
      // Router Advertisements provide the default route and RDNSS; the
      // modem simulator provides the address over the RIL.
      .advertise = true,
  };
}

Ipv6Gateway WifiApIpv6Gateway(int id) {
  return Ipv6Gateway{
      .interface = CvdallocInterfaceName("wifiap", id),
      .prefix = InstanceToWifiApIpv6Prefix(id),
      .prefix_length = kCvdallocIpv6PrefixLength,
      // OpenWrt configures its WAN statically from the kernel command line.
      .advertise = false,
      // The OpenWrt LAN (Android wlan0) is routed through the OpenWrt WAN.
      .routes = {Ipv6Route{
          .prefix = InstanceToWifiLanIpv6Prefix(id),
          .prefix_length = kCvdallocIpv6PrefixLength,
          .via = InstanceToWifiApIpv6Address(id),
      }},
  };
}

Ipv6Gateway BridgeIpv6Gateway(std::string_view bridge_name,
                              std::string prefix) {
  return Ipv6Gateway{
      .interface = std::string(bridge_name),
      .prefix = std::move(prefix),
      .prefix_length = kCvdallocIpv6PrefixLength,
      .advertise = true,
  };
}

// IPv6 state of one instance. Shared bridge state (address, Router
// Advertisements, NAT66 rule) is idempotently ensured by every instance and
// only removed together with the bridge.
class Ipv6Allocation {
 public:
  Ipv6Allocation(int id, std::string_view ethernet_bridge_name,
                 std::string_view wireless_bridge_name, Nftables& nft)
      : id_(id),
        ethernet_bridge_(BridgeIpv6Gateway(ethernet_bridge_name,
                                           CvdallocEthernetIpv6Prefix())),
        wireless_bridge_(BridgeIpv6Gateway(wireless_bridge_name,
                                           CvdallocBridgedWifiIpv6Prefix())),
        firewall_(nft) {}

  Result<void> Allocate() {
    CF_EXPECTF(id_ >= 1 && id_ <= static_cast<int>(kMaxIfaceNameId),
               "Instance id {} is outside the IPv6 address plan", id_);
    SharedFD lock = CF_EXPECT(LockIpv6Configuration());

    Result<bool> forwarding = Ipv6ForwardingEnabled();
    if (!forwarding.has_value() || !*forwarding) {
      LOG(WARNING) << "IPv6 forwarding is disabled on the host "
                      "(net.ipv6.conf.all.forwarding); guests will only reach "
                      "the host over IPv6.";
    }

    Ipv6Gateway mobile = MobileIpv6Gateway(id_);
    CF_EXPECT(SetupIpv6Gateway(mobile));
    CF_EXPECT(firewall_.AddMasquerade(mobile.interface, mobile.Cidr()));

    Ipv6Gateway wifi_ap = WifiApIpv6Gateway(id_);
    CF_EXPECT(SetupIpv6Gateway(wifi_ap));
    CF_EXPECT(firewall_.AddMasquerade(wifi_ap.interface, wifi_ap.Cidr()));
    for (const Ipv6Route& route : wifi_ap.routes) {
      CF_EXPECT(firewall_.AddMasquerade(
          absl::StrCat(wifi_ap.interface, "-lan"),
          absl::StrCat(route.prefix, "/", route.prefix_length)));
    }

    for (const Ipv6Gateway* bridge : {&ethernet_bridge_, &wireless_bridge_}) {
      CF_EXPECT(SetupIpv6Gateway(*bridge));
      CF_EXPECT(
          firewall_.EnsureSharedMasquerade(bridge->interface, bridge->Cidr()));
    }
    for (const std::string port : {"etap", "wtap"}) {
      std::string port_name = CvdallocInterfaceName(port, id_);
      CF_EXPECT(IgnoreRouterAdvertisements(port_name));
      CF_EXPECT(firewall_.AddRouterAdvertisementGuard(port_name));
    }

    LOG(INFO) << "cvdalloc: IPv6 allocated for instance " << id_;
    return {};
  }

  // Removes the per-instance IPv6 state. Must run before the instance taps
  // are destroyed.
  Result<void> ReleaseInstance() {
    SharedFD lock = CF_EXPECT(LockIpv6Configuration());
    Result<void> wifi_ap = TeardownIpv6Gateway(WifiApIpv6Gateway(id_));
    Result<void> mobile = TeardownIpv6Gateway(MobileIpv6Gateway(id_));
    firewall_.ReleaseOwnedRules();
    CF_EXPECT(std::move(wifi_ap));
    CF_EXPECT(std::move(mobile));
    return {};
  }

  // Removes the shared IPv6 state of bridges that no instance uses anymore.
  // Must run after the instance taps are destroyed and before the bridges are.
  Result<void> ReleaseUnusedBridges() {
    SharedFD lock = CF_EXPECT(LockIpv6Configuration());
    std::vector<Result<void>> results;
    for (const Ipv6Gateway* bridge : {&ethernet_bridge_, &wireless_bridge_}) {
      Result<bool> unused = BridgeIsUnused(bridge->interface);
      if (!unused.has_value() || !*unused) {
        continue;
      }
      results.emplace_back(firewall_.RemoveSharedMasquerade(bridge->interface));
      results.emplace_back(TeardownIpv6Gateway(*bridge));
    }
    results.emplace_back(firewall_.DeleteEmptyTables());
    for (Result<void>& result : results) {
      CF_EXPECT(std::move(result));
    }
    return {};
  }

 private:
  int id_;
  Ipv6Gateway ethernet_bridge_;
  Ipv6Gateway wireless_bridge_;
  Ipv6Firewall firewall_;
};

Result<void> Allocate(int id, std::string_view ethernet_bridge_name,
                      std::string_view wireless_bridge_name,
                      Ipv6Allocation& ipv6) {
  LOG(INFO) << "cvdalloc: allocating network resources";

  CF_EXPECT(CreateMobileIface(CvdallocInterfaceName("mtap", id), id,
                              kCvdallocMobileIpPrefix));
  CF_EXPECT(CreateEthernetBridgeIface(wireless_bridge_name,
                                      kCvdallocWirelessIpPrefix));
  CF_EXPECT(CreateEthernetIface(CvdallocInterfaceName("wtap", id),
                                wireless_bridge_name));
  CF_EXPECT(CreateMobileIface(CvdallocInterfaceName("wifiap", id), id,
                              kCvdallocWirelessApIpPrefix));
  CF_EXPECT(CreateEthernetBridgeIface(ethernet_bridge_name,
                                      kCvdallocEthernetIpPrefix));
  CF_EXPECT(CreateEthernetIface(CvdallocInterfaceName("etap", id),
                                ethernet_bridge_name));

  // IPv6 is layered on top of the IPv4 resources. A failure leaves the
  // instance IPv4-only instead of failing the launch.
  Result<void> ipv6_result = ipv6.Allocate();
  if (!ipv6_result.has_value()) {
    LOG(ERROR) << "cvdalloc: IPv6 allocation failed, continuing with IPv4 "
                  "only: "
               << ipv6_result.error();
    Result<void> rollback = ipv6.ReleaseInstance();
    if (!rollback.has_value()) {
      LOG(ERROR) << "cvdalloc: IPv6 rollback incomplete: " << rollback.error();
    }
  }

  return {};
}

Result<void> Teardown(int id, std::string_view ethernet_bridge_name,
                      std::string_view wireless_bridge_name,
                      Ipv6Allocation& ipv6) {
  LOG(INFO) << "cvdalloc: tearing down resources";

  Result<void> ipv6_instance = ipv6.ReleaseInstance();
  if (!ipv6_instance.has_value()) {
    LOG(ERROR) << "cvdalloc: IPv6 instance teardown incomplete: "
               << ipv6_instance.error();
  }

  DestroyMobileIface(CvdallocInterfaceName("mtap", id), id,
                     kCvdallocMobileIpPrefix);
  DestroyMobileIface(CvdallocInterfaceName("wtap", id), id,
                     kCvdallocWirelessIpPrefix);
  DestroyMobileIface(CvdallocInterfaceName("wifiap", id), id,
                     kCvdallocWirelessApIpPrefix);
  DestroyEthernetIface(CvdallocInterfaceName("etap", id));

  Result<void> ipv6_bridges = ipv6.ReleaseUnusedBridges();
  if (!ipv6_bridges.has_value()) {
    LOG(ERROR) << "cvdalloc: IPv6 bridge teardown incomplete: "
               << ipv6_bridges.error();
  }

  DestroyBridge(ethernet_bridge_name);
  DestroyBridge(wireless_bridge_name);

  return {};
}

}  // namespace

Result<int> CvdallocMain(int argc, char* argv[]) {
  std::vector<char*> args = absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_id) == 0 || absl::GetFlag(FLAGS_socket) == 0) {
    Usage();
    /* No need to dump a trace for usage. */
    return 1;
  }

  int id = absl::GetFlag(FLAGS_id);

  auto sock = SharedFD::Dup(absl::GetFlag(FLAGS_socket));
  if (!sock->IsOpen()) {
    return CF_ERRNO("cvdalloc: socket is closed: " << sock->StrError());
  }
  int r = TEMP_FAILURE_RETRY(close(absl::GetFlag(FLAGS_socket)));
  if (r == -1) {
    return CF_ERRNO("close: " << StrError(errno));
  }

  absl::Cleanup shutdown = [sock]() { sock->Shutdown(SHUT_RDWR); };

  /*
   * Save our current uid, so we can restore it to drop privileges later.
   */
  uid_t orig = getuid();

  absl::Cleanup drop_privileges = [orig]() {
    int r = DropPrivileges(orig);
    if (r == -1) {
      LOG(ERROR) << "cvdalloc: couldn't drop privileges: " << StrError(errno);
    }
  };

  r = BeginElevatedPrivileges();
  if (r == -1) {
    return CF_ERRF("Couldn't elevate permissions: {}", StrError(errno));
  }

  NftablesNft nft;
  Ipv6Allocation ipv6(id, kCvdallocEthernetBridgeName,
                      kCvdallocWirelessBridgeName, nft);

  absl::Cleanup teardown = [id, &ipv6]() {
    LOG(INFO) << "cvdalloc: teardown started";
    // TODO: b/471069557 - diagnose unused
    Result<void> unused = Teardown(id, kCvdallocEthernetBridgeName,
                                   kCvdallocWirelessBridgeName, ipv6);
  };

  CF_EXPECT(Allocate(id, kCvdallocEthernetBridgeName,
                     kCvdallocWirelessBridgeName, ipv6));
  CF_EXPECT(cvdalloc::Post(sock));

  LOG(INFO) << "cvdalloc: waiting to teardown";

  CF_EXPECT(cvdalloc::Wait(sock, cvdalloc::kSemNoTimeout));
  std::move(teardown).Invoke();
  CF_EXPECT(cvdalloc::Post(sock));

  return 0;
}

}  // namespace cuttlefish

int main(int argc, char* argv[]) {
  auto res = cuttlefish::CvdallocMain(argc, argv);
  if (!res.has_value()) {
    LOG(ERROR) << "cvdalloc failed: \n" << res.error();
    abort();
  }

  return *res;
}
