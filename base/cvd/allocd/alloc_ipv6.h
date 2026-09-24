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

#ifndef ALLOCD_ALLOC_IPV6_H_
#define ALLOCD_ALLOC_IPV6_H_

#include <string>
#include <string_view>
#include <vector>

#include "cuttlefish/common/libs/fs/shared_fd.h"
#include "cuttlefish/result/result.h"

namespace cuttlefish {

// DNS servers announced to guests (RDNSS option of Router Advertisements).
inline constexpr std::string_view kIpv6DnsServers[] = {
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
};

// Route to a guest-side network behind a guest router (e.g. the OpenWrt LAN).
struct Ipv6Route {
  // Textual prefix ending in "::", e.g. "fd00:cf:15:1::".
  std::string prefix;
  int prefix_length = 64;
  std::string via;
};

// Host side of one guest-facing IPv6 link. The host owns address
// `prefix` + "1" (e.g. "fd00:cf:11:1::1").
struct Ipv6Gateway {
  std::string interface;
  // Textual prefix ending in "::", e.g. "fd00:cf:11:1::".
  std::string prefix;
  int prefix_length = 64;
  // Send Router Advertisements (SLAAC prefix, default route, RDNSS).
  bool advertise = true;
  std::vector<Ipv6Route> routes;

  std::string Address() const;  // "fd00:cf:11:1::1"
  std::string Cidr() const;     // "fd00:cf:11:1::/64"
};

// Arguments of the dnsmasq instance that only sends Router Advertisements on
// `gateway.interface`. It is separate from the IPv4 DHCP dnsmasq, so IPv4
// behaviour does not depend on IPv6.
std::vector<std::string> Ipv6RouterAdvertisementArgs(
    std::string_view dnsmasq_path, const Ipv6Gateway& gateway,
    std::string_view pid_file);

// Configures the host side of an IPv6 link:
//  - enables IPv6 on the interface and disables accepting Router
//    Advertisements (the host is the router; guests must not configure it),
//  - adds the gateway address and the routes,
//  - starts Router Advertisements if requested. On shared bridges this is
//    idempotent: an already running advertisement daemon is kept.
Result<void> SetupIpv6Gateway(const Ipv6Gateway& gateway);
// Makes the host ignore Router Advertisements received on `interface`
// (accept_ra=0, autoconf=0). Used for guest-facing bridge ports.
Result<void> IgnoreRouterAdvertisements(std::string_view interface);
// Reverses SetupIpv6Gateway. Errors are returned after attempting every step.
Result<void> TeardownIpv6Gateway(const Ipv6Gateway& gateway);

// Returns true if `bridge_name` exists and has no ports.
Result<bool> BridgeIsUnused(std::string_view bridge_name);

// Returns whether IPv6 forwarding is enabled on the host. cvdalloc does not
// change global forwarding (as for IPv4, the host configuration owns it).
Result<bool> Ipv6ForwardingEnabled();

// Takes an exclusive advisory lock serializing IPv6 configuration across
// concurrent cvdalloc processes. The lock is released when the returned file
// descriptor is closed.
Result<SharedFD> LockIpv6Configuration();

}  // namespace cuttlefish

#endif  // ALLOCD_ALLOC_IPV6_H_
