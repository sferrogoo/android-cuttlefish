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

#ifndef ALLOCD_IPV6_FIREWALL_H_
#define ALLOCD_IPV6_FIREWALL_H_

#include <string>
#include <string_view>
#include <vector>

#include "allocd/net/nft_rule.h"
#include "allocd/net/nftables.h"
#include "cuttlefish/result/result.h"

namespace cuttlefish {

// Aggregate covering every Cuttlefish IPv6 ULA prefix (static mode fd00:cf:2X,
// cvdalloc fd00:cf:1X).
inline constexpr std::string_view kCuttlefishIpv6UlaAggregateCidr =
    "fd00:cf::/32";

// NAT66 table shared with the static-mode cuttlefish-host-resources service.
inline constexpr std::string_view kIpv6NatFamily = "ip6";
inline constexpr std::string_view kIpv6NatTable = "cuttlefish_nat6";
inline constexpr std::string_view kIpv6NatChain = "postrouting";
inline constexpr std::string_view kIpv6NatChainDefinition =
    "{ type nat hook postrouting priority 100 ; }";

// Bridge table dropping IPv6 Router Advertisements sent by guests, so that a
// guest on a shared bridge cannot become the IPv6 router of its neighbours.
inline constexpr std::string_view kRaGuardFamily = "bridge";
inline constexpr std::string_view kRaGuardTable = "cuttlefish_ra_guard";
inline constexpr std::string_view kRaGuardChain = "forward";
inline constexpr std::string_view kRaGuardChainDefinition =
    "{ type filter hook forward priority 0 ; }";

// Masquerades traffic from `source_cidr` unless it is addressed to
// `exempt_destination_cidr` (traffic between Cuttlefish networks keeps its
// source address).
std::string Ipv6MasqueradeRule(std::string_view source_cidr,
                               std::string_view exempt_destination_cidr);

// Drops Router Advertisements entering the bridge from `bridge_port`.
std::string RouterAdvertisementGuardRule(std::string_view bridge_port);

// Manages the nftables state that cvdalloc needs for IPv6.
//
// Rules added with AddMasquerade() and AddRouterAdvertisementGuard() belong to
// one instance and are removed by ReleaseOwnedRules() (or on destruction).
// Shared-bridge masquerade rules are shared by every instance using the
// bridge; they are identified by tag and removed explicitly by whichever
// instance tears the bridge down. Callers serialize concurrent cvdalloc
// processes with a lock around every call.
class Ipv6Firewall {
 public:
  explicit Ipv6Firewall(Nftables& nft);

  Ipv6Firewall(const Ipv6Firewall&) = delete;
  Ipv6Firewall& operator=(const Ipv6Firewall&) = delete;

  Result<void> AddMasquerade(std::string_view tag,
                             std::string_view source_cidr);
  // Idempotent: at most one rule exists per tag after the call.
  Result<void> EnsureSharedMasquerade(std::string_view tag,
                                      std::string_view source_cidr);
  Result<void> RemoveSharedMasquerade(std::string_view tag);
  Result<void> AddRouterAdvertisementGuard(std::string_view bridge_port);

  // Removes every rule owned by this object.
  void ReleaseOwnedRules();
  // Deletes the IPv6 tables if no rule (from any instance, or from the
  // static-mode service) remains in them.
  Result<void> DeleteEmptyTables();

 private:
  Result<void> EnsureNatChain();
  Result<void> EnsureRaGuardChain();

  Nftables& nft_;
  std::vector<NftRule> owned_rules_;
};

}  // namespace cuttlefish

#endif  // ALLOCD_IPV6_FIREWALL_H_
