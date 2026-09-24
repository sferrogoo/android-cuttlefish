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

#include "allocd/ipv6_firewall.h"

#include <stddef.h>

#include <string>
#include <string_view>
#include <utility>

#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

#include "allocd/net/nft_rule.h"
#include "allocd/net/nftables.h"
#include "cuttlefish/result/result.h"

namespace cuttlefish {
namespace {

// Comment prefix of rules shared by several instances. NftRule prefixes the
// rules it owns with "cvdalloc-", so the two sets never collide.
constexpr std::string_view kSharedRuleCommentPrefix = "cvdalloc-shared-";

std::string SharedRuleComment(std::string_view tag) {
  return absl::StrCat(kSharedRuleCommentPrefix, tag);
}

Result<void> DeleteTableIfEmpty(Nftables& nft, std::string_view family,
                                std::string_view table) {
  Result<size_t> count = nft.CountRules(family, table);
  if (!count.has_value()) {
    // The table does not exist (already removed, or never created).
    return {};
  }
  if (*count > 0) {
    LOG(INFO) << "Keeping nft table " << family << " " << table << ": "
              << *count << " rule(s) still in use";
    return {};
  }
  CF_EXPECT(nft.DeleteTable(family, table));
  return {};
}

}  // namespace

std::string Ipv6MasqueradeRule(std::string_view source_cidr,
                               std::string_view exempt_destination_cidr) {
  return absl::StrFormat("ip6 saddr %s ip6 daddr != %s masquerade", source_cidr,
                         exempt_destination_cidr);
}

std::string RouterAdvertisementGuardRule(std::string_view bridge_port) {
  return absl::StrFormat(
      "iifname \"%s\" icmpv6 type nd-router-advert counter drop", bridge_port);
}

Ipv6Firewall::Ipv6Firewall(Nftables& nft) : nft_(nft) {}

Result<void> Ipv6Firewall::EnsureNatChain() {
  CF_EXPECT(nft_.EnsureTable(kIpv6NatFamily, kIpv6NatTable));
  CF_EXPECT(nft_.EnsureChain(kIpv6NatFamily, kIpv6NatTable, kIpv6NatChain,
                             kIpv6NatChainDefinition));
  return {};
}

Result<void> Ipv6Firewall::EnsureRaGuardChain() {
  CF_EXPECT(nft_.EnsureTable(kRaGuardFamily, kRaGuardTable));
  CF_EXPECT(nft_.EnsureChain(kRaGuardFamily, kRaGuardTable, kRaGuardChain,
                             kRaGuardChainDefinition));
  return {};
}

Result<void> Ipv6Firewall::AddMasquerade(std::string_view tag,
                                         std::string_view source_cidr) {
  CF_EXPECT(EnsureNatChain());
  NftRule rule = CF_EXPECT(NftRule::Create(
      nft_, kIpv6NatFamily, kIpv6NatTable, kIpv6NatChain,
      Ipv6MasqueradeRule(source_cidr, kCuttlefishIpv6UlaAggregateCidr),
      absl::StrCat("nat6-", tag)));
  owned_rules_.emplace_back(std::move(rule));
  return {};
}

Result<void> Ipv6Firewall::EnsureSharedMasquerade(
    std::string_view tag, std::string_view source_cidr) {
  CF_EXPECT(EnsureNatChain());
  std::string comment = SharedRuleComment(absl::StrCat("nat6-", tag));
  CF_EXPECT(nft_.DeleteRulesByComment(kIpv6NatFamily, kIpv6NatTable,
                                      kIpv6NatChain, comment));
  CF_EXPECT(nft_.AddRule(
      kIpv6NatFamily, kIpv6NatTable, kIpv6NatChain,
      Ipv6MasqueradeRule(source_cidr, kCuttlefishIpv6UlaAggregateCidr),
      comment));
  return {};
}

Result<void> Ipv6Firewall::RemoveSharedMasquerade(std::string_view tag) {
  CF_EXPECT(
      nft_.DeleteRulesByComment(kIpv6NatFamily, kIpv6NatTable, kIpv6NatChain,
                                SharedRuleComment(absl::StrCat("nat6-", tag))));
  return {};
}

Result<void> Ipv6Firewall::AddRouterAdvertisementGuard(
    std::string_view bridge_port) {
  CF_EXPECT(EnsureRaGuardChain());
  NftRule rule = CF_EXPECT(
      NftRule::Create(nft_, kRaGuardFamily, kRaGuardTable, kRaGuardChain,
                      RouterAdvertisementGuardRule(bridge_port),
                      absl::StrCat("raguard-", bridge_port)));
  owned_rules_.emplace_back(std::move(rule));
  return {};
}

void Ipv6Firewall::ReleaseOwnedRules() { owned_rules_.clear(); }

Result<void> Ipv6Firewall::DeleteEmptyTables() {
  CF_EXPECT(DeleteTableIfEmpty(nft_, kIpv6NatFamily, kIpv6NatTable));
  CF_EXPECT(DeleteTableIfEmpty(nft_, kRaGuardFamily, kRaGuardTable));
  return {};
}

}  // namespace cuttlefish
