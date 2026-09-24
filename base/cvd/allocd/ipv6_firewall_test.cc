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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "allocd/test/fake_nftables.h"
#include "cuttlefish/result/result_matchers.h"

namespace cuttlefish {
namespace {

constexpr char kMtap1Cidr[] = "fd00:cf:11:1::/64";
constexpr char kEthernetCidr[] = "fd00:cf:14::/64";

TEST(Ipv6FirewallRulesTest, MasqueradeRuleExemptsCuttlefishDestinations) {
  EXPECT_EQ(Ipv6MasqueradeRule(kMtap1Cidr, kCuttlefishIpv6UlaAggregateCidr),
            "ip6 saddr fd00:cf:11:1::/64 ip6 daddr != fd00:cf::/32 masquerade");
}

TEST(Ipv6FirewallRulesTest, RouterAdvertisementGuardMatchesIngressPort) {
  EXPECT_EQ(RouterAdvertisementGuardRule("cvd-pi-etap1"),
            "iifname \"cvd-pi-etap1\" icmpv6 type nd-router-advert counter "
            "drop");
}

class Ipv6FirewallTest : public ::testing::Test {
 protected:
  int NatRules() {
    return fake_.RuleCount(kIpv6NatFamily, kIpv6NatTable, kIpv6NatChain);
  }
  int GuardRules() {
    return fake_.RuleCount(kRaGuardFamily, kRaGuardTable, kRaGuardChain);
  }

  FakeNftables fake_;
};

TEST_F(Ipv6FirewallTest, AddMasqueradeCreatesNat6TableAndChain) {
  Ipv6Firewall firewall(fake_);
  ASSERT_THAT(firewall.AddMasquerade("cvd-pi-mtap1", kMtap1Cidr), IsOk());

  EXPECT_TRUE(fake_.HasChain("ip6", "cuttlefish_nat6", "postrouting"));
  EXPECT_TRUE(fake_.HasRuleWithComment("ip6", "cuttlefish_nat6", "postrouting",
                                       "cvdalloc-nat6-cvd-pi-mtap1"));
  EXPECT_EQ(NatRules(), 1);
}

TEST_F(Ipv6FirewallTest, ReleaseRemovesOnlyOwnedRules) {
  Ipv6Firewall instance1(fake_);
  Ipv6Firewall instance2(fake_);
  ASSERT_THAT(instance1.AddMasquerade("cvd-pi-mtap1", kMtap1Cidr), IsOk());
  ASSERT_THAT(instance2.AddMasquerade("cvd-pi-mtap2", "fd00:cf:11:2::/64"),
              IsOk());

  instance1.ReleaseOwnedRules();

  EXPECT_FALSE(fake_.HasRuleWithComment("ip6", "cuttlefish_nat6", "postrouting",
                                        "cvdalloc-nat6-cvd-pi-mtap1"));
  EXPECT_TRUE(fake_.HasRuleWithComment("ip6", "cuttlefish_nat6", "postrouting",
                                       "cvdalloc-nat6-cvd-pi-mtap2"));
}

TEST_F(Ipv6FirewallTest, DestructionReleasesOwnedRules) {
  {
    Ipv6Firewall firewall(fake_);
    ASSERT_THAT(firewall.AddMasquerade("cvd-pi-mtap1", kMtap1Cidr), IsOk());
    ASSERT_THAT(firewall.AddRouterAdvertisementGuard("cvd-pi-etap1"), IsOk());
    EXPECT_EQ(GuardRules(), 1);
  }
  EXPECT_EQ(NatRules(), 0);
  EXPECT_EQ(GuardRules(), 0);
}

TEST_F(Ipv6FirewallTest, SharedMasqueradeIsIdempotentAndOutlivesOwners) {
  {
    Ipv6Firewall instance1(fake_);
    Ipv6Firewall instance2(fake_);
    ASSERT_THAT(instance1.EnsureSharedMasquerade("cvd-pi-ebr", kEthernetCidr),
                IsOk());
    ASSERT_THAT(instance2.EnsureSharedMasquerade("cvd-pi-ebr", kEthernetCidr),
                IsOk());
    EXPECT_EQ(NatRules(), 1);
  }
  // Instances going away do not remove the rule of a bridge still in use.
  EXPECT_TRUE(fake_.HasRuleWithComment("ip6", "cuttlefish_nat6", "postrouting",
                                       "cvdalloc-shared-nat6-cvd-pi-ebr"));

  Ipv6Firewall last(fake_);
  ASSERT_THAT(last.RemoveSharedMasquerade("cvd-pi-ebr"), IsOk());
  EXPECT_EQ(NatRules(), 0);
}

TEST_F(Ipv6FirewallTest, DeleteEmptyTablesKeepsTablesInUse) {
  Ipv6Firewall instance1(fake_);
  Ipv6Firewall instance2(fake_);
  ASSERT_THAT(instance1.AddMasquerade("cvd-pi-mtap1", kMtap1Cidr), IsOk());
  ASSERT_THAT(instance1.AddRouterAdvertisementGuard("cvd-pi-etap1"), IsOk());
  ASSERT_THAT(instance2.AddMasquerade("cvd-pi-mtap2", "fd00:cf:11:2::/64"),
              IsOk());

  instance1.ReleaseOwnedRules();
  ASSERT_THAT(instance1.DeleteEmptyTables(), IsOk());

  // instance2 still has a NAT66 rule; nobody uses the RA guard any more.
  EXPECT_TRUE(fake_.HasTable("ip6", "cuttlefish_nat6"));
  EXPECT_FALSE(fake_.HasTable("bridge", "cuttlefish_ra_guard"));

  instance2.ReleaseOwnedRules();
  ASSERT_THAT(instance2.DeleteEmptyTables(), IsOk());
  EXPECT_FALSE(fake_.HasTable("ip6", "cuttlefish_nat6"));
}

TEST_F(Ipv6FirewallTest, DeleteEmptyTablesKeepsRulesFromOtherOwners) {
  // E.g. static-mode rules added by cuttlefish-host-resources.
  ASSERT_THAT(fake_.EnsureTable("ip6", "cuttlefish_nat6"), IsOk());
  ASSERT_THAT(fake_.EnsureChain("ip6", "cuttlefish_nat6", "postrouting", ""),
              IsOk());
  ASSERT_THAT(fake_.AddRule("ip6", "cuttlefish_nat6", "postrouting",
                            "ip6 saddr fd00:cf:24::/64 masquerade", ""),
              IsOk());

  Ipv6Firewall firewall(fake_);
  ASSERT_THAT(firewall.DeleteEmptyTables(), IsOk());
  EXPECT_EQ(NatRules(), 1);
}

TEST_F(Ipv6FirewallTest, DeleteEmptyTablesWithoutTablesIsNoOp) {
  Ipv6Firewall firewall(fake_);
  EXPECT_THAT(firewall.DeleteEmptyTables(), IsOk());
}

}  // namespace
}  // namespace cuttlefish
