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

#include "cuttlefish/host/commands/cvdalloc/interface.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <set>
#include <string>

namespace cuttlefish {
namespace {

// Matches kMaxIfaceNameId in allocd/alloc_utils.h.
constexpr int kMaxInstance = 63;

bool IsValidIpv6(const std::string& address) {
  in6_addr parsed;
  return inet_pton(AF_INET6, address.c_str(), &parsed) == 1;
}

// First 64 bits of `prefix` as an integer, identifying the /64.
std::string Slash64(const std::string& prefix) {
  in6_addr parsed;
  EXPECT_EQ(inet_pton(AF_INET6, prefix.c_str(), &parsed), 1) << prefix;
  return std::string(reinterpret_cast<const char*>(parsed.s6_addr), 8);
}

TEST(CvdallocIpv6Test, MatchesDesignDocPlan) {
  EXPECT_EQ(InstanceToMobileIpv6Prefix(1), "fd00:cf:11:1::");
  EXPECT_EQ(InstanceToMobileIpv6Gateway(1), "fd00:cf:11:1::1");
  EXPECT_EQ(InstanceToMobileIpv6Address(1), "fd00:cf:11:1::2");
  EXPECT_EQ(CvdallocBridgedWifiIpv6Prefix(), "fd00:cf:12::");
  EXPECT_EQ(CvdallocBridgedWifiIpv6Gateway(), "fd00:cf:12::1");
  EXPECT_EQ(InstanceToWifiApIpv6Prefix(2), "fd00:cf:13:2::");
  EXPECT_EQ(InstanceToWifiApIpv6Gateway(2), "fd00:cf:13:2::1");
  EXPECT_EQ(InstanceToWifiApIpv6Address(2), "fd00:cf:13:2::2");
  EXPECT_EQ(CvdallocEthernetIpv6Prefix(), "fd00:cf:14::");
  EXPECT_EQ(CvdallocEthernetIpv6Gateway(), "fd00:cf:14::1");
  EXPECT_EQ(InstanceToWifiLanIpv6Prefix(12), "fd00:cf:15:12::");
  EXPECT_EQ(InstanceToWifiLanIpv6Gateway(12), "fd00:cf:15:12::1");
}

TEST(CvdallocIpv6Test, EveryPrefixIsUniqueAcrossInstancesAndSegments) {
  std::set<std::string> prefixes;
  auto insert = [&prefixes](const std::string& prefix) {
    ASSERT_TRUE(IsValidIpv6(prefix)) << prefix;
    EXPECT_TRUE(prefixes.insert(Slash64(prefix)).second)
        << "duplicate /64: " << prefix;
  };
  insert(CvdallocEthernetIpv6Prefix());
  insert(CvdallocBridgedWifiIpv6Prefix());
  for (int num = 1; num <= kMaxInstance; num++) {
    insert(InstanceToMobileIpv6Prefix(num));
    insert(InstanceToWifiApIpv6Prefix(num));
    insert(InstanceToWifiLanIpv6Prefix(num));
  }
  EXPECT_EQ(prefixes.size(), 2u + 3u * kMaxInstance);
}

TEST(CvdallocIpv6Test, PrefixesAreUlaInsideCuttlefishAggregate) {
  for (int num = 1; num <= kMaxInstance; num++) {
    for (const std::string& address :
         {InstanceToMobileIpv6Address(num), InstanceToWifiApIpv6Address(num),
          InstanceToWifiLanIpv6Gateway(num)}) {
      in6_addr parsed;
      ASSERT_EQ(inet_pton(AF_INET6, address.c_str(), &parsed), 1) << address;
      // fd00:00cf::/32
      EXPECT_EQ(parsed.s6_addr[0], 0xfd) << address;
      EXPECT_EQ(parsed.s6_addr[1], 0x00) << address;
      EXPECT_EQ(parsed.s6_addr[2], 0x00) << address;
      EXPECT_EQ(parsed.s6_addr[3], 0xcf) << address;
      // Dynamic mode uses the 0x1X segments; static mode owns 0x2X.
      EXPECT_EQ(parsed.s6_addr[4], 0x00) << address;
      EXPECT_EQ(parsed.s6_addr[5] & 0xf0, 0x10) << address;
    }
  }
}

TEST(CvdallocIpv6Test, GatewayAndGuestShareTheirInstancePrefix) {
  for (int num = 1; num <= kMaxInstance; num++) {
    EXPECT_EQ(Slash64(InstanceToMobileIpv6Gateway(num)),
              Slash64(InstanceToMobileIpv6Address(num)));
    EXPECT_NE(InstanceToMobileIpv6Gateway(num),
              InstanceToMobileIpv6Address(num));
    EXPECT_EQ(Slash64(InstanceToWifiApIpv6Gateway(num)),
              Slash64(InstanceToWifiApIpv6Address(num)));
  }
}

}  // namespace
}  // namespace cuttlefish
