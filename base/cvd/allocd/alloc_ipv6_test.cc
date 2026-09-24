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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace cuttlefish {
namespace {

using ::testing::Contains;
using ::testing::HasSubstr;
using ::testing::Not;

Ipv6Gateway MobileGateway() {
  return Ipv6Gateway{
      .interface = "cvd-pi-mtap3",
      .prefix = "fd00:cf:11:3::",
      .prefix_length = 64,
      .advertise = true,
  };
}

TEST(Ipv6GatewayTest, AddressAndCidr) {
  Ipv6Gateway gateway = MobileGateway();
  EXPECT_EQ(gateway.Address(), "fd00:cf:11:3::1");
  EXPECT_EQ(gateway.Cidr(), "fd00:cf:11:3::/64");
}

TEST(Ipv6RouterAdvertisementArgsTest, AdvertisesPrefixAndDnsOnly) {
  std::vector<std::string> args = Ipv6RouterAdvertisementArgs(
      "/usr/sbin/dnsmasq", MobileGateway(), "/tmp/dnsmasq6.pid");

  ASSERT_FALSE(args.empty());
  EXPECT_EQ(args[0], "/usr/sbin/dnsmasq");
  EXPECT_THAT(args, Contains("--interface=cvd-pi-mtap3"));
  EXPECT_THAT(args, Contains("--bind-interfaces"));
  EXPECT_THAT(args, Contains("--enable-ra"));
  // SLAAC via Router Advertisements, no stateful DHCPv6.
  EXPECT_THAT(args, Contains("--dhcp-range=fd00:cf:11:3::,ra-only,64"));
  // RDNSS.
  EXPECT_THAT(args, Contains("--dhcp-option=option6:dns-server,"
                             "[2001:4860:4860::8888],[2001:4860:4860::8844]"));
  // No DNS service and no system configuration.
  EXPECT_THAT(args, Contains("--port=0"));
  EXPECT_THAT(args, Contains("--conf-file="));
  EXPECT_THAT(args, Contains("--pid-file=/tmp/dnsmasq6.pid"));
  // IPv4 is served by a different dnsmasq instance.
  EXPECT_THAT(args, Not(Contains(HasSubstr("--listen-address="))));
  for (const std::string& arg : args) {
    EXPECT_THAT(arg, Not(HasSubstr("192.168.")));
  }
}

}  // namespace
}  // namespace cuttlefish
