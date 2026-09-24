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
#pragma once

#include <string>

namespace cuttlefish {

constexpr std::string_view kCvdallocInterfacePrefix = "cvd-pi";
constexpr std::string_view kCvdallocEthernetBridgeName = "cvd-pi-ebr";
constexpr std::string_view kCvdallocWirelessBridgeName = "cvd-pi-wbr";
constexpr char kCvdallocMobileIpPrefix[] = "192.168.144";
constexpr char kCvdallocWirelessIpPrefix[] = "192.168.160";
constexpr char kCvdallocWirelessApIpPrefix[] = "192.168.176";
constexpr char kCvdallocEthernetIpPrefix[] = "192.168.192";

// IPv6 Unique Local Address (RFC 4193) plan used by cvdalloc. Every prefix is
// "fd00:cf:<segment>:<instance>::/64" or, on the shared bridges,
// "fd00:cf:<segment>::/64". Static mode (cuttlefish-host-resources) uses the
// fd00:cf:2X segments, so the two modes never overlap. The instance number is
// written with decimal digits (instance 12 -> "fd00:cf:11:12::"), matching the
// interface names; this is injective for every valid instance id.
constexpr char kCvdallocIpv6UlaPrefix[] = "fd00:cf";
constexpr int kCvdallocIpv6PrefixLength = 64;
// Mobile network, point-to-point tap per instance (cvd-pi-mtapN).
constexpr int kCvdallocIpv6MobileSegment = 0x11;
// Bridged wireless network, shared bridge (cvd-pi-wbr).
constexpr int kCvdallocIpv6BridgedWifiSegment = 0x12;
// Link between the host and the OpenWrt WAN, tap per instance (cvd-pi-wifiapN).
constexpr int kCvdallocIpv6WifiApSegment = 0x13;
// Ethernet network, shared bridge (cvd-pi-ebr).
constexpr int kCvdallocIpv6EthernetSegment = 0x14;
// OpenWrt LAN serving the Android wlan0 client, routed by the host through the
// OpenWrt WAN address of the same instance.
constexpr int kCvdallocIpv6WifiLanSegment = 0x15;

std::string CvdallocInterfaceName(const std::string& name, int num);
std::string InstanceToMobileGatewayAddress(int num);
std::string InstanceToMobileAddress(int num);
std::string InstanceToMobileBroadcast(int num);
std::string InstanceToWifiGatewayAddress(int num);
std::string InstanceToWifiAddress(int num);
std::string InstanceToWifiBroadcast(int num);
std::string InstanceToBridgedWifiGatewayAddress(int num);
std::string InstanceToBridgedWifiAddress(int num);
std::string InstanceToBridgedWifiBroadcast(int num);

// IPv6 prefixes are returned without a length ("fd00:cf:11:3::"); the length
// is always kCvdallocIpv6PrefixLength. Gateways (host side) use host id 1,
// guests on point-to-point links use host id 2.
std::string InstanceToMobileIpv6Prefix(int num);
std::string InstanceToMobileIpv6Gateway(int num);
std::string InstanceToMobileIpv6Address(int num);
std::string InstanceToWifiApIpv6Prefix(int num);
std::string InstanceToWifiApIpv6Gateway(int num);
std::string InstanceToWifiApIpv6Address(int num);
std::string InstanceToWifiLanIpv6Prefix(int num);
// Address of the OpenWrt LAN interface serving the Android wlan0 client.
std::string InstanceToWifiLanIpv6Gateway(int num);
std::string CvdallocEthernetIpv6Prefix();
std::string CvdallocEthernetIpv6Gateway();
std::string CvdallocBridgedWifiIpv6Prefix();
std::string CvdallocBridgedWifiIpv6Gateway();

}  // namespace cuttlefish
