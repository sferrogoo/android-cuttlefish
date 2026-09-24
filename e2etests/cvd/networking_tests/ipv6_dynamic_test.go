// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	e2etests "github.com/google/android-cuttlefish/e2etests/cvd/common"
)

// IPv6 plan used by cvdalloc (dynamic mode). See
// base/cvd/cuttlefish/host/commands/cvdalloc/interface.h.
const (
	dynamicMobilePrefixFmt   = "fd00:cf:11:%s::"
	dynamicWifiApPrefixFmt   = "fd00:cf:13:%s::"
	dynamicEthernetPrefix    = "fd00:cf:14::"
	dynamicWifiLanPrefixFmt  = "fd00:cf:15:%s::"
	dynamicIPv6DNSServer     = "2001:4860:4860::8888"
	dynamicIPv6OffLinkTarget = "2001:4860:4860::8888"
	dynamicIPv6Timeout       = 60 * time.Second
)

var dynamicMobileAddrRe = regexp.MustCompile(`inet6 fd00:cf:11:([0-9]+):[0-9a-f:]+/64`)

// guestShell runs a read-only command in the guest.
func guestShell(c *e2etests.TestContext, cmd string) (string, error) {
	out, err := c.RunCmd("adb", "shell", cmd)
	return out.Stdout, err
}

// waitForGuestOutput polls a read-only guest command until match returns a
// non-empty string or the timeout expires.
func waitForGuestOutput(c *e2etests.TestContext, cmd string, timeout time.Duration, match func(string) string) (string, error) {
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		out, err := guestShell(c, cmd)
		if err == nil {
			if m := match(out); m != "" {
				return m, nil
			}
			last = out
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timed out after %v running %q, last output:\n%s", timeout, cmd, last)
		}
		time.Sleep(pollInterval)
	}
}

// globalIPv6InPrefix returns the first global address of iface within prefix.
func globalIPv6InPrefix(c *e2etests.TestContext, iface, prefix string) (string, error) {
	return waitForGuestOutput(c, "ip -6 -o addr show dev "+iface+" scope global", dynamicIPv6Timeout, func(out string) string {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.HasPrefix(fields[3], prefix) && strings.HasSuffix(fields[3], "/64") {
				return strings.TrimSuffix(fields[3], "/64")
			}
		}
		return ""
	})
}

// raDefaultRoute returns the IPv6 default route that a Router Advertisement
// installed for iface. The test never adds routes.
func raDefaultRoute(c *e2etests.TestContext, iface string) (string, error) {
	return waitForGuestOutput(c, "ip -6 route show table all", dynamicIPv6Timeout, func(out string) string {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "default via fe80:") && strings.Contains(line, " dev "+iface+" ") && strings.Contains(line, " proto ra ") {
				return line
			}
		}
		return ""
	})
}

// raCarriesRdnss checks that the Router Advertisement seen by the IpClient of
// iface carries the IPv6 DNS server (RDNSS option).
func raCarriesRdnss(c *e2etests.TestContext, iface string) error {
	_, err := waitForGuestOutput(c, "dumpsys network_stack", dynamicIPv6Timeout, func(out string) string {
		section := false
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "IpClient.") {
				section = strings.HasPrefix(line, "IpClient."+iface)
			}
			if section && strings.Contains(line, " RA fe80:") && strings.Contains(line, " DNS ") && strings.Contains(line, dynamicIPv6DNSServer) {
				return line
			}
		}
		return ""
	})
	return err
}

func pingFromInterface(c *e2etests.TestContext, family, iface, target string) error {
	cmd := fmt.Sprintf("su 0 toybox ping %s -c 3 %s", family, target)
	if iface != "" {
		cmd = fmt.Sprintf("su 0 toybox ping %s -c 3 -I %s %s", family, iface, target)
	}
	_, err := waitForGuestOutput(c, cmd, dynamicIPv6Timeout, func(out string) string {
		if strings.Contains(out, " 0% packet loss") {
			return "ok"
		}
		return ""
	})
	return err
}

// isAndroidNetwork reports whether Android runs a network (IpClient or RIL) on
// iface, as opposed to the interface only being up in the kernel.
func isAndroidNetwork(c *e2etests.TestContext, iface string) bool {
	out, err := guestShell(c, "dumpsys connectivity")
	return err == nil && strings.Contains(out, "InterfaceName: "+iface+" ")
}

func hostHasIPv6Upstream(c *e2etests.TestContext) bool {
	out, err := c.RunCmd("ip", "-6", "route", "show", "default")
	return err == nil && strings.TrimSpace(out.Stdout) != ""
}

// TestIPv6DynamicMode launches a device with cvdalloc and verifies the IPv6
// configuration that cvdalloc provides. The test only reads guest and host
// state: it never adds addresses or routes and never changes settings.
//
//   - buried_eth0: SLAAC in fd00:cf:11:<num>::/64 from the host RA.
//   - eth1: SLAAC in the shared fd00:cf:14::/64 from the host RA.
//   - wlan0: SLAAC in fd00:cf:15:<num>::/64 from the OpenWrt RA. This needs
//     an OpenWrt image that parses wan_ip6addr, wan_ip6gw and wifi0_ip6addr
//     (docs/networking/ipv6_dynamic_mode.md) and a connected Wi-Fi network;
//     otherwise the wlan0 checks are skipped.
func TestIPv6DynamicMode(t *testing.T) {
	c := e2etests.TestContext{}
	c.SetUp(t)
	defer c.TearDown()

	t.Log("Fetching Cuttlefish artifacts...")
	if _, err := c.CVDFetch(e2etests.FetchArgs{
		DefaultBuildBranch: "aosp-android-latest-release",
		DefaultBuildTarget: "aosp_cf_x86_64_only_phone-userdebug",
	}); err != nil {
		t.Fatal(err)
	}

	t.Log("Launching Cuttlefish instance with cvdalloc...")
	if _, err := c.CVDCreate(e2etests.CreateArgs{Args: []string{"--use_cvdalloc=true"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.RunAdbWaitForDevice(); err != nil {
		t.Fatal(err)
	}

	// The mobile prefix encodes the instance number: fd00:cf:11:<num>::/64.
	num, err := waitForGuestOutput(&c, "ip -6 -o addr show dev buried_eth0 scope global", dynamicIPv6Timeout, func(out string) string {
		if m := dynamicMobileAddrRe.FindStringSubmatch(out); m != nil {
			return m[1]
		}
		return ""
	})
	if err != nil {
		logDiagnostics(&c, t)
		t.Fatalf("buried_eth0 has no cvdalloc IPv6 address: %v", err)
	}
	t.Logf("cvdalloc instance number from buried_eth0: %s", num)

	checks := []struct {
		iface    string
		prefix   string
		gateway  string
		ipClient bool // Android's IpClient processes RAs (and RDNSS) here.
	}{
		{"buried_eth0", fmt.Sprintf(dynamicMobilePrefixFmt, num), fmt.Sprintf(dynamicMobilePrefixFmt, num) + "1", false},
		{"eth1", dynamicEthernetPrefix, dynamicEthernetPrefix + "1", true},
		{"wlan0", fmt.Sprintf(dynamicWifiLanPrefixFmt, num), fmt.Sprintf(dynamicWifiLanPrefixFmt, num) + "1", true},
	}
	for _, check := range checks {
		t.Run(check.iface, func(t *testing.T) {
			if check.iface == "wlan0" && !isAndroidNetwork(&c, "wlan0") {
				t.Skip("Wi-Fi is not connected; wlan0 checks need a connected Wi-Fi network")
			}
			addr, err := globalIPv6InPrefix(&c, check.iface, check.prefix)
			if err != nil {
				logDiagnostics(&c, t)
				t.Fatalf("no address in %s/64: %v", check.prefix, err)
			}
			t.Logf("address %s", addr)

			route, err := raDefaultRoute(&c, check.iface)
			if err != nil {
				logDiagnostics(&c, t)
				t.Fatalf("no RA default route: %v", err)
			}
			t.Logf("default route: %s", route)

			if !isAndroidNetwork(&c, check.iface) {
				t.Logf("Android runs no network on %s; skipping RDNSS and ping checks", check.iface)
				return
			}
			if check.ipClient {
				if err := raCarriesRdnss(&c, check.iface); err != nil {
					t.Fatalf("RA on %s has no RDNSS %s: %v", check.iface, dynamicIPv6DNSServer, err)
				}
			}
			if err := pingFromInterface(&c, "-6", check.iface, check.gateway); err != nil {
				logDiagnostics(&c, t)
				t.Fatalf("ping6 gateway %s failed: %v", check.gateway, err)
			}
		})
	}

	// The OpenWrt WAN side is routed by the host: fd00:cf:13:<num>::1.
	if isAndroidNetwork(&c, "wlan0") {
		if err := pingFromInterface(&c, "-6", "", fmt.Sprintf(dynamicWifiApPrefixFmt, num)+"1"); err != nil {
			t.Errorf("ping6 host wifiap gateway failed: %v", err)
		}
	}

	// Off-link IPv6 through NAT66 on the default network.
	if hostHasIPv6Upstream(&c) {
		if err := pingFromInterface(&c, "-6", "", dynamicIPv6OffLinkTarget); err != nil {
			logDiagnostics(&c, t)
			t.Errorf("ping6 %s (NAT66 egress) failed: %v", dynamicIPv6OffLinkTarget, err)
		}
	} else {
		t.Log("host has no IPv6 default route; skipping NAT66 egress check")
	}

	// IPv4 must keep working alongside IPv6.
	for _, iface := range []string{"buried_eth0", "wlan0"} {
		if !isAndroidNetwork(&c, iface) {
			continue
		}
		if err := pingFromInterface(&c, "-4", iface, "8.8.8.8"); err != nil {
			logDiagnostics(&c, t)
			t.Errorf("IPv4 ping 8.8.8.8 from %s failed: %v", iface, err)
		}
	}
}
