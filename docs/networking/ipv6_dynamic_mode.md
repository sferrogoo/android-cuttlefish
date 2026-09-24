# IPv6 in cvdalloc (dynamic) mode

`cvd create --use_cvdalloc=true` makes `cvdalloc` create the per-instance tap
devices. On top of IPv4 it now sets up IPv6 on each tap. The design is
"Cuttlefish IPv6 enablement", sections 4.2 and 4.3.

## Address plan

All prefixes come from the ULA aggregate `fd00:cf::/32`. `N` is the instance
number (1..63), written in decimal.

| Adapter (guest)       | Host interface        | Prefix                  | Host gateway       | Guest address source          |
| --------------------- | --------------------- | ----------------------- | ------------------ | ----------------------------- |
| Mobile (buried_eth0)  | `cvd-pi-mtapN`        | `fd00:cf:11:N::/64`     | `fd00:cf:11:N::1`  | modem simulator (`::2`)       |
| Wi-Fi AP (OpenWrt wan)| `cvd-pi-wifiapN`      | `fd00:cf:13:N::/64`     | `fd00:cf:13:N::1`  | OpenWrt kernel args (`::2`)   |
| Wi-Fi (wlan0)         | OpenWrt `br-wifi0`    | `fd00:cf:15:N::/64`     | OpenWrt `::1`      | SLAAC from OpenWrt odhcpd     |
| Ethernet (eth1)       | `cvd-pi-ebr` (bridge) | `fd00:cf:14::/64`       | `fd00:cf:14::1`    | SLAAC from host dnsmasq       |
| Bridged Wi-Fi         | `cvd-pi-wbr` (bridge) | `fd00:cf:12::/64`       | `fd00:cf:12::1`    | not configured (see below)    |

The host routes `fd00:cf:15:N::/64` via `fd00:cf:13:N::2`, which is the OpenWrt
wan address.

Point-to-point taps get a distinct /64 for each instance. The Ethernet taps
share one bridge, so they share its /64, the same way the IPv4 plan shares
`192.168.192.0/24`. Each guest still gets its own SLAAC address.

## Host configuration done by cvdalloc

- Sysctls on every interface it configures: `disable_ipv6=0`, `accept_ra=0`
  and `autoconf=0`. The host never learns routes from guest RAs.
- One `dnsmasq` in router advertisement mode per RA interface (`cvd-pi-mtapN`,
  `cvd-pi-ebr`, `cvd-pi-wbr`):
  - flags `--enable-ra --dhcp-range=<prefix>,ra-only,64`
  - RDNSS `2001:4860:4860::8888` and `2001:4860:4860::8844`
  - `--port=0`, so it runs no DNS or DHCPv6 service
- NAT66 in the nftables table `ip6 cuttlefish_nat6`, chain `postrouting`:
  `ip6 saddr <prefix> ip6 daddr != fd00:cf::/32 masquerade`
- RA guard in table `bridge cuttlefish_ra_guard`. It drops router
  advertisements that enter the shared bridges from guest taps.
- A `flock` on `/var/tmp/cvd/cuttlefish-ipv6.lock` serializes IPv6 changes when
  several `cvdalloc` processes run at once.

cvdalloc does not change `net.ipv6.conf.all.forwarding`. If forwarding is off,
it logs a warning.

IPv6 setup runs after IPv4 setup. If IPv6 setup fails, cvdalloc logs the
error, rolls back that instance's IPv6 state and continues with IPv4 only.
Teardown reverses setup. Shared bridge state (address, dnsmasq, NAT66 rule,
empty tables) is removed only when the last port leaves the bridge.

## OpenWrt dependency (wlan0)

`assemble_cvd` passes these arguments on the OpenWrt kernel command line:

- `wan_ip6addr=fd00:cf:13:N::2/64`
- `wan_ip6gw=fd00:cf:13:N::1`
- `wifi0_ip6addr=fd00:cf:15:N::1/64`

The current OpenWrt image ignores them. The script
`external/openwrt-prebuilts/shared/uci-defaults/0_default_config` in AOSP must
parse them. `openwrt_0_default_config_ipv6.patch` in this directory is that
change. Until an OpenWrt image with it ships, wlan0 has no IPv6 in dynamic
mode, and IPv4 on wlan0 is unchanged.

In dynamic mode the openwrt_control_server does not run its LuCI RPC IPv6
provisioning (`--provision_static_ipv6=false`).

Bridged Wi-Fi (`--use_bridged_wifi_tap`) with cvdalloc gets the bridge RA and
NAT66, but OpenWrt receives no IPv6 arguments.

## Bridge fixes

- `CreateEthernetBridgeIface` now brings the bridge up. Before this change
  `cvd-pi-ebr` and `cvd-pi-wbr` stayed DOWN, so neither DHCPv4 nor RAs reached
  the guest eth1. This bug also exists without IPv6.
- The bridge ports `cvd-pi-etapN` and `cvd-pi-wtapN` get `accept_ra=0` and
  `autoconf=0`, like the bridges.

## Known limitations seen in testing

Tested with `aosp_cf_x86_64_only_phone-userdebug` build 16373615.

- eth1: the guest kernel gets a SLAAC address and an RA default route. The
  phone's EthernetService does not bring up a network on eth1, so Android apps
  cannot use it. IPv4 on eth1 has the same limitation.
- Mobile: the default APN uses protocol `IP` (IPv4 only), so the RIL does not
  hand the `ril_ipv6_*` values to Android. The kernel still gets a SLAAC
  address from the RA on `cvd-pi-mtapN`, and NAT66 egress works.
- DNS: the RA carries RDNSS, but Android does not add the servers to
  LinkProperties. A likely cause is that Android does not treat a network with
  only ULA addresses as IPv6-provisioned. DNS keeps working over IPv4.
- Off-link IPv6 works only if the host has an IPv6 default route.

## Testing

`e2etests/cvd/networking_tests/ipv6_dynamic_test.go` creates a device with
`--use_cvdalloc=true` and only reads guest state (addresses, routes,
`dumpsys`, `ping`). It skips wlan0 if Wi-Fi is not connected.
