/// SSRF protection: returns true if the IP should be blocked.
///
/// Covers all private/reserved ranges per BYO_PLAN.md Section 5.4:
///   - IPv4: loopback, RFC 1918, link-local, RFC 6598, broadcast, unspecified
///   - IPv6: loopback, link-local, unique-local, discard prefix, 6to4, unspecified
///   - IPv4-mapped IPv6 (::ffff:0:0/96): re-checked against IPv4 rules
///   - 6to4 addresses (2002::/16): embedded IPv4 re-checked against IPv4 rules
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_ip_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_ipv4_blocked(v4),
        IpAddr::V6(v6) => is_ipv6_blocked(v6),
    }
}

fn is_ipv4_blocked(ip: &Ipv4Addr) -> bool {
    // 127.0.0.0/8 — loopback
    if ip.is_loopback() {
        return true;
    }
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — RFC 1918 private
    if ip.is_private() {
        return true;
    }
    // 169.254.0.0/16 — link-local
    if ip.is_link_local() {
        return true;
    }
    // 100.64.0.0/10 — RFC 6598 shared address space (carrier-grade NAT)
    if is_shared_address_space(ip) {
        return true;
    }
    // 255.255.255.255 — broadcast
    if ip.is_broadcast() {
        return true;
    }
    // 0.0.0.0 — unspecified
    if ip.is_unspecified() {
        return true;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — documentation ranges
    if is_documentation_v4(ip) {
        return true;
    }
    // RS4: additional reserved/internal-leaning ranges that were missing.
    // 224.0.0.0/4 — multicast. No legitimate SFTP target is multicast.
    if ip.is_multicast() {
        return true;
    }
    // 198.18.0.0/15 — RFC 2544 benchmarking. Some cloud overlays route this
    // to internal test fabric; allowing it would be an SSRF footgun.
    let o = ip.octets();
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    // 192.0.0.0/24 — IETF protocol assignments. No legitimate outside use.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    false
}

fn is_ipv6_blocked(ip: &Ipv6Addr) -> bool {
    // ::1/128 — loopback
    if ip.is_loopback() {
        return true;
    }
    // ::/128 — unspecified
    if ip.is_unspecified() {
        return true;
    }
    // fe80::/10 — link-local
    if is_ipv6_link_local(ip) {
        return true;
    }
    // fc00::/7 — unique local (includes fd00::/8)
    if is_ipv6_unique_local(ip) {
        return true;
    }
    // 100::/64 — discard prefix
    if is_ipv6_discard(ip) {
        return true;
    }
    // 2002::/16 — 6to4 (extract embedded IPv4 and re-validate)
    if is_6to4_blocked(ip) {
        return true;
    }
    // ::ffff:0:0/96 — IPv4-mapped (extract underlying IPv4 and re-validate)
    if is_ipv4_mapped_blocked(ip) {
        return true;
    }
    false
}

/// 100.64.0.0/10 — RFC 6598 shared address space
fn is_shared_address_space(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 100.64.0.0 to 100.127.255.255
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// Documentation ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
fn is_documentation_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        (octets[0], octets[1], octets[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    )
}

/// fe80::/10 — IPv6 link-local
fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segs = ip.segments();
    // fe80::/10 means first 10 bits are 1111 1110 10
    // First segment: 0xfe80 through 0xfebf
    (segs[0] & 0xffc0) == 0xfe80
}

/// fc00::/7 — IPv6 unique local (fc00:: and fd00::)
fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    let segs = ip.segments();
    // fc00::/7 means first 7 bits are 1111 110
    // First segment high byte: 0xfc or 0xfd
    (segs[0] & 0xfe00) == 0xfc00
}

/// 100::/64 — IPv6 discard prefix
fn is_ipv6_discard(ip: &Ipv6Addr) -> bool {
    let segs = ip.segments();
    segs[0] == 0x0100 && segs[1] == 0x0000 && segs[2] == 0x0000 && segs[3] == 0x0000
}

/// 2002::/16 — 6to4 addresses. Block if the embedded IPv4 is blocked.
/// The embedded IPv4 is in segments[1] (high 16 bits) and segments[2] (low 16 bits)...
/// Wait, 6to4 format is 2002:V4ADDR::/48 where V4ADDR is 32 bits split across segs[1..3].
/// Actually: 2002:aabb:ccdd::/48 where aabb is high 16 bits of IPv4, ccdd is low 16 bits.
fn is_6to4_blocked(ip: &Ipv6Addr) -> bool {
    let segs = ip.segments();
    if segs[0] != 0x2002 {
        return false;
    }
    // Extract embedded IPv4: segments[1] and [2] contain the 32-bit IPv4 address
    let v4_high = segs[1];
    let v4_low = segs[2];
    let v4 = Ipv4Addr::new(
        (v4_high >> 8) as u8,
        (v4_high & 0xff) as u8,
        (v4_low >> 8) as u8,
        (v4_low & 0xff) as u8,
    );
    // If the embedded IPv4 would be blocked, block this 6to4 address too
    is_ipv4_blocked(&v4)
}

/// ::ffff:0:0/96 — IPv4-mapped IPv6. Re-check the underlying IPv4 address.
fn is_ipv4_mapped_blocked(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_ipv4_blocked(&v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ── Public IPs allowed ──────────────────────────────────────────────
    #[test]
    fn allows_google_dns() {
        assert!(!is_ip_blocked(&ip("8.8.8.8")));
    }
    #[test]
    fn allows_cloudflare_dns() {
        assert!(!is_ip_blocked(&ip("1.1.1.1")));
    }
    #[test]
    fn allows_arbitrary_public() {
        assert!(!is_ip_blocked(&ip("93.184.216.34")));
    }
    #[test]
    fn allows_public_ipv6_google() {
        assert!(!is_ip_blocked(&ip("2001:4860:4860::8888")));
    }
    #[test]
    fn allows_public_ipv6_cloudflare() {
        assert!(!is_ip_blocked(&ip("2606:4700:4700::1111")));
    }

    // ── IPv4 loopback ───────────────────────────────────────────────────
    #[test]
    fn blocks_127_0_0_1() {
        assert!(is_ip_blocked(&ip("127.0.0.1")));
    }
    #[test]
    fn blocks_127_0_0_0() {
        assert!(is_ip_blocked(&ip("127.0.0.0")));
    }
    #[test]
    fn blocks_127_255_255_255() {
        assert!(is_ip_blocked(&ip("127.255.255.255")));
    }
    #[test]
    fn blocks_127_100_0_1() {
        assert!(is_ip_blocked(&ip("127.100.0.1")));
    }

    // ── RFC 1918 private ────────────────────────────────────────────────
    #[test]
    fn blocks_10_0_0_1() {
        assert!(is_ip_blocked(&ip("10.0.0.1")));
    }
    #[test]
    fn blocks_10_255_255_255() {
        assert!(is_ip_blocked(&ip("10.255.255.255")));
    }
    #[test]
    fn blocks_172_16_0_1() {
        assert!(is_ip_blocked(&ip("172.16.0.1")));
    }
    #[test]
    fn blocks_172_31_255_255() {
        assert!(is_ip_blocked(&ip("172.31.255.255")));
    }
    #[test]
    fn allows_172_32_0_1() {
        assert!(!is_ip_blocked(&ip("172.32.0.1")));
    } // boundary
    #[test]
    fn blocks_192_168_0_1() {
        assert!(is_ip_blocked(&ip("192.168.0.1")));
    }
    #[test]
    fn blocks_192_168_255_255() {
        assert!(is_ip_blocked(&ip("192.168.255.255")));
    }

    // ── Link-local ──────────────────────────────────────────────────────
    #[test]
    fn blocks_169_254_0_0() {
        assert!(is_ip_blocked(&ip("169.254.0.0")));
    }
    #[test]
    fn blocks_169_254_1_1() {
        assert!(is_ip_blocked(&ip("169.254.1.1")));
    }
    #[test]
    fn blocks_169_254_255_255() {
        assert!(is_ip_blocked(&ip("169.254.255.255")));
    }

    // ── RFC 6598 shared (100.64.0.0/10) ────────────────────────────────
    #[test]
    fn blocks_100_64_0_0() {
        assert!(is_ip_blocked(&ip("100.64.0.0")));
    }
    #[test]
    fn blocks_100_64_0_1() {
        assert!(is_ip_blocked(&ip("100.64.0.1")));
    }
    #[test]
    fn blocks_100_127_255_255() {
        assert!(is_ip_blocked(&ip("100.127.255.255")));
    }
    #[test]
    fn allows_100_128_0_0() {
        assert!(!is_ip_blocked(&ip("100.128.0.0")));
    } // boundary
    #[test]
    fn allows_100_63_255_255() {
        assert!(!is_ip_blocked(&ip("100.63.255.255")));
    } // below range

    // ── Broadcast + unspecified ─────────────────────────────────────────
    #[test]
    fn blocks_broadcast() {
        assert!(is_ip_blocked(&ip("255.255.255.255")));
    }
    #[test]
    fn blocks_unspecified_v4() {
        assert!(is_ip_blocked(&ip("0.0.0.0")));
    }

    // ── IPv6 loopback ───────────────────────────────────────────────────
    #[test]
    fn blocks_ipv6_loopback() {
        assert!(is_ip_blocked(&ip("::1")));
    }

    // ── IPv6 unspecified ────────────────────────────────────────────────
    #[test]
    fn blocks_ipv6_unspecified() {
        assert!(is_ip_blocked(&ip("::")));
    }

    // ── IPv6 link-local (fe80::/10) ─────────────────────────────────────
    #[test]
    fn blocks_fe80_link_local() {
        assert!(is_ip_blocked(&ip("fe80::1")));
    }
    #[test]
    fn blocks_fe80_high() {
        assert!(is_ip_blocked(&ip("febf::1")));
    }
    #[test]
    fn allows_fec0() {
        assert!(!is_ip_blocked(&ip("fec0::1")));
    } // not link-local

    // ── IPv6 unique-local (fc00::/7) ────────────────────────────────────
    #[test]
    fn blocks_fc00_unique_local() {
        assert!(is_ip_blocked(&ip("fc00::1")));
    }
    #[test]
    fn blocks_fd00_unique_local() {
        assert!(is_ip_blocked(&ip("fd00::1")));
    }
    #[test]
    fn blocks_fdff_unique_local() {
        assert!(is_ip_blocked(&ip("fdff::1")));
    }
    #[test]
    fn allows_fe00() {
        assert!(!is_ip_blocked(&ip("fe00::1")));
    } // boundary above

    // ── IPv6 discard prefix (100::/64) ──────────────────────────────────
    #[test]
    fn blocks_ipv6_discard() {
        assert!(is_ip_blocked(&ip("100::1")));
    }
    #[test]
    fn blocks_ipv6_discard_2() {
        assert!(is_ip_blocked(&ip("100::ffff")));
    }
    #[test]
    fn allows_101() {
        assert!(!is_ip_blocked(&ip("101::1")));
    } // adjacent range

    // ── 6to4 (2002::/16) ────────────────────────────────────────────────
    #[test]
    fn blocks_6to4_with_private_v4() {
        // 2002:0a00:0001:: embeds 10.0.0.1 (RFC 1918)
        assert!(is_ip_blocked(&ip("2002:0a00:0001::")));
    }
    #[test]
    fn blocks_6to4_with_loopback_v4() {
        // 2002:7f00:0001:: embeds 127.0.0.1
        assert!(is_ip_blocked(&ip("2002:7f00:0001::")));
    }
    #[test]
    fn blocks_6to4_with_link_local_v4() {
        // 2002:a9fe:0101:: embeds 169.254.1.1
        assert!(is_ip_blocked(&ip("2002:a9fe:0101::")));
    }
    #[test]
    fn allows_6to4_with_public_v4() {
        // 2002:0808:0808:: embeds 8.8.8.8
        assert!(!is_ip_blocked(&ip("2002:0808:0808::")));
    }

    // ── IPv4-mapped IPv6 (::ffff:0:0/96) ────────────────────────────────
    #[test]
    fn blocks_mapped_loopback() {
        assert!(is_ip_blocked(&ip("::ffff:127.0.0.1")));
    }
    #[test]
    fn blocks_mapped_private_10() {
        assert!(is_ip_blocked(&ip("::ffff:10.0.0.1")));
    }
    #[test]
    fn blocks_mapped_private_192() {
        assert!(is_ip_blocked(&ip("::ffff:192.168.1.1")));
    }
    #[test]
    fn blocks_mapped_link_local() {
        assert!(is_ip_blocked(&ip("::ffff:169.254.1.1")));
    }
    #[test]
    fn blocks_mapped_rfc6598() {
        assert!(is_ip_blocked(&ip("::ffff:100.64.0.1")));
    }
    #[test]
    fn allows_mapped_public() {
        assert!(!is_ip_blocked(&ip("::ffff:8.8.8.8")));
    }
}
