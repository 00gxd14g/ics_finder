"""Tests for ics_finder.ip_utils."""

import ipaddress

import pytest

from ics_finder.ip_utils import (
    count_hosts,
    parse_network,
    subtract_networks,
    iter_hosts,
    chunked_hosts,
)


class TestParseNetwork:
    def test_cidr_ipv4(self):
        net = parse_network("192.168.1.0/24")
        assert isinstance(net, ipaddress.IPv4Network)
        assert str(net) == "192.168.1.0/24"

    def test_bare_ipv4_host(self):
        net = parse_network("10.0.0.1")
        assert isinstance(net, ipaddress.IPv4Network)
        assert net.prefixlen == 32

    def test_cidr_ipv6(self):
        net = parse_network("2001:db8::/32")
        assert isinstance(net, ipaddress.IPv6Network)

    def test_bare_ipv6_host(self):
        net = parse_network("::1")
        assert isinstance(net, ipaddress.IPv6Network)
        assert net.prefixlen == 128

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_network("not-an-ip")

    def test_strips_whitespace(self):
        net = parse_network("  10.0.0.0/8  ")
        assert str(net) == "10.0.0.0/8"


class TestSubtractNetworks:
    def test_no_exclusion(self):
        targets = [parse_network("10.0.0.0/24")]
        result = subtract_networks(targets, [])
        # Should contain the original network (possibly collapsed).
        all_nets = list(ipaddress.collapse_addresses(result))
        assert parse_network("10.0.0.0/24") in all_nets

    def test_full_exclusion(self):
        targets = [parse_network("10.0.0.0/24")]
        exclusions = [parse_network("10.0.0.0/24")]
        result = subtract_networks(targets, exclusions)
        assert result == []

    def test_partial_exclusion(self):
        # Exclude the first /25 from a /24 — should leave the second /25.
        targets = [parse_network("10.0.0.0/24")]
        exclusions = [parse_network("10.0.0.0/25")]
        result = subtract_networks(targets, exclusions)
        # All remaining hosts must be in 10.0.0.128/25
        for net in result:
            assert net.subnet_of(parse_network("10.0.0.128/25"))

    def test_exclusion_larger_than_target(self):
        targets = [parse_network("10.1.2.0/24")]
        exclusions = [parse_network("10.0.0.0/8")]
        result = subtract_networks(targets, exclusions)
        assert result == []

    def test_non_overlapping_exclusion(self):
        targets = [parse_network("192.168.1.0/24")]
        exclusions = [parse_network("10.0.0.0/8")]
        result = subtract_networks(targets, exclusions)
        combined = list(ipaddress.collapse_addresses(result))
        assert parse_network("192.168.1.0/24") in combined

    def test_multiple_exclusions(self):
        targets = [parse_network("10.0.0.0/8")]
        exclusions = [
            parse_network("10.0.0.0/9"),
            parse_network("10.128.0.0/9"),
        ]
        result = subtract_networks(targets, exclusions)
        assert result == []

    def test_host_exclusion(self):
        targets = [parse_network("10.0.0.0/30")]
        exclusions = [parse_network("10.0.0.1/32")]
        result = subtract_networks(targets, exclusions)
        remaining_hosts = list(iter_hosts(result))
        assert ipaddress.ip_address("10.0.0.1") not in remaining_hosts
        # 10.0.0.2 should still be reachable
        assert ipaddress.ip_address("10.0.0.2") in remaining_hosts


class TestIterHosts:
    def test_slash24(self):
        net = parse_network("10.0.0.0/24")
        hosts = list(iter_hosts([net]))
        assert len(hosts) == 254  # .1 – .254

    def test_slash32(self):
        net = parse_network("10.0.0.1/32")
        hosts = list(iter_hosts([net]))
        assert len(hosts) == 1
        assert hosts[0] == ipaddress.ip_address("10.0.0.1")

    def test_slash31(self):
        net = parse_network("10.0.0.0/31")
        hosts = list(iter_hosts([net]))
        assert len(hosts) == 2

    def test_multiple_networks(self):
        nets = [parse_network("10.0.0.0/30"), parse_network("10.0.1.0/30")]
        hosts = list(iter_hosts(nets))
        # Each /30 has 2 hosts.
        assert len(hosts) == 4


class TestChunkedHosts:
    def test_chunks_correct_size(self):
        net = parse_network("10.0.0.0/24")  # 254 hosts
        chunks = list(chunked_hosts([net], chunk_size=100))
        sizes = [len(c) for c in chunks]
        assert sizes == [100, 100, 54]

    def test_chunk_size_larger_than_network(self):
        net = parse_network("10.0.0.0/30")  # 2 hosts
        chunks = list(chunked_hosts([net], chunk_size=100))
        assert len(chunks) == 1
        assert len(chunks[0]) == 2


class TestCountHosts:
    def test_slash24(self):
        assert count_hosts([parse_network("10.0.0.0/24")]) == 254

    def test_slash32(self):
        assert count_hosts([parse_network("10.0.0.1/32")]) == 1

    def test_slash31(self):
        assert count_hosts([parse_network("10.0.0.0/31")]) == 2

    def test_multiple(self):
        nets = [parse_network("10.0.0.0/30"), parse_network("10.0.1.0/30")]
        assert count_hosts(nets) == 4
