"""Tests for ics_finder.misp_warninglists."""

import ipaddress
import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import pytest

from ics_finder.misp_warninglists import (
    _parse_network,
    _extract_networks_from_list,
    load_warninglists_from_file,
    networks_from_iterable,
)


class TestParseNetwork:
    def test_ipv4_host(self):
        net = _parse_network("192.168.1.1")
        assert net is not None
        assert isinstance(net, ipaddress.IPv4Network)

    def test_ipv4_cidr(self):
        net = _parse_network("10.0.0.0/8")
        assert net is not None
        assert str(net) == "10.0.0.0/8"

    def test_ipv6_cidr(self):
        net = _parse_network("2001:db8::/32")
        assert net is not None
        assert isinstance(net, ipaddress.IPv6Network)

    def test_with_port_annotation(self):
        # Should strip the port part before parsing
        net = _parse_network("192.168.1.1|80")
        assert net is not None
        assert isinstance(net, ipaddress.IPv4Network)

    def test_hostname_returns_none(self):
        assert _parse_network("example.com") is None

    def test_empty_returns_none(self):
        assert _parse_network("") is None

    def test_random_string_returns_none(self):
        assert _parse_network("not-an-ip") is None


class TestExtractNetworks:
    def test_ip_list_type(self):
        list_data = {
            "name": "Test IP list",
            "type": "cidr",
            "list": ["10.0.0.0/8", "192.168.0.0/16", "example.com"],
        }
        nets = list(_extract_networks_from_list(list_data))
        assert len(nets) == 2
        cidrs = {str(n) for n in nets}
        assert "10.0.0.0/8" in cidrs
        assert "192.168.0.0/16" in cidrs

    def test_hostname_list_type_skipped(self):
        list_data = {
            "name": "Hostname list",
            "type": "hostname",
            "list": ["example.com", "test.org"],
        }
        nets = list(_extract_networks_from_list(list_data))
        assert nets == []

    def test_mixed_list_no_type(self):
        list_data = {
            "name": "Mixed",
            "type": "",
            "list": ["10.0.0.1", "not-an-ip", "2001:db8::/32"],
        }
        nets = list(_extract_networks_from_list(list_data))
        assert len(nets) == 2

    def test_empty_list(self):
        list_data = {"name": "Empty", "type": "cidr", "list": []}
        nets = list(_extract_networks_from_list(list_data))
        assert nets == []


class TestLoadWarninglistsFromFile:
    def test_reads_cidrs(self):
        content = "10.0.0.0/8\n192.168.0.0/16\n# a comment\n\n172.16.0.0/12\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            nets = load_warninglists_from_file(path)
            cidrs = {str(n) for n in nets}
            assert "10.0.0.0/8" in cidrs
            assert "192.168.0.0/16" in cidrs
            assert "172.16.0.0/12" in cidrs
        finally:
            os.unlink(path)

    def test_ignores_blank_and_comments(self):
        content = "# comment\n\n10.0.0.0/8\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            nets = load_warninglists_from_file(path)
            assert len(nets) == 1
        finally:
            os.unlink(path)

    def test_collapses_adjacent(self):
        # 10.0.0.0/25 and 10.0.0.128/25 should collapse to 10.0.0.0/24
        content = "10.0.0.0/25\n10.0.0.128/25\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            nets = load_warninglists_from_file(path)
            assert str(nets[0]) == "10.0.0.0/24"
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with pytest.raises(OSError):
            load_warninglists_from_file("/nonexistent/path/file.txt")


class TestNetworksFromIterable:
    def test_basic(self):
        nets = networks_from_iterable(["10.0.0.0/8", "192.168.0.0/16"])
        cidrs = {str(n) for n in nets}
        assert "10.0.0.0/8" in cidrs
        assert "192.168.0.0/16" in cidrs

    def test_skips_non_ip(self):
        nets = networks_from_iterable(["10.0.0.0/8", "not-an-ip", "example.com"])
        assert len(nets) == 1

    def test_empty(self):
        nets = networks_from_iterable([])
        assert nets == []

    def test_deduplicates(self):
        nets = networks_from_iterable(["10.0.0.0/8", "10.0.0.0/8"])
        assert len(nets) == 1
