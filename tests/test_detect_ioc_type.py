"""
Tests for IOC type detection in 3nricher.py.

The entrypoint file is named `3nricher.py` (starts with a digit),
which cannot be imported with a normal `import` statement. Use
importlib.import_module() to load it dynamically.
"""
import importlib

import pytest


# Load 3nricher.py as a module without running main()
_mod = importlib.import_module("3nricher")
detect_ioc_type = _mod.detect_ioc_type


class TestDetectIocType:
    def test_ipv4(self):
        assert detect_ioc_type("8.8.8.8") == "ip"
        assert detect_ioc_type("185.220.101.1") == "ip"
        assert detect_ioc_type("192.168.1.1") == "ip"
        assert detect_ioc_type("255.255.255.255") == "ip"

    def test_md5(self):
        assert detect_ioc_type("84c82835a5d21bbcf75a61706d8ab549") == "md5"
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
        assert detect_ioc_type("a" * 40) == "sha1"

    def test_sha256(self):
        assert detect_ioc_type(
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ) == "sha256"
        assert detect_ioc_type("a" * 64) == "sha256"

    def test_domain(self):
        assert detect_ioc_type("google.com") == "domain"
        assert detect_ioc_type("malware-traffic-analysis.net") == "domain"
        assert detect_ioc_type("sub.example.co.uk") == "domain"
        assert detect_ioc_type("a.b.c.d.example.com") == "domain"

    def test_unknown(self):
        assert detect_ioc_type("not-an-ioc") == "unknown"
        assert detect_ioc_type("!!!") == "unknown"
        assert detect_ioc_type("") == "unknown"
        assert detect_ioc_type("just text") == "unknown"

    def test_strips_whitespace(self):
        assert detect_ioc_type("  8.8.8.8  ") == "ip"
        assert detect_ioc_type("google.com\n") == "domain"
        assert detect_ioc_type("\t185.220.101.1") == "ip"
