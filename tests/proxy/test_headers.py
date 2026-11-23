"""Contract tests for engine.proxy.headers.

There are exactly fifteen tests. Each one calls a stub directly, so the
initial repository state must report fifteen failures and zero errors.
"""

from engine.proxy import headers

TRUSTED_NETS = ["10.0.0.0/8"]
POLICY = {
    "trusted_nets": TRUSTED_NETS,
    "max_chain": 4,
    "allowed_hosts": ["app.example.com"],
}


def test_parse_chain_strips_whitespace_and_empty_items():
    chain = headers.parse_chain(" 10.0.0.2 , 203.0.113.9 ,, ")
    assert chain == ["10.0.0.2", "203.0.113.9"]
    assert headers.trusted(chain[0], TRUSTED_NETS) is True


def test_client_ip_does_not_use_rightmost_proxy():
    got = headers.client_ip(["203.0.113.9", "10.0.0.2"], "10.0.0.3", TRUSTED_NETS)
    assert got == "203.0.113.9"


def test_client_ip_ignores_chain_from_untrusted_peer():
    got = headers.client_ip(["203.0.113.9"], "198.51.100.77", TRUSTED_NETS)
    assert got == "198.51.100.77"


def test_trusted_uses_network_containment_not_string_prefix():
    nets = ["10.0.0.1/32"]
    assert headers.trusted("10.0.0.1", nets) is True
    assert headers.trusted("10.0.0.10", nets) is False
    assert headers.trusted("10.0.0.999", nets) is False


def test_forwarded_for_enforces_chain_limit():
    long_chain = ["203.0.113.%d" % octet for octet in range(1, 31)]
    kept = headers.forwarded_for(long_chain, 3)
    assert kept == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]


def test_proto_of_requires_trusted_source():
    assert headers.proto_of("https", True) == "https"
    assert headers.proto_of("HTTP", True) == "http"
    assert headers.proto_of("https", False) == "http"


def test_sanitize_headers_drops_client_forwarding_overrides():
    raw = {
        "Host": "app.example.com",
        "X-Forwarded-For": "198.51.100.99, 203.0.113.9, 10.0.0.2",
        "X-Real-IP": "198.51.100.99",
        "X-Forwarded-Proto": "https",
        "Accept": "text/html",
    }
    clean = headers.sanitize_headers(raw, TRUSTED_NETS)
    assert clean.get("x-forwarded-for") == "203.0.113.9, 10.0.0.2"
    assert "x-real-ip" not in clean
    assert "x-forwarded-proto" not in clean
    assert clean["host"] == "app.example.com"


def test_header_batch_rejects_host_outside_allowlist():
    request = {
        "id": "evil-host",
        "peer": "10.0.0.2",
        "headers": {
            "host": "evil.example.com",
            "x-forwarded-for": "203.0.113.9",
        },
    }
    result = headers.header_batch([request], POLICY)["evil-host"]
    assert result["accepted"] is False
    assert result["reason"] == "host_not_allowed"


def test_validate_policy_flags_trust_any_source():
    issues = headers.validate_policy(
        {
            "trusted_nets": ["0.0.0.0/0", "10.0.0.0/33"],
            "max_chain": 0,
        }
    )
    assert any("信任任意来源" in issue for issue in issues)
    assert any("未限制链长" in issue for issue in issues)
    assert any("未校验网段" in issue for issue in issues)


def test_header_batch_does_not_reuse_previous_chain():
    requests = [
        {
            "id": "first",
            "peer": "10.0.0.2",
            "headers": {
                "host": "app.example.com",
                "x-forwarded-for": "203.0.113.9",
            },
        },
        {
            "id": "second",
            "peer": "10.0.0.2",
            "headers": {"host": "app.example.com"},
        },
    ]
    result = headers.header_batch(requests, POLICY)
    assert result["first"]["client_ip"] == "203.0.113.9"
    assert result["second"]["client_ip"] == "10.0.0.2"


def test_single_proxy_returns_real_client():
    got = headers.client_ip(["203.0.113.9"], "10.0.0.2", TRUSTED_NETS)
    assert got == "203.0.113.9"


def test_forged_header_is_ignored():
    raw = {
        "host": "app.example.com",
        "x-forwarded-for": "10.0.0.5, 198.51.100.77",
        "x-real-ip": "10.0.0.5",
    }
    clean = headers.sanitize_headers(raw, TRUSTED_NETS)
    assert "x-forwarded-for" not in clean
    assert "x-real-ip" not in clean
    assert clean["host"] == "app.example.com"


def test_overlong_chain_is_truncated():
    chain = ["203.0.113.9", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    assert headers.forwarded_for(chain, 2) == ["203.0.113.9", "10.0.0.2"]


def test_untrusted_source_cannot_rewrite_protocol():
    assert headers.proto_of("https", False) == "http"


def test_two_batches_match_individual_requests():
    requests = [
        {
            "id": "one",
            "peer": "10.0.0.2",
            "headers": {
                "host": "app.example.com",
                "x-forwarded-for": "203.0.113.9",
            },
        },
        {
            "id": "two",
            "peer": "10.0.0.3",
            "headers": {
                "host": "app.example.com",
                "x-forwarded-for": "203.0.113.10",
            },
        },
    ]
    batched = headers.header_batch(requests, POLICY)
    separate = {}
    separate.update(headers.header_batch([requests[0]], POLICY))
    separate.update(headers.header_batch([requests[1]], POLICY))
    assert batched == separate
