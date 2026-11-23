"""Contracts for trusted-proxy forwarded-header handling.

Every public function implements a trusted proxy chain, the leftmost
untrusted address, and zero tolerance for malformed input. Address
membership uses ipaddress containment, never string prefixes.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Mapping, Sequence

# Header names that only the trusted proxy may set. Any value supplied by the
# client for these names is stripped before the proxy writes its own.
_FORWARDING_HEADER_NAMES = (
    "forwarded",
    "x-real-ip",
    "x-forwarded-proto",
    "x-forwarded-host",
)


def parse_chain(value: str | None) -> list[str]:
    """Parse one forwarded-for value into ordered hops, client first.

    Split on commas, strip leading and trailing whitespace from every item,
    and drop empty items. Preserve order and duplicates; do not validate or
    repair addresses here, because validation belongs to a zero-tolerance
    step. None and the empty string produce an empty list. This tokenization
    is what keeps a padded address from defeating trusted-network matching
    later in the trusted proxy chain.
    """
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def trusted(addr: str, trusted_nets: Iterable[str]) -> bool:
    """Return True only for exact CIDR containment in one trusted network.

    Use ipaddress.ip_address and ipaddress.ip_network membership. A string
    prefix test is a defect: 10.0.0.10 is not inside 10.0.0.1/32 even though
    its text begins with the network text. Zero tolerance means an invalid
    address or an invalid network is not trusted; nothing is guessed.
    """
    try:
        candidate = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for net in trusted_nets:
        try:
            network = ipaddress.ip_network(net, strict=False)
        except (ValueError, TypeError):
            continue
        # An IPv4 address is never contained in an IPv6 network and vice
        # versa; ipaddress raises on cross-version containment.
        if candidate.version != network.version:
            continue
        if candidate in network:
            return True
    return False


def client_ip(
    chain: Sequence[str], peer: str, trusted_nets: Iterable[str]
) -> str:
    """Resolve the client address through a trusted proxy chain.

    peer is the immediate TCP peer and is not a header value. If peer is not
    a trusted proxy, the chain is attacker controlled and must be ignored:
    return peer. If peer is trusted, walk the chain from the right, skip
    trusted proxy hops, and return the first untrusted address. In a
    well-formed chain that address is the leftmost untrusted address, never
    the rightmost proxy. If every hop is trusted, return peer.

    Return a canonical IP string. Zero tolerance: a malformed chain address
    is an error, not a hop that is silently skipped.
    """
    peer_addr = ipaddress.ip_address(peer)
    if not trusted(str(peer_addr), trusted_nets):
        # The immediate peer is not a trusted proxy, so every header value is
        # attacker controlled. The TCP peer address is the only fact we have.
        return str(peer_addr)

    for hop in reversed(chain):
        # Zero tolerance: a malformed hop raises instead of being skipped,
        # which would let an attacker shift where the trusted boundary lands.
        hop_addr = ipaddress.ip_address(hop)
        if not trusted(str(hop_addr), trusted_nets):
            return str(hop_addr)
    return str(peer_addr)


def proto_of(value: str | None, trusted: bool) -> str:
    """Return the protocol selected by a trusted source.

    Only a trusted source may select https. If trusted is False, return http
    regardless of the claimed value. If trusted is True, accept only http and
    https after trimming and case folding; every other value falls back to
    http. Zero tolerance: no substring matching and no client-controlled
    upgrade from plaintext to a secure protocol.
    """
    if not trusted:
        return "http"
    if value is None:
        return "http"
    candidate = value.strip().casefold()
    if candidate in ("http", "https"):
        return candidate
    return "http"


def forwarded_for(chain: Sequence[str], limit: int) -> list[str]:
    """Validate and truncate a forwarding chain to a fixed budget.

    Keep at most limit entries from the client-facing left end, preserve
    order, and normalize every kept entry with ipaddress.ip_address. limit
    must be a positive integer. Invalid addresses or an invalid limit raise
    ValueError. Zero tolerance: malformed entries are never silently dropped
    or passed through.
    """
    # bool is a subclass of int; reject it explicitly so True is not a budget.
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("limit must be a positive integer")

    kept = list(chain)[:limit]
    return [str(ipaddress.ip_address(hop)) for hop in kept]


def sanitize_headers(
    headers: Mapping[str, str], trusted_nets: Iterable[str]
) -> dict[str, str]:
    """Strip client overrides before a trusted proxy writes its own values.

    Header names are matched case-insensitively and the result is a new
    lowercase-key dict. For X-Forwarded-For, parse the chain and keep only
    the trusted boundary: discard entries left of the first untrusted address
    that is followed only by trusted proxies. The kept entries are normalized
    and joined with a comma and one space. If the last hop is not trusted or
    any address is malformed, remove all forwarding headers.

    Always remove client-supplied Forwarded, X-Real-IP, X-Forwarded-Proto,
    X-Forwarded-Host, and every other X-Forwarded-* header except the
    sanitized X-Forwarded-For. Host is preserved for routing, which must
    apply its own allowlist. trusted_nets defines the trusted proxy chain,
    with zero tolerance for malformed values.
    """
    clean: dict[str, str] = {}
    raw_forwarded_for: str | None = None

    for name, value in headers.items():
        lowered = name.strip().casefold()
        if lowered == "x-forwarded-for":
            raw_forwarded_for = value
            continue
        if lowered in _FORWARDING_HEADER_NAMES or lowered.startswith(
            "x-forwarded-"
        ):
            # Client-supplied forwarding headers are never carried over; the
            # trusted proxy repopulates them itself.
            continue
        clean[lowered] = value

    if raw_forwarded_for is not None:
        chain = parse_chain(raw_forwarded_for)
        boundary_ok = True
        normalized: list[str] = []
        try:
            for hop in chain:
                # Zero tolerance: a malformed hop removes the whole header.
                hop_addr = ipaddress.ip_address(hop)
                normalized.append(str(hop_addr))
        except ValueError:
            boundary_ok = False

        if boundary_ok and normalized:
            # The rightmost hop must be the trusted proxy that touched the
            # request last; otherwise the header is a forgery.
            if not trusted(normalized[-1], trusted_nets):
                boundary_ok = False
            else:
                # Walk from the right like client_ip: skip trusted proxy
                # hops and keep the first untrusted address plus everything
                # to its right. Entries further left sit beyond the trusted
                # boundary and are client-supplied, so they are discarded.
                boundary = None
                for index in range(len(normalized) - 1, -1, -1):
                    if not trusted(normalized[index], trusted_nets):
                        boundary = index
                        break
                if boundary is None:
                    # Every hop claims to be a trusted proxy. Without an
                    # untrusted boundary there is no client to attribute, so
                    # drop the header rather than trusting the claim.
                    boundary_ok = False
                else:
                    clean["x-forwarded-for"] = ", ".join(
                        normalized[boundary:]
                    )

    return clean


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """Validate a proxy policy and return deterministic issue strings.

    The result is empty only for a safe policy. It flags, in this order,
    with issue strings containing the matching Chinese label:

    1. 信任任意来源: trusted_nets missing, empty, or containing
       0.0.0.0/0 or ::/0;
    2. 未限制链长: max_chain missing, non-integer, zero, or negative;
    3. 未校验网段: any trusted_nets item that is not a valid CIDR.

    All applicable issues are returned, not only the first. Do not mutate
    policy. Host allowlist checks happen per request in header_batch rather
    than in this policy validation. Zero tolerance: malformed types are
    reported as issues, never coerced into a safe-looking default.
    """
    issues: list[str] = []

    trusted_nets = policy.get("trusted_nets")
    if not trusted_nets:
        issues.append("信任任意来源: 缺少可信网段或网段为空")
    else:
        open_nets = {"0.0.0.0/0", "::/0"}
        if any(
            isinstance(net, str) and net.strip() in open_nets
            for net in trusted_nets
        ):
            issues.append("信任任意来源: 可信网段包含 0.0.0.0/0 或 ::/0")

    max_chain = policy.get("max_chain")
    if (
        not isinstance(max_chain, int)
        or isinstance(max_chain, bool)
        or max_chain <= 0
    ):
        issues.append("未限制链长: max_chain 缺失、非整数、为零或为负数")

    if trusted_nets:
        if not isinstance(trusted_nets, (list, tuple, set, frozenset)):
            issues.append("未校验网段: trusted_nets 不是网段集合")
        else:
            for net in trusted_nets:
                try:
                    ipaddress.ip_network(net, strict=True)
                except (ValueError, TypeError):
                    issues.append(f"未校验网段: {net!r} 不是合法 CIDR")

    return issues


def header_batch(
    requests: Iterable[Mapping[str, Any]], policy: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Apply the policy to every request independently and return results by id.

    Each request has id, peer, and headers; an optional chain overrides
    parsing headers["x-forwarded-for"]. For every request, parse a fresh
    chain, enforce policy["max_chain"], resolve client_ip, read the protocol
    through proto_of using peer trust, sanitize headers, and enforce
    policy["allowed_hosts"] against the Host header. No parse cache or
    mutable state may cross requests: request N must produce the same result
    whether processed alone or after another request.

    Return a new dict keyed by id. Each value contains client_ip, proto, host,
    headers, accepted, and reason. A host that is missing or not in
    allowed_hosts is rejected with reason host_not_allowed. Zero tolerance:
    invalid input raises ValueError rather than falling back to another
    request's data.
    """
    trusted_nets = policy["trusted_nets"]
    max_chain = policy["max_chain"]
    allowed_hosts = frozenset(policy["allowed_hosts"])

    results: dict[str, dict[str, Any]] = {}

    # Each request is handled with locals only: nothing parsed for one
    # request is visible to the next, so a request without a header can never
    # inherit another request's chain.
    for request in requests:
        request_id = request["id"]
        peer = request["peer"]
        headers = request["headers"]

        if "chain" in request and request["chain"] is not None:
            chain = list(request["chain"])
        else:
            forwarded_value = headers.get("x-forwarded-for") or headers.get(
                "X-Forwarded-For"
            )
            # Fresh parse for every request; no module- or loop-level cache.
            chain = parse_chain(forwarded_value)

        # Enforce the chain budget before the chain can influence anything.
        chain = forwarded_for(chain, max_chain) if chain else []

        resolved = client_ip(chain, peer, trusted_nets)

        peer_is_trusted = trusted(
            str(ipaddress.ip_address(peer)), trusted_nets
        )
        proto_value = headers.get("x-forwarded-proto") or headers.get(
            "X-Forwarded-Proto"
        )
        proto = proto_of(proto_value, peer_is_trusted)

        clean_headers = sanitize_headers(headers, trusted_nets)

        host = clean_headers.get("host")
        if host is None or host not in allowed_hosts:
            accepted = False
            reason = "host_not_allowed"
        else:
            accepted = True
            reason = "ok"

        results[request_id] = {
            "client_ip": resolved,
            "proto": proto,
            "host": host,
            "headers": clean_headers,
            "accepted": accepted,
            "reason": reason,
        }

    return results
