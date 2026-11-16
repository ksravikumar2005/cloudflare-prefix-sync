#!/usr/bin/env python3
"""
Read-only exposure audit: is Cloudflare the ONLY way into your AWS entry points?
================================================================================
The sync engine keeps the Cloudflare prefix lists current. This module checks the
other half of the requirement: that the security groups and load balancers which
should sit behind Cloudflare accept traffic from nothing else.

It never modifies anything. It needs only these read permissions:
  ec2:DescribeSecurityGroups
  elasticloadbalancing:DescribeLoadBalancers / DescribeListeners / DescribeRules

Checks
------
Security groups (explicit IDs, plus the SGs of internet-facing load balancers
when `audit_all_load_balancers` is enabled):
  - OPEN_TO_INTERNET                  HIGH    ingress from 0.0.0.0/0 or ::/0
  - NON_CLOUDFLARE_CIDR               MEDIUM  ingress from any other public CIDR
  - PRIVATE_CIDR                      LOW     ingress from a private (RFC1918) range
  - OTHER_PREFIX_LIST                 MEDIUM  ingress from a prefix list we do not manage
  - NON_CLOUDFLARE_SECURITY_GROUP     LOW     ingress from another security group
  - MISSING_CLOUDFLARE_PREFIX_LIST    MEDIUM  SG has no rule using the managed prefix lists

Load balancers (internet-facing ALB/NLB):
  - NLB_WITHOUT_SECURITY_GROUP        HIGH    an NLB with no SG cannot be restricted to Cloudflare
  - ORIGIN_AUTH_MISSING               MEDIUM  ALB has no mTLS (verify mode) and no http-header
                                              listener rule. Cloudflare IP ranges are shared by
                                              every Cloudflare customer, so IP allow-listing alone
                                              does not prove traffic came from YOUR zone.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set

logger = logging.getLogger("cloudflare_prefix_sync.audit")

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

_OPEN_V4 = "0.0.0.0/0"
_OPEN_V6 = "::/0"


def _chunks(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _finding(
    severity: str,
    code: str,
    resource: str,
    detail: str,
    **extra: Any,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "severity": severity,
        "code": code,
        "resource": resource,
        "detail": detail,
    }
    out.update(extra)
    return out


def _port_label(perm: Dict[str, Any]) -> str:
    proto = perm.get("IpProtocol", "?")
    if proto == "-1":
        return "all traffic"
    return f"{proto}/{perm.get('FromPort', '*')}-{perm.get('ToPort', '*')}"


@dataclass(frozen=True)
class AllowList:
    """Sources that are intentionally allowed and must not be reported or revoked."""

    cidrs: FrozenSet[str] = frozenset()
    prefix_list_ids: FrozenSet[str] = frozenset()
    security_group_ids: FrozenSet[str] = frozenset()

    @staticmethod
    def build(
        cidrs: Optional[Iterable[str]] = None,
        prefix_list_ids: Optional[Iterable[str]] = None,
        security_group_ids: Optional[Iterable[str]] = None,
    ) -> "AllowList":
        def norm(items: Optional[Iterable[str]]) -> FrozenSet[str]:
            return frozenset(i.strip() for i in (items or []) if i and i.strip())

        return AllowList(norm(cidrs), norm(prefix_list_ids), norm(security_group_ids))


_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
    "100.64.0.0/10",                                  # RFC6598 carrier-grade NAT
    "127.0.0.0/8", "169.254.0.0/16",                  # loopback, link-local
    "fc00::/7", "fe80::/10", "::1/128",               # IPv6 ULA, link-local, loopback
))


def is_private_cidr(cidr: str) -> bool:
    """
    True when the whole range is internal (RFC1918, CGNAT, ULA, loopback, link-local).
    Python's `is_private` is not used because it also covers documentation ranges.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return any(net.version == p.version and net.subnet_of(p) for p in _PRIVATE_NETWORKS)


def classify_ingress_sources(
    sg: Dict[str, Any],
    managed_prefix_list_ids: Iterable[str],
    allow: Optional[AllowList] = None,
) -> List[Dict[str, Any]]:
    """
    Flattens a security group's ingress into one record per source. Each record has:
      kind: cidr | prefix_list | security_group
      source, permission (the full IpPermission it came from), port label,
      category: open_to_internet | private_cidr | public_cidr | cloudflare_prefix_list |
                other_prefix_list | security_group | allowed
    """
    managed = {pl for pl in managed_prefix_list_ids if pl}
    allow = allow or AllowList()
    sg_id = sg["GroupId"]
    out: List[Dict[str, Any]] = []

    for perm in sg.get("IpPermissions", []):
        port = _port_label(perm)

        def add(kind: str, source: str, category: str) -> None:
            if (
                (kind == "cidr" and source in allow.cidrs)
                or (kind == "prefix_list" and source in allow.prefix_list_ids)
                or (kind == "security_group" and source in allow.security_group_ids)
            ):
                category = "allowed"
            out.append({"kind": kind, "source": source, "category": category,
                        "port": port, "permission": perm, "group_id": sg_id})

        for rng in perm.get("IpRanges", []):
            cidr = rng.get("CidrIp", "")
            cat = "open_to_internet" if cidr == _OPEN_V4 else (
                "private_cidr" if is_private_cidr(cidr) else "public_cidr")
            add("cidr", cidr, cat)
        for rng in perm.get("Ipv6Ranges", []):
            cidr = rng.get("CidrIpv6", "")
            cat = "open_to_internet" if cidr == _OPEN_V6 else (
                "private_cidr" if is_private_cidr(cidr) else "public_cidr")
            add("cidr", cidr, cat)
        for pl in perm.get("PrefixListIds", []):
            pl_id = pl.get("PrefixListId", "")
            add("prefix_list", pl_id, "cloudflare_prefix_list" if pl_id in managed else "other_prefix_list")
        for pair in perm.get("UserIdGroupPairs", []):
            src = pair.get("GroupId", "")
            if src == sg_id:
                continue  # self-reference is not an external path
            add("security_group", src, "security_group")
    return out


def classify_security_group(
    sg: Dict[str, Any],
    managed_prefix_list_ids: Iterable[str],
    allow: Optional[AllowList] = None,
) -> str:
    """cloudflare_only | open_to_internet | other_sources | no_ingress"""
    sources = classify_ingress_sources(sg, managed_prefix_list_ids, allow)
    if not sources:
        return "no_ingress"
    cats = {s["category"] for s in sources}
    if "open_to_internet" in cats:
        return "open_to_internet"
    if cats <= {"cloudflare_prefix_list", "allowed"} and "cloudflare_prefix_list" in cats:
        return "cloudflare_only"
    if cats <= {"allowed"}:
        return "no_ingress"
    return "other_sources"


def audit_security_group_rules(
    security_groups: List[Dict[str, Any]],
    managed_prefix_list_ids: Iterable[str],
    allow: Optional[AllowList] = None,
) -> List[Dict[str, Any]]:
    """Pure function: inspects `describe_security_groups` output and returns findings."""
    managed = {pl for pl in managed_prefix_list_ids if pl}
    findings: List[Dict[str, Any]] = []

    for sg in security_groups:
        sg_id = sg["GroupId"]
        referenced_managed: Set[str] = set()

        for src in classify_ingress_sources(sg, managed, allow):
            cat, source, port = src["category"], src["source"], src["port"]
            if cat == "allowed":
                continue
            if cat == "cloudflare_prefix_list":
                referenced_managed.add(source)
            elif cat == "open_to_internet":
                findings.append(_finding(
                    SEVERITY_HIGH, "OPEN_TO_INTERNET", sg_id,
                    f"Allows {port} from {source}, bypassing Cloudflare.", source=source))
            elif cat == "public_cidr":
                findings.append(_finding(
                    SEVERITY_MEDIUM, "NON_CLOUDFLARE_CIDR", sg_id,
                    f"Allows {port} from {source}, which is not Cloudflare-managed.", source=source))
            elif cat == "private_cidr":
                findings.append(_finding(
                    SEVERITY_LOW, "PRIVATE_CIDR", sg_id,
                    f"Allows {port} from private range {source}.", source=source))
            elif cat == "other_prefix_list":
                findings.append(_finding(
                    SEVERITY_MEDIUM, "OTHER_PREFIX_LIST", sg_id,
                    f"Allows {port} from prefix list {source}, which this tool does not manage.",
                    source=source))
            elif cat == "security_group":
                findings.append(_finding(
                    SEVERITY_LOW, "NON_CLOUDFLARE_SECURITY_GROUP", sg_id,
                    f"Allows {port} from security group {source}.", source=source))

        missing = managed - referenced_managed
        if managed and missing:
            findings.append(_finding(
                SEVERITY_MEDIUM, "MISSING_CLOUDFLARE_PREFIX_LIST", sg_id,
                "No ingress rule uses the managed Cloudflare prefix list(s): "
                + ", ".join(sorted(missing)), missing=sorted(missing)))

    return findings


def _describe_security_groups(ec2_client: Any, sg_ids: List[str]) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    for chunk in _chunks(sorted(set(sg_ids)), 100):
        resp = ec2_client.describe_security_groups(GroupIds=chunk)
        groups.extend(resp.get("SecurityGroups", []))
    return groups


def _paginate(call: Any, result_key: str, token_in: str, token_out: str, **kwargs: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        args = dict(kwargs)
        if token:
            args[token_in] = token
        resp = call(**args)
        items.extend(resp.get(result_key, []))
        token = resp.get(token_out)
        if not token:
            return items


def detect_alb_origin_auth(elbv2_client: Any, lb_arn: str) -> str:
    """Returns 'mtls', 'header_rule' or 'none' for an ALB's HTTPS listeners."""
    listeners = _paginate(
        elbv2_client.describe_listeners, "Listeners", "Marker", "NextMarker",
        LoadBalancerArn=lb_arn,
    )
    https = [l for l in listeners if l.get("Protocol") == "HTTPS"]
    if not https:
        return "none"
    if all((l.get("MutualAuthentication") or {}).get("Mode") == "verify" for l in https):
        return "mtls"
    for listener in https:
        rules = elbv2_client.describe_rules(ListenerArn=listener["ListenerArn"]).get("Rules", [])
        for rule in rules:
            if rule.get("IsDefault"):
                continue
            if any(c.get("Field") == "http-header" for c in rule.get("Conditions", [])):
                return "header_rule"
    return "none"


def audit_load_balancers(
    elbv2_client: Any,
    scope_sg_ids: Set[str],
    audit_all: bool,
) -> Dict[str, Any]:
    """
    Returns {"load_balancers": [...], "findings": [...], "sg_ids": set}.
    In scope: internet-facing ALB/NLBs that use one of `scope_sg_ids`, or all of them if `audit_all`.
    """
    lbs = _paginate(
        elbv2_client.describe_load_balancers, "LoadBalancers", "Marker", "NextMarker"
    )
    findings: List[Dict[str, Any]] = []
    audited: List[Dict[str, Any]] = []
    discovered_sg_ids: Set[str] = set()

    for lb in lbs:
        if lb.get("Scheme") != "internet-facing" or lb.get("Type") not in ("application", "network"):
            continue
        lb_sgs = set(lb.get("SecurityGroups", []))
        if not audit_all and not (lb_sgs & scope_sg_ids):
            continue

        name = lb.get("LoadBalancerName", lb["LoadBalancerArn"])
        entry: Dict[str, Any] = {
            "name": name,
            "arn": lb["LoadBalancerArn"],
            "type": lb["Type"],
            "security_groups": sorted(lb_sgs),
        }
        discovered_sg_ids |= lb_sgs

        if lb["Type"] == "network":
            if not lb_sgs:
                findings.append(_finding(
                    SEVERITY_HIGH, "NLB_WITHOUT_SECURITY_GROUP", name,
                    "Internet-facing NLB has no security group, so it cannot be restricted to Cloudflare."))
        else:
            try:
                auth = detect_alb_origin_auth(elbv2_client, lb["LoadBalancerArn"])
            except Exception as exc:
                logger.warning("Origin auth check failed for %s: %s", name, exc)
                auth = "unknown"
            entry["origin_auth"] = auth
            if auth == "none":
                findings.append(_finding(
                    SEVERITY_MEDIUM, "ORIGIN_AUTH_MISSING", name,
                    "No mTLS (verify mode) and no http-header listener rule. Any Cloudflare customer "
                    "can proxy to this origin. Enable Authenticated Origin Pulls or require a secret header."))
        audited.append(entry)

    return {"load_balancers": audited, "findings": findings, "sg_ids": discovered_sg_ids}


def run_exposure_audit(
    ec2_client: Any,
    elbv2_client: Optional[Any],
    managed_prefix_list_ids: List[str],
    explicit_sg_ids: List[str],
    audit_all_load_balancers: bool = False,
    allow: Optional[AllowList] = None,
    extra_sg_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Runs the full read-only audit and returns a JSON-serializable report."""
    explicit = {s.strip() for s in explicit_sg_ids if s and s.strip()}
    findings: List[Dict[str, Any]] = []
    lb_report: List[Dict[str, Any]] = []
    errors: List[str] = []
    sg_ids = set(explicit) | {s for s in (extra_sg_ids or []) if s}

    if elbv2_client is not None and (explicit or audit_all_load_balancers):
        try:
            lb_result = audit_load_balancers(elbv2_client, explicit, audit_all_load_balancers)
            findings.extend(lb_result["findings"])
            lb_report = lb_result["load_balancers"]
            sg_ids |= lb_result["sg_ids"]
        except Exception as exc:
            errors.append(f"load balancer audit failed: {exc}")
            logger.warning("Load balancer audit failed: %s", exc)
    elif audit_all_load_balancers:
        errors.append("audit_all_load_balancers requested but no elbv2 client was provided")

    audited_groups: List[Dict[str, Any]] = []
    if sg_ids:
        try:
            audited_groups = _describe_security_groups(ec2_client, sorted(sg_ids))
            findings.extend(audit_security_group_rules(audited_groups, managed_prefix_list_ids, allow))
        except Exception as exc:
            errors.append(f"security group audit failed: {exc}")
            logger.warning("Security group audit failed: %s", exc)

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)}
    return {
        "compliant": not errors and counts[SEVERITY_HIGH] == 0 and counts[SEVERITY_MEDIUM] == 0,
        "security_groups_audited": len(audited_groups),
        "load_balancers_audited": len(lb_report),
        "counts": counts,
        "findings": findings,
        "load_balancers": lb_report,
        "errors": errors,
        "_groups": audited_groups,  # raw describe output; callers pop it
    }
