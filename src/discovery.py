#!/usr/bin/env python3
"""
Discovery: read-only inventory of how your AWS account can be reached from the internet.
=======================================================================================
Used by `mode=discover`. Needs no prefix lists and never contacts Cloudflare or writes to AWS.

Inventoried entry points
  - Internet-facing ALB and NLB (security groups, origin authentication)
  - CloudFront distributions (a second public front door unless Cloudflare is its only client)
  - Running EC2 instances with a public IP address

Every security group found is classified:
  cloudflare_only   all ingress comes from the managed Cloudflare prefix lists
  open_to_internet  at least one rule allows 0.0.0.0/0 or ::/0
  other_sources     reachable from other CIDRs, prefix lists or security groups
  no_ingress        no inbound rules
and flagged `opted_in` if it carries the management tag (see remediate.py).

Required read permissions
  ec2:DescribeSecurityGroups, ec2:DescribeInstances,
  elasticloadbalancing:DescribeLoadBalancers/DescribeListeners/DescribeRules,
  cloudfront:ListDistributions
A missing permission is reported under `errors`; the rest of the report is still produced.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    from src.audit import (
        AllowList,
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        _finding,
        _paginate,
        audit_load_balancers,
        audit_security_group_rules,
        classify_security_group,
    )
except ImportError:  # Lambda flat layout
    from audit import (  # type: ignore
        AllowList,
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        _finding,
        _paginate,
        audit_load_balancers,
        audit_security_group_rules,
        classify_security_group,
    )

logger = logging.getLogger("cloudflare_prefix_sync.discovery")


def _describe_sgs(ec2_client: Any, sg_ids: Iterable[str]) -> List[Dict[str, Any]]:
    ids = sorted({s for s in sg_ids if s})
    groups: List[Dict[str, Any]] = []
    for i in range(0, len(ids), 100):
        resp = ec2_client.describe_security_groups(GroupIds=ids[i : i + 100])
        groups.extend(resp.get("SecurityGroups", []))
    return groups


def discover_public_instances(ec2_client: Any) -> List[Dict[str, Any]]:
    """Running EC2 instances that have a public IPv4 or an IPv6 address."""
    reservations = _paginate(
        ec2_client.describe_instances, "Reservations", "NextToken", "NextToken",
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
    )
    out: List[Dict[str, Any]] = []
    for res in reservations:
        for inst in res.get("Instances", []):
            public_ip = inst.get("PublicIpAddress")
            ipv6 = [a.get("Ipv6Address") for ni in inst.get("NetworkInterfaces", [])
                    for a in ni.get("Ipv6Addresses", [])]
            if not public_ip and not ipv6:
                continue
            name = next((t["Value"] for t in inst.get("Tags", []) if t.get("Key") == "Name"), "")
            out.append({
                "instance_id": inst["InstanceId"],
                "name": name,
                "public_ip": public_ip,
                "ipv6": [a for a in ipv6 if a],
                "security_groups": sorted(g["GroupId"] for g in inst.get("SecurityGroups", [])),
            })
    return out


def discover_cloudfront(cloudfront_client: Any) -> List[Dict[str, Any]]:
    """CloudFront distributions with their origins and WAF association."""
    out: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Marker": marker} if marker else {}
        resp = cloudfront_client.list_distributions(**kwargs)
        dist_list = resp.get("DistributionList", {})
        for d in dist_list.get("Items", []) or []:
            origins = [o.get("DomainName", "") for o in (d.get("Origins", {}) or {}).get("Items", []) or []]
            out.append({
                "id": d["Id"],
                "domain_name": d.get("DomainName", ""),
                "aliases": (d.get("Aliases", {}) or {}).get("Items", []) or [],
                "enabled": bool(d.get("Enabled", True)),
                "web_acl_id": d.get("WebACLId", "") or "",
                "origins": origins,
            })
        if dist_list.get("IsTruncated") and dist_list.get("NextMarker"):
            marker = dist_list["NextMarker"]
        else:
            return out


def run_discovery(
    ec2_client: Any,
    elbv2_client: Optional[Any] = None,
    cloudfront_client: Optional[Any] = None,
    managed_prefix_list_ids: Optional[List[str]] = None,
    tagged_sg_ids: Optional[Set[str]] = None,
    allow: Optional[AllowList] = None,
) -> Dict[str, Any]:
    """Builds the full read-only inventory and exposure report."""
    managed = [p for p in (managed_prefix_list_ids or []) if p]
    tagged = set(tagged_sg_ids or set())
    errors: List[str] = []
    findings: List[Dict[str, Any]] = []
    sg_attachments: Dict[str, List[str]] = {}

    load_balancers: List[Dict[str, Any]] = []
    if elbv2_client is not None:
        try:
            lb_result = audit_load_balancers(elbv2_client, set(), audit_all=True)
            load_balancers = lb_result["load_balancers"]
            findings.extend(lb_result["findings"])
            for lb in load_balancers:
                for sg_id in lb["security_groups"]:
                    sg_attachments.setdefault(sg_id, []).append(f"{lb['type']}-lb:{lb['name']}")
        except Exception as exc:
            errors.append(f"load balancer discovery failed: {exc}")

    instances: List[Dict[str, Any]] = []
    try:
        instances = discover_public_instances(ec2_client)
        for inst in instances:
            for sg_id in inst["security_groups"]:
                sg_attachments.setdefault(sg_id, []).append(f"ec2:{inst['instance_id']}")
    except Exception as exc:
        errors.append(f"EC2 instance discovery failed: {exc}")

    distributions: List[Dict[str, Any]] = []
    if cloudfront_client is not None:
        try:
            distributions = discover_cloudfront(cloudfront_client)
            for d in distributions:
                if not d["enabled"]:
                    continue
                severity = SEVERITY_MEDIUM if not d["web_acl_id"] else SEVERITY_LOW
                findings.append(_finding(
                    severity, "CLOUDFRONT_PUBLIC_ENTRY", d["id"],
                    f"CloudFront distribution {d['domain_name']} is a public entry point separate from "
                    "Cloudflare" + ("" if d["web_acl_id"] else " and has no WAF web ACL")
                    + ". It is not restricted by this tool.",
                    aliases=d["aliases"]))
        except Exception as exc:
            errors.append(f"CloudFront discovery failed: {exc}")

    for inst in instances:
        findings.append(_finding(
            SEVERITY_MEDIUM, "PUBLIC_EC2_INSTANCE", inst["instance_id"],
            f"Instance has a public address ({inst['public_ip'] or 'IPv6'}); "
            "confirm it is meant to be reachable outside Cloudflare.",
            security_groups=inst["security_groups"]))

    security_groups: List[Dict[str, Any]] = []
    raw_groups: List[Dict[str, Any]] = []
    try:
        groups = _describe_sgs(ec2_client, set(sg_attachments) | tagged)
        raw_groups = groups
        findings.extend(audit_security_group_rules(groups, managed, allow))
        for sg in groups:
            sg_id = sg["GroupId"]
            security_groups.append({
                "group_id": sg_id,
                "name": sg.get("GroupName", ""),
                "exposure": classify_security_group(sg, managed, allow),
                "opted_in": sg_id in tagged,
                "attached_to": sorted(sg_attachments.get(sg_id, [])),
            })
    except Exception as exc:
        errors.append(f"security group discovery failed: {exc}")

    exposure_counts: Dict[str, int] = {}
    for sg in security_groups:
        exposure_counts[sg["exposure"]] = exposure_counts.get(sg["exposure"], 0) + 1

    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in ("HIGH", "MEDIUM", "LOW")}
    return {
        "summary": {
            "load_balancers": len(load_balancers),
            "cloudfront_distributions": len(distributions),
            "public_ec2_instances": len(instances),
            "security_groups": len(security_groups),
            "security_group_exposure": exposure_counts,
            "findings": counts,
        },
        "load_balancers": load_balancers,
        "cloudfront_distributions": distributions,
        "public_ec2_instances": instances,
        "security_groups": security_groups,
        "findings": findings,
        "errors": errors,
        "_groups": raw_groups,  # raw describe output; callers pop it
    }
