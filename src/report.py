#!/usr/bin/env python3
"""
Gap report: what you have vs what needs to change, and who gets told.
=====================================================================
`build_gap_report` turns a run summary into a structured comparison:

  prefix_lists     for each managed or reference (compare-only) prefix list:
                   entries it has, entries Cloudflare publishes, what to add, what to remove
  security_groups  for each audited security group:
                   the sources that can reach it today, and the actions that would make
                   Cloudflare the only way in (authorize / revoke)
  findings         exposure findings grouped by severity

`render_text` formats it for email (SNS). `should_notify` applies the notification policy:

  never    send nothing
  alerts   send when changes were applied, when something needs action, or on error  (default)
  drift    send whenever any gap exists, including low-severity items
  always   send after every run, even when everything is compliant
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Iterable, List, Optional

try:
    from src.audit import AllowList, classify_ingress_sources, classify_security_group
except ImportError:  # Lambda flat layout
    from audit import AllowList, classify_ingress_sources, classify_security_group  # type: ignore

logger = logging.getLogger("cloudflare_prefix_sync.report")

NOTIFY_NEVER = "never"
NOTIFY_ALERTS = "alerts"
NOTIFY_DRIFT = "drift"
NOTIFY_ALWAYS = "always"
NOTIFY_POLICIES = (NOTIFY_NEVER, NOTIFY_ALERTS, NOTIFY_DRIFT, NOTIFY_ALWAYS)

FORMAT_TEXT = "text"
FORMAT_JSON = "json"

MAX_LIST_LINES = 25
MAX_MESSAGE_BYTES = 200_000  # SNS limit is 256 KB


def normalize_notify_policy(value: Optional[str]) -> str:
    policy = (value or NOTIFY_ALERTS).strip().lower()
    if policy not in NOTIFY_POLICIES:
        raise ValueError(f"Unknown notify_on '{value}'. Valid: {', '.join(NOTIFY_POLICIES)}.")
    return policy


def normalize_notify_format(value: Optional[str]) -> str:
    fmt = (value or FORMAT_TEXT).strip().lower()
    if fmt not in (FORMAT_TEXT, FORMAT_JSON):
        raise ValueError(f"Unknown notify_format '{value}'. Valid: text, json.")
    return fmt


# --------------------------------------------------------------------------- building
def summarize_security_group(
    sg: Dict[str, Any],
    cloudflare_prefix_list_ids: Iterable[str],
    allow: Optional[AllowList] = None,
) -> Dict[str, Any]:
    """The 'have' side for one security group."""
    cf = [p for p in cloudflare_prefix_list_ids if p]
    have: List[str] = []
    for src in classify_ingress_sources(sg, cf, allow):
        have.append(f"{src['port']} from {src['source']} [{src['category']}]")
    return {
        "group_id": sg["GroupId"],
        "name": sg.get("GroupName", ""),
        "exposure": classify_security_group(sg, cf, allow),
        "have": have,
    }


def build_gap_report(
    summary: Dict[str, Any],
    security_groups_state: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Builds the have-vs-needs report from a run summary (see sync_engine.run_sync)."""
    applied = summary.get("status") == "UPDATED"
    prefix_lists: List[Dict[str, Any]] = []

    for diff in (summary.get("diffs") or {}).values():
        prefix_lists.append({
            "prefix_list_id": diff["prefix_list_id"], "role": "managed",
            "address_family": diff["address_family"],
            "have": diff.get("have_count", len(diff.get("current_cidrs", []))),
            "cloudflare": diff.get("want_count", 0),
            "to_add": diff["to_add"], "to_remove": diff["to_remove"],
            "in_sync": not diff["has_changes"],
            "applied": bool(applied and diff["has_changes"]),
        })
    for cmp_ in summary.get("comparisons") or []:
        prefix_lists.append({
            "prefix_list_id": cmp_["prefix_list_id"], "role": "reference",
            "address_family": cmp_["address_family"], "have": cmp_["have_count"],
            "cloudflare": cmp_["want_count"], "to_add": cmp_["to_add"],
            "to_remove": cmp_["to_remove"], "in_sync": cmp_["in_sync"], "applied": False,
        })

    remediation = summary.get("remediation") or {}
    applied_keys = {
        (a["group_id"], a["detail"])
        for key in ("authorized", "revoked") for a in remediation.get(key, []) if a.get("applied")
    }
    plan = summary.get("security_group_plan") or {}
    sgs: List[Dict[str, Any]] = []
    for sg in security_groups_state or []:
        actions = plan.get(sg["group_id"], [])
        needs = [{"action": a["action"], "detail": a["detail"],
                  "applied": (a["group_id"], a["detail"]) in applied_keys} for a in actions]
        sgs.append({**sg, "needs": needs,
                    "status": "compliant" if not needs else (
                        "remediated" if all(n["applied"] for n in needs) else "needs_change")})

    findings = (summary.get("audit") or {}).get("findings", []) + \
        (summary.get("discovery") or {}).get("findings", [])
    by_sev: Dict[str, List[Dict[str, Any]]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)

    errors = list((summary.get("audit") or {}).get("errors", [])) + \
        list((summary.get("discovery") or {}).get("errors", [])) + \
        [e["error"] if isinstance(e, dict) else str(e) for e in remediation.get("errors", [])]

    pending_pl = [p for p in prefix_lists if not p["in_sync"] and not p["applied"]]
    pending_sg = [s for s in sgs if s["status"] == "needs_change"]
    actionable = bool(pending_pl or pending_sg or by_sev["HIGH"] or by_sev["MEDIUM"] or errors)
    has_gaps = bool(actionable or by_sev["LOW"] or any(not p["in_sync"] for p in prefix_lists))
    changes_applied = bool(
        any(p["applied"] for p in prefix_lists) or applied_keys)

    if actionable:
        headline = (f"ACTION NEEDED: {len(pending_pl)} prefix list(s) out of date, "
                    f"{len(pending_sg)} security group(s) to change, "
                    f"{len(by_sev['HIGH'])} high / {len(by_sev['MEDIUM'])} medium finding(s)")
    elif changes_applied:
        headline = "UPDATED: changes were applied and nothing else is pending"
    elif has_gaps:
        headline = "REVIEW: only low-severity items remain"
    else:
        headline = "COMPLIANT: Cloudflare is the only path in for everything checked"

    return {
        "headline": headline, "actionable": actionable, "has_gaps": has_gaps,
        "changes_applied": changes_applied, "prefix_lists": prefix_lists,
        "security_groups": sgs, "findings": by_sev, "errors": errors,
    }


# --------------------------------------------------------------------------- notify policy
def should_notify(policy: str, report: Dict[str, Any]) -> bool:
    policy = normalize_notify_policy(policy)
    if policy == NOTIFY_NEVER:
        return False
    if policy == NOTIFY_ALWAYS:
        return True
    if policy == NOTIFY_DRIFT:
        return bool(report["has_gaps"] or report["changes_applied"] or report["errors"])
    return bool(report["actionable"] or report["changes_applied"] or report["errors"])


# --------------------------------------------------------------------------- rendering
def _cap(lines: List[str], limit: int = MAX_LIST_LINES, indent: str = "      ") -> List[str]:
    if len(lines) <= limit:
        return lines
    return lines[:limit] + [f"{indent}... and {len(lines) - limit} more"]


def render_text(report: Dict[str, Any], summary: Dict[str, Any]) -> str:
    out: List[str] = []
    out.append("Cloudflare Prefix Sync report")
    out.append(f"  mode={summary.get('mode', '?')}  dry_run={summary.get('dry_run')}  "
               f"account={summary.get('account_id', '?')}  region={summary.get('region', '?')}  "
               f"time={summary.get('timestamp_utc', '?')}")
    out.append("")
    out.append(report["headline"])

    if report["prefix_lists"]:
        out += ["", "PREFIX LISTS  (have vs what Cloudflare publishes)"]
        for p in report["prefix_lists"]:
            state = "in sync" if p["in_sync"] else (
                "UPDATED" if p["applied"] else f"ADD {len(p['to_add'])}, REMOVE {len(p['to_remove'])}")
            out.append(f"  {p['prefix_list_id']} [{p['role']}, {p['address_family']}]  "
                       f"have {p['have']}, Cloudflare {p['cloudflare']}  ->  {state}")
            out += _cap([f"      + {c}" for c in p["to_add"]])
            out += _cap([f"      - {c}" for c in p["to_remove"]])

    if report["security_groups"]:
        out += ["", "SECURITY GROUPS  (what can reach them vs what must change)"]
        for s in report["security_groups"]:
            label = f" {s['name']}" if s.get("name") else ""
            out.append(f"  {s['group_id']}{label}  [{s['exposure']}]  status: {s['status']}")
            out.append("    have:")
            out += _cap([f"      {h}" for h in s["have"]] or ["      (no inbound rules)"])
            if s["needs"]:
                out.append("    needs:")
                out += _cap([f"      {'DONE ' if n['applied'] else ''}{n['detail']}" for n in s["needs"]])

    for sev in ("HIGH", "MEDIUM", "LOW"):
        items = report["findings"].get(sev, [])
        if items:
            out += ["", f"{sev} FINDINGS ({len(items)})"]
            out += _cap([f"  {f['code']}  {f['resource']}: {f['detail']}" for f in items], indent="  ")

    disc = summary.get("discovery")
    if disc:
        s = disc["summary"]
        out += ["", "ENTRY POINTS DISCOVERED",
                f"  load balancers: {s['load_balancers']}, CloudFront distributions: "
                f"{s['cloudfront_distributions']}, public EC2 instances: {s['public_ec2_instances']}, "
                f"security groups: {s['security_groups']}"]

    if report["errors"]:
        out += ["", "ERRORS"] + _cap([f"  {e}" for e in report["errors"]], indent="  ")

    rem = summary.get("remediation")
    if rem and (rem.get("skipped")):
        out += ["", "NOT APPLIED"] + _cap(
            [f"  {a['detail']} ({a['reason']})" for a in rem["skipped"]], indent="  ")
    backup = summary.get("backup")
    if backup:
        out += ["", f"Backup: {', '.join(backup.get('locations', []))}"]
    return "\n".join(out)


def build_subject(report: Dict[str, Any], region: str) -> str:
    tag = "ACTION NEEDED" if report["actionable"] else (
        "UPDATED" if report["changes_applied"] else ("REVIEW" if report["has_gaps"] else "OK"))
    return f"[CF-Prefix-Sync] {tag} ({region})"[:100]


def send_report(
    sns_client: Optional[Any],
    topic_arn: Optional[str],
    report: Dict[str, Any],
    summary: Dict[str, Any],
    fmt: str = FORMAT_TEXT,
) -> bool:
    """Publishes the report to SNS. Returns True if it was sent."""
    if not topic_arn or sns_client is None:
        return False
    fmt = normalize_notify_format(fmt)
    body = render_text(report, summary) if fmt == FORMAT_TEXT else json.dumps(
        {"report": report, "summary": summary}, indent=2, default=str)
    raw = body.encode("utf-8")
    if len(raw) > MAX_MESSAGE_BYTES:
        body = raw[:MAX_MESSAGE_BYTES].decode("utf-8", errors="ignore") + "\n... truncated"
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=build_subject(report, str(summary.get("region", "?"))),
            Message=body,
        )
        return True
    except Exception as exc:
        logger.warning("Failed to publish report to %s: %s", topic_arn, exc)
        return False
