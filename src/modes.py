"""
Operating modes: a ladder from "look but never touch" to "fully autonomous".
============================================================================
Each mode adds capabilities to the one before it.

  discover  Read-only inventory of entry points (ALB/NLB, CloudFront, public EC2) and
            how exposed each is. Needs no prefix lists and does not contact Cloudflare.
  audit     Discover scope + compare prefix lists with Cloudflare + exposure audit.
            Reports drift and exposure. Never writes.
  sync      Audit + keep the Cloudflare prefix lists current. Writes prefix lists only.
  attach    Sync + add missing Cloudflare prefix-list ingress rules to in-scope
            security groups. Additive only; never removes a rule.
  enforce   Attach + revoke ingress rules that do not come from Cloudflare (or the
            allow-list) on in-scope security groups. Fully autonomous.

`dry_run=True` turns any mode into a preview: planned writes are reported, none are made.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

DISCOVER = "discover"
AUDIT = "audit"
SYNC = "sync"
ATTACH = "attach"
ENFORCE = "enforce"

ALL_MODES = (DISCOVER, AUDIT, SYNC, ATTACH, ENFORCE)
DEFAULT_MODE = SYNC


@dataclass(frozen=True)
class Capabilities:
    fetch_cloudflare: bool       # contacts Cloudflare and diffs the prefix lists
    discovery: bool              # builds the entry-point inventory
    audit: bool                  # runs the exposure audit
    write_prefix_lists: bool     # may modify the managed prefix lists
    attach_rules: bool           # may authorize ingress rules on in-scope security groups
    revoke_rules: bool           # may revoke ingress rules on in-scope security groups

    @property
    def writes(self) -> bool:
        return self.write_prefix_lists or self.attach_rules or self.revoke_rules


CAPABILITIES: Dict[str, Capabilities] = {
    DISCOVER: Capabilities(False, True, False, False, False, False),
    AUDIT: Capabilities(True, False, True, False, False, False),
    SYNC: Capabilities(True, False, True, True, False, False),
    ATTACH: Capabilities(True, False, True, True, True, False),
    ENFORCE: Capabilities(True, False, True, True, True, True),
}


def normalize_mode(mode: str | None) -> str:
    value = (mode or DEFAULT_MODE).strip().lower()
    if value not in CAPABILITIES:
        raise ValueError(f"Unknown mode '{mode}'. Valid modes: {', '.join(ALL_MODES)}.")
    return value


def capabilities_for(mode: str | None) -> Capabilities:
    return CAPABILITIES[normalize_mode(mode)]
