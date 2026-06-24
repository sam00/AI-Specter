"""Finding post-processing: dedup, correlation, and second-opinion verification."""
from __future__ import annotations

import re
from typing import Any

from specter.engine.models import Finding, Severity
from specter.engine.phases import safe_json

_WORD = re.compile(r"[a-z0-9]+")


def normalize_title(title: str) -> str:
    return " ".join(_WORD.findall((title or "").lower()))


def _key(f: Finding) -> str:
    if f.cve:
        return "cve:" + ",".join(sorted(c.upper() for c in f.cve)) + "@" + f.target
    return "t:" + normalize_title(f.title) + "@" + f.target


def dedup(findings: list[Finding]) -> list[Finding]:
    """Merge duplicate findings, keeping the most severe and richest evidence."""
    merged: dict[str, Finding] = {}
    for f in findings:
        k = _key(f)
        cur = merged.get(k)
        if not cur:
            f.confidence = max(f.confidence, 0.5)
            merged[k] = f
            continue
        # Keep the higher-severity / higher-CVSS record, merge metadata.
        keep, drop = (cur, f) if (cur.severity.rank, cur.cvss) >= (f.severity.rank, f.cvss) else (f, cur)
        keep.cve = sorted(set(keep.cve) | set(drop.cve))
        keep.mitre_attack = sorted(set(keep.mitre_attack) | set(drop.mitre_attack))
        if drop.evidence and drop.evidence not in keep.evidence:
            keep.evidence = (keep.evidence + " | " + drop.evidence).strip(" |")
        # Corroboration across tools raises confidence (use the stronger prior).
        keep.confidence = min(1.0, max(keep.confidence, drop.confidence) + 0.2)
        merged[k] = keep
    return sorted(merged.values(), key=lambda x: (x.severity.rank, x.cvss), reverse=True)


def correlate(findings: list[Finding]) -> list[dict]:
    """Group findings into systemic clusters by CVE or normalized title."""
    clusters: dict[str, dict] = {}
    for f in findings:
        tag = (f.cve[0].upper() if f.cve else normalize_title(f.title)) or "misc"
        c = clusters.setdefault(tag, {"key": tag, "title": f.title, "severity": f.severity.value,
                                      "count": 0, "targets": set(), "finding_ids": []})
        c["count"] += 1
        c["targets"].add(f.target)
        c["finding_ids"].append(f.id)
        if f.severity.rank > Severity(c["severity"]).rank:
            c["severity"] = f.severity.value
    out = []
    for c in clusters.values():
        c["targets"] = sorted(t for t in c["targets"] if t)
        out.append(c)
    return sorted(out, key=lambda c: (Severity(c["severity"]).rank, c["count"]), reverse=True)


def verify(client: Any, findings: list[Finding], limit: int = 15) -> int:
    """Second-opinion pass: ask a model to confirm/dismiss top findings.

    Updates ``verified``, ``confidence``, and ``status`` in place. Degrades to a
    no-op when the model output is unusable (e.g. offline echo stub). Returns the
    number of findings the model explicitly adjudicated.
    """
    top = sorted(findings, key=lambda f: (f.severity.rank, f.cvss), reverse=True)[:limit]
    if not top:
        return 0
    items = [{"id": f.id, "title": f.title, "severity": f.severity.value,
              "evidence": f.evidence[:300]} for f in top]
    prompt = (
        "Adjudicate each security finding as a true or false positive based on its "
        f"evidence. Findings: {items}\n\nReturn ONLY JSON: {{\"verdicts\":[{{\"id\":str,"
        "\"true_positive\":bool,\"confidence\":number,\"reason\":str}}]}}"
    )
    try:
        data = safe_json(client.complete(
            "You are a precise vulnerability triage reviewer.", prompt, max_tokens=1200).text)
    except Exception:
        return 0
    verdicts = {v.get("id"): v for v in data.get("verdicts", []) or []}
    by_id = {f.id: f for f in findings}
    adjudicated = 0
    for fid, v in verdicts.items():
        f = by_id.get(fid)
        if not f:
            continue
        adjudicated += 1
        tp = bool(v.get("true_positive", True))
        f.verified = True
        f.confidence = float(v.get("confidence", f.confidence) or f.confidence)
        f.status = "confirmed" if tp else "dismissed"
        f.confirmed = tp
        reason = v.get("reason", "")
        if reason:
            f.comments.append(f"verifier: {reason}")
    return adjudicated
