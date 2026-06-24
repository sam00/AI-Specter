"""Deterministic parsers for common tool output.

Parsing structured output natively (instead of asking an LLM to read raw text)
makes findings reproducible and stops the model from inventing results. The LLM
then *enriches* these deterministic findings rather than producing them.

Each parser returns ``{"findings": [..], "hosts": [..]}`` where a finding is a
normalized dict and a host is ``{"address", "hostname", "services":[...]}``.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

SEV_BY_PORT = {23: "medium", 21: "medium", 3389: "medium", 445: "medium"}


def _finding(title, severity="info", cvss=0.0, host="", **extra) -> dict:
    return {"title": title, "severity": severity, "cvss": cvss, "host": host,
            "source": "parser", **extra}


def parse_nmap_xml(output: str) -> dict:
    findings, hosts = [], []
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return {"findings": [], "hosts": []}
    for host in root.iter("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""
        services = []
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pid = int(port.get("portid", 0))
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            services.append({"port": pid, "name": name, "product": product, "version": version})
            sev = SEV_BY_PORT.get(pid, "info")
            findings.append(_finding(
                f"Open port {pid}/{name or 'tcp'}" + (f" ({product} {version})".rstrip() if product else ""),
                severity=sev, host=addr,
                evidence=f"{addr}:{pid} {name} {product} {version}".strip(),
                description=f"Service {name or pid} reachable on {addr}.",
            ))
        hosts.append({"address": addr, "hostname": hostname, "services": services})
    return {"findings": findings, "hosts": hosts}


def parse_nuclei_jsonl(output: str) -> dict:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {})
        sev = str(info.get("severity", "info")).lower()
        if sev not in {"info", "low", "medium", "high", "critical"}:
            sev = "info"
        cves = [c.upper() for c in (info.get("classification", {}) or {}).get("cve-id", []) or []]
        findings.append(_finding(
            info.get("name", row.get("template-id", "nuclei finding")),
            severity=sev,
            cvss=float((info.get("classification", {}) or {}).get("cvss-score", 0) or 0),
            host=row.get("host", ""),
            cve=cves,
            evidence=row.get("matched-at", row.get("matcher-name", "")),
            description=info.get("description", ""),
        ))
    return {"findings": findings, "hosts": []}


def parse_httpx_json(output: str) -> dict:
    findings, hosts = [], []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = row.get("host") or row.get("input", "")
        hosts.append({"address": host, "hostname": "",
                      "services": [{"port": row.get("port", 0), "name": "http"}]})
        techs = row.get("tech", []) or row.get("technologies", []) or []
        if techs:
            findings.append(_finding(
                f"Web technologies: {', '.join(techs)}",
                severity="info", host=host,
                evidence=f"{row.get('url', host)} [{row.get('status_code', '')}] {row.get('title', '')}",
                description="Detected web stack; review for known-vulnerable versions.",
            ))
    return {"findings": findings, "hosts": hosts}


PARSERS = {
    "nmap": parse_nmap_xml,
    "nmap-full": parse_nmap_xml,
    "nuclei": parse_nuclei_jsonl,
    "httpx": parse_httpx_json,
}


def parse_tool(tool: str, output: str) -> dict:
    fn = PARSERS.get(tool)
    if not fn or not output:
        return {"findings": [], "hosts": []}
    return fn(output)


# Canned outputs used by `specter quickstart` / --demo so the full pipeline
# (parse -> enrich -> dedup -> verify -> report) lights up with zero network.
DEMO_OUTPUTS = {
    "nmap": (
        '<?xml version="1.0"?><nmaprun><host>'
        '<address addr="scanme.nmap.org"/>'
        '<hostnames><hostname name="scanme.nmap.org"/></hostnames>'
        '<ports>'
        '<port portid="22"><state state="open"/>'
        '<service name="ssh" product="OpenSSH" version="6.6.1"/></port>'
        '<port portid="80"><state state="open"/>'
        '<service name="http" product="Apache httpd" version="2.4.7"/></port>'
        '<port portid="23"><state state="open"/><service name="telnet"/></port>'
        '</ports></host></nmaprun>'
    ),
    "httpx": json.dumps({
        "host": "scanme.nmap.org", "url": "http://scanme.nmap.org", "port": 80,
        "status_code": 200, "title": "Go ahead and ScanMe!",
        "tech": ["Apache HTTPd:2.4.7", "Ubuntu"],
    }),
    "nuclei": "\n".join([
        json.dumps({"template-id": "apache-version", "host": "scanme.nmap.org",
                    "matched-at": "http://scanme.nmap.org",
                    "info": {"name": "Apache 2.4.7 outdated", "severity": "high",
                             "description": "Outdated Apache with known CVEs.",
                             "classification": {"cve-id": ["CVE-2017-15715"], "cvss-score": 8.1}}}),
        json.dumps({"template-id": "telnet-detect", "host": "scanme.nmap.org",
                    "matched-at": "scanme.nmap.org:23",
                    "info": {"name": "Telnet cleartext service", "severity": "medium",
                             "description": "Telnet transmits credentials in cleartext."}}),
    ]),
}
