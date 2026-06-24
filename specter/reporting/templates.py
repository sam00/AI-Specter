"""Inline Jinja2 report templates (kept in-code for zero-config packaging)."""

RISK_TEMPLATE = """# {{ eng.name }} — Risk Report

**Engagement ID:** {{ eng.id }}  •  **Profile:** {{ eng.profile }}  •  **Generated:** {{ now }}

## Executive Summary
{{ narrative }}

## Risk Posture
| Severity | Count | CVSS Band |
|---|---|---|
{% for sev, count in counts.items() -%}
| {{ sev | capitalize }} | {{ count }} | {{ bands[sev] }} |
{% endfor %}
**Overall risk rating:** {{ overall }}

## Top Business Risks
{% for f in top %}
{{ loop.index }}. **{{ f.title }}** — _{{ f.severity.value | upper }}_ (CVSS {{ f.cvss }}) on `{{ f.target }}`
{% endfor %}

## Scope
Targets tested: {{ eng.targets | join(', ') }}
"""

TECH_TEMPLATE = """# {{ eng.name }} — Technical Report

**Engagement ID:** {{ eng.id }}  •  **Generated:** {{ now }}

## Methodology & Model Routing
Specter routed each phase to a task-optimized model:
{% for task, model in eng.routing.items() %}
- **{{ task }}** → `{{ model }}`
{% endfor %}

## Findings ({{ eng.findings | length }})
{% for f in findings %}
### {{ loop.index }}. {{ f.title }}
- **Severity:** {{ f.severity.value | upper }} (CVSS {{ f.cvss }})
- **Target:** `{{ f.target }}`  •  **Phase:** {{ f.phase }}
{% if f.cve %}- **CVE:** {{ f.cve | join(', ') }}{% endif %}
{% if f.mitre_attack %}- **ATT&CK:** {{ f.mitre_attack | join(', ') }}{% endif %}

{{ f.description }}

**Evidence**
```
{{ f.evidence }}
```
{% endfor %}

## Activity Log
{% for s in eng.steps %}
- [{{ s.phase }}] {{ s.action }} {% if s.tool %}via `{{ s.tool }}`{% endif %} {% if s.target %}→ `{{ s.target }}`{% endif %} {% if s.model %}(`{{ s.model }}`){% endif %}
{% endfor %}
"""

FIX_TEMPLATE = """# {{ eng.name }} — Remediation Plan

**Engagement ID:** {{ eng.id }}  •  **Generated:** {{ now }}

## Prioritized Recommendations
{{ narrative }}

## Remediation Backlog (by severity)
{% for f in findings %}
### {{ f.severity.value | upper }} — {{ f.title }}
- **Affected:** `{{ f.target }}`
- **Fix:** {{ f.remediation or 'See technical report; apply vendor guidance.' }}
{% endfor %}
"""
