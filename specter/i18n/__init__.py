"""Lightweight localization for user-facing CLI strings.

Specter keeps a small message catalog keyed by short IDs. The active locale is
chosen from ``SPECTER_LANG`` (or the OS ``LANG``), falling back to English. This
is intentionally dependency-free — no gettext/.po toolchain required — so
translations are easy to contribute as plain Python dicts.
"""
from __future__ import annotations

import os

# Message catalogs. Keys are stable IDs; English is the source of truth and the
# fallback for any missing translation.
CATALOGS: dict[str, dict[str, str]] = {
    "en": {
        "tagline": "AI-driven automated pentesting from your terminal.",
        "get_started": "Get started in seconds",
        "ready": "Ready.",
        "authorized_only": "Authorized use only. Specter enforces a scope allowlist.",
        "no_targets": "No authorized targets.",
    },
    "es": {
        "tagline": "Pentesting automatizado con IA desde tu terminal.",
        "get_started": "Empieza en segundos",
        "ready": "Listo.",
        "authorized_only": "Solo uso autorizado. Specter aplica una lista de alcance permitida.",
        "no_targets": "No hay objetivos autorizados.",
    },
    "pt": {
        "tagline": "Pentest automatizado com IA a partir do seu terminal.",
        "get_started": "Comece em segundos",
        "ready": "Pronto.",
        "authorized_only": "Uso autorizado apenas. O Specter aplica uma allowlist de escopo.",
        "no_targets": "Nenhum alvo autorizado.",
    },
    "fr": {
        "tagline": "Tests d'intrusion automatisés par IA depuis votre terminal.",
        "get_started": "Commencez en quelques secondes",
        "ready": "Prêt.",
        "authorized_only": "Usage autorisé uniquement. Specter applique une liste de portée.",
        "no_targets": "Aucune cible autorisée.",
    },
    "de": {
        "tagline": "KI-gestützte automatisierte Pentests aus deinem Terminal.",
        "get_started": "In Sekunden loslegen",
        "ready": "Bereit.",
        "authorized_only": "Nur autorisierte Nutzung. Specter erzwingt eine Scope-Allowlist.",
        "no_targets": "Keine autorisierten Ziele.",
    },
    "ja": {
        "tagline": "ターミナルから実行するAI駆動の自動ペネトレーションテスト。",
        "get_started": "数秒で開始",
        "ready": "準備完了。",
        "authorized_only": "許可された利用のみ。Specterはスコープの許可リストを強制します。",
        "no_targets": "許可された対象がありません。",
    },
}

DEFAULT_LANG = "en"


def available_locales() -> list[str]:
    return sorted(CATALOGS)


def current_lang() -> str:
    raw = (os.environ.get("SPECTER_LANG") or os.environ.get("LANG") or DEFAULT_LANG)
    code = raw.split(".")[0].split("_")[0].lower()
    return code if code in CATALOGS else DEFAULT_LANG


def t(key: str, lang: str | None = None) -> str:
    """Translate a message id; falls back to English, then to the id itself."""
    lang = (lang or current_lang())
    cat = CATALOGS.get(lang, {})
    if key in cat:
        return cat[key]
    return CATALOGS[DEFAULT_LANG].get(key, key)
