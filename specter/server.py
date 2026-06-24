"""Optional FastAPI server for team collaboration.

Install with ``pip install 'ai-specter[server]'``. Exposes engagements and the
finding workflow over HTTP with API-key auth and simple RBAC
(viewer < operator < lead). FastAPI/uvicorn are imported lazily so the core
package stays dependency-light.
"""
from __future__ import annotations

from specter import __version__
from specter.config import Config
from specter.store import Store

ROLES = {"viewer": 0, "operator": 1, "lead": 2}


def create_app(config: Config | None = None):
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install 'ai-specter[server]' to use serve mode") from e

    config = config or Config.load()
    store = Store()
    keys = dict(config.api_keys)  # api_key -> role

    app = FastAPI(title="Specter", version=__version__)

    def require(min_role: str):
        def dep(x_api_key: str = Header(default="")) -> str:
            if not keys:
                return "lead"  # open mode when no keys configured (dev only)
            role = keys.get(x_api_key)
            if not role:
                raise HTTPException(status_code=401, detail="invalid or missing API key")
            if ROLES.get(role, 0) < ROLES[min_role]:
                raise HTTPException(status_code=403, detail=f"requires {min_role} role")
            return role
        return dep

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "auth": bool(keys)}

    @app.get("/engagements")
    def engagements(_: str = Depends(require("viewer"))) -> list:
        return store.list_engagements()

    @app.get("/engagements/{engagement_id}")
    def engagement(engagement_id: str, _: str = Depends(require("viewer"))):
        eng = store.get_engagement(engagement_id)
        if not eng:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="engagement not found")
        return eng

    @app.get("/findings")
    def findings(engagement_id: str = "", status: str = "",
                 _: str = Depends(require("viewer"))) -> list:
        return store.list_findings(engagement_id or None, status or None)

    @app.patch("/findings/{finding_id}")
    def update_finding(finding_id: str, status: str = "", assignee: str = "",
                       comment: str = "", role: str = Depends(require("operator"))) -> dict:
        ok = store.update_finding(finding_id, status or None,
                                  assignee or None, comment or None)
        if not ok:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="finding not found")
        return {"updated": finding_id}

    return app


def serve(host: str = "127.0.0.1", port: int = 8787, config: Config | None = None) -> None:
    try:
        import uvicorn
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install 'ai-specter[server]' to use serve mode") from e
    uvicorn.run(create_app(config), host=host, port=port)
