"""GUI/CLI-shared config: every domain's effective value (its override,
if `lh config set` or this router's PUT has ever been used. Otherwise
its file/env default), plus endpoints to change or reset it. Every
read/write here calls the exact same `ledgerhound.config_store`
functions `lh config` does, so the CLI and the dashboard's Settings page
can never disagree."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ledgerhound import config_store
from ledgerhound.api.deps import get_session
from ledgerhound.api.schemas.config import ConfigDomainOut, ConfigListOut
from ledgerhound.config_store import Domain

router = APIRouter(prefix="/api/config", tags=["config"])


def _domain_out(session: Session, domain: Domain) -> ConfigDomainOut:
    value = config_store.get_config(session, domain)
    return ConfigDomainOut(
        domain=domain,
        overridden=config_store.is_overridden(session, domain),
        value=value.model_dump(mode="json"),
    )


@router.get("", response_model=ConfigListOut)
def list_all_config(session: Session = Depends(get_session)) -> ConfigListOut:
    return ConfigListOut(domains=[_domain_out(session, d) for d in config_store.DOMAINS])


@router.get("/{domain}", response_model=ConfigDomainOut)
def get_config_domain(domain: Domain, session: Session = Depends(get_session)) -> ConfigDomainOut:
    return _domain_out(session, domain)


@router.put("/{domain}", response_model=ConfigDomainOut)
def set_config_domain(
    domain: Domain, body: dict[str, Any], session: Session = Depends(get_session)
) -> ConfigDomainOut:
    try:
        config_store.set_config(session, domain, body, updated_by="dashboard")
    except config_store.ConfigValidationError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
    return _domain_out(session, domain)


@router.post("/{domain}/reset", response_model=ConfigDomainOut)
def reset_config_domain(
    domain: Domain, session: Session = Depends(get_session)
) -> ConfigDomainOut:
    config_store.reset_config(session, domain)
    return _domain_out(session, domain)

