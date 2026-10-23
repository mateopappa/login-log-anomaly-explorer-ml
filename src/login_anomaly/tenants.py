"""Multi-site / multi-tenant catalog for synthetic streaming demos.

Tenants are organizational units (company sites or subsidiaries). They do not
change the AuthEvent schema: producers namespace event/account ids per tenant
and attach tenant metadata on the envelope and dataset config.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tenant:
    tenant_id: str
    display_name: str
    region: str
    kind: str  # "hq" | "site" | "subsidiary"
    topic: str
    seed_offset: int
    description: str


# Five streams: enough to tell a multi-site story without drowning the demo.
TENANTS: tuple[Tenant, ...] = (
    Tenant(
        "acme-hq",
        "Acme Corp · HQ",
        "US",
        "hq",
        "auth.events.acme-hq",
        0,
        "Headquarters identity provider; mixed campaigns and high volume.",
    ),
    Tenant(
        "acme-latam",
        "Acme Corp · LATAM",
        "AR",
        "site",
        "auth.events.acme-latam",
        17,
        "Regional site with travel-heavy workforce and shared NAT noise.",
    ),
    Tenant(
        "acme-emea",
        "Acme Corp · EMEA",
        "DE",
        "site",
        "auth.events.acme-emea",
        29,
        "EMEA site; spraying and impossible-travel pressure.",
    ),
    Tenant(
        "northwind",
        "Northwind Logistics",
        "US",
        "subsidiary",
        "auth.events.northwind",
        41,
        "Logistics subsidiary with shift workers and shared office IPs.",
    ),
    Tenant(
        "contoso-jp",
        "Contoso Japan",
        "JP",
        "subsidiary",
        "auth.events.contoso-jp",
        53,
        "APAC subsidiary; lower volume, sharper travel anomalies.",
    ),
)


def get_tenant(tenant_id: str) -> Tenant:
    for tenant in TENANTS:
        if tenant.tenant_id == tenant_id:
            return tenant
    raise KeyError(f"unknown tenant_id: {tenant_id}")


def list_tenants() -> list[dict[str, str | int]]:
    return [
        {
            "tenant_id": t.tenant_id,
            "display_name": t.display_name,
            "region": t.region,
            "kind": t.kind,
            "topic": t.topic,
            "seed_offset": t.seed_offset,
            "description": t.description,
        }
        for t in TENANTS
    ]
