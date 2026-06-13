"""acme_utils v1.0.0 — utilidades de formato benignas (baseline legítimo)."""


def version_banner() -> str:
    return "1.0.0 ok"


def money(cents: int) -> str:
    return f"S/ {cents / 100:.2f}"
