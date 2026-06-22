from __future__ import annotations

from .ansible.provider import AnsibleProvider
from .docker_compose.provider import DockerComposeProvider
from .hybrid.provider import HybridProvider
from .ludus.provider import LudusProvider
from .terraform.provider import TerraformProvider
from .base import Provider


PROVIDERS: dict[str, type[Provider]] = {
    DockerComposeProvider.name: DockerComposeProvider,
    AnsibleProvider.name: AnsibleProvider,
    TerraformProvider.name: TerraformProvider,
    LudusProvider.name: LudusProvider,
    HybridProvider.name: HybridProvider,
}


def get_provider(name: str) -> Provider:
    try:
        provider_cls = PROVIDERS[name]
    except KeyError as exc:
        available = ", ".join(sorted(PROVIDERS))
        raise ValueError(f"Unknown provider: {name}. Available providers: {available}") from exc
    return provider_cls()


def list_providers() -> list[str]:
    return sorted(PROVIDERS)

