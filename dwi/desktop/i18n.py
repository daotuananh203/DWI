"""Small resource-backed English/Vietnamese localization foundation."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from importlib import resources
from typing import Mapping


SUPPORTED_LOCALES = ("en", "vi")
DESKTOP_VERSION = "0.4.0-internal"


class LocaleCatalog:
    """Load stable human-facing strings from package resources."""

    def __init__(self) -> None:
        self._cache: dict[str, Mapping[str, str]] = {}

    def load(self, locale: str) -> Mapping[str, str]:
        normalized = locale if locale in SUPPORTED_LOCALES else "en"
        if normalized not in self._cache:
            resource = resources.files("dwi.desktop.resources").joinpath(f"{normalized}.json")
            self._cache[normalized] = json.loads(resource.read_text(encoding="utf-8"))
        return self._cache[normalized]

    def locales(self) -> tuple[str, ...]:
        return SUPPORTED_LOCALES


class Translator:
    def __init__(self, locale: str = "en", catalog: LocaleCatalog | None = None) -> None:
        self.catalog = catalog or LocaleCatalog()
        self.locale = locale if locale in SUPPORTED_LOCALES else "en"

    def set_locale(self, locale: str) -> None:
        self.locale = locale if locale in SUPPORTED_LOCALES else "en"

    def __call__(self, key: str, **values: object) -> str:
        english = self.catalog.load("en")
        value = self.catalog.load(self.locale).get(key, english.get(key, key))
        return value.format(**values) if values else value


@dataclass(frozen=True)
class DesktopSettings:
    """Runtime settings with no accounts, persistence, telemetry, or network."""

    locale: str = "en"
    max_seconds: float | None = 300.0
    max_nodes: int | None = 100_000
    max_files: int | None = 100_000
    allow_network: bool = False

    def with_locale(self, locale: str) -> "DesktopSettings":
        return replace(self, locale=locale if locale in SUPPORTED_LOCALES else "en")
