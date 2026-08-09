"""Safe developer smoke path for the Desktop orchestration boundary."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..application import create_cleanup_session, create_human_confirmation, execute_cleanup_session
from ..cleanup_engine import create_workspace_cleanup_plan, workspace_engine_revalidator, workspace_mutation_runtime
from ..scanner import scan_workspace


_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"
_PHRASE = "I reviewed this exact cleanup plan."


@dataclass(frozen=True)
class DesktopSmokeResult:
    imported: bool
    scanned: bool
    review_built: bool
    cleanup_executed: bool
    undo_completed: bool
    note: str


def run_desktop_smoke() -> DesktopSmokeResult:
    """Scan and, on Windows, quarantine/Undo only a self-owned temp fixture."""

    with tempfile.TemporaryDirectory(prefix="dwi-desktop-smoke-") as temporary:
        root = Path(temporary)
        cache = root / "project" / ".pytest_cache"
        cache.mkdir(parents=True)
        (cache / "CACHEDIR.TAG").write_text(_TAG, encoding="utf-8")
        scan = scan_workspace(root)
        plan = create_workspace_cleanup_plan(scan) if os.name == "nt" else None
        if plan is None:
            return DesktopSmokeResult(True, True, False, False, False, "mutation smoke skipped outside Windows")
        if not plan.items:
            return DesktopSmokeResult(True, True, True, False, False, "engine conservatively found no executable fixture item")
        session = create_cleanup_session(plan)
        confirmation = create_human_confirmation(
            session,
            session.review,
            confirmation_phrase=_PHRASE,
            confirmed_at="2026-01-01T00:00:00+00:00",
        )
        runtime = workspace_mutation_runtime()
        result = execute_cleanup_session(
            session,
            confirmation,
            engine_revalidator=workspace_engine_revalidator(),
            mutation_provider=runtime.provider,
        )
        recovery_ids = tuple(item.recovery_id for item in result.item_results if item.recovery_id)
        restored = bool(recovery_ids) and all(runtime.undo(recovery_id).state.value == "restored" for recovery_id in recovery_ids)
        return DesktopSmokeResult(True, True, True, result.state.value == "executed", restored, "fixture was quarantined and restored")
