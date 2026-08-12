from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dwi.application import (
    CleanupSessionState,
    create_cleanup_session,
    create_human_confirmation,
    execute_cleanup_session,
)
from dwi.cleanup_engine import (
    create_workspace_cleanup_plan,
    workspace_engine_revalidator,
    workspace_mutation_runtime,
)
from dwi.scanner import scan_workspace


_CACHE_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"
_MARKER = "DWI-DISPOSABLE-ROOT-v0.3\n"
_PHRASE = "I reviewed this exact cleanup plan."


class RealScannerCleanupIntegrationTests(unittest.TestCase):
    def _root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / ".dwi-disposable-root").write_text(_MARKER, encoding="utf-8")
        cache = root / ".pytest_cache"
        cache.mkdir()
        (cache / "CACHEDIR.TAG").write_text(_CACHE_TAG, encoding="utf-8")
        return temporary, root, cache

    def test_normal_scanner_to_cleanup_quarantine_and_undo_uses_real_finding(self) -> None:
        temporary, root, cache = self._root()
        try:
            scan = scan_workspace(root)
            plan = create_workspace_cleanup_plan(scan)
            self.assertEqual(tuple(item.snapshot.path.casefold() for item in plan.items), (str(cache).casefold(),))
            session = create_cleanup_session(plan)
            confirmation = create_human_confirmation(
                session,
                session.review,
                confirmation_phrase=_PHRASE,
                confirmed_at="2026-01-01T00:00:00Z",
            )
            runtime = workspace_mutation_runtime()
            result = execute_cleanup_session(
                session,
                confirmation,
                engine_revalidator=workspace_engine_revalidator(),
                mutation_provider=runtime.provider,
            )
            self.assertIs(result.state, CleanupSessionState.EXECUTED)
            recovery_id = result.item_results[0].recovery_id
            self.assertIsNotNone(recovery_id)
            self.assertFalse(cache.exists())
            restored = runtime.undo(recovery_id)
            self.assertEqual(restored.state.value, "restored")
            self.assertTrue(cache.exists())
        finally:
            temporary.cleanup()

    def test_real_scanner_stale_review_is_blocked_before_mutation(self) -> None:
        temporary, root, cache = self._root()
        try:
            scan = scan_workspace(root)
            plan = create_workspace_cleanup_plan(scan)
            session = create_cleanup_session(plan)
            confirmation = create_human_confirmation(
                session,
                session.review,
                confirmation_phrase=_PHRASE,
                confirmed_at="2026-01-01T00:00:00Z",
            )
            (cache / "changed-after-review").write_text("changed\n", encoding="utf-8")
            runtime = workspace_mutation_runtime()
            result = execute_cleanup_session(
                session,
                confirmation,
                engine_revalidator=workspace_engine_revalidator(),
                mutation_provider=runtime.provider,
            )
            self.assertIs(result.state, CleanupSessionState.BLOCKED)
            self.assertTrue(cache.exists())
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
