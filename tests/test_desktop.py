from __future__ import annotations

import time
import unittest
from enum import Enum
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dwi.application import CleanupMutationProvider, CleanupSessionState
from dwi.desktop import DesktopController, DesktopState, DesktopWorker, Translator, WorkerBusyError
from dwi.desktop.controller import RecoveryRow
from dwi.desktop.worker import CancelResult, WorkPhase
from dwi.domain import ActionEligibility, ActivityState, ProtectionClass, ReachabilityState, RegenerabilityState, RegenerationCost, RiskLabel
from dwi.scan_control import ScanTermination
from dwi.system_scan import RootStatus


class _Value(Enum):
    value = "value"


def _finding(path: str, *, eligible: bool, size: int = 10, risk: RiskLabel = RiskLabel.SAFE):
    return SimpleNamespace(
        artifact=SimpleNamespace(value="pytest_cache"),
        path=path,
        size=SimpleNamespace(known_bytes=size, complete=True, observation_failures=()),
        risk_label=risk,
        action_eligibility=ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION if eligible else ActionEligibility.REQUIRES_REVIEW,
        interpretation=SimpleNamespace(
            provenance=SimpleNamespace(ecosystem="python", generator="pytest", confidence="high"),
            regenerability=RegenerabilityState.REPRODUCIBLE,
            regeneration_cost=RegenerationCost.LOW,
            reachability=ReachabilityState.CONFIRMED_UNREFERENCED,
            activity=ActivityState.INACTIVE,
            protection=ProtectionClass.ORDINARY,
            reclaim_priority=SimpleNamespace(value="high"),
        ),
    )


def _scan(findings, termination=ScanTermination.COMPLETED, status=RootStatus.COMPLETE):
    return SimpleNamespace(
        findings=tuple(findings),
        termination=termination,
        observation_failures=(),
        ambiguous_boundaries=(),
        root_observations=(SimpleNamespace(status=status),),
    )


class DesktopTests(unittest.TestCase):
    def _wait(self, controller: DesktopController) -> None:
        deadline = time.time() + 3
        while controller.busy and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(controller.busy)

    def test_import_and_startup_state(self):
        controller = DesktopController()
        try:
            self.assertEqual(controller.state.state, DesktopState.IDLE)
            self.assertFalse(controller.busy)
            self.assertEqual(controller.translator("app.title"), "DWI Desktop")
        finally:
            controller.close()

    def test_worker_success_failure_and_duplicate_guard(self):
        worker = DesktopWorker()
        try:
            values = []
            gate = Event()
            handle = worker.submit(lambda _cancel: (gate.wait(2), "ok")[1], on_success=values.append, on_error=self.fail)
            with self.assertRaises(WorkerBusyError):
                worker.submit(lambda _cancel: "second", on_success=values.append, on_error=self.fail)
            gate.set()
            handle.future.result(timeout=2)
            self.assertEqual(values, ["ok"])
            errors = []
            failed = worker.submit(lambda _cancel: (_ for _ in ()).throw(RuntimeError("boom")), on_success=self.fail, on_error=errors.append)
            with self.assertRaises(RuntimeError):
                failed.future.result(timeout=2)
            self.assertEqual(str(errors[0]), "boom")
        finally:
            worker.close()

    def test_scan_complete_partial_and_cancelled_are_distinct(self):
        complete = _scan((_finding("C:\\work\\.pytest_cache", eligible=True),))
        controller = DesktopController(scan_fn=lambda _options: complete)
        try:
            self.assertTrue(controller.start_system_scan(root="C:\\work"))
            self._wait(controller)
            self.assertEqual(controller.state.state, DesktopState.SCAN_COMPLETE)
            partial = _scan((), status=RootStatus.PARTIAL)
            controller._scan_succeeded(partial)
            self.assertEqual(controller.state.state, DesktopState.SCAN_PARTIAL)
            cancelled = _scan((), termination=ScanTermination.CANCELLED)
            controller._scan_succeeded(cancelled)
            self.assertEqual(controller.state.state, DesktopState.CANCELLED)
        finally:
            controller.close()

    def test_filters_sort_and_risk_eligibility_are_separate(self):
        eligible = _finding("C:\\a\\.pytest_cache", eligible=True, size=20)
        review = _finding("C:\\b\\.pytest_cache", eligible=False, size=200, risk=RiskLabel.REVIEW_REQUIRED)
        controller = DesktopController()
        try:
            controller._scan_succeeded(_scan((eligible, review)))
            self.assertEqual(len(controller.finding_rows()), 2)
            controller.set_filter("eligibility", "eligible_for_explicit_action")
            self.assertEqual(len(controller.finding_rows()), 1)
            self.assertTrue(controller.toggle_selection(controller.finding_rows()[0].key))
            self.assertFalse(controller.toggle_selection("pytest_cache::missing"))
            controller.set_filter("eligibility", "all")
            controller.set_sort("size")
            self.assertEqual(controller.finding_rows()[0].known_bytes, 200)
            review_row = controller.finding_rows()[0]
            self.assertEqual(review_row.risk_label, RiskLabel.REVIEW_REQUIRED.value)
            self.assertFalse(review_row.executable)
        finally:
            controller.close()

    def test_exact_confirmation_phrase_is_required_before_worker(self):
        controller = DesktopController()
        try:
            controller.state.session = SimpleNamespace(review=SimpleNamespace())
            controller.state.review = SimpleNamespace()
            self.assertFalse(controller.confirm_cleanup("yes"))
            self.assertEqual(controller.state.state, DesktopState.CONFIRMING)
            self.assertIn("I reviewed this exact cleanup plan.", controller.state.error_message)
        finally:
            controller.close()

    def test_locales_keep_machine_values_unchanged(self):
        english = Translator("en")
        vietnamese = Translator("vi")
        self.assertEqual(english("nav.findings"), "Findings")
        self.assertEqual(vietnamese("nav.findings"), "Phát hiện")
        self.assertEqual(RiskLabel.SAFE.value, "safe")
        self.assertEqual(ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION.value, "eligible_for_explicit_action")

    def test_worker_accepted_cancel_never_calls_success(self):
        worker = DesktopWorker()
        started = Event()
        release = Event()
        cancelled = []
        succeeded = []

        def operation(token):
            started.set()
            while not release.wait(0.01):
                token.checkpoint()
            token.checkpoint()
            return "unexpected"

        try:
            worker.submit(operation, on_success=succeeded.append, on_error=self.fail, on_cancel=lambda: cancelled.append(True))
            self.assertTrue(started.wait(2))
            self.assertEqual(worker.cancel(), CancelResult.ACCEPTED)
            release.set()
            deadline = time.time() + 2
            while worker.busy and time.time() < deadline:
                time.sleep(0.01)
            self.assertFalse(succeeded)
            self.assertEqual(cancelled, [True])
            self.assertEqual(worker.phase, WorkPhase.IDLE)
        finally:
            worker.close()

    def test_worker_rejects_cancel_after_non_cancellable_boundary(self):
        worker = DesktopWorker()
        phase_reached = Event()
        release = Event()
        phases = []
        cancelled = []
        succeeded = []

        def operation(token):
            token.enter_phase(WorkPhase.AUTHORIZED_MUTATION)
            phase_reached.set()
            release.wait(2)
            return "completed"

        try:
            worker.submit(operation, on_success=succeeded.append, on_error=self.fail, on_cancel=lambda: cancelled.append(True), on_phase=phases.append)
            self.assertTrue(phase_reached.wait(2))
            self.assertEqual(worker.cancel(), CancelResult.REJECTED_NON_CANCELLABLE)
            release.set()
            deadline = time.time() + 2
            while worker.busy and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(succeeded, ["completed"])
            self.assertFalse(cancelled)
            self.assertIn(WorkPhase.AUTHORIZED_MUTATION, phases)
        finally:
            worker.close()

    def _fake_session_controller(self, *, runtime_factory=None):
        controller = DesktopController(runtime_factory=runtime_factory or (lambda: SimpleNamespace()))
        controller.state.session = SimpleNamespace(review=SimpleNamespace(), plan=SimpleNamespace())
        controller.state.review = SimpleNamespace()
        return controller

    def test_cleanup_cancel_before_finalizing_boundary_is_cancelled(self):
        controller = self._fake_session_controller()
        confirmation_started = Event()
        release = Event()
        execute = Mock(side_effect=AssertionError("cleanup must not execute after accepted cancellation"))
        try:
            with patch("dwi.desktop.controller.create_human_confirmation", side_effect=lambda *args, **kwargs: (confirmation_started.set(), release.wait(2), object())[2]), patch("dwi.desktop.controller.execute_cleanup_session", execute):
                self.assertTrue(controller.confirm_cleanup("I reviewed this exact cleanup plan."))
                self.assertTrue(confirmation_started.wait(2))
                self.assertEqual(controller.cancel(), CancelResult.ACCEPTED)
                release.set()
                self._wait(controller)
            self.assertEqual(controller.state.state, DesktopState.CANCELLED)
            execute.assert_not_called()
        finally:
            controller.close()

    def test_cleanup_cancel_after_authorized_boundary_is_rejected(self):
        authorized = Event()
        release = Event()
        runtime = SimpleNamespace(
            provider=CleanupMutationProvider(lambda _plan: SimpleNamespace(), lambda *_args: SimpleNamespace()),
            recovery_entries=lambda: SimpleNamespace(entries=(), failures=()),
        )
        controller = self._fake_session_controller(runtime_factory=lambda: runtime)

        def fake_execute(_session, _confirmation, *, mutation_provider, **_kwargs):
            mutation_provider.authorized_context(None, None, None)
            authorized.set()
            release.wait(2)
            return SimpleNamespace(state=CleanupSessionState.EXECUTED, reason=None, item_results=())

        try:
            with patch("dwi.desktop.controller.create_human_confirmation", return_value=object()), patch("dwi.desktop.controller.execute_cleanup_session", side_effect=fake_execute):
                self.assertTrue(controller.confirm_cleanup("I reviewed this exact cleanup plan."))
                self.assertTrue(authorized.wait(2))
                self.assertEqual(controller.operation_phase, WorkPhase.AUTHORIZED_MUTATION)
                self.assertEqual(controller.cancel(), CancelResult.REJECTED_NON_CANCELLABLE)
                release.set()
                self._wait(controller)
            self.assertEqual(controller.state.state, DesktopState.CLEANUP_COMPLETE)
        finally:
            controller.close()

    def test_undo_cancel_before_restore_checkpoint_prevents_restore(self):
        entered = Event()
        release = Event()
        restored = []

        def undo(_recovery_id, *, phase_callback, cancellation_checkpoint):
            entered.set()
            release.wait(2)
            cancellation_checkpoint()
            restored.append(True)
            phase_callback("authorized_mutation")
            return SimpleNamespace(state=SimpleNamespace(value="restored"), failure_reason=None)

        runtime = SimpleNamespace(undo=undo)
        controller = DesktopController(runtime_factory=lambda: runtime)
        controller._runtime = runtime
        controller.state.recovery_rows = (RecoveryRow("recovery-1", "C:\\original", "C:\\quarantine", "quarantined", True),)
        controller.refresh_recovery = lambda: True
        try:
            self.assertTrue(controller.undo("recovery-1"))
            self.assertTrue(entered.wait(2))
            self.assertEqual(controller.cancel(), CancelResult.ACCEPTED)
            release.set()
            self._wait(controller)
            self.assertFalse(restored)
            self.assertEqual(controller.state.state, DesktopState.CANCELLED)
        finally:
            controller.close()

    def test_undo_cancel_after_restore_boundary_is_rejected(self):
        authorized = Event()
        release = Event()

        def undo(_recovery_id, *, phase_callback, cancellation_checkpoint):
            cancellation_checkpoint()
            phase_callback("reconciling")
            phase_callback("authorized_mutation")
            authorized.set()
            release.wait(2)
            return SimpleNamespace(state=SimpleNamespace(value="restored"), failure_reason=None)

        runtime = SimpleNamespace(undo=undo)
        controller = DesktopController(runtime_factory=lambda: runtime)
        controller._runtime = runtime
        controller.state.recovery_rows = (RecoveryRow("recovery-2", "C:\\original", "C:\\quarantine", "quarantined", True),)
        controller.refresh_recovery = lambda: True
        try:
            self.assertTrue(controller.undo("recovery-2"))
            self.assertTrue(authorized.wait(2))
            self.assertEqual(controller.cancel(), CancelResult.REJECTED_NON_CANCELLABLE)
            release.set()
            self._wait(controller)
            self.assertEqual(controller.state.state, DesktopState.RECOVERY)
        finally:
            controller.close()


class _FakeRoot:
    def __init__(self):
        self.destroyed = False
        self.callbacks = []

    def after(self, _delay, callback):
        self.callbacks.append(callback)
        return "poll"

    def destroy(self):
        self.destroyed = True


class _FakeCloseController:
    def __init__(self, cancel_result):
        self.busy = True
        self.can_cancel = cancel_result is CancelResult.ACCEPTED
        self.cancel_result = cancel_result
        self.translator = Translator("en")
        self.status = ""

    def cancel(self):
        return self.cancel_result

    def request_close(self):
        return self.cancel()

    def close(self):
        return not self.busy

    def _update(self, **changes):
        self.status = changes.get("status_message", self.status)


class DesktopCloseTests(unittest.TestCase):
    def _app(self, controller):
        from dwi.desktop.app import DesktopApp

        app = object.__new__(DesktopApp)
        app.root = _FakeRoot()
        app.controller = controller
        app._closing = False
        app._close_poll_id = None
        app.render = lambda: None
        app.t = lambda key, **_values: controller.translator(key)
        return app

    def test_close_during_cancellable_operation_waits_for_termination(self):
        controller = _FakeCloseController(CancelResult.ACCEPTED)
        app = self._app(controller)
        app.close()
        self.assertFalse(app.root.destroyed)
        controller.busy = False
        app.root.callbacks.pop(0)()
        self.assertTrue(app.root.destroyed)

    def test_close_during_authorized_cleanup_waits_for_terminal_state(self):
        controller = _FakeCloseController(CancelResult.REJECTED_NON_CANCELLABLE)
        app = self._app(controller)
        app.close()
        self.assertFalse(app.root.destroyed)
        controller.busy = False
        app.root.callbacks.pop(0)()
        self.assertTrue(app.root.destroyed)

    def test_close_during_restore_uses_same_safe_wait(self):
        controller = _FakeCloseController(CancelResult.REJECTED_NON_CANCELLABLE)
        app = self._app(controller)
        app.close()
        self.assertFalse(app.root.destroyed)
        controller.busy = False
        app.root.callbacks.pop(0)()
        self.assertTrue(app.root.destroyed)


if __name__ == "__main__":
    unittest.main()
