"""Simple background work primitive with explicit safe cancellation phases."""

from __future__ import annotations

from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from threading import Event, Lock
from typing import Callable, TypeVar


T = TypeVar("T")


class WorkCancelled(RuntimeError):
    """A cancellable operation stopped at a documented safe checkpoint."""


class WorkerBusyError(RuntimeError):
    """A second long-running operation was requested while one is active."""


class WorkPhase(str, Enum):
    IDLE = "idle"
    CANCELLABLE = "cancellable"
    FINALIZING = "finalizing"
    AUTHORIZED_MUTATION = "authorized_mutation"
    RECONCILING = "reconciling"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    FAILED = "failed"


class CancelResult(str, Enum):
    ACCEPTED = "accepted"
    REJECTED_NO_ACTIVE_OPERATION = "rejected_no_active_operation"
    REJECTED_NON_CANCELLABLE = "rejected_non_cancellable"
    REJECTED_ALREADY_REQUESTED = "rejected_already_requested"

    def __bool__(self) -> bool:
        return self is CancelResult.ACCEPTED


class CancellationToken:
    """Cancellation token observable only at safe operation checkpoints."""

    def __init__(self, on_phase: Callable[[WorkPhase], None] | None = None) -> None:
        self._lock = Lock()
        self._event = Event()
        self._phase = WorkPhase.CANCELLABLE
        self._on_phase = on_phase

    @property
    def phase(self) -> WorkPhase:
        with self._lock:
            return self._phase

    @property
    def cancellation_requested(self) -> bool:
        return self._event.is_set()

    def is_set(self) -> bool:
        """Compatibility-friendly read used by scan callbacks."""

        return self._event.is_set()

    def request_cancel(self) -> CancelResult:
        with self._lock:
            if self._event.is_set():
                return CancelResult.REJECTED_ALREADY_REQUESTED
            if self._phase is not WorkPhase.CANCELLABLE:
                return CancelResult.REJECTED_NON_CANCELLABLE
            self._event.set()
            return CancelResult.ACCEPTED

    def checkpoint(self) -> None:
        with self._lock:
            if self._event.is_set() and self._phase is WorkPhase.CANCELLABLE:
                raise WorkCancelled("operation cancelled at a safe checkpoint")

    def enter_phase(self, phase: WorkPhase) -> None:
        with self._lock:
            if phase is not WorkPhase.CANCELLABLE and self._event.is_set():
                raise WorkCancelled("operation cancelled before the non-cancellable boundary")
            self._phase = phase
        if self._on_phase is not None:
            self._on_phase(phase)

    def terminal(self, phase: WorkPhase) -> None:
        with self._lock:
            self._phase = phase
        if self._on_phase is not None:
            self._on_phase(phase)


@dataclass(frozen=True)
class WorkHandle:
    future: Future[object]
    cancellation: CancellationToken

    @property
    def phase(self) -> WorkPhase:
        return self.cancellation.phase

    @property
    def cancellable(self) -> bool:
        return self.phase is WorkPhase.CANCELLABLE and not self.cancellation.cancellation_requested

    def cancel(self) -> CancelResult:
        result = self.cancellation.request_cancel()
        if result is CancelResult.ACCEPTED:
            # This only prevents a queued operation from starting. A running
            # operation must observe the token at its own safe checkpoints.
            self.future.cancel()
        return result


class DesktopWorker:
    """One-worker executor with phase-aware cancellation and callback ordering."""

    def __init__(self, dispatch: Callable[[Callable[[], None]], None] | None = None) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dwi-desktop")
        self._dispatch = dispatch or (lambda callback: callback())
        self._lock = Lock()
        self._handle: WorkHandle | None = None

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._handle is not None

    @property
    def phase(self) -> WorkPhase:
        with self._lock:
            return self._handle.cancellation.phase if self._handle is not None else WorkPhase.IDLE

    @property
    def cancellable(self) -> bool:
        with self._lock:
            return self._handle is not None and self._handle.cancellable

    def submit(
        self,
        operation: Callable[[CancellationToken], T],
        *,
        on_success: Callable[[T], None],
        on_error: Callable[[Exception], None],
        on_cancel: Callable[[], None] | None = None,
        on_started: Callable[[], None] | None = None,
        on_phase: Callable[[WorkPhase], None] | None = None,
    ) -> WorkHandle:
        with self._lock:
            if self._handle is not None:
                raise WorkerBusyError("desktop operation is already running")
            token = CancellationToken(
                lambda phase: self._dispatch(lambda: on_phase(phase)) if on_phase is not None else None
            )

            def run() -> T:
                if token.cancellation_requested:
                    raise WorkCancelled("operation cancelled before start")
                if on_started is not None:
                    self._dispatch(on_started)
                return operation(token)

            future = self._executor.submit(run)
            handle = WorkHandle(future, token)
            self._handle = handle

        def finish() -> None:
            with self._lock:
                if self._handle is handle:
                    self._handle = None

        def completed(done: Future[object]) -> None:
            def deliver_cancel() -> None:
                try:
                    if on_cancel is not None:
                        on_cancel()
                finally:
                    finish()

            def deliver_error(error: Exception) -> None:
                try:
                    on_error(error)
                finally:
                    finish()

            try:
                value = done.result()
            except (WorkCancelled, CancelledError) as error:
                if token.cancellation_requested:
                    token.terminal(WorkPhase.CANCELLED)
                    self._dispatch(deliver_cancel)
                else:
                    token.terminal(WorkPhase.FAILED)
                    self._dispatch(lambda: deliver_error(error))
            except Exception as error:  # structured boundary; UI receives no traceback
                token.terminal(WorkPhase.FAILED)
                self._dispatch(lambda: deliver_error(error))
            else:
                if token.cancellation_requested:
                    token.terminal(WorkPhase.CANCELLED)
                    self._dispatch(deliver_cancel)
                    return
                token.terminal(WorkPhase.COMPLETE)

                def deliver_success() -> None:
                    try:
                        on_success(value)
                    except Exception as error:  # keep controller/view failures structured too
                        on_error(error)
                    finally:
                        finish()

                self._dispatch(deliver_success)

        future.add_done_callback(completed)
        return handle

    def cancel(self) -> CancelResult:
        with self._lock:
            handle = self._handle
        if handle is None:
            return CancelResult.REJECTED_NO_ACTIVE_OPERATION
        return handle.cancel()

    def close(self, *, wait: bool = True) -> bool:
        """Shutdown only after the active callback/operation has terminated."""

        if self.busy:
            return False
        self._executor.shutdown(wait=wait, cancel_futures=True)
        return True
