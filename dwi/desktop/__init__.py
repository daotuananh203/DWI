"""Windows Desktop presentation/orchestration for the DWI core.

The package is intentionally importable without a GUI display. Tkinter is
loaded only when :func:`run_desktop` is called, which keeps controller tests
and CLI use headless and preserves the existing engine boundary.
"""

from .controller import (
    DesktopController,
    DesktopState,
    DesktopStateModel,
    FindingRow,
    RecoveryRow,
    ReviewModel,
)
from .i18n import DESKTOP_VERSION, DesktopSettings, LocaleCatalog, Translator
from .worker import DesktopWorker, WorkCancelled, WorkerBusyError
from .smoke import DesktopSmokeResult, run_desktop_smoke

__all__ = [
    "DesktopController",
    "DesktopSettings",
    "DESKTOP_VERSION",
    "DesktopState",
    "DesktopStateModel",
    "DesktopSmokeResult",
    "DesktopWorker",
    "FindingRow",
    "LocaleCatalog",
    "RecoveryRow",
    "ReviewModel",
    "Translator",
    "WorkCancelled",
    "WorkerBusyError",
    "run_desktop_smoke",
]


def run_desktop() -> int:
    """Launch the deterministic Tk desktop entry point."""

    from .app import DesktopApp

    return DesktopApp().run()
