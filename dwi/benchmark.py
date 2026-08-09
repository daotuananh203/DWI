"""Reproducible synthetic scan and MCP pagination benchmarks."""

from __future__ import annotations

import gc
import tempfile
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path

from .mcp.pagination import page_items
from .scan_control import MAX_SCAN_FILES, MAX_SCAN_NODES, MAX_SCAN_SECONDS, ScanLimits
from .scanner import scan_workspace
from .version import __version__


DEFAULT_SCALES = (10, 100, 500)
MAX_BENCHMARK_SCALE = 2_000


@dataclass(frozen=True)
class BenchmarkRow:
    scale: int
    duration_ms: float
    peak_memory_bytes: int
    nodes_observed: int
    files_observed: int
    findings_count: int
    known_bytes: int
    termination: str
    mcp_pagination_duration_ms: float


def _fixture(root: Path, scale: int) -> None:
    for index in range(scale):
        cache = root / f"workspace-{index:05d}" / ".pytest_cache"
        cache.mkdir(parents=True)
        (cache / "CACHEDIR.TAG").write_text(
            "Signature: 8a477f597d28d172789f06886806bc55\n",
            encoding="utf-8",
        )


def run_benchmarks(scales: tuple[int, ...] = DEFAULT_SCALES) -> dict[str, object]:
    if not scales or any(isinstance(scale, bool) or not isinstance(scale, int) or not 1 <= scale <= MAX_BENCHMARK_SCALE for scale in scales):
        raise ValueError(f"benchmark scales must be between 1 and {MAX_BENCHMARK_SCALE}")
    rows: list[BenchmarkRow] = []
    with tempfile.TemporaryDirectory(prefix="dwi-benchmark-") as temporary:
        base = Path(temporary)
        for scale in scales:
            root = base / f"scale-{scale}"
            root.mkdir()
            _fixture(root, scale)
            gc.collect()
            tracemalloc.start()
            started = time.perf_counter()
            scan = scan_workspace(
                root,
                limits=ScanLimits(
                    max_seconds=MAX_SCAN_SECONDS,
                    max_nodes=MAX_SCAN_NODES,
                    max_files=MAX_SCAN_FILES,
                ),
            )
            duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            values = tuple(range(scale * 2))
            page_started = time.perf_counter()
            cursor: str | None = None
            while True:
                page = page_items(values, key=f"benchmark-{scale}", limit=50, cursor=cursor, maximum=100)
                cursor = page.next_cursor
                if cursor is None:
                    break
            pagination_duration_ms = round((time.perf_counter() - page_started) * 1000.0, 3)
            rows.append(BenchmarkRow(
                scale=scale,
                duration_ms=duration_ms,
                peak_memory_bytes=peak,
                nodes_observed=scan.nodes_observed,
                files_observed=scan.files_observed,
                findings_count=len(scan.findings),
                known_bytes=scan.summary.known_analyzed_bytes,
                termination=scan.termination.value,
                mcp_pagination_duration_ms=pagination_duration_ms,
            ))
    return {
        "version": __version__,
        "scales": [asdict(row) for row in rows],
        "pagination_pages": {str(row.scale): (row.scale * 2 + 49) // 50 for row in rows},
        "synthetic_only": True,
    }
