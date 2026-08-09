"""Tkinter Desktop shell over :mod:`dwi.desktop.controller`."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Any

from ..domain import RiskLabel
from .controller import DesktopController, DesktopState
from .i18n import SUPPORTED_LOCALES


def _bytes(value: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


class DesktopApp:
    """Small native shell; all engine work stays in the controller worker."""

    def __init__(self, controller: DesktopController | None = None) -> None:
        self.root = tk.Tk()
        self.controller = controller or DesktopController(dispatch=lambda callback: self.root.after(0, callback))
        self.controller.subscribe(lambda _state: self.root.after(0, self.render))
        self._closing = False
        self._close_poll_id: str | None = None
        self._localized: list[tuple[tk.Misc, str]] = []
        self._build()
        self.render()

    def t(self, key: str, **values: object) -> str:
        return self.controller.translator(key, **values)

    def _label(self, parent: tk.Misc, key: str, **kwargs: Any) -> ttk.Label:
        widget = ttk.Label(parent, text=self.t(key, **kwargs))
        self._localized.append((widget, key))
        return widget

    def _button(self, parent: tk.Misc, key: str, command: Any, **kwargs: Any) -> ttk.Button:
        widget = ttk.Button(parent, text=self.t(key, **kwargs), command=command)
        self._localized.append((widget, key))
        return widget

    def _build(self) -> None:
        self.root.title(self.t("app.title"))
        self.root.minsize(1000, 650)
        self.root.geometry("1240x780")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=(16, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        self.title_label = self._label(header, "app.title")
        self.title_label.configure(font=("Segoe UI", 18, "bold"))
        self.title_label.grid(row=0, column=0, sticky="w")
        self.subtitle_label = self._label(header, "app.subtitle")
        self.subtitle_label.grid(row=1, column=0, sticky="w")
        self.version_label = self._label(header, "app.version")
        self.version_label.grid(row=2, column=0, sticky="w")
        self.status_var = tk.StringVar()
        ttk.Label(header, textvariable=self.status_var, anchor="e").grid(row=0, column=1, rowspan=2, sticky="e")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.overview = ttk.Frame(self.notebook, padding=14)
        self.findings = ttk.Frame(self.notebook, padding=14)
        self.review = ttk.Frame(self.notebook, padding=14)
        self.recovery = ttk.Frame(self.notebook, padding=14)
        self.settings = ttk.Frame(self.notebook, padding=14)
        self.tabs = [self.overview, self.findings, self.review, self.recovery, self.settings]
        self.tab_keys = ("nav.overview", "nav.findings", "nav.review", "nav.recovery", "nav.settings")
        for frame, key in zip(self.tabs, self.tab_keys):
            self.notebook.add(frame, text=self.t(key))
        self._build_overview()
        self._build_findings()
        self._build_review()
        self._build_recovery()
        self._build_settings()

    def _build_overview(self) -> None:
        self.overview.columnconfigure(0, weight=1)
        self.overview.rowconfigure(4, weight=1)
        toolbar = ttk.Frame(self.overview)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.scan_button = self._button(toolbar, "action.scan", self._scan)
        self.scan_button.pack(side="left")
        self.cancel_button = self._button(toolbar, "action.cancel", self.controller.cancel)
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.root_var = tk.StringVar()
        self._label(toolbar, "overview.explicit_root").pack(side="left", padx=(18, 6))
        ttk.Entry(toolbar, textvariable=self.root_var, width=46).pack(side="left")
        self.scan_root_button = self._button(toolbar, "action.scan_root", self._scan_root)
        self.scan_root_button.pack(side="left", padx=(6, 0))
        self.progress = ttk.Progressbar(self.overview, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        self._label(self.overview, "overview.summary").grid(row=2, column=0, sticky="w")
        cards = ttk.Frame(self.overview)
        cards.grid(row=3, column=0, sticky="ew", pady=(6, 14))
        for index in range(6):
            cards.columnconfigure(index, weight=1)
        self.summary_vars: dict[str, tk.StringVar] = {}
        for index, key in enumerate(("roots", "findings", "known_bytes", "partial_bytes", "reclaimable", "git")):
            frame = ttk.LabelFrame(cards, text=self.t(f"overview.{key}"), padding=8)
            frame.grid(row=0, column=index, sticky="nsew", padx=3)
            var = tk.StringVar(value="—")
            self.summary_vars[key] = var
            ttk.Label(frame, textvariable=var).pack(anchor="w")
        self._label(self.overview, "overview.warnings").grid(row=4, column=0, sticky="nw")
        self.overview_text = tk.Text(self.overview, height=14, wrap="word", state="disabled")
        self.overview_text.grid(row=5, column=0, sticky="nsew", pady=(5, 0))

    def _build_findings(self) -> None:
        self.findings.columnconfigure(0, weight=1)
        self.findings.rowconfigure(2, weight=1)
        controls = ttk.Frame(self.findings)
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.search_var = tk.StringVar()
        self._label(controls, "findings.search").pack(side="left")
        search = ttk.Entry(controls, textvariable=self.search_var, width=30)
        search.pack(side="left", padx=(6, 12))
        search.bind("<KeyRelease>", lambda _event: self._filter("search", self.search_var.get()))
        self.risk_var = tk.StringVar(value="all")
        self._label(controls, "findings.risk").pack(side="left")
        self.risk_combo = ttk.Combobox(controls, textvariable=self.risk_var, state="readonly", width=18, values=("all", *(item.value for item in RiskLabel)))
        self.risk_combo.pack(side="left", padx=(6, 12))
        self.risk_combo.bind("<<ComboboxSelected>>", lambda _event: self._filter("risk", self.risk_var.get()))
        self.eligibility_var = tk.StringVar(value="all")
        self._label(controls, "findings.action_filter").pack(side="left")
        self.eligibility_combo = ttk.Combobox(controls, textvariable=self.eligibility_var, state="readonly", width=28, values=("all", "executable", "review_only"))
        self.eligibility_combo.pack(side="left", padx=(6, 12))
        self.eligibility_combo.bind("<<ComboboxSelected>>", lambda _event: self._filter("eligibility", self.eligibility_var.get()))
        self.artifact_var = tk.StringVar(value="all")
        self._label(controls, "findings.artifact").pack(side="left")
        self.artifact_combo = ttk.Combobox(controls, textvariable=self.artifact_var, state="readonly", width=18, values=("all",))
        self.artifact_combo.pack(side="left", padx=(6, 12))
        self.artifact_combo.bind("<<ComboboxSelected>>", lambda _event: self._filter("artifact", self.artifact_var.get()))
        self.provenance_var = tk.StringVar(value="all")
        self._label(controls, "findings.tool").pack(side="left")
        self.provenance_combo = ttk.Combobox(controls, textvariable=self.provenance_var, state="readonly", width=18, values=("all",))
        self.provenance_combo.pack(side="left", padx=(6, 12))
        self.provenance_combo.bind("<<ComboboxSelected>>", lambda _event: self._filter("provenance", self.provenance_var.get()))
        self.sort_var = tk.StringVar(value="path")
        self._label(controls, "findings.sort").pack(side="left")
        sort = ttk.Combobox(controls, textvariable=self.sort_var, state="readonly", width=14, values=("path", "size", "priority"))
        sort.pack(side="left", padx=(6, 0))
        sort.bind("<<ComboboxSelected>>", lambda _event: self.controller.set_sort(self.sort_var.get()))

        actions = ttk.Frame(self.findings)
        actions.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.select_button = self._button(actions, "action.select", self._toggle_selected)
        self.select_button.pack(side="left")
        self.review_button = self._button(actions, "action.review", self.controller.build_cleanup_review)
        self.review_button.pack(side="left", padx=(8, 0))
        self.clear_button = self._button(actions, "action.clear", self.controller.clear_selection)
        self.clear_button.pack(side="left", padx=(8, 0))
        self.selected_var = tk.StringVar()
        ttk.Label(actions, textvariable=self.selected_var).pack(side="right")

        body = ttk.Panedwindow(self.findings, orient="vertical")
        body.grid(row=2, column=0, sticky="nsew")
        table_frame = ttk.Frame(body)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        columns = ("path", "artifact", "provenance", "size", "complete", "risk", "eligibility", "regen", "protection")
        self.finding_heading_keys = ("path", "kind", "tool", "size", "completeness", "risk_column", "eligibility_column", "regenerability", "protection")
        self.findings_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        for column, key, width in zip(columns, self.finding_heading_keys, (330, 120, 150, 100, 90, 120, 190, 150, 150)):
            self.findings_tree.heading(column, text=self.t(f"findings.{key}"))
            self.findings_tree.column(column, width=width, anchor="w")
        self.findings_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.findings_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.findings_tree.configure(yscrollcommand=scrollbar.set)
        self.findings_tree.bind("<<TreeviewSelect>>", lambda _event: self._show_detail())
        body.add(table_frame, weight=3)
        detail_frame = ttk.Frame(body)
        detail_frame.rowconfigure(1, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        self._label(detail_frame, "detail.title").grid(row=0, column=0, sticky="w")
        self.finding_detail = tk.Text(detail_frame, height=10, wrap="word", state="disabled")
        self.finding_detail.grid(row=1, column=0, sticky="nsew", pady=(5, 0))
        body.add(detail_frame, weight=2)

    def _build_review(self) -> None:
        self.review.columnconfigure(0, weight=1)
        self.review.rowconfigure(1, weight=1)
        self._label(self.review, "review.title").grid(row=0, column=0, sticky="w")
        self.review_text = tk.Text(self.review, wrap="word", state="disabled")
        self.review_text.grid(row=1, column=0, sticky="nsew", pady=(8, 8))
        footer = ttk.Frame(self.review)
        footer.grid(row=2, column=0, sticky="ew")
        self._label(footer, "review.phrase_label").pack(side="left")
        self.phrase_var = tk.StringVar()
        ttk.Entry(footer, textvariable=self.phrase_var, width=52).pack(side="left", padx=(8, 8))
        self.confirm_button = self._button(footer, "action.confirm", self._confirm)
        self.confirm_button.pack(side="left")

    def _build_recovery(self) -> None:
        self.recovery.columnconfigure(0, weight=1)
        self.recovery.rowconfigure(1, weight=1)
        self._label(self.recovery, "recovery.title").grid(row=0, column=0, sticky="w")
        columns = ("id", "original", "quarantine", "state", "eligible")
        self.recovery_heading_keys = ("id", "original", "quarantine", "state", "eligible")
        self.recovery_tree = ttk.Treeview(self.recovery, columns=columns, show="headings", selectmode="browse")
        for column, key, width in zip(columns, self.recovery_heading_keys, (260, 340, 340, 220, 120)):
            self.recovery_tree.heading(column, text=self.t(f"recovery.{key}"))
            self.recovery_tree.column(column, width=width, anchor="w")
        self.recovery_tree.grid(row=1, column=0, sticky="nsew", pady=(8, 8))
        actions = ttk.Frame(self.recovery)
        actions.grid(row=2, column=0, sticky="ew")
        self.undo_button = self._button(actions, "action.undo", self._undo)
        self.undo_button.pack(side="left")
        self.refresh_button = self._button(actions, "action.refresh", self.controller.refresh_recovery)
        self.refresh_button.pack(side="left", padx=(8, 0))
        self.recovery_note = self._label(self.recovery, "recovery.warning")
        self.recovery_note.grid(row=3, column=0, sticky="w", pady=(8, 0))

    def _build_settings(self) -> None:
        self.settings.columnconfigure(1, weight=1)
        self._label(self.settings, "settings.language").grid(row=0, column=0, sticky="w", pady=5)
        self.language_var = tk.StringVar(value="en")
        language = ttk.Combobox(self.settings, textvariable=self.language_var, state="readonly", values=SUPPORTED_LOCALES, width=12)
        language.grid(row=0, column=1, sticky="w", padx=10, pady=5)
        language.bind("<<ComboboxSelected>>", lambda _event: self._language_changed())
        self._label(self.settings, "settings.limits").grid(row=1, column=0, sticky="nw", pady=(18, 5))
        limits = ttk.Frame(self.settings)
        limits.grid(row=1, column=1, sticky="w", padx=10, pady=(18, 5))
        self.limit_vars = {}
        for row, key, value in ((0, "seconds", "300"), (1, "nodes", "100000"), (2, "files", "100000")):
            self._label(limits, f"settings.{key}").grid(row=row, column=0, sticky="w", pady=3)
            var = tk.StringVar(value=value)
            self.limit_vars[key] = var
            ttk.Entry(limits, textvariable=var, width=16).grid(row=row, column=1, padx=8, pady=3)
        self.network_var = tk.BooleanVar(value=False)
        self.network_check = ttk.Checkbutton(self.settings, text=self.t("settings.network"), variable=self.network_var, command=self._network_changed)
        self.network_check.grid(row=4, column=1, sticky="w", padx=10, pady=(16, 4))
        self._localized.append((self.network_check, "settings.network"))
        self._label(self.settings, "settings.network_warning").grid(row=5, column=1, sticky="w", padx=10)
        self._label(self.settings, "settings.trust").grid(row=6, column=1, sticky="w", padx=10, pady=(18, 0))

    def _scan(self) -> None:
        if not self._apply_limits():
            return
        self.controller.start_system_scan()

    def _scan_root(self) -> None:
        root = self.root_var.get().strip()
        if root:
            if not self._apply_limits():
                return
            self.controller.start_system_scan(root)

    def _apply_limits(self) -> bool:
        try:
            seconds = float(self.limit_vars["seconds"].get())
            nodes = int(self.limit_vars["nodes"].get())
            files = int(self.limit_vars["files"].get())
            self.controller.set_scan_limits(max_seconds=seconds, max_nodes=nodes, max_files=files)
        except (KeyError, TypeError, ValueError) as error:
            self.controller.state.error_message = str(error)
            self.render()
            return False
        return True

    def _filter(self, name: str, value: str) -> None:
        self.controller.set_filter(name, value)

    def _toggle_selected(self) -> None:
        selection = self.findings_tree.selection()
        if selection:
            self.controller.toggle_selection(selection[0])

    def _show_detail(self) -> None:
        selection = self.findings_tree.selection()
        if not selection:
            return
        finding = self.controller.finding_details(selection[0])
        if finding is None:
            return
        interpretation = finding.interpretation
        decision = finding.safety_decision
        payload = {
            self.t("detail.evidence"): [item.__dict__ for item in finding.evidence.observations],
            self.t("detail.provenance"): interpretation.provenance.__dict__,
            self.t("detail.interpretation"): {
                "regenerability": interpretation.regenerability.value,
                "regeneration_cost": interpretation.regeneration_cost.value,
            },
            self.t("detail.reachability"): interpretation.reachability.value,
            self.t("detail.activity"): interpretation.activity.value,
            self.t("detail.protection"): interpretation.protection.value,
            self.t("detail.safety"): decision.__dict__ if decision is not None else self.t("detail.unknown"),
            self.t("detail.trace"): decision.rule_trace.__dict__ if decision is not None else self.t("detail.unknown"),
            self.t("detail.warnings"): list(finding.size.observation_failures),
        }
        self._set_text(self.finding_detail, json.dumps(payload, indent=2, ensure_ascii=False, default=str))

    def _confirm(self) -> None:
        self.controller.confirm_cleanup(self.phrase_var.get())

    def _undo(self) -> None:
        selection = self.recovery_tree.selection()
        if selection:
            self.controller.undo(selection[0])

    def _language_changed(self) -> None:
        self.controller.set_locale(self.language_var.get())
        self._relocalize()

    def _network_changed(self) -> None:
        self.controller.set_allow_network(self.network_var.get())

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _relocalize(self) -> None:
        self.root.title(self.t("app.title"))
        for widget, key in self._localized:
            try:
                widget.configure(text=self.t(key))
            except tk.TclError:
                continue
        for index, key in enumerate(self.tab_keys):
            self.notebook.tab(index, text=self.t(key))
        for column, key in zip(self.findings_tree["columns"], self.finding_heading_keys):
            self.findings_tree.heading(column, text=self.t(f"findings.{key}"))
        for column, key in zip(self.recovery_tree["columns"], self.recovery_heading_keys):
            self.recovery_tree.heading(column, text=self.t(f"recovery.{key}"))
        self.render()

    def render(self) -> None:
        state = self.controller.state
        self.status_var.set(f"{self.t('state.' + state.state.value)}{(' — ' + state.status_message) if state.status_message else ''}")
        if state.progress_indeterminate:
            self.progress.start(12)
        else:
            self.progress.stop()
        self.cancel_button.configure(state="normal" if self.controller.can_cancel and not self._closing else "disabled")
        scan = state.scan
        if scan is None:
            for variable in self.summary_vars.values():
                variable.set("—")
            self._set_text(self.overview_text, self.t("overview.no_scan"))
        else:
            summary = scan.summary
            self.summary_vars["roots"].set(str(len(scan.root_observations)))
            self.summary_vars["findings"].set(str(len(scan.findings)))
            self.summary_vars["known_bytes"].set(_bytes(summary.known_analyzed_bytes))
            self.summary_vars["partial_bytes"].set(_bytes(summary.partial_known_bytes))
            self.summary_vars["reclaimable"].set(_bytes(summary.potentially_reclaimable_bytes))
            self.summary_vars["git"].set(str(len(scan.git_observations)))
            statuses = [item.status for item in scan.root_observations]
            lines = [
                f"{self.t('overview.roots')}: {len(statuses)} | {self.t('overview.scanned')}: {sum(item.value == 'complete' for item in statuses)} | {self.t('overview.denied')}: {sum(item.value == 'denied' for item in statuses)} | {self.t('overview.skipped')}: {sum(item.value == 'skipped' for item in statuses)} | {self.t('overview.partial_failed')}: {sum(item.value in {'partial', 'failed'} for item in statuses)}",
                *[f"{item.path}: {item.status.value} — {item.reason}" for item in scan.root_observations],
            ]
            lines += scan.observation_failures
            lines += scan.ambiguous_boundaries
            self._set_text(self.overview_text, "\n".join(lines) or self.t("overview.ready"))
        self._render_findings()
        self._render_review()
        self._render_recovery()

    def _render_findings(self) -> None:
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        for row in self.controller.finding_rows():
            self.findings_tree.insert("", "end", iid=row.key, values=(row.path, row.artifact, row.provenance, _bytes(row.known_bytes), "complete" if row.size_complete else "partial", row.risk_label, row.action_eligibility, row.regenerability, row.protection))
        self.selected_var.set(self.t("findings.selected", count=len(self.controller.state.selected_finding_keys)))
        provenance_values = ("all", *sorted({row.provenance for row in self.controller.finding_rows()}))
        self.provenance_combo.configure(values=provenance_values)
        artifact_values = ("all", *sorted({row.artifact for row in self.controller.finding_rows()}))
        self.artifact_combo.configure(values=artifact_values)
        self._show_detail()

    def _render_review(self) -> None:
        review = self.controller.state.review
        if review is None:
            self._set_text(self.review_text, self.t("review.empty"))
            return
        lines = [
            self.t("review.binding", session=review.session_id, plan=review.plan_id),
            f"Engine: {review.engine_version}",
            self.t("review.total", bytes=review.known_total_bytes),
            self.t("review.partial_warning") if review.partial_size_count else "",
            self.t("review.behavior"),
            self.t("review.phrase"),
            "",
        ]
        lines.extend(f"{row.artifact} | {row.path} | {row.known_bytes} bytes | {row.risk_label} | {row.action_eligibility}" for row in review.items)
        lines.extend(review.exclusions)
        if self.controller.state.result is not None:
            lines += ["", self.t("result.outcomes")]
            lines.extend(f"{item.plan_item_id.value}: {item.outcome.value} ({item.recovery_id or '—'})" for item in self.controller.state.result.item_results)
            lines.append(self.t("result.non_transactional"))
        self._set_text(self.review_text, "\n".join(line for line in lines if line))

    def _render_recovery(self) -> None:
        for item in self.recovery_tree.get_children():
            self.recovery_tree.delete(item)
        for row in self.controller.state.recovery_rows:
            self.recovery_tree.insert("", "end", iid=row.recovery_id, values=(row.recovery_id, row.original_path, row.quarantine_path or "—", row.state, "yes" if row.restore_eligible else "no"))
        self.undo_button.configure(state="normal" if any(row.restore_eligible for row in self.controller.state.recovery_rows) and not self.controller.busy else "disabled")

    def run(self) -> int:
        self.root.mainloop()
        return 0

    def close(self) -> None:
        if self._closing:
            return
        if self.controller.busy:
            self._closing = True
            self.controller.request_close()
            self.render()
            self._close_poll_id = self.root.after(50, self._poll_close)
            return
        if self.controller.close():
            self.root.destroy()

    def _poll_close(self) -> None:
        self._close_poll_id = None
        if self.controller.busy:
            self._close_poll_id = self.root.after(50, self._poll_close)
            return
        if self.controller.close():
            self.root.destroy()
        else:
            self._close_poll_id = self.root.after(50, self._poll_close)
