# Changelog

## 1.0.0rc1 — Release candidate

This release candidate prepares the deterministic DWI engine and its human and
agent interfaces for an independent public-release audit.

- Added bounded MCP collections, messages, responses and read-only pagination.
- Added server-owned opaque MCP handles with TTL, replay protection and
  restart invalidation.
- Preserved trusted human confirmation outside the MCP agent channel.
- Added Desktop cancellation phases and safe close-window behavior.
- Added finite scan resource limits and conservative evaluation/benchmark
  tooling.
- Added wheel/sdist packaging metadata, Windows Desktop bundling foundation,
  portable artifact support and installer configuration.
- Added MIT licensing, EN/VI public README files, CLI/Desktop/MCP usage docs,
  security guidance, contributing guidance and dependency/license audit.

Important limitations: permanent deletion does not exist; cleanup is
Quarantine + Journal + Undo. The EXE and installer are intentionally unsigned
under the accepted release policy; Windows SmartScreen may warn. SHA-256 values
and the disposable installer validation record are documented. Trusted code
signing and independent final release authorization remain future gates.

## v0.5 — MCP / Agent Integration

- Local stdio MCP adapter for untrusted AI-agent callers.
- Read-only findings and deterministic explanations.
- Engine-bound cleanup review, trusted human confirmation outside MCP, fresh
  revalidation, one-shot execution and recovery-handle Undo.

## v0.4 — Desktop

- Bilingual Tkinter Desktop over the shared engine.
- Cleanup cancellation phases, reconciliation-safe close behavior and Recovery/
  Undo presentation.

## v0.3 — Safe Cleanup

- Engine-generated plans, validation, authorization, Quarantine, Journal and
  Undo/recovery primitives.

## v0.2 — System Intelligence

- Bounded machine-wide developer-storage discovery with network default deny.

## v0.1 — Workspace Intelligence

- Deterministic workspace scanning, evidence contracts and safety reporting.
