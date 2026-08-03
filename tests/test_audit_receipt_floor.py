"""
FLOOR INVARIANTS - audit receipt outcomes and diagnostic redaction.

Stdlib-only: this runs in the dependency-light floor tier and reasons over
source, not imports. Every scan names a non-empty population so a moved function
or renamed file fails as not-observed instead of passing over nothing.
"""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

OUTCOME_CLASSES = {
    "proxy/audit/writer.py": "AuditWriteOutcome",
    "proxy/detection_adapter.py": "PushOutcome",
}

RECEIPT_EMITTERS = {
    "proxy/middleware/interception.py": "_emit",
    "proxy/audit/decision_journal.py": "emit",
    "registry_server/receipts.py": "emit",
}


def _parse(rel: str) -> ast.Module:
    path = ROOT / rel
    assert path.exists(), f"floor target missing: {rel}"
    return ast.parse(path.read_text(encoding="utf-8"))


def _function(tree: ast.Module, name: str) -> ast.AsyncFunctionDef | ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name:
            return node
    return None


def _class_fields(tree: ast.Module, name: str) -> set[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            fields = set()
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    fields.add(stmt.target.id)
            return fields
    return set()


def _source_segment(rel: str, node: ast.AST) -> str:
    src = (ROOT / rel).read_text(encoding="utf-8")
    return ast.get_source_segment(src, node) or ""


def _queue_full_handlers(fn: ast.AST) -> list[ast.ExceptHandler]:
    handlers = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.ExceptHandler):
            continue
        typ = node.type
        name = ""
        if isinstance(typ, ast.Attribute):
            name = typ.attr
        elif isinstance(typ, ast.Name):
            name = typ.id
        if name == "QueueFull":
            handlers.append(node)
    return handlers


def _mentions_receipt_outcome(fn: ast.AST, rel: str) -> bool:
    segment = _source_segment(rel, fn)
    return (
        ".receipt" in segment
        or 'getattr(write_outcome, "receipt"' in segment
        or 'getattr(outcome, "receipt"' in segment
        or "AuditWriteOutcome" in segment
    )


def test_floor_population_is_non_empty_and_named():
    hard = sorted(OUTCOME_CLASSES)
    emitters = sorted(f"{rel}::{fn}" for rel, fn in RECEIPT_EMITTERS.items())

    assert hard == [
        "proxy/audit/writer.py",
        "proxy/detection_adapter.py",
    ], f"outcome class population drifted: {hard}"
    assert len(emitters) == 3, f"receipt emitter population drifted: {emitters}"
    for rel, fn_name in RECEIPT_EMITTERS.items():
        assert _function(_parse(rel), fn_name) is not None, (
            f"receipt emitter not observed: {rel}::{fn_name}"
        )


def test_outcome_classes_expose_a_receipt_field():
    observed = {}
    for rel, cls in OUTCOME_CLASSES.items():
        fields = _class_fields(_parse(rel), cls)
        observed[f"{rel}::{cls}"] = sorted(fields)
        assert fields, f"{rel}::{cls} has no annotated fields; class not observed"
        assert "receipt" in fields, (
            f"{rel}::{cls} lacks a receipt field; callers cannot report the "
            f"specific evidence outcome. Observed fields: {sorted(fields)}"
        )
    assert len(observed) == 2, f"unexpected outcome class population: {observed}"


def test_queue_full_branch_returns_failed_outcome_and_redacts_before_logging():
    rel = "proxy/audit/writer.py"
    fn = _function(_parse(rel), "write")
    assert fn is not None, "AuditWriter.write not observed"
    handlers = _queue_full_handlers(fn)
    assert len(handlers) == 1, (
        f"expected one explicit QueueFull handler in AuditWriter.write, got {len(handlers)}"
    )
    segment = _source_segment(rel, handlers[0])
    required = {
        "AuditWriteOutcome.failed",
        "AUDIT_WRITE_QUEUE_FULL",
        "_safe_log_detection_id",
    }
    missing = sorted(token for token in required if token not in segment)
    assert not missing, (
        "QueueFull handling must return a failed receipt and log only a redacted "
        f"summary. Missing: {missing}\n{segment}"
    )


def test_receipt_emitters_consume_writer_outcomes():
    missing = []
    observed = []
    for rel, fn_name in RECEIPT_EMITTERS.items():
        fn = _function(_parse(rel), fn_name)
        assert fn is not None, f"receipt emitter not observed: {rel}::{fn_name}"
        observed.append(f"{rel}::{fn_name}")
        if not _mentions_receipt_outcome(fn, rel):
            missing.append(f"{rel}::{fn_name}")
    assert len(observed) == 3, f"emitter population drifted: {observed}"
    assert not missing, (
        "receipt emitters must inspect/return the writer outcome rather than "
        f"assuming enqueue success: {missing}"
    )


def test_negative_self_test_detects_outcome_without_receipt_field():
    tree = ast.parse(
        "class PushOutcome:\n"
        "    status: str\n"
        "    accepted: bool\n"
    )
    assert "receipt" not in _class_fields(tree, "PushOutcome")


def test_negative_self_test_detects_raw_queuefull_logging():
    tree = ast.parse(
        "async def write(record):\n"
        "    try:\n"
        "        queue.put_nowait(record)\n"
        "    except asyncio.QueueFull:\n"
        "        logger.warning('drop %s', record)\n"
        "        return None\n"
    )
    fn = _function(tree, "write")
    assert fn is not None
    segment = ast.get_source_segment(
        "async def write(record):\n"
        "    try:\n"
        "        queue.put_nowait(record)\n"
        "    except asyncio.QueueFull:\n"
        "        logger.warning('drop %s', record)\n"
        "        return None\n",
        _queue_full_handlers(fn)[0],
    ) or ""
    assert "_safe_log_detection_id" not in segment
    assert "AuditWriteOutcome.failed" not in segment
