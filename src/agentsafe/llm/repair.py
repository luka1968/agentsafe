"""Deterministic best-effort JSON repair for structured-output robustness.

P0-3a: when a provider returns near-JSON (single quotes, unquoted keys,
trailing commas, stray prose around the object, leftover markdown fences) the
router applies ONLY mechanical, content-preserving rewrites here before it
resorts to a costly re-prompt. No value is ever invented or truncated.

Contract: repair never fabricates content. It returns a string that actually
parses via ``json.loads`` and equals the original bytes modulo the mechanical
rewrites below. ``None`` means "no safe repair available".
"""

from __future__ import annotations

import json
import re


def extract_balanced(text: str) -> str | None:
    """Locate the FIRST balanced JSON object/array in arbitrary text
    (string-aware, escape-aware). Extraction only: bytes between the outermost
    brackets are never modified."""
    start = -1
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            break
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return text[start : j + 1]
    return None


def _parses(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except json.JSONDecodeError:
        return False


def repair_json(text: str) -> str | None:
    """Apply mechanical fixes to near-JSON and return reparsed text if safe."""
    if not text or not text.strip():
        return None
    text = text.strip()
    # Drop markdown fences the router's fence-unwrapper may have missed.
    if text.startswith("```"):
        n = text.find("\n")
        if n != -1:
            text = text[n + 1 :]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    candidate = extract_balanced(text)
    if candidate is None:
        return None

    # 1. trailing commas before } or ]
    s = re.sub(r",\s*([}\]])", r"\1", candidate)
    if _parses(s):
        return s

    # 2. single-quoted strings -> double-quoted (value-level, safe for JSON
    #    since JSON has no single-quote semantics).
    s2 = re.sub(r"'([^'\\]*(?:\\.[^'\\]*)*)'", r'"\1"', candidate)
    if _parses(s2):
        return s2

    # 3. unquoted keys -> quoted (only bare identifiers, never values).
    s3 = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:", r'\1"\2":', candidate)
    if _parses(s3):
        return s3

    # 4. combined fix (single quotes + unquoted keys at once) for the common
    #    case the LLM emits both together.
    s4 = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:", r'\1"\2":', s2)
    if _parses(s4):
        return s4

    return None