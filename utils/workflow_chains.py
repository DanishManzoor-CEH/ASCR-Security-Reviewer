"""
workflow_chains.py
------------------
The four-stage prompt-chaining workflow of the Agentic Security Code Reviewer.

    [Input Code] -> Stage 1: Vulnerability Detection      (Decide)
                 -> Stage 2: Policy Retrieval via RAG     (Augment)
                 -> Stage 3: Verification + Remediation   (Create & Check)
                 -> Stage 4: Report Synthesis             (Package)

Every stage returns an inspectable intermediate artifact, so the UI can show
exactly what the model saw and produced at each hop.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from groq import Groq

# ---------------------------------------------------------------------------
# Models available on Groq. Keep the first entry as the sensible default.
# ---------------------------------------------------------------------------
AVAILABLE_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "deepseek-r1-distill-llama-70b",
    "openai/gpt-oss-20b",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    title: str
    vulnerability_type: str
    severity: str
    line_start: int
    line_end: int
    vulnerable_snippet: str
    description: str
    cwe: str = ""
    owasp: str = ""
    block: str = "whole_file"

    # filled in by later stages
    retrieved_context: List[Dict[str, Any]] = field(default_factory=list)
    is_true_positive: Optional[bool] = None
    confidence: float = 0.0
    verdict_reason: str = ""
    patched_snippet: str = ""
    fix_explanation: str = ""
    logic_preserved: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Groq client wrapper
# ---------------------------------------------------------------------------
class LLM:
    def __init__(self, api_key: str, model: str = AVAILABLE_MODELS[0], temperature: float = 0.1):
        if not api_key:
            raise ValueError("A Groq API key is required. Add it in the sidebar or in .streamlit/secrets.toml")
        self.client = Groq(api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.call_log: List[Dict[str, Any]] = []

    def complete(self, system: str, user: str, max_tokens: int = 2048, json_mode: bool = False) -> str:
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self.client.chat.completions.create(**kwargs)
        except Exception as exc:
            # json_object is not supported by every model — retry without it.
            if json_mode:
                kwargs.pop("response_format", None)
                response = self.client.chat.completions.create(**kwargs)
            else:
                raise RuntimeError(f"Groq API call failed: {exc}") from exc

        content = response.choices[0].message.content or ""
        self.call_log.append({"model": self.model, "chars_in": len(user), "chars_out": len(content)})
        return content


# ---------------------------------------------------------------------------
# JSON helpers — LLMs wrap JSON in prose or fences more often than we'd like.
# ---------------------------------------------------------------------------
def extract_json(raw: str) -> Any:
    if not raw:
        return None
    text = re.sub(r"<think>.*?</think>", "", raw, flags=re.S)  # deepseek-r1 reasoning traces
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            candidate = text[start : end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    return None


def _clean_code(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    fence = re.search(r"```[a-zA-Z0-9_+-]*\n(.*?)```", text, flags=re.S)
    return (fence.group(1) if fence else text).strip()


# ---------------------------------------------------------------------------
# STAGE 1 — Static analysis / vulnerability detection
# ---------------------------------------------------------------------------
DETECT_SYSTEM = """You are a senior application security engineer performing a static code review.
You find real, exploitable security weaknesses in source code. You never invent issues that are
not clearly present in the code you are given, and you ignore pure style or performance problems.

Reply with a single JSON object and nothing else, in exactly this shape:
{
  "findings": [
    {
      "title": "short human readable title",
      "vulnerability_type": "e.g. SQL Injection, Hardcoded Credentials, Command Injection, Path Traversal, Insecure Deserialization, Weak Cryptography, XSS, SSRF, Missing Authorization, Insecure Randomness",
      "severity": "Critical | High | Medium | Low",
      "line_start": 12,
      "line_end": 14,
      "vulnerable_snippet": "the exact offending lines copied verbatim",
      "description": "why this is dangerous and how it could be abused",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection"
    }
  ]
}
If the code contains no security vulnerabilities, return {"findings": []}. Do not pad the list."""


def stage1_detect(llm: LLM, code: str, language: str, block_name: str = "whole_file", start_line: int = 1) -> List[Finding]:
    numbered = "\n".join(f"{i + start_line:>4} | {line}" for i, line in enumerate(code.splitlines()))
    user = (
        f"Language: {language}\n"
        f"Code unit: {block_name}\n\n"
        "Review the following code. Line numbers are shown on the left for reference only; "
        "do not include them in any snippet you copy.\n\n"
        f"```{language}\n{numbered}\n```"
    )
    raw = llm.complete(DETECT_SYSTEM, user, max_tokens=2600, json_mode=True)
    data = extract_json(raw) or {}
    items = data.get("findings", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

    findings: List[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            findings.append(
                Finding(
                    title=str(item.get("title") or item.get("vulnerability_type") or "Unnamed finding")[:160],
                    vulnerability_type=str(item.get("vulnerability_type") or "Unspecified"),
                    severity=_normalise_severity(item.get("severity")),
                    line_start=_as_int(item.get("line_start"), start_line),
                    line_end=_as_int(item.get("line_end"), _as_int(item.get("line_start"), start_line)),
                    vulnerable_snippet=str(item.get("vulnerable_snippet") or "").strip(),
                    description=str(item.get("description") or "").strip(),
                    cwe=str(item.get("cwe") or ""),
                    owasp=str(item.get("owasp") or ""),
                    block=block_name,
                )
            )
        except Exception:
            continue
    return findings


def _normalise_severity(value: Any) -> str:
    text = str(value or "Medium").strip().lower()
    for key in SEVERITY_ORDER:
        if key in text:
            return key.capitalize()
    return "Medium"


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


# ---------------------------------------------------------------------------
# STAGE 2 — Policy retrieval (RAG)
# ---------------------------------------------------------------------------
def stage2_retrieve(kb, finding: Finding, k: int = 4) -> List[Dict[str, Any]]:
    """Query the vector store with the vulnerability type + description."""
    if kb is None:
        return []
    query = f"{finding.vulnerability_type} {finding.title}. Secure coding guidance and remediation. {finding.description[:300]}"
    hits = kb.search(query, k=k)
    finding.retrieved_context = [{"source": h.source, "score": round(h.score, 4), "text": h.text} for h in hits]
    return finding.retrieved_context


# ---------------------------------------------------------------------------
# STAGE 3 — Agentic verification + remediation
# ---------------------------------------------------------------------------
VERIFY_SYSTEM = """You are a security reviewer acting as a strict verifier and remediation engineer.

You are given (a) a code snippet, (b) a vulnerability claimed by an earlier analysis pass, and
(c) authoritative secure-coding guidance retrieved from a policy knowledge base.

Do two things:
1. VERIFY. Decide whether the claim is a TRUE POSITIVE against the retrieved guidance and the
   actual code. Mark it a false positive when the code is already safe (parameterised query,
   value taken from a secrets manager, input already validated, sink is not reachable with
   attacker input, or the claim is merely stylistic).
2. REMEDIATE. Only if it is a true positive, rewrite the snippet so the weakness is removed while
   preserving the original behaviour, function signatures and return values.

Reply with one JSON object and nothing else:
{
  "is_true_positive": true,
  "confidence": 0.0-1.0,
  "verdict_reason": "one or two sentences grounded in the retrieved guidance",
  "corrected_severity": "Critical | High | Medium | Low",
  "patched_snippet": "the fixed code, or empty string if false positive",
  "fix_explanation": "why the fix removes the weakness",
  "logic_preserved": true
}"""


def stage3_verify_and_patch(llm: LLM, finding: Finding, language: str, full_code: str = "") -> Finding:
    context_block = "\n\n".join(
        f"[{c['source']} | similarity {c['score']}]\n{c['text']}" for c in finding.retrieved_context
    ) or "No policy context was retrieved. Rely on widely accepted secure coding practice."

    snippet = finding.vulnerable_snippet or _slice_lines(full_code, finding.line_start, finding.line_end)

    user = f"""LANGUAGE: {language}

CLAIMED VULNERABILITY
  Type      : {finding.vulnerability_type}
  Severity  : {finding.severity}
  Lines     : {finding.line_start}-{finding.line_end}
  Rationale : {finding.description}

CODE SNIPPET UNDER REVIEW
```{language}
{snippet}
```

SURROUNDING FILE CONTEXT (truncated)
```{language}
{full_code[:3000]}
```

RETRIEVED SECURE CODING GUIDANCE
{context_block}

Verify the claim, then patch it if real."""

    raw = llm.complete(VERIFY_SYSTEM, user, max_tokens=2200, json_mode=True)
    data = extract_json(raw) or {}

    finding.is_true_positive = bool(data.get("is_true_positive", True))
    try:
        finding.confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
    except Exception:
        finding.confidence = 0.5
    finding.verdict_reason = str(data.get("verdict_reason") or "").strip()
    finding.fix_explanation = str(data.get("fix_explanation") or "").strip()
    finding.patched_snippet = _clean_code(str(data.get("patched_snippet") or ""))
    finding.logic_preserved = data.get("logic_preserved")
    if data.get("corrected_severity"):
        finding.severity = _normalise_severity(data.get("corrected_severity"))
    if not finding.vulnerable_snippet:
        finding.vulnerable_snippet = snippet
    return finding


def _slice_lines(code: str, start: int, end: int, pad: int = 2) -> str:
    lines = code.splitlines()
    if not lines:
        return code
    a = max(0, start - 1 - pad)
    b = min(len(lines), max(end, start) + pad)
    return "\n".join(lines[a:b])


# ---------------------------------------------------------------------------
# STAGE 4 — Report synthesis
# ---------------------------------------------------------------------------
def stage4_report(
    findings: List[Finding],
    filename: str,
    language: str,
    model: str,
    kb_sources: List[str],
    rejected: List[Finding] | None = None,
) -> str:
    rejected = rejected or []
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = {sev: sum(1 for f in findings if f.severity.lower() == sev) for sev in SEVERITY_ORDER}

    lines = [
        "# Security Assessment Report",
        "",
        "**Agentic Security Code Reviewer (ASCR)**",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Target file | `{filename}` |",
        f"| Language | {language} |",
        f"| Generated | {now} |",
        f"| Analysis model | `{model}` |",
        f"| Knowledge base | {', '.join(kb_sources) if kb_sources else 'not loaded'} |",
        f"| Confirmed findings | {len(findings)} |",
        f"| Rejected as false positives | {len(rejected)} |",
        "",
        "## 1. Executive Summary",
        "",
    ]

    if findings:
        summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s])
        top = findings[0]
        lines += [
            f"The review confirmed **{len(findings)} security {'issue' if len(findings) == 1 else 'issues'}** "
            f"({summary}). The highest-risk item is **{top.title}** "
            f"({top.vulnerability_type}, {top.severity}) at line {top.line_start}.",
            "",
            "| # | Severity | Vulnerability | Location | Confidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for i, f in enumerate(findings, 1):
            lines.append(
                f"| {i} | {f.severity} | {f.vulnerability_type} | L{f.line_start}-{f.line_end} | {f.confidence:.0%} |"
            )
    else:
        lines.append(
            "No exploitable security weaknesses were confirmed in the submitted code. "
            "This is not a guarantee of absence — it reflects what static, context-limited review could observe."
        )

    lines += ["", "## 2. Detailed Findings", ""]
    if not findings:
        lines.append("_No confirmed findings._")

    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. {f.title}",
            "",
            f"- **Severity:** {f.severity}",
            f"- **Type:** {f.vulnerability_type}",
            f"- **Location:** lines {f.line_start}–{f.line_end} (`{f.block}`)",
            f"- **CWE:** {f.cwe or 'n/a'}",
            f"- **OWASP:** {f.owasp or 'n/a'}",
            f"- **Verification confidence:** {f.confidence:.0%}",
            "",
            "**Description**",
            "",
            f.description or "_n/a_",
            "",
            "**Vulnerable code**",
            "",
            f"```{language}",
            f.vulnerable_snippet or "_snippet unavailable_",
            "```",
            "",
        ]
        if f.patched_snippet:
            lines += [
                "**Remediated code**",
                "",
                f"```{language}",
                f.patched_snippet,
                "```",
                "",
                "**Why this fix works**",
                "",
                f.fix_explanation or "_n/a_",
                "",
                f"_Logic preservation check: {'passed' if f.logic_preserved else 'needs manual confirmation'}._",
                "",
            ]
        if f.verdict_reason:
            lines += ["**Verification verdict**", "", f.verdict_reason, ""]
        if f.retrieved_context:
            lines += ["**Secure coding references used**", ""]
            for c in f.retrieved_context:
                excerpt = " ".join(c["text"].split())[:320]
                lines.append(f"- `{c['source']}` (similarity {c['score']}): {excerpt}…")
            lines.append("")

    if rejected:
        lines += ["## 3. Rejected Candidates (Agentic False-Positive Filter)", ""]
        lines += ["| Candidate | Type | Reason for rejection |", "| --- | --- | --- |"]
        for f in rejected:
            reason = " ".join((f.verdict_reason or "Not corroborated by retrieved policy.").split())[:200]
            lines.append(f"| {f.title} | {f.vulnerability_type} | {reason} |")
        lines.append("")

    lines += [
        "## 4. Methodology",
        "",
        "1. **Detection** – the source was split into logical code units and passed to the LLM for structured static analysis.",
        "2. **Retrieval (RAG)** – each candidate vulnerability queried a FAISS vector index built from secure-coding guidance.",
        "3. **Verification & remediation** – an agentic evaluation node judged each candidate against the retrieved policy before a patch was generated.",
        "4. **Reporting** – confirmed findings were aggregated into this document.",
        "",
        "> Generated automatically. LLM output must be reviewed by a human before any patch is merged.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def run_pipeline(
    llm: LLM,
    kb,
    code: str,
    filename: str,
    language: str,
    top_k: int = 4,
    drop_false_positives: bool = True,
    progress: Optional[Callable[[float, str], None]] = None,
) -> Dict[str, Any]:
    """Execute stages 1-4 and return every intermediate artifact."""
    from .rag_pipeline import chunk_source_code

    def tick(pct: float, msg: str) -> None:
        if progress:
            progress(min(max(pct, 0.0), 1.0), msg)

    blocks = chunk_source_code(code)
    tick(0.05, f"Split source into {len(blocks)} code unit(s)")

    # Stage 1
    candidates: List[Finding] = []
    for i, block in enumerate(blocks):
        tick(0.05 + 0.35 * (i / max(len(blocks), 1)), f"Stage 1 — scanning `{block['name']}`")
        candidates.extend(stage1_detect(llm, block["code"], language, block["name"], block["start_line"]))

    candidates = _deduplicate(candidates)
    tick(0.4, f"Stage 1 complete — {len(candidates)} candidate(s)")

    confirmed: List[Finding] = []
    rejected: List[Finding] = []

    for i, finding in enumerate(candidates):
        base = 0.4 + 0.5 * (i / max(len(candidates), 1))
        tick(base, f"Stage 2 — retrieving policy for {finding.vulnerability_type}")
        stage2_retrieve(kb, finding, k=top_k)

        tick(base + 0.02, f"Stage 3 — verifying & patching {finding.vulnerability_type}")
        stage3_verify_and_patch(llm, finding, language, code)

        if finding.is_true_positive or not drop_false_positives:
            confirmed.append(finding)
        else:
            rejected.append(finding)

    confirmed.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity.lower(), 9), -f.confidence))

    tick(0.92, "Stage 4 — synthesising report")
    kb_sources = kb.sources if kb is not None else []
    report = stage4_report(confirmed, filename, language, llm.model, kb_sources, rejected)
    tick(1.0, "Done")

    return {
        "findings": confirmed,
        "rejected": rejected,
        "candidates": candidates,
        "blocks": blocks,
        "report_markdown": report,
        "filename": filename,
        "language": language,
        "model": llm.model,
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
    }


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.vulnerability_type.lower().strip(), f.line_start)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
