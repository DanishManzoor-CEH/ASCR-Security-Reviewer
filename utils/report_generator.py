"""
Markdown security report generator.
"""

from datetime import datetime


def build_markdown_report(
    filename: str,
    findings: list,
):
    """
    Generate a structured Markdown security report.
    """

    confirmed = [
        finding
        for finding in findings
        if finding.get(
            "status"
        ) == "confirmed"
    ]

    lines = []

    # ---------------------------------------------------------
    # HEADER
    # ---------------------------------------------------------

    lines.extend(
        [
            "# 🛡️ ASCR Security Assessment Report",
            "",
            f"**File:** `{filename}`  ",
            (
                f"**Generated:** "
                f"{datetime.utcnow().isoformat()}Z  "
            ),
            (
                f"**Confirmed Findings:** "
                f"{len(confirmed)}"
            ),
            "",
            "---",
            "",
        ]
    )

    # ---------------------------------------------------------
    # DISCLAIMER
    # ---------------------------------------------------------

    lines.extend(
        [
            "## ⚠️ Assessment Notice",
            "",
            (
                "This report was generated using an "
                "AI-assisted defensive security review "
                "workflow. Findings and patches should be "
                "manually verified before production use."
            ),
            "",
        ]
    )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    lines.extend(
        [
            "## Executive Summary",
            "",
        ]
    )

    if not confirmed:

        lines.extend(
            [
                (
                    "The verification stage did not "
                    "confirm any vulnerabilities."
                ),
                "",
            ]
        )

    else:

        lines.extend(
            [
                (
                    f"The workflow confirmed "
                    f"{len(confirmed)} security "
                    f"finding(s)."
                ),
                "",
            ]
        )

    # ---------------------------------------------------------
    # FINDINGS
    # ---------------------------------------------------------

    lines.extend(
        [
            "## Security Findings",
            "",
        ]
    )

    for number, finding in enumerate(
        confirmed,
        start=1,
    ):

        lines.extend(
            [
                (
                    f"### {number}. "
                    f"{finding.get('vulnerability_type', 'Finding')}"
                ),
                "",
                (
                    f"**Severity:** "
                    f"{finding.get('severity', 'Unknown')}"
                ),
                "",
                (
                    f"**Confidence:** "
                    f"{finding.get('confidence', 'N/A')}"
                ),
                "",
                (
                    f"**Lines:** "
                    f"{finding.get('line_start', '?')}"
                    f"–"
                    f"{finding.get('line_end', '?')}"
                ),
                "",
                "**Description**",
                "",
                finding.get(
                    "description",
                    "No description provided.",
                ),
                "",
                "**Validation Result**",
                "",
                finding.get(
                    "validation_reason",
                    "No validation explanation.",
                ),
                "",
            ]
        )

        # -----------------------------------------------------
        # ORIGINAL CODE
        # -----------------------------------------------------

        lines.extend(
            [
                "#### Original Code",
                "",
                "```",
                finding.get(
                    "original_code",
                    "",
                ),
                "```",
                "",
            ]
        )

        # -----------------------------------------------------
        # PATCH
        # -----------------------------------------------------

        lines.extend(
            [
                "#### Suggested Patch",
                "",
                "```",
                finding.get(
                    "patched_code",
                    "",
                ),
                "```",
                "",
            ]
        )

        # -----------------------------------------------------
        # EXPLANATION
        # -----------------------------------------------------

        lines.extend(
            [
                "#### Remediation Explanation",
                "",
                finding.get(
                    "patch_explanation",
                    "No explanation provided.",
                ),
                "",
            ]
        )

        # -----------------------------------------------------
        # RAG CONTEXT
        # -----------------------------------------------------

        lines.extend(
            [
                "#### Retrieved Security Guidance",
                "",
            ]
        )

        contexts = finding.get(
            "rag_context",
            [],
        )

        if contexts:

            for context in contexts:

                lines.extend(
                    [
                        f"> {context}",
                        "",
                    ]
                )

        else:

            lines.extend(
                [
                    "No RAG context available.",
                    "",
                ]
            )

        # -----------------------------------------------------
        # REFERENCE
        # -----------------------------------------------------

        lines.extend(
            [
                "#### Security Reference",
                "",
                finding.get(
                    "owasp_reference",
                    "Not provided.",
                ),
                "",
                "---",
                "",
            ]
        )

    # ---------------------------------------------------------
    # METHODOLOGY
    # ---------------------------------------------------------

    lines.extend(
        [
            "## ASCR Methodology",
            "",
            "### Stage 1 — Vulnerability Detection",
            "",
            (
                "The source code is submitted to a Groq-powered "
                "LLM which identifies potential security issues."
            ),
            "",
            "### Stage 2 — RAG Context Retrieval",
            "",
            (
                "Security guidance is retrieved from the local "
                "knowledge base using Sentence Transformer "
                "embeddings and FAISS similarity search."
            ),
            "",
            "### Stage 3 — Agentic Validation",
            "",
            (
                "Each candidate finding is independently "
                "validated against the source code and "
                "retrieved security guidance."
            ),
            "",
            "### Stage 4 — Remediation",
            "",
            (
                "Confirmed findings are passed to a remediation "
                "agent which generates a minimal secure patch."
            ),
            "",
            "### Stage 5 — Report Generation",
            "",
            (
                "The findings, remediation information and "
                "retrieved security guidance are compiled into "
                "this Markdown assessment."
            ),
            "",
            "---",
            "",
            "## Important",
            "",
            (
                "ASCR is an AI-assisted security review tool. "
                "It should not be treated as a replacement for "
                "professional penetration testing, SAST, DAST, "
                "manual code review or other security testing."
            ),
        ]
    )

    return "\n".join(lines)
