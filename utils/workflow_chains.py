"""
Agentic security review workflow.

Pipeline:

1. Detection
2. RAG retrieval
3. Validation
4. Patch generation

Groq is used for LLM reasoning.
"""

import json
import re

from groq import Groq


SYSTEM_PROMPT = """
You are ASCR, a defensive application security code reviewer.

Your job is to analyze source code for concrete security vulnerabilities.

Important rules:

1. Analyze only the supplied source code.
2. Never invent vulnerabilities.
3. Do not treat comments alone as vulnerabilities.
4. Do not report hypothetical vulnerabilities without evidence.
5. Prefer concrete security defects.
6. Explain the exact vulnerable pattern.
7. Use the supplied security guidance during validation.
8. Preserve application behavior when generating patches.
9. Never expose or request real secrets.
10. Return structured JSON whenever requested.
"""


class SecurityReviewWorkflow:
    """
    Multi-stage security review workflow.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        rag_pipeline,
    ):
        self.client = Groq(
            api_key=api_key,
        )

        self.model = model

        self.rag = rag_pipeline

    # =========================================================
    # GROQ REQUEST
    # =========================================================

    def _chat(
        self,
        prompt: str,
        temperature: float = 0.1,
    ):

        response = self.client.chat.completions.create(
            model=self.model,
            temperature=temperature,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )

        return response.choices[0].message.content

    # =========================================================
    # STAGE 1 — DETECTION
    # =========================================================

    def detect(
        self,
        code: str,
        filename: str,
    ):
        """
        Detect potential vulnerabilities.

        Returns raw LLM response.
        """

        prompt = f"""
Perform a security review of the following source code.

Filename:
{filename}

Return ONLY valid JSON using this structure:

{{
    "findings": [
        {{
            "vulnerability_type": "SQL Injection",
            "severity": "High",
            "confidence": 0.95,
            "line_start": 1,
            "line_end": 5,
            "description": "Specific explanation based on the code",
            "original_code": "Relevant vulnerable snippet",
            "language": "python"
        }}
    ]
}}

Allowed severity values:

High
Medium
Low

If no credible vulnerability is found, return:

{{
    "findings": []
}}

Do not report general coding style problems.

SOURCE CODE:

```text
{code[:30000]}
