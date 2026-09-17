import json
import re
from typing import Any, Dict, List

from groq import Groq


# ============================================================
# JSON EXTRACTION
# ============================================================

def extract_json_findings(response_text: str) -> List[Dict[str, Any]]:
    """
    Extract vulnerability findings from an LLM response.

    The function accepts:
    - A JSON object
    - A JSON array
    - JSON inside a markdown code block
    - A response containing JSON surrounded by normal text
    """

    if not response_text:
        return []

    text = response_text.strip()

    # --------------------------------------------------------
    # Remove markdown code fences
    # --------------------------------------------------------

    text = re.sub(
        r"```json\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"```\s*",
        "",
        text,
    )

    text = text.strip()

    # --------------------------------------------------------
    # Try direct JSON parsing
    # --------------------------------------------------------

    try:

        parsed = json.loads(text)

        if isinstance(parsed, list):
            return parsed

        if isinstance(parsed, dict):

            if isinstance(
                parsed.get("findings"),
                list,
            ):
                return parsed["findings"]

            return [parsed]

    except json.JSONDecodeError:
        pass

    # --------------------------------------------------------
    # Search for JSON array
    # --------------------------------------------------------

    array_match = re.search(
        r"\[[\s\S]*\]",
        text,
    )

    if array_match:

        try:

            parsed = json.loads(
                array_match.group(0)
            )

            if isinstance(parsed, list):
                return parsed

        except json.JSONDecodeError:
            pass

    # --------------------------------------------------------
    # Search for JSON object
    # --------------------------------------------------------

    object_match = re.search(
        r"\{[\s\S]*\}",
        text,
    )

    if object_match:

        try:

            parsed = json.loads(
                object_match.group(0)
            )

            if isinstance(parsed, dict):

                if isinstance(
                    parsed.get("findings"),
                    list,
                ):
                    return parsed["findings"]

                return [parsed]

        except json.JSONDecodeError:
            pass

    return []


# ============================================================
# FINDING NORMALIZATION
# ============================================================

def normalize_finding(
    finding: Dict[str, Any],
) -> Dict[str, Any]:

    normalized = dict(finding)

    normalized.setdefault(
        "vulnerability_type",
        "Unknown Security Issue",
    )

    normalized.setdefault(
        "severity",
        "Medium",
    )

    normalized.setdefault(
        "confidence",
        "Unknown",
    )

    normalized.setdefault(
        "description",
        "No description provided.",
    )

    normalized.setdefault(
        "line_start",
        0,
    )

    normalized.setdefault(
        "line_end",
        0,
    )

    normalized.setdefault(
        "original_code",
        "",
    )

    normalized.setdefault(
        "language",
        "text",
    )

    normalized.setdefault(
        "status",
        "uncertain",
    )

    normalized.setdefault(
        "validation_reason",
        "",
    )

    normalized.setdefault(
        "patched_code",
        "",
    )

    normalized.setdefault(
        "patch_explanation",
        "",
    )

    normalized.setdefault(
        "owasp_reference",
        "",
    )

    normalized.setdefault(
        "rag_context",
        [],
    )

    return normalized


# ============================================================
# SECURITY REVIEW WORKFLOW
# ============================================================

class SecurityReviewWorkflow:

    def __init__(
        self,
        api_key: str,
        model: str,
        rag_pipeline: Any = None,
    ):

        if not api_key:
            raise ValueError(
                "Groq API key is required."
            )

        self.client = Groq(
            api_key=api_key
        )

        self.model = model

        self.rag_pipeline = rag_pipeline

    # ========================================================
    # GROQ REQUEST
    # ========================================================

    def _chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> str:

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if not response.choices:
            return ""

        message = response.choices[0].message

        if not message:
            return ""

        content = message.content

        if content is None:
            return ""

        return content

    # ========================================================
    # STAGE 1
    # VULNERABILITY DETECTION
    # ========================================================

    def detect(
        self,
        code: str,
        filename: str = "source_code.txt",
    ) -> str:

        system_prompt = (
            "You are an expert defensive application security "
            "code reviewer. Analyze source code for realistic "
            "security vulnerabilities. Do not invent issues. "
            "Only report vulnerabilities supported by the "
            "provided code. Focus on OWASP-style application "
            "security problems. Return valid JSON only."
        )

        user_prompt = (
            "Review the following source code.\n\n"
            "Filename: "
            + str(filename)
            + "\n\n"
            "SOURCE CODE:\n"
            + code
            + "\n\n"
            "Return a JSON object using this exact structure:\n"
            "{\n"
            '  "findings": [\n'
            "    {\n"
            '      "vulnerability_type": "SQL Injection",\n'
            '      "severity": "High",\n'
            '      "confidence": "High",\n'
            '      "description": "Detailed explanation",\n'
            '      "line_start": 1,\n'
            '      "line_end": 2,\n'
            '      "original_code": "Relevant code",\n'
            '      "language": "python",\n'
            '      "owasp_reference": "OWASP category if applicable"\n'
            "    }\n"
            "  ]\n"
            "}\n\n"
            "If there are no credible vulnerabilities, return:\n"
            '{"findings": []}\n\n'
            "Do not wrap the JSON in markdown."
        )

        return self._chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.0,
            max_tokens=4096,
        )

    # ========================================================
    # STAGE 2
    # RAG CONTEXT RETRIEVAL
    # ========================================================

    def retrieve_context(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        normalized_findings = []

        for finding in findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue

            item = normalize_finding(
                finding
            )

            vulnerability = item.get(
                "vulnerability_type",
                "",
            )

            description = item.get(
                "description",
                "",
            )

            query = (
                str(vulnerability)
                + " "
                + str(description)
                + " secure coding mitigation OWASP"
            )

            contexts = []

            # ------------------------------------------------
            # Query RAG pipeline
            # ------------------------------------------------

            if self.rag_pipeline is not None:

                try:

                    contexts = self._query_rag(
                        query
                    )

                except Exception:

                    contexts = []

            item["rag_context"] = contexts

            normalized_findings.append(
                item
            )

        return normalized_findings

    # ========================================================
    # RAG COMPATIBILITY LAYER
    # ========================================================

    def _query_rag(
        self,
        query: str,
    ) -> List[str]:

        rag = self.rag_pipeline

        # ----------------------------------------------------
        # Method 1: search
        # ----------------------------------------------------

        if hasattr(
            rag,
            "search",
        ):

            result = rag.search(
                query,
                top_k=3,
            )

            return self._convert_rag_result(
                result
            )

        # ----------------------------------------------------
        # Method 2: retrieve
        # ----------------------------------------------------

        if hasattr(
            rag,
            "retrieve",
        ):

            result = rag.retrieve(
                query,
                top_k=3,
            )

            return self._convert_rag_result(
                result
            )

        # ----------------------------------------------------
        # Method 3: query
        # ----------------------------------------------------

        if hasattr(
            rag,
            "query",
        ):

            result = rag.query(
                query,
                top_k=3,
            )

            return self._convert_rag_result(
                result
            )

        return []

    # ========================================================
    # RAG RESULT CONVERSION
    # ========================================================

    def _convert_rag_result(
        self,
        result: Any,
    ) -> List[str]:

        if result is None:
            return []

        if isinstance(
            result,
            str,
        ):
            return [result]

        if isinstance(
            result,
            list,
        ):

            output = []

            for item in result:

                if isinstance(
                    item,
                    str,
                ):

                    output.append(
                        item
                    )

                elif isinstance(
                    item,
                    dict,
                ):

                    text = (
                        item.get("text")
                        or item.get("content")
                        or item.get("page_content")
                        or ""
                    )

                    if text:
                        output.append(
                            str(text)
                        )

            return output[:3]

        return []

    # ========================================================
    # STAGE 3
    # AGENTIC VALIDATION
    # ========================================================

    def validate(
        self,
        code: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        validated = []

        for finding in findings:

            item = normalize_finding(
                finding
            )

            contexts = item.get(
                "rag_context",
                [],
            )

            context_text = "\n\n".join(
                str(context)
                for context in contexts
            )

            validation_prompt = (
                "Evaluate the following potential security "
                "finding against the supplied source code and "
                "security guidance.\n\n"
                "SOURCE CODE:\n"
                + code
                + "\n\n"
                "POTENTIAL FINDING:\n"
                + json.dumps(
                    item,
                    indent=2,
                )
                + "\n\n"
                "SECURITY GUIDANCE:\n"
                + context_text
                + "\n\n"
                "Decide whether this finding is:\n"
                "- confirmed\n"
                "- false_positive\n"
                "- uncertain\n\n"
                "A finding should be confirmed only when the "
                "source code provides sufficient evidence of a "
                "real security issue. Do not confirm a finding "
                "only because the pattern looks suspicious.\n\n"
                "Return valid JSON only:\n"
                "{\n"
                '  "status": "confirmed",\n'
                '  "reason": "Detailed reasoning"\n'
                "}"
            )

            system_prompt = (
                "You are a security validation agent. "
                "Your job is to reduce false positives in "
                "automated source-code security reviews. "
                "Be evidence-based and conservative."
            )

            try:

                validation_response = self._chat(
                    system_prompt=system_prompt,
                    user_prompt=validation_prompt,
                    temperature=0.0,
                    max_tokens=1500,
                )

                validation_data = (
                    self._parse_object(
                        validation_response
                    )
                )

                status = str(
                    validation_data.get(
                        "status",
                        "uncertain",
                    )
                ).lower()

                allowed_statuses = {
                    "confirmed",
                    "false_positive",
                    "uncertain",
                }

                if status not in allowed_statuses:
                    status = "uncertain"

                item["status"] = status

                item["validation_reason"] = (
                    validation_data.get(
                        "reason",
                        "No validation reason provided.",
                    )
                )

            except Exception as exc:

                item["status"] = "uncertain"

                item["validation_reason"] = (
                    "Validation could not be completed: "
                    + str(exc)
                )

            validated.append(
                item
            )

        return validated

    # ========================================================
    # STAGE 4
    # PATCH GENERATION
    # ========================================================

    def generate_patches(
        self,
        code: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        patched_findings = []

        for finding in findings:

            item = normalize_finding(
                finding
            )

            # ------------------------------------------------
            # Do not patch false positives
            # ------------------------------------------------

            if item.get(
                "status"
            ) != "confirmed":

                patched_findings.append(
                    item
                )

                continue

            contexts = item.get(
                "rag_context",
                [],
            )

            context_text = "\n\n".join(
                str(context)
                for context in contexts
            )

            patch_prompt = (
                "Generate a secure remediation for the "
                "confirmed vulnerability below.\n\n"
                "SOURCE CODE:\n"
                + code
                + "\n\n"
                "CONFIRMED FINDING:\n"
                + json.dumps(
                    item,
                    indent=2,
                )
                + "\n\n"
                "SECURITY GUIDANCE:\n"
                + context_text
                + "\n\n"
                "Generate a minimal patch that fixes the "
                "security vulnerability while preserving the "
                "intended application behavior.\n\n"
                "Return valid JSON only:\n"
                "{\n"
                '  "patched_code": "Corrected code snippet",\n'
                '  "patch_explanation": "Explain why this patch '
                'removes the vulnerability",\n'
                '  "logic_preserved": true\n'
                "}"
            )

            system_prompt = (
                "You are a secure software remediation agent. "
                "Generate defensive code fixes. Do not introduce "
                "new vulnerabilities. Preserve application "
                "logic whenever possible."
            )

            try:

                patch_response = self._chat(
                    system_prompt=system_prompt,
                    user_prompt=patch_prompt,
                    temperature=0.1,
                    max_tokens=3000,
                )

                patch_data = self._parse_object(
                    patch_response
                )

                item["patched_code"] = (
                    patch_data.get(
                        "patched_code",
                        "",
                    )
                )

                item["patch_explanation"] = (
                    patch_data.get(
                        "patch_explanation",
                        "",
                    )
                )

                item["logic_preserved"] = (
                    patch_data.get(
                        "logic_preserved",
                        None,
                    )
                )

            except Exception as exc:

                item["patched_code"] = ""

                item["patch_explanation"] = (
                    "Patch generation failed: "
                    + str(exc)
                )

            patched_findings.append(
                item
            )

        return patched_findings

    # ========================================================
    # JSON OBJECT PARSER
    # ========================================================

    def _parse_object(
        self,
        response_text: str,
    ) -> Dict[str, Any]:

        if not response_text:
            return {}

        text = response_text.strip()

        text = re.sub(
            r"```json\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )

        text = re.sub(
            r"```\s*",
            "",
            text,
        )

        text = text.strip()

        try:

            parsed = json.loads(
                text
            )

            if isinstance(
                parsed,
                dict,
            ):

                return parsed

        except json.JSONDecodeError:
            pass

        match = re.search(
            r"\{[\s\S]*\}",
            text,
        )

        if match:

            try:

                parsed = json.loads(
                    match.group(0)
                )

                if isinstance(
                    parsed,
                    dict,
                ):

                    return parsed

            except json.JSONDecodeError:
                pass

        return {}


# ============================================================
# SIMPLE WORKFLOW TEST
# ============================================================

def test_groq_connection(
    api_key: str,
    model: str,
) -> str:

    workflow = SecurityReviewWorkflow(
        api_key=api_key,
        model=model,
        rag_pipeline=None,
    )

    return workflow._chat(
        system_prompt=(
            "You are a helpful assistant."
        ),
        user_prompt=(
            "Respond with exactly: ASCR connection successful"
        ),
        temperature=0.0,
        max_tokens=50,
    )
