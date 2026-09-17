import os

import streamlit as st

from utils.rag_pipeline import RAGPipeline
from utils.workflow_chains import (
    SecurityReviewWorkflow,
    extract_json_findings,
)
from utils.report_generator import (
    build_markdown_report,
)


# =============================================================
# PAGE CONFIGURATION
# =============================================================

st.set_page_config(
    page_title="ASCR - Security Code Reviewer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =============================================================
# CUSTOM CSS
# =============================================================

st.markdown(
    """
<style>

.main-title {
    font-size: 42px;
    font-weight: 800;
    margin-bottom: 0;
}

.subtitle {
    font-size: 18px;
    opacity: 0.75;
    margin-bottom: 25px;
}

.metric-card {
    padding: 20px;
    border-radius: 12px;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
}

</style>
""",
    unsafe_allow_html=True,
)


# =============================================================
# HEADER
# =============================================================

st.markdown(
    '<div class="main-title">🛡️ Agentic Security Code Reviewer</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="subtitle">
Analyze → Retrieve → Validate → Patch → Report
</div>
""",
    unsafe_allow_html=True,
)


# =============================================================
# SESSION STATE
# =============================================================

if "last_findings" not in st.session_state:
    st.session_state.last_findings = None

if "last_report" not in st.session_state:
    st.session_state.last_report = None


# =============================================================
# SIDEBAR
# =============================================================

with st.sidebar:

    st.header("⚙️ Configuration")

    # ---------------------------------------------------------
    # API KEY
    # ---------------------------------------------------------

    default_api_key = os.getenv(
        "GROQ_API_KEY",
        "",
    )

    try:

        if not default_api_key:
            default_api_key = st.secrets.get(
                "GROQ_API_KEY",
                "",
            )

    except Exception:
        pass

    api_key = st.text_input(
        "Groq API Key",
        value=default_api_key,
        type="password",
        help="Your Groq API key is never stored by this application.",
    )

    # ---------------------------------------------------------
    # MODEL
    # ---------------------------------------------------------

    model = st.selectbox(
        "Groq Model",
        [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
        ],
        index=0,
    )

    st.divider()

    st.subheader("🔎 ASCR Pipeline")

    st.write(
        "1. Vulnerability Detection"
    )

    st.write(
        "2. RAG Retrieval"
    )

    st.write(
        "3. Agentic Validation"
    )

    st.write(
        "4. Secure Patch Generation"
    )

    st.write(
        "5. Markdown Report"
    )

    st.divider()

    st.caption(
        "Groq + Sentence Transformers + FAISS + Streamlit"
    )


# =============================================================
# MAIN TABS
# =============================================================

review_tab, demo_tab, about_tab = st.tabs(
    [
        "🔎 Security Review",
        "🧪 Demo",
        "ℹ️ About",
    ]
)


# =============================================================
# SECURITY REVIEW TAB
# =============================================================

with review_tab:

    st.subheader(
        "Source Code Input"
    )

    uploaded_file = st.file_uploader(
        "Upload a source code file",
        type=[
            "py",
            "js",
            "ts",
            "java",
            "c",
            "cpp",
            "h",
            "hpp",
            "php",
            "go",
            "rb",
            "cs",
            "sql",
            "txt",
        ],
    )

    pasted_code = st.text_area(
        "Or paste source code",
        height=350,
        placeholder=(
            "Paste your source code here..."
        ),
    )

    filename = "pasted_code.txt"

    code = pasted_code

    if uploaded_file:

        filename = uploaded_file.name

        try:

            code = uploaded_file.read().decode(
                "utf-8",
                errors="replace",
            )

        except Exception as exc:

            st.error(
                f"Could not read file: {exc}"
            )

    st.caption(
        f"Current file: `{filename}`"
    )

    run_review = st.button(
        "🚀 Run Agentic Security Review",
        type="primary",
        use_container_width=True,
    )


# =============================================================
# DEMO TAB
# =============================================================

with demo_tab:

    st.subheader(
        "🧪 Vulnerable Demo"
    )

    st.write(
        """
This example intentionally contains security issues so
you can test the ASCR pipeline.
"""
    )

    demo_code = """import sqlite3

API_KEY = "sk-demo-secret"

def search_user(name):

    conn = sqlite3.connect("app.db")

    query = "SELECT * FROM users WHERE name = '" + name + "'"

    return conn.execute(query).fetchall()
"""

    st.code(
        demo_code,
        language="python",
    )

    if st.button(
        "Load Demo Code",
        use_container_width=True,
    ):

        st.session_state.demo_code = demo_code

        st.session_state.demo_filename = (
            "demo.py"
        )

        st.success(
            "Demo loaded. Go to Security Review and run the review."
        )


# =============================================================
# ABOUT TAB
# =============================================================

with about_tab:

    st.subheader("About ASCR")

    st.markdown(
        
### Agentic Security Code Reviewer

ASCR is an AI-assisted security auditing platform designed
to demonstrate modern AI application security workflows.

### Technologies

- Groq API
- Streamlit
- Sentence Transformers
- FAISS
- Retrieval-Augmented Generation
- Agentic Validation
- Automated Secure Patch Generation

### Architecture

```text
Source Code
     |
     v
+-------------------------+
| Vulnerability Detection |
|        Groq LLM         |
+------------+------------+
             |
             v
+-------------------------+
| RAG Security Guidance   |
| Sentence Transformers   |
| + FAISS                 |
+------------+------------+
             |
             v
+-------------------------+
| Agentic Validation      |
| Confirm / FP / Uncertain|
+------------+------------+
             |
             v
+-------------------------+
| Secure Patch Generation |
|        Groq LLM         |
+------------+------------+
             |
             v
+-------------------------+
| Security Report         |
|       Markdown          |
+-------------------------+







# =============================================================
# DEMO STATE
# =============================================================

if (
    "demo_code" in st.session_state
    and not run_review
):

    code = st.session_state.demo_code

    filename = st.session_state.get(
        "demo_filename",
        "demo.py",
    )


# =============================================================
# RUN WORKFLOW
# =============================================================

if run_review:

    if not api_key:

        st.error(
            "Please provide a Groq API key."
        )

        st.stop()

    if not code.strip():

        st.error(
            "Please upload or paste source code."
        )

        st.stop()

    progress = st.progress(
        0,
        text="Initializing ASCR...",
    )

    status = st.empty()

    try:

        status.info(
            "Loading security knowledge base..."
        )

        rag = RAGPipeline()

        workflow = SecurityReviewWorkflow(
            api_key=api_key,
            model=model,
            rag_pipeline=rag,
        )

        progress.progress(
            10,
            text="Stage 1/5 — Detecting vulnerabilities...",
        )

        raw_detection = workflow.detect(
            code=code,
            filename=filename,
        )

        findings = extract_json_findings(
            raw_detection
        )

        progress.progress(
            30,
            text="Stage 2/5 — Retrieving security guidance...",
        )

        findings = workflow.retrieve_context(
            findings
        )

        progress.progress(
            50,
            text="Stage 3/5 — Validating findings...",
        )

        findings = workflow.validate(
            code=code,
            findings=findings,
        )

        progress.progress(
            70,
            text="Stage 4/5 — Generating secure patches...",
        )

        findings = workflow.generate_patches(
            code=code,
            findings=findings,
        )

        progress.progress(
            90,
            text="Stage 5/5 — Generating security report...",
        )

        report = build_markdown_report(
            filename=filename,
            findings=findings,
        )

        progress.progress(
            100,
            text="Security review complete.",
        )

        status.success(
            "ASCR review completed successfully."
        )

        st.session_state.last_findings = findings

        st.session_state.last_report = report

    except Exception as exc:

        progress.empty()

        st.error(
            "The security review failed."
        )

        st.exception(exc)

        st.stop()


# =============================================================
# RESULTS
# =============================================================

findings = st.session_state.last_findings

if findings is not None:

    st.divider()

    st.subheader(
        "📊 Security Assessment"
    )

    confirmed = [
        finding
        for finding in findings
        if finding.get("status") == "confirmed"
    ]

    false_positives = [
        finding
        for finding in findings
        if finding.get("status") == "false_positive"
    ]

    uncertain = [
        finding
        for finding in findings
        if finding.get("status") == "uncertain"
    ]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Candidates",
            len(findings),
        )

    with col2:
        st.metric(
            "Confirmed",
            len(confirmed),
        )

    with col3:
        st.metric(
            "False Positives",
            len(false_positives),
        )

    with col4:
        st.metric(
            "Uncertain",
            len(uncertain),
        )

    if not findings:

        st.success(
            "No credible security vulnerabilities were detected."
        )

    elif not confirmed:

        st.info(
            "No vulnerabilities were confirmed by the validation agent."
        )

    for number, finding in enumerate(
        findings,
        start=1,
    ):

        severity = str(
            finding.get(
                "severity",
                "Unknown",
            )
        ).upper()

        vulnerability = finding.get(
            "vulnerability_type",
            "Security Finding",
        )

        status = finding.get(
            "status",
            "unknown",
        )

        title = (
            f"{severity} | "
            f"{vulnerability} | "
            f"{status.upper()}"
        )

        with st.expander(
            title,
            expanded=(number == 1),
        ):

            st.markdown(
                "### 🔍 Finding Details"
            )

            st.write(
                "**Description:**"
            )

            st.write(
                finding.get(
                    "description",
                    "No description available.",
                )
            )

            col_a, col_b, col_c = st.columns(3)

            with col_a:
                st.write("**Severity**")
                st.write(
                    finding.get(
                        "severity",
                        "Unknown",
                    )
                )

            with col_b:
                st.write("**Confidence**")
                st.write(
                    finding.get(
                        "confidence",
                        "N/A",
                    )
                )

            with col_c:
                st.write("**Lines**")
                st.write(
                    f"{finding.get('line_start', '?')}"
                    f"–"
                    f"{finding.get('line_end', '?')}"
                )

            st.markdown(
                "### 🤖 Agentic Validation"
            )

            st.write(
                "**Status:**",
                status,
            )

            st.write(
                "**Reason:**",
                finding.get(
                    "validation_reason",
                    "Not available.",
                ),
            )

            if status == "confirmed":

                st.markdown(
                    "### 🔧 Original vs Patched Code"
                )

                original_col, patched_col = st.columns(2)

                with original_col:

                    st.markdown(
                        "**🔴 Original**"
                    )

                    st.code(
                        finding.get(
                            "original_code",
                            "",
                        ),
                        language=finding.get(
                            "language",
                            "text",
                        ),
                    )

                with patched_col:

                    st.markdown(
                        "**🟢 Suggested Patch**"
                    )

                    st.code(
                        finding.get(
                            "patched_code",
                            "",
                        ),
                        language=finding.get(
                            "language",
                            "text",
                        ),
                    )

                st.markdown(
                    "### 💡 Why the Patch Works"
                )

                st.write(
                    finding.get(
                        "patch_explanation",
                        "No explanation available.",
                    )
                )

            st.markdown(
                "### 📚 Retrieved Security Guidance"
            )

            contexts = finding.get(
                "rag_context",
                [],
            )

            if contexts:

                for index, context in enumerate(
                    contexts,
                    start=1,
                ):

                    st.info(
                        f"**Context {index}**\n\n"
                        f"{context}"
                    )

            else:

                st.write(
                    "No RAG context retrieved."
                )

            if finding.get(
                "owasp_reference"
            ):

                st.markdown(
                    "### 📖 Security Reference"
                )

                st.write(
                    finding[
                        "owasp_reference"
                    ]
                )

    st.divider()

    st.subheader(
        "📄 Security Report"
    )

    report = st.session_state.last_report

    if report:

        st.download_button(
            label="⬇️ Download Markdown Security Report",
            data=report,
            file_name="ascr_security_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

        with st.expander(
            "Preview Report"
        ):

            st.markdown(
                report
            )
