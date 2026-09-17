import os

import streamlit as st

from utils.rag_pipeline import RAGPipeline
from utils.workflow_chains import (
    SecurityReviewWorkflow,
    extract_json_findings,
)
from utils.report_generator import build_markdown_report


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="ASCR - Agentic Security Code Reviewer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM CSS
# ============================================================

CUSTOM_CSS = (
    "<style>"
    ".main-title {"
    "font-size: 42px;"
    "font-weight: 800;"
    "margin-bottom: 0;"
    "}"
    ".subtitle {"
    "font-size: 18px;"
    "opacity: 0.75;"
    "margin-bottom: 25px;"
    "}"
    "</style>"
)

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ============================================================
# SESSION STATE
# ============================================================

if "last_findings" not in st.session_state:
    st.session_state.last_findings = None

if "last_report" not in st.session_state:
    st.session_state.last_report = None

if "demo_code" not in st.session_state:
    st.session_state.demo_code = ""

if "demo_filename" not in st.session_state:
    st.session_state.demo_filename = "demo.py"


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ Agentic Security Code Reviewer</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">Analyze → Retrieve → Validate → Patch → Report</div>',
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("⚙️ Configuration")

    environment_key = os.getenv("GROQ_API_KEY", "")

    try:
        secrets_key = st.secrets.get("GROQ_API_KEY", "")
    except Exception:
        secrets_key = ""

    default_api_key = environment_key or secrets_key

    api_key = st.text_input(
        "Groq API Key",
        value=default_api_key,
        type="password",
        help="Enter your Groq API key. Never commit it to GitHub.",
    )

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

    st.write("1️⃣ Vulnerability Detection")
    st.write("2️⃣ RAG Security Retrieval")
    st.write("3️⃣ Agentic Validation")
    st.write("4️⃣ Secure Patch Generation")
    st.write("5️⃣ Markdown Report")

    st.divider()

    st.success("RAG Knowledge Base: Ready")

    st.caption(
        "Groq + Streamlit + Sentence Transformers + FAISS"
    )


# ============================================================
# TABS
# ============================================================

review_tab, demo_tab, about_tab = st.tabs(
    [
        "🔎 Security Review",
        "🧪 Demo",
        "ℹ️ About",
    ]
)


# ============================================================
# SECURITY REVIEW TAB
# ============================================================

with review_tab:

    st.subheader("💻 Source Code Input")

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
        "Or paste your source code",
        height=350,
        placeholder="Paste source code here...",
    )

    filename = "pasted_code.txt"
    code = pasted_code

    if uploaded_file is not None:

        filename = uploaded_file.name

        try:

            code = uploaded_file.read().decode(
                "utf-8",
                errors="replace",
            )

        except Exception as exc:

            st.error(
                f"Could not read uploaded file: {exc}"
            )

    if st.session_state.demo_code:

        if not uploaded_file and not pasted_code:

            code = st.session_state.demo_code
            filename = st.session_state.demo_filename

            st.info(
                f"Demo code loaded: `{filename}`"
            )

    st.caption(
        f"Current file: `{filename}`"
    )

    run_review = st.button(
        "🚀 Run Agentic Security Review",
        type="primary",
        use_container_width=True,
    )


# ============================================================
# DEMO TAB
# ============================================================

with demo_tab:

    st.subheader("🧪 Vulnerable Demo Code")

    st.write(
        "Use this intentionally vulnerable code to test ASCR."
    )

    demo_code = (
        'import sqlite3\n'
        '\n'
        'API_KEY = "sk-demo-secret"\n'
        '\n'
        'def search_user(name):\n'
        '    conn = sqlite3.connect("app.db")\n'
        '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        '    return conn.execute(query).fetchall()\n'
    )

    st.code(
        demo_code,
        language="python",
    )

    if st.button(
        "📥 Load Demo Code",
        use_container_width=True,
    ):

        st.session_state.demo_code = demo_code
        st.session_state.demo_filename = "demo.py"

        st.success(
            "Demo code loaded. Open the Security Review tab and run the review."
        )


# ============================================================
# ABOUT TAB
# ============================================================

with about_tab:

    st.subheader("ℹ️ About ASCR")

    st.write(
        "Agentic Security Code Reviewer is an AI-assisted "
        "source-code security analysis platform."
    )

    st.markdown("### 🎯 Project Goals")

    st.write(
        "ASCR demonstrates Prompt Chaining, Retrieval-Augmented "
        "Generation, Agentic Validation, and AI-assisted remediation."
    )

    st.markdown("### 🧠 Technologies")

    st.write(
        "• Groq API\n"
        "• Streamlit\n"
        "• Sentence Transformers\n"
        "• FAISS\n"
        "• Python\n"
        "• RAG\n"
        "• Agentic AI"
    )

    st.markdown("### 🔄 Workflow")

    architecture_text = (
        "Source Code\n"
        "    ↓\n"
        "Groq Vulnerability Detection\n"
        "    ↓\n"
        "FAISS + Sentence Transformer RAG\n"
        "    ↓\n"
        "Agentic Validation\n"
        "    ↓\n"
        "Secure Patch Generation\n"
        "    ↓\n"
        "Security Report"
    )

    st.code(
        architecture_text,
        language="text",
    )

    st.warning(
        "AI-generated security findings and patches must be "
        "manually reviewed and tested before production use."
    )


# ============================================================
# RUN REVIEW
# ============================================================

if run_review:

    # --------------------------------------------------------
    # API KEY VALIDATION
    # --------------------------------------------------------

    if not api_key:

        st.error(
            "❌ Groq API key is missing."
        )

        st.info(
            "Add GROQ_API_KEY in Streamlit Secrets or enter "
            "your key in the sidebar."
        )

        st.stop()

    # --------------------------------------------------------
    # CODE VALIDATION
    # --------------------------------------------------------

    if not code or not code.strip():

        st.error(
            "❌ Please upload a source-code file or paste code."
        )

        st.stop()

    # --------------------------------------------------------
    # PROGRESS
    # --------------------------------------------------------

    progress = st.progress(
        0,
        text="Initializing ASCR...",
    )

    status_box = st.empty()

    try:

        # ====================================================
        # INITIALIZE RAG
        # ====================================================

        status_box.info(
            "📚 Loading security knowledge base..."
        )

        rag = RAGPipeline()

        workflow = SecurityReviewWorkflow(
            api_key=api_key,
            model=model,
            rag_pipeline=rag,
        )

        # ====================================================
        # STAGE 1
        # ====================================================

        progress.progress(
            10,
            text="Stage 1/5 — Vulnerability Detection",
        )

        status_box.info(
            "🔍 Groq is analyzing the source code..."
        )

        raw_detection = workflow.detect(
            code=code,
            filename=filename,
        )

        findings = extract_json_findings(
            raw_detection
        )

        # ====================================================
        # STAGE 2
        # ====================================================

        progress.progress(
            30,
            text="Stage 2/5 — RAG Security Retrieval",
        )

        status_box.info(
            "📚 Retrieving relevant secure-coding guidance..."
        )

        findings = workflow.retrieve_context(
            findings
        )

        # ====================================================
        # STAGE 3
        # ====================================================

        progress.progress(
            50,
            text="Stage 3/5 — Agentic Validation",
        )

        status_box.info(
            "🤖 Validation agent is checking findings..."
        )

        findings = workflow.validate(
            code=code,
            findings=findings,
        )

        # ====================================================
        # STAGE 4
        # ====================================================

        progress.progress(
            70,
            text="Stage 4/5 — Secure Patch Generation",
        )

        status_box.info(
            "🔧 Generating remediation patches..."
        )

        findings = workflow.generate_patches(
            code=code,
            findings=findings,
        )

        # ====================================================
        # STAGE 5
        # ====================================================

        progress.progress(
            90,
            text="Stage 5/5 — Report Generation",
        )

        status_box.info(
            "📄 Creating security assessment report..."
        )

        report = build_markdown_report(
            filename=filename,
            findings=findings,
        )

        # ====================================================
        # COMPLETE
        # ====================================================

        progress.progress(
            100,
            text="ASCR review completed!",
        )

        status_box.success(
            "✅ Security review completed successfully."
        )

        st.session_state.last_findings = findings
        st.session_state.last_report = report

    except Exception as exc:

        progress.empty()

        status_box.error(
            "❌ The security review failed."
        )

        st.error(
            f"Error: {exc}"
        )

        st.exception(exc)

        st.stop()


# ============================================================
# RESULTS
# ============================================================

findings = st.session_state.last_findings


if findings is not None:

    st.divider()

    st.header("📊 Security Assessment")

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

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # CLEAN CODE
    # --------------------------------------------------------

    if not findings:

        st.success(
            "✅ No credible security vulnerabilities were detected."
        )

    elif not confirmed:

        st.info(
            "ℹ️ No vulnerabilities were confirmed by the validation agent."
        )

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

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

        validation_status = finding.get(
            "status",
            "unknown",
        )

        title = (
            f"{severity} | "
            f"{vulnerability} | "
            f"{validation_status.upper()}"
        )

        with st.expander(
            title,
            expanded=(number == 1),
        ):

            # ------------------------------------------------
            # DETAILS
            # ------------------------------------------------

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

            detail_col1, detail_col2, detail_col3 = (
                st.columns(3)
            )

            with detail_col1:

                st.write("**Severity**")

                st.write(
                    finding.get(
                        "severity",
                        "Unknown",
                    )
                )

            with detail_col2:

                st.write("**Confidence**")

                st.write(
                    finding.get(
                        "confidence",
                        "N/A",
                    )
                )

            with detail_col3:

                st.write("**Lines**")

                st.write(
                    f"{finding.get('line_start', '?')}"
                    f" – "
                    f"{finding.get('line_end', '?')}"
                )

            # ------------------------------------------------
            # VALIDATION
            # ------------------------------------------------

            st.markdown(
                "### 🤖 Agentic Validation"
            )

            st.write(
                "**Validation Status:**",
                validation_status,
            )

            st.write(
                "**Validation Reason:**",
                finding.get(
                    "validation_reason",
                    "No validation explanation available.",
                ),
            )

            # ------------------------------------------------
            # PATCH
            # ------------------------------------------------

            if validation_status == "confirmed":

                st.markdown(
                    "### 🔧 Original vs Suggested Patch"
                )

                original_col, patched_col = (
                    st.columns(2)
                )

                with original_col:

                    st.markdown(
                        "#### 🔴 Original Code"
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
                        "#### 🟢 Suggested Patch"
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
                    "### 💡 Patch Explanation"
                )

                st.write(
                    finding.get(
                        "patch_explanation",
                        "No patch explanation available.",
                    )
                )

            # ------------------------------------------------
            # RAG CONTEXT
            # ------------------------------------------------

            st.markdown(
                "### 📚 Retrieved Security Guidance"
            )

            contexts = finding.get(
                "rag_context",
                [],
            )

            if contexts:

                for context_number, context in enumerate(
                    contexts,
                    start=1,
                ):

                    st.info(
                        f"Context {context_number}\n\n"
                        f"{context}"
                    )

            else:

                st.write(
                    "No RAG context was retrieved."
                )

            # ------------------------------------------------
            # SECURITY REFERENCE
            # ------------------------------------------------

            reference = finding.get(
                "owasp_reference",
                "",
            )

            if reference:

                st.markdown(
                    "### 📖 Security Reference"
                )

                st.write(
                    reference
                )


# ============================================================
# SECURITY REPORT
# ============================================================

if st.session_state.last_report is not None:

    st.divider()

    st.header("📄 Security Report")

    report = st.session_state.last_report

    st.download_button(
        label="⬇️ Download Markdown Security Report",
        data=report,
        file_name="ascr_security_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

    with st.expander(
        "👁️ Preview Generated Report"
    ):

        st.markdown(
            report
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "ASCR — Agentic Security Code Reviewer | "
    "AI-assisted defensive security analysis"
)
