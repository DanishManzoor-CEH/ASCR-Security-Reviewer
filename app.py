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

    st.subheader(
        "About ASCR"
    )

    st.markdown(
        """
### Agentic Security Code Reviewer

ASCR is an AI-assisted security auditing platform designed
to demonstrate:

- Prompt chaining
- Retrieval-Augmented Generation
- Agentic decision-making
- Secure coding analysis
- LLM-based remediation

### Architecture

```text
Source Code
     │
     ▼
Groq Detection Agent
     │
     ▼
FAISS + Sentence Transformer RAG
     │
     ▼
Validation Agent
     │
     ▼
Patch Agent
     │
     ▼
Security Report
