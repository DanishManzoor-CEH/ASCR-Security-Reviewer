"""
ASCR — Agentic Security Code Reviewer
=====================================
Streamlit front-end for a RAG-grounded, prompt-chained security auditing agent.

Run locally:   streamlit run app.py
Deploy:        Streamlit Community Cloud + GROQ_API_KEY in app secrets.
"""

from __future__ import annotations

import os
import traceback

import streamlit as st

from utils.rag_pipeline import DATA_DIR, KnowledgeBase, detect_language
from utils.report_export import markdown_to_html, markdown_to_pdf_bytes
from utils.workflow_chains import AVAILABLE_MODELS, LLM, run_pipeline

# ---------------------------------------------------------------------------
# Page config & styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ASCR — Agentic Security Code Reviewer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container { padding-top: 2.2rem; max-width: 1280px; }
      .ascr-title { font-size: 2rem; font-weight: 700; letter-spacing: -0.02em; margin-bottom: .1rem; }
      .ascr-sub { color: #6b7280; margin-bottom: 1.4rem; font-size: .95rem; }
      .badge { display:inline-block; padding: 2px 10px; border-radius: 999px;
               font-size: .72rem; font-weight: 700; letter-spacing:.03em; text-transform: uppercase; }
      .sev-critical { background:#7f1d1d; color:#fff; }
      .sev-high     { background:#b91c1c; color:#fff; }
      .sev-medium   { background:#b45309; color:#fff; }
      .sev-low      { background:#1d4ed8; color:#fff; }
      .sev-info     { background:#374151; color:#fff; }
      .pill { display:inline-block; background:#eef2f7; color:#334155; border-radius:6px;
              padding:2px 8px; font-size:.75rem; margin-right:6px; }
      .stage-box { border:1px solid #e5e7eb; border-radius:10px; padding:10px 14px; background:#fafafa; }
    </style>
    """,
    unsafe_allow_html=True,
)

SEV_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}

SAMPLE_CODE = '''import sqlite3, os, pickle, hashlib

DB_PASSWORD = "SuperSecret123!"          # credentials in source
API_TOKEN = "sk_live_9a8b7c6d5e4f3g2h"

def get_user(conn, username):
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def load_profile(blob):
    return pickle.loads(blob)

def run_report(report_name):
    os.system("python reports/" + report_name + ".py")

def read_file(path):
    with open("/var/data/" + path) as fh:
        return fh.read()
'''


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
def _init_state() -> None:
    defaults = {
        "result": None,
        "error": None,
        "kb_built": False,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


_init_state()


# ---------------------------------------------------------------------------
# Cached resources
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def build_knowledge_base(chunk_size: int, chunk_overlap: int) -> KnowledgeBase:
    kb = KnowledgeBase(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    kb.build(DATA_DIR)
    return kb


def resolve_api_key(sidebar_value: str) -> str:
    if sidebar_value:
        return sidebar_value.strip()
    try:
        if "GROQ_API_KEY" in st.secrets:
            return str(st.secrets["GROQ_API_KEY"]).strip()
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY", "").strip()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Configuration")

    api_key_input = st.text_input(
        "Groq API key",
        type="password",
        placeholder="gsk_...",
        help="Get a free key at console.groq.com. Leave blank to use st.secrets or the GROQ_API_KEY env var.",
    )
    api_key = resolve_api_key(api_key_input)
    st.caption("🔑 Key detected" if api_key else "⚠️ No key found yet")

    model = st.selectbox("Analysis model", AVAILABLE_MODELS, index=0)
    temperature = st.slider("Temperature", 0.0, 1.0, 0.1, 0.05,
                            help="Keep low — security analysis wants determinism.")

    st.markdown("---")
    st.markdown("### 📚 Knowledge base")
    chunk_size = st.number_input("Chunk size", 300, 3000, 1000, 100)
    chunk_overlap = st.number_input("Chunk overlap", 0, 800, 200, 50)
    top_k = st.slider("Chunks retrieved per finding", 1, 8, 4)

    kb = None
    kb_error = None
    try:
        with st.spinner("Loading vector index…"):
            kb = build_knowledge_base(int(chunk_size), int(chunk_overlap))
    except Exception as exc:
        kb_error = str(exc)

    if kb is not None:
        st.success(f"Indexed {len(kb.chunks)} chunks")
        st.caption(f"Backend: {kb.backend}")
        with st.expander("Sources"):
            for src in kb.sources:
                st.write(f"• {src}")
    else:
        st.error("Vector store unavailable")
        st.caption(kb_error or "")

    if st.button("🔄 Rebuild index", use_container_width=True):
        build_knowledge_base.clear()
        st.rerun()

    st.markdown("---")
    drop_fp = st.toggle("Drop false positives from report", value=True,
                        help="The agentic evaluation node decides. Turn off to see everything it rejected inline.")

    st.markdown("---")
    st.caption("ASCR · Prompt chaining + RAG + agentic verification")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown('<div class="ascr-title">🛡️ Agentic Security Code Reviewer</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="ascr-sub">Detect → Retrieve (RAG) → Verify &amp; Patch → Report. '
    'Findings are grounded in a local secure-coding knowledge base, not model memory.</div>',
    unsafe_allow_html=True,
)

tab_analyze, tab_report, tab_pipeline, tab_about = st.tabs(
    ["🔍 Analyze", "📄 Report", "🧩 Pipeline trace", "ℹ️ About"]
)

# ---------------------------------------------------------------------------
# Analyze tab
# ---------------------------------------------------------------------------
with tab_analyze:
    left, right = st.columns([3, 2], gap="large")

    with left:
        source = st.radio("Input", ["Paste code", "Upload file", "Load sample"],
                          horizontal=True, label_visibility="collapsed")

        code, filename = "", "snippet.py"

        if source == "Upload file":
            uploaded = st.file_uploader(
                "Source file",
                type=["py", "js", "jsx", "ts", "tsx", "java", "c", "h", "cpp", "cs",
                      "go", "rb", "php", "rs", "sql", "sh", "yml", "yaml", "txt"],
            )
            if uploaded is not None:
                code = uploaded.read().decode("utf-8", errors="ignore")
                filename = uploaded.name
                st.code(code[:4000] + ("\n… (truncated preview)" if len(code) > 4000 else ""),
                        language=detect_language(filename))
        elif source == "Load sample":
            filename = "vulnerable_sample.py"
            code = st.text_area("Sample code", value=SAMPLE_CODE, height=380)
        else:
            filename = st.text_input("File name (drives language detection)", value="snippet.py")
            code = st.text_area("Paste source code", height=380, placeholder="def login(user, pwd): …")

    with right:
        language = detect_language(filename)
        st.markdown("#### Run")
        st.markdown(
            f'<span class="pill">file: {filename or "—"}</span>'
            f'<span class="pill">lang: {language}</span>'
            f'<span class="pill">lines: {len(code.splitlines())}</span>',
            unsafe_allow_html=True,
        )
        st.write("")
        run = st.button("▶️ Run security review", type="primary", use_container_width=True,
                        disabled=not (code.strip() and api_key and kb is not None))

        if not api_key:
            st.info("Add a Groq API key in the sidebar to enable the run button.")
        elif kb is None:
            st.warning("Knowledge base failed to load — see the sidebar.")
        elif not code.strip():
            st.info("Provide some source code to review.")

        st.markdown("#### Workflow")
        st.markdown(
            '<div class="stage-box">'
            "1️⃣ Vulnerability detection<br>"
            "2️⃣ Policy retrieval (FAISS)<br>"
            "3️⃣ Verification &amp; remediation<br>"
            "4️⃣ Report synthesis"
            "</div>",
            unsafe_allow_html=True,
        )

    if run:
        st.session_state.result = None
        st.session_state.error = None
        progress_bar = st.progress(0.0)
        status = st.empty()

        def on_progress(pct: float, msg: str) -> None:
            progress_bar.progress(pct)
            status.markdown(f"`{int(pct * 100):>3}%` {msg}")

        try:
            llm = LLM(api_key=api_key, model=model, temperature=temperature)
            st.session_state.result = run_pipeline(
                llm=llm,
                kb=kb,
                code=code,
                filename=filename or "snippet",
                language=language,
                top_k=int(top_k),
                drop_false_positives=drop_fp,
                progress=on_progress,
            )
            status.success("Review complete.")
        except Exception as exc:
            st.session_state.error = f"{exc}\n\n{traceback.format_exc()}"
            status.empty()
            progress_bar.empty()

    if st.session_state.error:
        st.error("The pipeline failed.")
        with st.expander("Traceback"):
            st.code(st.session_state.error)

    result = st.session_state.result
    if result:
        findings = result["findings"]
        rejected = result["rejected"]

        st.markdown("---")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Confirmed", len(findings))
        c2.metric("Critical / High", sum(1 for f in findings if f.severity.lower() in ("critical", "high")))
        c3.metric("False positives filtered", len(rejected))
        c4.metric("Code units scanned", len(result["blocks"]))

        if not findings:
            st.success("No exploitable weaknesses were confirmed in this code.")

        for i, f in enumerate(findings, 1):
            badge = SEV_CLASS.get(f.severity.lower(), "sev-info")
            with st.expander(f"{i}. {f.title}  ·  {f.severity}  ·  lines {f.line_start}–{f.line_end}", expanded=i == 1):
                st.markdown(
                    f'<span class="badge {badge}">{f.severity}</span> '
                    f'<span class="pill">{f.vulnerability_type}</span>'
                    f'<span class="pill">{f.cwe or "CWE n/a"}</span>'
                    f'<span class="pill">{f.owasp or "OWASP n/a"}</span>'
                    f'<span class="pill">confidence {f.confidence:.0%}</span>',
                    unsafe_allow_html=True,
                )
                st.write("")
                st.markdown(f.description or "_No description returned._")

                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Original**")
                    st.code(f.vulnerable_snippet or "(snippet unavailable)", language=result["language"])
                with col_b:
                    st.markdown("**Patched**")
                    if f.patched_snippet:
                        st.code(f.patched_snippet, language=result["language"])
                    else:
                        st.info("No patch generated.")

                if f.fix_explanation:
                    st.markdown("**Why the fix works**")
                    st.markdown(f.fix_explanation)
                if f.verdict_reason:
                    st.markdown(f"**Verification verdict:** {f.verdict_reason}")
                if f.logic_preserved is not None:
                    st.caption("✅ Logic preservation check passed" if f.logic_preserved
                               else "⚠️ Logic preservation needs manual confirmation")

                if f.retrieved_context:
                    with st.expander("📚 Retrieved secure-coding context"):
                        for c in f.retrieved_context:
                            st.markdown(f"**{c['source']}** · similarity `{c['score']}`")
                            st.caption(c["text"][:900] + ("…" if len(c["text"]) > 900 else ""))

        if rejected:
            with st.expander(f"🧪 {len(rejected)} candidate(s) rejected by the agentic verifier"):
                for f in rejected:
                    st.markdown(f"- **{f.title}** ({f.vulnerability_type}) — {f.verdict_reason or 'not corroborated'}")

# ---------------------------------------------------------------------------
# Report tab
# ---------------------------------------------------------------------------
with tab_report:
    result = st.session_state.result
    if not result:
        st.info("Run a review first — the generated report will appear here.")
    else:
        md = result["report_markdown"]
        base = os.path.splitext(os.path.basename(result["filename"]))[0] or "report"

        d1, d2, d3 = st.columns(3)
        d1.download_button("⬇️ Markdown", md, file_name=f"{base}_security_report.md",
                           mime="text/markdown", use_container_width=True)
        d2.download_button("⬇️ HTML (print → PDF)",
                           markdown_to_html(md, f"ASCR report — {result['filename']}"),
                           file_name=f"{base}_security_report.html",
                           mime="text/html", use_container_width=True)

        pdf_bytes = markdown_to_pdf_bytes(md, f"ASCR report — {result['filename']}")
        if pdf_bytes:
            d3.download_button("⬇️ PDF", pdf_bytes, file_name=f"{base}_security_report.pdf",
                               mime="application/pdf", use_container_width=True)
        else:
            d3.caption("Install `reportlab` for direct PDF export.")

        st.markdown("---")
        st.markdown(md)

# ---------------------------------------------------------------------------
# Pipeline trace tab
# ---------------------------------------------------------------------------
with tab_pipeline:
    result = st.session_state.result
    if not result:
        st.info("Intermediate artifacts from each chain stage show up here after a run.")
    else:
        st.markdown("#### Stage 1 — code units submitted for detection")
        for block in result["blocks"]:
            st.markdown(f"- `{block['name']}` starting at line {block['start_line']} "
                        f"({len(block['code'].splitlines())} lines)")

        st.markdown("#### Stage 1 output — raw candidates")
        st.json([
            {
                "title": f.title,
                "type": f.vulnerability_type,
                "severity": f.severity,
                "lines": f"{f.line_start}-{f.line_end}",
            }
            for f in result["candidates"]
        ])

        st.markdown("#### Stage 2 output — retrieval per candidate")
        st.json({
            f.title: [{"source": c["source"], "score": c["score"]} for c in f.retrieved_context]
            for f in result["candidates"]
        })

        st.markdown("#### Stage 3 output — verification verdicts")
        st.json([
            {
                "title": f.title,
                "true_positive": f.is_true_positive,
                "confidence": f.confidence,
                "reason": f.verdict_reason,
                "patched": bool(f.patched_snippet),
            }
            for f in result["candidates"]
        ])

# ---------------------------------------------------------------------------
# About tab
# ---------------------------------------------------------------------------
with tab_about:
    st.markdown(
        """
### What this is

ASCR routes source code through a **four-stage prompt chain** instead of one fragile mega-prompt.
Each stage emits an inspectable artifact, and every claim the model makes is checked against a
local vector index of secure-coding guidance before it reaches the report.

| Stage | Purpose | Technology |
| --- | --- | --- |
| 1. Detection | Structured static analysis returning JSON findings | Groq LLM |
| 2. Retrieval | Pull matching remediation policy per vulnerability type | Sentence-Transformers + FAISS |
| 3. Verify & patch | Agentic true/false-positive judgement, then generate a fix | Groq LLM + retrieved policy |
| 4. Report | Aggregate into Markdown / HTML / PDF | Local synthesis |

### Design decisions worth defending in a viva

- **Functional code chunking.** Large files are split by function and class boundaries, not raw
  characters, so a vulnerability is never cut in half by the context window.
- **Agentic false-positive filter.** Stage 3 can reject a Stage 1 claim outright. Rejections are
  kept and listed, so the pipeline is auditable rather than silently lossy.
- **Grounded, not remembered.** Remediation advice is conditioned on retrieved policy text, which
  is what stops the model from inventing plausible-sounding but wrong guidance.
- **Graceful degradation.** If `faiss` is unavailable on the host, retrieval falls back to NumPy
  cosine similarity over the same embeddings.

### Limitations

Static, single-file, LLM-driven review. It does not perform taint tracking across modules, cannot
confirm reachability, and its patches must be reviewed by a human before merge.
        """
    )
