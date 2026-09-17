"""
rag_pipeline.py
---------------
Knowledge-base layer for the Agentic Security Code Reviewer (ASCR).

Responsibilities:
  1. Load secure-coding documents from ./data (PDF, Markdown, TXT).
  2. Split them into overlapping chunks (recursive character splitter).
  3. Embed chunks with a Sentence-Transformer model.
  4. Index them in FAISS (falls back to a pure-NumPy cosine search when
     faiss is unavailable, which happens on some slim cloud runtimes).
  5. Expose .search(query, k) for the retrieval stage of the workflow.
"""

from __future__ import annotations

import os
import pickle
import re
from dataclasses import dataclass, field
from typing import List, Sequence

import numpy as np

# ----------------------------------------------------------------------------
# Optional heavy dependencies are imported lazily / defensively so that the app
# still boots (with a clear message) if a wheel fails to build on the host.
# ----------------------------------------------------------------------------
try:
    import faiss  # type: ignore

    _HAS_FAISS = True
except Exception:  # pragma: no cover
    faiss = None  # type: ignore
    _HAS_FAISS = False

DEFAULT_EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
INDEX_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache")


# ----------------------------------------------------------------------------
# Document loading
# ----------------------------------------------------------------------------
def _read_pdf(path: str) -> str:
    from pypdf import PdfReader

    reader = PdfReader(path)
    pages = []
    for page in reader.pages:
        try:
            pages.append(page.extract_text() or "")
        except Exception:
            pages.append("")
    return "\n".join(pages)


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def load_documents(data_dir: str = DATA_DIR) -> List[dict]:
    """Return [{'source': filename, 'text': '...'}] for every file in data_dir."""
    docs: List[dict] = []
    if not os.path.isdir(data_dir):
        return docs

    for name in sorted(os.listdir(data_dir)):
        path = os.path.join(data_dir, name)
        if not os.path.isfile(path):
            continue
        lower = name.lower()
        try:
            if lower.endswith(".pdf"):
                text = _read_pdf(path)
            elif lower.endswith((".md", ".txt", ".rst")):
                text = _read_text(path)
            else:
                continue
        except Exception as exc:  # corrupt file should not kill the app
            print(f"[rag] skipped {name}: {exc}")
            continue

        text = _normalise(text)
        if len(text) > 50:
            docs.append({"source": name, "text": text})
    return docs


def _normalise(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ----------------------------------------------------------------------------
# Chunking  (a dependency-free RecursiveCharacterTextSplitter equivalent)
# ----------------------------------------------------------------------------
def recursive_split(
    text: str,
    chunk_size: int = 1000,
    chunk_overlap: int = 200,
    separators: Sequence[str] = ("\n\n", "\n", ". ", " ", ""),
) -> List[str]:
    """Split text, preferring the largest separator that keeps chunks under size."""
    if len(text) <= chunk_size:
        return [text] if text.strip() else []

    sep = separators[-1]
    for candidate in separators:
        if candidate == "":
            sep = ""
            break
        if candidate in text:
            sep = candidate
            break

    pieces = list(text) if sep == "" else text.split(sep)
    joiner = sep

    chunks: List[str] = []
    buffer = ""
    for piece in pieces:
        candidate = piece if not buffer else buffer + joiner + piece
        if len(candidate) <= chunk_size:
            buffer = candidate
            continue

        if buffer:
            chunks.append(buffer)
            # carry overlap forward
            buffer = (buffer[-chunk_overlap:] + joiner + piece) if chunk_overlap else piece
        else:
            buffer = piece

        if len(buffer) > chunk_size:
            remaining = separators[1:] if len(separators) > 1 else ("",)
            chunks.extend(recursive_split(buffer, chunk_size, chunk_overlap, remaining))
            buffer = ""

    if buffer.strip():
        chunks.append(buffer)

    return [c.strip() for c in chunks if c.strip()]


def chunk_documents(docs: List[dict], chunk_size: int = 1000, chunk_overlap: int = 200) -> List[dict]:
    out: List[dict] = []
    for doc in docs:
        for i, chunk in enumerate(recursive_split(doc["text"], chunk_size, chunk_overlap)):
            out.append({"source": doc["source"], "chunk_id": i, "text": chunk})
    return out


# ----------------------------------------------------------------------------
# Knowledge base
# ----------------------------------------------------------------------------
@dataclass
class RetrievedChunk:
    text: str
    source: str
    score: float


@dataclass
class KnowledgeBase:
    embed_model_name: str = DEFAULT_EMBED_MODEL
    chunk_size: int = 1000
    chunk_overlap: int = 200
    chunks: List[dict] = field(default_factory=list)
    _model = None
    _index = None
    _matrix: np.ndarray | None = None

    # -- build -------------------------------------------------------------
    def build(self, data_dir: str = DATA_DIR) -> "KnowledgeBase":
        docs = load_documents(data_dir)
        if not docs:
            raise FileNotFoundError(
                f"No knowledge-base documents found in {data_dir}. "
                "Add an OWASP PDF or keep the bundled owasp_guidelines.md."
            )
        self.chunks = chunk_documents(docs, self.chunk_size, self.chunk_overlap)
        embeddings = self._embed([c["text"] for c in self.chunks])
        self._install(embeddings)
        return self

    def _embed(self, texts: List[str]) -> np.ndarray:
        model = self._get_model()
        vectors = model.encode(
            texts,
            batch_size=32,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(vectors, dtype="float32")

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.embed_model_name)
        return self._model

    def _install(self, embeddings: np.ndarray) -> None:
        self._matrix = embeddings
        if _HAS_FAISS:
            index = faiss.IndexFlatIP(embeddings.shape[1])  # vectors are L2-normalised
            index.add(embeddings)
            self._index = index
        else:
            self._index = None

    # -- query -------------------------------------------------------------
    def search(self, query: str, k: int = 4) -> List[RetrievedChunk]:
        if not self.chunks:
            return []
        q = self._embed([query])
        if self._index is not None:
            scores, idxs = self._index.search(q, min(k, len(self.chunks)))
            pairs = zip(idxs[0].tolist(), scores[0].tolist())
        else:
            sims = (self._matrix @ q[0]).astype(float)
            top = np.argsort(-sims)[: min(k, len(self.chunks))]
            pairs = ((int(i), float(sims[i])) for i in top)

        results: List[RetrievedChunk] = []
        for idx, score in pairs:
            if idx < 0:
                continue
            chunk = self.chunks[idx]
            results.append(RetrievedChunk(text=chunk["text"], source=chunk["source"], score=float(score)))
        return results

    # -- persistence -------------------------------------------------------
    def save(self, path: str = INDEX_DIR) -> None:
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "chunks.pkl"), "wb") as fh:
            pickle.dump({"chunks": self.chunks, "model": self.embed_model_name}, fh)
        np.save(os.path.join(path, "embeddings.npy"), self._matrix)

    @classmethod
    def load(cls, path: str = INDEX_DIR) -> "KnowledgeBase | None":
        meta_path = os.path.join(path, "chunks.pkl")
        vec_path = os.path.join(path, "embeddings.npy")
        if not (os.path.exists(meta_path) and os.path.exists(vec_path)):
            return None
        with open(meta_path, "rb") as fh:
            meta = pickle.load(fh)
        kb = cls(embed_model_name=meta.get("model", DEFAULT_EMBED_MODEL))
        kb.chunks = meta["chunks"]
        kb._install(np.load(vec_path))
        return kb

    # -- info --------------------------------------------------------------
    @property
    def backend(self) -> str:
        return "FAISS (IndexFlatIP)" if self._index is not None else "NumPy cosine (FAISS unavailable)"

    @property
    def sources(self) -> List[str]:
        return sorted({c["source"] for c in self.chunks})


# ----------------------------------------------------------------------------
# Source-code chunking (functional, not character based) — Challenge 1 mitigation
# ----------------------------------------------------------------------------
_BLOCK_STARTERS = re.compile(
    r"^(?:\s*)(?:def |class |async def |func |function |public |private |protected |static |"
    r"const |var |let |int |void |char |struct |type |impl |module )",
)


def chunk_source_code(code: str, max_lines: int = 220) -> List[dict]:
    """
    Split code into logical units (functions / classes) so large files stay
    inside the model context window. Returns [{'name', 'start_line', 'code'}].
    """
    lines = code.splitlines()
    if len(lines) <= max_lines:
        return [{"name": "whole_file", "start_line": 1, "code": code}]

    boundaries: List[int] = []
    for i, line in enumerate(lines):
        if _BLOCK_STARTERS.match(line) and len(line) - len(line.lstrip()) <= 4:
            boundaries.append(i)

    if not boundaries:
        return [
            {"name": f"lines_{i + 1}", "start_line": i + 1, "code": "\n".join(lines[i : i + max_lines])}
            for i in range(0, len(lines), max_lines)
        ]

    if boundaries[0] != 0:
        boundaries.insert(0, 0)
    boundaries.append(len(lines))

    blocks: List[dict] = []
    start = boundaries[0]
    for nxt in boundaries[1:]:
        if nxt - start == 0:
            continue
        if nxt - start > max_lines * 2:  # runaway block, hard-split it
            for i in range(start, nxt, max_lines):
                blocks.append(
                    {
                        "name": _block_name(lines[i]) or f"lines_{i + 1}",
                        "start_line": i + 1,
                        "code": "\n".join(lines[i : i + max_lines]),
                    }
                )
            start = nxt
            continue

        chunk_lines = lines[start:nxt]
        if len("\n".join(chunk_lines).strip()):
            blocks.append(
                {
                    "name": _block_name(lines[start]) or f"lines_{start + 1}",
                    "start_line": start + 1,
                    "code": "\n".join(chunk_lines),
                }
            )
        start = nxt

    # merge tiny neighbouring blocks to reduce API round-trips
    merged: List[dict] = []
    for block in blocks:
        if merged and len(merged[-1]["code"].splitlines()) + len(block["code"].splitlines()) < max_lines:
            merged[-1]["code"] += "\n" + block["code"]
            merged[-1]["name"] += f" + {block['name']}"
        else:
            merged.append(block)
    return merged


def _block_name(line: str) -> str:
    match = re.search(r"(?:def|class|func|function)\s+([A-Za-z_][\w]*)", line)
    return match.group(1) if match else ""


LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".sql": "sql",
    ".sh": "bash",
    ".yml": "yaml",
    ".yaml": "yaml",
}


def detect_language(filename: str, default: str = "python") -> str:
    _, ext = os.path.splitext(filename.lower())
    return LANGUAGE_BY_EXTENSION.get(ext, default)
