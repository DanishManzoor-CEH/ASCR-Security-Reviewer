"""
RAG pipeline for ASCR.

Responsibilities:
1. Load local security guidance.
2. Split knowledge into chunks.
3. Generate Sentence Transformer embeddings.
4. Store embeddings in FAISS.
5. Perform semantic retrieval.
"""

from pathlib import Path
import re

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"


class RAGPipeline:
    """
    Local Retrieval-Augmented Generation pipeline.

    Uses:
        Sentence Transformers -> embeddings
        FAISS -> vector similarity search
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ):
        self.model_name = model_name
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

        self.embedding_model = SentenceTransformer(model_name)

        self.documents = self._load_documents()

        if not self.documents:
            raise ValueError(
                "No security knowledge was found in the data directory."
            )

        self.index = self._build_index()

    # ---------------------------------------------------------
    # DOCUMENT LOADING
    # ---------------------------------------------------------

    def _load_documents(self):
        """
        Load the local security knowledge base.

        Priority:
        1. data/owasp_guidelines.txt
        2. PDF files inside data/
        """

        text_file = DATA_DIR / "owasp_guidelines.txt"

        if text_file.exists():
            text = text_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            return self._chunk_text(text)

        pdf_files = list(DATA_DIR.glob("*.pdf"))

        if pdf_files:
            return self._load_pdf_documents(pdf_files)

        return []

    def _load_pdf_documents(self, pdf_files):
        """
        Extract text from PDF files using pypdf.
        """

        try:
            from pypdf import PdfReader
        except ImportError:
            return []

        full_text = []

        for pdf_file in pdf_files:

            try:
                reader = PdfReader(str(pdf_file))

                for page in reader.pages:
                    page_text = page.extract_text()

                    if page_text:
                        full_text.append(page_text)

            except Exception:
                continue

        combined_text = "\n".join(full_text)

        return self._chunk_text(combined_text)

    # ---------------------------------------------------------
    # CHUNKING
    # ---------------------------------------------------------

    def _chunk_text(self, text: str):
        """
        Split text into overlapping chunks.

        Example:
            chunk_size = 1000
            overlap = 200
        """

        text = re.sub(r"\s+", " ", text).strip()

        if not text:
            return []

        chunks = []

        start = 0
        text_length = len(text)

        while start < text_length:

            end = min(
                start + self.chunk_size,
                text_length,
            )

            chunk = text[start:end].strip()

            if chunk:
                chunks.append(chunk)

            if end >= text_length:
                break

            start = end - self.chunk_overlap

        return chunks

    # ---------------------------------------------------------
    # VECTOR INDEX
    # ---------------------------------------------------------

    def _build_index(self):
        """
        Generate embeddings and build a FAISS index.
        """

        embeddings = self.embedding_model.encode(
            self.documents,
            normalize_embeddings=True,
            show_progress_bar=False,
        )

        embeddings = np.asarray(
            embeddings,
            dtype="float32",
        )

        dimension = embeddings.shape[1]

        index = faiss.IndexFlatIP(dimension)

        index.add(embeddings)

        return index

    # ---------------------------------------------------------
    # SEARCH
    # ---------------------------------------------------------

    def search(
        self,
        query: str,
        top_k: int = 4,
    ):
        """
        Retrieve the most relevant security guidance.

        Returns:
            list of dictionaries containing:
                text
                score
        """

        if not query.strip():
            return []

        query_embedding = self.embedding_model.encode(
            [query],
            normalize_embeddings=True,
            show_progress_bar=False,
        )

        query_embedding = np.asarray(
            query_embedding,
            dtype="float32",
        )

        top_k = min(
            top_k,
            len(self.documents),
        )

        scores, indices = self.index.search(
            query_embedding,
            top_k,
        )

        results = []

        for score, index in zip(
            scores[0],
            indices[0],
        ):

            if index < 0:
                continue

            results.append(
                {
                    "text": self.documents[int(index)],
                    "score": float(score),
                }
            )

        return results
