import os
from pathlib import Path
from typing import List, Dict, Any

import faiss
import numpy as np
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer


class RAGPipeline:

    def __init__(
        self,
        data_directory: str = "data",
        embedding_model: str = "all-MiniLM-L6-v2",
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ):

        self.data_directory = Path(
            data_directory
        )

        self.embedding_model_name = (
            embedding_model
        )

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

        self.documents: List[str] = []

        self.metadata: List[Dict[str, Any]] = []

        self.index = None

        self.embedding_model = None

        self._build_index()

    # ========================================================
    # BUILD INDEX
    # ========================================================

    def _build_index(self):

        pdf_files = list(
            self.data_directory.glob(
                "*.pdf"
            )
        )

        if not pdf_files:

            self.documents = [
                (
                    "OWASP secure coding guidance: "
                    "validate and sanitize untrusted input, "
                    "use parameterized database queries, "
                    "protect authentication credentials, "
                    "avoid hardcoded secrets, apply least "
                    "privilege, encode output appropriately, "
                    "and handle errors securely."
                ),
                (
                    "SQL injection prevention: use "
                    "parameterized queries or prepared "
                    "statements instead of constructing SQL "
                    "commands by concatenating untrusted input."
                ),
                (
                    "Hardcoded credential prevention: secrets "
                    "should not be embedded directly in source "
                    "code. Use environment variables or a "
                    "dedicated secrets-management mechanism."
                ),
            ]

            self.metadata = [
                {
                    "source": "Built-in security guidance",
                    "page": 0,
                },
                {
                    "source": "Built-in security guidance",
                    "page": 0,
                },
                {
                    "source": "Built-in security guidance",
                    "page": 0,
                },
            ]

        else:

            pdf_path = pdf_files[0]

            text_pages = self._extract_pdf(
                pdf_path
            )

            self.documents = self._chunk_documents(
                text_pages
            )

        if not self.documents:

            self.documents = [
                "No security guidance was available."
            ]

            self.metadata = [
                {
                    "source": "Fallback",
                    "page": 0,
                }
            ]

        self.embedding_model = (
            SentenceTransformer(
                self.embedding_model_name
            )
        )

        embeddings = (
            self.embedding_model.encode(
                self.documents,
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
        )

        embeddings = np.asarray(
            embeddings,
            dtype="float32",
        )

        dimension = embeddings.shape[1]

        self.index = faiss.IndexFlatIP(
            dimension
        )

        self.index.add(
            embeddings
        )

    # ========================================================
    # PDF EXTRACTION
    # ========================================================

    def _extract_pdf(
        self,
        pdf_path: Path,
    ) -> List[Dict[str, Any]]:

        pages = []

        reader = PdfReader(
            str(pdf_path)
        )

        for page_number, page in enumerate(
            reader.pages,
            start=1,
        ):

            try:

                text = page.extract_text() or ""

            except Exception:

                text = ""

            text = text.strip()

            if text:

                pages.append(
                    {
                        "text": text,
                        "page": page_number,
                        "source": pdf_path.name,
                    }
                )

        return pages

    # ========================================================
    # CHUNKING
    # ========================================================

    def _chunk_documents(
        self,
        pages: List[Dict[str, Any]],
    ) -> List[str]:

        chunks = []

        self.metadata = []

        for page in pages:

            text = page["text"]

            start = 0

            text_length = len(
                text
            )

            while start < text_length:

                end = min(
                    start + self.chunk_size,
                    text_length,
                )

                chunk = text[
                    start:end
                ].strip()

                if chunk:

                    chunks.append(
                        chunk
                    )

                    self.metadata.append(
                        {
                            "source": page[
                                "source"
                            ],
                            "page": page[
                                "page"
                            ],
                        }
                    )

                if end >= text_length:
                    break

                next_start = (
                    end
                    - self.chunk_overlap
                )

                if next_start <= start:
                    next_start = end

                start = next_start

        return chunks

    # ========================================================
    # SEARCH
    # ========================================================

    def search(
        self,
        query: str,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:

        if not query:
            return []

        if self.index is None:
            return []

        query_embedding = (
            self.embedding_model.encode(
                [query],
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
        )

        query_embedding = np.asarray(
            query_embedding,
            dtype="float32",
        )

        k = min(
            top_k,
            len(self.documents),
        )

        scores, indices = (
            self.index.search(
                query_embedding,
                k,
            )
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
                    "text": self.documents[
                        index
                    ],
                    "score": float(
                        score
                    ),
                    "metadata": self.metadata[
                        index
                    ],
                }
            )

        return results

    # ========================================================
    # RETRIEVE
    # ========================================================

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:

        return self.search(
            query=query,
            top_k=top_k,
        )

    # ========================================================
    # QUERY
    # ========================================================

    def query(
        self,
        query: str,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:

        return self.search(
            query=query,
            top_k=top_k,
        )
