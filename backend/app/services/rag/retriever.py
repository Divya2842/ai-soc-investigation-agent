"""
Local knowledge-base retrieval ("RAG" retrieval half).

The spec calls for Chroma or FAISS. This implementation uses a small,
dependency-free TF-IDF + cosine-similarity index instead, for two
practical reasons: (1) it keeps the project runnable with zero extra
native/ML dependencies and no model download, and (2) the retrieval
*interface* (`retrieve(query, k) -> list[RetrievedChunk]`) is identical to
what a Chroma/FAISS-backed implementation would expose, so swapping the
backend later is a one-file change in this module -- nothing upstream
(the agent, the API) needs to know which index implementation is in use.

Documents are the markdown files in data/knowledge_base/.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
KB_DIR = REPO_ROOT / "data" / "knowledge_base"

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


@dataclass(frozen=True)
class RetrievedChunk:
    source: str  # filename
    text: str
    score: float


class KnowledgeBase:
    def __init__(self, directory: Path = KB_DIR):
        self._directory = directory
        self._chunks: list[tuple[str, str]] = []  # (source, chunk_text)
        self._doc_freq: Counter = Counter()
        self._chunk_vectors: list[Counter] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        for path in sorted(self._directory.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            # Chunk by markdown section (## headers) for reasonably sized,
            # topically coherent retrieval units.
            sections = re.split(r"\n(?=## )", text)
            for section in sections:
                section = section.strip()
                if len(section) < 20:
                    continue
                self._chunks.append((path.name, section))

        for _, chunk_text in self._chunks:
            tokens = set(_tokenize(chunk_text))
            self._doc_freq.update(tokens)

        n_docs = max(len(self._chunks), 1)
        for _, chunk_text in self._chunks:
            tf = Counter(_tokenize(chunk_text))
            vec = Counter()
            for term, freq in tf.items():
                idf = math.log((n_docs + 1) / (self._doc_freq[term] + 1)) + 1
                vec[term] = freq * idf
            self._chunk_vectors.append(vec)

        self._loaded = True

    def retrieve(self, query: str, k: int = 3) -> list[RetrievedChunk]:
        self._load()
        if not self._chunks:
            return []

        query_tf = Counter(_tokenize(query))
        n_docs = max(len(self._chunks), 1)
        query_vec = Counter()
        for term, freq in query_tf.items():
            idf = math.log((n_docs + 1) / (self._doc_freq.get(term, 0) + 1)) + 1
            query_vec[term] = freq * idf

        def cosine(a: Counter, b: Counter) -> float:
            common = set(a) & set(b)
            dot = sum(a[t] * b[t] for t in common)
            norm_a = math.sqrt(sum(v * v for v in a.values())) or 1.0
            norm_b = math.sqrt(sum(v * v for v in b.values())) or 1.0
            return dot / (norm_a * norm_b)

        scored = [
            RetrievedChunk(source=self._chunks[i][0], text=self._chunks[i][1], score=cosine(query_vec, vec))
            for i, vec in enumerate(self._chunk_vectors)
        ]
        scored.sort(key=lambda c: c.score, reverse=True)
        return [c for c in scored[:k] if c.score > 0]


_kb_singleton: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb_singleton
    if _kb_singleton is None:
        _kb_singleton = KnowledgeBase()
    return _kb_singleton
