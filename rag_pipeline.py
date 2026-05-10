"""
================================================================================
RAG PIPELINE
Enterprise Knowledge Research Agent
================================================================================
ChromaDB vector store indexing the 10-document AV/OT security corpus.
Provides semantic search with role-based access filtering.
================================================================================
"""

import os
import json
from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document

load_dotenv()

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data/corpus.json")
CHROMA_PATH = os.path.join(os.path.dirname(__file__), "knowledge_base/chroma_db")

ROLE_ACCESS = {
    "ANALYST":   ["PUBLIC", "INTERNAL"],
    "ENGINEER":  ["PUBLIC", "INTERNAL"],
    "EXECUTIVE": ["PUBLIC", "INTERNAL", "RESTRICTED"],
}


def build_vector_store() -> Chroma:
    """
    Index all corpus documents into ChromaDB.
    Each document stored with metadata: doc_id, sensitivity, category, date.
    Run once at setup — subsequent calls load existing store.
    """
    with open(CORPUS_PATH) as f:
        corpus = json.load(f)

    documents = []
    for doc in corpus:
        documents.append(Document(
            page_content=f"{doc['title']}\n\n{doc['content']}",
            metadata={
                "doc_id":      doc["doc_id"],
                "title":       doc["title"],
                "category":    doc["category"],
                "sensitivity": doc["sensitivity"],
                "date":        doc["date"],
                "author":      doc["author"],
            }
        ))

    embeddings = OpenAIEmbeddings(
        model="text-embedding-3-small",
        api_key=os.getenv("OPENAI_API_KEY")
    )

    os.makedirs(CHROMA_PATH, exist_ok=True)
    store = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=CHROMA_PATH
    )
    print(f"Vector store built: {len(documents)} documents indexed")
    return store


def get_vector_store() -> Chroma:
    """Load existing ChromaDB vector store."""
    embeddings = OpenAIEmbeddings(
        model="text-embedding-3-small",
        api_key=os.getenv("OPENAI_API_KEY")
    )
    return Chroma(
        persist_directory=CHROMA_PATH,
        embedding_function=embeddings
    )


def retrieve_context(query: str, user_role: str = "ANALYST", k: int = 3) -> list[dict]:
    """
    Retrieve top-k most relevant documents for a query.
    Filters by user role access level before returning results.

    Returns list of dicts with doc_id, title, content, relevance, sensitivity.
    """
    store = get_vector_store()
    allowed = ROLE_ACCESS.get(user_role, ["PUBLIC", "INTERNAL"])

    # Retrieve more than needed to account for access filtering
    results = store.similarity_search_with_relevance_scores(query, k=k * 3)

    filtered = []
    for doc, score in results:
        sensitivity = doc.metadata.get("sensitivity", "INTERNAL")
        if sensitivity in allowed:
            filtered.append({
                "doc_id":      doc.metadata.get("doc_id", "UNKNOWN"),
                "title":       doc.metadata.get("title", ""),
                "category":    doc.metadata.get("category", ""),
                "sensitivity": sensitivity,
                "date":        doc.metadata.get("date", ""),
                "content":     doc.page_content[:500],
                "relevance":   round(float(score), 3)
            })
        if len(filtered) >= k:
            break

    return filtered


if __name__ == "__main__":
    print("Building vector store...")
    build_vector_store()
    print("Testing retrieval...")
    results = retrieve_context("CAN bus vulnerabilities CVE", user_role="ENGINEER", k=3)
    for r in results:
        print(f"  {r['doc_id']} [{r['sensitivity']}] score={r['relevance']}: {r['title'][:50]}")
