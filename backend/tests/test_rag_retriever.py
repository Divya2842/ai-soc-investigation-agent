from app.services.rag.retriever import KnowledgeBase


def test_retrieves_relevant_chunk_for_credential_dumping_query():
    kb = KnowledgeBase()
    results = kb.retrieve("credential dumping lsass response", k=3)
    assert len(results) > 0
    assert any("lsass" in r.text.lower() or "credential" in r.text.lower() for r in results)


def test_retrieves_nothing_for_totally_unrelated_query_returns_list():
    kb = KnowledgeBase()
    results = kb.retrieve("zzz qqq nonsense query unrelated", k=3)
    assert isinstance(results, list)


def test_results_are_sorted_by_score_descending():
    kb = KnowledgeBase()
    results = kb.retrieve("phishing credential response", k=5)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)
