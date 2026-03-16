from sentinel_agent.graph import run_agent


def test_offline_smoke_runs_end_to_end(monkeypatch):
    # Ensure we run in offline mode (no API key required)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GPT5_KEY", raising=False)
    monkeypatch.delenv("CHATGPT_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    result = run_agent("samples/vuln_sample.cpp", max_iterations=2)

    assert isinstance(result, dict)
    assert result.get("final_report"), "Expected Markdown report"
    assert "SentinelAgent Security Audit Report" in result["final_report"]
    assert "reasoning_trace" in result
