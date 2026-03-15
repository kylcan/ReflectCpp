"""
LangSmith / LangFuse tracing configuration.

Activating tracing
------------------
Set these environment variables and tracing is auto-enabled:

    LANGSMITH_API_KEY=ls-xxxx
    LANGCHAIN_TRACING_V2=true          # LangSmith
    LANGCHAIN_PROJECT=RepoAudit        # optional project name

When these vars are absent, tracing is silently disabled and the
pipeline runs identically – zero impact on correctness.

Usage
-----
    from src.tracing import configure_tracing, get_run_url

    configure_tracing()           # call once at startup
    url = get_run_url(run_id)     # optional: build a LangSmith link
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def configure_tracing() -> bool:
    """Set up LangSmith tracing from environment variables.

    Returns True if tracing is active, False otherwise.
    """
    api_key = os.getenv("LANGSMITH_API_KEY", "")
    tracing_flag = os.getenv("LANGCHAIN_TRACING_V2", "").lower()

    if not api_key or tracing_flag not in ("true", "1", "yes"):
        logger.info("LangSmith tracing disabled (LANGSMITH_API_KEY or LANGCHAIN_TRACING_V2 not set).")
        return False

    # Ensure the env vars LangChain checks are set
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
    os.environ.setdefault("LANGCHAIN_PROJECT", "RepoAudit")

    project = os.environ.get("LANGCHAIN_PROJECT", "RepoAudit")
    logger.info("LangSmith tracing enabled – project: %s", project)
    return True


def get_run_url(run_id: str) -> str:
    """Build a LangSmith dashboard URL for a given run ID."""
    endpoint = os.getenv("LANGCHAIN_ENDPOINT", "https://smith.langchain.com")
    project = os.getenv("LANGCHAIN_PROJECT", "RepoAudit")
    return f"{endpoint}/o/default/projects/p/{project}/r/{run_id}"
