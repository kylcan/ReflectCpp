"""Algorithmic tool selection policy.

This module introduces an explicit scoring-based policy for selecting tools
instead of relying solely on LLM tool-picking.

score(tool) = semantic_match(task, tool) + historical_success_rate(tool) - cost_penalty(tool)

- semantic_match: keyword overlap between task text and tool capability
- historical_success_rate: smoothed success ratio from persisted counters
- cost_penalty: static penalty by tool cost tier
"""

from __future__ import annotations

import json
import math
import os
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, overload


_COST_PENALTY: dict[str, float] = {
    # Required tiers
    "cppcheck": 0.60,      # high
    "ast_parser": 0.30,    # medium
    "grep_scanner": 0.10,  # low
    "file_reader": 0.10,   # low
    # Reasonable defaults for remaining built-ins
    "repo_mapper": 0.20,
    "dependency_scanner": 0.20,
}


# Lightweight domain keyword map for security tasks.
# This intentionally stays deterministic and dependency-free, while still
# capturing higher-value semantic signals than token-level overlap alone.
KEYWORD_MAP: dict[str, list[str]] = {
    "buffer overflow": ["strcpy", "gets", "memcpy", "overflow"],
    "command injection": ["system", "exec", "popen"],
    "use after free": ["free", "dangling"],
    "null pointer": ["null", "nullptr"],
    "race condition": ["thread", "lock"],
}


# Heuristics for history weighting. We downweight tools with very little data
# to avoid overfitting to early runs.
_HISTORY_CONFIDENCE_MAX_SAMPLES = 5
_HISTORY_MIN_SAMPLES = 3


def _clip01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _contains_phrase(text: str, phrase: str) -> bool:
    return phrase.lower() in (text or "").lower()


def _keyword_boost(*, task_text: str, tool_text: str) -> float:
    """Return a semantic bonus based on domain keyword matches.

    Mechanism:
    - If the task text contains a high-level vulnerability phrase (key)
    - and the tool capability contains any related low-level keywords
    then we add a small bonus to semantic match.

    This keeps the base Jaccard score intact but adds a security-aware boost.
    """
    t_task = (task_text or "").lower()
    t_tool = (tool_text or "").lower()

    bonus = 0.0
    for phrase, kws in KEYWORD_MAP.items():
        if phrase in t_task:
            if any(kw.lower() in t_tool for kw in kws):
                # Bonus range requested: +0.2 ~ +0.4.
                # Use a conservative fixed value to avoid overpowering history/cost.
                bonus = max(bonus, 0.30)
    return bonus


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _l2(a: list[float]) -> float:
    return math.sqrt(sum(x * x for x in a))


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity in [-1, 1]."""
    if not a or not b:
        return 0.0
    if len(a) != len(b):
        # Defensive fallback; embeddings should be same length.
        n = min(len(a), len(b))
        a = a[:n]
        b = b[:n]
    denom = _l2(a) * _l2(b)
    if denom <= 0.0:
        return 0.0
    return _dot(a, b) / denom


class _Embedder:
    """Minimal embedding interface.

    We keep this as a small internal protocol to avoid hard dependencies.
    If `sentence-transformers` is installed, we use it; otherwise we fall back.
    """

    def embed(self, text: str) -> list[float]:
        raise NotImplementedError


class _SentenceTransformersEmbedder(_Embedder):
    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        # Import lazily so the module stays usable without extra deps.
        from sentence_transformers import SentenceTransformer  # type: ignore

        self._model = SentenceTransformer(model_name)

    def embed(self, text: str) -> list[float]:
        # sentence-transformers returns numpy arrays; convert to plain Python list
        vec = self._model.encode([text or ""], normalize_embeddings=False)[0]
        return [float(x) for x in vec]


def _try_create_default_embedder() -> _Embedder | None:
    """Try to create an embedding backend.

    Returns None if optional dependencies are missing.
    """
    try:
        return _SentenceTransformersEmbedder()
    except Exception:
        return None


def get_llm_preference(task_text: str, tool_name: str, tool_description: str) -> float:
    """Optional LLM-based preference score in [0, 1].

    This is designed to be production-safe:
    - Disabled by default
    - Automatically disabled in offline mode
    - Hard-falls back to 0.0 on any error

    Enable with:
      SENTINEL_TOOL_LLM_PREF=1

    Notes:
    - We keep this in this module to avoid coupling the policy logic to any
      particular agent graph; callers can still keep the system deterministic.
    """
    if os.getenv("SENTINEL_OFFLINE") == "1":
        return 0.0
    if os.getenv("SENTINEL_TOOL_LLM_PREF") != "1":
        return 0.0

    task_text = (task_text or "").strip()
    tool_name = (tool_name or "").strip()
    tool_description = (tool_description or "").strip()
    if not task_text or not tool_name:
        return 0.0

    # Lazy import so the policy module does not require LLM dependencies.
    try:
        from sentinel_agent.llm import get_llm, message_text  # type: ignore
        from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore

        system = (
            "You are helping an autonomous code security agent choose tools. "
            "Given a task description and a candidate tool, return a preference score. "
            "Respond with ONLY a single JSON object: {\"score\": <float 0..1>}"
        )
        user = (
            f"Task:\n{task_text}\n\n"
            f"Tool name: {tool_name}\n"
            f"Tool description:\n{tool_description}\n\n"
            "How suitable is this tool for the task?"
        )

        llm = get_llm(temperature=0.0)
        resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
        text = message_text(resp.content).strip()

        # Parse JSON payload.
        payload = json.loads(text)
        raw = payload.get("score", 0.0) if isinstance(payload, dict) else 0.0
        score = float(raw)
        return _clip01(score)
    except Exception:
        # Safe fallback: no preference signal.
        return 0.0


def _tokenize(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z0-9_]+", (text or "").lower())
    stop = {
        "the", "and", "or", "to", "of", "for", "on", "in", "a", "an", "with", "is",
        "run", "scan", "check", "analyze", "analysis", "file", "files", "repo", "repository",
    }
    return {t for t in tokens if len(t) >= 3 and t not in stop}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    denom = len(a | b)
    return (len(a & b) / denom) if denom else 0.0


@dataclass(frozen=True)
class ToolScore:
    tool_name: str
    score: float
    semantic: float
    history: float
    cost: float


class ToolHistory:
    """Persistent per-tool reward statistics.

    New format (preferred):
      {"tool": {"reward_sum": float, "count": int}}

    Legacy format (auto-migrated on load):
      {"tool": {"success": int, "fail": int}}

    Rewards:
      +1.0 => tool output was useful
       0.0 => neutral / not useful
      -1.0 => misleading / wrong
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.stats: dict[str, dict[str, float | int]] = {}
        self._load()

    @classmethod
    def default(cls) -> "ToolHistory":
        # Store inside the SentinelAgent project (not the audited repo).
        # This keeps "historical" results across runs without polluting user targets.
        base = Path(__file__).resolve().parents[1] / "memory"
        base.mkdir(parents=True, exist_ok=True)
        return cls(base / "tool_history.json")

    def _load(self) -> None:
        try:
            if not self.path.exists():
                return
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return

            migrated: dict[str, dict[str, float | int]] = {}
            for k, v in data.items():
                tool = str(k)
                if not isinstance(v, dict):
                    continue

                # Preferred format
                if "reward_sum" in v or "count" in v:
                    reward_sum = float(v.get("reward_sum", 0.0) or 0.0)
                    count = int(v.get("count", 0) or 0)
                    migrated[tool] = {"reward_sum": reward_sum, "count": max(count, 0)}
                    continue

                # Legacy format: success/fail -> reward_sum/count
                # IMPORTANT: legacy "fail" does not necessarily mean "misleading".
                # To preserve old semantics, we map:
                #   success => +1
                #   fail    =>  0 (neutral)
                success = int(v.get("success", 0) or 0)
                fail = int(v.get("fail", 0) or 0)
                reward_sum = float(max(success, 0))
                count = max(success, 0) + max(fail, 0)
                migrated[tool] = {"reward_sum": reward_sum, "count": int(count)}

            self.stats = migrated
        except Exception:
            self.stats = {}

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.stats, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def get_counts(self, tool_name: str) -> tuple[float, int]:
        """Return (reward_sum, count) for a tool."""
        s = self.stats.get(tool_name, {"reward_sum": 0.0, "count": 0})
        reward_sum = float(s.get("reward_sum", 0.0) or 0.0)
        count = int(s.get("count", 0) or 0)
        return reward_sum, max(count, 0)

    def get_rate(self, tool_name: str) -> float:
        """Return average reward in [-1, 1].

        Returns 0.0 when there is no data.
        """
        reward_sum, count = self.get_counts(tool_name)
        if count <= 0:
            return 0.0
        return float(reward_sum) / float(count)

    def record(self, tool_name: str, reward: float | None = None, *, success: bool | None = None) -> None:
        """Record a reward observation.

        Preferred usage:
          record(tool, reward=+1.0|0.0|-1.0)

        Backward-compatible usage (deprecated):
          record(tool, success=True/False)

        In that legacy form, we map:
          True  -> +1.0
          False ->  0.0  (neutral; not necessarily misleading)
        """
        if reward is None:
            if success is None:
                raise TypeError("record() requires either reward or success")
            reward = 1.0 if success else 0.0

        reward_f = float(reward)
        reward_f = max(-1.0, min(1.0, reward_f))

        s = self.stats.setdefault(tool_name, {"reward_sum": 0.0, "count": 0})
        s["reward_sum"] = float(s.get("reward_sum", 0.0) or 0.0) + reward_f
        s["count"] = int(s.get("count", 0) or 0) + 1


class ToolSelectionDebug(TypedDict):
    selected: list[str]
    ranking: list[str]
    scores: list[dict[str, Any]]


class ToolSelectionPolicy:
    """Scores tools and selects top-k candidates."""

    def __init__(
        self,
        *,
        tool_capabilities: dict[str, str],
        history: ToolHistory | None = None,
        embedder: _Embedder | None = None,
        llm_alpha: float = 0.3,
    ) -> None:
        self.tool_capabilities = dict(tool_capabilities)
        self.history = history or ToolHistory.default()
        # Optional embedding backend. If unavailable, semantic matching falls back to Jaccard.
        self.embedder = embedder
        # LLM preference blending weight. LLM itself is optional and disabled by default.
        # Override at runtime via SENTINEL_TOOL_LLM_ALPHA.
        try:
            env_alpha = os.getenv("SENTINEL_TOOL_LLM_ALPHA")
            self.llm_alpha = float(env_alpha) if env_alpha is not None and env_alpha != "" else float(llm_alpha)
        except Exception:
            self.llm_alpha = float(llm_alpha)

    def _embedding_similarity(self, *, task_text: str, tool_text: str) -> float | None:
        """Compute embedding similarity in [0, 1], or None if unavailable."""
        if self.embedder is None:
            # Lazy init so importing this module doesn't require extra deps.
            self.embedder = _try_create_default_embedder()
        if self.embedder is None:
            return None

        try:
            a = self.embedder.embed(task_text)
            b = self.embedder.embed(tool_text)
            cos = _cosine_similarity(a, b)  # [-1, 1]
            # Map cosine from [-1, 1] -> [0, 1]
            return _clip01((cos + 1.0) * 0.5)
        except Exception:
            # If the optional embedder flakes (model missing, runtime error), fall back cleanly.
            return None

    def semantic_match(self, *, task_text: str, tool_name: str, tool_hint: str = "") -> float:
        tool_text = self.tool_capabilities.get(tool_name, "")
        a = _tokenize(task_text)
        b = _tokenize(tool_text + " " + tool_name)
        # Base semantic similarity: token Jaccard.
        jaccard_sim = _jaccard(a, b)

        # Optional: embedding similarity (cosine), blended 50/50 with Jaccard.
        emb_sim = self._embedding_similarity(task_text=task_text, tool_text=tool_text)
        if emb_sim is None:
            blended = jaccard_sim
        else:
            blended = 0.5 * jaccard_sim + 0.5 * emb_sim

        # Keep the security-aware keyword boost mechanism.
        boost = _keyword_boost(task_text=task_text, tool_text=tool_text)
        sim = _clip01(blended + boost)

        # Make tool_hint more meaningful but safer:
        # - stronger bonus than before (~0.3)
        # - only apply if semantic similarity is non-zero (avoid blindly trusting hint)
        hint_bonus = 0.30 if tool_hint and tool_hint == tool_name and sim > 0.0 else 0.0
        return _clip01(sim + hint_bonus)

    def cost_penalty(self, tool_name: str) -> float:
        return float(_COST_PENALTY.get(tool_name, 0.20))

    def historical_success_rate(self, tool_name: str) -> float:
        # Reward-based history with confidence weighting.
        # - get_rate(): average reward in [-1, 1]
        # - confidence: downweights tools with low sample count
        avg_reward = float(self.history.get_rate(tool_name))
        _reward_sum, count = self.history.get_counts(tool_name)

        confidence = min(1.0, count / float(_HISTORY_CONFIDENCE_MAX_SAMPLES))
        if count < _HISTORY_MIN_SAMPLES:
            confidence *= (count / float(_HISTORY_MIN_SAMPLES)) if _HISTORY_MIN_SAMPLES else 0.0

        return float(avg_reward) * float(confidence)

    def score_tool(self, *, task_text: str, tool_name: str, tool_hint: str = "") -> ToolScore:
        semantic = self.semantic_match(task_text=task_text, tool_name=tool_name, tool_hint=tool_hint)
        history = self.historical_success_rate(tool_name)
        cost = self.cost_penalty(tool_name)
        policy_score = semantic + history - cost

        # Optional LLM preference score in [0, 1]. Disabled by default.
        llm_score = get_llm_preference(
            task_text=task_text,
            tool_name=tool_name,
            tool_description=self.tool_capabilities.get(tool_name, ""),
        )
        alpha = float(self.llm_alpha)
        score = policy_score + alpha * float(llm_score)
        return ToolScore(tool_name=tool_name, score=score, semantic=semantic, history=history, cost=cost)

    def rank_tools(self, *, task_text: str, tool_hint: str = "") -> list[ToolScore]:
        scores = [
            self.score_tool(task_text=task_text, tool_name=name, tool_hint=tool_hint)
            for name in sorted(self.tool_capabilities)
        ]
        return sorted(scores, key=lambda s: s.score, reverse=True)

    @overload
    def select(
        self,
        *,
        task_text: str,
        tool_hint: str = "",
        k: int = 1,
        epsilon: float = 0.1,
        return_debug: Literal[False] = False,
    ) -> list[ToolScore]: ...

    @overload
    def select(
        self,
        *,
        task_text: str,
        tool_hint: str = "",
        k: int = 1,
        epsilon: float = 0.1,
        return_debug: Literal[True],
    ) -> ToolSelectionDebug: ...

    def select(
        self,
        *,
        task_text: str,
        tool_hint: str = "",
        k: int = 1,
        epsilon: float = 0.1,
        return_debug: bool = False,
    ) -> list[ToolScore] | ToolSelectionDebug:
        """Select tools using an epsilon-greedy strategy.

        Backward-compatible behavior:
        - By default (return_debug=False) returns List[ToolScore] as before.
        - If return_debug=True returns a dict with selection + scoring details.

        Exploration (epsilon-greedy):
        - With probability epsilon, pick a random tool from ALL tools.
        - Otherwise, pick the top-k ranked tools.
        """
        ranked = self.rank_tools(task_text=task_text, tool_hint=tool_hint)
        k = max(int(k), 1)

        tool_names = list(self.tool_capabilities.keys())
        use_exploration = bool(tool_names) and (random.random() < float(epsilon))

        if use_exploration:
            # Exploration samples from ALL tools, not only top-k.
            chosen = random.choice(tool_names)
            # Reuse the computed score from ranked if available.
            chosen_score = next((s for s in ranked if s.tool_name == chosen), None)
            if chosen_score is None:
                chosen_score = self.score_tool(task_text=task_text, tool_name=chosen, tool_hint=tool_hint)

            selected_scores = [chosen_score]

            # If k>1, fill remaining slots with best-ranked tools excluding the random pick.
            if k > 1:
                selected_scores.extend([s for s in ranked if s.tool_name != chosen][: k - 1])
        else:
            selected_scores = ranked[:k]

        if not return_debug:
            return selected_scores

        return {
            "selected": [s.tool_name for s in selected_scores],
            "ranking": [s.tool_name for s in ranked],
            "scores": [
                {
                    "tool": s.tool_name,
                    "score": s.score,
                    "semantic": s.semantic,
                    "history": s.history,
                    "cost": s.cost,
                }
                for s in ranked
            ],
        }


def build_default_capabilities(tool_registry: dict[str, type]) -> dict[str, str]:
    """Build a {tool_name: capability_description} mapping from tool classes."""
    caps: dict[str, str] = {}
    for name, cls in tool_registry.items():
        desc = getattr(cls, "description", "")
        if not isinstance(desc, str):
            desc = ""
        caps[name] = desc.strip() or f"Tool '{name}'"
    return caps
