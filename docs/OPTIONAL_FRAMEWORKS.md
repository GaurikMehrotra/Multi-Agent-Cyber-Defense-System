# Optional comparisons

CrewAI and AutoGen are intentionally not installed or implemented; phase 16 is optional. The primary and required orchestration is LangGraph, with fixed-pipeline and single-call baselines.

**Before using AutoGen, check which project and package is currently maintained, including community forks.** Start at the [Microsoft AutoGen documentation](https://microsoft.github.io/autogen/) and verify maintenance status, package names, versioned APIs, migration/deprecation notices, release dates and community successors. Do not assume old `autogen` code is compatible with `autogen-agentchat` or any fork. Check [CrewAI's current docs](https://docs.crewai.com/) before pinning its current API.

A future adapter must reuse the immutable tool registry, evidence validator, budget, approval store and simulator, then join `src.eval.comparison` with the exact same scenarios/backend/upper limits. Do not claim a comparison for an adapter that has not been implemented and exercised. GPU experiments are also optional; the CPU AE is exercised now.
