# Selected hosted evaluation

The selected candidate is **Groq, `openai/gpt-oss-20b`**. On 2026-10-11, Groq's official [Python SDK README](https://github.com/groq/groq-python) used this model in its examples. Its chat-completions resource documents JSON-object output and `/openai/v1/chat/completions`, and its client defaults to `https://api.groq.com`. The existing HTTP interface therefore uses `https://api.groq.com/openai/v1` as its base URL. No new SDK dependency is needed.

This verifies the documented interface, not account access, inference quality, current free-tier eligibility, rate limits, prices, retention policy, or successful calls. Groq's console documentation was blocked by the current network proxy. Check those items in your account before proceeding; do not assume free means unlimited or enable billing automatically. Mocked contract tests verify request construction, output validation, export opt-in and provider-reported usage; they are not hosted-model results.

## Private prerequisites

Create your own provider account/key and enter it in private environment settings or the ignored `.env`. Never paste it into chat or Git. Configure:

```dotenv
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=openai/gpt-oss-20b
```

Set `LLM_API_KEY` privately. Set `ALLOW_EXTERNAL_LLM=yes` only after reviewing the provider's export/retention policy and consenting to the evidence being sent. Keep the normal Compose worker on FakeLLM; its internal networks do not have external egress. Run hosted evaluation from the host virtual environment, with network access to `api.groq.com`.

First run the generated, synthetic-evidence comparison, using the same configured model and upper budgets for all modes:

```bash
python -m dotenv run -- python -c 'from src.eval.comparison import evaluate; from src.llm.hosted import Hosted; print(evaluate(output="artifacts/groq-comparison", backend_factory=Hosted))'
```

Expected: 108 attempted runs, saved reports and CSV/JSON under ignored `artifacts/groq-comparison`. The harness records actual failures rather than promising schema-conforming responses. Inspect failures, token usage, reference grounding and actual decisions before publishing aggregate results. Character-derived token estimates remain estimates; dollar costs remain unknown without applicable prices. The synthetic scenario set does not demonstrate public IDS performance. Do not send public-data payloads to the provider just because their dataset is downloadable.

If this model is unavailable to your account, choose a currently supported replacement from the provider's authenticated model list, record the exact served model, and rerun every mode with the same replacement. Do not silently switch only one baseline. No hosted run has been performed because the private key is absent.
