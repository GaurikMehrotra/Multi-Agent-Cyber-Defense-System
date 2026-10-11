# Evaluation protocol

Run locally with FakeLLM first:

```bash
make detection-eval agent-eval safety
python -m src.eval.response_eval
python -m src.eval.replay_eval
```

Detection: 3 fixed seeds × temporal/family-disjoint/external splits × 5 methods. Every method uses the same validation-only candidate threshold search. Brier/ECE are calibration diagnostics, not a claim that scores are calibrated. Artificial benign observation coverage is one day in the generated demo; replace it with measured coverage for approved data. No random splitting or test-driven threshold tuning. Per-family precision is explicitly evaluated on that family plus benign rows, because a binary detector does not predict attack-family labels; it is not multiclass family precision.

Response: `response_eval` evaluates ground-truth oracle plans only to verify simulator semantics. `comparison` separately evaluates each method's actual proposed plan against scenario truth, including malicious containment, stopped activity and dependency-weighted collateral damage. It records decision accuracy and whether low-confidence escalation matches the scenario's expected action. An oracle result is never agent accuracy.

Agents: 6 scenarios × 3 repeats × 6 modes = 108 investigations. All use the same backend, input observations and upper call/time budgets. The fixed pipeline uses predetermined log/verification/intel collection and exactly one interpretation call, with no specialist agents; the single-call baseline receives initial evidence and has no tools. The single-call baseline intentionally uses no tools; report actual consumed budgets rather than forcing equal spend. Ablations remove Reviewer reasoning, verification, or enrichment, but mandatory validators and authorization are always retained. Typed-tool validity measures schema/role acceptance, not whether a tool call was substantively useful. The corpus's mock intel is always unknown and must not be counted as real threat-intel corroboration.

Hosted comparison after owner-approved evidence export and provider credentials, using the same configured model for all methods:

```bash
python -m dotenv run -- python -c 'from src.eval.comparison import evaluate; from src.llm.hosted import Hosted; print(evaluate(output="artifacts/hosted-comparison", backend_factory=Hosted))'
```

Provider free tiers and APIs must be checked currently. Costs remain unknown unless actual usage/prices are supplied; character-derived token estimates are not billed token counts. No hosted result has run in the cloud setup.

Replay: 12 generated flow records, real CPU model inference, then FakeLLM graph investigation. Time-to-detect and time-to-decision mean wall-clock processing from a ready normalized flow to its score/proposal. This accelerated offline replay excludes collection delays, production queue waits and inter-arrival sleeps; it is not a real-world detection SLA.

Manual review: `artifacts/comparison/manual_review.csv` has 30 blank assignments to incident JSON files in that directory. Inspect actual evidence and mark factual accuracy, support, unsafe claims and notes. Do not auto-fill this file. Small-model LLM judges are noisy. The review is outstanding until a human completes it.

Resource measurements: run `scripts/measure.py` per stage on the actual laptop and retain aggregate Docker stats separately. Cloud process peaks and timings are labelled cloud-only. Train larger models only as a separate optional experiment with resumable optimizer/epoch checkpoints; current AE checkpoints support safe inference restoration.

Report all failures/skips, source and model versions, fixed configs, seed variation, observation-day denominators and limits. Authored scenarios and generated flows validate engineering, not real IDS performance or agent intelligence.
