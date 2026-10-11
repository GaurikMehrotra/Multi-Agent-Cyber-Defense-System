# Dataset and rule-source review

**No public dataset has been downloaded or approved.** On 2026-10-11 the cloud network denied requests to the four review pages below (proxy 403). Domains were added to the environment draft; current licensing and terms remain unverified until those pages are reachable and the owner reviews them. No redistribution license is inferred from public availability.

| Source / authoritative starting point | Citation to verify | Checks before use |
|---|---|---|
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Sharafaldin, Lashkari, Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP 2018 | Current use/redistribution restrictions, publication citation, corrected vs original flows, timestamps/timezone, label ambiguity, duplicates, day-specific artifacts |
| CIC-IDS2018: navigate from UNB's CIC datasets catalog, do not guess download URLs | Verify dataset-specific authors and publication on authoritative page | CICFlowMeter version, AWS storage terms, invalid/NaN/infinite fields, attack schedules, bidirectional flow boundaries |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Moustafa and Slay, “UNSW-NB15: a comprehensive data set for network intrusion detection systems,” MilCIS 2015 | Current academic/commercial terms, redistribution, supplied split construction, synthetic lab artifacts, attack-category consistency, train/test duplicates |
| [CTU-13](https://www.stratosphereips.org/datasets-ctu13) | García et al., “An empirical comparison of botnet detection methods,” Computers & Security 2014 | Current per-capture license/citation, background vs benign vs botnet labels, scenario overlap and label uncertainty; PCAPs may contain sensitive content |
| [CIC-IDS2017 reanalysis / WTMC2021](https://intrusion-detection.distrinet-research.be/WTMC2021/) | Engelen, Rimmer, Joosen, “Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study,” WTMC 2021; confirm bibliographic details from paper | Read analysis and corrections before claiming results; original and corrected dataset variants must be distinguished |

These issue checks are a review checklist, not a claim that the current source pages or papers were read in this restricted environment. Flow construction, duplicate rows, label schedules and dataset-specific topology make IDS benchmarks easy to misuse. Random splitting often lets nearly identical flows and identifier artifacts occur on both sides of evaluation. This pipeline deduplicates canonical flows, rejects conflicting labels, uses chronological boundaries without splitting identical timestamps, excludes IPs/time/labels from features, and tests held-out families and external data. It cannot automatically repair mislabeled public rows. Cross-dataset feature mapping and units must be verified by the researcher; results are invalid if schemas have different meanings.

## Owner confirmation (required, secure local manifest)

Before downloading, record access date, license URL and exact terms/version, approved purpose, citation, variant, timezone/units, hashes and known-issues review. Decide whether “background” belongs in a benign-only AE training set; uncertainty is not benignness. Never redistribute raw rows.

Create `data/source.manifest.json` locally, **after your actual review**:

```json
{"dataset":"your-source-name","license_url":"authoritative reviewed URL","terms_reviewed_on":"YYYY-MM-DD","citation":"verified citation","known_issues_reviewed":true,"approved":true}
```

This is an example schema, not approval or a filled-in manifest. `src.eval.datasets` refuses ingestion without both explicit true confirmations. Supply a canonical CSV with `timestamp` (timezone), `src_ip`, `dst_ip`, `src_port`, `dest_port`, `protocol`, `duration` (seconds), `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `label` (0/1), `attack` (`benign` for label 0), `dataset`, optionally aligned `suricata_score` (0..1). Map vendor headers explicitly after checking units. The default generated-A/generated-B rows are algorithmic fixtures, **not real cross-dataset generalization evidence**.

## Rules and reference data

`configs/local.rules` is project-authored under MIT, intentionally alerts on harmless `example.com` DNS for sensor plumbing. No Emerging Threats or commercial rule set is bundled or downloaded. Verify a third-party rule set's current license, permitted redistribution, update policy and citations before replacing it. Do not interpret the demo rule as IDS coverage.

`configs/attack.json` contains one locally curated public technique ID T1046 and its reference URL, with no copied ATT&CK descriptions or STIX corpus. Load a broader official reference only with provenance/terms recorded. This project validates ID membership, not mapping correctness.
