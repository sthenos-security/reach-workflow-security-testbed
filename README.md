# reach-workflow-security-testbed

**Intentionally vulnerable CI/CD workflow-security testbed. Not for production use.**

This public repository is the isolated fixture corpus for validating REACHABLE
CI/CD workflow-code analysis. It focuses on GitHub Actions, Cordyceps-style
workflow attacks, chained pipeline trust boundaries, reusable-workflow
authority edges, and defended control examples.

The workflows are designed for scanner validation and repeatable release proof.
They are not application workflows and must not be copied into production
repositories.

## Expected Validation Result

The machine-readable baseline is
[expected/workflow-security.json](expected/workflow-security.json). The public
proof target is:

| Dimension | Expected |
|---|---:|
| Workflow fixture files | 22 |
| Native-positive workflow files | 19 |
| Zero-native fixture files | 3 |
| Native REACHABLE workflow-security findings | 85 |
| Critical native findings | 27 |
| High-risk native findings | 50 |
| Medium-risk native findings | 6 |
| Low-risk native findings | 2 |
| Required risk classes | 23 |
| Defended native-control files | 2 |

Optional tools such as `zizmor` and `actionlint` may add corroborating rows.
The stable validation contract is the exact native REACHABLE finding set, the
required class detections, and the zero-native fixture paths documented in
`expected/workflow-security.json`.

## Safety Contract

- Every intentionally vulnerable job is guarded with `if: ${{ false }}` so it
  cannot execute in GitHub Actions.
- Publishing, deployment, and secret-use examples are inert simulations. They
  use `echo` or disabled jobs, not real package, release, or cloud operations.
- No real secrets are stored in this repository.
- The expected findings are documented in [EXPECTED.md](EXPECTED.md) and
  [expected/workflow-security.json](expected/workflow-security.json).

## Fixture Goals

The support corpus proves that REACHABLE treats workflow code as a first-class
security surface, separate from application source code and package inventory.

| Area | Fixture | Expected class |
|---|---|---|
| Cordyceps command injection | `.github/workflows/cordyceps-command-injection.yml` | `cicd_command_injection` |
| Cordyceps code injection | `.github/workflows/cordyceps-code-injection.yml` | `cicd_code_injection` |
| Cordyceps broken authorization | `.github/workflows/cordyceps-broken-authorization.yml` | `cicd_auth_logic_error` |
| Cordyceps artifact poisoning | `.github/workflows/cordyceps-artifact-producer.yml` and `.github/workflows/cordyceps-artifact-consumer.yml` | `cicd_artifact_integrity_gap`, `cicd_cross_workflow_poisoning` |
| Secret authority exposure | `.github/workflows/secret-authority-exposure.yml` | `cicd_secret_authority_exposure` |
| Self-hosted runner exposure | `.github/workflows/self-hosted-runner-exposure.yml` | `cicd_self_hosted_runner_exposure` |
| Mutable action refs | vulnerable workflow action references | `cicd_unpinned_action` |
| Reusable boundary / inherited secrets | `.github/workflows/reusable-untrusted-caller.yml` calling `.github/workflows/reusable-inherit-secrets.yml` with `secrets: inherit` | `cicd_cross_workflow_poisoning`, `cicd_secret_authority_exposure`, `cicd_reusable_workflow_boundary` |
| Trigger abuse | `.github/workflows/trigger-abuse.yml` | `cicd_trigger_abuse` |
| Secret exfiltration | `.github/workflows/secret-exfiltration.yml` | `cicd_secret_exfiltration_path` |
| Action supply-chain exfiltration | `.github/workflows/action-supply-chain-exfiltration.yml` | `cicd_action_supply_chain_exfiltration` |
| Artifact/cache execution | `.github/workflows/artifact-cache-poisoning.yml` | `cicd_untrusted_artifact_execution` |
| Suspicious workflow execution | `.github/workflows/suspicious-workflow-execution.yml` | `cicd_suspicious_remote_execution`, `cicd_encoded_payload_execution`, `cicd_malware_signature` |
| Reusable workflow injection | `.github/workflows/reusable-workflow-injection.yml` | `cicd_reusable_workflow_injection` |
| Environment protection bypass | `.github/workflows/environment-protection-bypass.yml` | `cicd_environment_protection_bypass` |
| OIDC trust exposure | `.github/workflows/oidc-trust-exposure.yml` | `cicd_oidc_trust_exposure` |
| Step summary exfiltration | `.github/workflows/step-summary-exfiltration.yml` | `cicd_step_summary_exfiltration` |
| Workflow persistence | `.github/workflows/workflow-persistence.yml` | `cicd_workflow_persistence` |
| Concurrency TOCTOU | `.github/workflows/concurrency-toctou.yml` | `cicd_concurrency_toctou` |
| Defended controls | `.github/workflows/defended-internal-release.yml` and `.github/workflows/defended-guarded-pr.yml` | no Cordyceps finding expected |

## How To Validate

Run a fresh local scan and validate the metadata-backed native
workflow-security rows:

```bash
scan_dir="$(mktemp -d)"
reachctl scan /path/to/reach-workflow-security-testbed --ci \
  --output "$scan_dir" \
  --metadata-out "$scan_dir/metadata.json"

python ci/validate-workflow-security-results.py \
  --metadata "$scan_dir/metadata.json" \
  --repo-root /path/to/reach-workflow-security-testbed
```

Expected result:

- workflow-security scanning finds the expected deterministic classes and
  subclasses
- workflow-security findings remain production/security-relevant even though
  the files are under `.github/workflows`
- optional tool health for `zizmor` and `actionlint` is reported separately from
  native coverage
- zero-native helper and defended fixtures remain clean
- cloud/dashboard rollups must not include raw workflow YAML or secret values
- the validator prints `Workflow-security expected-results validation passed`

## Remediation Themes

The corpus is intentionally compact, but each fixture maps to a real remediation
pattern:

- never interpolate untrusted event fields directly into shell or script
  contexts
- avoid `pull_request_target` for untrusted code paths unless authorization
  gates, checkout boundaries, and permissions are explicit
- keep release/package/cloud authority out of low-trust workflow paths
- verify artifact provenance or digest before privileged consumption
- avoid `secrets: inherit` unless caller trust is explicit and bounded
- pin third-party actions to immutable commit SHAs
- avoid self-hosted runners for untrusted external events

## Repository Role

This repository is the isolated workflow-security lab. It keeps the full
subclass corpus, chained-pipeline fixtures, reusable-workflow boundary cases,
remediation-oriented experiments, and defended controls used for native
workflow-security regression proof.

## Copyright

Copyright (c) 2026 Sthenos Security. All rights reserved.
