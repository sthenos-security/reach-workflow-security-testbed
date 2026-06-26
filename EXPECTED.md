# Expected Workflow-Security Results

This file is the human-readable expected-results contract for the isolated
workflow-security lab corpus.

The native findings below are exact for the current validated workflow-security
model in this repository. Optional tool integrations may add corroborating
rows, but updates to the native counts or rule distribution require a fresh
native scan and a contract update.

## Required Classes

Golden baseline:

| Baseline dimension | Expected |
|---|---:|
| Workflow fixture files | 22 |
| Native-positive workflow files | 19 |
| Zero-native fixture files | 3 |
| Native REACHABLE workflow-security findings | 85 |
| Critical native findings | 27 |
| High-risk native findings | 50 |
| Medium-risk native findings | 6 |
| Low-risk native findings | 2 |
| Required native classes | 23 |
| Defended native-control files | 2 |

The exact optional-tool count can change as `zizmor` and `actionlint` evolve.
For that reason, CI should validate the exact native REACHABLE contract,
including class/rule/path counts, and treat optional tool output as
corroborating evidence.

| Required class | Risk | Expected evidence | Remediation guidance |
|---|---|---|---|
| `cicd_command_injection` | Attacker-controlled GitHub event data reaches shell or script execution. | PR title, issue/comment text, or workflow input used in `run` or `actions/github-script`. | Move untrusted values into quoted environment variables, validate/escape input, or avoid executing event-controlled content. |
| `cicd_code_injection` | Attacker-controlled GitHub event data reaches evaluated script or code-generation context. | Issue/comment text or workflow input used inside `actions/github-script`, `script:`, or inline interpreter/eval contexts. | Treat event fields as data, pass them through environment variables or structured inputs, and avoid string interpolation into executable scripts. |
| `cicd_auth_logic_error` | A privileged workflow can run from a low-trust trigger without an explicit local authorization guard. | `pull_request_target`, `issue_comment`, or `workflow_run` with write/OIDC/secret/release authority and no visible gate. | Add actor/association/base-ref/environment protection checks and reduce permissions to least privilege. |
| `cicd_artifact_integrity_gap` | A release/deploy path consumes artifact or cache data without digest/provenance verification. | `download-artifact`, `upload-artifact`, or cache use near release/deploy/package authority. | Bind artifacts to digest/provenance, use attestations, and verify before privileged consumption. |
| `cicd_cross_workflow_poisoning` | Low-trust workflow state can cross into a privileged workflow. | `workflow_run` or reusable workflow boundary with artifact/cache/secrets crossing trust levels. | Split trust zones, require provenance and environment gates, and avoid `secrets: inherit` from untrusted callers. |
| `cicd_secret_authority_exposure` | Low-trust workflow path can access secret, token, OIDC, or package authority. | References to `secrets.*`, write permissions, or OIDC in externally reachable workflows. | Remove secrets from external triggers, use environment protection, and scope tokens to read-only unless release authority is required. |
| `cicd_untrusted_checkout` | Privileged workflow checks out attacker-controlled code. | `actions/checkout` with PR head ref in a privileged trigger. | Checkout trusted base ref, inspect patch data separately, or run untrusted code only in a low-privilege workflow. |
| `cicd_self_hosted_runner_exposure` | External trigger can reach persistent self-hosted infrastructure. | `runs-on: self-hosted` in a low-trust workflow. | Use GitHub-hosted ephemeral runners for external events or add strict isolation and approval gates. |
| `cicd_unpinned_action` | Mutable third-party actions can change without review. | `uses: owner/action@vN` or branch refs. | Pin to full commit SHA and update through reviewed dependency changes. |
| `cicd_trigger_abuse` | Low-trust or manually dispatched triggers can reach privileged workflow authority. | `workflow_dispatch`, `repository_dispatch`, or `pull_request_target` with write/OIDC/release authority. | Add actor/environment gates, reduce permissions, and avoid privileged authority on low-trust triggers. |
| `cicd_secret_exfiltration_path` | Secret or token authority can flow to external, log, artifact, cache, or output sinks. | `${{ secrets.* }}` or token env vars in network/log/artifact/output contexts. | Keep secrets out of sinks, scope tokens least privilege, and rotate exposed credentials. |
| `cicd_action_supply_chain_exfiltration` | Third-party action code can receive and exfiltrate workflow authority. | Non-first-party `uses:` action near secrets, tokens, OIDC, or write authority. | Do not pass secrets to third-party actions unless pinned, reviewed, and isolated. |
| `cicd_untrusted_artifact_execution` | Artifact, cache, or workflow output can be executed after crossing a trust boundary. | `download-artifact` or cache restore followed by `chmod +x` and execution. | Require provenance and digest checks before executing shared state. |
| `cicd_suspicious_remote_execution` | Remote content can execute in runner context without integrity binding. | `curl`/`wget` piped to shell or downloaded, marked executable, and run. | Pin and verify downloaded content, or keep scripts in source control. |
| `cicd_encoded_payload_execution` | Encoded/compressed payloads are decoded and executed in workflow context. | `base64 -d`, archive extraction, or interpreter execution chain. | Remove encoded execution chains or replace with reviewed source-controlled scripts. |
| `cicd_malware_signature` | Workflow code contains reverse-shell, miner, credential-theft, or persistence signatures. | Shell snippets such as `/dev/tcp`, `xmrig`, credential-file reads, or persistence commands. | Remove the command and rotate any exposed runner, repo, cloud, or deployment credentials. |
| `cicd_reusable_workflow_injection` | Caller-controlled reusable workflow input reaches executable workflow code. | `workflow_call` inputs interpolated into `run:` or script contexts. | Treat `workflow_call` inputs as untrusted data and validate them before executable use. |
| `cicd_environment_protection_bypass` | Externally reachable workflow targets a protected environment without a visible approval boundary. | `workflow_dispatch`, `repository_dispatch`, or similar low-trust trigger plus `environment: production` or release environment. | Require protected environments, reviewer gates, and trusted branch conditions before deployment authority is reachable. |
| `cicd_oidc_trust_exposure` | Low-trust workflow can mint OIDC authority. | `id-token: write` on an externally reachable workflow. | Limit OIDC authority to trusted refs/workflows and bind cloud trust policies to exact repo, ref, and workflow claims. |
| `cicd_reusable_workflow_boundary` | A low-trust caller crosses a reusable-workflow boundary with inherited authority. | `secrets: inherit`, release authority, or other shared credentials crossing from the caller into a reusable workflow. | Keep reusable workflows on explicit trust boundaries and avoid inherited authority from low-trust callers. |
| `cicd_step_summary_exfiltration` | Secret or sensitive output is exposed through the workflow UI or API. | Secret/token data written to `$GITHUB_STEP_SUMMARY` or workflow annotations. | Keep secrets out of summaries and annotations and use non-UI channels only for non-sensitive status. |
| `cicd_workflow_persistence` | Workflow execution can establish a durable CI/CD backdoor. | Low-trust workflow writes `.github/workflows/*` or pushes workflow changes. | Block workflow-file writes and push authority from low-trust paths and isolate release automation. |
| `cicd_concurrency_toctou` | Mutable shared workflow state can win a race into privileged consumption. | Shared `concurrency:` group combined with shared cache/artifact state near privileged sinks. | Use unique cache/artifact keys per trust boundary and avoid shared mutable state across privileged and low-trust runs. |

## Defended Controls

| Fixture | Expected result | Why |
|---|---|---|
| `.github/workflows/defended-internal-release.yml` | No Cordyceps finding expected from native rules. | Internal `push` trigger, read-only permissions, SHA-pinned action, no low-trust entry. |
| `.github/workflows/defended-guarded-pr.yml` | No auth-logic finding expected. | Low-trust trigger is guarded by actor/association checks and uses read-only permissions. |

## Zero-Native Helper

| Fixture | Expected result | Why |
|---|---|---|
| `.github/workflows/reusable-inherit-secrets.yml` | No native finding expected on the callee by itself. | The reusable callee is inert on its own; the low-trust caller carries the boundary risk when it invokes the callee with `secrets: inherit`. |

## Minimum Scanner Assertions

The workflow-security lab should prove:

- at least one finding for each required class above
- exact native rule, severity, and path counts match
  `expected/workflow-security.json`
- `prod_status` remains `PRODUCTION` for workflow-security findings
- workflow-security findings are routed to `workflow_security_review`
- scan-plan generic exclusions for `.github` do not demote workflow findings as
  noise
- zero-native helper and defended fixtures remain clean
- no raw workflow YAML, real secret value, or prompt text is required in curated
  dashboard/cloud rollups

Validation command:

```bash
scan_dir="$(mktemp -d)"
reachctl scan /path/to/reach-workflow-security-testbed --ci \
  --output "$scan_dir" \
  --metadata-out "$scan_dir/metadata.json"

python ci/validate-workflow-security-results.py \
  --metadata "$scan_dir/metadata.json" \
  --repo-root /path/to/reach-workflow-security-testbed
```

Expected success output:

```text
Workflow-security expected-results validation passed
  workflow files: 22
  native findings: 85
```

See [expected/workflow-security.json](expected/workflow-security.json) for the
machine-readable expected contract.
