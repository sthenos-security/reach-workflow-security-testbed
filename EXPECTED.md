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
| Workflow fixture files | 39 |
| Native-positive workflow files | 30 |
| Zero-native fixture files | 10 |
| Native REACHABLE workflow-security findings | 142 |
| Critical native findings | 33 |
| High-risk native findings | 93 |
| Medium-risk native findings | 10 |
| Low-risk native findings | 6 |
| Required native classes | 23 |
| Defended native-control files | 4 |

The exact optional-tool count can change as `zizmor` and `actionlint` evolve.
For that reason, CI should validate the exact native REACHABLE contract,
including class/rule/path counts, and treat optional tool output as
corroborating evidence.

The native workflow-security baseline excludes duplicate generic secret-scanner
rows for workflow YAML. Workflow secret references such as
`${{ secrets.NPM_TOKEN }}` are modeled as workflow authority evidence, not as
literal leaked secret values. Path-backed findings are validated from persisted
workflow review payload when the DB raw-data copy is size-capped.

The Poutine-derived and Scorecard-derived fixtures are original synthetic
benchmark cases based on the accepted REACHABLE coverage-gap list. They are not
copied from upstream Poutine or Scorecard test code, and each positive case is
expected to be useful only when REACHABLE can connect a low-trust source,
workflow edges, authorities, and a sink.

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

## Poutine and Scorecard Gap Fixtures

| Fixture | Gap | Expected class |
|---|---|---|
| `.github/workflows/scorecard-dangerous-script-injection.yml` | Dangerous workflow script injection from untrusted PR metadata into shell. | `cicd_command_injection` |
| `.github/workflows/scorecard-default-write-token.yml` | Risky external trigger with inherited/default token authority and no local gate. | `cicd_auth_logic_error`, `cicd_trigger_abuse` |
| `.github/workflows/scorecard-token-permission-matrix.yml` | Read-only and SARIF-only controls stay non-path evidence while job-level package write reaches package publish. | `cicd_secret_authority_exposure` with `explicit_sensitive_write` and `packages` evidence |
| `.github/workflows/scorecard-untrusted-checkout-pr-head.yml` | Privileged workflow checks out pull-request head code. | `cicd_untrusted_checkout` |
| `.github/workflows/scorecard-build-component-posture-context.yml` | Actions, containers, remote downloads, signed-release/provenance, SAST, dependency-update, SBOM, packaging, and branch context attached to a real release path. | `cicd_secret_authority_exposure` with build-component and posture evidence |
| `.github/workflows/scorecard-pinned-dependencies-download-execute.yml` | Remote bootstrap download-execute reaches release authority without checksum, signature, or provenance binding. | `cicd_secret_authority_exposure` with `download_execute_without_integrity` component evidence |
| `.gitlab-ci.yml` + `.gitlab-includes/deploy.yml` | Local GitLab include traversal from parent pipeline into included deploy job. | `cicd_secret_authority_exposure` attributed to the included deploy file |
| `.github/workflows/poutine-all-secrets-exposure.yml` | Wildcard/all-secrets object exposure on a low-trust path. | `cicd_secret_authority_exposure` |
| `.github/workflows/poutine-debug-logging-exposure.yml` | Debug logging as a UI-visible secret exposure amplifier. | `cicd_step_summary_exfiltration`, `cicd_secret_exfiltration_path` |
| `.github/workflows/poutine-malformed-if-fail-open.yml` | Malformed authorization `if:` guard in front of release authority. | `cicd_auth_logic_error`, `cicd_secret_authority_exposure` |
| `.github/workflows/poutine-bot-auto-merge-confused-deputy.yml` | Bot identity trusted as auto-merge authorization without dependency-source provenance. | `cicd_auth_logic_error`, `cicd_untrusted_checkout` |

## Defended Controls

| Fixture | Expected result | Why |
|---|---|---|
| `.github/workflows/defended-internal-release.yml` | No Cordyceps finding expected from native rules. | Internal `push` trigger, read-only permissions, SHA-pinned action, no low-trust entry. |
| `.github/workflows/defended-guarded-pr.yml` | No auth-logic finding expected. | Low-trust trigger is guarded by actor/association checks and uses read-only permissions. |
| `.github/workflows/defended-explicit-readonly-token.yml` | No native finding expected. | Low-trust trigger is guarded, permissions are explicit read-only, and no release, package, checkout, or secret sink is present. |
| `.github/workflows/defended-untrusted-checkout.yml` | No native finding expected. | Low-trust trigger is guarded, permissions are read-only, and checkout stays on the trusted base boundary with a SHA-pinned action. |
| `.github/workflows/defended-verified-download-execute.yml` | No native finding expected. | Remote content is checksum-verified before execution and the workflow has read-only token permissions. |

## Zero-Native Helper

| Fixture | Expected result | Why |
|---|---|---|
| `.github/workflows/reusable-inherit-secrets.yml` | No native finding expected on the callee by itself. | The reusable callee is inert on its own; the low-trust caller carries the boundary risk when it invokes the callee with `secrets: inherit`. |
| `azure-pipelines.yml` | No native finding expected. | Azure Pipelines is inventory-only until source-to-sink semantics are fixture-proven. |
| `.tekton/pipeline.yaml` | No native finding expected. | Tekton is inventory-only until source-to-sink semantics are fixture-proven. |
| `.gitlab-ci.yml` | No native finding expected on the root include file. | The source-to-sink finding is attributed to `.gitlab-includes/deploy.yml`. |
| `.github/workflows/defended-sarif-only-token.yml` | No native finding expected. | SARIF upload uses security-events write only, read contents, and a SHA-pinned upload action. |
| `.github/workflows/defended-verified-download-execute.yml` | No native finding expected. | Remote content is checksum-verified before execution and the workflow has read-only token permissions. |

## Minimum Scanner Assertions

The workflow-security lab should prove:

- at least one finding for each required class above
- exact native rule, severity, and path counts match
  `expected/workflow-security.json`
- `prod_status` remains `PRODUCTION` for workflow-security findings
- path-backed workflow findings are routed to `workflow_security_review`
- non-path native/tool candidates stay out of workflow AI review unless graph
  correlation attaches `WorkflowPath` proof
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
  workflow files: 39
  native findings: 142
```

See [expected/workflow-security.json](expected/workflow-security.json) for the
machine-readable expected contract.
