# Expected Workflow-Security Results

This file is the human-readable expected-results contract for the public
workflow-security support testbed.

The exact number of findings can change as REACHABLE adds deterministic rules or
optional tool integrations. The required contract is the set of covered risk
classes and the defended cases that should remain clean.

## Required Classes

Golden baseline:

| Baseline dimension | Expected |
|---|---:|
| Workflow fixture files | 11 |
| Native REACHABLE workflow-security findings | 24 |
| High-risk native findings | 19 |
| Medium-risk native findings | 4 |
| Low-risk native findings | 1 |
| Defended native-control files | 2 |

The exact optional-tool count can change as `zizmor` and `actionlint` evolve.
For that reason, CI should validate the exact native REACHABLE contract and
treat optional tool output as corroborating evidence.

| Required class | Risk | Expected evidence | Remediation guidance |
|---|---|---|---|
| `cicd_command_injection` | Attacker-controlled GitHub event data reaches shell or script execution. | PR title, issue/comment text, or workflow input used in `run` or `actions/github-script`. | Move untrusted values into quoted environment variables, validate/escape input, or avoid executing event-controlled content. |
| `cicd_auth_logic_error` | A privileged workflow can run from a low-trust trigger without an explicit local authorization guard. | `pull_request_target`, `issue_comment`, or `workflow_run` with write/OIDC/secret/release authority and no visible gate. | Add actor/association/base-ref/environment protection checks and reduce permissions to least privilege. |
| `cicd_artifact_integrity_gap` | A release/deploy path consumes artifact or cache data without digest/provenance verification. | `download-artifact`, `upload-artifact`, or cache use near release/deploy/package authority. | Bind artifacts to digest/provenance, use attestations, and verify before privileged consumption. |
| `cicd_cross_workflow_poisoning` | Low-trust workflow state can cross into a privileged workflow. | `workflow_run` or reusable workflow boundary with artifact/cache/secrets crossing trust levels. | Split trust zones, require provenance and environment gates, and avoid `secrets: inherit` from untrusted callers. |
| `cicd_secret_authority_exposure` | Low-trust workflow path can access secret, token, OIDC, or package authority. | References to `secrets.*`, write permissions, or OIDC in externally reachable workflows. | Remove secrets from external triggers, use environment protection, and scope tokens to read-only unless release authority is required. |
| `cicd_untrusted_checkout` | Privileged workflow checks out attacker-controlled code. | `actions/checkout` with PR head ref in a privileged trigger. | Checkout trusted base ref, inspect patch data separately, or run untrusted code only in a low-privilege workflow. |
| `cicd_self_hosted_runner_exposure` | External trigger can reach persistent self-hosted infrastructure. | `runs-on: self-hosted` in a low-trust workflow. | Use GitHub-hosted ephemeral runners for external events or add strict isolation and approval gates. |
| `cicd_unpinned_action` | Mutable third-party actions can change without review. | `uses: owner/action@vN` or branch refs. | Pin to full commit SHA and update through reviewed dependency changes. |

## Defended Controls

| Fixture | Expected result | Why |
|---|---|---|
| `.github/workflows/defended-internal-release.yml` | No Cordyceps finding expected from native rules. | Internal `push` trigger, read-only permissions, SHA-pinned action, no low-trust entry. |
| `.github/workflows/defended-guarded-pr.yml` | No auth-logic finding expected. | Low-trust trigger is guarded by actor/association checks and uses read-only permissions. |

## Minimum Scanner Assertions

The public support testbed should prove:

- at least one finding for each required class above
- `prod_status` remains `PRODUCTION` for workflow-security findings
- workflow-security findings are routed to `workflow_security_review`
- scan-plan generic exclusions for `.github` do not demote workflow findings as
  noise
- no raw workflow YAML, real secret value, or prompt text is required in curated
  dashboard/cloud rollups

Validation command:

```bash
python ci/validate-workflow-security-results.py \
  --raw /path/to/scan/raw/workflow-security.json \
  --repo-root /path/to/reach-workflow-security-testbed
```

Expected success output:

```text
Workflow-security expected-results validation passed
  workflow files: 11
  native findings: 24
```

See [expected/workflow-security.json](expected/workflow-security.json) for the
machine-readable expected contract.
