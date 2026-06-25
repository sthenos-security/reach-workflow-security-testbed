# reach-workflow-security-testbed

**Intentionally vulnerable CI/CD workflow-security testbed. Not for production use.**

This public repository is a controlled fixture corpus for validating REACHABLE
CI/CD workflow-code analysis. It focuses on GitHub Actions, Cordyceps-style
workflow attacks, secret/release authority boundaries, and defended control
examples.

The workflows are designed for scanner validation, documentation screenshots,
and repeatable release proof. They are not application workflows and must not be
copied into production repositories.

## Expected Validation Result

The machine-readable baseline is
[expected/workflow-security.json](expected/workflow-security.json). The public
proof target is:

| Dimension | Expected |
|---|---:|
| Workflow fixture files | 11 |
| Native REACHABLE workflow-security findings | 27 |
| High-risk native findings | 22 |
| Medium-risk native findings | 4 |
| Low-risk native findings | 1 |
| Required risk classes | 9 |
| Defended native-control files | 2 |

Optional tools such as `zizmor` and `actionlint` may add corroborating rows.
The stable validation contract is the native REACHABLE finding set plus the
required testcase detections.

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
| Defended controls | `.github/workflows/defended-internal-release.yml` and `.github/workflows/defended-guarded-pr.yml` | no Cordyceps finding expected |

## How To Validate

From a local REACHABLE checkout:

```bash
reachctl scan /path/to/reach-workflow-security-testbed --ci
```

Then validate the raw workflow-security artifact:

```bash
python ci/validate-workflow-security-results.py \
  --raw /path/to/scan/raw/workflow-security.json \
  --repo-root /path/to/reach-workflow-security-testbed
```

Expected result:

- workflow-security scanning finds deterministic Cordyceps classes
- workflow-security findings remain production/security-relevant even though the
  files are under `.github/workflows`
- optional tool health for `zizmor` and `actionlint` is reported separately from
  native coverage
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

This is the expanded support testbed for workflow-security regression proof.
It is not the main customer demo and not the Marketplace action repository.

| Repo | Role |
|---|---|
| `reach-workflow-security-testbed` | Public support corpus for CI/CD workflow-code security and Cordyceps fixtures. |
| `reach-testbed-github-go` | Small public customer-facing remediation demo. |
| `reach-ci-github` | Public reusable GitHub Actions toolkit. |
| `reach-testbed-github-marketplace` | GitHub Marketplace distribution repository. |

## Copyright

Copyright (c) 2026 Sthenos Security. All rights reserved.
