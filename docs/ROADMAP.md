# Roadmap

## v1.1 Candidates

- Archive scanning for `.zip`, `.tar`, `.tar.gz`, `.tgz`, and `.jar`.
- Jupyter notebook extraction.
- `--changed-only` git-aware scanning.
- Progress indicator for interactive large scans.
- Custom local rules via `--rules-dir`.
- Rule packs and named config profiles.
- Public custom-rule and streaming APIs.
- ROT13, Caesar, and bounded XOR decoding if false positives remain controlled.
- Cross-file correlation rules.
- Static self-test command.
- GitLab SAST report format.
- Single-file static HTML report.

## Strategic Work

- IDE/LSP integration.
- Registry package download helpers outside the scan phase.
- Pinned community allowlists downloaded outside scan time.
- Signed releases, SBOM, reproducible build instructions, signature signing, and SLSA provenance.
