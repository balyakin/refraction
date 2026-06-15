# Threat Model

`refraction` addresses content-based anti-analysis attacks against automated security review, especially review stages that include AI or LLM tooling.

## In Scope

- Refusal-trigger injection: text crafted to make an AI reviewer refuse to inspect an artifact.
- Prompt injection: instructions that override scanner, reviewer, or system prompts.
- CBRN/WMD bait: non-functional text used as policy-trigger bait rather than functional package behavior.
- Obfuscation: bounded base64, hex, URL, Unicode escape, and HTML entity encoding that hides suspicious text.
- Trojan Source and confusables: BiDi controls, zero-width clusters, mixed-script identifiers, and filename collisions.
- Manifest tamper: duplicate JSON keys, YAML merge/anchor abuse, and TOML alternate forms that hide lifecycle behavior.
- Install hooks: package or build surfaces that can run code during installation or CI.

## Out of Scope

- Malware classification, antivirus reputation, or cloud lookups.
- Executing code, installing packages, or invoking package managers.
- Archive unpacking in v1.
- Full language-aware SAST.
- LLM or ML inference.

## Security Properties

Scans are deterministic for identical inputs, options, and signature data. The scanner uses only local content, bounded reads, stable fingerprints, and masked snippets. It records file read and ignore warnings in machine-readable reports.
