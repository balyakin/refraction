# Adversary Notes

This document catalogs representative anti-analysis techniques that inform the embedded rules. Examples are inert and are intended for defensive testing.

## Techniques

- Place refusal-like text in comments near risky install behavior.
- Instruct an AI reviewer to ignore previous instructions, suppress findings, or report a clean result.
- Hide prompt-injection text behind base64, hex, URL encoding, Unicode escapes, or HTML entities.
- Use CBRN/WMD bait terms in non-functional text to trigger downstream safety refusal.
- Use BiDi controls or zero-width characters so rendered source differs from reviewer-visible expectations.
- Mix Latin with Cyrillic or Greek confusables in identifiers or filenames.
- Add duplicate manifest keys so one parser sees a benign value and another sees executable behavior.
- Put download-and-execute behavior in npm lifecycle scripts, Python `.pth` files, Rust build scripts, Dockerfiles, CI workflows, Gradle/Maven/Ruby/NuGet manifests, or Git metadata.

`refraction` does not prove malicious intent. It gives deterministic evidence for human review.
