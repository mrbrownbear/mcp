---
name: release
description: Release a new version of the Novamira plugin with bin/release — the non-interactive step flow, the changelog entry, new-file checks, the manual commit/tag/push stop, and the rollout decision. Use whenever the user asks to cut, ship, publish, or finalize a release, or when a bin/release run stops and needs to be resumed.
---

# Releasing Novamira

Run the release as `bin/release VERSION --non-interactive`. It never waits for input: any step that needs a decision fails with the reason and the `RESUME_FROM="step name"` command to continue after fixing it. `bin/release --list-steps` lists the step names.

## Before starting

Write the changelog entry first, at the top of `CHANGELOG.txt` with no version header — the release assigns `vVERSION - date`. Proofread it yourself; this mode does not spellcheck.

NEVER modify `release-info.json` by hand unless explicitly instructed to do so; it is modified programmatically.

## Steps that stop the run

- **"check files"** fails when the zip ships files the previous release did not. Read the list: anything that does not belong in a plugin distributed to users goes in `build/build-ignore`. Re-run with `--accept-new-files` once the additions are meant to ship, and show the user the list when it is not obvious.
- **"commit release"** verifies rather than commits. The first run stops there; commit, tag and push as instructed, then resume with `RESUME_FROM="commit release"`.

## Rollout — always the user's call

The run then stops with exit code 10: everything is uploaded, but the version is not live. **Ask the user how to roll it out** — instantly, or gradually over 6, 12, 24, 72 or 168 hours — and never choose for them.

Then carry out their answer:

```sh
bin/release VERSION --finalize --rollout-hours N
bin/release VERSION --finalize --instant
```
