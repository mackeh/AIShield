# Releasing AIShield

AIShield uses tag-driven GitHub Releases.

## Prerequisites

- `main` is green in CI
- `CHANGELOG.md` has an updated `Unreleased` section
- version/tag follows semver (`v0.1.1`, `v0.2.0`, ...)

## Release Steps

1. Move relevant `Unreleased` entries into a new version section in `CHANGELOG.md`.
2. Commit the changelog update.
3. Create and push the tag:

```bash
git tag -a v0.1.1 -m "AIShield v0.1.1"
git push origin v0.1.1
```

4. GitHub Actions workflow `.github/workflows/release.yml` automatically creates/updates the release with generated notes.

## Manual Rerun

If a tag already exists and you need to recreate/update release metadata:

- run workflow `Release` via `workflow_dispatch`
- pass the tag name (for example `v0.1.1`)

## Notes

- Generated notes come from commit history/PR metadata.
- `CHANGELOG.md` remains the curated source of release highlights.
