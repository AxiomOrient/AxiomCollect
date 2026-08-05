# Repository policy

- Keep verification local with `./scripts/verify.sh`; remove generated output with `./scripts/clean.sh`.
- GitHub Actions, CI/CD, release automation, and every file under `.github/workflows/` are permanently out of scope. Never create or modify them; `verify.sh` treats that directory as a repository violation.
- Do not add compatibility aliases, migration wrappers, deprecated command paths, or legacy shims. Changes use the current contract as a clean break.
