# Scripts

| Script | What it does |
|---|---|
| `build-dmg.sh` | Builds a release `ISAT.app` and wraps it in an unsigned `.dmg` under `dist/`. Gatekeeper blocks it until you run `xattr -dr com.apple.quarantine /Applications/ISAT.app`. |
| `acquire-licenses.sh` | Gets App Store licences for a list of bundle IDs one at a time, so a later download run does not stop at the 2FA prompt. Usage: `acquire-licenses.sh <bundle-ids.txt> [delay_seconds]`. |
| `cvss4-score.mjs` | Scores one CVSS v4.0 vector with FIRST's calculator from `vendor/cvss-v4/`. |
| `cvss4-fill.mjs` | Fills `cvssScore` for every `cvss` rule in `taxonomy/severity-derivation.json`. Run after editing a vector. |
| `sync-rule-severities.py` | Writes the derived band into the `severity:` key of every `vectors/*.yaml`. |
| `sync-mas-catalogues.py` | Regenerates `taxonomy/{maswe,mastg,masvs}.json` from the OWASP repositories. `--check` exits 1 when upstream has changed. |
| `dashboard-smoke.mjs` | Runs the dashboard scripts in Node with a stub DOM to catch a broken chart setup. |
