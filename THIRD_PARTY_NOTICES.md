# Third-party notices

This source publication uses the direct Rust dependencies declared in
[`Cargo.toml`](Cargo.toml). The versions below are the versions selected by
[`Cargo.lock`](Cargo.lock); the SPDX expressions are the `license` values
reported by `cargo metadata --locked` for those lock-selected package
manifests. This is factual attribution, not a legal conclusion.

Only direct entries under `[dependencies]` are listed in the table. Cargo.lock
also records transitive and build-time packages needed to compile the source;
they are not direct dependencies and are not repeated here. Consult the lock
file and each package's upstream metadata for that complete resolved graph.

## Direct Rust dependencies

| Component | Cargo.toml requirement | Cargo.lock version | SPDX license expression |
| --- | --- | --- | --- |
| `aho-corasick` | `1.1` | `1.1.4` | `Unlicense OR MIT` |
| `base64` | `=0.23.0` | `0.23.0` | `MIT OR Apache-2.0` |
| `clap` | `4.5` | `4.6.4` | `MIT OR Apache-2.0` |
| `ego-tree` | `0.11` | `0.11.0` | `ISC` |
| `encoding_rs` | `0.8.35` | `0.8.35` | `(Apache-2.0 OR MIT) AND BSD-3-Clause` |
| `eoka` | `=0.5.4` | `0.5.4` | `MIT` |
| `futures-util` | `0.3.31` | `0.3.33` | `MIT OR Apache-2.0` |
| `iana-time-zone` | `0.1.65` | `0.1.65` | `MIT OR Apache-2.0` |
| `lopdf` | `=0.44.0` | `0.44.0` | `MIT` |
| `process-wrap` | `9.0` | `9.1.0` | `Apache-2.0 OR MIT` |
| `quick_html2md` | `0.2.1` | `0.2.1` | `MIT OR Apache-2.0` |
| `regex` | `1.13` | `1.13.1` | `MIT OR Apache-2.0` |
| `reqwest` | `0.13.4` | `0.13.4` | `MIT OR Apache-2.0` |
| `rmcp` | `3.0.1` | `3.0.1` | `Apache-2.0` |
| `schemars` | `1.2` | `1.2.2` | `MIT` |
| `scraper` | `0.27.0` | `0.27.0` | `ISC` |
| `serde` | `1.0` | `1.0.229` | `MIT OR Apache-2.0` |
| `serde_json` | `1.0` | `1.0.151` | `MIT OR Apache-2.0` |
| `serde_yaml` | `0.9` | `0.9.34+deprecated` | `MIT OR Apache-2.0` |
| `sha2` | `0.11.0` | `0.11.0` | `MIT OR Apache-2.0` |
| `tempfile` | `3.23` | `3.27.0` | `MIT OR Apache-2.0` |
| `tokio` | `1.51.0` | `1.53.1` | `MIT` |
| `tokio-util` | `0.7` | `0.7.19` | `MIT` |
| `url` | `2.5` | `2.5.8` | `MIT OR Apache-2.0` |

The feature selections and `default-features` settings for these components
remain exactly those in `Cargo.toml`; this table does not imply any additional
features. A bare version in the requirement column is Cargo's implicit caret
requirement.

## Optional operator-managed Puppeteer Core

The rescue path is not bundled with the Rust source or installed by the Rust
binary. If an operator provisions the optional Node runtime described in
[`puppeteer-rescue/package.json`](puppeteer-rescue/package.json), it directly
uses:

| Component | package.json requirement | package-lock.json version | SPDX license expression |
| --- | --- | --- | --- |
| `puppeteer-core` | `25.4.0` | `25.4.0` | `Apache-2.0` |

The exact npm resolution is recorded in
[`puppeteer-rescue/package-lock.json`](puppeteer-rescue/package-lock.json).
That lock also contains Puppeteer Core's transitive npm packages; they are
operator-managed and outside this source-only publication. Puppeteer Core does
not download a browser through this project.

## Source-only publication limits

This repository publishes source, manifests, lockfiles, and documentation. It
does not publish `target/` output, a Node `node_modules/` tree, browser binaries,
or runtime artifacts. Build and runtime evidence therefore depends on the
operator's toolchain and installed browser; this notice does not assert that
such environment-specific evidence is included here.
