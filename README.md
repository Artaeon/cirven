<img src="brand/cirven-logo.svg" width="360" alt="CIRVEN SYSTEMS">

# cirven systems

Open-source defense modules for Linux developer workstations.
Website: <https://cirven.dev>

| module | does | status |
|---|---|---|
| `audit`  | find weaknesses, rank them by real attack paths | planned |
| `harden` | fix findings: preview, apply, roll back | planned |
| `watch`  | detect persistence: new units, autostarts, hooks | planned |
| `lure`   | decoy credentials that alarm when touched | planned |
| `pkg`    | inspect AUR/npm/pip packages before install | planned |
| `cage`   | sandbox tools and AI agents to what they need | planned |
| `key`    | hardware key + password; unplug and it all locks | planned |

Each module is described in detail, threat model included, under `site/modules/`.

## Principles

- Local first, works offline, no account required, no telemetry.
- Every change is previewed and reversible.
- Every module ships a threat model: what it stops and what it does not.
- Least privilege, signed releases, reproducible builds.

## Roadmap

1. `audit` + `harden`: know and fix your own machine
2. `watch` + `lure`: notice when someone gets in
3. `pkg` + `cage`: stop it before it runs
4. `key`: tie it all to hardware

## License & business model

All code is Apache-2.0 and free. A paid, optional **cirven relay** may come later:
hosted alerting for `lure`, a signed package-intel feed for `pkg` and a fleet view
for teams. Self-hosting stays possible. Nothing is sold before it works.

## Build

Requires Rust 1.85+.

```
cargo build --release
./target/release/cirven modules
./target/release/cirven audit
```

Every module currently answers `not implemented yet` with exit code 64.

## Repository layout

```
crates/cirven/          the `cirven` binary: one subcommand per module
crates/cirven-core/     shared types: module metadata, findings, severities, errors
crates/cirven-<module>/ one crate per module, design notes in its lib.rs
site/                   the website: static HTML + one CSS file, no JavaScript
brand/                  logo (PNG original, traced SVG) and wallpapers
```

Modules are separate crates so each keeps its own dependency tree and attack
surface: `cage` and `key` will need kernel and hardware interfaces that `audit` never should.

## Website

```
make serve   # preview on http://127.0.0.1:8000
make size    # bytes per page, raw and gzipped
make check   # fails on scripts, inline styles, event handlers, third-party URLs
```

Deploy `site/` to Cloudflare Pages (or Netlify). Both read `site/_headers`, which sets
a strict CSP, HSTS and the other security headers. GitHub Pages cannot set headers.
