# krecon

**Kernel Reconnaissance — Hybrid deterministic + LLM-assisted Linux kernel commit exploitability analysis.**

krecon analyzes upstream Linux kernel commits against a target kernel `.config` to identify potentially exploitable changes. It uses a two-phase approach:

1. **Phase 1 (deterministic)**: Fast-fail filtering based on Kconfig reachability — skips merge commits, docs/scripts-only changes, and disabled subsystems without LLM queries.
2. **Phase 2 (parallel LLM)**: Reachable commits are analyzed by the configured LLM model via the opencode CLI for semantic exploit primitives, privilege requirements, and bypass strategies.

## Quick Start

```bash
# Analyze 100 commits against a specific kernel config
python3 krecon.py --repo /path/to/linux --config /path/to/config-6.8.0-generic --limit 100 --parallel 4

# Resume an interrupted batch (skips already-processed commits)
python3 krecon.py --repo /path/to/linux --config /path/to/config-6.8.0-generic --limit 5000 --parallel 8 --resume

# Analyze a specific commit range and save to custom output
python3 krecon.py --repo /path/to/linux --config /path/to/config-6.8.0-generic --range v6.8..v6.9 --output krecon_v6.9.md
```

## CLI Options

| Flag | Required | Description |
| :--- | :--- | :--- |
| `--repo` | Yes | Path to local upstream Linux git repository |
| `--config` | Yes | Path to target kernel `.config` file |
| `--commit` | No | Comma-separated commit hashes to analyze |
| `--range` | No | Git revision range (e.g., `v6.8..v6.8.1`) |
| `--limit` | No | Analyze the last N commits from current branch |
| `--days` | No | Analyze commits from the last N days |
| `--parallel` | No | Parallel LLM workers (default: 1) |
| `--batch-size` | No | Commits per LLM batch (default: 7) |
| `--model` | No | LLM model to use (default: `xai/grok-4.20-0309-reasoning`) |
| `--output` | No | Output report path (default: `krecon_report.md` in cwd) |
| `--resume` | No | Skip commits already REACHABLE in existing report |

## Config File

Instead of passing all options on the command line, you can use a JSON config file:

```bash
# With config file (krecon.json in current directory)
python3 krecon.py

# Or specify a custom config path
python3 krecon.py --krecon-config /path/to/config.json

# Config file path can also be set via KRECON_CONFIG env var
export KRECON_CONFIG=/path/to/config.json
python3 krecon.py
```

Example `krecon.json`:
```json
{
  "repo": "/path/to/linux",
  "config": "/path/to/config-6.8.0-generic",
  "parallel": 12,
  "batch_size": 7,
  "model": "xai/grok-4.20-0309-reasoning",
  "output": "krecon_report.md"
}
```

Config file keys use underscore naming (`batch_size`, `opencode_bin`, `opencode_config`). CLI arguments override config file values.

## Output Format

The report is written incrementally after each LLM result, so partial results survive timeout or interruption.

```
# Batch Kernel Commit Exploitability Triage Report
* **Target Config:** `config-6.8.0-117-generic`
* **Total Commits Analyzed:** 100
* **Parallel Workers:** 4

---

## Triage Summary Table
| Commit Hash | Subject | Status | Controlling Symbol | Feasibility Index |
| :--- | :--- | :--- | :--- | :--- |

---

## Detailed Commit Reports

### Commit `abc123...`: subject
* **Verdict:** REACHABLE (FEASIBILITY INDEX: 8.0 / 10.0)
* **Reachability table...**
* **Hardening & Mitigation table...**
* **LLM semantic analysis...**
```

## Architecture

### Kconfig Symbol Resolution

krecon resolves which `CONFIG_*` symbol controls a modified `.c` file by traversing parent Makefiles:

| Pattern | Example | Resolved Symbol |
| :--- | :--- | :--- |
| Simple module | `obj-$(CONFIG_XYZ) += file.o` | `CONFIG_XYZ` |
| Conditional sub-feature | `erofs-$(CONFIG_EROFS_FS_XATTR) += xattr.o` | `CONFIG_EROFS_FS_XATTR` |
| Composite (objs) | `nf_tables-objs := nf_tables_api.o nf_tables_core.o` | `CONFIG_NF_TABLES` |

A commit is **REACHABLE** if at least one modified `.c` file maps to a `CONFIG_*` symbol that is `y` or `m` in the target `.config`. Otherwise it is **UNREACHABLE** (fast-failed, no LLM query).

### Hardening Score

Base feasibility score: **8.0 / 10.0**

| Mitigation | Effect |
| :--- | :--- |
| `CONFIG_USER_NS=y` | **+1.5** (unprivileged namespace entry points) |
| `CONFIG_SLAB_FREELIST_RANDOM=y` | **-0.5** |
| `CONFIG_SLAB_FREELIST_HARDENED=y` | **-0.5** |
| `CONFIG_RANDOM_KMALLOC_CACHES=y` | **-1.5** (same-size kmalloc reuse blocked) |
| `CONFIG_CFI_CLANG=y` | **-1.5** (control flow integrity) |

### LLM Integration

Reachable commits are sent to the LLM via `opencode run` with:
- Full commit message and diff
- Per-file Kconfig reachability status
- Target hardening posture

The LLM is instructed to respond with:
1. Summary & Root Cause
2. Exploit Primitives
3. Privilege Requirements
4. Bypass Strategy

## Requirements

- Python 3
- Local Linux upstream git repository
- Target kernel `.config`
- opencode CLI (model: `xai/grok-4.20-0309-reasoning` by default, configurable via `--model` and `--opencode-bin`)
