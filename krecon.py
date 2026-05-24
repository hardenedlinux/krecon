#!/usr/bin/env python3
import os
import sys
import re
import argparse
import shutil
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice

OPENCODE_BIN = os.environ.get("OPENCODE_BIN", None)

class KernelTriageEngine:
    def __init__(self, repo_path, config_path, model="xai/grok-4.20-0309-reasoning", opencode_bin=None):
        self.repo_path = os.path.abspath(repo_path)
        self.config_path = os.path.abspath(config_path)
        self.target_config = self._parse_config(self.config_path)
        self.model = model
        self.opencode_bin = opencode_bin or OPENCODE_BIN or self._find_opencode()

    def _find_opencode(self):
        for name in ("opencode", "opencode-cli"):
            path = shutil.which(name)
            if path:
                return path
        return None

    def _parse_config(self, path):
        """Parses a Linux kernel .config file into a dictionary."""
        config = {}
        if not os.path.exists(path):
            print(f"[-] Error: Target config file not found at {path}", file=sys.stderr)
            sys.exit(1)
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    parts = line.split('=', 1)
                    config[parts[0].strip()] = parts[1].strip()
        return config

    def get_commit_subject(self, commit_hash):
        """Retrieves the commit subject/title line."""
        cmd = ["git", "-C", self.repo_path, "log", "-1", "--format=%s", commit_hash]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return "Unknown Subject"

    def get_commit_details(self, commit_hash):
        """Runs git show to extract the commit message, modified files, and diff."""
        if not os.path.exists(self.repo_path):
            print(f"[-] Error: Local git repository not found at {self.repo_path}", file=sys.stderr)
            sys.exit(1)

        cmd = ["git", "-C", self.repo_path, "show", commit_hash]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"[-] Error running git show for {commit_hash}: {result.stderr.strip()}", file=sys.stderr)
            return None

        output = result.stdout
        
        modified_files = []
        for line in output.splitlines():
            if line.startswith("+++ "):
                path = line[4:].strip()
                if path.startswith("b/"):
                    path = path[2:]
                if path != "dev/null":
                    modified_files.append(path)

        parts = output.split("\ndiff --git", 1)
        commit_msg = parts[0]
        diff = parts[1] if len(parts) > 1 else ""

        return {
            "commit_msg": commit_msg,
            "diff": diff,
            "modified_files": modified_files
        }

    def resolve_kconfig_symbol(self, file_path):
        """
        Recursively resolves the Kconfig symbol for a given source file by
        parsing parent directories' Makefiles.
        """
        dir_name = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        obj_name = base_name.replace(".c", ".o")

        makefile_path = os.path.join(self.repo_path, dir_name, "Makefile")
        if not os.path.exists(makefile_path):
            makefile_path = os.path.join(self.repo_path, dir_name, "Kbuild")
        
        if not os.path.exists(makefile_path):
            return None

        with open(makefile_path, 'r') as f:
            content = f.read()

        # Handle simple single-file module rule: obj-$(CONFIG_XYZ) += file.o
        pattern = r"obj-\$\((CONFIG_[A-Za-z0-9_]+)\)\s+[\+:]=\s+.*" + re.escape(obj_name)
        match = re.search(pattern, content)
        if match:
            return match.group(1)

        # Handle conditional sub-feature module definitions: erofs-$(CONFIG_EROFS_FS_XATTR) += xattr.o
        cond_pattern = r"([A-Za-z0-9_\-]+)-\$\((CONFIG_[A-Za-z0-9_]+)\)\s+[\+:]=\s+.*" + re.escape(obj_name)
        cond_match = re.search(cond_pattern, content)
        if cond_match:
            return cond_match.group(2)

        # Handle composite module definitions: obj-$(CONFIG_NF_TABLES) += nf_tables.o
        #       nf_tables-objs := nf_tables_api.o nf_tables_core.o
        composite_pattern = r"([A-Za-z0-9_\-]+)-objs\s+[\+:]=\s+.*" + re.escape(obj_name)
        composite_match = re.search(composite_pattern, content)
        if not composite_match:
            composite_pattern = r"([A-Za-z0-9_\-]+)-y\s+[\+:]=\s+.*" + re.escape(obj_name)
            composite_match = re.search(composite_pattern, content)

        if composite_match:
            parent_obj = composite_match.group(1) + ".o"
            parent_pattern = r"obj-\$\((CONFIG_[A-Za-z0-9_]+)\)\s+[\+:]=\s+.*" + re.escape(parent_obj)
            parent_match = re.search(parent_pattern, content)
            if parent_match:
                return parent_match.group(1)

        return None

    def evaluate_reachability(self, modified_files):
        """Checks if at least one modified file is compiled based on the target config."""
        reachability_map = {}
        any_reachable = False

        for f in modified_files:
            if not f.endswith('.c'):
                continue
            symbol = self.resolve_kconfig_symbol(f)
            if symbol:
                state = self.target_config.get(symbol, "is not set")
                if "is not set" not in state:
                    any_reachable = True
                    reachability_map[f] = {"symbol": symbol, "status": "ENABLED" if state == "y" else "MODULE"}
                else:
                    reachability_map[f] = {"symbol": symbol, "status": "DISABLED"}
            else:
                reachability_map[f] = {"symbol": "Unknown", "status": "FALLBACK"}
                any_reachable = True

        return any_reachable, reachability_map

    def calculate_hardening_score(self):
        """Calculates a base feasibility score and details based on active mitigations."""
        score = 8.0
        mitigations = {}

        userns = self.target_config.get("CONFIG_USER_NS", "is not set")
        if userns == "y":
            mitigations["CONFIG_USER_NS"] = "Enabled (Unprivileged namespace entryways active)"
            score += 1.5
        else:
            mitigations["CONFIG_USER_NS"] = "Disabled"

        freelist_rand = self.target_config.get("CONFIG_SLAB_FREELIST_RANDOM", "is not set")
        if freelist_rand == "y":
            mitigations["CONFIG_SLAB_FREELIST_RANDOM"] = "Enabled (-0.5)"
            score -= 0.5

        freelist_hard = self.target_config.get("CONFIG_SLAB_FREELIST_HARDENED", "is not set")
        if freelist_hard == "y":
            mitigations["CONFIG_SLAB_FREELIST_HARDENED"] = "Enabled (-0.5)"
            score -= 0.5

        random_caches = self.target_config.get("CONFIG_RANDOM_KMALLOC_CACHES", "is not set")
        if random_caches == "y":
            mitigations["CONFIG_RANDOM_KMALLOC_CACHES"] = "Enabled (-1.5)"
            score -= 1.5

        cfi = self.target_config.get("CONFIG_CFI_CLANG", "is not set")
        if cfi == "y":
            mitigations["CONFIG_CFI_CLANG"] = "Enabled (-1.5)"
            score -= 1.5

        return min(max(score, 0.0), 10.0), mitigations

    def invoke_opencode_llm(self, commit_msg, diff, reachability_info):
        """Invokes the configured LLM model via opencode run CLI."""
        prompt = f"""You are a senior Linux Kernel security researcher and exploit developer.
Analyze the following patch and commit metadata to determine its vulnerability class, triggering requirements, and exploit primitives.

--- COMMIT DETAILS ---
{commit_msg}

--- CODE DIFF ---
{diff}

--- COMPILE-TIME REACHABILITY ---
{json.dumps(reachability_info, indent=2)}

Format your assessment strictly in clean Markdown:
1. **Summary & Underlying Root Cause**: Detailed explanation of why the bug occurs.
2. **Exploit Primitives**: What can an attacker achieve? (e.g., UAF reclamation, controlled OOB write, information leaks).
3. **Privilege Requirements**: Does this require local unprivileged access, namespaces (user/net), or physical/root access?
4. **Bypass Strategy**: How would an attacker bypass enabled protections based on the primitive type?
"""
        cmd = [
            self.opencode_bin, "run",
            "-m", self.model,
            "--dangerously-skip-permissions",
            "--prompt-file", "-"
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, input=prompt)
        if result.returncode != 0:
            return f"[-] Error querying LLM: {result.stderr.strip()}"
        return result.stdout

    def invoke_opencode_llm_batch(self, batch_items):
        """
        Invokes the LLM with multiple commits in a single prompt.
        batch_items: list of (commit_hash, subject, commit_msg, diff, reachability_info, score, mitigations)
        Returns: list of LLM output strings (one per commit), or None for errors.
        """
        n = len(batch_items)
        commits_section = ""
        for i, (commit_hash, subject, commit_msg, diff, reachability_info, score, mitigations) in enumerate(batch_items, 1):
            commits_section += f"""--- COMMIT {i}/{n} ---
Subject: {subject}
Commit Hash: {commit_hash}

--- CODE DIFF ---
{diff}

--- COMPILE-TIME REACHABILITY ---
{json.dumps(reachability_info, indent=2)}

--- HARDENING CONTEXT ---
"""
            for opt, status in mitigations.items():
                commits_section += f"- {opt}: {status}\n"

        prompt = f"""You are a senior Linux Kernel security researcher and exploit developer.
Analyze each of the following {n} kernel commits independently and determine its vulnerability class, triggering requirements, and exploit primitives.

{commits_section}

CRITICAL REQUIREMENTS:
- You MUST respond for ALL {n} commits. Do NOT skip any commit, even if it seems unimportant.
- Respond in the EXACT format below, one block per commit, in the same order as listed above.
- Do NOT combine, merge, or omit any section. Every commit gets its own complete block.
- Do NOT let one commit's analysis influence another. Treat each in complete isolation.

For EACH of the {n} commits, provide this EXACT format (fill in angle brackets):

===== COMMIT 1/{n} =====
## Commit Hash
<full 40-char commit hash>

## Subject
<one-line subject>

## Summary & Underlying Root Cause
<detailed explanation of why the bug occurs>

## Exploit Primitives
<what attackers can achieve: e.g., UAF, OOB write, info leak>

## Privilege Requirements
<local unprivileged / namespace / root>

## Bypass Strategy
<how to evade protections>
===== END COMMIT 1/{n} =====

Repeat this exact block format for EVERY commit (2/{n}, 3/{n}, ... {n}/{n}). Each must be complete with all sections.
"""
        cmd = [
            self.opencode_bin, "run",
            "-m", self.model,
            "--dangerously-skip-permissions",
            "--prompt-file", "-"
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, input=prompt)
        if result.returncode != 0:
            return [None] * n
        return self._parse_batch_output(result.stdout, n)

    def _parse_batch_output(self, output, n):
        """
        Parses the LLM batch output into a list of individual analyses.
        Uses multiple fallback patterns for robustness.
        """
        outputs = [None] * n

        patterns = [
            (0, r"===== COMMIT (\d+)/(\d+) =====\s*(.*?)(?===== COMMIT \d+/\d+ =====|===== END COMMIT|$)", re.DOTALL),
            (1, r"--- COMMIT (\d+)/(\d+) ---\s*(.*?)(?=--- COMMIT \d+/\d+ ---|--- END COMMIT|$)", re.DOTALL),
            (2, r"COMMIT (\d+)/(\d+)\s*(?:---)?\s*(.*?)(?=COMMIT \d+/\d+|END COMMIT|$)", re.DOTALL | re.IGNORECASE),
        ]

        for priority, pattern, flags in patterns:
            matches = list(re.finditer(pattern, output, flags))
            if matches:
                for m in matches:
                    idx = int(m.group(1)) - 1
                    if 0 <= idx < n and outputs[idx] is None:
                        outputs[idx] = m.group(3).strip()
                if sum(1 for o in outputs if o is not None) == n:
                    return outputs

        if outputs.count(None) > 0:
            outputs = self._parse_by_fields(output, n)

        return outputs

    def _parse_by_fields(self, output, n):
        """
        Fallback parser: extracts commit sections by finding field markers.
        Looks for ## Commit Hash and ## Subject lines to identify each commit block.
        """
        outputs = [None] * n

        block_pattern = r"(?:===== )?COMMIT (\d+)/\d+(?: =====)?(.*?)(?=(?:===== )?COMMIT \d+/\d+(?: =====)?|${})".format("" if not re.search(r"===== END", output) else "===== END")
        for m in re.finditer(block_pattern, output, re.DOTALL | re.IGNORECASE):
            idx = int(m.group(1)) - 1
            if 0 <= idx < n:
                outputs[idx] = m.group(2).strip()

        if outputs.count(None) > 0:
            lines = output.split("\n")
            current_idx = -1
            current_content = []
            for i, line in enumerate(lines):
                m = re.match(r"(?:===== )?COMMIT (\d+)/(\d+)", line, re.IGNORECASE)
                if m:
                    if current_idx >= 0 and current_idx < n and current_content:
                        outputs[current_idx] = "\n".join(current_content).strip()
                    current_idx = int(m.group(1)) - 1
                    current_content = []
                elif current_idx >= 0:
                    current_content.append(line)
            if current_idx >= 0 and current_idx < n and current_content:
                outputs[current_idx] = "\n".join(current_content).strip()

        return outputs


def parse_report_commits(report_path):
    """
    Parses an existing report to extract full-hash commits that are REACHABLE.
    Returns a set of full 40-char commit hashes already processed.
    """
    if not os.path.exists(report_path):
        return set()
    skip_hashes = set()
    with open(report_path, "r") as f:
        for line in f:
            m = re.search(r"### Commit `([0-9a-f]{40})`", line)
            if m:
                skip_hashes.add(m.group(1))
    return skip_hashes


def extract_detailed_sections(report_path):
    """
    Extracts all existing detailed sections from a report file.
    Returns a dict mapping full commit hash -> section text.
    """
    if not os.path.exists(report_path):
        return {}
    sections = {}
    with open(report_path, "r") as f:
        content = f.read()
    for m in re.finditer(r"(### Commit `([0-9a-f]{40})`.*?)(?=\n### Commit `|$)", content, re.DOTALL):
        sections[m.group(2)] = m.group(1).strip()
    return sections


def extract_summary_entries(report_path):
    """
    Extracts summary table rows from an existing report.
    Returns a list of dicts with hash, subject, status, symbol, score.
    """
    if not os.path.exists(report_path):
        return []
    entries = []
    with open(report_path, "r") as f:
        in_table = False
        for line in f:
            if line.startswith("| Commit Hash |"):
                in_table = True
                continue
            if in_table and line.startswith("---"):
                break
            if in_table:
                m = re.match(r"\| `([0-9a-f]{12})` \| ([^|]+) \| \*\*(\w+)\*\* \| `([^`)]+)` \| \*\*([^*]+)\*\* \|", line)
                if m:
                    entries.append({
                        "hash": m.group(1),
                        "subject": m.group(2).strip(),
                        "status": m.group(3),
                        "symbol": m.group(4),
                        "score": m.group(5).strip()
                    })
    return entries


def process_commit(commit_data):
    """Worker function for parallel processing of a single commit."""
    commit, engine, score, mitigations = commit_data
    subject = engine.get_commit_subject(commit)
    details = engine.get_commit_details(commit)
    if not details:
        return {
            "hash": commit,
            "subject": subject,
            "status": "ERROR",
            "score": "-",
            "symbol": "-",
            "report": None
        }

    is_reachable, reachability_info = engine.evaluate_reachability(details["modified_files"])
    
    if reachability_info:
        first_file = next(iter(reachability_info))
        symbol = reachability_info[first_file]["symbol"]
    else:
        symbol = "None"
        status = "NO_C_CHANGES"

    if not is_reachable:
        return {
            "hash": commit,
            "subject": subject,
            "status": "UNREACHABLE",
            "score": "-",
            "symbol": symbol,
            "reachability_info": reachability_info,
            "report": None
        }

    # Query LLM
    llm_output = engine.invoke_opencode_llm(details["commit_msg"], details["diff"], reachability_info)

    # Build detailed reachable section
    reachable_section = f"""### Commit `{commit}`: {subject}
* **Commit Hash:** `{commit}`
* **Verdict:**  **REACHABLE (FEASIBILITY INDEX: {score:.1f} / 10.0)**

#### 1. Reachability Status
| File Path | Controlling Symbol | Status |
| :--- | :--- | :--- |"""
    for path, meta in reachability_info.items():
        reachable_section += f"\n| `{path}` | `{meta['symbol']}` | **{meta['status']}** |"

    reachable_section += """

#### 2. Hardening & Mitigation Analysis
| Hardening Option | Active Status |
| :--- | :--- |"""
    for opt, status in mitigations.items():
        reachable_section += f"\n| `{opt}` | {status} |"

    reachable_section += f"""

#### 3. Semantic Exploit Analysis (LLM)
{llm_output}

---
"""

    return {
        "hash": commit,
        "subject": subject,
        "status": "REACHABLE",
        "score": f"{score:.1f} / 10.0",
        "symbol": symbol,
        "reachability_info": reachability_info,
        "report": reachable_section
    }


def build_reachable_section(commit, subject, score, reachability_info, mitigations, llm_output):
    """Builds the markdown section for a REACHABLE commit."""
    section = f"""### Commit `{commit}`: {subject}
* **Commit Hash:** `{commit}`
* **Verdict:**  **REACHABLE (FEASIBILITY INDEX: {score:.1f} / 10.0)**

#### 1. Reachability Status
| File Path | Controlling Symbol | Status |
| :--- | :--- | :--- |"""
    for path, meta in reachability_info.items():
        section += f"\n| `{path}` | `{meta['symbol']}` | **{meta['status']}** |"

    section += """

#### 2. Hardening & Mitigation Analysis
| Hardening Option | Active Status |
| :--- | :--- |"""
    for opt, status in mitigations.items():
        section += f"\n| `{opt}` | {status} |"

    section += f"""

#### 3. Semantic Exploit Analysis (LLM)
{llm_output}

---
"""
    return section


def process_batch(batch_items):
    """
    Worker function for parallel processing of a batch of commits.
    batch_items: list of (commit, engine, score, mitigations)
    Returns: list of result dicts (one per commit).
    """
    results = []
    commit_hashes = [item[0] for item in batch_items]
    engine = batch_items[0][1]

    details_map = {}
    for commit, eng, score, mitigations in batch_items:
        details = eng.get_commit_details(commit)
        subject = eng.get_commit_subject(commit)
        if details:
            is_reachable, reachability_info = eng.evaluate_reachability(details["modified_files"])
        else:
            is_reachable, reachability_info = False, {}
        details_map[commit] = {
            "subject": subject,
            "details": details,
            "is_reachable": is_reachable,
            "reachability_info": reachability_info,
            "score": score,
            "mitigations": mitigations
        }

    batch_data = []
    for commit, eng, score, mitigations in batch_items:
        d = details_map[commit]
        if d["details"] is None:
            batch_data.append(None)
        elif not d["is_reachable"]:
            batch_data.append(None)
        else:
            batch_data.append((commit, d["subject"], d["details"]["commit_msg"], d["details"]["diff"], d["reachability_info"], score, mitigations))

    filtered_batch = [b for b in batch_data if b is not None]
    batch_results = engine.invoke_opencode_llm_batch(filtered_batch)

    result_idx = 0
    for commit, eng, score, mitigations in batch_items:
        d = details_map[commit]
        subject = d["subject"]
        is_reachable = d["is_reachable"]
        reachability_info = d["reachability_info"]

        if reachability_info:
            first_file = next(iter(reachability_info))
            symbol = reachability_info[first_file]["symbol"]
        else:
            symbol = "None"

        if d["details"] is None:
            results.append({
                "hash": commit,
                "subject": subject,
                "status": "ERROR",
                "score": "-",
                "symbol": symbol,
                "report": None
            })
        elif not is_reachable:
            results.append({
                "hash": commit,
                "subject": subject,
                "status": "UNREACHABLE",
                "score": "-",
                "symbol": symbol,
                "reachability_info": reachability_info,
                "report": None
            })
        else:
            llm_output = batch_results[result_idx] if result_idx < len(batch_results) else None
            result_idx += 1
            if llm_output is None:
                llm_output = "Error: LLM returned no output for this commit."
            section = build_reachable_section(commit, subject, score, reachability_info, mitigations, llm_output)
            results.append({
                "hash": commit,
                "subject": subject,
                "status": "REACHABLE",
                "score": f"{score:.1f} / 10.0",
                "symbol": symbol,
                "reachability_info": reachability_info,
                "report": section
            })

    return results


def _load_krecon_config(path):
    """Load krecon config from JSON file."""
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        cfg = json.load(f)
    valid_keys = {"repo", "commit", "range", "limit", "days", "config", "parallel", "batch_size", "model", "opencode_bin", "output", "resume"}
    return {k: v for k, v in cfg.items() if k in valid_keys}


def main():
    parser = argparse.ArgumentParser(description="Deterministic + LLM Hybrid Linux Kernel Commit Triage Tool")
    parser.add_argument("--repo", help="Path to local Linux upstream git repo")
    parser.add_argument("--commit", help="Comma-separated upstream commit hashes to analyze")
    parser.add_argument("--range", help="Git revision range to analyze (e.g., HEAD~5..HEAD or v6.8..v6.8.1)")
    parser.add_argument("--limit", type=int, help="Analyze the last N commits starting from current branch")
    parser.add_argument("--days", type=int, help="Analyze commits from the last N days")
    parser.add_argument("--config", help="Path to target kernel .config file")
    parser.add_argument("--parallel", type=int, help="Number of parallel LLM workers (default: 1)")
    parser.add_argument("--batch-size", type=int, help="Number of commits per LLM batch (default: 7)")
    parser.add_argument("--model", help="LLM model to use (default: xai/grok-4.20-0309-reasoning)")
    parser.add_argument("--opencode-bin", help="Path to opencode binary")
    parser.add_argument("--output", help="Output report path (default: krecon_report.md in cwd)")
    parser.add_argument("--resume", action="store_true", help="Skip commits already REACHABLE in existing report")
    parser.add_argument("--krecon-config", default=os.environ.get("KRECON_CONFIG", "krecon.json"), help="Path to krecon config file")
    args = parser.parse_args()

    krecon_defaults = _load_krecon_config(args.krecon_config)

    def get_arg(name, default_val=None):
        val = getattr(args, name)
        if val is not None:
            return val
        if name in krecon_defaults:
            return krecon_defaults[name]
        return default_val

    repo = get_arg("repo")
    config = get_arg("config")
    if not repo or not config:
        missing = []
        if not repo: missing.append("--repo")
        if not config: missing.append("--config")
        print(f"[-] Error: missing required arguments: {' '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    model = get_arg("model", "xai/grok-4.20-0309-reasoning")
    parallel = get_arg("parallel", 1)
    batch_size = get_arg("batch_size", 7)
    opencode_bin = get_arg("opencode_bin")
    output = get_arg("output")
    resume = get_arg("resume", False)
    commit = get_arg("commit")
    commit_range = get_arg("range")
    limit = get_arg("limit")
    days = get_arg("days")

    engine = KernelTriageEngine(repo, config, model=model, opencode_bin=opencode_bin)

    engine = KernelTriageEngine(repo, config, model=model, opencode_bin=opencode_bin)

    # 1. Resolve list of commits
    commits = []
    if commit:
        commits = [c.strip() for c in commit.split(",") if c.strip()]
    elif commit_range:
        cmd = ["git", "-C", engine.repo_path, "log", "--format=%H", commit_range]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            commits = [c.strip() for c in result.stdout.splitlines() if c.strip()]
        else:
            print(f"[-] Error parsing revision range: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
    elif limit:
        cmd = ["git", "-C", engine.repo_path, "log", "--format=%H", "-n", str(limit)]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            commits = [c.strip() for c in result.stdout.splitlines() if c.strip()]
        else:
            print(f"[-] Error retrieving last {limit} commits: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
    elif days:
        cmd = ["git", "-C", engine.repo_path, "log", "--format=%H", f"--since={days} days ago"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            commits = [c.strip() for c in result.stdout.splitlines() if c.strip()]
        else:
            print(f"[-] Error retrieving commits from the last {days} days: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
    else:
        cmd = ["git", "-C", engine.repo_path, "log", "--format=%H", "-n", "1"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            commits = [c.strip() for c in result.stdout.splitlines() if c.strip()]
        else:
            print("[-] Error: Could not determine default commit to analyze.", file=sys.stderr)
            sys.exit(1)

    if not commits:
        print("[-] Error: No commits found to analyze.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting triage pipeline for {len(commits)} commit(s)...", file=sys.stderr)
    print(f"[*] Parallel workers: {parallel}", file=sys.stderr)

    report_path = os.path.abspath(output) if output else os.path.join(os.getcwd(), "krecon_report.md")

    existing_summary = []
    reprocess_set = set()
    if resume and os.path.exists(report_path):
        existing_summary = extract_summary_entries(report_path)
        skip_set = parse_report_commits(report_path)
        if skip_set:
            original_count = len(commits)
            reprocess_set = set(commits) & skip_set
            commits = [c for c in commits if c not in skip_set]
            skipped = original_count - len(commits)
            print(f"[*] Resume: skipping {skipped} already-processed REACHABLE commit(s)", file=sys.stderr)
            if not commits:
                print("[*] All commits already processed. Exiting.", file=sys.stderr)
                sys.exit(0)

    # Phase 1: Pre-process all commits to get subjects and deterministically classify
    preprocessed = []
    summary_results = []
    detailed_reports = []
    reachable_work_items = []

    for i, commit in enumerate(commits, start=1):
        subject = engine.get_commit_subject(commit)
        details = engine.get_commit_details(commit)
        
        if not details:
            summary_results.append({
                "hash": commit,
                "subject": subject,
                "status": "ERROR",
                "score": "-",
                "symbol": "-"
            })
            continue

        is_reachable, reachability_info = engine.evaluate_reachability(details["modified_files"])
        
        if reachability_info:
            first_file = next(iter(reachability_info))
            symbol = reachability_info[first_file]["symbol"]
            status = reachability_info[first_file]["status"]
        else:
            symbol = "None"
            status = "NO_C_CHANGES"

        if not is_reachable:
            summary_results.append({
                "hash": commit,
                "subject": subject,
                "status": "UNREACHABLE",
                "score": "-",
                "symbol": symbol
            })
            
            unreachable_section = f"""### Commit `{commit[:12]}`: {subject}
* **Commit Hash:** `{commit}`
* **Verdict:** ❌ **UNREACHABLE / NOT COMPILED**

The required compilation dependencies are disabled inside target `.config`.

| File Path | Controlling Symbol | Status |
| :--- | :--- | :--- |"""
            for path, meta in reachability_info.items():
                unreachable_section += f"\n| `{path}` | `{meta['symbol']}` | **{meta['status']}** |"
            unreachable_section += "\n\n---\n"
            detailed_reports.append(unreachable_section)
            continue

        # This commit is reachable, prepare for parallel LLM processing
        score, mitigations = engine.calculate_hardening_score()
        summary_results.append({
            "hash": commit,
            "subject": subject,
            "status": "REACHABLE",
            "score": f"{score:.1f} / 10.0",
            "symbol": symbol
        })
        reachable_work_items.append((commit, engine, score, mitigations))

    # Phase 2: Parallel LLM queries for reachable commits
    if reachable_work_items:
        print(f"[*] Phase 2: Querying LLM for {len(reachable_work_items)} reachable commit(s) with {parallel} worker(s) in batches of {batch_size}...", file=sys.stderr)

        resume_mode = resume and os.path.exists(report_path)

        if resume_mode:
            existing_details = extract_detailed_sections(report_path)
        else:
            existing_details = {}

        new_summary_hashes = {r["hash"][:12] for r in summary_results}
        if resume and new_summary_hashes:
            filtered_existing = [e for e in existing_summary if e["hash"] not in new_summary_hashes]
        else:
            filtered_existing = existing_summary
        full_summary = filtered_existing + summary_results
        with open(report_path, "w") as f:
            f.write(f"""# Batch Kernel Commit Exploitability Triage Report
* **Target Config:** `{os.path.basename(config)}`
* **Total Commits Analyzed:** {len(full_summary)}
* **Parallel Workers:** {parallel}
* **Batch Size:** {batch_size}

---

## Triage Summary Table
| Commit Hash | Subject | Status | Controlling Symbol | Feasibility Index |
| :--- | :--- | :--- | :--- | :--- |
""")
            for res in full_summary:
                f.write(f"| `{res['hash'][:12]}` | {res['subject']} | **{res['status']}** | `{res['symbol']}` | **{res['score']}** |\n")
            f.write("\n---\n\n## Detailed Commit Reports\n\n")

            for h in sorted(existing_details.keys()):
                f.write(existing_details[h])
                f.write("\n")

        def make_batches(work_items, size):
            it = iter(work_items)
            while True:
                batch = list(islice(it, size))
                if not batch:
                    break
                yield batch

        batches = list(make_batches(reachable_work_items, batch_size))
        completed_commits = 0
        total_reachable = len(reachable_work_items)
        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {executor.submit(process_batch, batch): batch for batch in batches}

            for future in as_completed(futures):
                batch = futures[future]
                try:
                    batch_results = future.result()
                    for result in batch_results:
                        completed_commits += 1
                        if result["report"]:
                            with open(report_path, "a") as f:
                                f.write(result["report"] + "\n")
                                f.flush()
                        print(f"[*] [{completed_commits}/{total_reachable}] Processed {result['hash'][:12]} - {result['status']}", file=sys.stderr)
                except Exception as e:
                    for item in batch:
                        print(f"[-] Error processing batch containing {item[0][:12]}: {str(e)}", file=sys.stderr)
    else:
        new_summary_hashes = {r["hash"][:12] for r in summary_results}
        if resume and new_summary_hashes:
            filtered_existing = [e for e in existing_summary if e["hash"] not in new_summary_hashes]
        else:
            filtered_existing = existing_summary
        full_summary = filtered_existing + summary_results
        resume_mode = resume and os.path.exists(report_path)
        if resume_mode:
            existing_details = extract_detailed_sections(report_path)
        else:
            existing_details = {}
        with open(report_path, "w") as f:
            f.write(f"""# Batch Kernel Commit Exploitability Triage Report
* **Target Config:** `{os.path.basename(config)}`
* **Total Commits Analyzed:** {len(full_summary)}
* **Parallel Workers:** {parallel}
* **Batch Size:** {batch_size}

---

## Triage Summary Table
| Commit Hash | Subject | Status | Controlling Symbol | Feasibility Index |
| :--- | :--- | :--- | :--- | :--- |
""")
            for res in full_summary:
                f.write(f"| `{res['hash'][:12]}` | {res['subject']} | **{res['status']}** | `{res['symbol']}` | **{res['score']}** |\n")
            f.write("\n---\n\n## Detailed Commit Reports\n\n")
            for h in sorted(existing_details.keys()):
                f.write(existing_details[h])
                f.write("\n")
            f.flush()

    print(f"[*] Report saved to: {report_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
