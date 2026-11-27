# Install for Claude Code or Codex

Use this guide for **local stdio MCP**, not a marketplace plugin or a hosted connector. The same server works with both clients. Install and verify it with generated fixtures before connecting it to any case directory.

> **Prompt to give your agent:** Set up Forensic Maldoc for my local Claude Code or Codex workspace using this guide. Confirm the workspace and configuration scope. Use only generated fixtures for the smoke test, and report which steps passed. Do not stage real files, change system security settings, or install the optional PDF tools.

## 1. Confirm the scope and prepare the installation

For an agent: confirm the client, the target workspace, and whether any persistent settings change is wanted. Reuse a trusted checkout if one exists; do not overwrite an existing MCP entry or another project's settings. If the client runs on a different machine, build and stage there. Do not assume access to the user's local filesystem from a hosted session.

The host running the MCP process needs Linux, Git, `uv`, Python 3.11+, and `/usr/bin/bwrap` with unprivileged user namespaces. Check prerequisites before proceeding. If Bubblewrap is blocked, keep the failure visible and stop; do not use elevated privileges, change kernel settings, or run the parser unsandboxed.

From a directory chosen for installing tools (not an evidence directory), run:

```bash
git clone https://github.com/BlinkVoid/forensic-maldoc-plugin.git
cd forensic-maldoc-plugin
uv sync --locked --extra mcp
server="$PWD/.venv/bin/forensic-maldoc"
staging="$(mktemp -d)"
"$PWD/.venv/bin/python" -m labs.fixtures "$staging"
"$server" assess --staging "$staging" wrapper-lookalike.docx
printf 'Server: %s\nFixture staging: %s\n' "$server" "$staging"
```

Use the printed absolute paths in the next step. The `assess` command must exit `0`; expect CFB identification and `payload_status` equal to `not_inspected`. The fixture has wrapper-shaped names but no encrypted package to inspect. Exit `1` means incomplete or unsupported; exit `2` means rejected input or usage error. Keep this temporary directory for the smoke test; if it disappears, recreate fixtures in a fresh directory and reconfigure the path.

## 2. Register only the requested client

### Claude Code

From the **workspace where the analyst will start Claude Code** (not necessarily the toolkit checkout), set `server` and `staging` to the exact paths from step 1 if you opened a new shell. Register in local scope so the entry is not shared in Git:

```bash
claude mcp add --scope local --transport stdio forensic-maldoc -- \
  "$server" mcp --staging "$staging"
claude mcp get forensic-maldoc
```

See [Claude Code’s MCP setup and scopes](https://code.claude.com/docs/en/mcp#local-scope).

### Codex

For a single approved workspace, merge this table into its trusted `.codex/config.toml`. Replace both placeholder paths; TOML does not expand shell variables here. Preserve unrelated settings and keep this machine-specific entry out of version control.

```toml
[mcp_servers.forensic-maldoc]
command = "/absolute/path/to/forensic-maldoc-plugin/.venv/bin/forensic-maldoc"
args = ["mcp", "--staging", "/absolute/path/to/fixture-staging"]
```

If the user explicitly wants a **user-wide** registration instead, use the CLI command below with the paths from step 1. Do not add the server in both scopes.

```bash
codex mcp add forensic-maldoc -- "$server" mcp --staging "$staging"
codex mcp list
```

See [Codex MCP setup and configuration scopes](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

## 3. Prove that the client can call the server

Start a new local session in the intended workspace. Use `/mcp` to check the server and ask:

> Call `assess_staged_document` on `wrapper-lookalike.docx` in the `forensic-maldoc` server. Report the observed format, encryption evidence, and whether payload inspection was performed. Do not open the file or substitute a shell parser.

Expect `format: ole_cfb`, `encryption.state: office_wrapper_empty`, and `payload_status: not_inspected`. A config entry or successful CLI-only check is not evidence that the client called the tool. If the tool is missing, check the client workspace, approved configuration, executable and absolute staging path. If a tool reports incomplete coverage, report its status and reason, not a clean verdict. Do not work around a client or sandbox policy denial.

## 4. Use the skills and switch to case staging only when authorized

The MCP connection exposes tools, not skills. An agent can read the bundled [skill folders](../skills/) directly in the clone. Start with metadata triage, use the relevant PDF or OLE skill for the next check, and use evidence review before handing off a finding. Optional discovery: link individual skill folders from the trusted workspace’s `.claude/skills/` or `.agents/skills/` to their directories in the retained checkout. Use the original folder names, do not replace existing entries, and reopen the client if needed. See [Claude Code skill locations](https://code.claude.com/docs/en/skills#choose-where-skills-load) and [Codex skill locations](https://learn.chatgpt.com/docs/build-skills#where-to-save-skills).

For casework, the analyst chooses an approved, dedicated staging directory and stages the intended copy outside Git. Change the MCP entry only after approval, then restart the client. Do not use a home directory, download directory, or network share as the staging root. Tools take a **basename only**, not a path or URL. Local stdio is not a guarantee of local model processing: the client or its model provider may receive structured results. Use an approved client and provider for confidential evidence.

No extra tools are needed for `assess_staged_document` or `triage_staged_ole`. For the dedicated `triage_staged_pdf` scan, the operator may separately supply the two [verified upstream scripts](pdf-triage-v0.1.md#upstream-provenance) in a dedicated directory and append `--tools /absolute/path/to/verified-tools` to the server's launch arguments. The server does not download them. Do not add that directory during the basic smoke test.
