#!/usr/bin/env node
/**
 * npm launcher for Specter AI.
 *
 * Specter is a Python tool; this thin wrapper lets npm users run `npx
 * @ai-specter/cli` by delegating to the installed Python package. On first run
 * it ensures the Python package is present (via pipx or pip --user).
 */
"use strict";
const { spawnSync } = require("child_process");

function has(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: "ignore" });
  return r.status === 0;
}

function ensureInstalled() {
  if (has("specter", ["version"])) return true;
  console.error("[specter] Python package not found — installing…");
  if (has("pipx", ["--version"])) {
    spawnSync("pipx", ["install", "ai-specter"], { stdio: "inherit" });
  } else {
    const py = has("python3", ["--version"]) ? "python3" : "python";
    spawnSync(py, ["-m", "pip", "install", "--user", "ai-specter"], { stdio: "inherit" });
  }
  return has("specter", ["version"]);
}

const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === "--__check") {
  ensureInstalled();
  process.exit(0);
}

if (!ensureInstalled()) {
  console.error("[specter] Could not install the Python package. Install Python 3.10+ and retry.");
  process.exit(1);
}

const res = spawnSync("specter", argv, { stdio: "inherit" });
process.exit(res.status === null ? 1 : res.status);
