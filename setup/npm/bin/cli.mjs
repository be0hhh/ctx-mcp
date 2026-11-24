#!/usr/bin/env node
// Zero-dependency npx launcher for ctx-mcp (`npx github:be0hhh/ctx-mcp`).
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const setupDir = join(here, "..", "..");
const args = process.argv.slice(2);
const isUninstall = args[0] === "uninstall" || args[0] === "--uninstall";
const rest = isUninstall ? args.slice(1) : args;

if (process.platform === "win32") {
  const script = join(setupDir, isUninstall ? "uninstall.ps1" : "install.ps1");
  const res = spawnSync("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, ...rest], {
    stdio: "inherit",
  });
  process.exit(res.status ?? 1);
} else {
  const script = join(setupDir, isUninstall ? "uninstall.sh" : "install.sh");
  const res = spawnSync("bash", [script, ...rest], { stdio: "inherit" });
  process.exit(res.status ?? 1);
}
