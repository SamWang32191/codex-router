import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

let windowsSid;

function currentWindowsSid() {
  if (windowsSid) return windowsSid;
  const script =
    "[Console]::Out.Write([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)";
  windowsSid = execFileSync(
    "powershell.exe",
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  ).trim();
  if (!windowsSid) throw new Error("Could not resolve the current Windows user SID.");
  return windowsSid;
}

export function windowsFullControlGrant(sid) {
  if (!/^S-\d+(?:-\d+)+$/i.test(sid)) {
    throw new Error("Could not format an invalid Windows user SID.");
  }
  // icacls requires an asterisk before a numeric SID so it is not resolved as
  // an account name. Without it, hosted runners fail with system error 1332.
  return `*${sid}:(F)`;
}

export function protectPrivateFile(target) {
  chmodSync(target, 0o600);
  if (process.platform !== "win32") return target;
  const sid = currentWindowsSid();
  execFileSync(
    "icacls.exe",
    [target, "/inheritance:r", "/grant:r", windowsFullControlGrant(sid)],
    { stdio: "ignore" },
  );
  return target;
}

// All private JSON state uses the same temp-file, owner-only, atomic replace.
// Keeping it here prevents one state writer from drifting away from the rest.
//
// Resolve the real file a path points at so an atomic replace updates a
// symlink's target instead of replacing the symlink itself with a regular
// file. `renameSync` over a symlink path silently substitutes the link, which
// breaks user-managed setups where a config document points at dotfiles.
export function resolveWriteTarget(target) {
  try {
    return realpathSync(target);
  } catch {
    // ENOENT: the path does not exist yet (first write) or the link is
    // dangling. Keep the requested path; there is no symlink to preserve.
    return target;
  }
}

export function writePrivateFile(target, contents, { directoryMode } = {}) {
  const destination = resolveWriteTarget(target);
  const directory = path.dirname(destination);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (directoryMode !== undefined) chmodSync(directory, directoryMode);
  const temporary = `${destination}.tmp.${process.pid}`;
  try {
    writeFileSync(temporary, contents, { encoding: "utf8", mode: 0o600 });
    protectPrivateFile(temporary);
    renameSync(temporary, destination);
    protectPrivateFile(destination);
  } catch (error) {
    if (existsSync(temporary)) unlinkSync(temporary);
    throw error;
  }
  return target;
}

export function writePrivateJson(target, value, { space = 2, directoryMode } = {}) {
  writePrivateFile(target, `${JSON.stringify(value, null, space)}\n`, { directoryMode });
  return value;
}

export function privateFileIsProtected(target) {
  if (!existsSync(target)) return false;
  if (process.platform !== "win32") return (statSync(target).mode & 0o777) === 0o600;
  const script = [
    // Get-Acl lazy-loads Microsoft.PowerShell.Security, which can fail under
    // concurrent Windows processes. The .NET API returns the same FileSecurity
    // object without importing a PowerShell module.
    "$acl = [System.IO.File]::GetAccessControl($env:CODEX_ROUTER_PRIVATE_FILE)",
    "$identity = [Security.Principal.WindowsIdentity]::GetCurrent()",
    "$sid = $identity.User.Value",
    "$name = $identity.Name",
    "$allowed = $false",
    "foreach ($rule in $acl.Access) { $ruleIdentity = $rule.IdentityReference.Value; $matches = $ruleIdentity -eq $sid -or $ruleIdentity -eq $name; if (-not $matches) { try { $matches = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid } catch { $matches = $false } }; if ($matches -and $rule.AccessControlType -eq 'Allow') { $allowed = $true } }",
    "[Console]::Out.Write(($acl.AreAccessRulesProtected -and $allowed).ToString())",
  ].join("; ");
  try {
    return execFileSync(
      "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
      {
        encoding: "utf8",
        env: { ...process.env, CODEX_ROUTER_PRIVATE_FILE: target },
        stdio: ["ignore", "pipe", "ignore"],
      },
    ).trim().toLowerCase() === "true";
  } catch {
    return false;
  }
}
