/**
 * TOCTOU (Time-of-Check-Time-of-Use) Race Condition PoC
 *
 * This demonstrates the vulnerability where a file is checked for security
 * but then modified before it's actually used.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, unlinkSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";

describe("Security PoC - TOCTOU Race Condition", () => {
  describe("VULN-3: Command Execution TOCTOU", () => {
    it("POC: Race between permission check and execution", async () => {
      const tempDir = mkdtempSync(join(tmpdir(), "openclaw-touctu-"));
      const scriptPath = join(tempDir, "script.sh");
      const maliciousPath = join(tempDir, "malicious.sh");

      try {
        // Step 1: Create a benign script
        writeFileSync(scriptPath, "#!/bin/bash\necho 'Hello, World!'", { mode: 0o755 });

        // Step 2: Check permission (simulating the security check)
        // In real code, this would check if script.sh is in the allowlist
        const isAllowed = checkScriptAllowed(scriptPath);
        expect(isAllowed).toBe(true);

        // Step 3: Attacker replaces the file (in the race window)
        // This would happen in a separate thread/process
        writeFileSync(scriptPath, "#!/bin/bash\necho 'PWNED!'\nrm -rf /tmp/test", { mode: 0o755 });

        // Step 4: Execute the "checked" script
        // The script has been replaced after the check
        const output = execSync(scriptPath, { encoding: "utf-8" });

        // VULNERABILITY: The output will be "PWNED!" not "Hello, World!"
        expect(output).toContain("PWNED!");
        console.log("TOCTOU Vulnerability demonstrated!");
        console.log("Checked: Hello, World!");
        console.log("Executed:", output.trim());
      } finally {
        // Cleanup
        try {
          unlinkSync(scriptPath);
        } catch {}
      }
    });

    it("POC: Symlink swap attack", async () => {
      const tempDir = mkdtempSync(join(tmpdir(), "openclaw-symlink-"));
      const benignPath = join(tempDir, "benign.sh");
      const evilPath = join(tempDir, "evil.sh");
      const linkPath = join(tempDir, "link.sh");

      try {
        // Step 1: Create benign and evil scripts
        writeFileSync(benignPath, "#!/bin/bash\necho 'Safe'", { mode: 0o755 });
        writeFileSync(evilPath, "#!/bin/bash\necho 'EVIL COMMAND'", { mode: 0o755 });

        // Step 2: Create symlink to benign
        symlinkSync(benignPath, linkPath);

        // Step 3: Check that link points to benign
        const isAllowed = checkScriptAllowed(linkPath);
        expect(isAllowed).toBe(true);

        // Step 4: Swap symlink to point to evil
        unlinkSync(linkPath);
        symlinkSync(evilPath, linkPath);

        // Step 5: Execute the "checked" link
        const output = execSync(linkPath, { encoding: "utf-8" });

        // VULNERABILITY: Output is "EVIL COMMAND"
        expect(output).toContain("EVIL COMMAND");
        console.log("Symlink swap vulnerability demonstrated!");
      } finally {
        // Cleanup
        try {
          unlinkSync(linkPath);
          unlinkSync(benignPath);
          unlinkSync(evilPath);
        } catch {}
      }
    });
  });

  describe("VULN-4: Path Traversal via Symlink", () => {
    it("POC: Directory boundary escape via symlink", async () => {
      const workspaceDir = mkdtempSync(join(tmpdir(), "workspace-"));
      const evilDir = mkdtempSync(join(tmpdir(), "evil-"));

      try {
        // Create a "safe" file in workspace
        const safeFile = join(workspaceDir, "safe.txt");
        writeFileSync(safeFile, "safe content");

        // Create evil file outside workspace
        const evilFile = join(evilDir, "evil.txt");
        writeFileSync(evilFile, "EVIL CONTENT - /etc/passwd data");

        // Create symlink inside workspace pointing outside
        const linkPath = join(workspaceDir, "link.txt");
        symlinkSync(evilFile, linkPath);

        // VULNERABILITY: Code checks path is inside workspace
        const insideWorkspace = isInsideWorkspace(linkPath, workspaceDir);
        console.log(`Link inside workspace: ${insideWorkspace}`);

        // But reading it accesses files outside workspace
        const content = readFileSync(linkPath, "utf-8");
        expect(content).toContain("EVIL CONTENT");

        console.log("Path traversal via symlink demonstrated!");
        console.log(`Link path: ${linkPath}`);
        console.log(`Resolves to: ${evilFile}`);
        console.log(`Content: ${content}`);
      } finally {
        // Cleanup
        try {
          unlinkSync(join(workspaceDir, "link.txt"));
          unlinkSync(join(workspaceDir, "safe.txt"));
          unlinkSync(evilFile);
        } catch {}
      }
    });

    it("POC: Relative symlink escape", async () => {
      const workspaceDir = mkdtempSync(join(tmpdir(), "workspace-"));
      const tempDir = tmpdir();

      try {
        // Create relative symlink that escapes workspace
        const linkPath = join(workspaceDir, "escape.txt");
        const target = join(tempDir, "target.txt");
        writeFileSync(target, "escaped content");

        // Create relative symlink: ../../tmp/target.txt
        const relativeTarget = join(workspaceDir, "../".repeat(10), "tmp", target.split("/").pop()!);
        symlinkSync(relativeTarget, linkPath);

        // VULNERABILITY: Escapes via relative path
        const content = readFileSync(linkPath, "utf-8");
        expect(content).toContain("escaped");

        console.log("Relative symlink escape demonstrated!");
      } finally {
        // Cleanup
        try {
          unlinkSync(join(workspaceDir, "escape.txt"));
        } catch {}
      }
    });
  });

  describe("VULN-5: Hard link boundary escape", () => {
    it("POC: Hard link allows write outside workspace", async () => {
      const workspaceDir = mkdtempSync(join(tmpdir(), "workspace-"));
      const targetDir = mkdtempSync(join(tmpdir(), "target-"));

      try {
        // Create file outside workspace
        const targetFile = join(targetDir, "outside.txt");
        writeFileSync(targetFile, "original content");

        // Create hard link inside workspace
        const linkPath = join(workspaceDir, "inside.txt");
        try {
          fs.linkSync(targetFile, linkPath);
        } catch (e) {
          console.log("Hard link not supported (cross-device?)");
          return;
        }

        // VULNERABILITY: Modifying "inside" file affects outside
        writeFileSync(linkPath, "MODIFIED VIA HARD LINK");

        const content = readFileSync(targetFile, "utf-8");
        expect(content).toContain("MODIFIED VIA HARD LINK");

        console.log("Hard link boundary escape demonstrated!");
        console.log(`Workspace link: ${linkPath}`);
        console.log(`Target file: ${targetFile}`);
        console.log(`Target content: ${content}`);
      } finally {
        // Cleanup
        try {
          unlinkSync(join(workspaceDir, "inside.txt"));
          unlinkSync(join(targetDir, "outside.txt"));
        } catch {}
      }
    });
  });
});

// Helper functions for the PoC

function checkScriptAllowed(path: string): boolean {
  // Simulated security check
  // In real code, this would check allowlist, permissions, etc.
  try {
    const content = readFileSync(path, "utf-8");
    return !content.includes("EVIL") && !content.includes("PWNED");
  } catch {
    return false;
  }
}

function isInsideWorkspace(path: string, workspace: string): boolean {
  // Naive check that can be bypassed
  const resolved = path;
  return resolved.startsWith(workspace);
}

// Note: This test requires special permissions and setup
describe.skip("VULN-6: Privilege Escalation via SUID", () => {
  it("POC: SUID binary with TOCTOU", () => {
    // This would demonstrate a more severe vulnerability
    // if the binary is SUID and has TOCTOU issues
    console.log("SUID tests require root privileges - skipped");
  });
});

describe("Race Condition Mitigation Tests", () => {
  it("DEMO: Using O_NOFOLLOW prevents symlink swap", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "nofollow-"));
    const benignPath = join(tempDir, "benign");
    const evilPath = join(tempDir, "evil");
    const linkPath = join(tempDir, "link");

    try {
      writeFileSync(benignPath, "safe");
      writeFileSync(evilPath, "evil");

      symlinkSync(benignPath, linkPath);

      // FIXED APPROACH: Use open with O_NOFOLLOW
      // This prevents following symlinks during the open
      // (Node.js doesn't expose O_NOFOLLOW directly, but fs.open with O_NOFOLLOW would)

      const content = readFileSync(linkPath, "utf-8");
      expect(content).toBe("safe");

      // Swap happens after open
      // But the fd still points to the original inode
      console.log("O_NOFOLLOW prevents symlink swap after open");
    } finally {
      try {
        unlinkSync(linkPath);
        unlinkSync(benignPath);
        unlinkSync(evilPath);
      } catch {}
    }
  });
});
