# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

Starting with **macOS Big Sur (11.0)**, the system volume is cryptographically sealed using an **APFS snapshot hash tree**. This is called the **Sealed System Volume (SSV)**. The system partition is mounted **read-only** and any modification breaks the seal, which is verified during boot.

The SSV provides:
- **Tamper detection** — any modification to system binaries/frameworks is detectable via the broken cryptographic seal
- **Rollback protection** — the boot process verifies the system snapshot's integrity
- **Rootkit prevention** — even root cannot persistently modify files on the system volume (without breaking the seal)

### Checking SSV Status

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Verify the system volume seal
diskutil apfs listVolumeGroups
```

### SSV Writer Entitlements

Certain Apple system binaries have entitlements that allow them to modify or manage the sealed system volume:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Revert the system volume to a previous snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Create a new sealed snapshot after system updates |
| `com.apple.rootless.install.heritable` | Write to SIP-protected paths (inherited by child processes) |
| `com.apple.rootless.install` | Write to SIP-protected paths |

### Finding SSV Writers

```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```

### Attack Scenarios

#### Snapshot Rollback Attack

If an attacker compromises a binary with `com.apple.private.apfs.revert-to-snapshot`, they can **roll back the system volume to a pre-update state**, restoring known vulnerabilities:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Snapshot rollback effectively **undoes security updates**, restoring previously-patched kernel and system vulnerabilities. This is one of the most dangerous operations possible on modern macOS.

#### System Binary Replacement

With SIP bypass + SSV write capability, an attacker can:

1. Mount the system volume read-write
2. Replace a system daemon or framework library with a trojaned version
3. Re-seal the snapshot (or accept the broken seal if SIP is already degraded)
4. The rootkit persists across reboots and is invisible to userland detection tools

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass allowing SSV modification via `system_installd` |
| CVE-2022-22583 | SSV bypass through PackageKit's snapshot handling |
| CVE-2022-46689 | Race condition allowing writes to SIP-protected files |

---

## DataVault

### Basic Information

**DataVault** is Apple's protection layer for sensitive system databases. Even **root cannot access DataVault-protected files** — only processes with specific entitlements can read or modify them. Protected stores include:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection is enforced at the **filesystem level** using extended attributes and volume protection flags, verified by the kernel.

### DataVault Controller Entitlements

```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```

### Finding DataVault Controllers

```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```

### Attack Scenarios

#### Direct TCC Database Modification

If an attacker compromises a DataVault controller binary (e.g., via code injection into a process with `com.apple.private.tcc.manager`), they can **directly modify the TCC database** to grant any application any TCC permission:

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCC database modification is the **ultimate privacy bypass** — it grants any permission silently, without any user prompt or visible indicator. Historically, multiple macOS privilege escalation chains have ended with TCC database writes as the final payload.

#### Keychain Database Access

DataVault also protects the keychain backing files. A compromised DataVault controller can:

1. Read the raw keychain database files
2. Extract encrypted keychain items
3. Attempt offline decryption using the user's password or recovered keys

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
