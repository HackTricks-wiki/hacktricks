# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

Starting with **macOS Big Sur (11.0)**, the system volume is cryptographically sealed using an **APFS snapshot hash tree**. This is called the **Sealed System Volume (SSV)**. The system partition is mounted **read-only** and any modification breaks the seal, which is verified during boot.<sup>[[11]](#references)</sup>

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
| CVE-2021-30892 | **Shrootless** — SIP bypass abusing `system_installd`'s `com.apple.rootless.install.heritable` entitlement to run arbitrary post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` staged the post-install script in a SIP-protected folder under `/tmp`, but `/tmp` itself isn't SIP-protected, so the folder could be swapped by mounting an image over it ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race in XNU allowing writes to read-only root-owned files ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault** is Apple's protection layer for sensitive system databases. Even **root cannot access DataVault-protected files** — only processes with specific entitlements can read or modify them.<sup>[[4]](#references)</sup> Protected stores include:

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

If an attacker compromises a DataVault controller binary (e.g., via code injection into a process with `com.apple.private.tcc.manager`), they can **directly modify the TCC database** to grant any application any TCC permission:<sup>[[12]](#references)</sup>

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
| CVE-2024-44131 | FileProvider symlink race letting a privileged helper reach TCC-protected data ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | As root, **create a new user whose `NFSHomeDirectory` points at an attacker-controlled `TCC.db`**; on login `tccd` consumes it and the grants apply, reaching other users' data ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": changing the user's home dir to plant an attacker-controlled TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion flaw letting an app **inherit the TCC grants of a donor bundle** without a prompt; exploited in the wild by **XCSSET** to screenshot the desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` built the DB path from `$HOME`, so `launchctl setenv HOME` redirected it to an attacker-controlled `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` held `com.apple.private.tcc.manager` **and** disabled library validation, so a HAL plug-in dropped in `/Library/Audio/Plug-Ins/HAL` could grant arbitrary TCC rights ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## References

- [1] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
