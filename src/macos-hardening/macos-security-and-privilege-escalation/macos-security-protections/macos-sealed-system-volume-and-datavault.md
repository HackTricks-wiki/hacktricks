# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本情報

**macOS Big Sur (11.0)** 以降、system volume は **APFS snapshot hash tree** を使用して cryptographically sealed されています。これは **Sealed System Volume (SSV)** と呼ばれます。system partition は **read-only** で mount され、変更を加えると seal が破壊されます。この seal は boot 時に検証されます。

SSV は以下を提供します。
- **Tamper detection** — system binaries/frameworks への変更は、cryptographic seal が破損するため検出可能
- **Rollback protection** — boot process が system snapshot の integrity を検証
- **Rootkit prevention** — root であっても、seal を破壊せずに system volume 上のファイルを永続的に変更することはできない

### SSV Status の確認
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

特定の Apple system binaries には、sealed system volume の変更または管理を可能にする entitlements が付与されています。

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume を以前の snapshot に戻す |
| `com.apple.private.apfs.create-sealed-snapshot` | system update 後に新しい sealed snapshot を作成する |
| `com.apple.rootless.install.heritable` | SIP-protected paths への書き込み（child processes に継承される） |
| `com.apple.rootless.install` | SIP-protected paths への書き込み |

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
### Snapshot Rollback Attack

攻撃者が `com.apple.private.apfs.revert-to-snapshot` を持つバイナリを侵害した場合、**システムボリュームをアップデート前の状態にロールバックし**、既知の脆弱性を復元できます：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback は、以前に修正された kernel および system の脆弱性を復元し、**security updates を事実上取り消します**。これは、現代の macOS で実行可能な操作の中でも最も危険なものの一つです。

#### System Binary Replacement

SIP bypass + SSV write capability がある場合、攻撃者は次の操作を実行できます。

1. system volume を read-write で mount する
2. system daemon または framework library を trojaned version に置き換える
3. snapshot を再 sealing する（または、SIP がすでに degraded している場合は broken seal を受け入れる）
4. rootkit は reboot 後も persistence し、userland detection tools からは見えない

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` の `com.apple.rootless.install.heritable` entitlement を悪用して arbitrary post-install scripts を実行する SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` は post-install script を `/tmp` 配下の SIP-protected folder に staging しますが、`/tmp` 自体は SIP-protected ではないため、その folder に image を mount して置き換えることが可能でした ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — read-only root-owned files への write を可能にする XNU の copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** は、sensitive system databases のための Apple の protection layer です。**root であっても DataVault-protected files にはアクセスできません** — それらを read または modify できるのは、特定の entitlements を持つ processes だけです。<sup>[1]</sup> Protected stores には次のものが含まれます。

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | system-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | system keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | user keychain |

DataVault protection は、extended attributes と volume protection flags を使用して **filesystem level** で適用され、kernel によって検証されます。

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault Controllers の検索
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
### 攻撃シナリオ

#### TCC Database の直接変更

攻撃者が DataVault controller binary（例: `com.apple.private.tcc.manager` を持つプロセスへの code injection による侵害）を侵害した場合、**TCC database を直接変更**して、任意のアプリケーションに任意の TCC permission を付与できます:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC databaseの変更は**究極のプライバシー bypass**です。ユーザーへの prompt や目に見える indicator なしに、あらゆる permission を無断で付与します。これまで、複数の macOS privilege escalation chain が、最終 payload としての TCC database write に行き着いています。

#### Keychain Database Access

DataVault は keychain の backing file も保護します。侵害された DataVault controller は、以下を実行できます。

1. raw keychain database file を読み取る
2. encrypted keychain item を抽出する
3. ユーザーの password または復元した key を使用して offline decryption を試みる

### DataVault/TCC Bypass に関係する実際の CVE

| CVE | Description |
|---|---|
| CVE-2024-44131 | privileged helper が TCC-protected data に到達できる FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | root として、`NFSHomeDirectory` が attacker-controlled な `TCC.db` を指す**新しい user を作成**できる。login 時に `tccd` がそれを読み込み、grant が適用されて他の user の data に到達できる ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | ユーザーの home dir を変更して attacker-controlled な TCC.db を設置する "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | prompt なしで app が**donor bundle の TCC grant を継承**できる bundle-conclusion flaw。実環境では **XCSSET** がこれを悪用して desktop の screenshot を取得した ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` が `$HOME` から DB path を構築していたため、`launchctl setenv HOME` により attacker-controlled な `TCC.db` へ redirect できた ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` は `com.apple.private.tcc.manager` を保持し、さらに library validation を無効化していた。そのため、`/Library/Audio/Plug-Ins/HAL` に配置した HAL plug-in が任意の TCC right を付与できた ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
