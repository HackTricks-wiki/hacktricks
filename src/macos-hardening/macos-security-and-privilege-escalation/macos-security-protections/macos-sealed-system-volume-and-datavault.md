# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本情報

**macOS Big Sur (11.0)** 以降、システムボリュームは **APFS snapshot hash tree** を使用して暗号学的に封印されています。これを **Sealed System Volume (SSV)** と呼びます。システムパーティションは **read-only** でマウントされ、変更を加えると封印が破られます。この封印は boot 時に検証されます。<sup>[[11]](#references)</sup>

SSV は以下を提供します:
- **Tamper detection** — システムバイナリや framework が変更されると、暗号学的な封印が破られるため検出可能
- **Rollback protection** — boot プロセスによって system snapshot の整合性が検証される
- **Rootkit prevention** — root であっても、封印を破らずに system volume 上のファイルを永続的に変更することはできない

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

一部の Apple system binaries には、sealed system volume を変更または管理できる entitlements が付与されています。

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume を以前の snapshot に戻す |
| `com.apple.private.apfs.create-sealed-snapshot` | system update 後に新しい sealed snapshot を作成する |
| `com.apple.rootless.install.heritable` | SIP で保護された path への書き込み（child process に継承） |
| `com.apple.rootless.install` | SIP で保護された path への書き込み |

### SSV Writers の発見
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
### 攻撃シナリオ

#### スナップショット・ロールバック攻撃

攻撃者が `com.apple.private.apfs.revert-to-snapshot` を持つバイナリを侵害した場合、**システムボリュームをアップデート前の状態にロールバック**して、既知の脆弱性を復元できます:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback は、以前に修正された kernel および system の脆弱性を復元し、**security updates を事実上取り消します**。これは、現代の macOS で実行可能な最も危険な操作の一つです。

#### System Binary Replacement

SIP bypass + SSV write capability により、攻撃者は次の操作を実行できます。

1. system volume を read-write で mount する
2. system daemon または framework library を trojaned version に置き換える
3. snapshot を再度 seal する（または、SIP がすでに degraded している場合は broken seal を受け入れる）
4. rootkit は reboot 後も persistence し、userland detection tools からは見えない

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` の `com.apple.rootless.install.heritable` entitlement を悪用して SIP bypass を行い、任意の post-install scripts を実行する ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` は SIP-protected folder 内の `/tmp` に post-install script を staging していましたが、`/tmp` 自体は SIP-protected ではないため、その folder に image を mount することで置き換え可能でした ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU における copy-on-write race により、read-only の root-owned files への write を可能にする ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault** は、機密性の高い system databases を保護する Apple の protection layer です。**root であっても DataVault-protected files にはアクセスできず**、読み取りまたは変更が可能なのは特定の entitlements を持つ processes のみです。<sup>[[4]](#references)</sup> 保護される stores には次のものが含まれます。

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | system-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | user ごとの TCC privacy decisions |
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
### DataVault Controllerを探す
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

#### TCCデータベースの直接変更

攻撃者がDataVault controller binary（`com.apple.private.tcc.manager`を持つprocessへのcode injectionなど）を侵害した場合、**TCCデータベースを直接変更**して、任意のapplicationに任意のTCC permissionを付与できます:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database の変更は**究極のプライバシーバイパス**です。ユーザーへのプロンプトや目に見えるインジケーターなしで、あらゆる権限をサイレントに付与します。歴史的に、macOS の複数の privilege escalation chain は、最終 payload として TCC database への書き込みに行き着いています。

#### Keychain Database Access

DataVault は keychain の backing files も保護します。侵害された DataVault controller は、以下を実行できます。

1. raw keychain database files の読み取り
2. encrypted keychain items の抽出
3. ユーザーの password または復元した keys を使用した offline decryption の試行

### DataVault/TCC Bypass に関係する実際の CVE

| CVE | 説明 |
|---|---|
| CVE-2024-44131 | FileProvider の symlink race により、privileged helper が TCC-protected data に到達できる ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root として、`NFSHomeDirectory` が attacker-controlled な `TCC.db` を指す**新しいユーザーを作成**できる。ログイン時に `tccd` がそれを読み込み、grant が適用されることで、他のユーザーの data に到達できる ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": ユーザーの home dir を変更して、attacker-controlled な TCC.db を配置する ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion flaw により、アプリがプロンプトなしで**donor bundle の TCC grants を継承**できる。実環境では **XCSSET** によって悪用され、desktop の screenshot が取得された ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` が `$HOME` から DB path を構築していたため、`launchctl setenv HOME` により attacker-controlled な `TCC.db` へリダイレクトできた ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` が `com.apple.private.tcc.manager` を保持し、**library validation も無効化**していたため、`/Library/Audio/Plug-Ins/HAL` に配置した HAL plug-in によって任意の TCC rights を付与できた ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

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
