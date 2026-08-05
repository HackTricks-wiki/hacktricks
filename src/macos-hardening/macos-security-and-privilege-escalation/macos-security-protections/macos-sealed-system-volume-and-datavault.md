# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本情報

**macOS Big Sur (11.0)** 以降、system volume は **APFS snapshot hash tree** を使用して cryptographically sealed されています。これは **Sealed System Volume (SSV)** と呼ばれます。system partition は **read-only** で mount され、変更を加えると seal が破損します。これは boot 中に検証されます。

SSV は以下を提供します：
- **Tamper detection** — system binaries/frameworks への変更は、cryptographic seal の破損によって検出可能
- **Rollback protection** — boot process によって system snapshot の integrity が検証される
- **Rootkit prevention** — root であっても、seal を破損させずに system volume 上のファイルを永続的に変更することはできない

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
| `com.apple.private.apfs.create-sealed-snapshot` | system updates 後に新しい sealed snapshot を作成する |
| `com.apple.rootless.install.heritable` | SIP-protected paths への書き込み（child processes に継承される） |
| `com.apple.rootless.install` | SIP-protected paths への書き込み |

### SSV Writers の検索
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

#### Snapshot Rollback Attack

攻撃者が `com.apple.private.apfs.revert-to-snapshot` を持つバイナリを侵害した場合、**システムボリュームをアップデート前の状態にロールバック**し、既知の脆弱性を復元できます:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback は実質的に**セキュリティアップデートを取り消し**、以前に修正された kernel およびシステムの脆弱性を復元します。これは、現代の macOS で実行可能な操作の中でも最も危険なものの1つです。

#### System Binary Replacement

SIP bypass + SSV write capability があれば、攻撃者は次の操作を実行できます。

1. システムボリュームを read-write でマウントする
2. システムデーモンまたは framework library を trojaned version に置き換える
3. snapshot を再シールする（または、SIP がすでに劣化している場合は壊れた seal を受け入れる）
4. rootkit は再起動後も永続化し、userland の検出ツールからは見えない

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` の `com.apple.rootless.install.heritable` entitlement を悪用して任意の post-install scripts を実行する SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` は post-install script を `/tmp` 配下の SIP-protected folder にステージングしていましたが、`/tmp` 自体は SIP-protected ではないため、その folder に image をマウントして置き換えることが可能でした ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — XNU における copy-on-write race により、read-only の root-owned files への書き込みを可能にする脆弱性 ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** は、機密性の高いシステムデータベースを保護する Apple の protection layer です。**root であっても DataVault-protected files にはアクセスできず**、読み取りまたは変更が可能なのは特定の entitlements を持つプロセスだけです。<sup>[[1]](#references)</sup> 保護対象の store には次のものがあります。

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | システム全体に適用される TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | ユーザーごとの TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | システム keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | ユーザー keychain |

DataVault protection は、extended attributes と volume protection flags を使用して**filesystem level**で適用され、kernel によって検証されます。

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault Controllersの検索
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

攻撃者が DataVault controller binary（例：`com.apple.private.tcc.manager` を持つプロセスへの code injection により）を侵害した場合、**TCC database を直接変更**して、任意の application に任意の TCC permission を付与できます:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database の変更は**究極のプライバシー bypass**です。ユーザーへの prompt や目に見える indicator なしで、あらゆる permission を密かに付与します。これまで、macOS の複数の privilege escalation chain は、最終 payload として TCC database への書き込みに至っています。

#### Keychain Database Access

DataVault は keychain の backing file も保護します。侵害された DataVault controller は、次の操作を実行できます。

1. raw keychain database file の読み取り
2. encrypted keychain item の抽出
3. ユーザーの password または復元した key を使用した offline decryption の試行

### DataVault/TCC Bypass に関係する実際の CVE

| CVE | Description |
|---|---|
| CVE-2024-44131 | FileProvider の symlink race により、privileged helper が TCC で保護された data にアクセス可能になる ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | root として、`NFSHomeDirectory` が攻撃者の管理下にある `TCC.db` を指す**新しい user を作成**できる。login 時に `tccd` がこれを読み込み、grant が適用されて他の user の data に到達できる ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": user の home dir を変更して、攻撃者が管理する TCC.db を配置する ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | bundle-conclusion の欠陥により、prompt なしで app が**donor bundle の TCC grant を継承**できる。実環境では **XCSSET** がこれを悪用し、desktop の screenshot を取得した ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` は `$HOME` から DB path を構築していたため、`launchctl setenv HOME` により攻撃者が管理する `TCC.db` へ redirect できた ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` は `com.apple.private.tcc.manager` を保持し、さらに library validation を無効化していた。そのため `/Library/Audio/Plug-Ins/HAL` に配置された HAL plug-in が任意の TCC rights を付与できた ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
