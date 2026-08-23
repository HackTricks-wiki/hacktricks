# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本情報

**macOS Big Sur (11.0)** 以降、system volume は **APFS snapshot hash tree** を使用して暗号学的に封印されています。これは **Sealed System Volume (SSV)** と呼ばれます。system partition は **read-only** でマウントされ、変更を加えると seal が破壊されます。この seal は boot 時に検証されます。<sup>[[11]](#references)</sup>

SSV は以下を提供します:
- **改ざん検知** — system binaries/frameworks に変更を加えると Merkle-tree root が変化し、Apple が署名した seal が無効になります
- **boot-time authentication** — boot chain は、選択された system snapshot が root filesystem になる前に検証します
- **rootkit resistance** — root 権限であっても、authenticated root を無効化するか、認証済みの update path を侵害しない限り、認証済み system snapshot 内のファイルを永続的に置き換えることはできません

SSV が保護するのは **System** volume であり、それと対になっている書き込み可能な **Data** volume ではありません。Firmlinks によって両方の volume が `/` から見える namespace に統合されるため、書き込み可能に見える path であっても、基盤となる object が sealed snapshot に属していることの証明にはなりません。FileVault と Data Protection は保存データの機密性を保護するものであり、SSV の integrity とは別のものです。<sup>[[11]](#references)</sup>

### SSV ステータスの確認
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
### 実効的なシステムビュー: SSV + Cryptex grafts

最近の macOS リリースでは、`/System` 配下に表示されるすべての実行ファイルが、必ずしも起動済みの SSV snapshot に由来するとは限りません。**Cryptexes** は個別に認証された APFS disk images であり、そのコンテンツは選択されたディレクトリに graft されます。そのため、Rapid Security Responses はベース SSV を再構築せずに、セキュリティ上重要なコンポーネントを置き換えられます。persistence のトリアージやシステムコードの diff を行う場合は、ベース snapshot だけをハッシュするのではなく、稼働中のマウントと Preboot Cryptex store をインベントリしてください:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
ブートチェーンと Rapid Security Response の詳細については、[macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)で説明しています。このセクションでは、SSV の境界自体に焦点を当てます。

### SSV Writer の Entitlements

一部の Apple system binaries には、sealed system volume を変更または管理できる Entitlements が付与されています。

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume を以前の snapshot に戻す |
| `com.apple.private.apfs.create-sealed-snapshot` | system update 後に新しい sealed snapshot を作成する |
| `com.apple.rootless.install.heritable` | SIP-protected paths に書き込む（child processes に継承される） |
| `com.apple.rootless.install` | SIP-protected paths に書き込む |

### SSV Writers の確認
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

攻撃者が `com.apple.private.apfs.revert-to-snapshot` を持つバイナリを侵害した場合、**システムボリュームを更新前の状態にロールバックし**、既知の脆弱性を復元できます：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback は実質的に **security updates を取り消し**、以前にパッチ適用された kernel および system の脆弱性を復元します。これは、modern macOS で実行可能な操作の中でも最も危険なものの 1 つです。

#### System Binary Replacement

SIP bypass + SSV write capability により、攻撃者は次の操作を実行できます。

1. system volume を read-write で mount する
2. system daemon または framework library を trojaned version に置き換える
3. snapshot を再 seal する（または、SIP がすでに degraded している場合は broken seal を受け入れる）
4. rootkit は reboot 後も persistence し、userland の detection tools から見えなくなる

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` の `com.apple.rootless.install.heritable` entitlement を悪用して arbitrary post-install scripts を実行する SIP bypass（[Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)）<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` は post-install script を `/tmp` 配下の SIP-protected folder に staged しますが、`/tmp` 自体は SIP-protected ではないため、その folder に image を mount することで置き換え可能でした（[Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)）<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU における copy-on-write race により、read-only の root-owned files への writes を可能にする（[Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)）<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault** は、sensitive files および directories を保護する entitlement-gated filesystem protection です。BSD flag `UF_DATAVAULT` (`0x00000080`) は、object の read と write の両方に entitlement が必要であることを示します。通常の DAC とは異なり、protection が有効な間は、単に **root** になったり Full Disk Access を取得したりするだけでは、その check を満たしません。<sup>[[4]](#references)[[13]](#references)</sup>

すべての protected database の synonym として「DataVault」を使用しないでください。TCC databases は TCC/FDA および SIP-specific policy によって管理され（[macOS TCC](macos-tcc/README.md) を参照）、keychain item access も Keychain ACLs と cryptographic protection に依存します（[macOS Keychain](../../macos-red-teaming/macos-keychain.md) を参照）。実際の DataVault の例は、一般に `/private/var/folders/.../0/` 配下にある service-owned stores として存在し、Screen Time store などが該当します。parent に対して stat を実行できる場合、この flag は BSD file flags 上で `datavault` として確認できます。

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` objects への access/manage<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC decisions を manage する。これは関連するものの、別個の privacy boundary |
| `com.apple.private.tcc.allow` | entitlement value で指定された selected TCC services を bypass する |
| `com.apple.rootless.storage.TCC` | SIP-protected TCC store に write する |

DataVault-controller entitlement と FDA、backup、indexing、または IPC functionality を組み合わせた process は、特に興味深い対象です。vault を直接 open しようとするのではなく、protected object を ordinary path に copy する confused-deputy primitive を探してください。<sup>[[14]](#references)</sup>

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
### 攻撃シナリオ

#### 直接的なTCCデータベース変更（分離されたTCC境界）

攻撃者がTCC managerプロセス（例：`com.apple.private.tcc.manager`を保持するプロセスへのcode injection）を侵害すると、**TCCデータベースを直接変更**して、任意のアプリケーションに任意のTCC permissionを付与できます。<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database の modification は**究極の privacy bypass**です。ユーザーへの prompt や目に見える indicator なしに、あらゆる permission を silently 付与します。これまで、複数の macOS privilege escalation chain は、最終 payload として TCC database への write に行き着いています。

#### Keychain Database Access

Keychain の backing database への raw access は、plaintext secret への access と同等ではありません。別の privilege boundary によって attacker が database を copy できたとしても、key material と item ACL は引き続き attack する必要があります。DataVault-controller entitlement だけで十分だと想定せず、専用の [macOS Keychain](../../macos-red-teaming/macos-keychain.md) ページを参照してください。

#### Backup-copy boundary: Time Machine

2026 年の analysis により、便利な general pattern が示されました。`backupd` は protected store を copy できるよう、`com.apple.rootless.datavault.controller` と Full Disk Access の両方を保持しています。テストされた configuration では、`/private/var/folders` が Time Machine に含まれており、mount された backup copy では live DataVault boundary が enforce されませんでした。researcher はこれを利用して Screen Time SQLite store の場所を特定し、live vault を開かずに plaintext の restrictions PIN を読み取りました。これを**copy-boundary attack**として扱い、より弱い mount または path の下で vault data を materialize できる backup、export、migration、indexing、diagnostic の deputy を列挙してください。<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
この動作は、バージョンとバックアップのレイアウトに依存します。対象ビルドで検証し、暗号化された Time Machine の保存先はロック中のみコピーを保護することに注意してください。マウントされると、そのアクセス制御も攻撃対象領域の一部になります。

### DataVault/TCC Bypass に関連する実際の CVE

| CVE | 説明 |
|---|---|
| CVE-2024-44131 | 特権ヘルパーが TCC で保護されたデータに到達できる FileProvider の symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root として、**`NFSHomeDirectory` が攻撃者の管理下にある `TCC.db` を指す新しいユーザーを作成する**。ログイン時に `tccd` がそれを読み込み、権限が適用されることで、他のユーザーのデータに到達できる ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": ユーザーの home dir を変更して、攻撃者が管理する TCC.db を設置する ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | アプリが prompt なしで **donor bundle の TCC grants を継承できる** bundle-conclusion の欠陥。実環境では **XCSSET** が desktop の screenshot を取得するために悪用した ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` は `$HOME` から DB path を構築していたため、`launchctl setenv HOME` によって攻撃者が管理する `TCC.db` にリダイレクトできた ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` は `com.apple.private.tcc.manager` **を保持し**、さらに library validation **を無効化していた**ため、`/Library/Audio/Plug-Ins/HAL` に配置した HAL plug-in に任意の TCC 権限を付与させることができた ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft が、System Integrity Protection を bypass できる新しい macOS vulnerability「Shrootless」を発見](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - 不十分な実装でも実行する価値](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass により iCloud からデータを窃取](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS Malware の解明: TCC の bypass](https://blog.kandji.io/malware-bypass-tcc)
- [7] [新しい macOS vulnerability「powerdir」により、承認されていないユーザーデータアクセスが可能になるおそれ](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET malware で Zero-Day TCC bypass が発見される](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework の bypass](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [音楽を再生して TCC を bypass、別名 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA Updates の悪夢 (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [自分の Screen Time passcode を bypass する方法 — source と Time Machine/DataVault の分析](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
