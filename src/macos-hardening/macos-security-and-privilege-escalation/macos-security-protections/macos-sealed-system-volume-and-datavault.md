# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本情報

**macOS Big Sur (11.0)** 以降、システムボリュームは **APFS snapshot hash tree** を使って暗号学的に封印されています。これを **Sealed System Volume (SSV)** と呼びます。システムパーティションは **読み取り専用** でマウントされ、変更を加えると封印が破られ、起動時に検証されます。<sup>[[11]](#references)</sup>

SSV は次の機能を提供します。
- **改ざん検知** — システムバイナリやフレームワークに変更を加えると、Merkle tree のルートが変わり、Apple が署名した封印が無効になります
- **起動時認証** — 起動チェーンは、選択されたシステム snapshot がルートファイルシステムになる前に検証します
- **rootkit 耐性** — authenticated root を無効化するか、許可された更新経路を侵害しない限り、root であっても認証済みシステム snapshot 内のファイルを永続的に置き換えることはできません

SSV が保護するのは **System** ボリュームであり、対になっている書き込み可能な **Data** ボリュームではありません。Firmlink によって両方のボリュームが `/` から見える名前空間に統合されるため、書き込み可能に見えるパスであっても、対象のオブジェクトが封印された snapshot に属しているとは限りません。FileVault と Data Protection は保存データの機密性を保護するものであり、SSV の完全性保護とは別のものです。<sup>[[11]](#references)</sup>

### SSV の状態を確認する

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

最近の macOS リリースでは、`/System` 以下に表示される実行ファイルがすべて、起動中の SSV スナップショットに由来するとは限りません。**Cryptexes** は、選択されたディレクトリに内容が graft される、個別に認証された APFS ディスクイメージです。そのため、Rapid Security Responses はベースの SSV を再構築せずに、セキュリティ上重要なコンポーネントを置き換えられます。永続化の調査やシステムコードの差分比較を行う際は、ベースのスナップショットだけをハッシュするのではなく、稼働中のマウントと Preboot Cryptex ストアをインベントリしてください:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

ブートチェーンとRapid Security Responseの詳細については、[macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)を参照してください。このセクションでは、SSVの境界自体に焦点を当てます。

### SSV Writerのエンタイトルメント

一部のAppleシステムバイナリには、sealed system volumeの変更や管理を可能にするエンタイトルメントがあります。

| エンタイトルメント | 目的 |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | システムボリュームを以前のスナップショットに戻す |
| `com.apple.private.apfs.create-sealed-snapshot` | システムアップデート後に新しいsealed snapshotを作成する |
| `com.apple.rootless.install.heritable` | SIPで保護されたパスに書き込む（子プロセスに継承される） |
| `com.apple.rootless.install` | SIPで保護されたパスに書き込む |

### SSV Writerの特定

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

#### スナップショットのロールバック攻撃

攻撃者が `com.apple.private.apfs.revert-to-snapshot` を持つバイナリを侵害すると、**システムボリュームをアップデート前の状態にロールバック**し、既知の脆弱性を復元できます。

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Snapshot rollback は、以前に修正された kernel とシステムの脆弱性を復元し、実質的に**セキュリティアップデートを取り消します**。これは、最新の macOS で可能な操作の中でも特に危険なものの一つです。

#### システムバイナリの置き換え

SIP bypass + SSV write capability があれば、攻撃者は次のことができます。

1. システムボリュームを read-write でマウントする
2. システムデーモンまたはフレームワークライブラリを trojaned version に置き換える
3. Snapshot に seal を再設定する（または SIP がすでに劣化している場合は、seal が壊れたままにする）
4. rootkit は再起動後も存続し、userland の検出ツールから見えなくなる

### 実際に確認された CVE

| CVE | 説明 |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd` の `com.apple.rootless.install.heritable` entitlement を悪用して任意の post-install script を実行する SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` は post-install script を `/tmp` 内の SIP 保護フォルダーに配置していましたが、`/tmp` 自体は SIP で保護されていないため、そのフォルダーはイメージをマウントして差し替えることができました ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU における copy-on-write race。読み取り専用の root 所有ファイルへの書き込みを可能にする ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### 基本情報

**DataVault** は、機密ファイルやディレクトリを保護する、entitlement によって制御されるファイルシステム保護機能です。BSD flag `UF_DATAVAULT` (`0x00000080`) は、オブジェクトの読み取りと書き込みの両方に entitlement が必要であることを示します。通常の DAC とは異なり、保護が有効な場合、単に **root** になったり Full Disk Access を取得したりしても、このチェックを満たすことはできません。<sup>[[4]](#references)[[13]](#references)</sup>

すべての保護データベースを「DataVault」と呼ばないでください。TCC データベースは TCC/FDA および SIP 固有のポリシーによって制御されます（[macOS TCC](macos-tcc/README.md) を参照）。一方、Keychain item へのアクセスは Keychain ACL と暗号化保護にも依存します（[macOS Keychain](../../macos-red-teaming/macos-keychain.md) を参照）。実際の DataVault の例は、Screen Time ストアなど、`/private/var/folders/.../0/` 以下にあるサービス所有のストアとして見つかることがよくあります。親ディレクトリを stat できる場合、BSD file flags ではこの flag は `datavault` と表示されます。

### DataVault Controller Entitlements

| Entitlement | 境界 |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` オブジェクトへのアクセスと管理<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC の判定を管理する。関連はあるが、別個のプライバシー境界 |
| `com.apple.private.tcc.allow` | entitlement の値に指定された一部の TCC サービスをバイパスする |
| `com.apple.rootless.storage.TCC` | SIP 保護された TCC ストアへの書き込み |

DataVault-controller entitlement と FDA、backup、indexing、または IPC 機能を組み合わせたプロセスは、特に注目すべき対象です。vault を直接開こうとするのではなく、保護されたオブジェクトを通常のパスへコピーする confused-deputy primitive を探してください。<sup>[[14]](#references)</sup>

### DataVault Controller の特定方法

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

#### TCCデータベースの直接変更（独立したTCC境界）

攻撃者がTCC managerプロセス（例：`com.apple.private.tcc.manager`を持つプロセスへのコードインジェクション）を侵害すると、**TCCデータベースを直接変更**して、任意のアプリケーションに任意のTCC権限を付与できます:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCCデータベースの変更は**究極のプライバシーバイパス**です。ユーザーへのプロンプトや目に見えるインジケーターなしに、あらゆる権限を付与します。これまで、複数のmacOS権限昇格チェーンは、最終ペイロードとしてTCCデータベースへの書き込みを行ってきました。

#### Keychainデータベースへのアクセス

Keychainのバックエンドデータベースへの生のアクセスは、平文の秘密情報へのアクセスと同じではありません。別の権限境界を越えて攻撃者がデータベースをコピーできても、鍵素材やアイテムACLへの攻撃が必要です。DataVaultコントローラーのentitlementで十分だと決めつけず、専用の[macOS Keychain](../../macos-red-teaming/macos-keychain.md)ページを参照してください。

#### バックアップコピーの境界: Time Machine

2026年の分析では、有用な一般的パターンが実証されました。`backupd`は、保護されたストアをコピーできるよう、`com.apple.rootless.datavault.controller`とFull Disk Accessの両方を持っています。テストされた構成では、`/private/var/folders`がTime Machineの対象に含まれており、マウントされたバックアップコピーには、稼働中のDataVault境界が適用されませんでした。研究者はこれを利用してScreen TimeのSQLiteストアを特定し、稼働中のVaultを開くことなく、平文の制限用PINを読み取りました。これは**コピー境界攻撃**として捉えてください。バックアップ、エクスポート、移行、インデックス作成、診断を担い、より制約の弱いマウントやパスにVaultデータを実体化できる代理プロセスを列挙します。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

この動作はバージョンとバックアップのレイアウトに依存します。対象のビルドで検証してください。また、暗号化されたTime Machineの保存先がコピーを保護するのはロック中だけであり、マウント後はそのアクセス制御も攻撃対象領域の一部になることを忘れないでください。

### DataVault/TCC Bypassに関する実世界のCVE

| CVE | 説明 |
|---|---|
| CVE-2024-44131 | FileProviderのsymlink raceにより、特権ヘルパーがTCCで保護されたデータにアクセスできる ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root権限で、`NFSHomeDirectory`が攻撃者の制御下にある`TCC.db`を指す新規ユーザーを作成する。ログイン時に`tccd`がそれを読み込み、許可設定が適用されて、他のユーザーのデータにアクセスできる ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | 「powerdir」: ユーザーのホームディレクトリを変更し、攻撃者が制御するTCC.dbを配置する ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusionの欠陥により、アプリがプロンプトなしで**ドナーバンドルのTCC許可設定を継承**できる。実際の攻撃では**XCSSET**がデスクトップのスクリーンショット撮影に悪用 ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`が`$HOME`からDBのパスを構築していたため、`launchctl setenv HOME`で攻撃者が制御する`TCC.db`にリダイレクトできた ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`は`com.apple.private.tcc.manager`を保持し、**さらに**library validationを無効にしていたため、`/Library/Audio/Plug-Ins/HAL`に配置したHALプラグインから任意のTCC権限を付与できた ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoftが新たなmacOSの脆弱性Shrootlessを発見、System Integrity Protectionを回避できる可能性](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [技術分析: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - 下手でもやる価値はある](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypassでiCloudのデータを窃取](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOSマルウェアの解明: TCCの回避](https://blog.kandji.io/malware-bypass-tcc)
- [7] [新たなmacOSの脆弱性「powerdir」により、ユーザーデータへの不正アクセスが可能になるおそれ](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSETマルウェアでZero-Day TCC bypassを発見](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Frameworkの回避](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [音楽を再生してTCCを回避する、別名CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTAアップデートの悪夢 (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [自分のScreen Timeパスコードを回避する方法 — ソースコードとTime Machine/DataVaultの分析](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
