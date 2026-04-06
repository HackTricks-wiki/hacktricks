# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

macOS Big Sur (11.0) 以降、システムボリュームは APFS スナップショットハッシュツリーを使って暗号的に封印されます。これは Sealed System Volume (SSV) と呼ばれます。システムパーティションは読み取り専用でマウントされ、改変は封印を破ることになり、起動時に検証されます。

The SSV provides:
- Tamper detection — システムのバイナリ／フレームワークへの改変は、暗号的封印が破れることで検出可能です
- Rollback protection — ブートプロセスはシステムスナップショットの整合性を検証します
- Rootkit prevention — root であっても（封印を破らない限り）システムボリューム上のファイルを永続的に変更できません

### SSV ステータスの確認
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
### SSV Writer の権限

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | システムボリュームを以前のスナップショットに戻す |
| `com.apple.private.apfs.create-sealed-snapshot` | システム更新後に新しい sealed snapshot を作成する |
| `com.apple.rootless.install.heritable` | SIP保護パスに書き込む（子プロセスに継承される） |
| `com.apple.rootless.install` | SIP保護パスに書き込む |

### SSV Writer を見つける方法
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

もし攻撃者が `com.apple.private.apfs.revert-to-snapshot` を持つバイナリを侵害した場合、**システムボリュームをアップデート前の状態にロールバックする**ことで、既知の脆弱性を復元できます：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> スナップショットのロールバックは実質的に **セキュリティアップデートを元に戻す** ことになり、以前に修正されたカーネルやシステムの脆弱性を復元します。これは現代の macOS 上で可能な最も危険な操作の一つです。

#### System Binary Replacement

SIPバイパス + SSV 書き込み能力があれば、攻撃者は以下を行えます:

1. システムボリュームを読み書き可能にマウントする
2. システムデーモンやフレームワークライブラリをトロイ化されたバージョンと置き換える
3. スナップショットを再シールする（または SIP が既に低下している場合は壊れたシールを受け入れる）
4. rootkit は再起動後も持続し、ユーザーランドの検出ツールからは見えなくなる

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIPバイパスにより `system_installd` 経由でSSVの変更を可能にする |
| CVE-2022-22583 | PackageKitのスナップショット処理を通じたSSVバイパス |
| CVE-2022-46689 | SIP保護ファイルへの書き込みを許すレースコンディション |

---

## DataVault

### Basic Information

**DataVault** は機密性の高いシステムデータベース向けのAppleの保護レイヤーです。Even **root cannot access DataVault-protected files** — 特定のentitlementsを持つプロセスのみがそれらを読み書きできます。保護対象のストアには以下が含まれます:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | システム全体のTCCプライバシー許可設定 |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | ユーザーごとのTCCプライバシー許可設定 |
| Keychain (system) | `/Library/Keychains/System.keychain` | システムキーチェーン |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | ユーザーのキーチェーン |

DataVault の保護は、カーネルによって検証される拡張属性とボリューム保護フラグを使用してファイルシステムレベルで強制されます。

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault コントローラーの検出
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

#### 直接的な TCC データベースの改変

攻撃者が DataVault コントローラのバイナリを侵害した場合（例：`com.apple.private.tcc.manager` を持つプロセスへのコード注入経由など）、彼らは **TCC データベースを直接改変** して任意のアプリケーションに任意の TCC 権限を付与することができます:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCCデータベースの改ざんは、**究極のプライバシー回避手段**です — ユーザーのプロンプトや可視のインジケータなしに任意の権限を静かに付与します。歴史的に、複数のmacOS権限昇格チェーンは最終ペイロードとしてTCCデータベースへの書き込みで終わっています。

#### Keychain Database Access

DataVaultはkeychainのバックエンドファイルも保護します。DataVaultコントローラが侵害された場合、以下が可能になります:

1. 生のkeychainデータベースファイルを読み取る
2. 暗号化されたkeychainアイテムを抽出する
3. ユーザーのパスワードや回収した鍵を使ってオフラインで復号を試みる

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | DataVault保護ファイルへのsymlinkを介したTCCバイパス |
| CVE-2023-32364 | TCCデータベースの変更につながるSandboxバイパス |
| CVE-2021-30713 | XCSSETマルウェアがTCC.dbを変更することでのTCCバイパス |
| CVE-2020-9934 | 環境変数の操作によるTCCバイパス |
| CVE-2020-29621 | MusicアプリのTCCバイパスがDataVaultに到達 |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
