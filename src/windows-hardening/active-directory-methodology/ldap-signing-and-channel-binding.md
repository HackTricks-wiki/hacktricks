# LDAP Signing & Channel Binding ハードニング

{{#include ../../banners/hacktricks-training.md}}

## なぜ重要か

LDAP relay/MITM により攻撃者は binds を Domain Controllers に転送して認証済みコンテキストを取得できます。サーバー側の二つの制御がこの経路を阻止します:

- **LDAP Channel Binding (CBT)** は LDAPS bind を特定の TLS トンネルに紐付け、異なるチャネル間での relays/replays を断ちます。
- **LDAP Signing** は整合性保護された LDAP メッセージを強制し、改ざんや未署名のほとんどの relays を防ぎます。

**Quick offensive check**: `netexec ldap <dc> -u user -p pass` のようなツールはサーバーの姿勢を出力します。もし `(signing:None)` と `(channel binding:Never)` が表示されれば、Kerberos/NTLM による **relays to LDAP** が実行可能です（例: KrbRelayUp を使って `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き込み RBCD により管理者を偽装する等）。

**Server 2025 DCs** は新しい GPO (**LDAP server signing requirements Enforcement**) を導入しており、**Not Configured** のままだと既定で **Require Signing** が適用されます。適用（enforcement）を避けるには、そのポリシーを明示的に **Disabled** に設定する必要があります。

## LDAP Channel Binding (LDAPS only)

- **要件**:
- CVE-2017-8563 パッチ（2017）は Extended Protection for Authentication のサポートを追加します。
- **KB4520412** (Server 2019/2022) は LDAPS CBT の “what-if” テレメトリを追加します。
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (デフォルト、CBTなし)
- `When Supported` (監査: 失敗を記録するがブロックはしない)
- `Always` (適用: 有効な CBT がない LDAPS bind を拒否する)
- **Audit**: **When Supported** を設定して可視化する:
- **3074** – 適用されていれば LDAPS bind は CBT 検証に失敗していた。
- **3075** – LDAPS bind が CBT データを省略しており、適用されていれば拒否されていた。
- (イベント **3039** は古いビルドで依然として CBT 失敗を示します。)
- **Enforcement**: LDAPS クライアントが CBT を送信するようになったら **Always** に設定してください; 効果があるのは **LDAPS** のみ（生の 389 ではありません）。

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows のデフォルト `Negotiate signing` と対比して)
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (デフォルトは `None`)
- **Server 2025**: レガシーポリシーを `None` のままにして、`LDAP server signing requirements Enforcement` = `Enabled` に設定してください（Not Configured = デフォルトで強制されます。適用を避けるには `Disabled` に設定する）。
- **Compatibility**: LDAP signing をサポートするのは Windows **XP SP3+** のみです; 古いシステムは enforcement を有効にすると動作しなくなります。

## 監査優先のロールアウト（推奨：約30日）

1. 各 DC で LDAP インターフェース診断を有効にし、未署名の bind をログに記録する（イベント **2889**）:
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC の GPO `LDAP server channel binding token requirements` = **When Supported** を設定し、CBT テレメトリを開始します。
3. Directory Service イベントを監視します:
- **2889** – unsigned/unsigned-allow binds (署名非準拠)。
- **3074/3075** – LDAPS binds that would fail or omit CBT (2019/2022 では KB4520412 と上記ステップ 2 が必要)。
4. 個別の変更で強制適用します:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 参考資料

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
