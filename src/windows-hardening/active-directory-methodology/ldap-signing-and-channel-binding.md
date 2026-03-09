# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Why it matters

LDAP relay/MITM により攻撃者は binds を Domain Controllers に転送して認証済みコンテキストを取得できます。これらの経路を阻止するサーバ側の制御が二つあります:

- **LDAP Channel Binding (CBT)** は LDAPS の bind を特定の TLS トンネルに紐付け、異なるチャネル間での relays/replays を破壊します。
- **LDAP Signing** は整合性保護された LDAP メッセージを強制し、改ざんとほとんどの未署名の relays を防ぎます。

**Quick offensive check**: `netexec ldap <dc> -u user -p pass` のようなツールはサーバの posture を表示します。もし `(signing:None)` と `(channel binding:Never)` が見えるなら、Kerberos/NTLM **relays to LDAP** が可能です（例: KrbRelayUp を使って `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き込み、RBCD により管理者をなりすます等）。

**Server 2025 DCs** は新しい GPO（**LDAP server signing requirements Enforcement**）を導入しており、**Not Configured** のままにするとデフォルトで **Require Signing** になります。強制を回避するにはそのポリシーを明示的に **Disabled** に設定する必要があります。

## LDAP Channel Binding (LDAPS only)

- **要件**:
- CVE-2017-8563 パッチ（2017）が Extended Protection for Authentication のサポートを追加します。
- **KB4520412** (Server 2019/2022) は LDAPS CBT の “what-if” テレメトリを追加します。
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (デフォルト、CBTなし)
- `When Supported` (監査: 失敗を記録するがブロックしない)
- `Always` (強制: 有効な CBT なしの LDAPS bind を拒否する)
- **監査**: 表示するには **When Supported** を設定:
- **3074** – LDAPS bind は強制されていれば CBT 検証に失敗していた。
- **3075** – LDAPS bind は CBT データを省略しており、強制されていれば拒否されていた。
- (古いビルドではイベント **3039** が依然として CBT 失敗を示します。)
- **強制**: LDAPS クライアントが CBT を送信し始めたら **Always** に設定してください；これは **LDAPS** のみに有効で（生の 389 には適用されません）。

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows のデフォルトは `Negotiate signing`)
- **DC GPO**:
- レガシー: `Domain controller: LDAP server signing requirements` = `Require signing` (デフォルトは `None`)
- **Server 2025**: レガシー ポリシーを `None` のままにし、`LDAP server signing requirements Enforcement` を `Enabled` に設定してください（Not Configured = デフォルトで強制されます；回避するには `Disabled` に設定）。
- **互換性**: LDAP signing をサポートするのは Windows **XP SP3+** のみ；古いシステムは enforcement を有効にすると動作しなくなります。

## Audit-first rollout (recommended ~30 days)

1. 各 DC で LDAP インターフェース診断を有効にし、未署名の binds をログする（イベント **2889**）：
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC の GPO `LDAP server channel binding token requirements` を **When Supported** に設定して CBT テレメトリを開始します。
3. Directory Service イベントを監視します:
- **2889** – unsigned/unsigned-allow binds (署名非準拠)。
- **3074/3075** – CBT を失敗または省略する LDAPS binds (2019/2022 では KB4520412 と上記のステップ 2 が必要)。
4. 別々の変更で強制適用します:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 参考資料

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
