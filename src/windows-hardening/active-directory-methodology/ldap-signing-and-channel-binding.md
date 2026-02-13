# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## なぜ重要か

LDAP relay/MITM により攻撃者は binds を Domain Controllers に転送して認証済みコンテキストを得ることができます。サーバー側でこれらの経路を鈍らせるための 2 つの制御があります:

- **LDAP Channel Binding (CBT)** は LDAPS の bind を特定の TLS トンネルに紐付け、異なるチャネル間でのリレー/リプレイを阻止します。
- **LDAP Signing** は整合性保護された LDAP メッセージを強制し、改ざんとほとんどの未署名リレーを防ぎます。

**Server 2025 DCs** は新しい GPO（**LDAP server signing requirements Enforcement**）を導入し、**Not Configured** のままにすると既定で **Require Signing** になります。強制を回避するには、そのポリシーを明示的に **Disabled** に設定する必要があります。

## LDAP Channel Binding (LDAPS only)

- **要件**:
- CVE-2017-8563 patch (2017) が Extended Protection for Authentication のサポートを追加します。
- **KB4520412** (Server 2019/2022) は LDAPS CBT の “what-if” テレメトリを追加します。
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never`（既定、CBT なし）
- `When Supported`（監査: 失敗を記録するがブロックしない）
- `Always`（強制: 有効な CBT がない LDAPS binds を拒否）
- **監査**: **When Supported** を設定して以下を可視化:
- **3074** – LDAPS bind は強制されていれば CBT 検証に失敗していたことを示します。
- **3075** – LDAPS bind は CBT データを省略しており、強制されれば拒否されます。
- （Event **3039** は古いビルドでの CBT 失敗を引き続き通知します。）
- **強制**: LDAPS クライアントが CBT を送信するようになったら **Always** に設定してください; 効果があるのは **LDAPS** のみ（raw 389 では有効ではありません）。

## LDAP Signing

- **クライアント GPO**: `Network security: LDAP client signing requirements` = `Require signing`（現代の Windows のデフォルトは `Negotiate signing`）
- **DC GPO**:
- レガシー: `Domain controller: LDAP server signing requirements` = `Require signing`（デフォルトは `None`）
- **Server 2025**: レガシー ポリシーを `None` のままにし、`LDAP server signing requirements Enforcement` = `Enabled` に設定します（Not Configured = デフォルトで強制されます；回避するには `Disabled` に設定してください）。
- **互換性**: LDAP signing をサポートするのは Windows **XP SP3+** のみです；古いシステムは強制を有効にすると動作しなくなります。

## 監査優先の展開（推奨：約30日）

1. 各 DC で LDAP インターフェイス診断を有効にし、未署名の binds をログに記録する（Event **2889**）:
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC の GPO `LDAP server channel binding token requirements` = **When Supported** に設定して CBT テレメトリを開始する。
3. Directory Service イベントを監視する:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. 個別の変更で強制する:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**。

## 参考資料

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
