# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## 重要性

LDAP relay/MITM により、攻撃者は Domain Controller に bind を転送し、認証済みコンテキストを取得できます。サーバー側の次の 2 つの制御により、これらの経路を抑止できます。

- **LDAP Channel Binding (CBT)** は LDAPS bind を特定の TLS トンネルに結び付け、異なるチャネル間での relay/replay を阻止します。
- **LDAP Signing** は整合性保護された LDAP メッセージを強制し、改ざんや大部分の unsigned relay を防止します。

**簡易 offensive check**: `netexec ldap <dc> -u user -p pass` などのツールで、サーバーの状態を確認できます。`(signing:None)` と `(channel binding:Never)` が表示される場合、Kerberos/NTLM **relays to LDAP** が可能です（例: KrbRelayUp を使用して `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み、RBCD を設定して administrators を impersonate する）。<sup>[[4]](#references)</sup>

**Server 2025 DCs** には新しい GPO（**LDAP server signing requirements Enforcement**）が導入されており、**Not Configured** のままにするとデフォルトで **Require Signing** になります。enforcement を回避するには、この policy を明示的に **Disabled** に設定する必要があります。<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch（2017 年）により、Extended Protection for Authentication の support が追加されます。<sup>[[3]](#references)</sup>
- **KB4520412**（Server 2019/2022）により、LDAPS CBT の「what-if」telemetry が追加されます。<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never`（default、CBT なし）
- `When Supported`（audit: failures を出力するが、block はしない）
- `Always`（enforce: 有効な CBT なしの LDAPS bind を reject）<sup>[[1]](#references)</sup>
- **Audit**: **When Supported** に設定して、以下を検出します。
- **3074** – enforcement されていた場合、LDAPS bind が CBT validation に失敗していたことを示します。
- **3075** – LDAPS bind に CBT data が含まれておらず、enforcement されていた場合に reject されていたことを示します。
- （Event **3039** は、古い build でも CBT failures を示します。）<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS clients が CBTs を送信するようになったら **Always** に設定します。これは **LDAPS** でのみ有効であり、raw 389 では有効になりません。<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing`（modern Windows ではデフォルトが `Negotiate signing`）。<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing`（default は `None`）。<sup>[[2]](#references)</sup>
- **Server 2025**: legacy policy は `None` のままにし、`LDAP server signing requirements Enforcement` = `Enabled` に設定します（**Not Configured** = デフォルトで enforced、回避するには **Disabled** に設定）。<sup>[[1]](#references)</sup>
- **Compatibility**: LDAP signing を support するのは Windows **XP SP3+** のみです。enforcement を有効にすると、より古い system は動作しなくなります。

## Audit-first rollout（推奨期間: 約 30 日）

1. 各 DC で LDAP interface diagnostics を有効にし、unsigned binds を log に記録します（Event **2889**）。<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO `LDAP server channel binding token requirements` を **When Supported** に設定し、CBT telemetry を開始します。<sup>[[1]](#references)</sup>
3. Directory Service events を監視します。<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds（signing 非準拠）。
- **3074/3075** – 失敗する、または CBT を省略する LDAPS binds（2019/2022 では KB4520412 と上記の手順 2 が必要）。
4. 個別の変更として適用します。<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always**（DCs）。
- `LDAP client signing requirements` = **Require signing**（clients）。
- `LDAP server signing requirements` = **Require signing**（DCs）**または**（Server 2025 の場合）`LDAP server signing requirements Enforcement` = **Enabled**。

## References

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
