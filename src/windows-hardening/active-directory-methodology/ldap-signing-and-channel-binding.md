# LDAP Signing & Channel Binding の強化

{{#include ../../banners/hacktricks-training.md}}

## 重要な理由

LDAP relay/MITM attacks は、認証を domain controller に転送して、認証済みの LDAP context を取得します。[name-resolution poisoning and relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)では、より広範な手順を説明しています。関連する2つの制御により、こうした攻撃経路を減らせます。

- **LDAP channel binding (CBT)** は、LDAPS で使用される TLS server certificate/channel に該当する認証を結び付け、異なる channel 間の relay を困難にします。
- **LDAP signing** は、SASL LDAP bind に integrity protection を要求します。機密性は付加されないため、LDAP の内容も暗号化する必要がある場合は TLS を使用してください。<sup>[[2]](#references)</sup>

**簡易的な設定確認**: `netexec ldap <dc> -u user -p pass` などのツールは、検出された signing と channel-binding のポリシーを報告します。(signing:None) と (channel binding:Never) は制御が設定されていないことを示します。ただし、relay の成功は、取得した認証の種類、EPA の動作、アカウント権限、対象プロトコル、relay の保護策にも左右されます。relay された principal に必要な権限がある場合、KrbRelayUp などのツールで `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き込み、resource-based constrained delegation (RBCD) を設定し、その委任経路を使って特権 principal に impersonate できます。<sup>[[4]](#references)</sup>

**Server 2025 DC** では新しい GPO (**LDAP server signing requirements Enforcement**) が導入されており、**Not Configured** のままにすると、既定で **Require Signing** になります。適用を回避するには、このポリシーを明示的に **Disabled** に設定する必要があります。<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS only)

- **要件**:
  - CVE-2017-8563 の patch (2017) により、Extended Protection for Authentication のサポートが追加されます。<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) により、LDAPS CBT の「what-if」テレメトリが追加されます。<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (既定、CBT なし)
  - `When Supported` (部分的な適用: CBT 対応クライアントには有効な token が必要です。CBT 非対応クライアントは引き続き bind でき、監査イベントが出力されます)
  - `Always` (適用: 有効な CBT がない LDAPS bind を拒否)<sup>[[1]](#references)</sup>
- **監査**: **When Supported** に設定して、次のイベントを確認します。
  - **3074** – 適用時に CBT 検証で失敗する LDAPS bind。
  - **3075** – CBT データがなく、適用時に拒否される LDAPS bind。
  - (古い build では、イベント **3039** が引き続き CBT の失敗を示します。)<sup>[[1]](#references)[[2]](#references)</sup>
- **適用**: LDAPS クライアントが CBT を送信するようになったら **Always** に設定します。これは **LDAPS** でのみ有効で、raw 389 には適用されません。<sup>[[1]](#references)</sup>

`When Supported` は監査のみの設定ではありません。CBT 対応クライアントでは CBT を検証し、CBT 非対応クライアントは許可します。[Microsoft policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)では、バージョンごとの既定値について説明しています。LDAP signing は LDAP/389 上の該当する bind に適用され、channel binding は TLS で保護された LDAP 認証に適用されます。


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (最近の Windows での既定値 `Negotiate signing` とは異なります)。<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (既定値は `None`)。<sup>[[2]](#references)</sup>
  - **Server 2025**: legacy policy は `None` のままにし、`LDAP server signing requirements Enforcement` = `Enabled` に設定します (`Not Configured` では既定で適用されます。適用を回避するには `Disabled` に設定します)。<sup>[[1]](#references)</sup>
- **互換性**: simple bind または unsigned SASL bind を使用する、Windows 以外のアプライアンスやアプリケーションを棚卸しします。Microsoft はサポート対象の Windows バージョンでのサポートを文書化しています。legacy client の互換性に関する説明を XP のバージョン要件だけに単純化せず、実際の client stack で確認してください。<sup>[[2]](#references)</sup>

## 監査を優先した段階的な導入 (推奨期間: 約30日)

1. 各 DC で LDAP interface diagnostics を有効にして、unsigned bind を記録します (イベント **2889**)。<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. DC GPO `LDAP server channel binding token requirements` = **When Supported** に設定し、部分的な CBT 適用とテレメトリを有効にします。まずレガシークライアントとの互換性を確認してください。<sup>[[1]](#references)</sup>
3. Directory Service イベントを監視します。<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow bind（signing の準拠違反）。
   - **3074/3075** – 失敗する、または CBT が欠落する LDAPS bind（2019/2022 では KB4520412 と上記の手順 2 が必要）。
4. 以下を別々の変更として適用します。<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always**（DC）。
   - `LDAP client signing requirements` = **Require signing**（クライアント）。
   - `LDAP server signing requirements` = **Require signing**（DC）、または（Server 2025）`LDAP server signing requirements Enforcement` = **Enabled**。



## References

- [1] [TrustedSec - LDAP Channel Binding と LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding と signing の要件](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 緩和アップデート](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno（LDAP signing 無効 → Kerberos relay → RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
