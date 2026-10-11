# LDAP Signing & Channel Binding のハードニング

{{#include ../../banners/hacktricks-training.md}}

## 重要性

LDAP relay/MITM 攻撃では、認証をドメインコントローラーに転送して、認証済みの LDAP コンテキストを取得します。関連する2つの制御によって、こうした経路を制限できます。

- **LDAP channel binding (CBT)** は、LDAPS で使用される TLS サーバー証明書／チャネルに該当する認証を紐付け、チャネルをまたぐ relay を困難にします。
- **LDAP signing** は、SASL LDAP bind に整合性保護を要求します。機密性は追加されないため、LDAP の内容も暗号化する必要がある場合は TLS を使用してください。<sup>[[2]](#references)</sup>

**簡易的なセキュリティ状態の確認**: `netexec ldap <dc> -u user -p pass` などのツールで、検出された signing と channel-binding ポリシーを確認できます。(signing:None) と (channel binding:Never) は制御が欠如していることを示します。ただし、relay の成功は、取得した認証タイプ、EPA の動作、アカウント権限、対象プロトコル、relay 対策にも左右されます。relay されたプリンシパルが必要な権限を持つ場合、KrbRelayUp などのツールで `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み、resource-based constrained delegation (RBCD) を構成して、作成した委任経路を使い、特権プリンシパルになりすますことができます。<sup>[[4]](#references)</sup>

**Server 2025 DC** では新しい GPO (**LDAP server signing requirements Enforcement**) が導入され、**Not Configured** の場合は既定で **Require Signing** になります。適用を避けるには、このポリシーを明示的に **Disabled** に設定する必要があります。<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS のみ)

- **要件**:
  - CVE-2017-8563 のパッチ (2017) により、Extended Protection for Authentication のサポートが追加されます。<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) により、LDAPS CBT の「what-if」テレメトリが追加されます。<sup>[[2]](#references)</sup>
- **GPO (DC)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (既定、CBT なし)
  - `When Supported` (部分的な適用: CBT に対応するクライアントには有効なトークンを要求します。CBT 非対応のクライアントは引き続き bind でき、監査イベントが記録されます)
  - `Always` (適用: 有効な CBT のない LDAPS bind を拒否します)<sup>[[1]](#references)</sup>
- **監査**: **When Supported** に設定して、次のイベントを検出します:
  - **3074** – 適用時に CBT 検証に失敗していた LDAPS bind。
  - **3075** – CBT データが含まれておらず、適用時に拒否される LDAPS bind。
  - (古いビルドでは、イベント **3039** も引き続き CBT の失敗を示します。)<sup>[[1]](#references)[[2]](#references)</sup>
- **適用**: LDAPS クライアントが CBT を送信するようになったら **Always** に設定します。これは **LDAPS** でのみ有効で、raw 389 には適用されません。<sup>[[1]](#references)</sup>

`When Supported` は監査のみのモードではありません。CBT 対応クライアントの CBT を検証しつつ、CBT 非対応クライアントは許可します。[Microsoft のポリシーリファレンス](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)では、バージョンによって異なる既定値が説明されています。LDAP signing は LDAP/389 上の該当する bind に適用され、channel binding は TLS で保護された LDAP 認証に適用されます。


## LDAP Signing

- **クライアント GPO**: `Network security: LDAP client signing requirements` = `Require signing` (最新の Windows では既定値の `Negotiate signing` ではなく、こちらを設定)。<sup>[[1]](#references)</sup>
- **DC GPO**:
  - 従来: `Domain controller: LDAP server signing requirements` = `Require signing` (既定値は `None`)。<sup>[[2]](#references)</sup>
  - **Server 2025**: 従来のポリシーは `None` のままにし、`LDAP server signing requirements Enforcement` = `Enabled` に設定します (`Not Configured` は既定で適用されます。回避するには `Disabled` に設定します)。<sup>[[1]](#references)</sup>
- **互換性**: simple bind または署名なしの SASL bind を使用する、Windows 以外のアプライアンスやアプリケーションを洗い出してください。Microsoft はサポート対象の Windows バージョンでのサポートを文書化しています。旧式クライアントの互換性については、XP のバージョンを基準に一律に判断せず、実際のクライアントスタックで確認してください。<sup>[[2]](#references)</sup>

## 監査を先行する段階的な導入 (推奨期間: 約30日)

1. 各 DC で LDAP インターフェイスの診断を有効にし、署名なし bind をログに記録します (イベント **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. DC GPO `LDAP server channel binding token requirements` を **When Supported** に設定し、部分的な CBT 適用とテレメトリを有効にします。事前にレガシークライアントとの互換性を確認してください。<sup>[[1]](#references)</sup>
3. Directory Service イベントを監視します:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – 署名なし／署名なし許可のバインド（署名要件に準拠していない）。
   - **3074/3075** – 失敗する、または CBT が付与されない LDAPS バインド（2019/2022 では KB4520412 と上記の手順 2 が必要）。
4. 個別の変更として適用します:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always**（DC）。
   - `LDAP client signing requirements` = **Require signing**（クライアント）。
   - `LDAP server signing requirements` = **Require signing**（DC）、または（Server 2025 の場合）`LDAP server signing requirements Enforcement` = **Enabled**。

## References

- [1] [TrustedSec - LDAP Channel Binding と LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding と signing の要件](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 緩和策の更新](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno（LDAP signing 無効 → Kerberos relay → RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
