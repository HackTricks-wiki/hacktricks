# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Check the amazing post from:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 攻撃者向け TL;DR
- Kerberos is the default AD auth protocol; most lateral-movement chains will touch it.
- **3つのオペレータ段階**で考える:
- **AS-REQ / AS-REP** → password/hash/certificate から **TGT** を取得する。ここが **AS-REP roasting**、**over-pass-the-hash / pass-the-key**、**PKINIT** の領域。
- **TGS-REQ / TGS-REP** → TGT を使って **service tickets** を取得する。ここが **Kerberoasting**、**S4U abuse**、**delegation abuse**、そして多くの **ticket-forging tradecraft** に関係する。
- **AP-REQ / AP-REP** → ticket を service に提示する。ここが **pass-the-ticket** と service 固有の lateral movement の場面。
- ハンズオン用の cheatsheet（AS-REP/Kerberoasting、ticket forgery、delegation abuse など）は以下を参照:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- このページは **概要 / 「最近何が変わったか」** の索引として使い、その後で [Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md)、または [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) の専用ページへ進む。

## 最新の攻撃メモ (2024-2026)
- **RC4 hardening はデフォルトを変えただけで、Kerberos 自体は変わっていない** – 現代の DC hardening は、`msDS-SupportedEncryptionTypes` を明示していないアカウントに対する **デフォルトの想定 encryption types** に重点を置く。2026 の展開後は、こうしたアカウントが patched DC ではますます **AES-only** をデフォルトにするため、盲目的な `/rc4` Kerberoast の前提はより失敗しやすい。とはいえ、**明示的に RC4 を有効化した service accounts** は依然として優れたオフライン crack 対象。
- **PAC validation enforcement は forged tickets に重要** – 2024 の PAC-signature hardening により、**golden/diamond/sapphire/extraSID-style abuses** では、より現実的な PAC data と正しい signing context が必要になる。未パッチの domain や、compatibility/audit-style deployments のままの domain は、依然としてより柔らかい target。
- **certificate-based Kerberos は 2回変わった**:
- **Strong certificate binding** (KB5014754 timeline) により、雑な certificate-to-account mappings は、完全に enforced された環境では信頼性が下がる。
- **CVE-2025-26647** により、**altSecID / SKI certificate mappings** 周辺にさらなる hardening layer が追加された。DC が未パッチ、監査モードのまま、または NTAuth validation を明示的に bypass している場合、pass-the-certificate / shadow-credential の後続 abuse は引き続き実用的。
- **クロスドメイン / クロスフォレストの delegation abuse は依然として非常に有効** – Windows は modern cross-realm **S4U2Self/S4U2Proxy** フローをサポートしているため、別の domain にある writable な delegation attributes は今でも価値が高い。制約になるのは通常 protocol support ではなく、tooling の精度と trust/policy の詳細。
- **Windows Server 2025 は dMSA** migration logic によって新しい Kerberos 近接の attack surface を導入した。2025 domain で OU や service-account objects に対する delegated rights を見つけたら、単なる「別の gMSA」として扱わず、専用の [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) を確認する。

## 現代の domain における高速 operator チェック

Kerberos attack path を選ぶ前に、次の4つを素早く確認する:

1. **どの accounts がまだ RC4-friendly か?**
2. **どの users が pre-auth を必要としないか?**
3. **どの objects が delegation abuse を露出しているか?**
4. **domain のどの部分が最近の hardening を適用するのに十分新しいか?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
実践的な解釈:
- もし **興味深い SPN アカウントが明示的に RC4 対応** なら、Kerberoasting は引き続き安価で高速です。
- ほとんどのサービスアカウントに **明示的な etype 設定がない** 場合、更新済みの 2026 DC では **AES-only** の挙動を想定し、より遅いオフライン総当たり、または別の経路を計画してください。
- **RBCD / KCD / unconstrained delegation** が存在する場合、S4U はしばしば brute-force より有効です。
- **certificate auth** が使われている場合、失敗した PKINIT 経路が **必ずしも** 証明書が無価値であることを意味しない点に注意してください。多くの環境では、同じ証明書が **Schannel/LDAPS** の悪用にも使えます（[AD Certificates / PKINIT abuse](ad-certificates.md) を参照）。

## 攻撃計画を変える一般的な Kerberos エラー
- **`KDC_ERR_ETYPE_NOTSUPP`** → 対象アカウント / DC が、要求した暗号化方式を使いません。RC4 のみで再試行するのはやめ、**AES keys** を使うか、代わりに **AES** roast material を要求してください。
- **`KRB_AP_ERR_MODIFIED`** → おそらく **正しくない service key**、**正しくない SPN**、またはサービスアカウントと一致しない偽造チケットを使っています。
- **`KRB_AP_ERR_SKEW`** → 時刻がずれています。まず DC に同期してください。
- S4U / delegation フロー中の **`KDC_ERR_BADOPTION`** → 多くの場合、**sensitive/not-delegable users**、誤った delegation model、または **classic KCD** を使おうとしていて、**RBCD** のみが non-forwardable な S4U2Self ticket を受け入れる状況を意味します。

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
