# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**こちらの素晴らしい投稿も確認してください:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 攻撃者向け TL;DR
- Kerberos は AD のデフォルト auth protocol であり、ほとんどの lateral-movement chain がこれに触れる。
- **3つの operator phase** で考える:
- **AS-REQ / AS-REP** → password/hash/certificate を使用して **TGT** を取得する。ここに **AS-REP roasting**、**over-pass-the-hash / pass-the-key**、**PKINIT** が該当する。
- **TGS-REQ / TGS-REP** → TGT を使用して **service tickets** を取得する。ここで **Kerberoasting**、**S4U abuse**、**delegation abuse**、そして多くの **ticket-forging tradecraft** が関係する。
- **AP-REQ / AP-REP** → ticket を service に提示する。ここで **pass-the-ticket** と service-specific lateral movement が発生する。
- 実践的な cheatsheets（AS-REP/Kerberoasting、ticket forgery、delegation abuse など）については、以下を参照:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- このページは **overview / 「最近変更された内容」** の index として使用し、その後 [Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md)、または [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) の専用ページへ移動する。

## 新しい攻撃メモ（2024-2026）
- **RC4 hardening によって変わったのはデフォルトであり、Kerberos 自体ではない** – modern DC hardening では、`msDS-SupportedEncryptionTypes` を明示的に設定していないアカウントに対する **default assumed encryption types** に重点が置かれている。2026年の rollout 後、patched DC 上ではこれらのアカウントが **AES-only** になるケースが増えるため、無条件の `/rc4` Kerberoast の想定はより頻繁に失敗する。ただし、**明示的に RC4-enabled な service accounts は、依然として優れた offline-crack target である**。
- **PAC validation enforcement は forged tickets にとって重要** – 2024年の PAC-signature hardening により、**golden/diamond/sapphire/extraSID-style abuses** には、より現実的な PAC data と正しい signing context が必要になった。Unpatched domain、または compatibility/audit-style deployment のままの domain は、依然としてより soft な target である。
- **Certificate-based Kerberos は2度変更された**:
- **Strong certificate binding**（KB5014754 timeline）により、fully enforced environment では、ずさんな certificate-to-account mapping の信頼性が低下する。
- **CVE-2025-26647** により、**altSecID / SKI certificate mappings** に対する別の hardening layer が追加された。DC が unpatched、依然として auditing 中、または NTAuth validation を明示的に bypass している場合、pass-the-certificate / shadow-credential follow-on abuse は引き続き実行しやすい。
- **Cross-domain / cross-forest delegation abuse は依然として非常に有効** – Windows は modern cross-realm **S4U2Self/S4U2Proxy** flow をサポートしているため、別 domain の writable delegation attributes は依然として価値がある。通常の blocker は protocol support ではなく、tooling fidelity と trust/policy の詳細である。
- **Recursive multi-domain RBCD は operational に重要** – 3つ以上の domain を持つ forest では、**S4U2Self/S4U2Proxy** が trust referral を通じて recurse でき、**SPN-less** abuse には、最終的な **`S4U2Self+U2U`** hop と RC4-dependent ticket handling が必要になる場合がある。[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照。
- **Windows Server 2025 では、dMSA migration logic によって Kerberos-adjacent attack surface が新たに生じた**。2025 domain で OU または service-account object に対する delegated rights を確認した場合は、「単なる別の gMSA」とみなすのではなく、専用の [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) を確認する。

## modern domain での高速な operator checks

Kerberos attack path を選択する前に、次の4つの質問に素早く答える:

1. **依然として RC4-friendly な account はどれか?**
2. **pre-auth を必要としない user は誰か?**
3. **delegation abuse を expose している object はどれか?**
4. **domain のどの部分が、最近の hardening を enforce できるほど新しいか?**
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
- **興味深いSPNアカウントが明示的にRC4対応の場合**、Kerberoastingは低コストかつ高速なままです。
- ほとんどのサービスアカウントに**明示的なetype設定がない場合**、更新済みの2026年のDCでは **AES-only** の動作を想定し、より遅いoffline crackingまたは別の手法を計画してください。
- **RBCD / KCD / unconstrained delegation** が存在する場合、S4Uはbrute-forceを上回ることがよくあります。
- **certificate auth** が使用されている場合、PKINIT pathの失敗が必ずしも証明書が使えないことを意味するわけではない点に注意してください。多くの環境では、同じ証明書が **Schannel/LDAPS** abuseにも引き続き使用できます（[AD Certificates / PKINIT abuse](ad-certificates.md)）。

## attack planを変える一般的なKerberosエラー
- **`KDC_ERR_ETYPE_NOTSUPP`** → target account / DCは、指定したencryption typeを使用しません。RC4 onlyでのretryを止め、**AES keys**を指定するか、代わりに **AES** roast materialを要求してください。
- **`KRB_AP_ERR_MODIFIED`** → **wrong service key**、**wrong SPN**、または実際に復号するservice accountと一致しないforged ticketを持っている可能性があります。
- **`KRB_AP_ERR_SKEW`** → 時刻がずれています。他のdebugを行う前に、DCと時刻を同期してください。
- S4U / delegation flows中の **`KDC_ERR_BADOPTION`** → 多くの場合、**sensitive/not-delegable users**、誤ったdelegation model、または **RBCD** ならnon-forwardable S4U2Self ticketを受け入れる状況で **classic KCD** を実行しようとしていることを意味します。

## References
- [Microsoft Learn - KerberosでのRC4使用の検出と修正](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - 最新のWindows hardening guidanceと重要な日付](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
