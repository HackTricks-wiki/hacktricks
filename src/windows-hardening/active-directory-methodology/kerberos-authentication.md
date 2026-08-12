# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

以下で要約した交換処理をプロトコルレベルで確認するには、TarlogicのKerberos記事を参照してください。<sup>[[3]](#references)</sup>

## 攻撃者向けTL;DR
- KerberosはデフォルトのAD認証プロトコルであり、ほとんどのlateral-movement chainがこれに触れます。
- **3つのoperatorフェーズ**として考えます:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → password/hash/certificateを使用して**TGT**を取得します。ここに**AS-REP roasting**、**over-pass-the-hash / pass-the-key**、**PKINIT**があります。
- **TGS-REQ / TGS-REP** → TGTを使用して**service tickets**を取得します。ここで**Kerberoasting**、**S4U abuse**、**delegation abuse**、そして大半の**ticket-forging tradecraft**が関係します。
- **AP-REQ / AP-REP** → ticketをserviceに提示します。ここで**pass-the-ticket**とservice固有のlateral movementが発生します。
- 実践向けのcheatsheets（AS-REP/Kerberoasting、ticket forgery、delegation abuseなど）については、以下を参照してください:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- このページは**overview / 「最近何が変わったか」**のindexとして使用し、[Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md)、または[BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md)の専用ページに移動してください。

## 最近のattack notes（2024-2026）
- **RC4 hardeningによって変わったのはデフォルトであり、Kerberos自体ではない** – modern DC hardeningは、`msDS-SupportedEncryptionTypes`を明示的に設定していないaccountに対する**default assumed encryption types**に重点を置いています。2026年のrollout後、これらのaccountはpatched DC上で次第に**AES-only**がデフォルトになるため、盲目的な`/rc4` Kerberoastの想定はより頻繁に失敗します。ただし、**明示的にRC4-enabledのservice accountは、依然として優れたoffline-crack対象です**。<sup>[[1]](#references)</sup>
- **PAC validation enforcementはforged ticketにとって重要です** – 2024年のPAC-signature hardeningにより、**golden/diamond/sapphire/extraSID-style abuse**では、より現実的なPAC dataと正しいsigning contextが必要になりました。Unpatched domainや、compatibility/audit-style deploymentのままのdomainは、引き続き防御が弱い対象です。<sup>[[2]](#references)</sup>
- **Certificate-based Kerberosは2度変更されました**:
- **Strong certificate binding**（KB5014754のtimeline）により、完全にenforcedされたenvironmentでは、粗雑なcertificate-to-account mappingの信頼性が低下します。
- **CVE-2025-26647**により、certificateのSubject Key Identifierを使用する`altSecurityIdentities` mapping周辺に、さらにhardening layerが追加されました。そのため、pass-the-certificateおよび関連するcertificate-based pathを評価する際には、patch level、enforcementまたはaudit state、明示的なmapping configurationが重要です。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> PKINITでは、KDCがcertificate pathも検証し、NTAuth storeを通じてissuerがtrustedであることを確認します。<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuseは依然として非常に有効です** – Windowsはmodern cross-realm **S4U2Self/S4U2Proxy** flowをサポートしているため、別domainにあるwritableなdelegation attributeには依然として価値があります。通常の障害はprotocol supportではなく、tooling fidelityとtrust/policyの詳細です。
- **Recursive multi-domain RBCDは運用上重要です** – 3つ以上のdomainを持つforestでは、**S4U2Self/S4U2Proxy**がtrust referralを通じて再帰でき、**SPN-less** abuseでは、最後に**`S4U2Self+U2U`** hopとRC4依存のticket handlingが必要になる場合があります。[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)を参照してください。<sup>[[4]](#references)</sup>
- **Windows Server 2025ではdelegated Managed Service Accounts（dMSAs）とそのmigration logicが導入されました**。2025 domainでOUまたはservice-account objectに対するdelegated rightsを確認した場合は、「単なる別のgMSA」として扱うのではなく、専用の[BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)を確認してください。<sup>[[7]](#references)</sup>

## modern domainでの迅速なoperatorチェック

Kerberos attack pathを選択する前に、次の4つの質問にすばやく答えてください:

1. **まだRC4-friendlyなaccountはどれか？**
2. **pre-authを要求しないuserはどれか？**
3. **delegation abuseを露出させているobjectはどれか？**
4. **domainのどの部分が十分に新しく、最近のhardeningをenforceしているか？**
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
- **興味深い SPN アカウントが明示的に RC4 対応の場合**、Kerberoasting は低コストかつ高速なままです。
- ほとんどのサービスアカウントに **明示的な etype 設定がない場合**、更新済みの 2026 年の DC では **AES-only** の動作を想定し、低速なオフライン cracking または別の手法を計画してください。
- **RBCD / KCD / unconstrained delegation** が存在する場合、S4U はしばしば brute-force より有効です。
- **certificate auth** が関係する場合、PKINIT の経路に失敗しても、証明書が必ずしも使えないとは限らないことに注意してください。多くの環境では、同じ証明書が **Schannel/LDAPS** abuse に引き続き使用できます（[AD Certificates / PKINIT abuse](ad-certificates.md) を参照）。

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → 対象アカウント / DC は、要求した encryption type を使用しません。RC4 only での再試行を止め、**AES keys** を提供するか、代わりに **AES** の roast material を要求してください。
- **`KRB_AP_ERR_MODIFIED`** → **wrong service key**、**wrong SPN**、または実際に復号するサービスアカウントと一致しない forged ticket を持っている可能性があります。
- **`KRB_AP_ERR_SKEW`** → 時刻がずれています。他の問題を debug する前に、DC と同期してください。
- S4U / delegation flows 中の **`KDC_ERR_BADOPTION`** → 多くの場合、**sensitive/not-delegable users**、誤った delegation model、または **RBCD** でのみ non-forwardable S4U2Self ticket が受け入れられる状況で **classic KCD** を実行しようとしていることを意味します。

## References
- [1] [Microsoft Learn - Kerberos における RC4 の使用を検出して修正する](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - 最新の Windows hardening guidance と主要な日付](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos はどのように機能するのか？– 理論](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Cross-Domain および Cross-Forest 環境における RBCD の Exploiting: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - KB5014754 certificate-based authentication の変更](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos certificate mapping vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Delegated Managed Service Accounts の概要](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Smart-card certificate の要件と KDC validation](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
