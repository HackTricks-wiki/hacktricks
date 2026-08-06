# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**次のすばらしい記事も確認してください:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## 攻撃者向けTL;DR
- KerberosはデフォルトのAD認証プロトコルであり、ほとんどの横展開チェーンで関与します。
- **3つのオペレーター・フェーズ**で考えます:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → パスワード/hash/certificateを使用して**TGT**を取得します。ここで**AS-REP roasting**、**over-pass-the-hash / pass-the-key**、**PKINIT**が行われます。
- **TGS-REQ / TGS-REP** → TGTを使用して**service tickets**を取得します。ここで**Kerberoasting**、**S4U abuse**、**delegation abuse**、および大半の**ticket-forging tradecraft**が関係します。
- **AP-REQ / AP-REP** → serviceにticketを提示します。ここで**pass-the-ticket**とservice固有の横展開が行われます。
- 実践的なcheatsheets（AS-REP/Kerberoasting、ticket forgery、delegation abuseなど）については、以下を参照してください:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- このページは**概要 / 「最近何が変わったか」**のindexとして使用し、[Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md)、または[BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md)の専用ページに進んでください。

## 最新のattack notes（2024-2026）
- **RC4 hardeningによって変わったのはデフォルト設定であり、Kerberos自体ではありません** – modern DC hardeningでは、`msDS-SupportedEncryptionTypes`を明示的に設定していないアカウントに対する**default assumed encryption types**が重視されます。2026年のrollout後、patch済みDCでは、これらのアカウントは次第に**AES-only**がデフォルトになるため、無差別な`/rc4` Kerberoastの想定はより頻繁に失敗します。しかし、**明示的にRC4が有効なservice accountsは、依然として優れたoffline-crack targetsです**。<sup>[[1]](#references)</sup>
- **PAC validation enforcementはforged ticketsにとって重要です** – 2024年のPAC-signature hardeningにより、**golden/diamond/sapphire/extraSID-style abuses**では、より現実的なPAC dataと正しいsigning contextが必要になりました。未patchのdomain、またはcompatibility/audit-style deploymentのままのdomainは、引き続き防御の弱いtargetです。<sup>[[2]](#references)</sup>
- **Certificate-based Kerberosは2度変更されました**:<sup>[[2]](#references)</sup>
- **Strong certificate binding**（KB5014754のtimeline）により、完全にenforcedされた環境では、粗雑なcertificate-to-account mappingsの信頼性が低下します。
- **CVE-2025-26647**により、**altSecID / SKI certificate mappings**周辺に別のhardening layerが追加されました。DCが未patch、監査中、またはNTAuth validationを明示的にbypassしている場合、pass-the-certificate / shadow-credentialのfollow-on abuseは依然として実行しやすい状態です。
- **Cross-domain / cross-forest delegation abuseは依然として非常に有効です** – Windowsはmodern cross-realm **S4U2Self/S4U2Proxy** flowsをサポートしているため、別domain内で書き込み可能なdelegation attributesは依然として価値があります。通常のblockerはprotocol supportではなく、tooling fidelityとtrust/policyの詳細です。
- **Recursive multi-domain RBCDは運用上重要です** – 3つ以上のdomainを持つforestでは、**S4U2Self/S4U2Proxy**がtrust referralsを通じて再帰でき、**SPN-less** abuseでは、最終的に**`S4U2Self+U2U`** hopとRC4に依存するticket handlingが必要になる場合があります。[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)を参照してください。<sup>[[4]](#references)</sup>
- **Windows Server 2025では、dMSA migration logicを通じてKerberos隣接の新たなattack surfaceが導入されました**。2025 domainでOUまたはservice-account objectsに対するdelegated rightsを見つけた場合は、「別のgMSA」として扱うのではなく、専用の[BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)を確認してください。

## modern domainでの迅速なoperator checks

Kerberos attack pathを選択する前に、次の4つの質問にすばやく答えてください:

1. **まだRC4-friendlyなアカウントはどれか？**
2. **pre-authを要求していないuserはどれか？**
3. **delegation abuseを可能にするobjectはどれか？**
4. **domainのどの部分が新しく、最近のhardeningをenforceできる状態か？**
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
- ほとんどのサービスアカウントに **明示的な etype 設定がない場合**、更新済みの 2026 年の DC では **AES-only** の動作を想定し、より遅いオフライン cracking または別の経路を計画してください。
- **RBCD / KCD / unconstrained delegation** が存在する場合、S4U は brute-force より有効なことが多くあります。
- **certificate auth** が関係する場合、PKINIT の経路に失敗しても、その cert が使えないとは限らない点に注意してください。多くの環境では、同じ cert が **Schannel/LDAPS** abuse にも引き続き使用できます（[AD Certificates / PKINIT abuse](ad-certificates.md) を参照）。

## attack plan を変える一般的な Kerberos エラー
- **`KDC_ERR_ETYPE_NOTSUPP`** → 対象アカウント / DC は、指定した encryption type を使用しません。RC4 only での再試行はやめ、**AES keys** を指定するか、代わりに **AES** の roast material を要求してください。
- **`KRB_AP_ERR_MODIFIED`** → おそらく **wrong service key**、**wrong SPN**、または実際に復号する service account と一致しない forged ticket を使用しています。
- **`KRB_AP_ERR_SKEW`** → 時刻がずれています。他の debugging を行う前に、DC と時刻を同期してください。
- S4U / delegation フロー中の **`KDC_ERR_BADOPTION`** → 多くの場合、**sensitive/not-delegable users**、誤った delegation model、または **RBCD** でのみ non-forwardable S4U2Self ticket が受け入れられる状況で、**classic KCD** を実行しようとしていることを意味します。

## 参考資料
- [1] [Microsoft Learn - Kerberos における RC4 の使用を検出して修正する](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Windows の最新の hardening ガイダンスと重要な日付](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos はどのように動作するのか? – 理論](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Cross-Domain および Cross-Forest 環境における RBCD の Exploiting: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
