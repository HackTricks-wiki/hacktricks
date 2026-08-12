# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

Aşağıda özetlenen değiş tokuşların protokol düzeyinde açıklaması için Tarlogic'in Kerberos makalesine bakın.<sup>[[3]](#references)</sup>

## Saldırganlar için TL;DR
- Kerberos, varsayılan AD auth protokolüdür; çoğu lateral-movement zinciri ona dokunur.
- **Üç operatör aşaması** şeklinde düşünün:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → bir **TGT** almak için parola/hash/certificate kullanılır. **AS-REP roasting**, **over-pass-the-hash / pass-the-key** ve **PKINIT** burada yer alır.
- **TGS-REQ / TGS-REP** → service ticket'ları almak için bir TGT kullanılır. **Kerberoasting**, **S4U abuse**, **delegation abuse** ve çoğu **ticket-forging tradecraft** burada önem kazanır.
- **AP-REQ / AP-REP** → ticket service'e sunulur. **pass-the-ticket** ve service-specific lateral movement burada gerçekleşir.
- Uygulamalı cheatsheet'ler (AS-REP/Kerberoasting, ticket forgery, delegation abuse vb.) için:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Bu sayfayı **overview / “son dönemde ne değişti”** index'i olarak kullanın; ardından [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) veya [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) için özel sayfalara geçin.

## Güncel saldırı notları (2024-2026)
- **RC4 hardening varsayılanları değiştirdi, Kerberos'un kendisini değil** – modern DC hardening, `msDS-SupportedEncryptionTypes` değerini açıkça ayarlamayan account'lar için **default assumed encryption types** üzerine odaklanır. 2026 rollout'undan sonra bu account'lar patched DC'lerde giderek daha fazla **AES-only** olarak varsayılır; bu nedenle körlemesine `/rc4` Kerberoast varsayımları daha sık başarısız olur. Ancak **açıkça RC4-enabled service account'lar offline-crack için hâlâ mükemmel hedeflerdir**.<sup>[[1]](#references)</sup>
- **PAC validation enforcement forged ticket'lar için önemlidir** – 2024 PAC-signature hardening, **golden/diamond/sapphire/extraSID-style abuse** tekniklerinin daha gerçekçi PAC verileri ve doğru signing context gerektirmesine neden olur. Patched olmayan veya compatibility/audit-style deployment'larda bırakılan domain'ler daha kolay hedefler olmaya devam eder.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos iki kez değişti**:
- **Strong certificate binding** (KB5014754 timeline), tamamen enforced ortamlarda özensiz certificate-to-account mapping'lerini daha az güvenilir hâle getirir.
- **CVE-2025-26647**, bir certificate'ın Subject Key Identifier değerini kullanan `altSecurityIdentities` mapping'leri çevresine başka bir hardening katmanı ekledi. Bu nedenle pass-the-certificate ve ilgili certificate-based path'leri değerlendirirken patch level, enforcement veya audit state ve explicit mapping configuration önem taşır.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> PKINIT için KDC ayrıca certificate path'i doğrular ve issuer'ın NTAuth store üzerinden trusted olduğunu kontrol eder.<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse hâlâ oldukça canlıdır** – Windows modern cross-realm **S4U2Self/S4U2Proxy** flow'larını destekler; bu nedenle başka bir domain'deki writable delegation attribute'ları hâlâ değerlidir. Genellikle engel protocol support değil, tooling fidelity ile trust/policy ayrıntılarıdır.
- **Recursive multi-domain RBCD operasyonel olarak önemlidir** – 3+ domain forest'larında **S4U2Self/S4U2Proxy**, trust referral'ları üzerinden recurse edebilir ve **SPN-less** abuse için RC4-dependent ticket handling ile birlikte son bir **`S4U2Self+U2U`** hop'u gerekebilir. Bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 delegated Managed Service Accounts (dMSAs)** ve bunların migration logic'ini kullanıma sundu. 2025 domain'inde OU'lar veya service-account object'leri üzerinde delegated rights görürseniz, bunu “bir başka gMSA” gibi değerlendirmek yerine özel [BadSuccessor sayfasını](acl-persistence-abuse/BadSuccessor.md) kontrol edin.<sup>[[7]](#references)</sup>

## Modern domain'lerde hızlı operatör kontrolleri

Bir Kerberos attack path seçmeden önce dört soruyu hızlıca yanıtlayın:

1. **Hangi account'lar hâlâ RC4-friendly?**
2. **Hangi user'lar pre-auth gerektirmiyor?**
3. **Hangi object'ler delegation abuse'a açık?**
4. **Domain'in hangi bölümleri recent hardening'i uygulayacak kadar yeni?**
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
Pratik yorum:
- **İlgi çekici SPN hesapları açıkça RC4-capable ise**, Kerberoasting ucuz ve hızlı kalır.
- Çoğu service account için **explicit etype configuration yoksa**, güncellenmiş 2026 DC'lerde **AES-only** davranışı bekleyin ve daha yavaş offline cracking veya farklı bir yol planlayın.
- **RBCD / KCD / unconstrained delegation** mevcutsa, S4U çoğu zaman brute-force'tan daha iyi bir seçenektir.
- **Certificate auth** kullanılıyorsa, başarısız bir PKINIT yolunun sertifikanın işe yaramaz olduğu anlamına her zaman gelmediğini unutmayın; birçok ortamda aynı sertifika hâlâ **Schannel/LDAPS** abuse için çalışır (bkz. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Attack plan'ını değiştiren yaygın Kerberos hataları
- **`KDC_ERR_ETYPE_NOTSUPP`** → Hedef account / DC, istediğiniz encryption type'ı kullanmayacaktır. Yalnızca RC4 ile tekrar denemeyi bırakın; **AES keys** sağlayın veya bunun yerine **AES** roast material isteyin.
- **`KRB_AP_ERR_MODIFIED`** → Muhtemelen **yanlış service key**, **yanlış SPN** kullanıyorsunuz ya da service account tarafından gerçekten decrypt edilmeyen bir forged ticket'a sahipsiniz.
- **`KRB_AP_ERR_SKEW`** → Zamanınız hatalı. Başka herhangi bir şeyi debug etmeden önce DC ile senkronize olun.
- S4U / delegation flow'ları sırasında **`KDC_ERR_BADOPTION`** → Sıklıkla **sensitive/not-delegable users**, yanlış delegation modeli veya yalnızca **RBCD**'nin non-forwardable S4U2Self ticket'ını kabul edeceği bir durumda **classic KCD** kullanmaya çalıştığınız anlamına gelir.

## References
- [1] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - En güncel Windows hardening guidance ve önemli tarihler](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos nasıl çalışır? – Teori](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Cross-Domain ve Cross-Forest ortamlarında RBCD exploitation: 2. Bölüm](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - KB5014754 certificate-based authentication değişiklikleri](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos certificate mapping vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Smart-card certificate requirements ve KDC validation](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
