# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Şu harika gönderiye göz atın:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Saldırganlar için TL;DR
- Kerberos, varsayılan AD auth protokolüdür; çoğu lateral-movement zinciri buna dokunur.
- **Üç operator aşamasını** düşünün:
- **AS-REQ / AS-REP** → bir **TGT** elde etmek için password/hash/certificate kullanılır. **AS-REP roasting**, **over-pass-the-hash / pass-the-key** ve **PKINIT** burada yer alır.
- **TGS-REQ / TGS-REP** → service tickets elde etmek için bir TGT kullanılır. **Kerberoasting**, **S4U abuse**, **delegation abuse** ve çoğu **ticket-forging tradecraft** burada önem kazanır.
- **AP-REQ / AP-REP** → ticket service'e sunulur. **pass-the-ticket** ve service-specific lateral movement burada gerçekleşir.
- Uygulamalı cheatsheet'ler (AS-REP/Kerberoasting, ticket forgery, delegation abuse vb.) için bkz.:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Bu sayfayı **genel bakış / “son zamanlarda ne değişti”** index'i olarak kullanın; ardından [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) veya [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) için ilgili sayfalara geçin.

## Güncel attack notları (2024-2026)
- **RC4 hardening, Kerberos'un kendisini değil varsayılanları değiştirdi** – modern DC hardening, `msDS-SupportedEncryptionTypes` değerini açıkça ayarlamayan hesaplar için **varsayılan kabul edilen encryption types** üzerine odaklanır. 2026 rollout'undan sonra bu hesaplar patched DC'lerde giderek daha fazla **AES-only** varsayılanına geçiyor; bu nedenle doğrudan `/rc4` Kerberoast varsayımları daha sık başarısız oluyor. Bununla birlikte, **açıkça RC4 etkinleştirilmiş service accounts** offline-crack hedefleri olmaya devam ediyor.
- **PAC validation enforcement, forged tickets için önemlidir** – 2024 PAC-signature hardening, **golden/diamond/sapphire/extraSID-style abuses** için daha gerçekçi PAC verileri ve doğru signing context gerektiği anlamına gelir. Unpatched domain'ler veya compatibility/audit-style deployment'larda bırakılmış domain'ler daha zayıf hedefler olmaya devam eder.
- **Certificate-based Kerberos iki kez değişti**:
- **Strong certificate binding** (KB5014754 timeline), fully enforced environment'larda özensiz certificate-to-account mapping'lerini daha az güvenilir hale getirir.
- **CVE-2025-26647**, **altSecID / SKI certificate mappings** etrafına başka bir hardening katmanı ekledi. DC'ler unpatched durumdaysa, hâlâ auditing yapıyorsa veya NTAuth validation'ı açıkça bypass ediyorsa, pass-the-certificate / shadow-credential follow-on abuse daha uygulanabilir olmaya devam eder.
- **Cross-domain / cross-forest delegation abuse hâlâ çok canlı** – Windows modern cross-realm **S4U2Self/S4U2Proxy** akışlarını desteklediğinden, başka bir domain'deki yazılabilir delegation attributes hâlâ değerlidir. Genellikle engel protocol support değil, tooling fidelity ve trust/policy ayrıntılarıdır.
- **Recursive multi-domain RBCD operasyonel olarak önemlidir** – 3+ domain forest'lerinde **S4U2Self/S4U2Proxy**, trust referrals üzerinden recursive olabilir ve **SPN-less** abuse için RC4-dependent ticket handling ile birlikte son bir **`S4U2Self+U2U`** hop gerekebilir. Bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025, dMSA migration logic aracılığıyla Kerberos-adjacent yeni bir attack surface sundu.** 2025 domain'inde OU'lar veya service-account objects üzerinde delegated rights görürseniz, bunu “sıradan başka bir gMSA” olarak değerlendirmek yerine ilgili [BadSuccessor sayfasını](acl-persistence-abuse/BadSuccessor.md) kontrol edin.

## Modern domain'lerde hızlı operator kontrolleri

Bir Kerberos attack path seçmeden önce şu dört soruyu hızlıca yanıtlayın:

1. **Hangi hesaplar hâlâ RC4-friendly?**
2. **Hangi kullanıcılar pre-auth gerektirmiyor?**
3. **Hangi object'ler delegation abuse ortaya çıkarıyor?**
4. **Domain'in hangi bölümleri recent hardening'ı enforce edecek kadar yeni?**
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
- Çoğu service account için **explicit etype configuration yoksa**, güncellenmiş 2026 DC'lerde **AES-only** davranış bekleyin ve daha yavaş offline cracking veya farklı bir yol planlayın.
- **RBCD / KCD / unconstrained delegation** mevcutsa, S4U çoğu zaman brute-force'tan daha etkilidir.
- **Certificate auth** kullanılıyorsa, başarısız bir PKINIT yolunun sertifikanın işe yaramaz olduğu anlamına her zaman gelmediğini unutmayın; birçok ortamda aynı sertifika **Schannel/LDAPS** abuse için hâlâ çalışır (bkz. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Attack planını değiştiren yaygın Kerberos hataları
- **`KDC_ERR_ETYPE_NOTSUPP`** → Hedef account / DC, istediğiniz encryption type'ı kullanmayacaktır. Yalnızca RC4 ile tekrar denemeyi bırakın; **AES keys** sağlayın veya bunun yerine **AES** roast material isteyin.
- **`KRB_AP_ERR_MODIFIED`** → Büyük olasılıkla **yanlış service key**, **yanlış SPN** kullanıyorsunuz ya da service account tarafından gerçekten decrypt edilmeyen, sahte bir ticket'a sahipsiniz.
- **`KRB_AP_ERR_SKEW`** → Saatiniz yanlış. Başka bir şeyi debug etmeden önce DC ile sync edin.
- S4U / delegation flow'ları sırasında **`KDC_ERR_BADOPTION`** → Genellikle **sensitive/not-delegable users**, yanlış delegation model veya yalnızca **RBCD**'nin forwardable olmayan bir S4U2Self ticket'ını kabul edeceği bir yerde **classic KCD** kullanmaya çalıştığınız anlamına gelir.

## References
- [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - En güncel Windows hardening rehberi ve önemli tarihler](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
