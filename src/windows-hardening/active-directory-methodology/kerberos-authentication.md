# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Şu harika yazıya göz atın:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## Saldırganlar için TL;DR
- Kerberos, varsayılan AD auth protocol'dür; lateral-movement chain'lerinin çoğu ona dokunur.
- **Üç operator aşamasını** düşünün:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → bir **TGT** elde etmek için password/hash/certificate kullanılır. **AS-REP roasting**, **over-pass-the-hash / pass-the-key** ve **PKINIT** burada yer alır.
- **TGS-REQ / TGS-REP** → service ticket'ları elde etmek için TGT kullanılır. **Kerberoasting**, **S4U abuse**, **delegation abuse** ve ticket-forging tradecraft'ının çoğu burada önem kazanır.
- **AP-REQ / AP-REP** → ticket service'e sunulur. **Pass-the-ticket** ve service-specific lateral movement burada gerçekleşir.
- Uygulamalı cheatsheet'ler (AS-REP/Kerberoasting, ticket forgery, delegation abuse vb.) için:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Bu sayfayı **genel bakış / “son zamanlarda ne değişti”** index'i olarak kullanın; ardından [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) veya [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) için ilgili sayfalara geçin.

## Güncel attack notları (2024-2026)
- **RC4 hardening, Kerberos'un kendisini değil varsayılanları değiştirdi** – modern DC hardening, `msDS-SupportedEncryptionTypes` değerini açıkça ayarlamayan account'lar için **varsayılan encryption type** değerlerine odaklanır. 2026 rollout'undan sonra bu account'lar patched DC'lerde giderek daha fazla **yalnızca AES** kullanacak şekilde varsayılan hale geliyor; bu nedenle körlemesine `/rc4` Kerberoast varsayımları daha sık başarısız oluyor. Ancak **RC4 açıkça etkinleştirilmiş service account'lar offline-crack hedefleri olmaya devam ediyor**.<sup>[[1]](#references)</sup>
- **PAC validation enforcement, forged ticket'lar için önem taşıyor** – 2024 PAC-signature hardening, **golden/diamond/sapphire/extraSID-style abuse** tekniklerinin daha gerçekçi PAC data'sı ve doğru signing context gerektirmesine neden oluyor. Patched olmayan veya compatibility/audit-style deployment'larda bırakılan domain'ler daha kolay hedef olmaya devam ediyor.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos iki kez değişti**:<sup>[[2]](#references)</sup>
- **Strong certificate binding** (KB5014754 timeline'ı), tam olarak enforced ortamlarda hatalı certificate-to-account mapping'lerini daha az güvenilir hale getiriyor.
- **CVE-2025-26647**, **altSecID / SKI certificate mapping** etrafına başka bir hardening katmanı ekledi. DC'ler patched değilse, hâlâ audit modundaysa veya NTAuth validation'ı açıkça bypass ediyorsa, pass-the-certificate / shadow-credential follow-on abuse daha uygulanabilir olmaya devam ediyor.
- **Cross-domain / cross-forest delegation abuse hâlâ oldukça canlı** – Windows modern cross-realm **S4U2Self/S4U2Proxy** flow'larını destekliyor; bu nedenle başka bir domain'deki writable delegation attribute'ları hâlâ değerlidir. Engelleyici genellikle protocol support değil, tooling fidelity ve trust/policy ayrıntılarıdır.
- **Recursive multi-domain RBCD operasyonel olarak önem taşıyor** – 3+ domain'li forest'larda **S4U2Self/S4U2Proxy**, trust referral'ları üzerinden recursive olabilir ve **SPN-less** abuse, RC4-dependent ticket handling ile birlikte son bir **`S4U2Self+U2U`** hop'u gerektirebilir. Bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025, dMSA migration logic aracılığıyla Kerberos'a komşu yeni bir attack surface sundu.** 2025 domain'inde OU'lar veya service-account object'leri üzerinde delegated right'lar görürseniz, bunu “başka bir gMSA” olarak değerlendirmek yerine özel [BadSuccessor sayfasına](acl-persistence-abuse/BadSuccessor.md) bakın.

## Modern domain'lerde hızlı operator kontrolleri

Bir Kerberos attack path seçmeden önce şu dört soruyu hızlıca yanıtlayın:

1. **Hangi account'lar hâlâ RC4-friendly?**
2. **Hangi user'lar pre-auth gerektirmiyor?**
3. **Hangi object'ler delegation abuse'a açık?**
4. **Domain'in hangi bölümleri yakın zamanda oluşturulduğu için yeni hardening'ı enforce ediyor?**
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
- **İlgi çekici SPN hesapları açıkça RC4 destekliyorsa**, Kerberoasting ucuz ve hızlı kalır.
- Çoğu service account'ta **açık bir etype yapılandırması yoksa**, güncellenmiş 2026 DC'lerinde **yalnızca AES** davranışı bekleyin ve daha yavaş offline cracking veya farklı bir yol planlayın.
- **RBCD / KCD / unconstrained delegation** mevcutsa, S4U çoğu zaman brute-force'tan daha etkilidir.
- **Certificate auth** devredeyse, başarısız bir PKINIT yolunun sertifikanın işe yaramaz olduğu anlamına her zaman gelmediğini unutmayın; birçok ortamda aynı sertifika **Schannel/LDAPS abuse** için hâlâ çalışır (bkz. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Saldırı planını değiştiren yaygın Kerberos hataları
- **`KDC_ERR_ETYPE_NOTSUPP`** → Hedef account / DC, istediğiniz encryption type'ı kullanmayacaktır. Yalnızca RC4 ile tekrar denemeyi bırakın; **AES keys** sağlayın veya bunun yerine **AES** roast material isteyin.
- **`KRB_AP_ERR_MODIFIED`** → Muhtemelen **yanlış service key**, **yanlış SPN** kullanıyorsunuz ya da gerçekten şifre çözme işlemini yapan service account ile eşleşmeyen forged ticket oluşturdunuz.
- **`KRB_AP_ERR_SKEW`** → Zamanınız hatalı. Başka bir şeyi debug etmeden önce DC ile senkronize olun.
- S4U / delegation akışları sırasında **`KDC_ERR_BADOPTION`** → Genellikle **sensitive/not-delegable users**, yanlış delegation modeli veya yalnızca **RBCD**'nin forwardable olmayan bir S4U2Self ticket'ını kabul edeceği bir durumda **classic KCD** kullanmaya çalıştığınız anlamına gelir.

## Referanslar
- [1] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - En güncel Windows hardening rehberi ve önemli tarihler](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos nasıl çalışır? – Teori](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Cross-Domain ve Cross-Forest Ortamlarında RBCD Exploitation: Bölüm 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
