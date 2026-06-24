# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Şu harika yazıya göz atın:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Saldırganlar için TL;DR
- Kerberos varsayılan AD auth protokolüdür; çoğu lateral-movement zinciri buna dokunur.
- Düşünceyi **üç operatör aşamasına** ayırın:
- **AS-REQ / AS-REP** → **TGT** elde etmek için password/hash/certificate kullanılır. **AS-REP roasting**, **over-pass-the-hash / pass-the-key** ve **PKINIT** burada yer alır.
- **TGS-REQ / TGS-REP** → **service tickets** elde etmek için bir TGT kullanın. **Kerberoasting**, **S4U abuse**, **delegation abuse** ve çoğu **ticket-forging tradecraft** burada önem kazanır.
- **AP-REQ / AP-REP** → ticket'ı service'e sunun. **pass-the-ticket** ve service'e özgü lateral movement burada gerçekleşir.
- Uygulamalı cheatsheet'ler için (AS-REP/Kerberoasting, ticket forgery, delegation abuse, vb.) şuna bakın:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Bu sayfayı **genel bakış / “son zamanlarda ne değişti”** indeksi olarak kullanın, ardından [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) veya [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) için ayrılmış sayfalara geçin.

## Yeni saldırı notları (2024-2026)
- **RC4 hardening varsayılanları değiştirdi, Kerberos'un kendisini değil** – modern DC hardening, `msDS-SupportedEncryptionTypes` değerini açıkça ayarlamayan account'lar için **varsayılan varsayılan encryption types** üzerine odaklanır. 2026 rollout'undan sonra, bu account'lar yamalı DC'lerde giderek daha fazla **AES-only** varsayılır, bu yüzden kör `/rc4` Kerberoast varsayımları daha sık başarısız olur. Ancak, **explicit olarak RC4-enabled service accounts** hâlâ offline-crack için mükemmel hedeflerdir.
- **PAC validation enforcement forged ticket'ler için önemlidir** – 2024 PAC-signature hardening, **golden/diamond/sapphire/extraSID-style abuses** için daha gerçekçi PAC verileri ve doğru signing context gerektirir. Unpatched domain'ler veya compatibility/audit-style deployment'larda bırakılan domain'ler daha zayıf hedefler olarak kalır.
- **Certificate-based Kerberos iki kez değişti**:
- **Strong certificate binding** (KB5014754 timeline) tamamen enforced ortamlarda gevşek certificate-to-account eşleştirmelerini daha az güvenilir hale getirir.
- **CVE-2025-26647**, **altSecID / SKI certificate mappings** etrafında başka bir hardening katmanı ekledi. DC'ler unpatched ise, hâlâ auditing modundaysa veya NTAuth validation'ı açıkça bypass ediyorsa, pass-the-certificate / shadow-credential sonraki abuse'u daha pratik kalır.
- **Cross-domain / cross-forest delegation abuse hâlâ çok canlı** – Windows modern cross-realm **S4U2Self/S4U2Proxy** akışlarını destekler, bu yüzden başka bir domain'deki writable delegation attribute'ları hâlâ değerlidir. Engel genelde protocol desteği değil, tooling fidelity ve trust/policy detaylarıdır.
- **Windows Server 2025, yeni Kerberos-adjacent attack surface**'i **dMSA** migration logic üzerinden tanıttı. 2025 domain'inde OU'lar veya service-account object'leri üzerinde delegated rights görürseniz, bunu “sadece başka bir gMSA” gibi ele almak yerine ayrılmış [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)'e bakın.

## Modern domain'lerde hızlı operatör kontrolleri

Bir Kerberos attack path seçmeden önce, şu dört soruyu hızlıca yanıtlayın:

1. **Hangi account'lar hâlâ RC4-friendly?**
2. **Hangi users pre-auth gerektirmiyor?**
3. **Hangi object'ler delegation abuse'a açık?**
4. **Domain'in hangi bölümleri son hardening'i zorlayacak kadar yeni?**
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
- Eğer **ilginç SPN hesapları açıkça RC4-capable** ise, Kerberoasting ucuz ve hızlı kalır.
- Çoğu service account için **açık etype configuration** yoksa, güncellenmiş 2026 DC'lerde **AES-only** davranışı bekleyin ve daha yavaş offline cracking ya da farklı bir yol planlayın.
- Eğer **RBCD / KCD / unconstrained delegation** varsa, S4U çoğu zaman brute-force'tan daha iyi sonuç verir.
- Eğer **certificate auth** kullanılıyorsa, başarısız bir PKINIT yolunun her zaman cert'in işe yaramaz olduğu anlamına gelmediğini unutmayın; birçok ortamda aynı cert, **Schannel/LDAPS** abuse için hâlâ çalışır (bkz. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Attack planını değiştiren yaygın Kerberos hataları
- **`KDC_ERR_ETYPE_NOTSUPP`** → Hedef account / DC, istediğiniz encryption type'ı kullanmayacak. Sadece RC4 ile yeniden denemeyi bırakın; **AES keys** sağlayın veya bunun yerine **AES** roast material isteyin.
- **`KRB_AP_ERR_MODIFIED`** → Büyük olasılıkla **yanlış service key**, **yanlış SPN** veya service account'un gerçekten decrypt ettiği eşleşmeyen forged ticket var.
- **`KRB_AP_ERR_SKEW`** → Saatiniz yanlış. Başka bir şeyi debug etmeden önce DC ile time sync yapın.
- S4U / delegation akışları sırasında **`KDC_ERR_BADOPTION`** → sıkça **sensitive/not-delegable users**, yanlış delegation modeli veya **classic KCD** yapmaya çalıştığınızı, oysa yalnızca **RBCD**'nin non-forwardable bir S4U2Self ticket'ı kabul edeceğini gösterir.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
