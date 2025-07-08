# Active Directory ACL'lerinin/ACE'lerinin Suistimali

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Delegated Managed Service Accounts (dMSA'lar), **Windows Server 2025** ile tanıtılan yeni bir AD anahtar türüdür. Eski hizmet hesaplarının yerini almak üzere tasarlanmıştır ve eski hesabın Service Principal Names (SPN'ler), grup üyelikleri, delegasyon ayarları ve hatta kriptografik anahtarlarını yeni dMSA'ya otomatik olarak kopyalayan tek tıklamalı bir “göç” imkanı sunar, bu da uygulamalara kesintisiz bir geçiş sağlar ve Kerberoasting riskini ortadan kaldırır.

Akamai araştırmacıları, tek bir niteliğin — **`msDS‑ManagedAccountPrecededByLink`** — KDC'ye bir dMSA'nın hangi eski hesabı “devraldığını” söylediğini buldular. Bir saldırgan bu niteliği yazabiliyorsa (ve **`msDS‑DelegatedMSAState` → 2**'yi değiştirebiliyorsa), KDC, seçilen kurbanın her SID'ini **miras alan** bir PAC oluşturur, bu da dMSA'nın herhangi bir kullanıcıyı, Domain Admin'ler dahil, taklit etmesine olanak tanır.

## dMSA tam olarak nedir?

* **gMSA** teknolojisi üzerine inşa edilmiştir ancak yeni AD sınıfı **`msDS‑DelegatedManagedServiceAccount`** olarak depolanır.
* **Opt-in göç** destekler: `Start‑ADServiceAccountMigration` çağrısı dMSA'yı eski hesapla bağlar, eski hesaba `msDS‑GroupMSAMembership` üzerinde yazma erişimi verir ve `msDS‑DelegatedMSAState`'i 1'e çevirir.
* `Complete‑ADServiceAccountMigration` sonrasında, eski hesap devre dışı bırakılır ve dMSA tamamen işlevsel hale gelir; daha önce eski hesabı kullanan herhangi bir ana bilgisayar, dMSA'nın şifresini çekmek için otomatik olarak yetkilendirilir.
* Kimlik doğrulama sırasında, KDC, Windows 11/24H2 istemcilerinin dMSA ile şeffaf bir şekilde yeniden denemesi için **KERB‑SUPERSEDED‑BY‑USER** ipucunu gömülü olarak ekler.

## Saldırı için Gereksinimler
1. **En az bir Windows Server 2025 DC** böylece dMSA LDAP sınıfı ve KDC mantığı mevcut olur.
2. **Bir OU üzerinde herhangi bir nesne oluşturma veya nitelik yazma hakları** (herhangi bir OU) – örneğin, `Create msDS‑DelegatedManagedServiceAccount` veya basitçe **Create All Child Objects**. Akamai, gerçek dünya kiracılarının %91'inin bu tür “zararsız” OU izinlerini yöneticiler dışındaki kullanıcılara verdiğini buldu.
3. Kerberos biletleri talep etmek için herhangi bir alan bağlı ana bilgisayardan araç çalıştırma yeteneği.
*Kurban kullanıcı üzerinde kontrol gerekmiyor; saldırı hedef hesabı doğrudan etkilemiyor.*

## Adım adım: BadSuccessor* ayrıcalık yükseltme

1. **Kontrol ettiğiniz bir dMSA bulun veya oluşturun**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Nesneyi yazabileceğiniz bir OU içinde oluşturduğunuz için, otomatik olarak tüm niteliklerinin sahibi olursunuz.

2. **İki LDAP yazımında “tamamlanmış göç” simüle edin**:
- `msDS‑ManagedAccountPrecededByLink = DN` herhangi bir kurbanın (örneğin, `CN=Administrator,CN=Users,DC=lab,DC=local`) değerini ayarlayın.
- `msDS‑DelegatedMSAState = 2` (göç tamamlandı) ayarlayın.

**Set‑ADComputer, ldapmodify** veya hatta **ADSI Edit** gibi araçlar çalışır; alan yöneticisi hakları gerekmez.

3. **dMSA için bir TGT talep edin** — Rubeus `/dmsa` bayrağını destekler:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Dönen PAC artık SID 500 (Administrator) artı Domain Admins/Enterprise Admins gruplarını içerir.

## Tüm kullanıcıların şifrelerini toplayın

Meşru göçler sırasında KDC, yeni dMSA'nın **eski hesaba verilen biletleri deşifre etmesine** izin vermelidir. Canlı oturumları bozmayı önlemek için, hem mevcut anahtarları hem de önceki anahtarları **`KERB‑DMSA‑KEY‑PACKAGE`** adlı yeni bir ASN.1 blob içinde yerleştirir.

Sahte göçümüz, dMSA'nın kurbanı devraldığını iddia ettiğinden, KDC, kurbanın RC4-HMAC anahtarını **önceki anahtarlar** listesine özenle kopyalar – dMSA'nın asla “önceki” bir şifreye sahip olmaması durumunda bile. O RC4 anahtarı tuzlanmamıştır, bu nedenle etkili bir şekilde kurbanın NT hash'idir ve saldırgana **çevrimdışı kırma veya “hash'i geçme”** yeteneği verir.

Bu nedenle, binlerce kullanıcıyı toplu olarak bağlamak, bir saldırganın **BadSuccessor'ı hem ayrıcalık yükseltme hem de kimlik bilgisi ihlali ilkesine** dönüştürmesine olanak tanır.

## Araçlar

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Referanslar

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
