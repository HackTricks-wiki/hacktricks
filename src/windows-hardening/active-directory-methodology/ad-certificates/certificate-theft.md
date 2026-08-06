# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresindeki kapsamlı araştırmanın Certificate Theft bölümlerinin kısa bir özetidir.**<sup>[[1]](#references)</sup>

## Bir sertifika ile ne yapabilirim

Sertifikaları nasıl çalacağınızı incelemeden önce, sertifikanın ne işe yaradığını nasıl bulabileceğinize dair bazı bilgiler:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Crypto APIs Kullanarak Sertifika Export Etme – THEFT1

**Etkileşimli bir masaüstü oturumunda**, özellikle **özel anahtar export edilebilir** durumdaysa, bir kullanıcı veya makine sertifikası özel anahtarıyla birlikte kolayca çıkarılabilir. Bunun için `certmgr.msc` içinde sertifikaya gidip sağ tıklamak ve parola korumalı bir .pfx dosyası oluşturmak üzere `All Tasks → Export` seçeneğini belirlemek yeterlidir.<sup>[[1]](#references)</sup>

**Programmatic bir yaklaşım** için PowerShell `ExportPfxCertificate` cmdlet'i veya [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) gibi project'ler kullanılabilir. Bunlar, sertifika store'una erişmek için **Microsoft CryptoAPI** (CAPI) veya Cryptography API: Next Generation (CNG) kullanır. Bu API'ler, sertifika storage'ı ve authentication için gerekenler de dahil olmak üzere çeşitli cryptographic service'ler sağlar.

Ancak bir özel anahtar non-exportable olarak ayarlanmışsa, hem CAPI hem de CNG normalde bu tür sertifikaların extraction işlemini engeller. Bu restriction'ı bypass etmek için **Mimikatz** gibi tool'lar kullanılabilir. Mimikatz, ilgili API'leri patch ederek özel anahtarların export edilmesini sağlayan `crypto::capi` ve `crypto::cng` command'larını sunar. Özellikle `crypto::capi`, mevcut process içindeki CAPI'yi patch ederken `crypto::cng`, patch işlemi için **lsass.exe**'nin memory'sini hedefler.

## DPAPI ile User Certificate Theft – THEFT2

DPAPI hakkında daha fazla bilgi:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Windows'ta **sertifika özel anahtarları DPAPI tarafından korunur**. **Kullanıcı ve makine özel anahtarlarının storage location'larının** birbirinden farklı olduğunu ve file structure'larının operating system tarafından kullanılan cryptographic API'ye göre değiştiğini bilmek önemlidir. **SharpDPAPI**, DPAPI blob'larını decrypt ederken bu farklılıklar arasında otomatik olarak gezinebilir.<sup>[[1]](#references)</sup>

**User certificate'ları** çoğunlukla registry'de `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` altında tutulur, ancak bazıları `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` directory'sinde de bulunabilir. Bu certificate'lara karşılık gelen **özel anahtarlar** genellikle **CAPI** key'leri için `%APPDATA%\Microsoft\Crypto\RSA\User SID\`, **CNG** key'leri için ise `%APPDATA%\Microsoft\Crypto\Keys\` altında saklanır.

**Bir sertifikayı ve ilişkili özel anahtarını extract etmek** için süreç şu adımlardan oluşur:

1. User store'undan **hedef sertifikanın seçilmesi** ve key store name'inin alınması.
2. İlgili özel anahtarı decrypt etmek için gereken **DPAPI masterkey'in bulunması**.
3. Plaintext DPAPI masterkey kullanılarak **özel anahtarın decrypt edilmesi**.

**Plaintext DPAPI masterkey'i elde etmek** için aşağıdaki yaklaşımlar kullanılabilir:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Masterkey dosyalarının ve private key dosyalarının şifre çözme işlemini kolaylaştırmak için [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) aracındaki `certificates` komutu oldukça kullanışlıdır. Özel anahtarların ve bunlarla ilişkili sertifikaların şifresini çözmek için `/pvk`, `/mkfile`, `/password` veya `{GUID}:KEY` bağımsız değişkenlerini kabul eder ve ardından bir `.pem` dosyası oluşturur.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPI ile Machine Certificate Theft – THEFT3

Windows tarafından registry içinde `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` konumunda saklanan machine certificates ve `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI için) ile `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG için) konumlarında bulunan ilişkili private keys, machine'in DPAPI master keys kullanılarak şifrelenir. Bu keys, domain'in DPAPI backup key'i ile decrypt edilemez; bunun yerine yalnızca SYSTEM user'ın erişebildiği **DPAPI_SYSTEM LSA secret** gereklidir.<sup>[[1]](#references)</sup>

Manual decryption, **Mimikatz** içinde `lsadump::secrets` command'ı çalıştırılarak DPAPI_SYSTEM LSA secret'ın çıkarılması ve ardından bu key kullanılarak machine masterkeys'lerin decrypt edilmesiyle gerçekleştirilebilir. Alternatif olarak, daha önce açıklandığı şekilde CAPI/CNG patch edildikten sonra Mimikatz'ın `crypto::certificates /export /systemstore:LOCAL_MACHINE` command'ı kullanılabilir.

**SharpDPAPI**, certificates command'ı ile daha automated bir yaklaşım sunar. `/machine` flag'i elevated permissions ile kullanıldığında SYSTEM'e yükselir, DPAPI_SYSTEM LSA secret'ı dump eder, bunu machine DPAPI masterkeys'lerini decrypt etmek için kullanır ve ardından bu plaintext keys'leri, tüm machine certificate private keys'lerini decrypt etmek üzere bir lookup table olarak kullanır.

## Certificate Files Bulma – THEFT4

Certificates bazen file shares veya Downloads folder gibi filesystem konumlarında doğrudan bulunabilir. Windows environments için hedeflenen ve en sık karşılaşılan certificate file türleri `.pfx` ve `.p12` dosyalarıdır. Daha az sıklıkla `.pkcs12` ve `.pem` uzantılı dosyalar da görülür. Dikkate değer diğer certificate-related file extensions şunlardır:<sup>[[1]](#references)</sup>

- private keys için `.key`,
- yalnızca certificates için `.crt`/`.cer`,
- certificates veya private keys içermeyen Certificate Signing Requests için `.csr`,
- Java Keystores için `.jks`/`.keystore`/`.keys`; bunlar certificates ile birlikte Java applications tarafından kullanılan private keys'leri barındırabilir.

Bu files, belirtilen extensions aranarak PowerShell veya command prompt kullanılarak bulunabilir.

Bir PKCS#12 certificate file bulunur ve password ile korunuyorsa, [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) adresinde bulunan `pfx2john.py` kullanılarak bir hash extract edilebilir. Daha sonra JohnTheRipper, password'ü crack etmeyi denemek için kullanılabilir.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## PKINIT üzerinden NTLM Credential Theft – THEFT5 (UnPAC the hash)

Verilen içerikte, özellikle THEFT5 olarak adlandırılan theft method aracılığıyla PKINIT üzerinden NTLM credential theft yöntemi açıklanmaktadır. Aşağıda içerik passive voice kullanılarak ve uygun yerlerde anonymized ve summarized biçimde yeniden açıklanmıştır:<sup>[[1]](#references)</sup>

Kerberos authentication kullanımını kolaylaştırmayan uygulamalar için NTLM authentication `MS-NLMP` desteği sağlamak amacıyla KDC, PKCA kullanıldığında kullanıcının NTLM one-way function (OWF) değerini privilege attribute certificate (PAC) içinde, özellikle `PAC_CREDENTIAL_INFO` buffer'ında döndürecek şekilde tasarlanmıştır. Bu nedenle, bir account PKINIT üzerinden authentication gerçekleştirip bir Ticket-Granting Ticket (TGT) aldığında, legacy authentication protocols desteğini sürdürmek amacıyla mevcut host'un TGT'den NTLM hash değerini çıkarmasını sağlayan bir mekanizma doğal olarak sunulmuş olur. Bu işlem, esas olarak NTLM plaintext'in NDR serialized gösterimi olan `PAC_CREDENTIAL_DATA` structure'ının decrypt edilmesini içerir.

[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) adresinden erişilebilen **Kekeo** utility'sinin, bu özel veriyi içeren bir TGT request edebildiği ve böylece kullanıcının NTLM değerinin elde edilmesini kolaylaştırdığı belirtilmektedir. Bu amaçla kullanılan command aşağıda verilmiştir:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** bu bilgileri **`asktgt [...] /getcredentials`** seçeneğiyle de alabilir.

Ek olarak, PIN'in alınabilmesi koşuluyla Kekeo'nun smartcard-korumalı sertifikaları işleyebildiği belirtilmektedir; bu kapsamda [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) adresine atıfta bulunulmuştur. Aynı özelliğin [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) adresinde bulunan **Rubeus** tarafından da desteklendiği belirtilmektedir.

Bu açıklama, PKINIT üzerinden NTLM credential theft sürecini ve bu süreçte kullanılan araçları kapsamaktadır. Odak noktası, PKINIT kullanılarak alınan TGT üzerinden NTLM hash'lerinin elde edilmesi ve bu süreci kolaylaştıran yardımcı programlardır.

## Referanslar

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
