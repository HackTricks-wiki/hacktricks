# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) से किए गए शानदार research के Certificate Theft chapters का एक छोटा सारांश है।**<sup>[[1]](#references)</sup>

## Certificate के साथ मैं क्या कर सकता हूँ

Certificates को चुराने का तरीका देखने से पहले, यहाँ कुछ जानकारी दी गई है कि certificate किस काम के लिए उपयोगी है:
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
## Crypto APIs का उपयोग करके Certificates Export करना – THEFT1

एक **interactive desktop session** में, किसी user या machine certificate को private key के साथ extract करना आसानी से किया जा सकता है, विशेष रूप से तब जब **private key exportable** हो। इसे `certmgr.msc` में certificate पर जाकर, उस पर right-click करके और `All Tasks → Export` चुनकर password-protected .pfx file generate करके किया जा सकता है।<sup>[[1]](#references)</sup>

**Programmatic approach** के लिए, PowerShell के `ExportPfxCertificate` cmdlet या [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) जैसे projects उपलब्ध हैं। ये certificate store के साथ interact करने के लिए **Microsoft CryptoAPI** (CAPI) या Cryptography API: Next Generation (CNG) का उपयोग करते हैं। ये APIs कई cryptographic services प्रदान करती हैं, जिनमें certificate storage और authentication के लिए आवश्यक services भी शामिल हैं।

हालाँकि, यदि private key को non-exportable के रूप में set किया गया हो, तो CAPI और CNG दोनों सामान्यतः ऐसे certificates के extraction को block कर देंगे। इस restriction को bypass करने के लिए **Mimikatz** जैसे tools का उपयोग किया जा सकता है। Mimikatz संबंधित APIs को patch करने के लिए `crypto::capi` और `crypto::cng` commands प्रदान करता है, जिससे private keys को export किया जा सकता है। विशेष रूप से, `crypto::capi` current process के भीतर CAPI को patch करता है, जबकि `crypto::cng` patching के लिए **lsass.exe** की memory को target करता है।

## DPAPI के माध्यम से User Certificate Theft – THEFT2

DPAPI के बारे में अधिक जानकारी:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Windows में, **certificate private keys को DPAPI द्वारा सुरक्षित रखा जाता है**। यह समझना महत्वपूर्ण है कि **user और machine private keys के storage locations** अलग-अलग होते हैं, और operating system द्वारा उपयोग की जाने वाली cryptographic API के आधार पर file structures भी अलग होते हैं। **SharpDPAPI** DPAPI blobs को decrypt करते समय इन differences को automatically navigate करने वाला tool है।<sup>[[1]](#references)</sup>

**User certificates** मुख्य रूप से registry में `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` के अंतर्गत रखे जाते हैं, लेकिन कुछ certificates directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` में भी पाए जा सकते हैं। इन certificates की संबंधित **private keys** सामान्यतः **CAPI** keys के लिए `%APPDATA%\Microsoft\Crypto\RSA\User SID\` में और **CNG** keys के लिए `%APPDATA%\Microsoft\Crypto\Keys\` में stored होती हैं।

**किसी certificate और उससे संबंधित private key को extract करने** की process में शामिल हैं:

1. User के store से **target certificate को select करना** और उसका key store name retrieve करना।
2. संबंधित private key को decrypt करने के लिए आवश्यक **DPAPI masterkey को locate करना**।
3. Plaintext DPAPI masterkey का उपयोग करके **private key को decrypt करना**।

**Plaintext DPAPI masterkey प्राप्त करने** के लिए निम्नलिखित approaches का उपयोग किया जा सकता है:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Masterkey फ़ाइलों और private key फ़ाइलों के decryption को सरल बनाने के लिए, [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) का `certificates` command उपयोगी साबित होता है। यह private keys और उनसे linked certificates को decrypt करने के लिए `/pvk`, `/mkfile`, `/password`, या `{GUID}:KEY` को arguments के रूप में स्वीकार करता है और इसके बाद एक `.pem` फ़ाइल generate करता है।
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Machine Certificate Theft via DPAPI – THEFT3

Windows द्वारा registry में `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` पर संग्रहीत machine certificates और `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI के लिए) तथा `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG के लिए) में स्थित संबंधित private keys, machine की DPAPI master keys का उपयोग करके encrypted होती हैं। इन keys को domain की DPAPI backup key से decrypt नहीं किया जा सकता; इसके बजाय **DPAPI_SYSTEM LSA secret** आवश्यक होता है, जिसे केवल SYSTEM user ही access कर सकता है।<sup>[[1]](#references)</sup>

Manual decryption के लिए **Mimikatz** में `lsadump::secrets` command चलाकर DPAPI_SYSTEM LSA secret निकाला जा सकता है और फिर इस key का उपयोग machine masterkeys को decrypt करने के लिए किया जा सकता है। वैकल्पिक रूप से, पहले बताए अनुसार CAPI/CNG को patch करने के बाद Mimikatz की `crypto::certificates /export /systemstore:LOCAL_MACHINE` command का उपयोग किया जा सकता है।

**SharpDPAPI** अपने certificates command के माध्यम से अधिक automated तरीका प्रदान करता है। Elevated permissions के साथ `/machine` flag का उपयोग किए जाने पर यह SYSTEM तक escalate करता है, DPAPI_SYSTEM LSA secret dump करता है, इसका उपयोग machine DPAPI masterkeys को decrypt करने के लिए करता है और फिर इन plaintext keys को lookup table के रूप में इस्तेमाल करके किसी भी machine certificate private keys को decrypt करता है।

## Finding Certificate Files – THEFT4

Certificates कभी-कभी filesystem में सीधे मिलते हैं, जैसे file shares या Downloads folder में। Windows environments के लिए targeted certificate files में सबसे सामान्य प्रकार `.pfx` और `.p12` हैं। कम सामान्य होने पर भी `.pkcs12` और `.pem` extensions वाली files भी मिलती हैं। Certificate से संबंधित अन्य महत्वपूर्ण file extensions में शामिल हैं:<sup>[[1]](#references)</sup>

- private keys के लिए `.key`,
- केवल certificates के लिए `.crt`/`.cer`,
- Certificate Signing Requests के लिए `.csr`, जिनमें certificates या private keys शामिल नहीं होतीं,
- Java Keystores के लिए `.jks`/`.keystore`/`.keys`, जिनमें certificates के साथ Java applications द्वारा उपयोग की जाने वाली private keys भी हो सकती हैं।

इन files को PowerShell या command prompt का उपयोग करके, ऊपर बताए गए extensions को खोजकर ढूँढा जा सकता है।

यदि कोई PKCS#12 certificate file मिलती है और वह password से protected है, तो [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) पर उपलब्ध `pfx2john.py` का उपयोग करके hash निकाला जा सकता है। इसके बाद password को crack करने का प्रयास करने के लिए JohnTheRipper का उपयोग किया जा सकता है।
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## PKINIT के माध्यम से NTLM Credential Theft – THEFT5 (UnPAC the hash)

दिया गया content NTLM authentication के लिए PKINIT के माध्यम से credential theft की एक विधि समझाता है, विशेष रूप से THEFT5 नामक theft method के द्वारा। इसे passive voice में, और जहाँ लागू हो वहाँ content को anonymize तथा summarize करके प्रस्तुत किया गया है:<sup>[[1]](#references)</sup>

ऐसे applications के लिए NTLM authentication `MS-NLMP` का समर्थन करने हेतु, जो Kerberos authentication की सुविधा नहीं देते, KDC को PKCA के उपयोग के समय privilege attribute certificate (PAC) के भीतर, विशेष रूप से `PAC_CREDENTIAL_INFO` buffer में, user का NTLM one-way function (OWF) लौटाने के लिए design किया गया है। परिणामस्वरूप, यदि कोई account PKINIT के माध्यम से authenticate करके Ticket-Granting Ticket (TGT) सुरक्षित करता है, तो ऐसा mechanism स्वाभाविक रूप से उपलब्ध हो जाता है जिसके द्वारा current host legacy authentication protocols को बनाए रखने के लिए TGT से NTLM hash extract कर सकता है। इस process में `PAC_CREDENTIAL_DATA` structure को decrypt करना शामिल है, जो मूल रूप से NTLM plaintext का NDR serialized representation है।

[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) पर उपलब्ध utility **Kekeo** को ऐसे TGT का अनुरोध करने में सक्षम बताया गया है जिसमें यह specific data शामिल होता है, जिससे user का NTLM retrieve किया जा सकता है। इस उद्देश्य के लिए उपयोग की जाने वाली command इस प्रकार है:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** इस जानकारी को **`asktgt [...] /getcredentials`** विकल्प के साथ भी प्राप्त कर सकता है।

इसके अतिरिक्त, यह उल्लेख किया गया है कि यदि pin प्राप्त किया जा सके, तो Kekeo smartcard-protected certificates को process कर सकता है। इसके संदर्भ के रूप में [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) दिया गया है। यही capability **Rubeus** द्वारा भी supported बताई गई है, जो [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) पर उपलब्ध है।

यह explanation PKINIT के माध्यम से NTLM credential theft में शामिल process और tools को समाहित करती है। इसमें PKINIT का उपयोग करके प्राप्त TGT के माध्यम से NTLM hashes प्राप्त करने और इस process को सुविधाजनक बनाने वाली utilities पर ध्यान केंद्रित किया गया है।

## संदर्भ

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
