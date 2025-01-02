# AD CS प्रमाणपत्र चोरी

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) से शानदार शोध के चोरी अध्यायों का एक छोटा सारांश है।**

## मैं एक प्रमाणपत्र के साथ क्या कर सकता हूँ

प्रमाणपत्रों को चुराने के तरीके की जांच करने से पहले, यहाँ कुछ जानकारी है कि प्रमाणपत्र किसके लिए उपयोगी है:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exporting Certificates Using the Crypto APIs – THEFT1

In an **interactive desktop session**, extracting a user or machine certificate, along with the private key, can be easily done, particularly if the **private key is exportable**. This can be achieved by navigating to the certificate in `certmgr.msc`, right-clicking on it, and selecting `All Tasks → Export` to generate a password-protected .pfx file.

For a **programmatic approach**, tools such as the PowerShell `ExportPfxCertificate` cmdlet or projects like [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) are available. These utilize the **Microsoft CryptoAPI** (CAPI) or the Cryptography API: Next Generation (CNG) to interact with the certificate store. These APIs provide a range of cryptographic services, including those necessary for certificate storage and authentication.

However, if a private key is set as non-exportable, both CAPI and CNG will normally block the extraction of such certificates. To bypass this restriction, tools like **Mimikatz** can be employed. Mimikatz offers `crypto::capi` and `crypto::cng` commands to patch the respective APIs, allowing for the exportation of private keys. Specifically, `crypto::capi` patches the CAPI within the current process, while `crypto::cng` targets the memory of **lsass.exe** for patching.

## User Certificate Theft via DPAPI – THEFT2

More info about DPAPI in:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

In Windows, **certificate private keys are safeguarded by DPAPI**. It's crucial to recognize that the **storage locations for user and machine private keys** are distinct, and the file structures vary depending on the cryptographic API utilized by the operating system. **SharpDPAPI** is a tool that can navigate these differences automatically when decrypting the DPAPI blobs.

**User certificates** are predominantly housed in the registry under `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, but some can also be found in the directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. The corresponding **private keys** for these certificates are typically stored in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` for **CAPI** keys and `%APPDATA%\Microsoft\Crypto\Keys\` for **CNG** keys.

To **extract a certificate and its associated private key**, the process involves:

1. **Selecting the target certificate** from the user’s store and retrieving its key store name.
2. **Locating the required DPAPI masterkey** to decrypt the corresponding private key.
3. **Decrypting the private key** by utilizing the plaintext DPAPI masterkey.

For **acquiring the plaintext DPAPI masterkey**, the following approaches can be used:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
मास्टरकी फ़ाइलों और प्राइवेट की फ़ाइलों के डिक्रिप्शन को सरल बनाने के लिए, `certificates` कमांड [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) से लाभकारी साबित होती है। यह प्राइवेट कीज़ और संबंधित सर्टिफिकेट्स को डिक्रिप्ट करने के लिए `/pvk`, `/mkfile`, `/password`, या `{GUID}:KEY` को आर्गुमेंट के रूप में स्वीकार करती है, और इसके बाद एक `.pem` फ़ाइल उत्पन्न करती है।
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## मशीन सर्टिफिकेट चोरी DPAPI के माध्यम से – THEFT3

मशीन सर्टिफिकेट Windows द्वारा रजिस्ट्री में `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` में संग्रहीत होते हैं और संबंधित निजी कुंजी `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI के लिए) और `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG के लिए) में स्थित होती हैं, जो मशीन के DPAPI मास्टर कुंजी का उपयोग करके एन्क्रिप्ट की जाती हैं। इन कुंजियों को डोमेन के DPAPI बैकअप कुंजी के साथ डिक्रिप्ट नहीं किया जा सकता; इसके बजाय, **DPAPI_SYSTEM LSA सीक्रेट**, जिसे केवल SYSTEM उपयोगकर्ता एक्सेस कर सकता है, की आवश्यकता होती है।

मैनुअल डिक्रिप्शन `lsadump::secrets` कमांड को **Mimikatz** में निष्पादित करके DPAPI_SYSTEM LSA सीक्रेट को निकालकर किया जा सकता है, और इसके बाद इस कुंजी का उपयोग मशीन मास्टरकी को डिक्रिप्ट करने के लिए किया जाता है। वैकल्पिक रूप से, Mimikatz का `crypto::certificates /export /systemstore:LOCAL_MACHINE` कमांड CAPI/CNG को पहले वर्णित तरीके से पैच करने के बाद उपयोग किया जा सकता है।

**SharpDPAPI** अपने सर्टिफिकेट कमांड के साथ एक अधिक स्वचालित दृष्टिकोण प्रदान करता है। जब `/machine` फ्लैग को ऊंचे अनुमतियों के साथ उपयोग किया जाता है, तो यह SYSTEM में बढ़ता है, DPAPI_SYSTEM LSA सीक्रेट को डंप करता है, इसका उपयोग मशीन DPAPI मास्टरकी को डिक्रिप्ट करने के लिए करता है, और फिर इन प्लेनटेक्स्ट कुंजियों का उपयोग किसी भी मशीन सर्टिफिकेट निजी कुंजी को डिक्रिप्ट करने के लिए लुकअप टेबल के रूप में करता है।

## सर्टिफिकेट फ़ाइलें खोजना – THEFT4

सर्टिफिकेट कभी-कभी फ़ाइल सिस्टम के भीतर सीधे पाए जाते हैं, जैसे फ़ाइल शेयर या डाउनलोड फ़ोल्डर में। Windows वातावरण के लिए लक्षित सर्टिफिकेट फ़ाइलों के सबसे सामान्य प्रकार `.pfx` और `.p12` फ़ाइलें हैं। हालांकि कम बार, `.pkcs12` और `.pem` एक्सटेंशन वाली फ़ाइलें भी दिखाई देती हैं। अन्य उल्लेखनीय सर्टिफिकेट-संबंधित फ़ाइल एक्सटेंशन में शामिल हैं:

- `.key` निजी कुंजियों के लिए,
- `.crt`/`.cer` केवल सर्टिफिकेट के लिए,
- `.csr` सर्टिफिकेट साइनिंग अनुरोधों के लिए, जिसमें सर्टिफिकेट या निजी कुंजियाँ नहीं होती हैं,
- `.jks`/`.keystore`/`.keys` Java कीस्टोर्स के लिए, जो Java अनुप्रयोगों द्वारा उपयोग की जाने वाली सर्टिफिकेट के साथ निजी कुंजियाँ रख सकते हैं।

इन फ़ाइलों को PowerShell या कमांड प्रॉम्प्ट का उपयोग करके उल्लेखित एक्सटेंशन की खोज करके खोजा जा सकता है।

यदि कोई PKCS#12 सर्टिफिकेट फ़ाइल पाई जाती है और यह पासवर्ड द्वारा सुरक्षित है, तो `pfx2john.py` का उपयोग करके हैश निकालना संभव है, जो [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) पर उपलब्ध है। इसके बाद, पासवर्ड क्रैक करने के लिए JohnTheRipper का उपयोग किया जा सकता है।
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM क्रेडेंशियल चोरी PKINIT के माध्यम से – THEFT5

दिया गया सामग्री PKINIT के माध्यम से NTLM क्रेडेंशियल चोरी के लिए एक विधि को समझाता है, विशेष रूप से THEFT5 के रूप में लेबल की गई चोरी विधि के माध्यम से। यहाँ एक पुनः व्याख्या की गई है जो निष्क्रिय वॉयस में है, सामग्री को गुमनाम और संक्षिप्त किया गया है जहाँ आवश्यक हो:

NTLM प्रमाणीकरण [MS-NLMP] का समर्थन करने के लिए, उन अनुप्रयोगों के लिए जो Kerberos प्रमाणीकरण की सुविधा नहीं देते, KDC को उपयोगकर्ता के NTLM एक-तरफा फ़ंक्शन (OWF) को विशेष रूप से `PAC_CREDENTIAL_INFO` बफर में प्रिविलेज एट्रिब्यूट सर्टिफिकेट (PAC) के भीतर लौटाने के लिए डिज़ाइन किया गया है, जब PKCA का उपयोग किया जाता है। परिणामस्वरूप, यदि कोई खाता प्रमाणीकरण करता है और PKINIT के माध्यम से एक टिकट-ग्रांटिंग टिकट (TGT) प्राप्त करता है, तो एक तंत्र स्वाभाविक रूप से प्रदान किया जाता है जो वर्तमान होस्ट को NTLM हैश को TGT से निकालने की अनुमति देता है ताकि विरासती प्रमाणीकरण प्रोटोकॉल को बनाए रखा जा सके। इस प्रक्रिया में `PAC_CREDENTIAL_DATA` संरचना का डिक्रिप्शन शामिल है, जो मूलतः NTLM प्लेनटेक्स्ट का एक NDR सीरियलाइज्ड चित्रण है।

उपयोगिता **Kekeo**, जो [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) पर उपलब्ध है, का उल्लेख किया गया है कि यह इस विशेष डेटा को शामिल करने वाले TGT का अनुरोध करने में सक्षम है, इस प्रकार उपयोगकर्ता के NTLM को पुनः प्राप्त करने की सुविधा प्रदान करता है। इस उद्देश्य के लिए उपयोग की जाने वाली कमांड इस प्रकार है:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
इसके अतिरिक्त, यह नोट किया गया है कि Kekeo स्मार्टकार्ड-संरक्षित प्रमाणपत्रों को संसाधित कर सकता है, बशर्ते कि पिन को पुनः प्राप्त किया जा सके, जिसका संदर्भ [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) में दिया गया है। यह समान क्षमता **Rubeus** द्वारा समर्थित होने का संकेत दिया गया है, जो [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) पर उपलब्ध है।

यह व्याख्या NTLM क्रेडेंशियल चोरी की प्रक्रिया और उपकरणों को संक्षेप में प्रस्तुत करती है, जो PKINIT के माध्यम से NTLM हैश की पुनः प्राप्ति पर केंद्रित है, जो PKINIT का उपयोग करके प्राप्त TGT के माध्यम से होती है, और उन उपयोगिताओं पर जो इस प्रक्रिया को सुविधाजनक बनाती हैं।

{{#include ../../../banners/hacktricks-training.md}}
