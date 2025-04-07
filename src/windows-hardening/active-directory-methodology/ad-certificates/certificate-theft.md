# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) से शानदार शोध के चोरी अध्यायों का एक छोटा सारांश है।**

## मैं एक प्रमाणपत्र के साथ क्या कर सकता हूँ

प्रमाणपत्रों को चुराने के तरीके की जांच करने से पहले, यहाँ आपके पास यह जानने के लिए कुछ जानकारी है कि प्रमाणपत्र किसके लिए उपयोगी है:
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
## Exporting Certificates Using the Crypto APIs – THEFT1

In an **interactive desktop session**, एक उपयोगकर्ता या मशीन प्रमाणपत्र को, साथ में निजी कुंजी के, आसानी से निकाला जा सकता है, विशेष रूप से यदि **निजी कुंजी निर्यात योग्य है**। इसे `certmgr.msc` में प्रमाणपत्र पर नेविगेट करके, उस पर राइट-क्लिक करके, और `All Tasks → Export` का चयन करके एक पासवर्ड-संरक्षित .pfx फ़ाइल उत्पन्न करके प्राप्त किया जा सकता है।

For a **programmatic approach**, tools such as the PowerShell `ExportPfxCertificate` cmdlet or projects like [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) are available. These utilize the **Microsoft CryptoAPI** (CAPI) or the Cryptography API: Next Generation (CNG) to interact with the certificate store. These APIs provide a range of cryptographic services, including those necessary for certificate storage and authentication.

हालांकि, यदि एक निजी कुंजी को गैर-निर्यात योग्य के रूप में सेट किया गया है, तो सामान्यतः CAPI और CNG ऐसे प्रमाणपत्रों के निष्कर्षण को रोक देंगे। इस प्रतिबंध को बायपास करने के लिए, **Mimikatz** जैसे उपकरणों का उपयोग किया जा सकता है। Mimikatz `crypto::capi` और `crypto::cng` कमांड प्रदान करता है ताकि संबंधित APIs को पैच किया जा सके, जिससे निजी कुंजियों का निर्यात संभव हो सके। विशेष रूप से, `crypto::capi` वर्तमान प्रक्रिया के भीतर CAPI को पैच करता है, जबकि `crypto::cng` पैचिंग के लिए **lsass.exe** की मेमोरी को लक्षित करता है।

## User Certificate Theft via DPAPI – THEFT2

More info about DPAPI in:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

In Windows, **certificate private keys are safeguarded by DPAPI**. यह पहचानना महत्वपूर्ण है कि **उपयोगकर्ता और मशीन निजी कुंजियों के लिए भंडारण स्थान** भिन्न होते हैं, और फ़ाइल संरचनाएँ ऑपरेटिंग सिस्टम द्वारा उपयोग किए जाने वाले क्रिप्टोग्राफिक API के आधार पर भिन्न होती हैं। **SharpDPAPI** एक उपकरण है जो DPAPI ब्लॉब्स को डिक्रिप्ट करते समय इन भिन्नताओं को स्वचालित रूप से नेविगेट कर सकता है।

**User certificates** मुख्य रूप से रजिस्ट्री में `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` के तहत स्थित होते हैं, लेकिन कुछ `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` निर्देशिका में भी मिल सकते हैं। इन प्रमाणपत्रों के लिए संबंधित **निजी कुंजियाँ** आमतौर पर `%APPDATA%\Microsoft\Crypto\RSA\User SID\` में **CAPI** कुंजियों के लिए और `%APPDATA%\Microsoft\Crypto\Keys\` में **CNG** कुंजियों के लिए संग्रहीत होती हैं।

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
मास्टरकी फ़ाइलों और प्राइवेट की फ़ाइलों के डिक्रिप्शन को सरल बनाने के लिए, [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) से `certificates` कमांड फायदेमंद साबित होता है। यह प्राइवेट की और संबंधित सर्टिफिकेट्स को डिक्रिप्ट करने के लिए `/pvk`, `/mkfile`, `/password`, या `{GUID}:KEY` को आर्गुमेंट के रूप में स्वीकार करता है, और इसके बाद एक `.pem` फ़ाइल उत्पन्न करता है।
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Machine Certificate Theft via DPAPI – THEFT3

Windows द्वारा रजिस्ट्री में `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` में संग्रहीत मशीन प्रमाणपत्र और संबंधित निजी कुंजी `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI के लिए) और `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG के लिए) में स्थित होती हैं, जो मशीन के DPAPI मास्टर कुंजियों का उपयोग करके एन्क्रिप्ट की जाती हैं। इन कुंजियों को डोमेन के DPAPI बैकअप कुंजी के साथ डिक्रिप्ट नहीं किया जा सकता; इसके बजाय, **DPAPI_SYSTEM LSA सीक्रेट**, जिसे केवल SYSTEM उपयोगकर्ता एक्सेस कर सकता है, की आवश्यकता होती है।

मैनुअल डिक्रिप्शन `lsadump::secrets` कमांड को **Mimikatz** में निष्पादित करके DPAPI_SYSTEM LSA सीक्रेट को निकालकर किया जा सकता है, और इसके बाद इस कुंजी का उपयोग मशीन मास्टरकीज़ को डिक्रिप्ट करने के लिए किया जाता है। वैकल्पिक रूप से, Mimikatz का `crypto::certificates /export /systemstore:LOCAL_MACHINE` कमांड का उपयोग CAPI/CNG को पहले वर्णित तरीके से पैच करने के बाद किया जा सकता है।

**SharpDPAPI** अपने प्रमाणपत्र कमांड के साथ एक अधिक स्वचालित दृष्टिकोण प्रदान करता है। जब `/machine` ध्वज को ऊंचे अनुमतियों के साथ उपयोग किया जाता है, तो यह SYSTEM में बढ़ता है, DPAPI_SYSTEM LSA सीक्रेट को डंप करता है, इसका उपयोग मशीन DPAPI मास्टरकीज़ को डिक्रिप्ट करने के लिए करता है, और फिर इन प्लेनटेक्स्ट कुंजियों का उपयोग किसी भी मशीन प्रमाणपत्र निजी कुंजी को डिक्रिप्ट करने के लिए लुकअप टेबल के रूप में करता है।

## Finding Certificate Files – THEFT4

प्रमाणपत्र कभी-कभी फ़ाइल सिस्टम के भीतर सीधे पाए जाते हैं, जैसे फ़ाइल शेयर या डाउनलोड फ़ोल्डर में। Windows वातावरण के लिए लक्षित प्रमाणपत्र फ़ाइलों के सबसे सामान्य प्रकार `.pfx` और `.p12` फ़ाइलें हैं। हालांकि कम बार, `.pkcs12` और `.pem` एक्सटेंशन वाली फ़ाइलें भी दिखाई देती हैं। अन्य उल्लेखनीय प्रमाणपत्र-संबंधित फ़ाइल एक्सटेंशन में शामिल हैं:

- `.key` निजी कुंजियों के लिए,
- `.crt`/`.cer` केवल प्रमाणपत्रों के लिए,
- `.csr` प्रमाणपत्र हस्ताक्षर अनुरोधों के लिए, जिसमें प्रमाणपत्र या निजी कुंजियाँ नहीं होती हैं,
- `.jks`/`.keystore`/`.keys` Java कीस्टोर्स के लिए, जो Java अनुप्रयोगों द्वारा उपयोग की जाने वाली प्रमाणपत्रों के साथ निजी कुंजियाँ रख सकते हैं।

इन फ़ाइलों को PowerShell या कमांड प्रॉम्प्ट का उपयोग करके उल्लेखित एक्सटेंशन की खोज करके खोजा जा सकता है।

यदि एक PKCS#12 प्रमाणपत्र फ़ाइल पाई जाती है और यह एक पासवर्ड द्वारा सुरक्षित है, तो `pfx2john.py` का उपयोग करके हैश निकालना संभव है, जो [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) पर उपलब्ध है। इसके बाद, JohnTheRipper का उपयोग पासवर्ड को क्रैक करने का प्रयास करने के लिए किया जा सकता है।
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM क्रेडेंशियल चोरी PKINIT के माध्यम से – THEFT5 (हैश को UnPAC करें)

दिया गया सामग्री NTLM क्रेडेंशियल चोरी के लिए PKINIT के माध्यम से एक विधि को समझाता है, विशेष रूप से THEFT5 के रूप में लेबल की गई चोरी विधि के माध्यम से। यहाँ एक पुनः व्याख्या की गई है जो निष्क्रिय वॉयस में है, सामग्री को गुमनाम और संक्षिप्त किया गया है जहाँ आवश्यक हो:

NTLM प्रमाणीकरण `MS-NLMP` का समर्थन करने के लिए, उन अनुप्रयोगों के लिए जो Kerberos प्रमाणीकरण की सुविधा नहीं देते, KDC को उपयोगकर्ता के NTLM एक-तरफा फ़ंक्शन (OWF) को विशेष रूप से `PAC_CREDENTIAL_INFO` बफर में प्रिविलेज एट्रिब्यूट सर्टिफिकेट (PAC) के भीतर लौटाने के लिए डिज़ाइन किया गया है, जब PKCA का उपयोग किया जाता है। परिणामस्वरूप, यदि कोई खाता PKINIT के माध्यम से प्रमाणीकरण करता है और एक टिकट-ग्रांटिंग टिकट (TGT) प्राप्त करता है, तो एक तंत्र स्वाभाविक रूप से प्रदान किया जाता है जो वर्तमान होस्ट को NTLM हैश को TGT से निकालने की अनुमति देता है ताकि विरासती प्रमाणीकरण प्रोटोकॉल को बनाए रखा जा सके। इस प्रक्रिया में `PAC_CREDENTIAL_DATA` संरचना का डिक्रिप्शन शामिल है, जो मूलतः NTLM प्लेनटेक्स्ट का एक NDR सीरियलाइज्ड चित्रण है।

उपयोगिता **Kekeo**, जो [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) पर उपलब्ध है, का उल्लेख किया गया है कि यह इस विशेष डेटा को शामिल करने वाले TGT का अनुरोध करने में सक्षम है, जिससे उपयोगकर्ता के NTLM की पुनर्प्राप्ति को सुविधाजनक बनाया जा सके। इस उद्देश्य के लिए उपयोग की जाने वाली कमांड इस प्रकार है:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** इस जानकारी को विकल्प **`asktgt [...] /getcredentials`** के साथ भी प्राप्त कर सकता है।

इसके अतिरिक्त, यह नोट किया गया है कि Kekeo स्मार्टकार्ड-संरक्षित प्रमाणपत्रों को संसाधित कर सकता है, बशर्ते कि पिन को पुनः प्राप्त किया जा सके, जिसका संदर्भ [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) पर दिया गया है। यह समान क्षमता **Rubeus** द्वारा समर्थित बताई गई है, जो [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) पर उपलब्ध है।

यह व्याख्या NTLM क्रेडेंशियल चोरी की प्रक्रिया और उपकरणों को संक्षेप में प्रस्तुत करती है, जो PKINIT के माध्यम से NTLM हैश की पुनः प्राप्ति पर केंद्रित है, जो PKINIT का उपयोग करके प्राप्त TGT के माध्यम से होती है, और उन उपयोगिताओं पर जो इस प्रक्रिया को सुविधाजनक बनाती हैं।

{{#include ../../../banners/hacktricks-training.md}}
