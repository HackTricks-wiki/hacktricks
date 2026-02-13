# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** एक तकनीक है जो हमलावरों को प्रत्येक domain controller के LSASS प्रोसेस में **injecting a master password** करके **bypass Active Directory authentication** करने की अनुमति देती है। इंजेक्शन के बाद, master password (default **`mimikatz`**) का उपयोग किसी भी domain user के रूप में प्रमाणीकृत करने के लिए किया जा सकता है जबकि उनके वास्तविक पासवर्ड अभी भी काम करते हैं।

Key facts:

- प्रत्येक DC पर **Domain Admin/SYSTEM + SeDebugPrivilege** की आवश्यकता होती है और इसे **reapplied after each reboot** करना पड़ता है।
- **NTLM** और **Kerberos RC4 (etype 0x17)** validation paths को patch करता है; केवल AES‑only realms या AES अनिवार्य करने वाले अकाउंट **not accept the skeleton key**।
- तीसरे‑पक्ष के LSA authentication packages या अतिरिक्त smart‑card / MFA providers के साथ टकराव हो सकता है।
- The Mimikatz module accepts the optional switch `/letaes` to avoid touching Kerberos/AES hooks in case of compatibility issues.

### क्रियान्वयन

Classic, non‑PPL protected LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
यदि **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), LSASS को पैच करने से पहले सुरक्षा हटाने के लिए एक kernel driver की आवश्यकता होती है:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
इंजेक्शन के बाद, किसी भी domain खाते से प्रमाणीकृत करें लेकिन पासवर्ड के रूप में `mimikatz` (या ऑपरेटर द्वारा सेट की गई वैल्यू) का उपयोग करें। मल्टी‑DC वातावरण में इसे **सभी DCs** पर दोहराना याद रखें।

## Mitigations

- **लॉग मॉनिटरिंग**
- अनसाइन्ड ड्राइवर्स जैसे `mimidrv.sys` के लिए System **Event ID 7045** (service/driver install)।
- **Sysmon**: `mimidrv.sys` के लिए Event ID 7 (driver load); गैर‑सिस्टम प्रोसेस से `lsass.exe` तक संदिग्ध पहुंच के लिए Event ID 10।
- संवेदनशील privilege उपयोग या LSA authentication package रजिस्ट्रेशन असामान्यताओं के लिए Security **Event ID 4673/4611**; DCs से RC4 (etype 0x17) का उपयोग करके अनपेक्षित 4624 लॉगऑन के साथ correlate करें।
- **LSASS हार्डनिंग**
- attackers को kernel‑mode driver तैनाती की ओर मजबूर करने के लिए DCs पर **RunAsPPL/Credential Guard/Secure LSASS** सक्षम रखें (अधिक telemetry, exploitation कठिन)।
- जहाँ संभव हो legacy **RC4** को अक्षम करें; Kerberos टिकट्स को AES तक सीमित करने से उस RC4 hook path को रोका जा सकता है जिसका उपयोग skeleton key करता है।
- त्वरित PowerShell हंट्स:
- अनसाइन्ड kernel driver इंस्टॉल का पता लगाएँ: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver की तलाश: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- रीबूट के बाद PPL लागू है यह सत्यापित करें: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

अतिरिक्त credential‑hardening मार्गदर्शन के लिए देखें [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## संदर्भ

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
