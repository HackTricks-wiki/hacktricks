# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** एक ऐसी technique है जो attackers को प्रत्येक domain controller की LSASS process में **master password inject** करके **Active Directory authentication को bypass** करने की अनुमति देती है। Injection के बाद, master password (default **`mimikatz`**) का उपयोग **किसी भी domain user** के रूप में authenticate करने के लिए किया जा सकता है, जबकि उनके वास्तविक passwords भी काम करते रहते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

मुख्य तथ्य:

- प्रत्येक DC पर **Domain Admin/SYSTEM + SeDebugPrivilege** आवश्यक है और इसे **हर reboot के बाद फिर से apply** करना पड़ता है।<sup>[[2]](#references)</sup>
- यह **NTLM** और **Kerberos RC4 (etype 0x17)** validation paths को patch करता है; केवल AES वाले realms या AES लागू करने वाले accounts **skeleton key को स्वीकार नहीं करेंगे**।<sup>[[2]](#references)</sup>
- यह third‑party LSA authentication packages या अतिरिक्त smart‑card / MFA providers के साथ conflict कर सकता है।<sup>[[2]](#references)</sup>
- Mimikatz module में optional switch `/letaes` स्वीकार किया जाता है, जिससे compatibility issues की स्थिति में Kerberos/AES hooks को modify करने से बचा जा सके।<sup>[[3]](#references)</sup>

### Execution

Classic, non‑PPL protected LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
यदि **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), LSASS को patch करने से पहले protection हटाने के लिए एक kernel driver आवश्यक है:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Injection के बाद, किसी भी domain account से authenticate करें, लेकिन password `mimikatz` (या operator द्वारा set की गई value) का उपयोग करें। Multi‑DC environments में इसे **सभी DCs** पर दोहराना याद रखें।

## Mitigations

- **Log monitoring**
- Unsigned drivers जैसे `mimidrv.sys` के लिए System **Event ID 7045** (service/driver install) की निगरानी करें।
- **Sysmon**: `mimidrv.sys` के लिए Event ID 7 (driver load); non‑system processes से `lsass.exe` तक suspicious access के लिए Event ID 10।
- Sensitive privilege use या LSA authentication package registration anomalies के लिए Security **Event ID 4673/4611**; इसे DCs से RC4 (etype 0x17) का उपयोग करने वाले unexpected 4624 logons के साथ correlate करें।
- **LSASS Hardening**
- DCs पर **RunAsPPL/Credential Guard/Secure LSASS** enabled रखें, ताकि attackers को kernel‑mode driver deployment की ओर जाना पड़े (अधिक telemetry, अधिक कठिन exploitation)।
- जहाँ संभव हो, legacy **RC4** को disable करें; केवल AES तक सीमित Kerberos tickets skeleton key द्वारा उपयोग किए जाने वाले RC4 hook path को रोकते हैं।<sup>[[2]](#references)</sup>
- Quick PowerShell hunts:
- Unsigned kernel driver installs detect करें: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver के लिए hunt करें: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Reboot के बाद PPL enforced है या नहीं validate करें: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Additional credential‑hardening guidance के लिए [Windows credentials protections](../stealing-credentials/credentials-protections.md) देखें।

## References

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
