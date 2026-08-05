# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDMs ausnutzen

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Wenn es dir gelingt, **Admin-Zugangsdaten zu kompromittieren**, um auf die Management-Plattform zuzugreifen, kannst du **potenziell alle Computer kompromittieren**, indem du deine Malware auf den Geräten verteilst.

Für Red Teaming in MacOS-Umgebungen wird dringend empfohlen, ein gewisses Verständnis dafür zu haben, wie MDMs funktionieren:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM als C2 verwenden

Ein MDM verfügt über die Berechtigungen, Profile zu installieren, abzufragen oder zu entfernen, Anwendungen zu installieren, lokale Admin-Konten zu erstellen, ein Firmware-Passwort festzulegen und den FileVault-Schlüssel zu ändern ...

Um dein eigenes MDM zu betreiben, benötigst du **deine CSR, die von einem Anbieter signiert wurde**. Diese kannst du versuchen, über [**https://mdmcert.download/**](https://mdmcert.download/) zu erhalten. Um dein eigenes MDM für Apple-Geräte zu betreiben, kannst du **[MicroMDM](https://github.com/micromdm/micromdm)** verwenden.

Um jedoch eine Anwendung auf einem registrierten Gerät zu installieren, muss sie weiterhin von einem Entwicklerkonto signiert sein ... bei der MDM-Registrierung fügt das **Gerät jedoch das SSL-Zertifikat des MDM als vertrauenswürdige CA hinzu**, sodass du nun alles signieren kannst.<sup>[[4]](#references)</sup>

Um das Gerät bei einem MDM zu registrieren, musst du eine **`mobileconfig`**-Datei als root installieren. Diese kann über eine **pkg**-Datei bereitgestellt werden (du könntest sie in eine zip-Datei komprimieren; beim Download über Safari wird sie dekomprimiert).

Der **Mythic-Agent Orthrus** verwendet diese Technik.

### JAMF PRO ausnutzen

JAMF kann **benutzerdefinierte Scripts** (vom Sysadmin entwickelte Scripts), **native Payloads** (Erstellung lokaler Konten, Festlegen des EFI-Passworts, Überwachung von Dateien/Prozessen ...) und **MDM** (Gerätekonfigurationen, Gerätezertifikate ...) ausführen.<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Rufe eine Seite wie `https://<company-name>.jamfcloud.com/enroll/` auf, um zu prüfen, ob **self-enrolment aktiviert** ist. Falls ja, werden möglicherweise **Zugangsdaten für den Zugriff angefordert**.

Du kannst das Script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) verwenden, um einen Password-Spraying-Angriff durchzuführen.

Nachdem du außerdem gültige Zugangsdaten gefunden hast, kannst du möglicherweise weitere Benutzernamen mit dem folgenden Formular per Brute-Force testen:

![JAMF PRO ausnutzen - JAMF self-enrolment: Nachdem du gültige Zugangsdaten gefunden hast, kannst du möglicherweise weitere Benutzernamen mit dem folgenden Formular per Brute-Force testen](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`**-Binärdatei enthielt das Geheimnis zum Öffnen des Keychains, das zum Zeitpunkt der Entdeckung **für alle gemeinsam verwendet** wurde. Es lautete: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Außerdem **persistiert** jamf als **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

Die **JSS**-**URL** (Jamf Software Server), die **`jamf`** verwenden wird, befindet sich in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Diese Datei enthält im Wesentlichen die URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Ein Angreifer könnte ein bösartiges Paket (`pkg`) einschleusen, das bei der Installation **diese Datei überschreibt** und die **URL auf einen Mythic-C2-Listener eines Typhon-Agenten setzt**, sodass JAMF als C2 missbraucht werden kann.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF-Impersonation

Um die **Kommunikation** zwischen einem Gerät und JMF zu **impersonate**, benötigst du:

- Die **UUID** des Geräts: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Die **JAMF-Keychain** aus: `/Library/Application\ Support/Jamf/JAMF.keychain`, die das Geräte-Zertifikat enthält

Mit diesen Informationen **erstelle eine VM** mit der **gestohlenen** Hardware-**UUID**, **deaktiviere SIP**, kopiere die **JAMF-Keychain**, **hooke** den Jamf-**Agent** und stiehl seine Informationen.

#### Secrets stehlen

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Du könntest außerdem den Pfad `/Library/Application Support/Jamf/tmp/` auf **custom scripts** überwachen, die Administratoren möglicherweise über Jamf ausführen möchten, da sie **hier abgelegt, ausgeführt und entfernt** werden. Diese Scripts **könnten Credentials enthalten**.

Allerdings könnten **Credentials** auch als **Parameter** an diese Scripts übergeben werden. Daher müsstest du `ps aux | grep -i jamf` überwachen (ohne überhaupt root zu sein).

Das Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kann auf das Hinzufügen neuer Dateien und neue Prozessargumente lauschen.

### macOS-Remote-Access

Und außerdem zu den "speziellen" **Netzwerk**-**Protokollen** von **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

In manchen Fällen wirst du feststellen, dass der **MacOS-Computer mit einem AD verbunden ist**. In diesem Szenario solltest du versuchen, das Active Directory so zu **enumerate**, wie du es gewohnt bist. Die folgenden Seiten bieten dir **Hilfe**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Ein **lokales MacOS-Tool**, das dir ebenfalls helfen könnte, ist `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Außerdem gibt es einige für MacOS vorbereitete Tools, um die AD automatisch zu enumerieren und mit kerberos zu arbeiten:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound ist eine Erweiterung des Bloodhound-Auditing-Tools, mit der sich Active-Directory-Beziehungen auf MacOS-Hosts sammeln und einlesen lassen.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ist ein Objective-C-Projekt zur Interaktion mit den Heimdal-krb5-APIs unter macOS. Ziel des Projekts ist es, bessere Security-Tests rund um Kerberos auf macOS-Geräten mithilfe nativer APIs zu ermöglichen, ohne ein anderes Framework oder zusätzliche Pakete auf dem Zielsystem zu benötigen.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript-for-Automation-(JXA)-Tool zur Active-Directory-Enumeration.

### Domain-Informationen
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Benutzer

Die drei Arten von MacOS-Benutzern sind:

- **Lokale Benutzer** — Sie werden vom lokalen OpenDirectory-Dienst verwaltet und sind in keiner Weise mit dem Active Directory verbunden.
- **Netzwerkbenutzer** — Flüchtige Active Directory-Benutzer, die für die Authentifizierung eine Verbindung zum DC-Server benötigen.
- **Mobile Benutzer** — Active Directory-Benutzer mit einer lokalen Sicherung ihrer Anmeldedaten und Dateien.

Die lokalen Informationen zu Benutzern und Gruppen werden im Ordner _/var/db/dslocal/nodes/Default._ gespeichert.\
Beispielsweise werden die Informationen zum Benutzer _mark_ in _/var/db/dslocal/nodes/Default/users/mark.plist_ und die Informationen zur Gruppe _admin_ in _/var/db/dslocal/nodes/Default/groups/admin.plist_ gespeichert.

Zusätzlich zur Verwendung der HasSession- und AdminTo-Edges fügt **MacHound der Bloodhound-Datenbank drei neue Edges hinzu**:<sup>[[2]](#references)</sup>

- **CanSSH** - Entität, die per SSH eine Verbindung zum Host herstellen darf
- **CanVNC** - Entität, die per VNC eine Verbindung zum Host herstellen darf
- **CanAE** - Entität, die AppleEvent-Skripte auf dem Host ausführen darf
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Weitere Informationen unter [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Passwörter abrufen mit:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Es ist möglich, auf das Passwort von **`Computer$`** im System-Schlüsselbund zuzugreifen.

### Over-Pass-The-Hash

Rufe ein TGT für einen bestimmten Benutzer und Dienst ab:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Sobald das TGT erfasst wurde, kann es mit folgendem Befehl in die aktuelle Session injiziert werden:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Mit erlangten Service-Tickets ist es möglich, zu versuchen, auf Freigaben anderer Computer zuzugreifen:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Zugriff auf den Keychain

Der Keychain enthält höchstwahrscheinlich sensible Informationen, die dabei helfen könnten, eine Red-Team-Übung voranzubringen, wenn ohne das Erzeugen einer Eingabeaufforderung darauf zugegriffen wird:


{{#ref}}
macos-keychain.md
{{#endref}}

## Externe Dienste

MacOS Red Teaming unterscheidet sich von einem regulären Windows Red Teaming, da **MacOS normalerweise direkt in mehrere externe Plattformen integriert ist**. Eine häufige Konfiguration von MacOS besteht darin, über **mit OneLogin synchronisierte Zugangsdaten auf den Computer zuzugreifen und über OneLogin auf mehrere externe Dienste** (wie github, aws ...) **zuzugreifen**.

## Verschiedene Red-Team-Techniken

### Safari

Wenn in Safari eine Datei heruntergeladen wird und es sich um eine „sichere“ Datei handelt, wird sie **automatisch geöffnet**. Wenn du beispielsweise **eine zip-Datei herunterlädst**, wird sie automatisch dekomprimiert:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referenzen

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
