# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Missbrauch von MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Wenn es dir gelingt, **Admin-Anmeldedaten zu kompromittieren**, um auf die Managementplattform zuzugreifen, kannst du **potenziell alle Computer kompromittieren**, indem du deine Malware auf den Geräten verteilst.

Für Red Teaming in MacOS-Umgebungen ist es sehr empfehlenswert, ein gewisses Verständnis davon zu haben, wie MDMs funktionieren:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM als C2 verwenden

Ein MDM hat die Berechtigung, Profile zu installieren, abzufragen oder zu entfernen, Anwendungen zu installieren, lokale Admin-Konten zu erstellen, ein Firmware-Passwort festzulegen, den FileVault-Schlüssel zu ändern ...

Um dein eigenes MDM zu betreiben, musst du **deinen CSR von einem Anbieter signieren lassen**. Das kannst du über [**https://mdmcert.download/**](https://mdmcert.download/) versuchen. Um dein eigenes MDM für Apple-Geräte zu betreiben, kannst du [**MicroMDM**](https://github.com/micromdm/micromdm) verwenden.

Die MDM-Registrierung macht das TLS-Zertifikat des Managementservers **nicht** automatisch zu einer vertrauenswürdigen CA und gewährt auch keine App-Signaturidentität. Verwendet der Server eine private CA, müssen deren Root- und Intermediate-Zertifikate im Registrierungsprofil oder in einem separaten Vertrauensprofil bereitgestellt werden. Das für die MDM-Authentifizierung verwendete Client-Identitätszertifikat ist ein anderes Zertifikat.<sup>[[7]](#references)</sup>

Ein heruntergeladenes MDM-Registrierungsprofil (`.mobileconfig`) muss geöffnet und unter **Systemeinstellungen → Allgemein → Geräteverwaltung** genehmigt werden. Es wird auf einem aktuellen Mac nicht stillschweigend registriert, wenn es lediglich in ein als root installiertes `.pkg` oder ein mit Safari geöffnetes ZIP-Archiv gelegt wird. Siehe [Verhalten von Konfigurationsprofilen](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Die automatisierte Geräteregistrierung während des Setup-Assistenten ist ein separater Ablauf. Informationen zu den anderen Voraussetzungen findest du unter [unerlaubte Registrierung eines Geräts einer anderen Organisation](macos-mdm/enrolling-devices-in-other-organisations.md).<sup>[[9]](#references)</sup>

**Der Mythic-Agent Orthrus** verwendet diese Technik.

### Bereitstellen eines Pakets über ein kontrolliertes MDM

Auf einem **überwachten Mac mit macOS 26 oder neuer** ermöglicht die Kontrolle über den MDM-Dienst eine `com.apple.configuration.package`-Deklaration im Systembereich.<sup>[[10]](#references)</sup> Das Paket muss eine Signatur haben, die das Gerät verifizieren kann. Seine App benötigt jedoch keine separate Developer-ID-Signatur: Gatekeeper überprüft keine Apps, die über die Geräteverwaltung installiert wurden.<sup>[[11]](#references)</sup> Ein vertrauenswürdiges TLS-Zertifikat des Servers allein verschafft dem Betreiber weder den privaten Schlüssel noch die erforderliche Signaturberechtigung für diese Paketsignatur.<sup>[[11]](#references)[[12]](#references)</sup>

Erstelle ein signiertes Testpaket, berechne dessen Digest und veröffentliche sowohl das Paket als auch eine `ManifestURL`-Plist über HTTPS. Das Manifest benötigt ein `software-package`-Asset mit dessen URL und SHA-256 sowie eine eindeutige `bundle-identifier`- und `bundle-version`-Angabe.<sup>[[11]](#references)</sup> Sende anschließend eine Paketdeklaration mit der URL des Manifests und setze `InstallBehavior.Install` auf `Required`; überprüfe den Status-Eintrag `package.list` auf die Installation oder Fehler.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Eine minimale Deklaration für eine erforderliche Installation, die über den MDM-Dienst übermittelt wird, sieht so aus (ersetze die URL und beide UUIDs).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Missbrauch von JAMF PRO

JAMF kann **custom scripts** (vom Sysadmin entwickelte Skripte), **native payloads** (lokale Accounts erstellen, EFI-Passwort festlegen, Dateien/Prozesse überwachen usw.) und **MDM** (Gerätekonfigurationen, Gerätezertifikate usw.) ausführen.<sup>[[5]](#references)</sup>

#### JAMF-Selbstregistrierung

Rufe eine Seite wie `https://<company-name>.jamfcloud.com/enroll/` auf, um zu prüfen, ob **Selbstregistrierung aktiviert** ist. Falls ja, werden möglicherweise **Anmeldedaten für den Zugriff abgefragt**.

Mit dem Skript [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kannst du einen Password-Spraying-Angriff durchführen.

Außerdem könntest du nach dem Finden gültiger Anmeldedaten mit dem folgenden Formular weitere Benutzernamen per Brute-Force-Angriff herausfinden:

![Missbrauch von JAMF PRO – JAMF-Selbstregistrierung: Außerdem könntest du nach dem Finden gültiger Anmeldedaten mit dem folgenden Formular weitere Benutzernamen per Brute-Force-Angriff herausfinden](<../../images/image (107).png>)

#### JAMF-Geräteauthentifizierung

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Die Binärdatei **`jamf`** enthielt das Geheimnis zum Öffnen des Schlüsselbunds. Zum Zeitpunkt der Entdeckung war es **für alle gleich** und lautete: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Außerdem bleibt jamf als **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`** persistent.

#### Übernahme eines JAMF-Geräts

Die **JSS**-**URL** (Jamf Software Server), die **`jamf`** verwendet, befindet sich in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
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

Ein Angreifer könnte also ein bösartiges Paket (`pkg`) platzieren, das bei der Installation **diese Datei überschreibt** und die **URL auf einen Mythic-C2-Listener eines Typhon-Agenten setzt**, sodass JAMF als C2 missbraucht werden kann.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF-Impersonation

Um die **Kommunikation** zwischen einem Gerät und JMF zu **imitieren**, benötigst du:

- Die **UUID** des Geräts: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Den **JAMF-Schlüsselbund** unter `/Library/Application\ Support/Jamf/JAMF.keychain`, der das Gerätezertifikat enthält

Erstelle mit diesen Informationen eine **VM** mit der **gestohlenen** Hardware-**UUID** und deaktiviertem **SIP**, lege den **JAMF-Schlüsselbund** ab, **hooke** den Jamf-**Agent** und stiehl seine Informationen.

#### Geheimnisse stehlen

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Du kannst auch den Speicherort `/Library/Application Support/Jamf/tmp/` auf **benutzerdefinierte Skripte** überwachen, die Admins möglicherweise über Jamf ausführen wollen: Sie werden hier abgelegt, ausgeführt und entfernt. Diese Skripte **könnten Zugangsdaten enthalten**.

**Zugangsdaten** könnten diesen Skripten jedoch auch als **Parameter** übergeben werden. Daher müsstest du `ps aux | grep -i jamf` überwachen (auch ohne Root-Rechte).

Das Skript [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kann auf neu hinzugefügte Dateien und neue Prozessargumente lauschen.

### macOS-Fernzugriff

Und auch zu den „speziellen“ **Netzwerkprotokollen** von **macOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Gelegentlich wirst du feststellen, dass der **macOS-Computer mit einem AD verbunden ist**. In diesem Szenario solltest du versuchen, das Active Directory wie gewohnt zu **enumerieren**. Auf den folgenden Seiten findest du **Hilfe**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Einige **lokale macOS-Tools**, die dir ebenfalls helfen können, sind `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Außerdem gibt es einige Tools für macOS, mit denen sich AD automatisch enumerieren und Kerberos nutzen lässt:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound ist eine Erweiterung des Bloodhound-Auditing-Tools, mit der sich Active-Directory-Beziehungen auf macOS-Hosts erfassen und importieren lassen.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ist ein Objective-C-Projekt, das für die Interaktion mit den Heimdal-krb5-APIs unter macOS entwickelt wurde. Ziel des Projekts ist es, umfassendere Sicherheitstests für Kerberos auf macOS-Geräten mithilfe nativer APIs zu ermöglichen, ohne ein weiteres Framework oder Pakete auf dem Zielsystem vorauszusetzen.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Ein JavaScript-for-Automation-(JXA-)Tool zur Active-Directory-Enumeration.

### Domaininformationen

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Benutzer

Die drei Arten von MacOS-Benutzern sind:

- **Lokale Benutzer** — Werden vom lokalen OpenDirectory-Dienst verwaltet und sind in keiner Weise mit Active Directory verbunden.
- **Netzwerkbenutzer** — Flüchtige Active-Directory-Benutzer, die zum Authentifizieren eine Verbindung zum DC-Server benötigen.
- **Mobile Benutzer** — Active-Directory-Benutzer mit einer lokalen Sicherung ihrer Anmeldedaten und Dateien.

Die lokalen Informationen zu Benutzern und Gruppen werden im Ordner _/var/db/dslocal/nodes/Default._ gespeichert.\
Beispielsweise werden die Informationen zum Benutzer _mark_ unter _/var/db/dslocal/nodes/Default/users/mark.plist_ und die Informationen zur Gruppe _admin_ unter _/var/db/dslocal/nodes/Default/groups/admin.plist_ gespeichert.

Zusätzlich zu den HasSession- und AdminTo-Edges fügt **MacHound der Bloodhound-Datenbank drei neue Edges** hinzu:<sup>[[2]](#references)</sup>

- **CanSSH** – Entität, die per SSH eine Verbindung zum Host herstellen darf
- **CanVNC** – Entität, die per VNC eine Verbindung zum Host herstellen darf
- **CanAE** – Entität, die AppleEvent-Skripte auf dem Host ausführen darf

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

Weitere Informationen unter [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$-Passwort

Passwörter abrufen mit:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Es ist möglich, auf das **`Computer$`**-Passwort im System-Schlüsselbund zuzugreifen.

### Over-Pass-The-Hash

Ein TGT für einen bestimmten Benutzer und Dienst abrufen:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Sobald das TGT erfasst wurde, lässt es sich mit folgendem Befehl in die aktuelle Sitzung injizieren:

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

Mit erhaltenen Service-Tickets kann versucht werden, auf Freigaben anderer Computer zuzugreifen:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Zugriff auf den Keychain

Der Keychain enthält sehr wahrscheinlich sensible Informationen, deren Zugriff ohne Auslösen einer Eingabeaufforderung dabei helfen könnte, eine Red-Team-Übung voranzubringen:


{{#ref}}
macos-keychain.md
{{#endref}}

## Externe Dienste

MacOS Red Teaming unterscheidet sich von regulärem Windows Red Teaming, da **MacOS gewöhnlich direkt in mehrere externe Plattformen integriert ist**. Eine gängige MacOS-Konfiguration ermöglicht den Zugriff auf den Computer mit **synchronisierten OneLogin-Anmeldedaten sowie den Zugriff auf mehrere externe Dienste** (wie github, aws usw.) über OneLogin.

## Verschiedene Red-Team-Techniken

### Safari

Wenn in Safari eine Datei heruntergeladen wird und es sich um eine „sichere“ Datei handelt, wird sie **automatisch geöffnet**. Wenn du also beispielsweise **eine ZIP-Datei herunterlädst**, wird sie automatisch entpackt:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Apple-Ernte: Red Teaming von MacOS-Umgebungen im Jahr 2021 – Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Vorstellung von MacHound: Eine Lösung für Angriffe auf macOS mit Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature – Befehle zur Domain-Aufzählung (Äquivalente von dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Komm auf die dunkle Seite, wir haben Äpfel: macOS-Verwaltung für böswillige Zwecke nutzen](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: „Die Perspektive eines Angreifers auf Jamf-Konfigurationen“ – Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory-Erkennung mit einem Mac – its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Zertifikate für Geräteverwaltungsdienste und Geräte verwalten](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Konfigurationsprofile auf dem Mac verwenden](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Bereitstellen von Registrierungsprofilen für die Geräteverwaltung](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Paketdeklaration](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Pakete installieren](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identitäten](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
