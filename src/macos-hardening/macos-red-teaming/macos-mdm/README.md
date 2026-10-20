# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Weitere Informationen zu macOS-MDMs:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Grundlagen

### **MDM (Mobile Device Management) – Überblick**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) wird zur Verwaltung verschiedener Endgeräte wie Smartphones, Laptops und Tablets eingesetzt. Insbesondere auf den Plattformen von Apple (iOS, macOS, tvOS) umfasst es eine Reihe spezialisierter Funktionen, APIs und Verfahren. MDM basiert auf einem kompatiblen MDM-Server, der entweder kommerziell verfügbar oder Open Source ist und das [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) unterstützen muss. Wichtige Punkte:

- Zentralisierte Kontrolle über Geräte.
- Abhängigkeit von einem MDM-Server, der das MDM-Protokoll einhält.
- Der MDM-Server kann verschiedene Befehle an Geräte senden, beispielsweise zum Remote-Löschen von Daten oder zur Installation von Konfigurationen.

### **Grundlagen von DEP (Device Enrollment Program)**

Das von Apple angebotene [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereinfacht die Integration von Mobile Device Management (MDM), indem es eine Zero-Touch-Konfiguration für iOS-, macOS- und tvOS-Geräte ermöglicht. DEP automatisiert die Registrierung, sodass Geräte direkt nach dem Auspacken einsatzbereit sind und nur minimale Eingriffe durch Benutzer oder Administratoren benötigen. Wesentliche Aspekte:

- Geräte können sich bei der ersten Aktivierung automatisch bei einem vordefinierten MDM-Server registrieren.
- Besonders nützlich für fabrikneue Geräte, aber auch für Geräte, die neu konfiguriert werden.
- Ermöglicht eine unkomplizierte Einrichtung, sodass Geräte schnell für den Einsatz in einer Organisation bereit sind.

### **Sicherheitsaspekte**

Die einfache Registrierung durch DEP ist zwar nützlich, kann aber auch Sicherheitsrisiken mit sich bringen. Werden bei der MDM-Registrierung keine ausreichenden Schutzmaßnahmen erzwungen, könnten Angreifer diesen vereinfachten Prozess ausnutzen, um ihr Gerät beim MDM-Server der Organisation zu registrieren und sich dabei als Unternehmensgerät auszugeben.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Sicherheitswarnung**: Eine vereinfachte DEP-Registrierung könnte die unbefugte Registrierung von Geräten beim MDM-Server der Organisation ermöglichen, wenn keine geeigneten Schutzmaßnahmen vorhanden sind.

### Grundlagen: Was ist SCEP (Simple Certificate Enrolment Protocol)?

- Ein relativ altes Protokoll, das vor der weiten Verbreitung von TLS und HTTPS entwickelt wurde.
- Bietet Clients eine standardisierte Möglichkeit, einen **Certificate Signing Request** (CSR) zu senden, um ein Zertifikat zu erhalten. Der Client fordert den Server auf, ihm ein signiertes Zertifikat auszustellen.

### Was sind Configuration Profiles (auch mobileconfigs genannt)?

- Apples offizielle Methode zum **Festlegen und Erzwingen von Systemkonfigurationen**.
- Dateiformat, das mehrere Payloads enthalten kann.
- Basiert auf Property Lists (im XML-Format).
- „können signiert und verschlüsselt werden, um ihre Herkunft zu validieren, ihre Integrität sicherzustellen und ihren Inhalt zu schützen.“ *Basics* — Seite 70, *iOS Security Guide*, Januar 2018.

## Protokolle

### MDM

- Kombination aus APNs (**Apple-Servern**) und RESTful API (**MDM**-**Anbieterservern**)
- Die **Kommunikation** findet zwischen einem **Gerät** und einem Server statt, der einem **Geräteverwaltungsprodukt** zugeordnet ist.
- Vom MDM an das Gerät gesendete **Befehle** liegen in **plist-kodierten Dictionaries** vor.
- Alles läuft über **HTTPS**. MDM-Server können Zertifikat-Pinning verwenden und tun dies in der Regel auch.
- Apple stellt dem MDM-Anbieter ein **APNs-Zertifikat** zur Authentifizierung aus.

### DEP

- **3 APIs**: 1 für Reseller, 1 für MDM-Anbieter und 1 für die Geräteidentität (nicht dokumentiert):
  - Die sogenannte [DEP-„Cloud-Service“-API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM-Server verwenden sie, um DEP-Profile bestimmten Geräten zuzuordnen.
  - Die [DEP-API, die von autorisierten Apple-Resellern verwendet wird](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), um Geräte zu registrieren, den Registrierungsstatus zu prüfen und den Transaktionsstatus abzufragen.
  - Die undokumentierte private DEP-API. Apple-Geräte verwenden sie, um ihr DEP-Profil anzufordern. Unter macOS ist die Binärdatei `cloudconfigurationd` für die Kommunikation über diese API zuständig.
- Moderner und **JSON**-basiert (im Gegensatz zu plist)
- Apple stellt dem MDM-Anbieter ein **OAuth-Token** aus.

**DEP-„Cloud-Service“-API**

- RESTful
- Synchronisiert Gerätedatensätze von Apple zum MDM-Server.
- Synchronisiert „DEP-Profile“ vom MDM-Server zu Apple (Apple übermittelt sie später an das Gerät).
- Ein DEP-„Profil“ enthält:
  - URL des MDM-Anbieterservers
  - Zusätzliche vertrauenswürdige Zertifikate für die Server-URL (optionales Pinning)
  - Zusätzliche Einstellungen (z. B. welche Bildschirme im Setup Assistant übersprungen werden)

## Seriennummer

Apple-Geräte, die nach 2010 hergestellt wurden, haben im Allgemeinen **12-stellige alphanumerische** Seriennummern. Die **ersten drei Ziffern stehen für den Herstellungsort**, die folgenden **zwei** geben das **Herstellungsjahr** und die **Herstellungswoche** an, die nächsten **drei** Ziffern bilden eine **eindeutige Kennung** und die **letzten vier** Ziffern stehen für die **Modellnummer**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Schritte zur Registrierung und Verwaltung

1. Gerätedatensatz erstellen (Reseller, Apple): Der Datensatz für das neue Gerät wird erstellt.
2. Gerätedatensatz zuweisen (Kunde): Das Gerät wird einem MDM-Server zugewiesen.
3. Gerätedatensatz synchronisieren (MDM-Anbieter): Das MDM synchronisiert die Gerätedatensätze und übermittelt die DEP-Profile an Apple.
4. DEP-Check-in (Gerät): Das Gerät erhält sein DEP-Profil.
5. Profilabruf (Gerät)
6. Profilinstallation (Gerät), einschließlich MDM-, SCEP- und Root-CA-Payloads
7. MDM-Befehle ausgeben (Gerät)

![Seriennummer – Schritte zur Registrierung und Verwaltung: 7. MDM-Befehle ausgeben (Gerät)](<../../../images/image (694).png>)

Die Datei `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exportiert Funktionen, die als **übergeordnete „Schritte“** des Registrierungsprozesses betrachtet werden können.

### Schritt 4: DEP-Check-in – Aktivierungsdatensatz abrufen

Dieser Teil des Prozesses findet statt, wenn ein **Benutzer einen Mac zum ersten Mal startet** (oder nach einem vollständigen Löschen des Geräts).

![Schritte zur Registrierung und Verwaltung – Schritt 4: DEP-Check-in – Aktivierungsdatensatz abrufen: Dieser Teil des Prozesses findet statt, wenn ein Benutzer einen Mac zum ersten Mal startet (oder nach einem vollständigen...](<../../../images/image (1044).png>)

oder wenn `sudo profiles show -type enrollment` ausgeführt wird.

- Ermitteln, **ob das Gerät DEP-fähig ist**
- Aktivierungsdatensatz ist die interne Bezeichnung für das **DEP-„Profil“**.
- Beginnt, sobald das Gerät mit dem Internet verbunden ist.
- Wird durch **`CPFetchActivationRecord`** gesteuert.
- Wird über XPC von **`cloudconfigurationd`** implementiert. Der **„Setup Assistant“** (beim ersten Start des Geräts) oder der Befehl **`profiles`** kontaktiert diesen Daemon, um den Aktivierungsdatensatz abzurufen.
  - LaunchDaemon (läuft immer als root)

Zum Abrufen des Aktivierungsdatensatzes führt **`MCTeslaConfigurationFetcher`** mehrere Schritte aus. Dieser Prozess verwendet eine Verschlüsselung namens **Absinthe**<sup>[[1]](#references)</sup>.

1. **Zertifikat** abrufen
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Zustand anhand des Zertifikats **initialisieren** (**`NACInit`**)
   1. Verwendet verschiedene gerätespezifische Daten (d. h. **Seriennummer über `IOKit`**).
3. **Sitzungsschlüssel** abrufen
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Sitzung aufbauen (**`NACKeyEstablishment`**)
5. Anfrage senden
   1. POST an [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) mit den Daten `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. Die JSON-Payload wird mit Absinthe verschlüsselt (**`NACSign`**).
   3. Alle Anfragen laufen über HTTPS; integrierte Root-Zertifikate werden verwendet.

![Schritte zur Registrierung und Verwaltung – Schritt 4: DEP-Check-in – Aktivierungsdatensatz abrufen: 3. Alle Anfragen laufen über HTTPS; integrierte Root-Zertifikate werden verwendet](<../../../images/image (566) (1).png>)

Die Antwort ist ein JSON-Dictionary mit wichtigen Daten, darunter:

- **url**: URL des Hosts des MDM-Anbieters für das Aktivierungsprofil
- **anchor-certs**: Array von DER-Zertifikaten, die als vertrauenswürdige Anker verwendet werden

### **Schritt 5: Profilabruf**

![Schritt 4: DEP-Check-in – Aktivierungsdatensatz abrufen – Schritt 5: Profilabruf: Schritt 5: Profilabruf](<../../../images/image (444).png>)

- Die Anfrage wird an die **im DEP-Profil angegebene URL** gesendet.
- **Ankerzertifikate** werden, sofern vorhanden, zur **Bewertung der Vertrauenswürdigkeit** verwendet.
  - Zur Erinnerung: die Eigenschaft **anchor_certs** des DEP-Profils
- **Die Anfrage ist eine einfache .plist** mit Geräteidentifikationsdaten.
  - Beispiele: **UDID, Betriebssystemversion**
- CMS-signiert, DER-kodiert
- Mit dem **Geräteidentitätszertifikat (von APNS)** signiert
- Die **Zertifikatskette** enthält ein abgelaufenes **Apple iPhone Device CA**-Zertifikat.

![Schritt 4: DEP-Check-in – Aktivierungsdatensatz abrufen – Schritt 5: Profilabruf: Signiert mit dem Geräteidentitätszertifikat (von APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Schritt 6: Profilinstallation

- Nach dem Abruf wird **das Profil auf dem System gespeichert**.
- Dieser Schritt beginnt automatisch (wenn der **Setup Assistant** läuft).
- Wird durch **`CPInstallActivationProfile`** gesteuert.
- Wird von mdmclient über XPC implementiert.
  - LaunchDaemon (als root) oder LaunchAgent (als Benutzer), je nach Kontext
- Configuration Profiles enthalten mehrere zu installierende Payloads.
- Das Framework verwendet eine Plugin-basierte Architektur zur Installation von Profilen.
- Jeder Payload-Typ ist einem Plugin zugeordnet.
  - Kann XPC (im Framework) oder klassisches Cocoa (in ManagedClient.app) sein.
- Beispiel:
  - Certificate-Payloads verwenden CertificateService.xpc.

Ein **Aktivierungsprofil** eines MDM-Anbieters enthält typischerweise die folgenden Payloads:

- `com.apple.mdm`: um das Gerät beim MDM zu **registrieren**
- `com.apple.security.scep`: um dem Gerät sicher ein **Clientzertifikat** bereitzustellen
- `com.apple.security.pem`: um **vertrauenswürdige CA-Zertifikate** im System-Keychain des Geräts zu **installieren**
- Die Installation der MDM-Payload entspricht dem **MDM-Check-in in der Dokumentation**.
- Die Payload **enthält wichtige Eigenschaften**:
- - MDM-Check-in-URL (**`CheckInURL`**)
  - MDM-URL für den Befehlsabruf (**`ServerURL`**) + APNs-Topic, um diesen auszulösen
- Zur Installation der MDM-Payload wird eine Anfrage an **`CheckInURL`** gesendet.
- Wird in **`mdmclient`** implementiert.
- Die MDM-Payload kann von anderen Payloads abhängig sein.
- Ermöglicht das **Pinnen von Anfragen auf bestimmte Zertifikate**:
  - Eigenschaft: **`CheckInURLPinningCertificateUUIDs`**
  - Eigenschaft: **`ServerURLPinningCertificateUUIDs`**
  - Wird über eine PEM-Payload bereitgestellt.
- Ermöglicht, dem Gerät ein Identitätszertifikat zuzuordnen:
  - Eigenschaft: IdentityCertificateUUID
  - Wird über eine SCEP-Payload bereitgestellt.

### **Schritt 7: Auf MDM-Befehle warten**

- Sobald der MDM-Check-in abgeschlossen ist, kann der Anbieter **Push-Benachrichtigungen über APNs senden**.
- Nach Eingang werden sie von **`mdmclient`** verarbeitet.
- Zum Abrufen von MDM-Befehlen wird eine Anfrage an ServerURL gesendet.
- Dabei wird die zuvor installierte MDM-Payload verwendet:
  - **`ServerURLPinningCertificateUUIDs`** zum Pinnen der Anfrage
  - **`IdentityCertificateUUID`** für das TLS-Clientzertifikat

## Angriffe

### Geräte bei anderen Organisationen registrieren

Eine zugewiesene Seriennummer kann den Registrierungspfad einer Organisation erkennen lassen, garantiert aber **keine** MDM-Registrierung. Der Server kann eine Benutzerauthentifizierung über `configuration_web_url` verlangen, bevor er das Registrierungsprofil zurückgibt. Prüfen Sie, ob ein alternativer Registrierungspfad diese Prüfung auslässt, anstatt davon auszugehen, dass jede zugewiesene Seriennummer dem Gerätebestand hinzugefügt werden kann.<sup>[[3]](#references)</sup>

Für einen Rogue-Enrollment-Workflow verwenden Sie die unten verlinkte Seite. Informationen zur MDM-Kontrolle und Paketzustellung nach einer Kompromittierung finden Sie unter [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Ein tiefer Einblick in macOS MDM (und wie es kompromittiert werden kann)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — „MDM Me Maybe?“ (Sicherheitsforschung zu DEP-/MDM-Registrierungen)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Authentifizierung über Webansichten](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
