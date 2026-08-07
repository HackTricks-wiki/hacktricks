# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Informationen zu macOS-MDMs findest du hier:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Grundlagen

### **Übersicht über MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) wird zur Verwaltung verschiedener Endgeräte wie Smartphones, Laptops und Tablets eingesetzt. Insbesondere bei den Plattformen von Apple (iOS, macOS, tvOS) umfasst es eine Reihe spezialisierter Funktionen, APIs und Verfahren. Der Betrieb von MDM basiert auf einem kompatiblen MDM-Server, der entweder kommerziell verfügbar oder Open Source ist und das [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) unterstützen muss. Die wichtigsten Punkte sind:

- Zentralisierte Kontrolle über Geräte.
- Abhängigkeit von einem MDM-Server, der das MDM-Protokoll einhält.
- Möglichkeit des MDM-Servers, verschiedene Befehle an Geräte zu senden, beispielsweise zum Remote-Löschen von Daten oder zur Installation von Konfigurationen.

### **Grundlagen von DEP (Device Enrollment Program)**

Das von Apple angebotene [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereinfacht die Integration von Mobile Device Management (MDM), indem es eine Zero-Touch-Konfiguration für iOS-, macOS- und tvOS-Geräte ermöglicht. DEP automatisiert den Enrollment-Prozess, sodass Geräte direkt nach dem Auspacken betriebsbereit sind und nur minimale Eingriffe durch Benutzer oder Administratoren erfordern. Zu den wesentlichen Aspekten gehören:

- Ermöglicht Geräten, sich bei der ersten Aktivierung selbstständig bei einem vordefinierten MDM-Server zu registrieren.
- Vor allem für brandneue Geräte nützlich, aber auch auf Geräte anwendbar, die neu konfiguriert werden.
- Ermöglicht eine unkomplizierte Einrichtung, sodass Geräte schnell für die organisatorische Nutzung bereitstehen.

### **Sicherheitsaspekte**

Es ist wichtig zu beachten, dass die durch DEP bereitgestellte einfache Enrollment-Möglichkeit zwar vorteilhaft ist, aber auch Sicherheitsrisiken bergen kann. Wenn beim MDM-Enrollment keine ausreichenden Schutzmaßnahmen durchgesetzt werden, könnten Angreifer diesen vereinfachten Prozess ausnutzen, um ihr Gerät beim MDM-Server der Organisation zu registrieren und sich als Unternehmensgerät auszugeben.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Sicherheitswarnung**: Ein vereinfachtes DEP-Enrollment könnte die unbefugte Registrierung eines Geräts beim MDM-Server der Organisation ermöglichen, wenn keine geeigneten Schutzmaßnahmen vorhanden sind.

### Grundlagen: Was ist SCEP (Simple Certificate Enrolment Protocol)?

- Ein relativ altes Protokoll, das entwickelt wurde, bevor TLS und HTTPS weit verbreitet waren.
- Bietet Clients eine standardisierte Möglichkeit, eine **Certificate Signing Request** (CSR) zu senden, um ein Zertifikat zu erhalten. Der Client fordert den Server auf, ihm ein signiertes Zertifikat auszustellen.

### Was sind Configuration Profiles (auch mobileconfigs genannt)?

- Apples offizielle Methode zum **Festlegen und Durchsetzen von Systemkonfigurationen.**
- Dateiformat, das mehrere Payloads enthalten kann.
- Basiert auf Property Lists (im XML-Format).
- „can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.“ Basics — Page 70, iOS Security Guide, January 2018.

## Protokolle

### MDM

- Kombination aus APNs (**Apple-Servern**) + RESTful API (**MDM**-**Anbieter**-Server)
- Die **Kommunikation** erfolgt zwischen einem **Gerät** und einem Server, der einem **Geräte**-**Management**-**Produkt** zugeordnet ist.
- Vom MDM an das Gerät gesendete **Befehle** werden in **plist-kodierten Dictionaries** übertragen.
- Alles über **HTTPS**. MDM-Server können per Certificate Pinning abgesichert sein und sind es normalerweise auch.
- Apple stellt dem MDM-Anbieter ein **APNs-Zertifikat** zur Authentifizierung aus.

### DEP

- **3 APIs**: 1 für Reseller, 1 für MDM-Anbieter, 1 für die Geräteidentität (undokumentiert):
- Die sogenannte [DEP-"Cloud-Service"-API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Sie wird von MDM-Servern verwendet, um DEP-Profile bestimmten Geräten zuzuordnen.
- Die [DEP API für Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), um Geräte zu enrollen, den Enrollment-Status zu prüfen und den Transaktionsstatus zu überprüfen.
- Die undokumentierte private DEP API. Sie wird von Apple-Geräten verwendet, um ihr DEP-Profil anzufordern. Unter macOS ist die Binärdatei `cloudconfigurationd` für die Kommunikation über diese API zuständig.
- Moderner und auf **JSON** basierend (im Gegensatz zu **plist**).
- Apple stellt dem MDM-Anbieter ein **OAuth-Token** aus.

**DEP-"Cloud-Service"-API**

- RESTful
- Synchronisiert Gerätedatensätze von Apple mit dem MDM-Server.
- Synchronisiert „DEP-Profile“ vom MDM-Server mit Apple (sie werden später von Apple an das Gerät übertragen).
- Ein DEP-„Profil“ enthält:
- URL des MDM-Anbieter-Servers
- Zusätzliche vertrauenswürdige Zertifikate für die Server-URL (optionales Pinning)
- Zusätzliche Einstellungen (z. B. welche Bildschirme im Setup Assistant übersprungen werden sollen)

## Seriennummer

Apple-Geräte, die nach 2010 hergestellt wurden, verfügen im Allgemeinen über **12-stellige alphanumerische** Seriennummern. Die **ersten drei Ziffern geben den Herstellungsort an**, die folgenden **zwei** das **Jahr** und die **Kalenderwoche** der Herstellung, die nächsten **drei** Ziffern einen **eindeutigen** **Identifikator** und die **letzten** **vier** Ziffern die **Modellnummer**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Schritte für Enrollment und Management

1. Erstellung des Gerätedatensatzes (Reseller, Apple): Der Datensatz für das neue Gerät wird erstellt.
2. Zuweisung des Gerätedatensatzes (Kunde): Das Gerät wird einem MDM-Server zugewiesen.
3. Synchronisierung des Gerätedatensatzes (MDM-Anbieter): Der MDM synchronisiert die Gerätedatensätze und überträgt die DEP-Profile an Apple.
4. DEP-Check-in (Gerät): Das Gerät erhält sein DEP-Profil.
5. Abruf des Profils (Gerät)
6. Installation des Profils (Gerät), einschließlich MDM-, SCEP- und Root-CA-Payloads
7. Ausstellung von MDM-Befehlen (Gerät)

![Seriennummer – Schritte für Enrollment und Management: 7. Ausstellung von MDM-Befehlen (Gerät)](<../../../images/image (694).png>)

Die Datei `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exportiert Funktionen, die als **übergeordnete „Schritte“** des Enrollment-Prozesses betrachtet werden können.

### Schritt 4: DEP-Check-in – Abrufen des Activation Record

Dieser Teil des Prozesses findet statt, wenn ein **Benutzer einen Mac zum ersten Mal startet** (oder nach einer vollständigen Löschung).

![Schritte für Enrollment und Management – Schritt 4: DEP-Check-in – Abrufen des Activation Record: Dieser Teil des Prozesses findet statt, wenn ein Benutzer einen Mac zum ersten Mal startet oder nach einer vollständigen...](<../../../images/image (1044).png>)

oder beim Ausführen von `sudo profiles show -type enrollment`

- Ermittelt, **ob das Gerät DEP-aktiviert ist**.
- Activation Record ist die interne Bezeichnung für das **DEP-„Profil“**.
- Beginnt, sobald das Gerät mit dem Internet verbunden ist.
- Wird durch **`CPFetchActivationRecord`** gesteuert.
- Wird von **`cloudconfigurationd`** über XPC implementiert. Der **„Setup Assistant**“ (beim ersten Start des Geräts) oder der Befehl **`profiles`** kontaktiert diesen Daemon, um den Activation Record abzurufen.
- LaunchDaemon (läuft immer als root).

Zum Abrufen des Activation Record werden einige Schritte von **`MCTeslaConfigurationFetcher`** ausgeführt. Dieser Prozess verwendet eine Verschlüsselung namens **Absinthe**<sup>[[1]](#references)</sup>

1. **Zertifikat** abrufen
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Zustand anhand des Zertifikats **initialisieren** (**`NACInit`**)
1. Verwendet verschiedene gerätespezifische Daten (z. B. **Seriennummer über `IOKit`**)
3. **Session-Key** abrufen
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session herstellen (**`NACKeyEstablishment`**)
5. Anfrage senden
1. POST an [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), wobei die Daten `{ "action": "RequestProfileConfiguration", "sn": "" }` gesendet werden.
2. Die JSON-Payload wird mit Absinthe verschlüsselt (**`NACSign`**).
3. Alle Anfragen erfolgen über HTTPs; integrierte Root-Zertifikate werden verwendet.

![Schritte für Enrollment und Management – Schritt 4: DEP-Check-in – Abrufen des Activation Record: 3. Alle Anfragen erfolgen über HTTPs; integrierte Root-Zertifikate werden verwendet](<../../../images/image (566) (1).png>)

Die Antwort ist ein JSON-Dictionary mit wichtigen Daten wie:

- **url**: URL des MDM-Anbieterhosts für das Activation Profile
- **anchor-certs**: Array von DER-Zertifikaten, die als vertrauenswürdige Anker verwendet werden

### **Schritt 5: Abrufen des Profils**

![Schritt 4: DEP-Check-in – Abrufen des Activation Record – Schritt 5: Abrufen des Profils: Schritt 5: Abrufen des Profils](<../../../images/image (444).png>)

- Die Anfrage wird an die im DEP-Profil angegebene **url** gesendet.
- **Anchor-Zertifikate** werden zur **Vertrauensbewertung** verwendet, sofern sie angegeben sind.
- Zur Erinnerung: die Eigenschaft **anchor_certs** des DEP-Profils.
- **Die Anfrage ist ein einfaches .plist** mit der Geräteidentifikation.
- Beispiele: **UDID, Betriebssystemversion**.
- CMS-signiert, DER-kodiert
- Signiert mit dem **Geräteidentitätszertifikat (von APNS)**.
- Die **Zertifikatskette** enthält die abgelaufene **Apple iPhone Device CA**.

![Schritt 4: DEP-Check-in – Abrufen des Activation Record – Schritt 5: Abrufen des Profils: Signiert mit dem Geräteidentitätszertifikat (von APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Schritt 6: Installation des Profils

- Nach dem Abruf wird das **Profil auf dem System gespeichert**.
- Dieser Schritt beginnt automatisch (wenn der **Setup Assistant** aktiv ist).
- Wird durch **`CPInstallActivationProfile`** gesteuert.
- Wird von mdmclient über XPC implementiert.
- LaunchDaemon (als root) oder LaunchAgent (als Benutzer), abhängig vom Kontext.
- Configuration Profiles enthalten mehrere zu installierende Payloads.
- Das Framework verfügt über eine pluginbasierte Architektur zur Installation von Profilen.
- Jeder Payload-Typ ist einem Plugin zugeordnet.
- Kann XPC (im Framework) oder klassisches Cocoa (in ManagedClient.app) sein.
- Beispiel:
- Certificate Payloads verwenden CertificateService.xpc.

Typischerweise enthält das von einem MDM-Anbieter bereitgestellte **Activation Profile** die folgenden Payloads:

- `com.apple.mdm`: zum **Enrollen** des Geräts in MDM
- `com.apple.security.scep`: zur sicheren Bereitstellung eines **Client-Zertifikats** für das Gerät.
- `com.apple.security.pem`: zur **Installation vertrauenswürdiger CA-Zertifikate** im System-Keychain des Geräts.
- Die Installation des MDM-Payloads entspricht dem **MDM-Check-in in der Dokumentation**.
- Der Payload **enthält wichtige Eigenschaften**:
- - MDM-Check-in-URL (**`CheckInURL`**)
- MDM-Command-Polling-URL (**`ServerURL`**) + APNs-Topic zu dessen Auslösung
- Zur Installation des MDM-Payloads wird eine Anfrage an **`CheckInURL`** gesendet.
- Implementiert in **`mdmclient`**.
- Der MDM-Payload kann von anderen Payloads abhängig sein.
- Ermöglicht das **Pinnen von Anfragen an bestimmte Zertifikate**:
- Eigenschaft: **`CheckInURLPinningCertificateUUIDs`**
- Eigenschaft: **`ServerURLPinningCertificateUUIDs`**
- Wird über einen PEM-Payload bereitgestellt.
- Ermöglicht die Zuordnung einer Identitätszertifikats zu einem Gerät:
- Eigenschaft: IdentityCertificateUUID
- Wird über einen SCEP-Payload bereitgestellt.

### **Schritt 7: Auf MDM-Befehle warten**

- Nach Abschluss des MDM-Check-ins kann der Anbieter **Push-Benachrichtigungen über APNs senden**.
- Nach deren Eingang werden sie von **`mdmclient`** verarbeitet.
- Um MDM-Befehle abzurufen, wird eine Anfrage an ServerURL gesendet.
- Verwendet den zuvor installierten MDM-Payload:
- **`ServerURLPinningCertificateUUIDs`** zum Pinnen der Anfrage.
- **`IdentityCertificateUUID`** für das TLS-Clientzertifikat.

## Angriffe

### Enrollen von Geräten bei anderen Organisationen

Wie bereits erwähnt, wird zum Versuch, ein Gerät bei einer Organisation zu enrollen, **nur eine Seriennummer benötigt, die zu dieser Organisation gehört**. Nach dem Enrollment installieren mehrere Organisationen vertrauliche Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WLAN-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Enrollment-Prozess nicht korrekt geschützt ist:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referenzen

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
