# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Informationen zu macOS MDMs findest du hier:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Grundlagen

### **Überblick über MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) wird zur Verwaltung verschiedener Endgeräte wie Smartphones, Laptops und Tablets eingesetzt. Insbesondere für die Plattformen von Apple (iOS, macOS, tvOS) umfasst es eine Reihe spezialisierter Funktionen, APIs und Verfahren. Der Betrieb von MDM basiert auf einem kompatiblen MDM-Server, der entweder kommerziell verfügbar oder Open Source ist und das [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) unterstützen muss. Wichtige Punkte sind:

- Zentrale Kontrolle über Geräte.
- Abhängigkeit von einem MDM-Server, der dem MDM-Protokoll entspricht.
- Der MDM-Server kann verschiedene Befehle an Geräte senden, beispielsweise das Remote-Löschen von Daten oder die Installation von Konfigurationen.

### **Grundlagen von DEP (Device Enrollment Program)**

Das von Apple angebotene [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereinfacht die Integration von Mobile Device Management (MDM), indem es eine Zero-Touch-Konfiguration für iOS-, macOS- und tvOS-Geräte ermöglicht. DEP automatisiert den Enrollment-Prozess, sodass Geräte direkt nach dem Auspacken mit minimalem Eingreifen durch Benutzer oder Administratoren einsatzbereit sind. Zu den wesentlichen Aspekten gehören:

- Geräte können sich bei der ersten Aktivierung automatisch bei einem vordefinierten MDM-Server registrieren.
- Primär für brandneue Geräte gedacht, aber auch auf Geräte anwendbar, die neu konfiguriert werden.
- Ermöglicht eine unkomplizierte Einrichtung, sodass Geräte schnell für die Verwendung in der Organisation bereitstehen.

### **Sicherheitsaspekte**

Es ist wichtig zu beachten, dass die durch DEP erleichterte Registrierung zwar vorteilhaft ist, aber auch Sicherheitsrisiken bergen kann. Wenn beim MDM-Enrollment keine ausreichenden Schutzmaßnahmen erzwungen werden, könnten Angreifer diesen optimierten Prozess ausnutzen, um ihr Gerät beim MDM-Server der Organisation zu registrieren und sich dabei als Unternehmensgerät auszugeben.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Sicherheitswarnung**: Ein vereinfachtes DEP-Enrollment könnte die unbefugte Registrierung eines Geräts beim MDM-Server der Organisation ermöglichen, wenn keine geeigneten Schutzmaßnahmen vorhanden sind.

### Grundlagen: Was ist SCEP (Simple Certificate Enrolment Protocol)?

- Ein relativ altes Protokoll, das entwickelt wurde, bevor TLS und HTTPS weit verbreitet waren.
- Bietet Clients eine standardisierte Möglichkeit, eine **Certificate Signing Request** (CSR) zu senden, um ein Zertifikat zu erhalten. Der Client bittet den Server, ihm ein signiertes Zertifikat auszustellen.

### Was sind Configuration Profiles (auch mobileconfigs genannt)?

- Apples offizielle Möglichkeit zum **Festlegen und Erzwingen von Systemkonfigurationen.**
- Dateiformat, das mehrere Payloads enthalten kann.
- Basiert auf Property Lists (im XML-Format).
- „can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.“ Basics — Page 70, iOS Security Guide, January 2018.

## Protokolle

### MDM

- Kombination aus APNs (**Apple-Servern**) + RESTful API (**MDM**-**Vendor**-Servern)
- Die **Kommunikation** findet zwischen einem **Gerät** und einem Server statt, der einem **Geräte**-**Management**-**Produkt** zugeordnet ist.
- Vom MDM an das Gerät gesendete **Befehle** werden in **plist-kodierten Dictionaries** übertragen.
- Alles über **HTTPS**. MDM-Server können (und werden normalerweise) gepinnt.
- Apple stellt dem MDM-Vendor ein **APNs-Zertifikat** zur Authentifizierung aus.

### DEP

- **3 APIs**: 1 für Reseller, 1 für MDM-Vendoren, 1 für die Geräteidentität (undokumentiert):
- Die sogenannte [DEP-„Cloud-Service“-API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Sie wird von MDM-Servern verwendet, um DEP-Profile bestimmten Geräten zuzuordnen.
- Die [DEP-API, die von autorisierten Apple-Resellern verwendet wird](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), um Geräte zu registrieren, den Enrollment-Status zu prüfen und den Transaktionsstatus zu überprüfen.
- Die undokumentierte private DEP-API. Sie wird von Apple-Geräten verwendet, um ihr DEP-Profil anzufordern. Unter macOS ist das Binary `cloudconfigurationd` für die Kommunikation über diese API verantwortlich.
- Moderner und **JSON**-basiert (im Gegensatz zu **plist**)
- Apple stellt dem MDM-Vendor ein **OAuth-Token** aus.

**DEP-„Cloud-Service“-API**

- RESTful
- Synchronisiert Gerätedatensätze von Apple mit dem MDM-Server.
- Synchronisiert „DEP-Profile“ vom MDM-Server zu Apple (und später von Apple zum Gerät übertragen).
- Ein DEP-„Profil“ enthält:
- URL des MDM-Vendor-Servers
- Zusätzliche vertrauenswürdige Zertifikate für die Server-URL (optionales Pinning)
- Zusätzliche Einstellungen (z. B. welche Bildschirme im Setup Assistant übersprungen werden sollen)

## Seriennummer

Apple-Geräte, die nach 2010 hergestellt wurden, besitzen im Allgemeinen **alphanumerische Seriennummern mit 12 Zeichen**. Die **ersten drei Zeichen geben den Herstellungsort an**, die folgenden **zwei das Herstellungsjahr** und die **Herstellungswoche**, die nächsten **drei Zeichen einen **eindeutigen** **Identifier**, und die **letzten** **vier Zeichen die Modellnummer**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Schritte für Enrollment und Management

1. Erstellung des Gerätedatensatzes (Reseller, Apple): Der Datensatz für das neue Gerät wird erstellt.
2. Zuweisung des Gerätedatensatzes (Kunde): Das Gerät wird einem MDM-Server zugewiesen.
3. Synchronisierung des Gerätedatensatzes (MDM-Vendor): Der MDM synchronisiert die Gerätedatensätze und überträgt die DEP-Profile zu Apple.
4. DEP-Check-in (Gerät): Das Gerät erhält sein DEP-Profil.
5. Abruf des Profils (Gerät)
6. Installation des Profils (Gerät), einschließlich MDM-, SCEP- und Root-CA-Payloads
7. Ausgabe von MDM-Befehlen (Gerät)

![Seriennummer – Schritte für Enrollment und Management: 7. Ausgabe von MDM-Befehlen (Gerät)](<../../../images/image (694).png>)

Die Datei `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exportiert Funktionen, die als **„High-Level-Schritte“** des Enrollment-Prozesses betrachtet werden können.

### Schritt 4: DEP-Check-in – Abrufen des Activation Record

Dieser Teil des Prozesses findet statt, wenn ein **Benutzer einen Mac zum ersten Mal startet** (oder nach einem vollständigen Löschen)

![Schritte für Enrollment und Management – Schritt 4: DEP-Check-in – Abrufen des Activation Record: Dieser Teil des Prozesses findet statt, wenn ein Benutzer einen Mac zum ersten Mal startet (oder nach einem vollständigen...](<../../../images/image (1044).png>)

oder wenn `sudo profiles show -type enrollment` ausgeführt wird.

- Ermittelt, **ob das Gerät DEP aktiviert hat**.
- Activation Record ist die interne Bezeichnung für das **DEP-„Profil“**.
- Beginnt, sobald das Gerät mit dem Internet verbunden ist.
- Wird durch **`CPFetchActivationRecord`** gesteuert.
- Wird über XPC von **`cloudconfigurationd`** implementiert. Der **„Setup Assistant**“ (wenn das Gerät erstmals gestartet wird) oder der Befehl **`profiles`** kontaktiert diesen Daemon, um den Activation Record abzurufen.
- LaunchDaemon (wird immer als Root ausgeführt)

Der Activation Record wird in einigen von **`MCTeslaConfigurationFetcher`** ausgeführten Schritten abgerufen. Dieser Prozess verwendet eine Verschlüsselung namens **Absinthe**<sup>[[1]](#references)</sup>

1. **Zertifikat** abrufen
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Zustand aus dem Zertifikat **initialisieren** (**`NACInit`**)
1. Verwendet verschiedene gerätespezifische Daten (z. B. die **Seriennummer über `IOKit`**)
3. **Session-Key** abrufen
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session aufbauen (**`NACKeyEstablishment`**)
5. Anfrage senden
1. POST an [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), wobei die Daten `{ "action": "RequestProfileConfiguration", "sn": "" }` gesendet werden.
2. Der JSON-Payload wird mit Absinthe verschlüsselt (**`NACSign`**).
3. Alle Anfragen erfolgen über HTTPs; integrierte Root-Zertifikate werden verwendet.

![Schritte für Enrollment und Management – Schritt 4: DEP-Check-in – Abrufen des Activation Record: 3. Alle Anfragen erfolgen über HTTPs; integrierte Root-Zertifikate werden verwendet](<../../../images/image (566) (1).png>)

Die Antwort ist ein JSON-Dictionary mit einigen wichtigen Daten, darunter:

- **url**: URL des MDM-Vendor-Hosts für das Activation Profile
- **anchor-certs**: Array von DER-Zertifikaten, die als vertrauenswürdige Anker verwendet werden

### **Schritt 5: Abrufen des Profils**

![Schritt 4: DEP-Check-in – Abrufen des Activation Record – Schritt 5: Abrufen des Profils: Schritt 5: Abrufen des Profils](<../../../images/image (444).png>)

- Anfrage wird an die **im DEP-Profil angegebene URL** gesendet.
- **Anchor-Zertifikate** werden verwendet, um das **Vertrauen zu bewerten**, sofern sie angegeben sind.
- Erinnerung: die Eigenschaft **anchor_certs** des DEP-Profils
- **Anfrage ist ein einfaches .plist** mit Geräteidentifikationsdaten.
- Beispiele: **UDID, Betriebssystemversion**.
- CMS-signiert, DER-kodiert
- Signiert mit dem **Geräteidentitätszertifikat (von APNS)**
- **Zertifikatskette** enthält die abgelaufene **Apple iPhone Device CA**

![Schritt 4: DEP-Check-in – Abrufen des Activation Record – Schritt 5: Abrufen des Profils: Signiert mit dem Geräteidentitätszertifikat (von APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Schritt 6: Installation des Profils

- Nach dem Abruf wird das **Profil auf dem System gespeichert**.
- Dieser Schritt beginnt automatisch (wenn der **Setup Assistant** ausgeführt wird).
- Wird durch **`CPInstallActivationProfile`** gesteuert.
- Wird von mdmclient über XPC implementiert.
- LaunchDaemon (als Root) oder LaunchAgent (als Benutzer), abhängig vom Kontext.
- Configuration Profiles enthalten mehrere zu installierende Payloads.
- Das Framework besitzt eine Plugin-basierte Architektur zur Installation von Profilen.
- Jeder Payload-Typ ist einem Plugin zugeordnet.
- Kann XPC (im Framework) oder klassisches Cocoa (in ManagedClient.app) sein.
- Beispiel:
- Certificate Payloads verwenden CertificateService.xpc.

Typischerweise enthält ein von einem MDM-Vendor bereitgestelltes **Activation Profile** die folgenden Payloads:

- `com.apple.mdm`: um das Gerät im MDM zu **registrieren**
- `com.apple.security.scep`: um dem Gerät sicher ein **Client-Zertifikat** bereitzustellen.
- `com.apple.security.pem`: um vertrauenswürdige CA-Zertifikate im System-Keychain des Geräts zu **installieren**.
- Die Installation des MDM-Payloads entspricht dem **MDM-Check-in in der Dokumentation**.
- Der Payload **enthält wichtige Eigenschaften**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs-Topic zum Auslösen
- Zur Installation des MDM-Payloads wird eine Anfrage an **`CheckInURL`** gesendet.
- Wird in **`mdmclient`** implementiert.
- Der MDM-Payload kann von anderen Payloads abhängen.
- Ermöglicht das **Pinnen von Anfragen auf bestimmte Zertifikate**:
- Eigenschaft: **`CheckInURLPinningCertificateUUIDs`**
- Eigenschaft: **`ServerURLPinningCertificateUUIDs`**
- Wird über einen PEM-Payload bereitgestellt.
- Ermöglicht die Zuordnung einer Identität zu einem Gerät mittels Identitätszertifikat:
- Eigenschaft: IdentityCertificateUUID
- Wird über einen SCEP-Payload bereitgestellt.

### **Schritt 7: Auf MDM-Befehle warten**

- Nach Abschluss des MDM-Check-ins kann der Vendor **Push-Benachrichtigungen über APNs senden**.
- Nach deren Empfang werden sie von **`mdmclient`** verarbeitet.
- Um MDM-Befehle abzurufen, wird eine Anfrage an ServerURL gesendet.
- Verwendet den zuvor installierten MDM-Payload:
- **`ServerURLPinningCertificateUUIDs`** zum Pinnen der Anfrage
- **`IdentityCertificateUUID`** für das TLS-Client-Zertifikat

## Angriffe

### Registrieren von Geräten in anderen Organisationen

Wie bereits erwähnt, wird zum Versuch, ein Gerät bei einer Organisation zu registrieren, **nur eine Seriennummer benötigt, die zu dieser Organisation gehört**. Sobald das Gerät registriert ist, installieren mehrere Organisationen vertrauliche Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WLAN-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Enrollment-Prozess nicht korrekt geschützt ist:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referenzen

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
