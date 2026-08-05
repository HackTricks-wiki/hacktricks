# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Informationen zu macOS-MDMs finden Sie hier:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Grundlagen

### **Überblick über MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) wird zur Verwaltung verschiedener Endgeräte wie Smartphones, Laptops und Tablets eingesetzt. Insbesondere für die Plattformen von Apple (iOS, macOS, tvOS) umfasst es eine Reihe spezialisierter Funktionen, APIs und Verfahren. Der Betrieb von MDM basiert auf einem kompatiblen MDM-Server, der entweder kommerziell verfügbar oder Open Source ist und das [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) unterstützen muss. Zu den wichtigsten Punkten gehören:

- Zentrale Kontrolle über Geräte.
- Abhängigkeit von einem MDM-Server, der dem MDM-Protokoll entspricht.
- Fähigkeit des MDM-Servers, verschiedene Befehle an Geräte zu senden, beispielsweise zum Remote-Löschen von Daten oder zur Installation von Konfigurationen.

### **Grundlagen von DEP (Device Enrollment Program)**

Das von Apple angebotene [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereinfacht die Integration von Mobile Device Management (MDM), indem es eine Zero-Touch-Konfiguration für iOS-, macOS- und tvOS-Geräte ermöglicht. DEP automatisiert den Enrolment-Prozess, sodass Geräte direkt nach dem Auspacken einsatzbereit sind und nur minimale Eingriffe durch Benutzer oder Administratoren benötigen. Wesentliche Aspekte sind:

- Ermöglicht Geräten, sich bei der erstmaligen Aktivierung selbstständig bei einem vordefinierten MDM-Server zu registrieren.
- Primär für brandneue Geräte geeignet, aber auch auf Geräte anwendbar, die neu konfiguriert werden.
- Ermöglicht eine unkomplizierte Einrichtung, sodass Geräte schnell für die organisatorische Nutzung bereit sind.

### **Sicherheitsaspekte**

Es ist wichtig zu beachten, dass die durch DEP bereitgestellte einfache Registrierung zwar vorteilhaft ist, aber auch Sicherheitsrisiken bergen kann. Wenn beim MDM-Enrolment keine ausreichenden Schutzmaßnahmen erzwungen werden, könnten Angreifer diesen vereinfachten Prozess ausnutzen, um ihr Gerät beim MDM-Server der Organisation zu registrieren und sich als Unternehmensgerät auszugeben.<sup>[2]</sup>

> [!CAUTION]
> **Sicherheitswarnung**: Eine vereinfachte DEP-Registrierung könnte die unbefugte Registrierung eines Geräts beim MDM-Server der Organisation ermöglichen, wenn keine geeigneten Schutzmaßnahmen vorhanden sind.

### Grundlagen: Was ist SCEP (Simple Certificate Enrolment Protocol)?

- Ein relativ altes Protokoll, das entwickelt wurde, bevor TLS und HTTPS weit verbreitet waren.
- Bietet Clients eine standardisierte Möglichkeit, eine **Certificate Signing Request** (CSR) zu senden, um ein Zertifikat zu erhalten. Der Client fordert den Server auf, ihm ein signiertes Zertifikat auszustellen.

### Was sind Configuration Profiles (auch mobileconfigs genannt)?

- Apples offizielle Methode zum **Festlegen und Erzwingen der Systemkonfiguration.**
- Dateiformat, das mehrere Payloads enthalten kann.
- Basiert auf Property Lists (im XML-Format).
- „can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.“ Basics — Page 70, iOS Security Guide, January 2018.

## Protokolle

### MDM

- Kombination aus APNs (**Apple-Servern**) + RESTful API (**MDM-** **Vendor**-Servern)
- Die **Kommunikation** findet zwischen einem **Gerät** und einem Server statt, der einem **Geräte-** **Management-** **Produkt** zugeordnet ist.
- Vom MDM an das Gerät gesendete **Befehle** werden in **plist-kodierten Dictionaries** übertragen.
- Alles über **HTTPS**. MDM-Server können (und werden üblicherweise) gepinnt.
- Apple stellt dem MDM-Vendor ein **APNs-Zertifikat** zur Authentifizierung aus.

### DEP

- **3 APIs**: 1 für Reseller, 1 für MDM-Vendoren und 1 für die Geräteidentität (undokumentiert):
- Die sogenannte [DEP-„Cloud-Service“-API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Sie wird von MDM-Servern verwendet, um DEP-Profile bestimmten Geräten zuzuordnen.
- Die [von Apple Authorized Resellers verwendete DEP-API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), um Geräte zu registrieren, den Registrierungsstatus zu überprüfen und den Transaktionsstatus abzufragen.
- Die undokumentierte private DEP-API. Sie wird von Apple-Geräten verwendet, um ihr DEP-Profil anzufordern. Unter macOS ist die Binärdatei `cloudconfigurationd` für die Kommunikation über diese API zuständig.
- Moderner und auf **JSON** basierend (im Gegensatz zu **plist**).
- Apple stellt dem MDM-Vendor ein **OAuth-Token** aus.

**DEP-„Cloud-Service“-API**

- RESTful
- Synchronisiert Gerätedatensätze von Apple zum MDM-Server.
- Synchronisiert „DEP-Profile“ vom MDM-Server zu Apple (sie werden später von Apple an das Gerät übermittelt).
- Ein DEP-„Profil“ enthält:
- URL des MDM-Vendor-Servers
- Zusätzliche vertrauenswürdige Zertifikate für die Server-URL (optionales Pinning)
- Zusätzliche Einstellungen (z. B. welche Bildschirme im Setup Assistant übersprungen werden sollen)

## Seriennummer

Apple-Geräte, die nach 2010 hergestellt wurden, besitzen im Allgemeinen **12-stellige alphanumerische** Seriennummern. Die **ersten drei Ziffern geben den Herstellungsort an**, die folgenden **zwei** das **Herstellungsjahr** und die **Herstellungswoche**, die nächsten **drei** Ziffern einen **eindeutigen** **Identifier** und die **letzten** **vier** Ziffern die **Modellnummer**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Schritte für Enrolment und Management

1. Erstellung des Gerätedatensatzes (Reseller, Apple): Der Datensatz für das neue Gerät wird erstellt.
2. Zuweisung des Gerätedatensatzes (Kunde): Das Gerät wird einem MDM-Server zugewiesen.
3. Synchronisierung des Gerätedatensatzes (MDM-Vendor): Der MDM synchronisiert die Gerätedatensätze und überträgt die DEP-Profile an Apple.
4. DEP-Check-in (Gerät): Das Gerät erhält sein DEP-Profil.
5. Abruf des Profils (Gerät)
6. Installation des Profils (Gerät), einschließlich MDM-, SCEP- und Root-CA-Payloads
7. Ausgabe von MDM-Befehlen (Gerät)

![Seriennummer – Schritte für Enrolment und Management: 7. Ausgabe von MDM-Befehlen (Gerät)](<../../../images/image (694).png>)

Die Datei `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exportiert Funktionen, die als **höherstufige „Schritte“** des Enrolment-Prozesses betrachtet werden können.

### Schritt 4: DEP-Check-in – Abrufen des Activation Record

Dieser Teil des Prozesses findet statt, wenn ein **Benutzer einen Mac zum ersten Mal startet** (oder nach einer vollständigen Löschung).

![Schritte für Enrolment und Management – Schritt 4: DEP-Check-in – Abrufen des Activation Record: Dieser Teil des Prozesses findet statt, wenn ein Benutzer einen Mac zum ersten Mal startet (oder nach einer vollständigen...](<../../../images/image (1044).png>)

oder bei der Ausführung von `sudo profiles show -type enrollment`

- Feststellen, **ob das Gerät DEP aktiviert hat**
- Activation Record ist die interne Bezeichnung für das **DEP-„Profil“**.
- Beginnt, sobald das Gerät mit dem Internet verbunden ist.
- Gesteuert durch **`CPFetchActivationRecord`**.
- Implementiert von **`cloudconfigurationd`** über XPC. Der **„Setup Assistant“** (beim erstmaligen Start des Geräts) oder der Befehl **`profiles`** kontaktiert diesen Daemon, um den Activation Record abzurufen.
- LaunchDaemon (läuft immer als root).

Das Abrufen des Activation Record erfolgt in mehreren Schritten durch **`MCTeslaConfigurationFetcher`**. Dieser Prozess verwendet eine Verschlüsselung namens **Absinthe**<sup>[1]</sup>.

1. **Zertifikat** abrufen
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Status aus dem Zertifikat **initialisieren** (**`NACInit`**)
1. Verwendet verschiedene gerätespezifische Daten (z. B. **Seriennummer über `IOKit`**).
3. **Session-Key** abrufen
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session aufbauen (**`NACKeyEstablishment`**)
5. Anfrage stellen
1. POST an [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), wobei die Daten `{ "action": "RequestProfileConfiguration", "sn": "" }` gesendet werden.
2. Die JSON-Payload wird mit Absinthe verschlüsselt (**`NACSign`**).
3. Alle Anfragen erfolgen über HTTPS; integrierte Root-Zertifikate werden verwendet.

![Schritte für Enrolment und Management – Schritt 4: DEP-Check-in – Abrufen des Activation Record: 3. Alle Anfragen erfolgen über HTTPS; integrierte Root-Zertifikate werden verwendet](<../../../images/image (566) (1).png>)

Die Antwort ist ein JSON-Dictionary mit wichtigen Daten wie:

- **url**: URL des MDM-Vendor-Hosts für das Activation Profile
- **anchor-certs**: Array von DER-Zertifikaten, die als vertrauenswürdige Anchors verwendet werden

### **Schritt 5: Abrufen des Profils**

![Schritt 4: DEP-Check-in – Abrufen des Activation Record – Schritt 5: Abrufen des Profils: Schritt 5: Abrufen des Profils](<../../../images/image (444).png>)

- Anfrage wird an die im DEP-Profil angegebene **url** gesendet.
- **Anchor-Zertifikate** werden zur **Vertrauensbewertung** verwendet, sofern vorhanden.
- Hinweis: die Eigenschaft **anchor_certs** des DEP-Profils.
- **Anfrage ist eine einfache .plist** mit Geräteidentifikation.
- Beispiele: **UDID, OS-Version**.
- CMS-signiert, DER-kodiert.
- Signiert mit dem **Geräteidentitätszertifikat (von APNS)**.
- Die **Zertifikatskette** enthält eine abgelaufene **Apple iPhone Device CA**.

![Schritt 4: DEP-Check-in – Abrufen des Activation Record – Schritt 5: Abrufen des Profils: Signiert mit dem Geräteidentitätszertifikat (von APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Schritt 6: Installation des Profils

- Nach dem Abruf wird das **Profil auf dem System gespeichert**.
- Dieser Schritt beginnt automatisch (im **Setup Assistant**).
- Gesteuert durch **`CPInstallActivationProfile`**.
- Implementiert von mdmclient über XPC.
- LaunchDaemon (als root) oder LaunchAgent (als Benutzer), abhängig vom Kontext.
- Configuration Profiles enthalten mehrere zu installierende Payloads.
- Das Framework verwendet eine Plugin-basierte Architektur zur Installation von Profilen.
- Jeder Payload-Typ ist einem Plugin zugeordnet.
- Kann XPC (im Framework) oder klassisches Cocoa (in ManagedClient.app) sein.
- Beispiel:
- Certificate Payloads verwenden CertificateService.xpc.

Typischerweise enthält das von einem MDM-Vendor bereitgestellte **Activation Profile** die folgenden Payloads:

- `com.apple.mdm`: zur **Registrierung** des Geräts bei MDM.
- `com.apple.security.scep`: zur sicheren Bereitstellung eines **Client-Zertifikats** für das Gerät.
- `com.apple.security.pem`: zur **Installation vertrauenswürdiger CA-Zertifikate** im System-Keychain des Geräts.
- Die Installation des MDM-Payloads entspricht dem **MDM-Check-in in der Dokumentation**.
- Der Payload **enthält wichtige Eigenschaften**:
- - MDM-Check-in-URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs-Topic zum Auslösen des Pollings
- Zur Installation des MDM-Payloads wird eine Anfrage an **`CheckInURL`** gesendet.
- Implementiert in **`mdmclient`**.
- Der MDM-Payload kann von anderen Payloads abhängig sein.
- Ermöglicht das **Pinnen von Anfragen an bestimmte Zertifikate**:
- Eigenschaft: **`CheckInURLPinningCertificateUUIDs`**
- Eigenschaft: **`ServerURLPinningCertificateUUIDs`**
- Wird über einen PEM-Payload bereitgestellt.
- Ermöglicht, dem Gerät ein Identitätszertifikat zuzuordnen:
- Eigenschaft: IdentityCertificateUUID
- Wird über einen SCEP-Payload bereitgestellt.

### **Schritt 7: Auf MDM-Befehle warten**

- Nach Abschluss des MDM-Check-ins kann der Vendor **Push-Benachrichtigungen über APNs senden**.
- Nach dem Empfang werden diese von **`mdmclient`** verarbeitet.
- Zum Abrufen von MDM-Befehlen wird eine Anfrage an die ServerURL gesendet.
- Verwendet den zuvor installierten MDM-Payload:
- **`ServerURLPinningCertificateUUIDs`** zum Pinnen der Anfrage.
- **`IdentityCertificateUUID`** für das TLS-Client-Zertifikat.

## Angriffe

### Geräte in anderen Organisationen registrieren

Wie bereits erwähnt, wird zum Versuch, ein Gerät bei einer Organisation zu registrieren, **nur eine Seriennummer benötigt, die zu dieser Organisation gehört**. Sobald das Gerät registriert ist, installieren mehrere Organisationen vertrauliche Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WLAN-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Enrolment-Prozess nicht korrekt geschützt ist:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referenzen

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
