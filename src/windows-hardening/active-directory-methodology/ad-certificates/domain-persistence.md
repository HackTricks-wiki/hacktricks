# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der Techniken zur Domain-Persistenz, die in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) geteilt werden**. Überprüfen Sie es für weitere Details.

## Fälschen von Zertifikaten mit gestohlenen CA-Zertifikaten - DPERSIST1

Wie können Sie feststellen, dass ein Zertifikat ein CA-Zertifikat ist?

Es kann festgestellt werden, dass ein Zertifikat ein CA-Zertifikat ist, wenn mehrere Bedingungen erfüllt sind:

- Das Zertifikat ist auf dem CA-Server gespeichert, wobei der private Schlüssel durch die DPAPI der Maschine oder durch Hardware wie ein TPM/HSM gesichert ist, sofern das Betriebssystem dies unterstützt.
- Sowohl die Felder Issuer als auch Subject des Zertifikats stimmen mit dem Distinguished Name der CA überein.
- Eine "CA Version"-Erweiterung ist ausschließlich in den CA-Zertifikaten vorhanden.
- Das Zertifikat hat keine Felder für die erweiterte Schlüsselverwendung (EKU).

Um den privaten Schlüssel dieses Zertifikats zu extrahieren, ist das Tool `certsrv.msc` auf dem CA-Server die unterstützte Methode über die integrierte GUI. Dennoch unterscheidet sich dieses Zertifikat nicht von anderen, die im System gespeichert sind; daher können Methoden wie die [THEFT2-Technik](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zur Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy mit dem folgenden Befehl abgerufen werden:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nachdem das CA-Zertifikat und der private Schlüssel im `.pfx`-Format erworben wurden, können Tools wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu generieren:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Der Benutzer, der für die Zertifikatsfälschung ins Visier genommen wird, muss aktiv sein und in der Lage sein, sich im Active Directory zu authentifizieren, damit der Prozess erfolgreich ist. Das Fälschen eines Zertifikats für spezielle Konten wie krbtgt ist ineffektiv.

Dieses gefälschte Zertifikat wird **gültig** sein bis zum angegebenen Enddatum und **solange das Root-CA-Zertifikat gültig ist** (normalerweise von 5 bis **10+ Jahren**). Es ist auch für **Maschinen** gültig, sodass ein Angreifer in Kombination mit **S4U2Self** **die Persistenz auf jeder Domänenmaschine** aufrechterhalten kann, solange das CA-Zertifikat gültig ist.\
Darüber hinaus **können die mit dieser Methode generierten Zertifikate** **nicht widerrufen** werden, da die CA nicht über sie informiert ist.

## Vertrauen in bösartige CA-Zertifikate - DPERSIST2

Das `NTAuthCertificates`-Objekt ist definiert, um ein oder mehrere **CA-Zertifikate** innerhalb seines `cacertificate`-Attributs zu enthalten, die vom Active Directory (AD) verwendet werden. Der Verifizierungsprozess durch den **Domänencontroller** umfasst die Überprüfung des `NTAuthCertificates`-Objekts auf einen Eintrag, der mit der **CA, die im Ausstellerfeld des authentifizierenden **Zertifikats** angegeben ist, übereinstimmt. Die Authentifizierung erfolgt, wenn ein Treffer gefunden wird.

Ein selbstsigniertes CA-Zertifikat kann von einem Angreifer zum `NTAuthCertificates`-Objekt hinzugefügt werden, vorausgesetzt, er hat die Kontrolle über dieses AD-Objekt. Normalerweise haben nur Mitglieder der **Enterprise Admin**-Gruppe sowie **Domain Admins** oder **Administratoren** im **Wurzel-Domain des Forests** die Berechtigung, dieses Objekt zu ändern. Sie können das `NTAuthCertificates`-Objekt mit `certutil.exe` und dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` bearbeiten oder das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

Diese Fähigkeit ist besonders relevant, wenn sie in Verbindung mit einer zuvor beschriebenen Methode verwendet wird, die ForgeCert zur dynamischen Generierung von Zertifikaten beinhaltet.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten zur **Persistenz** durch **Änderungen des Sicherheitsdeskriptors von AD CS**-Komponenten sind reichlich vorhanden. Änderungen, die im Abschnitt "[Domain Escalation](domain-escalation.md)" beschrieben sind, können von einem Angreifer mit erhöhtem Zugriff böswillig implementiert werden. Dazu gehört die Hinzufügung von "Kontrollrechten" (z. B. WriteOwner/WriteDACL/etc.) zu sensiblen Komponenten wie:

- Das **AD-Computerobjekt des CA-Servers**
- Der **RPC/DCOM-Server des CA-Servers**
- Jedes **Nachkommen-AD-Objekt oder Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (zum Beispiel der Container für Zertifikatvorlagen, der Container für Zertifizierungsstellen, das NTAuthCertificates-Objekt usw.)
- **AD-Gruppen, die standardmäßig oder durch die Organisation Rechte zur Kontrolle von AD CS delegiert haben** (wie die integrierte Gruppe der Zertifikatsverleger und deren Mitglieder)

Ein Beispiel für eine böswillige Implementierung wäre, dass ein Angreifer, der **erhöhte Berechtigungen** in der Domäne hat, die **`WriteOwner`**-Berechtigung zur Standard-**`User`**-Zertifikatvorlage hinzufügt, wobei der Angreifer der Hauptverantwortliche für das Recht ist. Um dies auszunutzen, würde der Angreifer zunächst das Eigentum der **`User`**-Vorlage auf sich selbst ändern. Danach würde das **`mspki-certificate-name-flag`** auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, was es einem Benutzer ermöglicht, einen Subject Alternative Name in der Anfrage bereitzustellen. Anschließend könnte der Angreifer sich mit der **Vorlage** anmelden, einen **Domänenadministrator**-Namen als alternativen Namen wählen und das erworbene Zertifikat zur Authentifizierung als DA verwenden.

{{#include ../../../banners/hacktricks-training.md}}
