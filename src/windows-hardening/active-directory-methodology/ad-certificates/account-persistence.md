# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kleine Zusammenfassung der Kapitel zur Maschinenpersistenz aus der großartigen Forschung von [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Verstehen des Diebstahls aktiver Benutzeranmeldeinformationen mit Zertifikaten – PERSIST1**

In einem Szenario, in dem ein Benutzer ein Zertifikat anfordern kann, das die Authentifizierung im Domänenbereich ermöglicht, hat ein Angreifer die Möglichkeit, dieses Zertifikat **anzufordern** und **zu stehlen**, um **Persistenz** in einem Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt die `User`-Vorlage in Active Directory solche Anfragen, obwohl sie manchmal deaktiviert sein kann.

Mit einem Tool namens [**Certify**](https://github.com/GhostPack/Certify) kann man nach gültigen Zertifikaten suchen, die persistenten Zugriff ermöglichen:
```bash
Certify.exe find /clientauth
```
Es wird hervorgehoben, dass die Stärke eines Zertifikats in seiner Fähigkeit liegt, **als der Benutzer** zu authentifizieren, dem es gehört, unabhängig von Passwortänderungen, solange das Zertifikat **gültig** bleibt.

Zertifikate können über eine grafische Benutzeroberfläche mit `certmgr.msc` oder über die Befehlszeile mit `certreq.exe` angefordert werden. Mit **Certify** wird der Prozess zur Anforderung eines Zertifikats wie folgt vereinfacht:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Nach erfolgreicher Anfrage wird ein Zertifikat zusammen mit seinem privaten Schlüssel im `.pem`-Format generiert. Um dies in eine `.pfx`-Datei zu konvertieren, die auf Windows-Systemen verwendbar ist, wird der folgende Befehl verwendet:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Die `.pfx`-Datei kann dann auf ein Zielsystem hochgeladen und mit einem Tool namens [**Rubeus**](https://github.com/GhostPack/Rubeus) verwendet werden, um ein Ticket Granting Ticket (TGT) für den Benutzer anzufordern, wodurch der Zugriff des Angreifers so lange verlängert wird, wie das Zertifikat **gültig** ist (typischerweise ein Jahr):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Ein wichtiger Hinweis wird gegeben, wie diese Technik, kombiniert mit einer anderen Methode, die im Abschnitt **THEFT5** beschrieben ist, es einem Angreifer ermöglicht, den **NTLM-Hash** eines Kontos dauerhaft zu erhalten, ohne mit dem Local Security Authority Subsystem Service (LSASS) zu interagieren und aus einem nicht erhöhten Kontext, was eine stealthier Methode für den langfristigen Diebstahl von Anmeldeinformationen bietet.

## **Maschinenpersistenz mit Zertifikaten erlangen - PERSIST2**

Eine andere Methode besteht darin, das Maschinenkonto eines kompromittierten Systems für ein Zertifikat zu registrieren, wobei die Standardvorlage `Machine` verwendet wird, die solche Aktionen erlaubt. Wenn ein Angreifer erhöhte Berechtigungen auf einem System erlangt, kann er das **SYSTEM**-Konto verwenden, um Zertifikate anzufordern, was eine Form der **Persistenz** bietet:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Dieser Zugriff ermöglicht es dem Angreifer, sich als Maschinenkonto bei **Kerberos** zu authentifizieren und **S4U2Self** zu nutzen, um Kerberos-Diensttickets für jeden Dienst auf dem Host zu erhalten, was dem Angreifer effektiv dauerhaften Zugriff auf die Maschine gewährt.

## **Erweiterung der Persistenz durch Zertifikatserneuerung - PERSIST3**

Die letzte besprochene Methode beinhaltet die Nutzung der **Gültigkeits**- und **Erneuerungszeiträume** von Zertifikatvorlagen. Durch die **Erneuerung** eines Zertifikats vor dessen Ablauf kann ein Angreifer die Authentifizierung bei Active Directory aufrechterhalten, ohne zusätzliche Ticketanmeldungen, die Spuren auf dem Zertifizierungsstellen- (CA) Server hinterlassen könnten.

Dieser Ansatz ermöglicht eine **erweiterte Persistenz**-Methode, die das Risiko der Entdeckung durch weniger Interaktionen mit dem CA-Server minimiert und die Generierung von Artefakten vermeidet, die Administratoren auf die Eindringung aufmerksam machen könnten.

{{#include ../../../banners/hacktricks-training.md}}
