# Phishing erkennen

{{#include ../../banners/hacktricks-training.md}}

## Einführung

Um einen Phishing-Versuch zu erkennen, ist es wichtig, die **Phishing-Techniken zu verstehen, die heutzutage verwendet werden**. Auf der übergeordneten Seite dieses Beitrags finden Sie diese Informationen. Wenn Sie sich nicht bewusst sind, welche Techniken heute verwendet werden, empfehle ich Ihnen, zur übergeordneten Seite zu gehen und mindestens diesen Abschnitt zu lesen.

Dieser Beitrag basiert auf der Idee, dass die **Angreifer versuchen werden, den Domainnamen des Opfers irgendwie nachzuahmen oder zu verwenden**. Wenn Ihre Domain `example.com` heißt und Sie aus irgendeinem Grund mit einem völlig anderen Domainnamen wie `youwonthelottery.com` gefischt werden, werden diese Techniken es nicht aufdecken.

## Variationen von Domainnamen

Es ist ziemlich **einfach**, diese **Phishing**-Versuche aufzudecken, die einen **ähnlichen Domainnamen** in der E-Mail verwenden.\
Es reicht aus, eine **Liste der wahrscheinlichsten Phishing-Namen** zu erstellen, die ein Angreifer verwenden könnte, und zu **überprüfen**, ob sie **registriert** sind oder einfach zu überprüfen, ob es eine **IP** gibt, die sie verwendet.

### Verdächtige Domains finden

Zu diesem Zweck können Sie eines der folgenden Tools verwenden. Beachten Sie, dass diese Tools auch automatisch DNS-Anfragen durchführen, um zu überprüfen, ob der Domainname eine zugewiesene IP hat:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Eine kurze Erklärung dieser Technik finden Sie auf der übergeordneten Seite. Oder lesen Sie die ursprüngliche Forschung unter** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Zum Beispiel kann eine 1-Bit-Modifikation in der Domain microsoft.com sie in _windnws.com_ verwandeln.\
**Angreifer können so viele Bit-Flipping-Domains wie möglich registrieren, die mit dem Opfer in Verbindung stehen, um legitime Benutzer auf ihre Infrastruktur umzuleiten**.

**Alle möglichen Bit-Flipping-Domainnamen sollten ebenfalls überwacht werden.**

### Grundlegende Überprüfungen

Sobald Sie eine Liste potenziell verdächtiger Domainnamen haben, sollten Sie sie **überprüfen** (hauptsächlich die Ports HTTP und HTTPS), um **zu sehen, ob sie ein Login-Formular verwenden, das dem eines der Opfer-Domains ähnlich ist**.\
Sie könnten auch Port 3333 überprüfen, um zu sehen, ob er offen ist und eine Instanz von `gophish` ausführt.\
Es ist auch interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist**, je jünger sie ist, desto riskanter ist sie.\
Sie können auch **Screenshots** der verdächtigen HTTP- und/oder HTTPS-Webseite machen, um zu sehen, ob sie verdächtig ist, und in diesem Fall **darauf zugreifen, um einen genaueren Blick zu werfen**.

### Erweiterte Überprüfungen

Wenn Sie einen Schritt weiter gehen möchten, empfehle ich Ihnen, **diese verdächtigen Domains zu überwachen und von Zeit zu Zeit nach weiteren zu suchen** (jeden Tag? Es dauert nur ein paar Sekunden/Minuten). Sie sollten auch die offenen **Ports** der zugehörigen IPs **überprüfen** und **nach Instanzen von `gophish` oder ähnlichen Tools suchen** (ja, Angreifer machen auch Fehler) und die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains **überwachen**, um zu sehen, ob sie ein Login-Formular von den Webseiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste von Login-Formularen der Domains des Opfers zu haben, die verdächtigen Webseiten zu durchsuchen und jedes gefundene Login-Formular in den verdächtigen Domains mit jedem Login-Formular der Domain des Opfers mit etwas wie `ssdeep` zu vergleichen.\
Wenn Sie die Login-Formulare der verdächtigen Domains gefunden haben, können Sie versuchen, **Müllanmeldeinformationen zu senden** und **zu überprüfen, ob Sie auf die Domain des Opfers umgeleitet werden**.

## Domainnamen mit Schlüsselwörtern

Die übergeordnete Seite erwähnt auch eine Technik zur Variation von Domainnamen, die darin besteht, den **Domainnamen des Opfers in eine größere Domain** einzufügen (z. B. paypal-financial.com für paypal.com).

### Zertifikatstransparenz

Es ist nicht möglich, den vorherigen "Brute-Force"-Ansatz zu verfolgen, aber es ist tatsächlich **möglich, solche Phishing-Versuche aufzudecken**, auch dank der Zertifikatstransparenz. Jedes Mal, wenn ein Zertifikat von einer CA ausgestellt wird, werden die Details öffentlich gemacht. Das bedeutet, dass es durch das Lesen der Zertifikatstransparenz oder sogar durch deren Überwachung **möglich ist, Domains zu finden, die ein Schlüsselwort in ihrem Namen verwenden**. Zum Beispiel, wenn ein Angreifer ein Zertifikat für [https://paypal-financial.com](https://paypal-financial.com) generiert, ist es möglich, durch das Ansehen des Zertifikats das Schlüsselwort "paypal" zu finden und zu wissen, dass eine verdächtige E-Mail verwendet wird.

Der Beitrag [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) schlägt vor, dass Sie Censys verwenden können, um nach Zertifikaten zu suchen, die ein bestimmtes Schlüsselwort betreffen, und nach Datum (nur "neue" Zertifikate) und nach dem CA-Aussteller "Let's Encrypt" zu filtern:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Sie können jedoch "das Gleiche" mit dem kostenlosen Web-Tool [**crt.sh**](https://crt.sh) tun. Sie können **nach dem Schlüsselwort suchen** und die **Ergebnisse nach Datum und CA filtern**, wenn Sie möchten.

![](<../../images/image (519).png>)

Mit dieser letzten Option können Sie sogar das Feld Matching Identities verwenden, um zu sehen, ob eine Identität der echten Domain mit einer der verdächtigen Domains übereinstimmt (beachten Sie, dass eine verdächtige Domain ein falsch positives Ergebnis sein kann).

**Eine weitere Alternative** ist das fantastische Projekt namens [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream bietet einen Echtzeit-Stream neu generierter Zertifikate, den Sie verwenden können, um bestimmte Schlüsselwörter in (nahezu) Echtzeit zu erkennen. Tatsächlich gibt es ein Projekt namens [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), das genau das tut.

### **Neue Domains**

**Eine letzte Alternative** besteht darin, eine Liste von **neu registrierten Domains** für einige TLDs zu sammeln ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bietet einen solchen Service) und die **Schlüsselwörter in diesen Domains zu überprüfen**. Allerdings verwenden lange Domains normalerweise einen oder mehrere Subdomains, daher wird das Schlüsselwort nicht innerhalb der FLD erscheinen und Sie werden die Phishing-Subdomain nicht finden können.

{{#include ../../banners/hacktricks-training.md}}
