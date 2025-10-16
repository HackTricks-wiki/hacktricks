# Phishing Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Recon des Opfers
1. Wähle die **Victim-Domain**.
2. Führe eine grundlegende Web-Enumeration durch, **suche nach Login-Portalen**, die das Opfer verwendet, und **entscheide**, welches du **imitieren** wirst.
3. Nutze OSINT, um **E-Mails zu finden**.
2. Vorbereitung der Umgebung
1. **Kaufe die Domain**, die du für die Phishing-Assessment verwenden wirst
2. **Konfiguriere die E-Mail-Service-bezogenen Records** (SPF, DMARC, DKIM, rDNS)
3. Konfiguriere den VPS mit gophish
3. Vorbereitung der Kampagne
1. Bereite die **E-Mail-Vorlage** vor
2. Bereite die **Webseite** vor, um die Credentials zu stehlen
4. Starte die Kampagne!

## Generiere ähnliche Domain-Namen oder kaufe eine vertrauenswürdige Domain

### Domain Name Variation Techniques

- **Keyword**: Der Domain-Name **enthält** ein wichtiges **Keyword** der Original-Domain (z. B. zelster.com-management.com).
- **hypened subdomain**: Ersetze den **Punkt durch einen Bindestrich** in einer Subdomain (z. B. www-zelster.com).
- **New TLD**: Dieselbe Domain mit einer **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Ersetze einen Buchstaben im Domain-Namen durch **ähnlich aussehende Zeichen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Vertausche zwei Buchstaben innerhalb des Domain-Namens (z. B. zelsetr.com).
- **Singularization/Pluralization**: Füge am Ende des Domain-Namens ein „s“ hinzu oder entferne es (z. B. zeltsers.com).
- **Omission**: Entferne einen Buchstaben aus dem Domain-Namen (z. B. zelser.com).
- **Repetition:** Wiederhole einen Buchstaben im Domain-Namen (z. B. zeltsser.com).
- **Replacement**: Ähnlich wie Homoglyph, aber weniger unauffällig. Ersetze einen Buchstaben im Domain-Namen, zum Beispiel durch einen auf der Tastatur benachbarten Buchstaben (z. B. zektser.com).
- **Subdomained**: Füge einen **Punkt** in den Domain-Namen ein (z. B. ze.lster.com).
- **Insertion**: Füge einen Buchstaben in den Domain-Namen ein (z. B. zerltser.com).
- **Missing dot**: Hänge die TLD an den Domain-Namen an (z. B. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einzelne Bits**, die gespeichert oder übertragen werden, **automatisch umkippen** (bit flip) durch Faktoren wie Sonnenstürme, kosmische Strahlung oder Hardware-Fehler.

Wenn dieses Konzept auf DNS-Anfragen **angewendet wird**, kann es passieren, dass die **Domain, die der DNS-Server erhält**, nicht mit der ursprünglich angeforderten Domain übereinstimmt.

Beispielsweise kann eine einzelne Bit-Änderung in der Domain "windows.com" diese in "windnws.com" ändern.

Angreifer können dies **ausnutzen, indem sie mehrere bit-flipping Domains registrieren**, die der Domain des Opfers ähneln. Ihr Ziel ist es, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Für mehr Informationen siehe [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kaufe eine vertrauenswürdige Domain

Du kannst auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits eine gute SEO** hat, kannst du prüfen, wie sie in folgenden Diensten kategorisiert ist:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen entdecken

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr gültige E-Mail-Adressen zu entdecken** oder die bereits gefundenen zu **verifizieren**, kannst du prüfen, ob du die SMTP-Server des Opfers brute-forcen kannst. [Lerne hier, wie man E-Mail-Adressen verifiziert/entdeckt](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem: Wenn Benutzer **ein Web-Portal verwenden, um auf ihre Mails zuzugreifen**, solltest du überprüfen, ob dieses für **Username-Brute-Force** anfällig ist, und die Schwachstelle ausnutzen, falls möglich.

## Konfiguration von GoPhish

### Installation

Du kannst es herunterladen von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Lade es herunter und entpacke es in `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
Im Output wird dir ein Passwort für den admin-User auf Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikat-Konfiguration**

Vor diesem Schritt sollten Sie die **Domain bereits gekauft** haben, die Sie verwenden werden, und diese muss **auf die IP des VPS** zeigen, auf dem Sie **gophish** konfigurieren.
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

Installation starten: `apt-get install postfix`

Dann füge die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf deinen Domainnamen und **starte deinen VPS neu.**

Erstelle nun einen **DNS A record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX**-Eintrag, der auf `mail.<domain>` zeigt.

Jetzt testen wir das Senden einer E-Mail:
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

Um den gophish service so zu erstellen, dass er automatisch gestartet und als service verwaltet werden kann, legen Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt an:
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
Schließe die Konfiguration des Dienstes ab und überprüfe, dass er funktioniert:
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
## Konfiguration von Mailserver und Domain

### Warten & seriös wirken

Je älter eine Domain ist, desto unwahrscheinlicher wird sie als Spam eingestuft. Du solltest daher so viel Zeit wie möglich warten (mindestens 1 Woche) bevor du die Phishing-Bewertung durchführst. Außerdem verbessert sich die Reputation, wenn du eine Seite zu einem reputationsstarken Sektor erstellst.

Beachte, dass du auch wenn du eine Woche warten musst bereits jetzt alles konfigurieren kannst.

### Reverse DNS (rDNS) record konfigurieren

Setze einen rDNS (PTR) record, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF record ist, [**siehe diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst https://www.spfwizard.net/ verwenden, um deine SPF-Policy zu generieren (verwende die IP des VPS)

![](<../../images/image (1037).png>)

Dies ist der Inhalt, der in einem TXT record der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Eintrag

Sie müssen **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Sie müssen einen neuen DNS TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` zeigt, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst für die neue Domain **DKIM konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst beide vom DKIM-Schlüssel erzeugten B64-Werte zusammenfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Rufe einfach die Seite auf und sende eine E-Mail an die Adresse, die sie dir geben:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Du kannst auch **deine E-Mail-Konfiguration prüfen**, indem du eine E-Mail an `check-auth@verifier.port25.com` sendest und die **Antwort liest** (dafür musst du Port **25** öffnen und die Antwort in der Datei _/var/mail/root_ ansehen, wenn du die E-Mail als root sendest).\
Stelle sicher, dass du alle Tests bestehst:
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
Du könntest auch eine **Nachricht an ein Gmail-Konto unter deiner Kontrolle** senden und die **E-Mail-Header** in deinem Gmail-Posteingang prüfen, `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Entfernung aus der Spamhouse-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von spamhouse blockiert wird. Du kannst die Entfernung deiner Domain/IP beantragen unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernung aus der Microsoft-Blacklist

​​Du kannst die Entfernung deiner Domain/IP beantragen unter [https://sender.office.com/](https://sender.office.com).

## Erstelle & Starte eine GoPhish-Kampagne

### Sending Profile

- Vergib einen **Namen zur Identifikation** des Absenderprofils
- Entscheide, von welchem Account du die Phishing-E-Mails senden wirst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, achte jedoch darauf, die Option Ignore Certificate Errors zu aktivieren

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu prüfen, ob alles funktioniert.\
> Ich würde empfehlen, **die Test-E-Mails an 10min mails addresses zu senden**, um zu vermeiden, dass man beim Testen geblacklistet wird.

### E-Mail-Vorlage

- Vergib einen **Namen zur Identifikation** der Vorlage
- Schreibe dann eine **Betreffzeile** (nichts Ungewöhnliches, einfach etwas, das man in einer normalen E-Mail erwarten würde)
- Stelle sicher, dass du "**Add Tracking Image**" aktiviert hast
- Schreibe die **E-Mail-Vorlage** (du kannst Variablen verwenden, wie im folgenden Beispiel):
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
Beachte, dass du **zur Erhöhung der Glaubwürdigkeit der E‑Mail** am besten eine Signatur aus einer echten E‑Mail des Kunden verwendest. Vorschläge:

- Sende eine E‑Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E‑Mails** wie info@ex.com oder press@ex.com oder public@ex.com, sende ihnen eine E‑Mail und warte auf die Antwort.
- Versuche, **eine gefundene gültige** E‑Mail‑Adresse zu kontaktieren und warte auf die Antwort.

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Schreibe einen **Namen**
- **Schreibe den HTML‑Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Markiere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Redirection**

![](<../../images/image (826).png>)

> [!TIP]
> In der Regel musst du den HTML‑Code der Seite anpassen und lokal testen (z. B. mit einem Apache‑Server), **bis dir das Ergebnis gefällt.** Danach fügst du diesen HTML‑Code in das Feld ein.\
> Beachte, dass du, wenn du **statische Ressourcen** für das HTML (z. B. CSS‑ oder JS‑Dateien) benötigst, diese in _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen kannst.

> [!TIP]
> Für die Weiterleitung könntest du die Nutzer **zur legitimen Hauptseite** des Opfers umleiten oder sie z. B. zu _/static/migration.html_ schicken, dort ein **Spinning Wheel** ([https://loading.io/](https://loading.io)) für 5 Sekunden anzeigen und dann mitteilen, dass der Prozess erfolgreich war.

### Users & Groups

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass für das Beispieltemplate Vorname, Nachname und E‑Mail‑Adresse jedes Nutzers benötigt werden)

![](<../../images/image (163).png>)

### Campaign

Erstelle abschließend eine Campaign, indem du einen Namen, das Email‑Template, die Landing Page, die URL, das Sending Profile und die Group auswählst. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass das **Sending Profile es erlaubt, eine Test‑E‑Mail zu senden, um zu sehen, wie die finale Phishing‑Mail aussehen wird**:

![](<../../images/image (192).png>)

> [!TIP]
> Ich empfehle, die Test‑Mails an 10min mails‑Adressen zu senden, um beim Testen nicht auf Blacklists zu landen.

Sobald alles bereit ist, starte einfach die Campaign!

## Website Cloning

Wenn du aus irgendeinem Grund die Website klonen möchtest, siehe folgende Seite:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei manchen Phishing‑Assessments (hauptsächlich für Red Teams) möchtest du vielleicht auch **Dateien mit irgendeiner Art Backdoor** versenden (z. B. ein C2 oder etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite für Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Webseite vortäuschst und die vom Nutzer eingegebenen Informationen sammelst. Wenn der Nutzer jedoch das falsche Passwort eingibt oder die von dir gefälschte Anwendung mit 2FA konfiguriert ist, **erlauben diese Informationen dir nicht, den getäuschten Nutzer zu impersonifizieren**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) ins Spiel. Diese Tools ermöglichen einen MitM‑ähnlichen Angriff. Grundsätzlich funktioniert der Angriff wie folgt:

1. Du **imitierst das Login‑Formular** der echten Webseite.
2. Der Nutzer **sendet** seine **Credentials** an deine Fake‑Seite und das Tool leitet diese an die echte Webseite weiter, **prüft, ob die Credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM‑Seite danach und sobald der **Nutzer diese eingibt**, sendet das Tool sie an die echte Webseite.
4. Sobald der Nutzer authentifiziert ist, hast du (als Angreifer) **die Credentials, die 2FA, das Cookie und alle Informationen** jeder Interaktion erfasst, während das Tool den MitM durchführt.

### Via VNC

Was, wenn du den Nutzer nicht zu einer bösartigen Seite mit gleichem Aussehen wie das Original schickst, sondern zu einer **VNC‑Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**? Du kannst sehen, was er tut, das Passwort stehlen, die genutzte MFA, die Cookies...\
Das geht mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Offensichtlich ist eine der besten Methoden, um herauszufinden, ob du erwischt wurdest, deine Domain in **Blacklists** zu suchen. Wenn sie gelistet ist, wurde deine Domain irgendwie als verdächtig erkannt.\
Eine einfache Möglichkeit, zu prüfen, ob deine Domain in einer Blacklist auftaucht, ist [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch auch andere Möglichkeiten zu erkennen, ob das Opfer **aktiv nach verdächtigen Phishing‑Aktivitäten im Netz sucht**, wie in folgendem Dokument erklärt:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit sehr ähnlichem Namen** wie die Domain des Opfers **kaufen und/oder ein Zertifikat** für eine **Subdomain** einer von dir kontrollierten Domain **generieren**, die das **Keyword** der Domain des Opfers enthält. Wenn das **Opfer** irgendeine **DNS- oder HTTP‑Interaktion** mit diesen Domains durchführt, weißt du, dass **es aktiv nach** verdächtigen Domains sucht und du sehr stealthy vorgehen musst.

### Evaluate the phishing

Nutze [**Phishious**](https://github.com/Rices/Phishious), um zu bewerten, ob deine E‑Mail im Spam‑Ordner landen, blockiert werden oder erfolgreich sein wird.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion‑Sets überspringen zunehmend E‑Mail‑Lures und **zielen direkt auf den Service‑Desk / Identity‑Recovery‑Workflow** ab, um MFA zu umgehen. Der Angriff ist vollständig "living‑off‑the‑land": Sobald der Operator gültige Credentials besitzt, pivotiert er mit eingebauten Admin‑Tools – es ist keine Malware erforderlich.

### Attack flow
1. Recon des Opfers
* Sammle persönliche & unternehmensbezogene Daten von LinkedIn, Datenlecks, öffentlichem GitHub usw.
* Identifiziere hochrangige Identitäten (Executives, IT, Finance) und ermittle den **genauen Help‑Desk‑Prozess** für Passwort‑/MFA‑Resets.
2. Echtzeit Social Engineering
* Rufe den Help‑Desk an, nutze Teams oder Chat und gib dich als Zielperson aus (oft mit **gespoofter Anrufer‑ID** oder **geklonter Stimme**).
* Gib die zuvor gesammelten PII an, um wissensbasierte Verifikation zu bestehen.
* Überzeuge den Agenten, das **MFA‑Secret zurückzusetzen** oder ein **SIM‑Swap** auf eine registrierte Mobilnummer durchzuführen.
3. Sofortige Post‑Access‑Aktionen (≤60 min in realen Fällen)
* Etabliere einen Fuß in einem beliebigen Web‑SSO‑Portal.
* Enumriere AD / AzureAD mit integrierten Tools (ohne Binaries abzulegen):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale Bewegung mit **WMI**, **PsExec** oder legitimen **RMM**‑Agenten, die bereits in der Umgebung auf der Whitelist stehen.

### Detection & Mitigation
* Behandle Help‑Desk‑Identity‑Recovery als eine **privilegierte Operation** – erfordere Step‑Up‑Auth & Manager‑Freigabe.
* Setze **Identity Threat Detection & Response (ITDR)** / **UEBA**‑Regeln ein, die alarmieren bei:
* Änderung der MFA‑Methode + Authentifizierung von neuem Gerät / Geo.
* Sofortige Erhöhung desselben Principal (User → Admin).
* Nimm Help‑Desk‑Anrufe auf und fordere vor einem Reset einen **Rückruf an eine bereits registrierte Nummer**.
* Implementiere **Just‑In‑Time (JIT) / Privileged Access**, sodass neu zurückgesetzte Konten **nicht** automatisch hochprivilegierte Tokens erhalten.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity‑Gruppen kompensieren die Kosten von High‑Touch‑Operationen mit Massenangriffen, die **Suchmaschinen & Werbenetzwerke als Auslieferungskanal** nutzen.

1. **SEO poisoning / malvertising** pusht ein gefälschtes Ergebnis wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First‑Stage Loader** herunter (oft JS/HTA/ISO). Beispiele, die Unit 42 beobachtet hat:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser‑Cookies + Credential‑DBs und lädt dann einen **silent loader**, der in Echtzeit entscheidet, ob er deployt:
* RAT (z. B. AsyncRAT, RustDesk)
* Ransomware / Wiper
* Persistenzkomponente (Registry Run‑Key + Scheduled Task)

### Hardening tips
* Blockiere neu registrierte Domains & setze **Advanced DNS / URL Filtering** sowohl für *Search‑Ads* als auch für E‑Mails durch.
* Beschränke Softwareinstallationen auf signierte MSI / Store‑Pakete, verbiete `HTA`, `ISO`, `VBS`‑Ausführung per Richtlinie.
* Überwache Child‑Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First‑Stage‑Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Angreifer verketten jetzt **LLM & voice‑clone APIs**, um vollständig personalisierte Lures und Echtzeit‑Interaktion zu erstellen.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Füge **dynamische Banner** hinzu, die Nachrichten hervorheben, die von untrusted automation stammen (auf Basis von ARC/DKIM‑Anomalien).  
• Setze **voice‑biometric challenge phrases** für hochriskante Telefonanfragen ein.  
• Simuliere kontinuierlich AI‑generierte Lures in Awareness‑Programmen – statische Templates sind veraltet.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Neben klassischem Push‑Bombing setzen Operatoren einfach darauf, während des Help‑Desk‑Anrufs eine **neue MFA‑Registrierung zu erzwingen**, wodurch das bestehende Token des Nutzers ungültig wird. Jeder anschließend erscheinende Login‑Prompt wirkt für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta‑Ereignisse, bei denen **`deleteMFA` + `addMFA`** **innerhalb weniger Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können stillschweigend bösartige Befehle in die Zwischenablage des Opfers von einer kompromittierten oder typosquatted Webseite kopieren und den Benutzer dann dazu verleiten, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen, wodurch beliebiger Code ausgeführt wird, ohne dass ein Download oder Anhang erforderlich ist.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatoren schotten ihre phishing-Flows zunehmend hinter einer einfachen Geräteprüfung ab, damit Desktop-Crawler nie die finalen Seiten erreichen. Ein typisches Muster ist ein kleines Script, das prüft, ob das DOM Touch-fähig ist, und das Ergebnis an einen Server-Endpunkt postet; Nicht‑mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Nutzern der vollständige Flow ausgeliefert wird.

Minimales Client‑Snippet (typische Logik):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` Logik (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Häufig beobachtetes Serververhalten:
- Setzt ein Session-Cookie beim ersten Laden.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt für nachfolgende GETs einen 500 (oder Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing-Inhalt nur, wenn `true`.

Hunting- und Detection-Heuristiken:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Sequenz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für Nicht‑Mobile; legitime mobile Opferpfade geben 200 mit anschließendem HTML/JS zurück.
- Seiten blockieren oder genauer prüfen, die Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Gerätechecks abhängig machen.

Verteidigungstipps:
- Führe Crawler mit mobilen Fingerprints und aktiviertem JS aus, um zugangsbeschränkte Inhalte aufzudecken.
- Alarmieren bei verdächtigen 500-Antworten nach `POST /detect` auf neu registrierten Domains.

## Referenzen

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
