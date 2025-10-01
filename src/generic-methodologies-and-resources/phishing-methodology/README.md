# Phishing Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Recon des Ziels
1. Wähle die **Ziel-Domain**.
2. Führe eine grundlegende Web-Enumeration durch, **suche nach Login-Portalen**, die vom Ziel verwendet werden, und **entscheide**, welches du **imitieren** wirst.
3. Nutze OSINT, um **E-Mails zu finden**.
2. Bereite die Umgebung vor
1. **Kaufe die Domain**, die du für die Phishing-Bewertung verwenden wirst
2. **Konfiguriere die E-Mail-Service**-bezogenen Records (SPF, DMARC, DKIM, rDNS)
3. Konfiguriere das VPS mit **gophish**
3. Bereite die Kampagne vor
1. Bereite die **E-Mail-Vorlage** vor
2. Bereite die **Webseite** vor, um die Zugangsdaten zu stehlen
4. Starte die Kampagne!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Der Domainname **enthält** ein wichtiges **Keyword** der Originaldomain (z. B. zelster.com-management.com).
- **hypened subdomain**: Ersetze den **Punkt durch einen Bindestrich** in einer Subdomain (z. B. www-zelster.com).
- **New TLD**: Dieselbe Domain mit einer **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Ersetzt einen Buchstaben im Domainnamen durch **ähnlich aussehende Zeichen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Es **tauscht zwei Buchstaben** innerhalb des Domainnamens aus (z. B. zelsetr.com).
- **Singularization/Pluralization**: Fügt ein „s“ am Ende der Domain hinzu oder entfernt es (z. B. zeltsers.com).
- **Omission**: Entfernt **einen Buchstaben** aus dem Domainnamen (z. B. zelser.com).
- **Repetition:** Wiederholt **einen Buchstaben** im Domainnamen (z. B. zeltsser.com).
- **Replacement**: Ähnlich wie Homoglyph, aber weniger unauffällig. Ersetzt einen Buchstaben im Domainnamen, möglicherweise durch einen Buchstaben in der Nähe auf der Tastatur (z. B. zektser.com).
- **Subdomained**: Fügt einen **Punkt** innerhalb des Domainnamens ein (z. B. ze.lster.com).
- **Insertion**: **Fügt einen Buchstaben ein** in den Domainnamen (z. B. zerltser.com).
- **Missing dot**: Hängt die TLD an den Domainnamen an. (z. B. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einzelne Bits, die gespeichert sind oder während der Kommunikation übertragen werden, automatisch umflippen** — verursacht durch Faktoren wie Sonnenstürme, kosmische Strahlung oder Hardwarefehler.

Wenn dieses Konzept auf DNS-Anfragen **angewandt** wird, ist es möglich, dass die **vom DNS-Server empfangene Domain** nicht mit der ursprünglich angeforderten Domain übereinstimmt.

Beispielsweise kann eine einzelne Bitmodifikation in der Domain "windows.com" diese in "windnws.com" ändern.

Angreifer können **davon profitieren, indem sie mehrere bitflipping-ähnliche Domains registrieren**, die der Domain des Ziels ähneln. Ihr Ziel ist es, legitime Nutzer auf ihre eigene Infrastruktur umzuleiten.

Weitere Informationen: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Du kannst auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits ein gutes SEO** hat, kannst du prüfen, wie sie kategorisiert ist in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100% kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr gültige E-Mail-Adressen zu entdecken** oder **die bereits gefundenen zu verifizieren**, kannst du prüfen, ob du die SMTP-Server des Ziels brute-forcen kannst. [Erfahre hier, wie man E-Mail-Adressen verifiziert/entdeckt](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem: Vergiss nicht, dass wenn Benutzer **ein Webportal zur Mail-Zugriffs** nutzen, du prüfen kannst, ob dieses für **Username-Brute-Force** verwundbar ist, und diese Schwachstelle im gegebenen Fall ausnutzen kannst.

## GoPhish konfigurieren

### Installation

Du kannst es von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Downloade und entpacke es innerhalb von `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
Im Output wird dir ein Passwort für den Admin-User auf Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port zu lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikatkonfiguration**

Vor diesem Schritt sollten Sie **die Domain bereits gekauft haben**, die Sie verwenden möchten, und sie muss **auf die IP des VPS** zeigen, auf dem Sie **gophish** konfigurieren.
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

Beginnen Sie mit der Installation: `apt-get install postfix`

Fügen Sie dann die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändern Sie außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändern Sie abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf Ihren Domainnamen und **starten Sie Ihren VPS neu.**

Erstellen Sie nun einen **DNS A record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX**-Eintrag, der auf `mail.<domain>` zeigt.

Jetzt testen wir das Versenden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Stoppe die Ausführung von gophish und lass es uns konfigurieren.\\
Ändere `/opt/gophish/config.json` wie folgt (achte auf die Verwendung von https):
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
**Gophish-Service konfigurieren**

Um den gophish-Service zu erstellen, damit er automatisch gestartet und als Service verwaltet werden kann, können Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:
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
Schließen Sie die Konfiguration des Dienstes ab und überprüfen Sie ihn, indem Sie:
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

### Warten & legitim sein

Je älter eine Domain ist, desto unwahrscheinlicher wird sie als Spam eingestuft. Daher solltest du so viel Zeit wie möglich warten (mindestens 1 Woche) vor der phishing assessment. Außerdem, wenn du eine Seite zu einem reputablen Sektor erstellst, wird die erhaltene Reputation besser sein.

Beachte, dass du auch wenn du eine Woche warten musst, jetzt alles konfigurieren kannst.

### Reverse DNS (rDNS) record konfigurieren

Setze einen rDNS (PTR)-Eintrag, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF)-Eintrag

Du musst **einen SPF-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Policy zu erzeugen (verwende die IP des VPS).

![](<../../images/image (1037).png>)

Das ist der Inhalt, der in einen TXT-Eintrag der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-basierte Message Authentication, Reporting & Conformance (DMARC)-Eintrag

Sie müssen **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Sie müssen einen neuen DNS TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` zeigt, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **einen DKIM für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst beide B64-Werte, die der DKIM-Schlüssel erzeugt, zusammenfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste die Bewertung deiner E-Mail-Konfiguration

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Öffne die Seite und sende eine E-Mail an die dort angegebene Adresse:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können auch **Ihre E-Mail-Konfiguration prüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (dafür müssen Sie **öffnen** Port **25** und die Antwort in der Datei _/var/mail/root_ sehen, wenn Sie die E-Mail als root senden).\
Prüfen Sie, ob Sie alle Tests bestehen:
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
Sie können auch **eine Nachricht an ein Gmail-Konto unter Ihrer Kontrolle** senden und die **E-Mail-Header** in Ihrem Gmail-Posteingang prüfen; `dkim=pass` sollte im `Authentication-Results` Header-Feld vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Entfernen aus der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von Spamhaus blockiert wird. Du kannst die Entfernung deiner Domain/IP hier anfordern: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen aus der Microsoft-Blacklist

​​Du kannst die Entfernung deiner Domain/IP hier anfordern: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Vergib einen **Namen zur Identifikation** des Absenderprofils
- Entscheide, von welchem Account du die Phishing-Mails senden wirst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, achte aber darauf, "**Ignore Certificate Errors**" anzuhaken

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu prüfen, ob alles funktioniert.\
> Ich empfehle, die Test-E-Mails an Adressen von 10min mails zu senden, um zu vermeiden, dass man beim Testen auf Blacklists landet.

### Email Template

- Vergib einen **Namen zur Identifikation** der Vorlage
- Dann schreibe einen **Betreff** (nichts Ungewöhnliches, nur etwas, das man in einer normalen E-Mail erwarten würde)
- Stelle sicher, dass du "**Add Tracking Image**" angehakt hast
- Schreibe die **E-Mail-Vorlage** (du kannst Variablen verwenden wie im folgenden Beispiel):
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
Beachte, dass **um die Glaubwürdigkeit der E‑Mail zu erhöhen**, empfohlen wird, eine Signatur aus einer E‑Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E‑Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E‑Mail‑Adressen** wie info@ex.com oder press@ex.com oder public@ex.com, sende ihnen eine E‑Mail und warte auf die Antwort.
- Versuche, eine **entdeckte gültige** E‑Mail zu kontaktieren und warte auf die Antwort

![](<../../images/image (80).png>)

> [!TIP]
> Die E‑Mail‑Vorlage erlaubt es außerdem, **Dateien anzuhängen, die versendet werden**. Wenn du außerdem NTLM‑Challenges mit speziell gestalteten Dateien/Dokumenten stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Trage einen **Namen** ein
- **Schreibe den HTML‑Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Weiterleitung**

![](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML‑Code der Seite anpassen und lokal testen (z. B. mit einem Apache‑Server), **bis dir das Ergebnis gefällt.** Dann fügst du diesen HTML‑Code in das Feld ein.\
> Beachte, dass du, falls du **statische Ressourcen** für das HTML benötigst (z. B. CSS‑ oder JS‑Dateien), diese in _**/opt/gophish/static/endpoint**_ speichern und anschließend über _**/static/\<filename>**_ aufrufen kannst.

> [!TIP]
> Zur Weiterleitung könntest du die Benutzer zur legitimen Hauptseite des Opfers weiterleiten oder sie z. B. zu _/static/migration.html_ schicken, dort für 5 Sekunden ein **Ladesymbol** ([https://loading.io/](https://loading.io)) anzeigen und anschließend mitteilen, dass der Vorgang erfolgreich war.

### Users & Groups

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass du für die Verwendung der Vorlage im Beispiel Vorname, Nachname und E‑Mail‑Adresse jedes Benutzers benötigst)

![](<../../images/image (163).png>)

### Campaign

Erstelle schließlich eine Kampagne, indem du einen Namen, die E‑Mail‑Vorlage, die Landing‑Seite, die URL, das Sending Profile und die Gruppe auswählst. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird

Beachte, dass das **Sending Profile erlaubt, eine Test‑E‑Mail zu senden, um zu sehen, wie die finale Phishing‑E‑Mail aussehen wird**:

![](<../../images/image (192).png>)

> [!TIP]
> Ich empfehle, die Test‑E‑Mails an 10min‑Mail‑Adressen zu senden, um zu vermeiden, beim Testen auf Blacklists zu landen.

Sobald alles bereit ist, starte einfach die Kampagne!

## Website Cloning

Wenn du aus irgendeinem Grund die Webseite klonen möchtest, siehe folgende Seite:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumente & Dateien mit Backdoor

In einigen Phishing‑Assessments (hauptsächlich für Red Teams) möchtest du eventuell auch **Dateien versenden, die eine Art Backdoor enthalten** (z. B. ein C2 oder etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite für einige Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich raffiniert, da du eine echte Webseite vortäuschst und die vom Benutzer eingegebenen Informationen sammelst. Leider erlauben dir diese Informationen nicht, dich als den getäuschten Benutzer auszugeben, wenn der Benutzer das falsche Passwort eingegeben hat oder die von dir gefälschte Anwendung mit 2FA konfiguriert ist.

An dieser Stelle sind Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2), [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) nützlich. Diese Tools ermöglichen es, einen MitM‑artigen Angriff durchzuführen. Grundsätzlich funktioniert der Angriff wie folgt:

1. Du fälschst das Login‑Formular der echten Webseite.
2. Der Benutzer **sendet** seine **credentials** an deine gefälschte Seite und das Tool leitet diese an die echte Webseite weiter, **prüft, ob die credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fordert die MitM‑Seite diese an und sobald der **Benutzer sie eingibt**, sendet das Tool sie an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, hast du (als Angreifer) **die credentials, die 2FA, das cookie und alle Informationen** jeder Interaktion erfasst, während das Tool den MitM durchführt.

### Via VNC

Was, wenn du anstatt das Opfer auf eine bösartige Seite zu schicken, die genauso aussieht wie die Originalseite, es zu einer **VNC‑Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**, leitest? Du kannst dann sehen, was es macht, das Passwort, die verwendete MFA, die Cookies stehlen...\
Das kannst du mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) durchführen.

## Erkennen, ob man entdeckt wurde

Offensichtlich ist eine der besten Methoden herauszufinden, ob du aufgeflogen bist, deine Domain in Blacklists zu **suchen**. Wenn sie gelistet ist, wurde deine Domain offenbar als verdächtig erkannt.\
Eine einfache Möglichkeit, zu prüfen, ob deine Domain in einer Blacklist erscheint, ist die Nutzung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch andere Möglichkeiten zu erkennen, ob das Opfer **aktiv nach verdächtiger Phishing‑Aktivität in freier Wildbahn sucht**, wie erklärt in:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst eine Domain mit einem sehr ähnlichen Namen wie die Domain des Opfers **kaufen** und/oder ein Zertifikat für eine **Subdomain** einer von dir kontrollierten Domain **erzeugen**, die das **Schlüsselwort** der Domain des Opfers enthält. Wenn das **Opfer** irgendwelche **DNS‑ oder HTTP‑Interaktionen** mit ihnen durchführt, weißt du, dass **es aktiv nach** verdächtigen Domains sucht und du extrem verdeckt vorgehen musst.

### Phishing bewerten

Nutze [**Phishious**](https://github.com/Rices/Phishious), um zu bewerten, ob deine E‑Mail im Spam‑Ordner landen wird, blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

### Angriffsablauf
1. Aufklärung des Opfers
* Sammle persönliche & geschäftliche Details von LinkedIn, data breaches, öffentlichem GitHub, etc.
* Identifiziere hochrangige Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help‑Desk‑Prozess** für Passwort-/MFA‑Resets.
2. Echtzeit‑Social‑Engineering
* Rufe per Telefon, Teams oder Chat beim Help‑Desk an und gib dich als Zielperson aus (oft mit **gefälschter Anrufer‑ID** oder **geklonter Stimme**).
* Gib die zuvor gesammelten PII an, um wissensbasierte Verifizierungen zu bestehen.
* Überzeuge den Agenten, das **MFA‑Secret zurückzusetzen** oder einen **SIM‑Swap** auf eine registrierte Mobilnummer durchzuführen.
3. Sofortige Aktionen nach Zugang (≤60 min in realen Fällen)
* Etabliere einen Fuß in der Tür über ein beliebiges Web‑SSO‑Portal.
* Enumeriere AD / AzureAD mit eingebauten Tools (keine Binaries werden abgelegt):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Seitliche Bewegung mit **WMI**, **PsExec** oder legitimen **RMM**‑Agenten, die bereits in der Umgebung auf der Whitelist stehen.

### Erkennung & Gegenmaßnahmen
* Behandle Help‑Desk‑Identitätswiederherstellungen als eine **privilegierte Operation** – erfordere Step‑Up‑Authentifizierung & Manager‑Genehmigung.
* Stelle Regeln für **Identity Threat Detection & Response (ITDR)** / **UEBA** bereit, die alarmieren bei:
  * Änderung der MFA‑Methode + Authentifizierung von neuem Gerät / Geo.
  * Sofortige Erhöhung derselben Entität (user → admin).
* Nimm Help‑Desk‑Anrufe auf und erzwinge einen **Rückruf an eine bereits registrierte Nummer** vor jedem Reset.
* Implementiere **Just‑In‑Time (JIT) / Privileged Access**, sodass neu zurückgesetzte Konten **nicht** automatisch hochprivilegierte Tokens erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Massenakteure kompensieren die Kosten von High‑Touch‑Operationen durch Massenangriffe, die **Suchmaschinen & Werbenetzwerke zum Lieferkanal** machen.

1. **SEO poisoning / malvertising** schiebt ein gefälschtes Ergebnis wie `chromium-update[.]site` in die Top‑Suchanzeigen.
2. Das Opfer lädt einen kleinen **first-stage loader** herunter (oft JS/HTA/ISO). Beispiele, die Unit 42 beobachtet hat:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser‑Cookies + credential DBs und lädt dann einen **silent loader**, der in *Echtzeit* entscheidet, ob er ausrollt:
* RAT (z. B. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (Registry Run Key + Scheduled Task)

### Härtungshinweise
* Sperre neu registrierte Domains & setze **Advanced DNS / URL Filtering** für *search-ads* sowie E‑Mail durch.
* Beschränke Softwareinstallationen auf signierte MSI / Store‑Pakete, verhindere per Richtlinie die Ausführung von `HTA`, `ISO`, `VBS`.
* Überwache Child‑Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First‑Stage‑Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Angreifer verketten nun **LLM & voice-clone APIs**, um vollständig personalisierte Köder und Echtzeit‑Interaktion zu erzeugen.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generiere & sende >100 k E‑Mails / SMS mit randomisiertem Wortlaut & Tracking‑Links.|
|Generative AI|Erzeuge *einmalige* E‑Mails, die öffentliche M&A und Insider‑Witze aus Social Media referenzieren; Deep‑Fake‑CEO‑Stimme im Rückruf‑Betrug.|
|Agentic AI|Registriert autonom Domains, scraped Open‑Source‑Intel und erstellt nächste‑Stufen‑Mails, wenn ein Opfer klickt, aber keine credentials übermittelt.|

**Defence:**
• Füge **dynamische Banner** hinzu, die Nachrichten hervorheben, die von nicht vertrauenswürdiger Automation gesendet wurden (z. B. bei ARC/DKIM‑Anomalien).  
• Setze **voice‑biometric challenge phrases** für risikoreiche Telefonanfragen ein.  
• Simuliere kontinuierlich KI‑generierte Köder in Awareness‑Programmen – statische Vorlagen sind obsolet.

Siehe auch – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Neben dem klassischen Push‑Bombing erzwingen Operatoren während des Help‑Desk‑Anrufs einfach die **Registrierung eines neuen MFA‑Tokens**, wodurch das bestehende Token des Benutzers ungültig wird. Jeder nachfolgende Login‑Prompt erscheint für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** **innerhalb weniger Minuten von derselben IP** auftreten.

## Clipboard Hijacking / Pastejacking

Angreifer können heimlich bösartige Befehle in die Zwischenablage des Opfers von einer kompromittierten oder typosquatted Webseite kopieren und den Benutzer dann dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen, wodurch beliebiger Code ausgeführt wird, ohne dass etwas heruntergeladen oder angehängt werden muss.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Referenzen

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
