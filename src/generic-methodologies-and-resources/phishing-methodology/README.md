# Phishing Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Recon the victim
1. Wähle die **victim domain**.
2. Führe grundlegende web enumeration durch, indem du nach **login portals** suchst, die vom victim verwendet werden, und **decide**, welches du **impersonate** wirst.
3. Nutze etwas **OSINT**, um **find emails**.

2. Bereite die Umgebung vor
1. **Buy the domain** die du für die phishing assessment verwenden wirst
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS mit **gophish**
3. Bereite die Kampagne vor
1. Bereite die **email template** vor
2. Bereite die **web page** vor, um die credentials zu stehlen
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Der Domainname **contains** ein wichtiges **keyword** der Original-Domain (z. B. zelster.com-management.com).
- **hypened subdomain**: Ersetze den **dot durch einen Bindestrich** einer Subdomain (z. B. www-zelster.com).
- **New TLD**: Gleiche Domain mit einer **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Ersetzt einen Buchstaben im Domainnamen durch **Buchstaben, die ähnlich aussehen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Vertauscht zwei Buchstaben innerhalb des Domainnamens (z. B. zelsetr.com).
- **Singularization/Pluralization**: Fügt am Ende des Domainnamens ein „s“ hinzu oder entfernt es (z. B. zeltsers.com).
- **Omission**: Entfernt einen der Buchstaben aus dem Domainnamen (z. B. zelser.com).
- **Repetition:** Wiederholt einen der Buchstaben im Domainnamen (z. B. zeltsser.com).
- **Replacement**: Ähnlich wie Homoglyph, aber weniger unauffällig. Ersetzt einen Buchstaben im Domainnamen, z. B. durch einen Nachbarbuchstaben auf der Tastatur (z. B. zektser.com).
- **Subdomained**: Fügt einen **dot** innerhalb des Domainnamens ein (z. B. ze.lster.com).
- **Insertion**: Fügt einen Buchstaben in den Domainnamen ein (z. B. zerltser.com).
- **Missing dot**: Hängt die TLD an den Domainnamen an. (z. B. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die Möglichkeit, dass einzelne Bits, die gespeichert sind oder während der Kommunikation übertragen werden, sich durch verschiedene Faktoren wie Sonneneruptionen, kosmische Strahlung oder Hardwarefehler automatisch umdrehen.

Wendet man dieses Konzept auf DNS-Anfragen an, kann es passieren, dass die **Domain, die beim DNS-Server ankommt**, nicht dieselbe ist wie die ursprünglich angeforderte Domain.

Beispielsweise kann eine einzelne Bit-Änderung in der Domain "windows.com" zu "windnws.com" führen.

Angreifer können dies ausnutzen, indem sie mehrere bit-flipping Domains registrieren, die der Domain des Opfers ähneln. Ihre Absicht ist es, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Für mehr Informationen siehe [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Du kannst auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, bereits eine gute SEO hat, kannst du prüfen, wie sie in folgenden Diensten kategorisiert ist:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Ermittlung

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr** gültige E-Mail-Adressen zu entdecken oder die bereits gefundenen Adressen zu **verifizieren**, kannst du prüfen, ob du die SMTP-Server des Opfers brute-forcen kannst. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem solltest du nicht vergessen, dass wenn Benutzer **einen Webportal nutzen, um auf ihre Mails zuzugreifen**, du überprüfen kannst, ob dieser anfällig für **username brute force** ist, und die Schwachstelle falls möglich ausnutzen.

## Configuring GoPhish

### Installation

Du kannst es von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter und entpacke es unter `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
Im Output wird dir ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Greife daher auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port auf lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikat-Konfiguration**

Vor diesem Schritt sollten Sie die Domain, die Sie verwenden werden, bereits gekauft haben; sie muss auf die IP des VPS zeigen, auf dem Sie gophish konfigurieren.
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

Füge dann die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf deinen Domainnamen und **starte deinen VPS neu.**

Erstelle nun einen **DNS A record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX** record, der auf `mail.<domain>` zeigt.

Testen wir jetzt das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Beenden Sie die Ausführung von gophish und konfigurieren Sie es.\
Bearbeiten Sie `/opt/gophish/config.json` wie folgt (beachten Sie die Verwendung von https):
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

Um den gophish-Dienst so zu erstellen, dass er automatisch gestartet und als Dienst verwaltet werden kann, können Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:
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
Konfiguriere den Dienst fertig und prüfe ihn, indem du:
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

Je älter eine Domain ist, desto geringer ist die Wahrscheinlichkeit, dass sie als Spam eingestuft wird. Daher solltest du so lange wie möglich (mindestens 1 Woche) vor der phishing assessment warten. Außerdem: Wenn du eine Seite zu einem reputablen Sektor anlegst, wird die dadurch erzielte Reputation besser sein.

Beachte, dass du selbst wenn du eine Woche warten musst, jetzt bereits alles konfigurieren kannst.

### Configure Reverse DNS (rDNS) record

Setze einen rDNS (PTR) record, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) nutzen, um deine SPF-Policy zu generieren (verwende die IP des VPS).

![](<../../images/image (1037).png>)

Dies ist der Inhalt, der in einem TXT record der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Eintrag

Du musst **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Eintrag ist, [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS TXT-Eintrag für den Hostnamen `_dmarc.<domain>` mit folgendem Inhalt erstellen:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst **für die neue Domain DKIM konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst beide B64-Werte, die der DKIM key erzeugt, aneinanderfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste die Bewertung deiner E-Mail-Konfiguration

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com) machen.\
Öffne einfach die Seite und sende eine E-Mail an die Adresse, die dir dort angezeigt wird:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Du kannst auch **deine E-Mail-Konfiguration überprüfen**, indem du eine E-Mail an `check-auth@verifier.port25.com` sendest und **die Antwort liest** (dafür musst du **Port 25 öffnen** und die Antwort in der Datei _/var/mail/root_ ansehen, wenn du die E-Mail als root sendest).\
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
Du könntest auch eine **Nachricht an ein unter deiner Kontrolle stehendes Gmail-Konto** senden und die **Header der E-Mail** in deinem Gmail-Posteingang prüfen, `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann anzeigen, ob Ihre Domain von Spamhouse blockiert wird. Sie können die Entfernung Ihrer Domain/IP hier beantragen: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Sie können die Entfernung Ihrer Domain/IP hier beantragen: [https://sender.office.com/](https://sender.office.com).

## Erstellen & Starten einer GoPhish-Kampagne

### Sending Profile

- Vergeben Sie einen **Namen zur Identifikation** des Absenderprofils
- Entscheiden Sie, von welchem Account Sie die Phishing-E-Mails senden werden. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Sie können Benutzername und Passwort leer lassen, stellen Sie aber sicher, dass die Option "Ignore Certificate Errors" aktiviert ist

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die "**Send Test Email**"-Funktion zu verwenden, um zu prüfen, ob alles funktioniert.\
> Ich empfehle, **die Test-E-Mails an 10min mails-Adressen zu senden**, um zu vermeiden, beim Testen auf Blacklists zu landen.

### E-Mail-Vorlage

- Geben Sie einen **Namen zur Identifikation** der Vorlage an
- Schreiben Sie dann einen **Betreff** (nichts Verdächtiges, etwas, das man in einer normalen E-Mail erwarten würde)
- Stellen Sie sicher, dass Sie "**Add Tracking Image**" aktiviert haben
- Schreiben Sie die **E-Mail-Vorlage** (Sie können Variablen verwenden wie im folgenden Beispiel):
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
Beachte, dass es **zur Erhöhung der Glaubwürdigkeit der E-Mail** empfohlen wird, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existente Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, **eine gültige gefundene** E-Mail zu kontaktieren und warte auf die Antwort

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing-Page

- Gib einen **Namen** an
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Weiterleitung**

![](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite anpassen und einige Tests lokal durchführen (z. B. mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Dann füge diesen HTML-Code in das Feld ein.\
> Beachte, dass du, falls du **statische Ressourcen** für das HTML (z. B. CSS- oder JS-Dateien) benötigst, diese in _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen kannst.

> [!TIP]
> Für die Weiterleitung könntest du die Nutzer auf die legitime Hauptwebseite des Opfers **umleiten**, oder sie z. B. zu _/static/migration.html_ weiterleiten, ein **Lade-Symbol (**[**https://loading.io/**](https://loading.io)**) für 5 Sekunden anzeigen und dann angeben, dass der Prozess erfolgreich war**.

### Benutzer & Gruppen

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass du für die Verwendung der Vorlage im Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Nutzers benötigst)

![](<../../images/image (163).png>)

### Kampagne

Erstelle abschließend eine Kampagne, indem du einen Namen, die Email-Vorlage, die Landing-Page, die URL, das Sending Profile und die Gruppe auswählst. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass das **Sending Profile erlaubt, eine Test-E-Mail zu senden, um zu sehen, wie die finale Phishing-E-Mail aussehen wird**:

![](<../../images/image (192).png>)

> [!TIP]
> Ich empfehle, **die Test-E-Mails an 10min mails Adressen** zu senden, um zu vermeiden, dass man beim Testen auf Blacklists landet.

Sobald alles fertig ist, starte einfach die Kampagne!

## Website klonen

Falls du aus irgendeinem Grund die Website klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumente & Dateien mit Backdoor

Bei manchen Phishing-Assessments (hauptsächlich für Red Teams) möchtest du möglicherweise auch **Dateien mit einer Backdoor** versenden (z. B. ein C2 oder etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite mit einigen Beispielen an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing & MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Website vortäuschst und die vom Benutzer eingegebenen Informationen sammelst. Leider erlauben dir diese Informationen nicht, das getäuschte Konto zu übernehmen, wenn der Benutzer das falsche Passwort eingegeben hat oder die gefälschte Anwendung mit 2FA konfiguriert ist.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) ins Spiel. Diese Tools erlauben dir, einen MitM-ähnlichen Angriff zu erzeugen. Grundsätzlich funktioniert der Angriff folgendermaßen:

1. Du **gibst das Login-Formular** der echten Webseite vor.
2. Der Benutzer **sendet** seine **Credentials** an deine gefälschte Seite und das Tool leitet diese an die echte Webseite weiter und **prüft, ob die Credentials funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fordert die MitM-Seite diese an, und sobald der **Benutzer sie eingibt**, sendet das Tool sie an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, hast du (als Angreifer) **die Credentials, die 2FA, das Cookie und alle Informationen** jeder Interaktion erfasst, während das Tool den MitM durchführt.

### Via VNC

Was, wenn du das Opfer nicht auf eine bösartige Seite mit gleichem Erscheinungsbild schickst, sondern es zu einer **VNC-Sitzung weiterleitest, in der ein Browser mit der echten Webseite verbunden ist**? Du kannst sehen, was er tut, das Passwort, die verwendete MFA, die Cookies … stehlen.\
Das kannst du mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) realisieren.

## Erkennen, ob man entdeckt wurde

Offensichtlich ist eine der besten Methoden herauszufinden, ob du enttarnt wurdest, **deine Domain in Blacklists zu suchen**. Wenn sie gelistet erscheint, wurde deine Domain als verdächtig erkannt.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain in einer Blacklist auftaucht, ist die Nutzung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch weitere Möglichkeiten zu erkennen, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten im Netz** sucht, wie in folgendem Abschnitt erklärt:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit sehr ähnlichem Namen** wie die Domain des Opfers **kaufen und/oder ein Zertifikat** für eine **Subdomain** einer von dir kontrollierten Domain **generieren**, die das **Schlüsselwort** der Domain des Opfers enthält. Wenn das **Opfer** irgendeine **DNS- oder HTTP-Interaktion** mit diesen Domains ausführt, weißt du, dass **es aktiv nach** verdächtigen Domains sucht und du sehr stealthy vorgehen musst.

### Phishing bewerten

Nutze [**Phishious** ](https://github.com/Rices/Phishious)um zu bewerten, ob deine E-Mail im Spam-Ordner landet, blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion-Teams überspringen zunehmend E-Mail-Köder und **richten ihre Angriffe direkt auf den Service-Desk / Identity-Recovery-Workflow**, um MFA zu umgehen. Der Angriff ist vollständig "living-off-the-land": Sobald der Operator gültige Anmeldeinformationen besitzt, pivotiere er mit eingebauten Admin-Tools – keine Malware ist erforderlich.

### Angriffsablauf
1. Aufklärung des Opfers
* Sammle persönliche und unternehmensbezogene Informationen von LinkedIn, Datenlecks, öffentlichem GitHub usw.
* Identifiziere hochkarätige Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help-Desk-Prozess** für Passwort-/MFA-Resets.
2. Echtzeit Social Engineering
* Ruf den Help-Desk per Telefon, Teams oder Chat an und gib dich als Zielperson aus (oft mit **gefälschtem Caller-ID** oder **klonender Stimme**).
* Gib die zuvor gesammelten PII an, um die wissensbasierte Verifizierung zu bestehen.
* Überzeuge den Agenten, das **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** auf eine registrierte Mobilnummer durchzuführen.
3. Sofortige Post-Access-Aktionen (≤60 Minuten in realen Fällen)
* Etabliere einen Fuß in der Tür über ein beliebiges Web-SSO-Portal.
* Enumeriere AD / AzureAD mit eingebauten Tools (es werden keine Binärdateien abgelegt):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale Bewegung mit **WMI**, **PsExec** oder legitimen bereits in der Umgebung whitelisti ng RMM-Agenten.

### Erkennung & Gegenmaßnahmen
* Behandle Help-Desk-Identity-Recovery als **privilegierte Operation** – erfordere Step-Up-Authentifizierung & Manager-Freigabe.
* Setze **Identity Threat Detection & Response (ITDR)** / **UEBA**-Regeln ein, die Alarm schlagen bei:
* MFA-Methode geändert + Authentifizierung von neuem Gerät / Geo.
* Sofortige Erhöhung desselben Prinzips (User → Admin).
* Nimm Help-Desk-Anrufe auf und erzwinge einen **Rückruf an eine bereits registrierte Nummer**, bevor ein Reset durchgeführt wird.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, sodass neu zurückgesetzte Konten **nicht** automatisch hochprivilegierte Tokens erhalten.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Kampagnen
Commodity-Gruppen kompensieren die Kosten für High-Touch-Operationen mit Massenangriffen, die **Suchmaschinen & Werbenetzwerke als Zustellkanal** nutzen.

1. **SEO poisoning / malvertising** pusht ein gefälschtes Ergebnis wie `chromium-update[.]site` in die obersten Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage Loader** herunter (oft JS/HTA/ISO). Beispiele, die Unit 42 gesehen hat:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies + Credential-DBs und lädt dann einen **silent loader**, der in *Echtzeit* entscheidet, ob er ausrollt:
* RAT (z. B. AsyncRAT, RustDesk)
* Ransomware / Wiper
* Persistence-Komponente (Registry Run-Key + Scheduled Task)

### Härtungstipps
* Blockiere neu registrierte Domains & implementiere **Advanced DNS / URL Filtering** sowohl für *Suchanzeigen* als auch für E-Mails.
* Beschränke Software-Installationen auf signierte MSI / Store-Pakete, verweigere die Ausführung von `HTA`, `ISO`, `VBS` per Richtlinie.
* Überwache Child-Prozesse von Browsern, die Installer starten:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

---

## KI-gestützte Phishing-Operationen
Angreifer verketten jetzt **LLM- & Voice-Clone-APIs** für vollständig personalisierte Köder und Interaktion in Echtzeit.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Verteidigung:**
• Füge **dynamische Banner** hinzu, die Nachrichten hervorheben, die von nicht vertrauenswürdiger Automation gesendet wurden (via ARC/DKIM-Anomalien).  
• Implementiere **stimm-biometrische Challenge-Phrasen** für telefonische Anfragen mit hohem Risiko.  
• Simuliere kontinuierlich KI-generierte Köder in Awareness-Programmen – statische Vorlagen sind veraltet.

Siehe auch – agentic browsing abuse für credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variante – Erzwingtes Zurücksetzen
Neben klassischem Push-Bombing erzwingen Operatoren einfach **eine neue MFA-Registrierung** während des Help-Desk-Anrufs und machen so das bestehende Token des Nutzers ungültig. Jeder nachfolgende Login-Prompt erscheint für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** **innerhalb weniger Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können stillschweigend bösartige Befehle in das Clipboard des Opfers von einer kompromittierten oder typosquatted Webseite kopieren und den Nutzer dann dazu verleiten, diese in **Win + R**, **Win + X** oder ein Terminal-Fenster einzufügen, wodurch beliebiger Code ausgeführt wird, ganz ohne Download oder Anhang.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Betreiber schotten ihre phishing-Flows zunehmend hinter einer einfachen Geräteprüfung ab, damit desktop crawlers nie die finalen Seiten erreichen. Ein typisches Muster ist ein kleines Script, das prüft, ob das DOM touch-fähig ist, und das Ergebnis an einen Server-Endpoint postet; nicht-mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Nutzern der vollständige Flow angezeigt wird.

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
Serververhalten, häufig beobachtet:
- Setzt beim ersten Laden ein Session-Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs 500 (oder Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing nur, wenn `true`.

Hunting- und Erkennungsheuristiken:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Sequenz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für nicht‑mobile; legitime mobile Zielpfade liefern 200 mit anschließendem HTML/JS.
- Seiten blockieren oder genauer prüfen, die Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Geräteprüfungen steuern.

Abwehrtipps:
- Crawler mit mobile‑ähnlichen Fingerprints und aktiviertem JS ausführen, um zugangsbeschränkte Inhalte aufzudecken.
- Alarm bei verdächtigen 500-Antworten nach `POST /detect` auf neu registrierten Domains.

## Referenzen

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
