# Phishing Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Recon des Ziels
1. Wähle die **Ziel-Domain**.
2. Führe eine grundlegende Web-Enumeration durch, **suche nach Login-Portalen** des Ziels und **entscheide**, welches du **imitieren** wirst.
3. Verwende etwas **OSINT**, um **E-Mail-Adressen zu finden**.
2. Bereite die Umgebung vor
1. **Kaufe die Domain**, die du für die Phishing-Bewertung verwenden wirst
2. **Konfiguriere die Einträge** des E-Mail-Services (SPF, DMARC, DKIM, rDNS)
3. Konfiguriere den VPS mit **gophish**
3. Bereite die Kampagne vor
1. Bereite die **E-Mail-Vorlage** vor
2. Bereite die **Webseite** vor, um Zugangsdaten abzugreifen
4. Starte die Kampagne!

## Generiere ähnliche Domainnamen oder kaufe eine vertrauenswürdige Domain

### Techniken zur Variation von Domainnamen

- **Schlüsselwort**: Der Domainname **enthält** ein wichtiges **Schlüsselwort** der Original-Domain (z. B. zelster.com-management.com).
- **Bindestrich-Subdomain**: Ersetze den **Punkt durch einen Bindestrich** einer Subdomain (z. B. www-zelster.com).
- **Neue TLD**: Dieselbe Domain mit einer **neuen TLD** (z. B. zelster.org)
- **Homoglyph**: Ersetzt einen Buchstaben im Domainnamen durch **ähnlich aussehende Zeichen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Vertauscht zwei Buchstaben im Domainnamen (z. B. zelsetr.com).
- **Singularisierung/Pluralisierung**: Fügt ein „s“ hinzu oder entfernt es am Ende des Domainnamens (z. B. zeltsers.com).
- **Auslassung**: Entfernt einen Buchstaben aus dem Domainnamen (z. B. zelser.com).
- **Wiederholung:** Wiederholt einen Buchstaben im Domainnamen (z. B. zeltsser.com).
- **Ersetzung**: Ähnlich wie Homoglyph, aber weniger subtil. Ersetzt einen Buchstaben im Domainnamen, eventuell mit einem Nachbarzeichen auf der Tastatur (z. B. zektser.com).
- **Mit Subdomain**: Füge einen **Punkt** innerhalb des Domainnamens ein (z. B. ze.lster.com).
- **Einfügung**: Fügt einen Buchstaben in den Domainnamen ein (z. B. zerltser.com).
- **Fehlender Punkt**: Hänge die TLD an den Domainnamen an (z. B. zelstercom.com)

**Automatische Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einzelne Bits, die gespeichert sind oder bei der Kommunikation verwendet werden, automatisch umkippen** — verursacht durch Faktoren wie Sonnenstürme, kosmische Strahlung oder Hardwarefehler.

Wenn dieses Konzept auf DNS-Anfragen **angewendet** wird, ist es möglich, dass die **Domain, die beim DNS-Server ankommt**, nicht identisch mit der ursprünglich angeforderten Domain ist.

Zum Beispiel kann eine einzelne Bitänderung in der Domain "windows.com" diese in "windnws.com" verändern.

Angreifer können **davon profitieren, indem sie mehrere bit-flipping Domains registrieren**, die der Domain des Ziels ähneln. Ihre Absicht ist es, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Für mehr Informationen siehe [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kaufe eine vertrauenswürdige Domain

Du kannst auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits eine gute SEO** hat, kannst du prüfen, wie sie in folgenden Diensten kategorisiert ist:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Entdecken von E-Mail-Adressen

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100% kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr gültige E-Mail-Adressen zu entdecken** oder die bereits gefundenen zu **verifizieren**, kannst du prüfen, ob du die SMTP-Server des Ziels brute-forcen kannst. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Außerdem: Vergiss nicht, dass wenn Nutzer **ein Webportal** zum Zugriff auf ihre Mails verwenden, du prüfen kannst, ob dieses gegenüber **Username-Bruteforce** verwundbar ist, und die Schwachstelle ggf. ausnutzen kannst.

## Konfiguration von GoPhish

### Installation

Du kannst es von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter und entpacke es in `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
Im Output wird dir ein Passwort für den Admin-Benutzer und der Port 3333 angezeigt. Greife auf diesen Port zu und verwende diese Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikatskonfiguration**

Vor diesem Schritt sollten Sie **die Domain bereits gekauft haben**, die Sie verwenden werden, und sie muss auf die **IP des VPS** zeigen, auf dem Sie **gophish** konfigurieren.
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

Ändere außerdem die Werte der folgenden Variablen in **/etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere schließlich die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf deinen Domainnamen und **starte deinen VPS neu.**

Erstelle nun einen **DNS A record** von `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX record**, der auf `mail.<domain>` zeigt.

Jetzt testen wir das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish Konfiguration**

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
**gophish-Service konfigurieren**

Um den gophish-Dienst so zu erstellen, dass er automatisch gestartet und als Dienst verwaltet werden kann, legen Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt an:
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
Konfiguriere den Dienst fertig und überprüfe ihn, indem du Folgendes ausführst:
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
## Konfiguration des Mailservers und der Domain

### Warten & legitim auftreten

Je älter eine Domain ist, desto unwahrscheinlicher ist es, dass sie als Spam erkannt wird. Daher sollten Sie vor der phishing-Bewertung so lange wie möglich warten (mindestens 1 Woche). Außerdem: Wenn Sie eine Seite in einem reputationsstarken Sektor erstellen, wird die erhaltene Reputation besser sein.

Beachten Sie, dass Sie, selbst wenn Sie eine Woche warten müssen, alles jetzt konfigurieren können.

### Reverse DNS (rDNS) record konfigurieren

Setzen Sie einen rDNS (PTR) record, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Sie müssen **einen SPF record für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein SPF record ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Sie können [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um Ihre SPF-Policy zu generieren (verwenden Sie die IP des VPS).

![](<../../images/image (1037).png>)

Dies ist der Inhalt, der als TXT record in der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Sie müssen **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Sie müssen einen neuen DNS TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` zeigt, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Du musst für die neue Domain **DKIM konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst beide B64-Werte, die der DKIM-Schlüssel generiert, zusammenfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste den Score deiner E-Mail-Konfiguration

Das kannst du mit [https://www.mail-tester.com/](https://www.mail-tester.com)\  
Rufe einfach die Seite auf und sende eine E-Mail an die Adresse, die sie dir nennen:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können auch **Ihre E-Mail-Konfiguration überprüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (dafür müssen Sie Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ einsehen, wenn Sie die E-Mail als root senden).\
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
Du könntest auch eine **Nachricht an ein Gmail, das du kontrollierst**, senden und die **Header der E-Mail** in deinem Gmail-Posteingang prüfen; `dkim=pass` sollte im `Authentication-Results`-Headerfeld vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Entfernung von der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann Ihnen anzeigen, ob Ihre Domain von Spamhaus blockiert wird. Sie können die Entfernung Ihrer Domain/IP unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) beantragen.

### Entfernung aus der Microsoft-Blacklist

​​Die Entfernung Ihrer Domain/IP können Sie unter [https://sender.office.com/](https://sender.office.com) beantragen.

## GoPhish-Kampagne erstellen und starten

### Sendeprofil

- Vergib einen **Namen zur Identifikation** des Absenderprofils
- Entscheide, von welchem Account du die Phishing-E-Mails verschickst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Benutzername und Passwort leer lassen, achte aber darauf, die Option Ignore Certificate Errors zu aktivieren

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu prüfen, ob alles funktioniert.\
> Ich empfehle, die **Test-E-Mails an 10min-Mail-Adressen** zu senden, um zu vermeiden, beim Testen auf eine Blacklist zu gelangen.

### E-Mail-Vorlage

- Vergib einen **Namen zur Identifikation** der Vorlage
- Schreibe dann eine **Betreffzeile** (nichts Ungewöhnliches, einfach etwas, das man in einer normalen E‑Mail erwarten würde)
- Stelle sicher, dass du '**Add Tracking Image**' angehakt hast
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
Beachte, dass **um die Glaubwürdigkeit der E-Mail zu erhöhen**, es empfohlen wird, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort irgendeine Signatur enthält.
- Suche nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und sende ihnen eine E-Mail und warte auf die Antwort.
- Versuche, **eine valide gefundene** E-Mail zu kontaktieren und warte auf die Antwort

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing-Seite

- Gib einen **Namen** ein
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Markiere **Capture Submitted Data** und **Capture Passwords**
- Setze eine **Umleitung**

![](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite anpassen und lokal testen (vielleicht mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Dann schreibe diesen HTML-Code in das Feld.\
> Beachte, dass wenn du **statische Ressourcen** für das HTML benötigst (z. B. CSS- und JS-Dateien), du sie in _**/opt/gophish/static/endpoint**_ speichern kannst und dann von _**/static/\<filename>**_ darauf zugreifst.

> [!TIP]
> Für die Umleitung könntest du **die Benutzer zur legitimen Hauptwebseite** des Opfers weiterleiten, oder sie z. B. zu _/static/migration.html_ schieben, dort ein **drehendes Rad (**[**https://loading.io/**](https://loading.io)**) für 5 Sekunden** anzeigen und dann angeben, dass der Prozess erfolgreich war.

### Users & Groups

- Vergib einen Namen
- **Importiere die Daten** (beachte, dass du für die Nutzung der Vorlage für das Beispiel den Vorname, Nachname und die E-Mail-Adresse jedes Benutzers benötigst)

![](<../../images/image (163).png>)

### Campaign

Erstelle abschließend eine Kampagne, indem du einen Namen, die E-Mail-Vorlage, die Landing-Seite, die URL, das Sending Profile und die Gruppe auswählst. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass das **Sending Profile** erlaubt, eine Test-E-Mail zu senden, um zu sehen, wie die finale Phishing-E-Mail aussehen wird:

![](<../../images/image (192).png>)

> [!TIP]
> Ich würde empfehlen, die Test-E-Mails an 10min mails Adressen zu senden, um zu vermeiden, beim Testen geblacklistet zu werden.

Wenn alles bereit ist, starte einfach die Kampagne!

## Website Cloning

Wenn du aus irgendeinem Grund die Webseite klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In einigen Phishing-Bewertungen (hauptsächlich für Red Teams) möchtest du möglicherweise auch **Dateien senden, die eine Art Backdoor enthalten** (vielleicht ein C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Sieh dir die folgende Seite für einige Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da du eine echte Webseite fälschst und die vom Benutzer eingegebenen Informationen sammelst. Leider, wenn der Benutzer das falsche Passwort eingegeben hat oder wenn die Anwendung, die du gefälscht hast, mit 2FA konfiguriert ist, **erlauben diese Informationen dir nicht, den getäuschten Benutzer zu impersonifizieren**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) ins Spiel. Dieses Tool ermöglicht es dir, einen MitM-ähnlichen Angriff zu erzeugen. Grundsätzlich funktioniert der Angriff wie folgt:

1. Du **gibst das Login-Formular** der echten Webseite vor.
2. Der Benutzer **sendet** seine **Zugangsdaten** an deine gefälschte Seite und das Tool sendet diese an die echte Webseite, um **zu prüfen, ob die Zugangsdaten funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach und sobald der **Benutzer sie eingibt**, leitet das Tool sie an die echte Webseite weiter.
4. Sobald der Benutzer authentifiziert ist, hast du (als Angreifer) **die erfassten Zugangsdaten, die 2FA, das Cookie und alle Informationen** jeder Interaktion, während das Tool den MitM durchführt.

### Via VNC

Was, wenn du den Benutzer statt auf eine bösartige Seite mit identischem Aussehen zur Originalseite auf eine **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**, schickst? Du wirst sehen können, was er tut, das Passwort stehlen, die verwendete MFA, die Cookies...\
Das kannst du mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) machen.

## Detecting the detection

Offensichtlich ist eine der besten Methoden herauszufinden, ob du entdeckt wurdest, **deine Domain in Blacklists zu suchen**. Wenn sie gelistet ist, wurde deine Domain irgendwie als verdächtig erkannt.\
Eine einfache Möglichkeit, zu prüfen, ob deine Domain in einer Blacklist erscheint, ist die Nutzung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch weitere Möglichkeiten zu erkennen, ob das Opfer **aktiv nach verdächtiger Phishing-Aktivität sucht**, wie in erklärt wird:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit einem sehr ähnlichen Namen kaufen** wie die Domain des Opfers **und/oder ein Zertifikat für eine Subdomain** einer von dir kontrollierten Domain **erstellen, das das Schlüsselwort der Domain des Opfers enthält**. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** mit ihnen durchführt, wirst du wissen, dass **es aktiv nach** verdächtigen Domains sucht und du sehr stealthy sein musst.

### Evaluate the phishing

Nutze [**Phishious** ](https://github.com/Rices/Phishious), um zu bewerten, ob deine E-Mail im Spam-Ordner landen, blockiert werden oder erfolgreich sein wird.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Angriffsgruppen umgehen zunehmend E-Mail-Locken vollständig und **zielen direkt auf den Service-Desk / Identitäts-Wiederherstellungs-Workflow**, um MFA zu umgehen. Der Angriff ist vollständig "living-off-the-land": Sobald der Operator gültige Zugangsdaten besitzt, pivotiert er mit eingebauten Admin-Tools – es ist keine Malware erforderlich.

### Attack flow
1. Recon des Opfers
* Sammle persönliche & unternehmensbezogene Details von LinkedIn, Datenlecks, öffentlichem GitHub, etc.
* Identifiziere hochwichtige Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help-Desk-Prozess** für Passwort-/MFA-Resets.
2. Echtzeit Social Engineering
* Telefon, Teams oder Chat mit dem Help-Desk, während du das Ziel impersonifizierst (oft mit **gespoofter Caller-ID** oder **kloonierter Stimme**).
* Gib die zuvor gesammelten PII an, um die wissensbasierte Verifikation zu bestehen.
* Überzeuge den Agenten, das **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** auf einer registrierten Mobilnummer durchzuführen.
3. Sofortige Post-Access-Aktionen (≤60 min in realen Fällen)
* Etabliere einen Fuß in der Tür über ein beliebiges Web-SSO-Portal.
* Enumeriere AD / AzureAD mit eingebauten Tools (keine Binärdateien ablegen):
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
* Behandle Help-Desk-Identity-Recovery als **privilegierte Operation** – erfordere Step-Up-Authentifizierung & Manager-Freigabe.
* Setze **Identity Threat Detection & Response (ITDR)** / **UEBA**-Regeln ein, die alarmieren bei:
* Änderung der MFA-Methode + Authentifizierung von neuem Gerät / Geo.
* Sofortige Erhöhung desselben Prinzips (User → Admin).
* Nimm Help-Desk-Anrufe auf und erzwinge einen **Rückruf an eine bereits registrierte Nummer**, bevor ein Reset durchgeführt wird.
* Implementiere **Just-In-Time (JIT) / Privileged Access**, sodass neu zurückgesetzte Konten **nicht** automatisch hoch-privilegierte Tokens erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-Gruppen kompensieren die Kosten für High-Touch-Operationen mit Massenangriffen, die **Suchmaschinen & Werbenetzwerke zum Lieferkanal** machen.

1. **SEO poisoning / malvertising** pusht ein gefälschtes Ergebnis wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage-Loader** herunter (oft JS/HTA/ISO). Beispiele, die Unit 42 beobachtet hat:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies + Credential-DBs, und lädt dann einen **silent loader**, der in *Echtzeit* entscheidet, ob er deployt:
* RAT (z. B. AsyncRAT, RustDesk)
* Ransomware / Wiper
* Persistence-Komponente (Registry Run-Key + Scheduled Task)

### Hardening tips
* Blockiere neu registrierte Domains & setze **Advanced DNS / URL Filtering** für *Search-Ads* sowie E-Mail durch.
* Beschränke Softwareinstallation auf signierte MSI / Store-Pakete, verweigere die Ausführung von `HTA`, `ISO`, `VBS` per Richtlinie.
* Überwache Child-Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Angreifer verketten nun **LLM- & Voice-Clone-APIs** für vollständig personalisierte Köder und Echtzeitinteraktion.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Füge **dynamische Banner** hinzu, die Nachrichten hervorheben, die von untrusted automation gesendet wurden (via ARC/DKIM-Anomalien).  
• Setze **Voice-Biometric Challenge-Phrasen** für hochriskante Telefonanfragen ein.  
• Simuliere kontinuierlich AI-generierte Köder in Awareness-Programmen – statische Vorlagen sind veraltet.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Abgesehen von klassischem Push-Bombing zwingen Operatoren einfach eine **neue MFA-Registrierung** während des Help-Desk-Anrufs, wodurch das bestehende Token des Benutzers ungültig wird. Jeder anschließende Login-Prompt erscheint für das Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Überwache AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** **innerhalb weniger Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können heimlich bösartige Befehle von einer compromised or typosquatted web page in die Zwischenablage des Opfers kopieren und den Benutzer dann dazu verleiten, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen, wodurch beliebiger Code ausgeführt wird, ohne dass etwas heruntergeladen werden muss oder ein Anhang nötig ist.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing, um crawlers/sandboxes zu umgehen
Betreiber verlagern ihre phishing-Flows zunehmend hinter eine einfache Geräteprüfung, sodass Desktop‑Crawler nie die finalen Seiten erreichen. Ein gängiges Muster ist ein kleines Skript, das prüft, ob das DOM touch-fähig ist, und das Ergebnis an ein Server-Endpoint postet; nicht‑mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Benutzern der vollständige Flow ausgeliefert wird.

Minimales Client-Snippet (typische Logik):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` Logik (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Häufig beobachtetes Server‑Verhalten:
- Setzt beim ersten Laden ein Session‑Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs 500 (oder Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing‑Inhalte nur wenn `true`.

Hunting und Erkennungsheuristiken:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web‑Telemetrie: Sequenz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für non‑mobile; legitime mobile Zielpfade geben 200 mit nachfolgendem HTML/JS zurück.
- Sperre oder überprüfe Seiten, die Inhalte ausschließlich abhängig von `ontouchstart` oder ähnlichen Geräteprüfungen anzeigen.

Verteidigungstipps:
- Führe Crawler mit mobilen Fingerprints und aktiviertem JS aus, um gated Content aufzudecken.
- Alarm bei verdächtigen 500‑Antworten nach `POST /detect` auf neu registrierten Domains.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
