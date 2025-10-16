# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer basiese web-enumerasie uit deur te **soek na login portals** wat deur die slagoffer gebruik word en **besluit** watteren jy gaan **impersonate**.
3. Gebruik 'n bietjie **OSINT** om **e-posadresse te vind**.
2. Bereid die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die phishing-assessering
2. **Konfigureer die email service** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-possjabloon** voor
2. Berei die **webblad** voor om die inlogbewyse te steel
4. Lanseer die veldtog!

## Genereer soortgelyke domeinnamen of koop 'n vertroude domein

### Tegnieke vir domeinnaamvariasie

- **Sleutelwoord**: Die domeinnaam **bevat** 'n belangrike **sleutelwoord** van die oorspronklike domein (e.g., zelster.com-management.com).
- **hypened subdomain**: Verander die **punt na 'n koppelteken** van 'n subdomein (e.g., www-zelster.com).
- **New TLD**: Dieselfde domein met 'n **nuwe TLD** (e.g., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** binne die domeinnaam (e.g., zelsetr.com).
- **Singularization/Pluralization**: Voeg 'n “s” by of verwyder dit aan die einde van die domeinnaam (e.g., zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (e.g., zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (e.g., zeltsser.com).
- **Replacement**: Soortgelyk aan homoglyph maar minder stil. Dit vervang een van die letters in die domeinnaam, moontlik met 'n letter naby die oorspronklike op die sleutelbord (e.g, zektser.com).
- **Subdomained**: Voeg 'n **punt** binne die domeinnaam in (e.g., ze.lster.com).
- **Insertion**: Dit **voeg 'n letter in** die domeinnaam (e.g., zerltser.com).
- **Missing dot**: Plak die TLD aan die domeinnaam vas. (e.g., zelstercom.com)

**Outomatiese Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n moontlikheid dat een of meer bits wat gestoor is of in kommunikasie is, outomaties kan omgeskakel word as gevolg van verskeie faktore soos sonvlamme, kosmiese strale of hardeware-foute.

Wanneer hierdie konsep op DNS-versoeke toegepas word, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein wat oorspronklik versoek is nie.

Byvoorbeeld, 'n enkele bit-wysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan hiervan voordeel trek deur meerdere bit-flipping domeine te registreer wat soortgelyk is aan die slagoffer se domein. Hul doel is om wettige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan in [https://www.expireddomains.net/](https://www.expireddomains.net) soek vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **alreeds 'n goeie SEO** het, kan jy kyk hoe dit gekategoriseer word in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posadresse te ontdek of die adresse wat jy reeds ontdek het te verifieer, kan jy kyk of jy die smtp-bedieners van die slagoffer kan brute-force. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Verder, moenie vergeet dat as gebruikers 'n webportaal gebruik om hul e-pos te bereik nie, jy kan nagaan of dit kwesbaar is vir username brute force, en die kwesbaarheid uitbuit as dit moontlik is.

## Konfigureer GoPhish

### Installering

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal 'n wagwoord vir die admin-gebruiker vir poort 3333 in die uitset ontvang. Toegang tot daardie poort en gebruik daardie aanmeldbewyse om die admin-wagwoord te verander. Jy mag daardie poort na jou lokale masjien moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS sertifikaatkonfigurasie**

Voor hierdie stap behoort jy **alreeds die domein gekoop** te hê wat jy gaan gebruik en dit moet **wys na** die **IP van die VPS** waar jy **gophish** gaan konfigureer.
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
**Mail-konfigurasie**

Begin installasie: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Laastens wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** van `mail.<domain>` wat wys na die **IP-adres** van die VPS en 'n **DNS MX** rekord wat wys na `mail.<domain>`

Kom ons toets nou om 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfigurasie**

Stop die uitvoering van gophish en laat ons dit konfigureer.\
Wysig `/opt/gophish/config.json` na die volgende (let op die gebruik van https):
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
**Konfigureer gophish-diens**

Om die gophish-diens te skep sodat dit outomaties begin kan word en as 'n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` skep met die volgende inhoud:
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
Voltooi die konfigurasie van die diens en kontroleer dit deur:
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
## Konfigureer mailbediener en domein

### Wag & wees wettig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam beskou sal word. Daarom moet jy so lank as moontlik wag (ten minste 1 week) voor die phishing-assessering. Boonop, as jy 'n bladsy oor 'n reputasiesektor opstel, sal die verkrygde reputasie beter wees.

Let wel: selfs al moet jy 'n week wag, kan jy alles nou reeds konfigureer.

### Konfigureer Reverse DNS (rDNS) rekord

Stel 'n rDNS (PTR) rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) rekord

Jy moet **'n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![](<../../images/image (1037).png>)

Dit is die inhoud wat binne 'n TXT-rekord in die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domein-gebaseerde boodskapverifikasie, verslaggewing & nakoming (DMARC) rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die hostname `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer, saamvoeg:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Jy kan dit doen met [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Just access the page and send an email to the address they give you:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie kontroleer** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die reaksie te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die reaksie sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
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
Jy kan ook 'n **boodskap na 'n Gmail wat jy beheer** stuur, en die **email’s headers** in jou Gmail inbox nagaan; `dkim=pass` behoort in die `Authentication-Results` header field voor te kom.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwyder uit Spamhouse se Swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwyder uit Microsoft se Swartlys

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Veldtog

### Sending Profile

- Gee 'n **naam om die senderprofiel te identifiseer**
- Besluit vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die username en password leeg laat, maar maak seker jy merk die Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek beveel aan om **die toets-e-posse aan 10min mails adresse te stuur** om te voorkom dat jy tydens toetse op die swartlys geplaas word.

### Email Template

- Gee 'n **naam om die sjabloon te identifiseer**
- Skryf dan 'n **subject** (niks vreemd, net iets wat jy in 'n gewone e-pos sou verwag om te lees)
- Maak seker jy het "**Add Tracking Image**" gekontroleer
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
Neem kennis dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om 'n handtekening uit 'n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die antwoord enige handtekening bevat.
- Soek na **openbare e-posse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die antwoord.
- Probeer om 'n **geldig ontdekte** e-pos te kontak en wag vir die antwoord

![](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM challenges wil steel deur sommige spesiaal vervaardigde lêers/dokumente te gebruik [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Stel 'n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webbladsye kan **invoer**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel 'n **herleiding** op

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en toetse lokaal moet doen (miskien deur 'n Apache-bediener te gebruik) **tot jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die boks.\
> Let daarop dat as jy **sommige statiese hulpbronne** vir die HTML nodig het (miskien sommige CSS- en JS-bladsye) jy dit kan stoor in _**/opt/gophish/static/endpoint**_ en dit dan kan benader vanaf _**/static/\<filename>**_

> [!TIP]
> Vir die herleiding kan jy die gebruikers na die regmatige hoofwebblad van die slagoffer herlei, of herlei na _/static/migration.html_ byvoorbeeld; sit 'n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Users & Groups

- Stel 'n naam
- **Importeer die data** (let daarop dat om die sjabloon vir die voorbeeld te gebruik jy die voornaam, van en e-posadres van elke gebruiker nodig het)

![](<../../images/image (163).png>)

### Campaign

Skep uiteindelik 'n veldtog deur 'n naam, die Email Template, die Landing Page, die URL, die Sending Profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word

Let daarop dat die **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek beveel aan om **die toets-e-posse na 10min mails-adresse te stuur** om te voorkom dat jy tydens toetse op 'n swartlys beland.

Sodra alles gereed is, begin net die veldtog!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) wil jy ook **lêers stuur wat 'n soort backdoor bevat** (miskien 'n C2 of miskien net iets wat 'n verifikasie sal aktiveer).\
Kyk na die volgende bladsy vir 'n paar voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is nogal slim omdat jy 'n werklike webwerf naboots en die inligting wat deur die gebruiker ingevoer is versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die mislei gebruiker te verpersoonlik nie**.

Hier is waar gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie instrument sal jou toelaat om 'n MitM-agtige aanval te genereer. Basies werk die aanval soos volg:

1. Jy **doen voor as die login-formulier** van die werklike webblad.
2. Die gebruiker **stuur** sy **inlogbesonderhede** na jou valse blad en die instrument stuur dit na die werklike webblad, en **kontroleer of die inlogbesonderhede werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarna vra en sodra die **gebruiker dit invoer** sal die instrument dit na die werklike webblad stuur.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die inlogbesonderhede, die 2FA, die cookie en enige inligting** van elke interaksie vasgelê het terwyl die instrument 'n MitM uitvoer.

### Via VNC

Wat as jy in plaas daarvan om die slagoffer na 'n kwaadwillige blad te stuur met dieselfde voorkoms as die oorspronklike, hom na 'n **VNC-sessie met 'n blaaier wat aan die werklike webblad gekoppel is** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Een van die beste maniere om te weet of jy ontdek is, is om jou domein in swartlyste te **soek**. As dit gelys verskyn, is jou domein op een of ander manier as verdag opgespoor.\
'n Maklike manier om te kyk of jou domein in enige swartlys verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktiwiteit aktief na verdagte phishing-aktiwiteit soek** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein koop met 'n baie soortgelyke naam** aan die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat deur jou beheer word **wat die sleutelwoord van die slagoffer se domein bevat**. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** met hulle uitvoer, sal jy weet dat **hy aktief na verdagte domeine soek** en sal jy baie stil en versigtig moet wees.

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam-gids gaan eindig of of dit geblokkeer of suksesvol gaan wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne inbraakstelle slaan toenemend e-pos lokvalle uit en **rig direk op die service-desk / identity-recovery-werkvloei** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operateur geldige inlogbesonderhede besit, draai hulle met ingeboude administratiewe gereedskap – geen malware is nodig nie.

### Attack flow
1. Recon die slagoffer
* Versamel persoonlike & korporatiewe besonderhede van LinkedIn, datalekke, openbare GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende beamptes, IT, finansies) en som die **presiese help-desk proses** vir wagwoord / MFA-herstel op.
2. Reële-tyd sosiale ingenieurswese
* Bel, gebruik Teams of chat die help-desk terwyl jy die teiken nadoen (dikwels met 'n **gespoofte oproeper-ID** of 'n **gekloneerde stem**).
* Verskaf die vooraf-versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oorred die agent om die **MFA-geheim terug te stel** of 'n **SIM-swap** op 'n geregistreerde mobiele nommer uit te voer.
3. Onmiddellike post-toegangsaksies (≤60 min in werklike gevalle)
* Vestig 'n voet tussen die deur deur enige web SSO-portaal.
* Enumereer AD / AzureAD met ingeboude gereedskap (geen binaries word neergelê nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec**, of geldige **RMM**-agente wat reeds op die witlys in die omgewing is.

### Detection & Mitigation
* Behandel help-desk identity recovery as 'n **bevoorregte operasie** – vereis step-up-verifikasie & bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku op:
* MFA-metode verander + verifikasie vanaf 'n nuwe toestel / geo.
* Onmiddellike opgradering van dieselfde prinsipaal (user-→-admin).
* Neem help-desk oproepe op en afdwing 'n **terugbel na 'n reeds-geregistreerde nommer** voor enige herstel.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-herstelde rekeninge **nie** outomaties hoë-privilegie tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Kommersiële groepe balanseer die koste van hoë-touch operasies met massale aanvalle wat **soekenjins & advertensienetwerke in 'n afleweringskanaal omskep**.

1. **SEO poisoning / malvertising** druk 'n valse resultaat soos `chromium-update[.]site` na die top van soekadvertensies.
2. Die slagoffer laai 'n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde waargeneem deur Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Die loader voer browser-cookies + credential DBs uit, en haal dan 'n **silent loader** wat beslis – *in realtime* – of dit gaan ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokkeer pas-geregistreerde domeine & handhaaf **Advanced DNS / URL Filtering** op *soekadvertensies* sowel as e-pos.
* Beperk sagteware-installasie tot ondertekende MSI / Store-pakkette, weier die uitvoering van `HTA`, `ISO`, `VBS` volgens beleid.
* Monitor vir child processes van blaaier wat installateurs open:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jaag op LOLBins wat gereeld deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokvalle en reële-tyd interaksie.

| Laag | Voorbeeldgebruik deur bedreigingsaktor |
|------|----------------------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS met gerandomiseerde bewoording & tracking-skakels.|
|Generative AI|Skep *eenmalige* e-posse wat openbare M&A, binnenshuise grappe vanaf sosiale media verwys; deep-fake CEO-stem in terugbel-bedrog.|
|Agentic AI|Regautonomies registreer domeine, skraap open-source intelligensie, skryf volgende-stage e-posse wanneer 'n slagoffer klik maar nie inlogbesonderhede indien nie.|

**Verdediging:**
• Voeg **dinamiese banier** by wat boodskappe beklemtoon wat vanaf onbetroubare outomatisering gestuur is (via ARC/DKIM-afwykings).
• Ontplooi **stem-biometriese uitdagingfrases** vir hoë-risiko telefoonaansoeke.
• Simuleer deurlopend AI-gegenereerde lokvalle in bewusmakingsprogramme – statiese sjablone is verouderd.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, dwing operateurs eenvoudig 'n **nuwe MFA-registrasie af** tydens die help-desk oproep, wat die gebruiker se bestaande token nietig maak. Enige daaropvolgende aanmeldprompt lyk vir die slagoffer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Moniteer AzureAD/AWS/Okta-geleenthede waar **`deleteMFA` + `addMFA`** **binne minute vanaf dieselfde IP** plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte na die slagoffer se knipbord kopieer vanaf 'n gekompromitteerde of typosquatted webblad en dan die gebruiker mislei om dit in **Win + R**, **Win + X** of 'n terminalvenster te plak, waardeur willekeurige kode uitgevoer word sonder enige aflaai of aanhangsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing om crawlers/sandboxes te omseil
Operateurs plaas toenemend hul phishing-vloei agter 'n eenvoudige toestelkontrole sodat desktop crawlers nooit die finale bladsye bereik nie. 'n Algemene patroon is 'n klein skrip wat toets vir 'n touch-capable DOM en die resultaat na 'n server endpoint stuur; nie-mobiele kliënte ontvang HTTP 500 (of 'n leë bladsy), terwyl mobiele gebruikers die volledige vloei bedien word.

Minimale kliënt-snippet (tipiese logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (vereenvoudigde):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Bedieneroptrede wat dikwels waargeneem word:
- Stel 'n session cookie in tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of 'n plekhouer) terug op daaropvolgende GETs wanneer `is_mobile=false`; bedien phishing slegs as dit `true` is.

Opsporing- en deteksie-heuristieke:
- urlscan navraag: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiele; legitieme mobiele slagofferpaaie gee 200 terug met vervolg-HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik laat afhang van `ontouchstart` of soortgelyke toestelkontroles.

Verdedigingswenke:
- Voer crawlers uit met mobiele-agtige fingerprints en JS aangeskakel om toegangsgereguleerde inhoud te openbaar.
- Waarsku oor verdagte 500-antwoorde wat volg op `POST /detect` op pas-gedregeerde domeine.

## Verwysings

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
