# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer basiese web-ontleding uit deur **na aanmeldportale te soek** wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **voordoen as**.
3. Gebruik 'n bietjie **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die phishing-assessering
2. **Konfigureer die e-posdiens** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-possjabloon** voor
2. Berei die **webblad** voor om die inlogbewyse te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop 'n vertroude domein

### Tegnieke vir domeinnaamvariasie

- **Keyword**: Die domeinnaam **bevat** 'n belangrike **sleutelwoord** van die oorspronklike domein (e.g., zelster.com-management.com).
- **hypened subdomain**: Vervang die **punt** met 'n **koppelteken** in 'n subdomein (e.g., www-zelster.com).
- **New TLD**: Dieselfde domein wat 'n **nuwe TLD** gebruik (e.g., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters om** in die domeinnaam (e.g., zelsetr.com).
- **Singularization/Pluralization**: Voeg of verwyder “s” aan die einde van die domeinnaam (e.g., zeltsers.com).
- **Omission**: Dit verwyder een van die letters uit die domeinnaam (e.g., zelser.com).
- **Repetition:** Dit herhaal een van die letters in die domeinnaam (e.g., zeltsser.com).
- **Replacement**: Soortgelyk aan homoglyph, maar minder sluipend. Dit vervang een van die letters in die domeinnaam, dalk met 'n letter wat naby die oorspronklike op die sleutelbord is (e.g., zektser.com).
- **Subdomained**: Voeg 'n **punt** binne die domeinnaam in (e.g., ze.lster.com).
- **Insertion**: Dit **voeg 'n letter in** die domeinnaam in (e.g., zerltser.com).
- **Missing dot**: Hang die TLD aan die einde van die domeinnaam sonder die punt (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een of meer bits wat gestoor is of in kommunikasie is outomaties omgeskakel kan word** as gevolg van verskeie faktore soos sonvlamme, kosmiese strale, of hardeware-foute.

Wanneer hierdie konsep op **DNS-versoeke toegepas** word, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein wat aanvanklik gevra is nie.

Byvoorbeeld, 'n enkele bit-wysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **hierdie voordeel benut deur meerdere bit-flipping-domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hul bedoeling is om regmatige gebruikers na hul eie infrastruktuur om te lei.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan in [https://www.expireddomains.net/](https://www.expireddomains.net) soek vir 'n verloopte domein wat jy kan gebruik.\
Om seker te maak dat die verloopte domein wat jy gaan koop **reeds 'n goeie SEO het**, kan jy kyk hoe dit gekategoriseer is in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdek e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posadresse te **ontdek** of die wat jy reeds gevind het te **verifieer**, kan jy kyk of jy hul SMTP-bedieners van die slagoffer kan brute-force. [Leer hoe om e-posadresse te verifieer/ontdek hier](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Bovendien, moenie vergeet dat as gebruikers **enige webportaal gebruik om toegang tot hul e-posse te kry**, jy kan kontroleer of dit vatbaar is vir **username brute force**, en die kwesbaarheid misbruik indien moontlik.

## Konfigurasie van GoPhish

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal 'n wagwoord vir die admin-gebruiker in die uitset op poort 3333 kry. Daarom, kry toegang tot daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag daardie poort na lokaal moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap moet jy **reeds die domein gekoop het** wat jy gaan gebruik, en dit moet **wys na** die **IP van die VPS** waar jy **gophish** konfigureer.
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
**E-poskonfigurasie**

Begin installasie: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Laastens wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** vir `mail.<domain>` wat wys na die **IP-adres** van die VPS en 'n **DNS MX** record wat wys na `mail.<domain>`

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
## Konfigurasie van e-posbediener en domein

### Wag & wees geloofwaardig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam aangemerk sal word. Wag dus so lank as moontlik (ten minste 1 week) voor die phishing assessment. Boonop, as jy 'n bladsy oor 'n reputasie-verwante sektor plaas, sal die verkrygde reputasie beter wees.

Let daarop dat selfs al moet jy 'n week wag, jy nou alles kan klaarmaak.

### Konfigureer Reverse DNS (rDNS) rekord

Stel 'n rDNS (PTR) rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Rekord

Jy moet **'n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF-rekord is nie [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![](<../../images/image (1037).png>)

Dit is die inhoud wat in 'n TXT-rekord in die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domeingebaseerde boodskapverifikasie, verslaggewing & nakoming (DMARC) Rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasheernaam `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-record is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet beide B64-waardes wat die DKIM-sleutel genereer aanmekaar koppel:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasie telling

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com)\
Besigtig net die bladsy en stuur 'n e-pos na die adres wat hulle jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **kontroleer jou email-konfigurasie** deur 'n email te stuur na `check-auth@verifier.port25.com` en **die reaksie te lees** (hiervoor sal jy port **25** moet **oopmaak** en die reaksie sien in die lêer _/var/mail/root_ as jy die email as root stuur).\
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
Jy kan ook 'n **boodskap na 'n Gmail wat jy beheer** stuur en die **e-pos se headers** in jou Gmail-inboks nagaan; `dkim=pass` moet in die `Authentication-Results` header field voorkom.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwyder uit Spamhouse Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein geblokkeer word deur spamhouse. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwyder uit Microsoft Blacklist

Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Veldtog

### Stuurprofiel

- Stel 'n **naam** om die afsenderprofiel te identifiseer
- Bepaal vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy die Ignore Certificate Errors merk

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek sou aanbeveel om **send the test emails to 10min mails addresses** om te voorkom dat jy tydens toetse op 'n blacklist beland.

### E-pos Sjabloon

- Stel 'n **naam om te identifiseer** die sjabloon
- Skryf dan 'n **onderwerp** (niks vreemd, net iets wat jy in 'n gewone e-pos sou verwag om te lees)
- Maak seker jy het die "**Add Tracking Image**" aangestip
- Skryf die **e-pos sjabloon** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
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

- Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die reaksie enige handtekening bevat.
- Soek na **publieke e-posadresse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die reaksie.
- Probeer kontak maak met **'n geldige ontdekte** e-pos en wag vir die reaksie

![](<../../images/image (80).png>)

> [!TIP]
> Die E-possjabloon laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-challenges wil steel deur sommige spesiaalgemaakte lêers/dokumente te gebruik [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Stel 'n **naam** in
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webbladsye kan **importeer**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel 'n **omleiding** in

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en toetse plaaslik doen (miskien met 'n Apache-server) **tot jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die boks.\
> Let daarop dat as jy sommige **statiese hulpbronne** vir die HTML moet gebruik (miskien sommige CSS- en JS-bladsye) jy dit kan stoor in _**/opt/gophish/static/endpoint**_ en dan toegang kry vanaf _**/static/\<filename>**_

> [!TIP]
> Vir die omleiding kan jy **gebruikers na die regte hoofblad** van die slagoffer omlei, of hulle na _/static/migration.html_ omlei byvoorbeeld, plaas 'n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Users & Groups

- Stel 'n naam in
- **Importeer die data** (let wel dat om die sjabloon vir die voorbeeld te gebruik jy die voornaam, van en e-posadres van elke gebruiker nodig het)

![](<../../images/image (163).png>)

### Campaign

Uiteindelik, skep 'n veldtog deur 'n naam, die e-possjabloon, die landing page, die URL, die sending profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat na die slagoffers gestuur word

Let daarop dat die **Sending Profile toelaat om 'n toets-e-pos te stuur om te sien hoe die finale phishing e-pos sal lyk**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek beveel aan om die **toets-e-posse na 10min mails adresse** te stuur om te voorkom dat jy vir toetse op 'n swartlys beland.

Sodra alles gereed is, lanseer net die veldtog!

## Website Cloning

As jy om een of ander rede die webwerf wil kloon kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) wil jy ook **lêers stuur wat 'n soort backdoor bevat** (miskien 'n C2 of net iets wat 'n verifikasie sal aktiveer).\
Kyk na die volgende bladsy vir sommige voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is baie slim aangesien jy 'n werklike webwerf naboots en die inligting wat deur die gebruiker ingevul is versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingee nie of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, sal **daardie inligting jou nie toelaat om die mislei gebruiker te imiteer nie**.

Dit is waar gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie instrumente laat jou toe om 'n MitM-agtige aanval te genereer. Basies werk die aanval op die volgende wyse:

1. Jy **maskeer die login-formulier** van die werklike webblad.
2. Die gebruiker **stuur** sy **credentials** na jou vervalste bladsy en die instrument stuur dit na die werklike webblad, **kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra en sodra die **gebruiker dit invoer** sal die instrument dit na die werklike webblad stuur.
4. Sodra die gebruiker geauthentiseer is, sal jy (as aanvaller) **die gekapte credentials, die 2FA, die cookie en enige inligting** van elke interaksie hê terwyl die instrument die MitM uitvoer.

### Via VNC

Wat as jy in plaas daarvan om **die slagoffer na 'n kwaadwillige bladsy te stuur** met dieselfde voorkoms as die oorspronklike, hom na 'n **VNC-sessie met 'n blaaier wat aan die werklike webblad gekoppel is** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die MFA gebruik, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Een van die beste maniere om te weet of jy ontmasker is, is om **jou domein in swartlyste te soek**. As dit gelys is, is jou domein op een of ander manier as verdag aangeteken.\
'n Maklike manier om te kontroleer of jou domein in enige swartlys verskyn is om [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die slagoffer **aktiwiteit soek na verdagte phishing in die wild** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein met 'n baie soortgelyke naam koop** as die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat jy beheer **wat die sleutelwoord** van die slagoffer se domein bevat. As die **slagoffer** enige vorm van **DNS of HTTP-interaksie** met hulle uitvoer, sal jy weet dat **hy aktief kyk** na verdagte domeine en jy sal baie stil moet wees.

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam-vou/ folder gaan beland of of dit geblokkeer of suksesvol sal wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne indringingsettings slaan toenemend e-poslokkies heeltemal oor en **teiken direk die service-desk / identity-recovery werkstroom** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operateur geldige credentials besit, pivot hulle met ingeboude admin-gereedskap – geen malware is nodig nie.

### Attack flow
1. Recon the victim
* Versamel persoonlike en korporatiewe besonderhede van LinkedIn, data breaches, openbare GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende, IT, finansies) en enumereer die **presiese help-desk proses** vir wagwoord / MFA-hersetting.
2. Real-time social engineering
* Bel, gebruik Teams of klets die help-desk terwyl jy die teiken imiteer (dikwels met **gespoofte caller-ID** of **gekloonde stem**).
* Verskaf die vooraf-versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oorred die agent om die **MFA-geheim te reset** of 'n **SIM-swap** op 'n geregistreerde mobiele nommer uit te voer.
3. Immediate post-access actions (≤60 min in real cases)
* Vestig 'n voet in enige web SSO-portal.
* Enumereer AD / AzureAD met ingeboude hulpmiddels (geen binaries word afgelaai nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec**, of regmatige **RMM** agents wat reeds op die witlys in die omgewing is.

### Detection & Mitigation
* Behandel help-desk identity recovery as 'n **geprivilegieerde operasie** – vereis step-up auth & bestuurder goedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku oor:
* MFA-metode verander + verifikasie vanaf nuwe toestel / geo.
* Onmiddellike verhoging van dieselfde prinsipal (user → admin).
* Neem help-desk oproepe op en afdwing 'n **terugbel na 'n reeds- geregistreerde nommer** voordat enige reset plaasvind.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-geresette rekeninge **nie** outomaties hoë-privaatheids-tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Kommoditeits groepe kompenseer die koste van hoog-aanraking operasies met massa-aanvalle wat **soekenjins & advertensienetwerke in die afleweringskanaal omskep**.

1. **SEO poisoning / malvertising** druk 'n vervalste resultaat soos `chromium-update[.]site` na die top soekadvertensies.
2. Slagoffer laai 'n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde gesien deur Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltreer blaaier-cookies + credential DBs, en trek dan 'n **silent loader** wat besluit – *in reële tyd* – of dit gaan ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistentie-komponent (registry Run key + scheduled task)

### Hardening tips
* Blokkeer pas-ged registreerde domeine & afdwing **Advanced DNS / URL Filtering** op *search-ads* sowel as e-pos.
* Beperk sagteware-installasie tot ondertekende MSI / Store-pakkette, weier `HTA`, `ISO`, `VBS` uitvoering deur beleid.
* Monitor vir kind-prosesse van blaaiers wat installateurs open:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jaag LOLBins wat gereeld misbruik word deur first-stage loaders (bv. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokmiddels en reële-tyd interaksie.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Genereer & stuur >100k e-posse / SMS met gerandomiseerde bewoording & volgskakels.|
|Generative AI|Skep *eenmalige* e-posse wat na publieke M&A verwys, binnejokes van sosiale media; deep-fake CEO-stem in terugbelbedrog.|
|Agentic AI|Registreer outonoom domeine, skraap open-source intel, skryf volgende-trap e-posse wanneer 'n slagoffer klik maar nie creds indien nie.|

**Verdediging:**
• Voeg **dinamiese baniere** by wat boodskappe wat deur onbetroubare automasie gestuur is beklemtoon (via ARC/DKIM anomalieë).  
• Ontplooi **stem-biometriese uitdaging-frasies** vir hoog-risiko telefoonversoeke.  
• Simuleer voortdurend AI-gegenereerde lokmiddels in bewustheidsprogramme – statiese sjablone is verouderd.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, dwing operateurs eenvoudig **'n nuwe MFA-registrasie af** tydens die help-desk oproep, wat die gebruiker se bestaande token ongeldig maak. Enige daaropvolgende aanmeldprompt lyk vir die slagoffer eg.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Moniteer vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** binne minute vanaf dieselfde IP plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte na die slagoffer se knipbord kopieer vanaf 'n gekompromitteerde of typosquatted webblad, en dan die gebruiker mislei om dit in te plak binne **Win + R**, **Win + X** of 'n terminalvenster, waardeur willekeurige kode uitgevoer word sonder enige aflaai of aanhangsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Verwysings

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
