# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **slagoffer domein**.
2. Voer 'n paar basiese web-opsomming **uit om aanmeldportale** te soek wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **naboots**.
3. Gebruik 'n bietjie **OSINT** om **e-posse** te **vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die phishing assessering
2. **Konfigureer die e-posdiens** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos sjabloon** voor
2. Berei die **webblad** voor om die inligting te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinnaam of koop 'n vertroude domein

### Domeinnaam Variasie Tegnieke

- **Sleutelwoord**: Die domeinnaam **bevat** 'n belangrike **sleutelwoord** van die oorspronklike domein (bv., zelster.com-management.com).
- **gehipen subdomein**: Verander die **punt in 'n hipen** van 'n subdomein (bv., www-zelster.com).
- **Nuwe TLD**: Dieselfde domein met 'n **nuwe TLD** (bv., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv., zelfser.com).
- **Transposisie:** Dit **ruil twee letters** binne die domeinnaam (bv., zelsetr.com).
- **Singularisering/Pluralisering**: Voeg of verwyder “s” aan die einde van die domeinnaam (bv., zeltsers.com).
- **Omissie**: Dit **verwyder een** van die letters uit die domeinnaam (bv., zelser.com).
- **Herhaling:** Dit **herhaal een** van die letters in die domeinnaam (bv., zeltsser.com).
- **Vervanging**: Soos homoglyph maar minder stil. Dit vervang een van die letters in die domeinnaam, dalk met 'n letter in die nabye ligging van die oorspronklike letter op die sleutelbord (bv., zektser.com).
- **Subdomein**: Introduceer 'n **punt** binne die domeinnaam (bv., ze.lster.com).
- **Invoeging**: Dit **voeg 'n letter** in die domeinnaam in (bv., zerltser.com).
- **Verlies van punt**: Voeg die TLD by die domeinnaam. (bv., zelstercom.com)

**Outomatiese Gereedskap**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een van sommige bits wat gestoor of in kommunikasie is, outomaties omgedraai kan word** as gevolg van verskeie faktore soos sonvlamme, kosmiese strale, of hardewarefoute.

Wanneer hierdie konsep **toegepas word op DNS versoeke**, is dit moontlik dat die **domein wat deur die DNS bediener ontvang word** nie dieselfde is as die domein wat aanvanklik aangevra is nie.

Byvoorbeeld, 'n enkele bit-wijziging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **voordeel trek uit hierdie deur verskeie bit-flipping domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hul bedoeling is om wettige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan soek in [https://www.expireddomains.net/](https://www.expireddomains.net) vir 'n vervalle domein wat jy kan gebruik.\
Om seker te maak dat die vervalle domein wat jy gaan koop **alreeds 'n goeie SEO het**, kan jy soek hoe dit gekategoriseer is in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdek E-posse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of **diegene** wat jy reeds ontdek het te **verifieer**, kan jy kyk of jy hulle smtp bedieners van die slagoffer kan brute-force. [Leer hoe om e-posadres hier te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Boonop, moenie vergeet dat as die gebruikers **enige webportaal gebruik om toegang tot hul e-posse te verkry**, jy kan kyk of dit kwesbaar is vir **gebruikersnaam brute force**, en die kwesbaarheid indien moontlik benut.

## Konfigureer GoPhish

### Installasie

Jy kan dit aflaai van [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en ontspan dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit.\
Jy sal 'n wagwoord vir die admin gebruiker in poort 3333 in die uitvoer ontvang. Daarom, toegang daartoe en gebruik daardie geloofsbriewe om die admin wagwoord te verander. Jy mag nodig hê om daardie poort na lokaal te tonnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS sertifikaat konfigurasie**

Voor hierdie stap moet jy **reeds die domein gekoop het** wat jy gaan gebruik en dit moet **wys** na die **IP van die VPS** waar jy **gophish** konfigureer.
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

Begin met installasie: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domein>`\
`mydestination = $myhostname, <domein>, localhost.com, localhost`

Laastens, wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A rekord** van `mail.<domein>` wat na die **ip adres** van die VPS wys en 'n **DNS MX** rekord wat na `mail.<domein>` wys.

Nou laat ons toets om 'n e-pos te stuur:
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
**Stel gophish diens op**

Om die gophish diens te skep sodat dit outomaties begin kan word en as 'n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` met die volgende inhoud skep:
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
## Konfigurasie van e-pos bediener en domein

### Wag & wees wettig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang gaan word. Dan moet jy so lank as moontlik wag (ten minste 1 week) voordat die phishing assessering plaasvind. Boonop, as jy 'n bladsy oor 'n reputasionele sektor plaas, sal die reputasie wat verkry word beter wees.

Let daarop dat selfs al moet jy 'n week wag, jy alles nou kan klaar konfigureer.

### Konfigureer Reverse DNS (rDNS) rekord

Stel 'n rDNS (PTR) rekord op wat die IP adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Rekord

Jy moet **'n SPF rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF beleid te genereer (gebruik die IP van die VPS masjien)

![](<../../images/image (1037).png>)

Dit is die inhoud wat binne 'n TXT rekord binne die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domein-gebaseerde Boodskapoutentiekering, Verslagdoening & Nakoming (DMARC) Rekord

Jy moet **'n DMARC rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC rekord is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT rekord skep wat die gasheernaam `_dmarc.<domain>` met die volgende inhoud aandui:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-record is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> Jy moet beide B64 waardes wat die DKIM-sleutel genereer, saamvoeg:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-pos konfigurasie telling

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com)\
Net toegang tot die bladsy en 'n e-pos na die adres wat hulle jou gee, te stuur:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
U kan ook **u e-poskonfigurasie nagaan** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die antwoord te lees** (vir hierdie sal u moet **oopmaak** poort **25** en die antwoord in die lêer _/var/mail/root_ sien as u die e-pos as root stuur).\
Kontroleer dat u al die toetse slaag:
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
Jy kan ook 'n **boodskap na 'n Gmail onder jou beheer** stuur, en die **e-pos se koptekste** in jou Gmail-inboks nagaan, `dkim=pass` moet teenwoordig wees in die `Authentication-Results` koptekstveld.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Verwydering van Spamhouse Swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan jou aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft Swartlys

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Campagne

### Stuurprofiel

- Stel 'n **naam om die** sender profiel te identifiseer
- Besluit vanaf watter rekening jy die phishing e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker om die Ignore Certificate Errors te merk

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> Dit word aanbeveel om die "**Stuur Toets E-pos**" funksionaliteit te gebruik om te toets of alles werk.\
> Ek sou aanbeveel om **die toets e-posse na 10min e-pos adresse te stuur** om te verhoed dat jy op 'n swartlys geplaas word tydens toetse.

### E-pos Sjabloon

- Stel 'n **naam om die** sjabloon te identifiseer
- Skryf dan 'n **onderwerp** (niks vreemd nie, net iets wat jy sou verwag om in 'n gewone e-pos te lees)
- Maak seker jy het "**Voeg Volgbeeld**" gemerk
- Skryf die **e-pos sjabloon** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
```markup
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

- Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die antwoord enige handtekening het.
- Soek na **publieke e-posse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die antwoord.
- Probeer om **'n geldige ontdekte** e-pos te kontak en wag vir die antwoord.

![](<../../images/image (80).png>)

> [!NOTE]
> Die E-pos Sjabloon laat ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-uitdagings wil steel met behulp van spesiaal saamgestelde lêers/dokumente [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf 'n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy **webbladsye kan invoer**.
- Merk **Vang ingediende data** en **Vang wagwoorde**
- Stel 'n **omleiding** in

![](<../../images/image (826).png>)

> [!NOTE]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en 'n paar toetse in plaaslike omgewing doen (miskien met 'n Apache-bediener) **tot jy hou van die resultate.** Skryf dan daardie HTML-kode in die boks.\
> Let daarop dat as jy **sommige statiese hulpbronne** vir die HTML nodig het (miskien sommige CSS en JS bladsye) jy dit in _**/opt/gophish/static/endpoint**_ kan stoor en dit dan kan benader vanaf _**/static/\<filename>**_

> [!NOTE]
> Vir die omleiding kan jy **die gebruikers na die wettige hoofwebblad** van die slagoffer omlei, of hulle na _/static/migration.html_ omlei, byvoorbeeld, 'n **draaiwiel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes plaas en dan aandui dat die proses suksesvol was**.

### Users & Groups

- Stel 'n naam in
- **Importeer die data** (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die sjabloon vir die voorbeeld te gebruik)

![](<../../images/image (163).png>)

### Campaign

Laastens, skep 'n veldtog deur 'n naam, die e-pos sjabloon, die landing page, die URL, die sending profiel en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let daarop dat die **Sending Profile toelaat om 'n toets e-pos te stuur om te sien hoe die finale phishing e-pos sal lyk**:

![](<../../images/image (192).png>)

> [!NOTE]
> Ek sou aanbeveel om **die toets e-posse na 10min e-posadresse te stuur** om te verhoed dat jy op 'n swartlys geplaas word terwyl jy toetse doen.

Sodra alles gereed is, begin net die veldtog!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing assesserings (hoofsaaklik vir Red Teams) wil jy ook **lêers stuur wat 'n soort backdoor bevat** (miskien 'n C2 of miskien net iets wat 'n verifikasie sal aktiveer).\
Kyk na die volgende bladsy vir 'n paar voorbeelde:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is redelik slim aangesien jy 'n werklike webwerf naboots en die inligting wat deur die gebruiker ingestel is, versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy naboots met 2FA geconfigureer is, **sal hierdie inligting jou nie toelaat om die misleide gebruiker na te boots nie**.

Hierdie is waar gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie gereedskap sal jou toelaat om 'n MitM-agtige aanval te genereer. Basies werk die aanvalle soos volg:

1. Jy **naboots die aanmeld** vorm van die werklike webblad.
2. Die gebruiker **stuur** sy **akkrediteer** na jou vals bladsy en die gereedskap stuur dit na die werklike webblad, **om te kyk of die akkrediteer werk**.
3. As die rekening met **2FA** geconfigureer is, sal die MitM-bladsy daarna vra en sodra die **gebruiker dit invoer**, sal die gereedskap dit na die werklike webblad stuur.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die akkrediteer, die 2FA, die koekie en enige inligting** van elke interaksie wat jy terwyl die gereedskap 'n MitM uitvoer, gevang het.

### Via VNC

Wat as jy in plaas van **die slagoffer na 'n kwaadwillige bladsy te stuur** wat dieselfde lyk as die oorspronklike, hom na 'n **VNC-sessie met 'n blaaskans wat aan die werklike webblad gekoppel is** stuur? Jy sal in staat wees om te sien wat hy doen, die wagwoord, die MFA wat gebruik word, die koekies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Dit is duidelik dat een van die beste maniere om te weet of jy betrap is, is om **jou domein in swartlyste te soek**. As dit gelys word, was jou domein op een of ander manier as verdag beskou.\
Een maklike manier om te kyk of jou domein in enige swartlys verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktief op soek is na verdagte phishingaktiwiteite in die natuur** soos verduidelik in:

{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein met 'n baie soortgelyke naam** as die slagoffer se domein **koop en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat deur jou beheer word **wat die** **sleutelwoord** van die slagoffer se domein bevat. As die **slagoffer** enige soort **DNS of HTTP-interaksie** met hulle uitvoer, sal jy weet dat **hy aktief op soek is** na verdagte domeine en jy sal baie versigtig moet wees.

### Evaluate the phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spammap gaan eindig of of dit geblokkeer gaan word of suksesvol gaan wees.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
