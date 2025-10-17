# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **victim domain**.
2. Voer basiese web-enumerasie uit deur **na login-portale te soek** wat deur die slagoffer gebruik word en **besluit** watter een jy gaan **imiter**.
3. Gebruik OSINT om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy vir die phishing-assessering gaan gebruik
2. **Konfigureer die email service** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **email template** voor
2. Berei die **web page** om die credentials te steel
4. Lans die veldtog!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Die domeinnaam **bevat** ’n belangrike **keyword** van die oorspronklike domein (bv. zelster.com-management.com).
- **hypened subdomain**: Vervang die **punt met 'n koppelteken'** in ’n subdomein (bv. www-zelster.com).
- **New TLD**: Dieselfde domein met ’n **nuwe TLD** (bv. zelster.org)
- **Homoglyph**: Dit **vervang** ’n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** binne die domeinnaam (bv. zelsetr.com).
- **Singularization/Pluralization**: Voeg ’n “s” by of verwyder dit aan die einde van die domeinnaam (bv. zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
- **Replacement**: Soortgelyk aan homoglyph maar minder stil. Dit vervang een van die letters in die domeinnaam, dalk met ’n letter naby die oorspronklike op die sleutelbord (bv. zektser.com).
- **Subdomained**: Voeg ’n **punt** binne die domeinnaam in (bv. ze.lster.com).
- **Insertion**: Dit **voeg ’n letter in** in die domeinnaam (bv. zerltser.com).
- **Missing dot**: Voeg die TLD aan die domeinnaam vas. (bv. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is ’n **moontlikheid dat een van die bis wat gestoor of in kommunikasie gebruik word outomaties kan omskakel** weens verskeie faktore soos sonvlamme, kosmiese strale of hardeware-foute.

Wanneer hierdie konsep **op DNS-versoeke toegepas** word, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein oorspronklik versoek nie.

Byvoorbeeld, ’n enkel bis-modifikasie in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **gebruik maak van dit deur meerdere bit-flipping-domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hul bedoeling is om regsmatige gebruikers na eie infrastruktuur om te lei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Jy kan in [https://www.expireddomains.net/](https://www.expireddomains.net) soek vir ’n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds goeie SEO het** kan jy kyk hoe dit gekategoriseer is by:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posadresse te **ontdek** of om die wat jy reeds gevind het te **verifieer**, kan jy kyk of jy dit kan brute-force teen die victim se SMTP-bedieners. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Verder, moenie vergeet nie dat as gebruikers **enige webportaal gebruik om hul e-posse te bereik**, jy kan kontroleer of dit kwesbaar is vir **username brute force**, en die kwesbaarheid benut indien moontlik.

## Konfigurasie van GoPhish

### Installasie

Jy kan dit aflaai van [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit.\
Jy sal ’n wagwoord vir die admin-gebruiker in die uitvoer vir poort 3333 ontvang. Toegang tot daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag die poort na lokaal moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

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
**E-poskonfigurasie**

Begin die installasie: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Uiteindelik wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** van `mail.<domain>` wat na die **ip address** van die VPS wys en 'n **DNS MX** record wat na `mail.<domain>` wys

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

Om die gophish service te skep sodat dit outomaties gestart en as 'n service bestuur kan word, kan jy die lêer `/etc/init.d/gophish` skep met die volgende inhoud:
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
## Konfigureer e-posbediener en domein

### Wag & wees geloofwaardig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang sal word. Jy moet dus so lank as moontlik wag (ten minste 1 week) voor die phishing-assessering. Verder, as jy 'n blad oor 'n reputasionele sektor plaas, sal die verkrygde reputasie beter wees.

Neem kennis dat selfs al moet jy 'n week wag, jy alles nou reeds kan klaar konfigureer.

### Konfigureer Reverse DNS (rDNS) rekord

Stel 'n rDNS (PTR)-rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Rekord

Jy moet **'n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF-rekord is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![](<../../images/image (1037).png>)

Dit is die inhoud wat binne 'n TXT-rekord in die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domeingebaseerde Boodskapverifikasie, Verslagdoening en Nakoming (DMARC) Rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasheernaam `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer, aaneenskakel:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Gaan net na die bladsy en stuur 'n e-pos na die adres wat hulle vir jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en die **antwoord te lees** (hiervoor sal jy **poort** **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ sien as jy die e-pos as root stuur).\
Kontroleer dat jy vir al die toetse slaag:
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
Jy kan ook 'n **boodskap na 'n Gmail wat jy beheer** stuur, en die **email’s headers** in jou Gmail-inboks nagaan, `dkim=pass` behoort in die `Authentication-Results` header field voor te kom.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwydering uit Spamhouse Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering uit Microsoft Blacklist

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Campaign

### Stuurprofiel

- Stel 'n **naam om die senderprofiel te identifiseer**
- Besluit vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy die "Ignore Certificate Errors" merk

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek beveel aan om **die toets-e-posse na 10min mails-adresse te stuur** om te voorkom dat jy tydens toetse op 'n swartlys beland.

### E-possjabloon

- Stel 'n **naam om die sjabloon te identifiseer**
- Skryf dan 'n **subject** (niks vreemd, net iets wat jy sou verwag om in 'n gewone e-pos te lees)
- Maak seker jy het "**Add Tracking Image**" gemerk
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
Let wel dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om ’n handtekening van ’n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur ’n e-pos na ’n **nie-bestaande adres** en kyk of die reaksie enige handtekening het.
- Soek na **openbare e-posadresse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle ’n e-pos en wag vir die reaksie.
- Probeer om **’n geldige ontdekte** e-pos te kontak en wag vir die reaksie.

![](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM challenges wil steel deur sekere spesiaal-gerigte lêers/dokumente te gebruik [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Gee ’n **naam**
- **Skryf die HTML-kode** van die webblad. Let wel dat jy webbladsye kan **invoer**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel ’n **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en plaaslike toetse doen (dalk met ’n Apache server) **tot jy tevrede is met die resultate.** Skryf daardie HTML-kode dan in die blokkie.\
> Let wel dat as jy sekere **statiese hulpbronne** vir die HTML nodig het (dalk CSS en JS bladsye) jy dit in _**/opt/gophish/static/endpoint**_ kan stoor en dan vanaf _**/static/\<filename>**_ toegang kry.

> [!TIP]
> Vir die omleiding kan jy die gebruikers **herlei na die regte hoofblad** van die teiken, of hulle na _/static/migration.html_ stuur byvoorbeeld, sit ’n **spinner (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Users & Groups

- Gee ’n naam
- **Importeer die data** (let wel dat om die template as voorbeeld te gebruik jy die voornaam, van en e-posadres van elke gebruiker nodig het)

![](<../../images/image (163).png>)

### Campaign

Uiteindelik, skep ’n kampanje deur ’n naam, die email template, die landing page, die URL, die sending profile en die groep te kies. Let wel dat die URL die skakel sal wees wat aan die slagoffers gestuur word.

Let wel dat die **Sending Profile toelaat om ’n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek raai aan om **toets-e-posse na 10min mails adresse** te stuur om te verhoed dat jy geblokkeer word tydens toetse.

Sodra alles gereed is, begin net die kampanje!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk die volgende bladsy:

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) wil jy ook **lêers stuur wat ’n soort backdoor bevat** (dalk ’n C2 of iets wat net ’n verifikasie sal aktiveer).\
Kyk na die volgende bladsy vir voorbeelde:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is baie slim aangesien jy ’n regte webblad naboots en die inligting wat die gebruiker instel versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, sal **daardie inligting jou nie toelaat om die gevanggemaakte gebruiker te imiteer nie**.

Hier kom gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) van pas. Hierdie gereedskap laat jou ’n MitM-agtige aanval genereer. Basies werk die aanval soos volg:

1. Jy **nim die login** vorm van die regte webblad aan.
2. Die gebruiker **stuur** sy **credentials** na jou valse bladsy en die gereedskap stuur dit aan die regte webblad, **kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy dit vra en sodra die **gebruiker dit invoer**, stuur die gereedskap dit aan die regte webblad.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die credentials, die 2FA, die cookie en enige inligting** van elke interaksie gekap het terwyl die gereedskap die MitM uitvoer.

### Via VNC

Wat as jy in plaas daarvan om die slagoffer na ’n kwaadwillige bladsy met die selfde voorkoms te stuur, hom na ’n **VNC-sessie met ’n blaaier wat by die regte webblad aangemeld is** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Een van die beste maniere om te weet of jy uitgekrap is, is om jou domein in swartlyste te **soek**. As dit gelys verskyn, is jou domein om ’n of ander rede as verdag opgespoor.\
Een maklike manier om te kyk of jou domein in ’n swartlys verskyn is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die teiken **aktief soek na verdagte phishing-aktiwiteit in die veld**, soos verduidelik in:

{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **’n domein koop met ’n baie soortgelyke naam** aan die teiken se domein **en/of ’n sertifikaat genereer** vir ’n **subdomein** van ’n domein wat jy beheer **wat die sleutelwoord van die teiken se domein bevat**. As die **teiken** enige tipe **DNS of HTTP-interaksie** met hulle uitvoer, sal jy weet dat **hy aktief soek** na verdagte domeine en jy sal baie stil moet optree.

### Evaluate the phishing

Gebruik [**Phishious**](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam-lêer gaan eindig of geblokkeer of suksesvol sal wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne indringingsversamelings slaan toenemend e-pos-lokmiddels oor en **teiken direk die service-desk / identity-recovery werkvloei** om MFA te omseil. Die aanval is volledig “living-off-the-land”: sodra die operateur geldige credentials het, draai hulle met ingeboude admin-gereedskap – geen malware word vereis nie.

### Attack flow
1. Rekognosering van die teiken
* Versamel persoonlike & korporatiewe besonderhede van LinkedIn, data breaches, publieke GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende beams, IT, finansies) en enumereer die **precieze help-desk proses** vir wagwoord / MFA reset.
2. Regstreekse sosiale ingenieurswese
* Bel, gebruik Teams of chat die help-desk terwyl jy die teiken naboots (dikwels met **gespoofte caller-ID** of **gekloneerde stem**).
* Verskaf die vooraf-versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA secret te reset** of ’n **SIM-swap** op ’n geregistreerde mobiele nommer uit te voer.
3. Onmiddellike post-toegang aksies (≤60 min in regte gevalle)
* Vestig ’n voetdeur via enige web SSO-portaal.
* Enumereer AD / AzureAD met ingeboude hulpmiddels (geen binaries word gedrop nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec**, of wettige **RMM** agents wat reeds in die omgewing op die witlys staan.

### Detection & Mitigation
* Behandel help-desk identity recovery as ’n **bevoorregte operasie** – vereis stap-op-auth & bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku op:
* MFA-metode verander + verifikasie vanaf ’n nuwe toestel / geo.
* Onmiddellike verhoging van dieselfde hoofkarakter (user → admin).
* Neem help-desk oproepe op en dwing ’n **terugbel na ’n reeds-geregistreerde nommer** voor enige reset.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat pas-geresette rekeninge nie outomaties hoog-privilege tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-groepe balanseer die koste van high-touch operasies met massa-aanvalle wat **soekenjins & advertensienetwerke as die afleweringskanaal gebruik**.

1. **SEO poisoning / malvertising** stoot ’n valse resultaat soos `chromium-update[.]site` na die top soekadvertensies.
2. Slagoffer laai ’n klein **eerste-fase loader** af (dikwels JS/HTA/ISO). Voorbeelde gesien deur Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltreer blaaier cookies + credential DBs, en trek dan ’n **stilswyende loader** wat in realtime besluit of dit gaan uitrol:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistentie komponent (register Run key + scheduled task)

### Hardening tips
* Blokkeer nuut-geregistreerde domeine & handhaaf **Advanced DNS / URL Filtering** op *search-ads* sowel as e-pos.
* Beperk sagteware-installasie tot ondertekende MSI / Store-pakkette, weier `HTA`, `ISO`, `VBS` uitvoering per beleid.
* Monitor vir child-processes van blaaiers wat installers open:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jaag vir LOLBins wat gereeld deur eerste-fase loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & stem-klone APIs** vir volledig gepersonaliseerde lokmiddels en regstreekse interaksie.

| Laag | Voorbeeld gebruik deur bedreigingsakteur |
|------|------------------------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS met ewekansige woordings & tracking-skakels.|
|Generative AI|Produseer *eenmalige* e-posse wat openbare M&A, binnegrappe van sosiale media verwys; deep-fake CEO-stem in terugbel-bedrog.|
|Agentic AI|Registreer outonoom domeine, scrape open-source intel, confeer volgende-stap e-posse wanneer ’n slagoffer klik maar nie creds indien nie.|

**Verdediging:**
• Voeg **dinamiese banners** by wat boodskappe uitlig wat van onbetroubare outomatisering kom (via ARC/DKIM anomalieë).
• Ontplooi **stem-biometriese challenge-frasies** vir hoë-risiko telefoonversoeke.
• Simuleer voortdurend AI-gegenereerde lokmiddels in bewustheidsprogramme – statiese sjablone is verouderd.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, dwing operateurs bloot ’n nuwe MFA-registrasie gedurende die help-desk oproep af, wat die gebruiker se bestaande token nietig maak. Enige daaropvolgende aanmeldingsprompt lyk legitiem vir die teiken.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Moniteer AzureAD/AWS/Okta-gebreurtenisse waar **`deleteMFA` + `addMFA`** binne minute vanaf dieselfde IP plaasvind.



## Clipboard Hijacking / Pastejacking

Aanslagmakers kan stilweg kwaadwillige opdragte na die slagoffer se clipboard kopieer vanaf 'n gekompromitteerde of typosquatted webblad en dan die gebruiker mislei om dit in te plak in **Win + R**, **Win + X** of 'n terminalvenster, wat willekeurige kode uitvoer sonder enige aflaai of byhegting.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateurs sit toenemend hul phishing-strome agter 'n eenvoudige toestelkontrole sodat desktop crawlers nooit die finale bladsye bereik nie. 'n Algemene patroon is 'n klein script wat toets vir 'n touch-capable DOM en die resultaat na 'n server endpoint stuur; nie-mobiele kliënte ontvang HTTP 500 (of 'n leë bladsy), terwyl mobiele gebruikers die volle vloei bedien word.

Minimale kliëntsnippet (tipiese logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` vereenvoudigde logika:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Bedienergedrag wat gereeld waargeneem word:
- Stel 'n sessiekoekie in tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of 'n plaashouer) terug op daaropvolgende GETs wanneer `is_mobile=false`; bied phishing slegs as dit `true` is.

Jag- en opsporingsheuristieke:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiele; legitieme mobiele slagofferpaadjies stuur 200 terug met opvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles baseer.

Verdedigingswenke:
- Voer crawlers uit met mobiele-agtige vingerafdrukke en JS aangeskakel om toegangsbeperkte inhoud openbaar te maak.
- Waarsku oor verdagte 500-antwoorde wat volg op `POST /detect` op nuut geregistreerde domeine.

## Verwysings

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
