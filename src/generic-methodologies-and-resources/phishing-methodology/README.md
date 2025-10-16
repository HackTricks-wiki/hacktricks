# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer basiese web-ontleding uit **om na aanmeldportale te soek** wat deur die slagoffer gebruik word en **besluit** watteren jy sal **naboots**.
3. Gebruik OSINT om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy vir die phishing-assessment gaan gebruik
2. **Konfigureer die e-posdiens** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos sjabloon** voor
2. Berei die **webblad** voor om die geloofsbriewe te steel
4. Loën die veldtog!

## Genereer soortgelyke domeinname of koop 'n betroubare domein

### Domeinnaam-variasie tegnieke

- **Keyword**: Die domeinnaam **bevat** 'n belangrike **keyword** van die oorspronklike domein (bv., zelster.com-management.com).
- **hypened subdomain**: Vervang die **punt met 'n koppelteken** in 'n subdomein (bv., www-zelster.com).
- **New TLD**: Dieselfde domein met 'n **nuwe TLD** (bv., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters om** binne die domeinnaam (bv., zelsetr.com).
- **Singularization/Pluralization**: Voeg 'n "s" by of verwyder dit aan die einde van die domeinnaam (bv., zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (bv., zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (bv., zeltsser.com).
- **Replacement**: Soortgelyk aan homoglyph maar minder sluier. Dit vervang een van die letters in die domeinnaam, moontlik met 'n letter wat naby die oorspronklike letter op die sleutelbord is (bv., zektser.com).
- **Subdomained**: Voer 'n **punt** in binne die domeinnaam in (bv., ze.lster.com).
- **Insertion**: Dit **voeg 'n letter in** die domeinnaam in (bv., zerltser.com).
- **Missing dot**: Heg die TLD aan die domeinnaam aan. (bv., zelstercom.com)

**Outomatiese Gereedskap**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een of meer bis wat gestoor of in kommunikasie is outomaties omgeslaan kan word** as gevolg van verskeie faktore soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep op **DNS-versoeke** toegepas word, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word** nie dieselfde is as die domein wat aanvanklik versoek is nie.

Byvoorbeeld, 'n enkele bit-modifikasie in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **hiervoor voordeel trek deur verskeie bitflipping-domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hul doel is om regmatige gebruikers na hul eie infrastruktuur te herlei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n betroubare domein

Jy kan soek op [https://www.expireddomains.net/](https://www.expireddomains.net) vir 'n verstrykte domein wat jy kan gebruik.\
Om seker te maak dat die verstrykte domein wat jy gaan koop **reeds 'n goeie SEO het**, kan jy kyk hoe dit gekategoriseer is by:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van e-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om **meer** geldige e-posadresse te **ontdek** of die wat jy reeds gevind het te **verifieer**, kan jy kyk of jy die SMTP-bedieners van die slagoffer kan brute-force. [Leer hoe om e-posadresse te verifieer/op te spoor hier](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Boonop, moenie vergeet dat as gebruikers **enige webportaal gebruik om hul e-posse te bereik**, jy kan kyk of dit kwesbaar is vir **gebruikersnaam-brute force**, en die kwesbaarheid indien moontlik uitbuit nie.

## Konfigureer GoPhish

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit binne `/opt/gophish` uit en voer `/opt/gophish/gophish` uit.\
Jy sal 'n wagwoord vir die admin gebruiker op poort 3333 in die uitvoer gegee word. Toegang daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag nodig hê om daardie poort na lokal te tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap behoort jy reeds die domein gekoop te hê wat jy gaan gebruik, en dit moet na die IP van die VPS wys waarop jy gophish gaan konfigureer.
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

Begin installering: `apt-get install postfix`

Voeg daarna die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Laastens wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** vir `mail.<domain>` wat na die **IP-adres** van die VPS wys en 'n **DNS MX** record wat na `mail.<domain>` wys

Kom ons toets nou om 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-konfigurasie**

Stop die uitvoering van gophish en kom ons configureer dit.\
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
**Konfigureer gophish-diens**

Om die gophish-diens te skep sodat dit outomaties begin kan word en as 'n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` skep met die volgende inhoud:
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
Rond die konfigurasie van die diens af en kontroleer dit deur die volgende te doen:
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

### Wag & wees legitiem

Hoe ouer 'n domein is, hoe minder waarskynlik sal dit as spam vasgevang word. Daarom moet jy soveel moontlik wag (ten minste 1week) voordat die phishing assessment. Boonop, as jy 'n bladsy oor 'n reputasionele sektor plasing, sal die reputasie wat verkry word beter wees.

Let daarop dat selfs al moet jy 'n week wag, jy alles nou klaar kan konfigureer.

### Konfigureer Reverse DNS (rDNS) record

Stel 'n rDNS (PTR) record wat die IP address van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Record

Jy moet **'n SPF record vir die nuwe domein konfigureer**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Dit is die inhoud wat binne 'n TXT record in die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasheernaam `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC record is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet albei B64-waardes wat die DKIM-sleutel genereer saamvoeg:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasie se telling

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Besoek net die bladsy en stuur 'n e-pos na die adres wat hulle jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die reaksie te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die reaksie sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
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
Jy kan ook 'n **message to a Gmail under your control** stuur, en die **email’s headers** in jou Gmail inbox nagaan, `dkim=pass` moet in die `Authentication-Results` header field teenwoordig wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein geblokkeer word deur spamhouse. Jy kan versoek dat jou domein/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Lanseer GoPhish Campaign

### Sending Profile

- Gee 'n **naam om die stuurprofiel te identifiseer**
- Besluit vanaf watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan gebruikersnaam en wagwoord leeg laat, maar maak seker om die "Ignore Certificate Errors" aan te merk

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek beveel aan om **die toets-e-posse na 10min mails adresse te stuur** om te verhoed dat jy op 'n swartlys beland tydens toetse.

### Email Template

- Gee 'n **naam om die sjabloon te identifiseer**
- Skryf dan 'n **onderwerp** (niks vreemds nie, net iets wat jy in 'n gewone e-pos sou verwag om te lees)
- Maak seker jy het '**Add Tracking Image**' aangevink
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
Let wel dat **om die geloofwaardigheid van die e-pos te verhoog**, word dit aanbeveel om 'n handtekening uit 'n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur 'n e-pos aan 'n **nie-bestaande adres** en kyk of die antwoord enige handtekening bevat.
- Soek vir **publieke e-posadresse** soos info@ex.com of press@ex.com of public@ex.com, stuur hulle 'n e-pos en wag vir die reaksie.
- Probeer om 'n van die ontdekte **geldige e-posadresse** te kontak en wag vir die reaksie.

![](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM challenges wil steel met behulp van spesiaal vervaardigde lêers/dokumente [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landingbladsy

- Skryf 'n **naam**
- **Skryf die HTML-kode** van die webblad. Let wel dat jy webblaaie kan **invoer**.
- Merk die opsies **Vang ingediende data** en **Vang wagwoorde**
- Stel 'n **omleiding**

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en plaaslike toetse uitvoer (miskien deur 'n Apache-bediener te gebruik) **tot jy tevrede is met die resultate.** Dan plak daardie HTML-kode in die boks.\
> Let wel dat as jy **statiese hulpbronne** nodig het vir die HTML (miskien CSS en JS blaaie) jy dit kan stoor in _**/opt/gophish/static/endpoint**_ en daarna toegang kry vanaf _**/static/\<filename>**_

> [!TIP]
> Vir die omleiding kan jy **gebruikers na die egte hoofbladsy** van die slagoffer omlei, of hulle byvoorbeeld na _/static/migration.html_ omlei, sit 'n **spinner (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Gebruikers & Groepe

- Stel 'n naam
- **Importeer die data** (let wel dat om die sjabloon te gebruik vir die voorbeeld jy die voornaam, van en e-posadres van elke gebruiker benodig)

![](<../../images/image (163).png>)

### Kampanje

Laastens, skep 'n kampanje deur 'n naam, die e-pos sjabloon, die landingbladsy, die URL, die stuurprofiel en die groep te kies. Let wel dat die URL die skakel sal wees wat na die slagoffers gestuur word

Let wel dat die **Stuurprofiel toelaat om 'n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek beveel aan om **die toets-e-posse na 10min mails adresse** te stuur om te voorkom dat jy tydens toetse op 'n swartlys beland.

Sodra alles gereed is, begin net die kampanje!

## Webwerf-kloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) sal jy ook graag **lêers wil stuur wat 'n soort backdoor bevat** (miskien 'n C2 of miskien net iets wat 'n verifikasie sal aktiveer).\
Kyk na die volgende bladsy vir sommige voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is nogal slim aangesien jy 'n werklike webwerf namaak en die inligting wat deur die gebruiker ingevoer is versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nageaam het met 2FA gekonfigureer is, sal **hierdie inligting jou nie toelaat om die misleiende gebruiker te imiteer nie**.

Dit is waar gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie gereedskap sal jou toelaat om 'n MitM-agtige aanval te genereer. Basies werk die aanval soos volg:

1. Jy **namaak die aanmeldvorm** van die werklike webblad.
2. Die gebruiker **stuur** sy **credentials** na jou vals bladsy en die gereedskap stuur dit na die werklike webblad, **en kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daaroor vra en sodra die **gebruiker dit invoer** sal die gereedskap dit na die werklike webblad stuur.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die credentials, die 2FA, die cookie en enige inligting** van elke interaksie opgeneem hê terwyl die gereedskap die MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om die slagoffer na 'n kwaadwillige bladsy te stuur wat dieselfde voorkoms as die oorspronklike het, hom na 'n **VNC-sessie met 'n blaaier verbind aan die werklike webblad** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die koekies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Opspoor of jy ontdek is

Een van die beste maniere om te weet of jy deurdag is, is om jou domein in swartlyste te **soek**. As dit gelys is, is jou domein op een of ander manier as verdag bespeur.\
'n Maklike manier om te kyk of jou domein in 'n swartlys verskyn is om [https://malwareworld.com/](https://malwareworld.com) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktive na verdagte phishing-aktiwiteit in die natuur soek** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein koop met 'n baie soortgelyke naam** aan die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomain** van 'n domein wat deur jou beheer word wat die **keyword** van die slagoffer se domein bevat. As die **slagoffer** enige vorm van **DNS of HTTP interaksie** daarmee uitvoer, sal jy weet dat **hy aktief soek** na verdagte domeine en jy sal baie stil te werk moet gaan.

### Evalueer die phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die rommel-pos vouer gaan eindig, geblokkeer gaan word of suksesvol sal wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne indringingsgroepe slaan toenemend e-pos-aas heeltemal oor en **teiken direk die service-desk / identity-recovery workflow** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operateur geldige credentials besit, beweeg hulle met ingeboude admin-gereedskap – geen malware is nodig nie.

### Aanvalsverloop
1. Recon the victim
* Versamel persoonlike & korporatiewe besonderhede van LinkedIn, data breaches, openbare GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende beamptes, IT, finansies) en enumereer die **presiese help-desk proses** vir wagwoord / MFA herstelling.
2. Real-time social engineering
* Bel, gebruik Teams of chat die help-desk terwyl jy die teiken namaak (dikwels met **spoofed caller-ID** of **cloned voice**).
* Verskaf die vooraf-versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oorreed die agent om die **MFA secret te reset** of 'n **SIM-swap** op 'n geregistreerde mobiele nommer uit te voer.
3. Immediate post-access actions (≤60 min in real cases)
* Vestig 'n voeting deur enige web SSO portal.
* Enumereer AD / AzureAD met ingeboude gereedskap (geen binaries word neergelê nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec**, of geldige **RMM** agents wat reeds op die witlys in die omgewing is.

### Opsporing & Mitigering
* Behandel help-desk identity recovery as 'n **privileged operation** – vereis step-up auth & bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku op:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Neem help-desk oproepe op en handhaaf 'n **call-back to an already-registered number** voordat enige herstel plaasvind.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat pas-hergestelde rekeninge nie outomaties hoë-privilege tokens erf nie.

---

## Op Skala Misleiding – SEO Poisoning & “ClickFix” Kampagnes
Massakolle los die koste van hoë-touch operasies op met massa-aanvalle wat **soekenjins & advertensienetwerke in die afleweringskanaal** omskakel.

1. **SEO poisoning / malvertising** stoot 'n vals resultaat soos `chromium-update[.]site` na die top van soekadvertensies.
2. Slagoffer laai 'n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde gesien deur Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Die lader exfiltreer blaaier-koekies + credential DBs, en trek dan 'n **silent loader** wat besluit – *in realtime* – of om te ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistensiekomponent (register Run key + scheduled task)

### Verhardingswenke
* Blokkeer nuut-geregistreerde domeine & handhaaf **Advanced DNS / URL Filtering** op *search-ads* sowel as e-pos.
* Beperk sagteware-instalering tot getekende MSI / Store-pakkette, weier die uitvoering van `HTA`, `ISO`, `VBS` deur beleid.
* Monitor vir child processes van blaaiers wat installers oopmaak:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jaag op LOLBins wat dikwels deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokmiddels en real-time interaksie.

| Laag | Voorbeeld gebruik deur bedreigingsakteur |
|-------|-----------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS met gevarieerde woordings & opsporingsskakels.|
|Generative AI|Skep *eenmalige* e-posse wat verwys na openbare M&A, binnenskop-grappe van sosiale media; deep-fake CEO-stem in terugbel-bedrog.|
|Agentic AI|Registreer outonoom domeine, kap open-source intel, skep volgende-fase e-posse wanneer 'n slagoffer klik maar nie creds indien nie.|

**Verdediging:**
• Voeg **dinamiese banniers** by wat boodskappe wat vanaf onbetroubare outomatisering gestuur is uitlig (via ARC/DKIM anomalieë).
• Ontplooi **voice-biometric challenge phrases** vir hoë-risiko telefoonsversoeke.
• Simuleer deurlopend AI-gegenereerde lokmiddels in bewustheidsprogramme – statiese sjablone is verouderd.

Sien ook – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Sien ook – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, dwing operateurs eenvoudig 'n **nuwe MFA-registrasie** tydens die help-desk oproep af, wat die gebruiker se bestaande token nietig maak. Enige daaropvolgende aanmeldprompt lyk vir die slagoffer legitim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor vir AzureAD/AWS/Okta gebeure waar **`deleteMFA` + `addMFA`** binne minute vanaf dieselfde IP voorkom.



## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte in die slagoffer se clipboard kopieer vanaf 'n gekompromitteerde of typosquatted webblad en dan die gebruiker mislei om dit binne **Win + R**, **Win + X** of 'n terminalvenster te plak, wat willekeurige kode uitvoer sonder enige aflaai of aanhangsel.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing om crawlers/sandboxes te ontduik
Operateurs plaas toenemend hul phishing‑vloei agter 'n eenvoudige toestelkontrole sodat desktop crawlers nooit die finale bladsye bereik nie. 'n Algemene patroon is 'n klein skrip wat toets vir 'n touch-capable DOM en die resultaat na 'n server-endpoint stuur; nie-mobiele kliënte ontvang HTTP 500 (of 'n leë bladsy), terwyl mobiele gebruikers die volle vloei bedien word.

Minimale kliëntsnippet (tipiese logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (vereenvoudigde):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Bedienergedrag wat dikwels waargeneem word:
- Stel 'n session cookie in tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of 'n plaasvervanger) terug vir daaropvolgende GETs wanneer `is_mobile=false`; bedien slegs phishing as dit `true` is.

Jag- en opsporingsheuristieke:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiel; legitieme mobiele slagofferpaaie gee 200 terug met opvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik afhanklik maak van `ontouchstart` of soortgelyke toesteltoetse.

Verdedigingswenke:
- Voer crawlers uit met mobiel-agtige vingerafdrukke en JS aangeskakel om afgeslote inhoud te onthul.
- Waarskuw oor verdagte 500-antwoorde wat volg op `POST /detect` op pas geregistreerde domeine.

## Verwysings

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
