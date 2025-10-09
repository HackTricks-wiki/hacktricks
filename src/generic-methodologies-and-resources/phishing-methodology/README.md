# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer basiese web-ontleding uit deur te **soek na aanmeldportale** wat deur die slagoffer gebruik word en **besluit** watteren jy gaan **namaak**.
3. Gebruik bietjie **OSINT** om **e-posadresse te vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die phishing-assessering
2. **Konfigureer die e-posdiens** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos-sjabloon** voor
2. Berei die **webblad** voor om die inlogbewyse te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop 'n vertroude domein

### Tegnieke vir domeinnaamvariasie

- **Sleutelwoord**: Die domeinnaam **bevat** 'n belangrike **sleutelwoord** van die oorspronklike domein (e.g., zelster.com-management.com).
- **hypened subdomain**: Vervang die **punt met 'n koppelteken** in 'n subdomein (e.g., www-zelster.com).
- **New TLD**: Dieselfde domein wat 'n **nuwe TLD** gebruik (e.g., zelster.org)
- **Homoglyph**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **ruil twee letters** in die domeinnaam (e.g., zelsetr.com).
- **Singularization/Pluralization**: Voeg of verwyder “s” aan die einde van die domeinnaam (e.g., zeltsers.com).
- **Omission**: Dit **verwyder een** van die letters uit die domeinnaam (e.g., zelser.com).
- **Repetition:** Dit **herhaal een** van die letters in die domeinnaam (e.g., zeltsser.com).
- **Replacement**: Soortgelyk aan homoglyph maar minder stil. Dit vervang een van die letters in die domeinnaam, moontlik met 'n letter naby die oorspronklike op die sleutelbord (e.g, zektser.com).
- **Subdomained**: Stel 'n **punt** binne die domeinnaam in (e.g., ze.lster.com).
- **Insertion**: Dit **voeg 'n letter in** die domeinnaam (e.g., zerltser.com).
- **Missing dot**: Voeg die TLD by die domeinnaam sonder 'n punt. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een of meer bits wat gestoor is of in kommunikasie is, outomaties omgeskakel kan word** as gevolg van verskeie faktore soos sonvlamme, kosmiese strale, of hardeware-foute.

Wanneer hierdie konsep op **DNS requests** **toegepas** word, is dit moontlik dat die **domein wat die DNS-server ontvang** nie dieselfde is as die domein aanvanklik versoek nie.

Byvoorbeeld, 'n enkele bitwysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanhangers mag **hierby voordeel trek deur verskeie bit-flipping domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hul bedoeling is om geldige gebruikers na hul eie infrastruktuur om te lei.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan soek op [https://www.expireddomains.net/](https://www.expireddomains.net) vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds 'n goeie SEO het**, kan jy kyk hoe dit gekategoriseer word in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdekking van E-posadresse

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posadresse te **ontdek** of die wat jy reeds gevind het te **verifieer**, kan jy kyk of jy die smtp-bedieners van die slagoffer kan brute-force. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Verder, moenie vergeet dat as gebruikers **'n webportaal gebruik om hul e-posse te bereik** nie, jy kan kyk of dit kwesbaar is vir **username brute force**, en die kwesbaarheid benut indien moontlik.

## Konfigureer GoPhish

### Installering

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit in `/opt/gophish` en voer `/opt/gophish/gophish` uit.\
Jy sal 'n wagwoord vir die admin-gebruiker vir poort 3333 in die uitset kry. Daarom, verkry toegang tot daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag daardie poort na lokaal moet tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voordat jy hierdie stap uitvoer moet jy **reeds die domein gekoop het** wat jy gaan gebruik, en dit moet **wys** na die **IP of the VPS** waar jy **gophish** konfigureer.
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

**Verander ook die waardes van die volgende veranderlikes in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Laastens, wysig die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** vir `mail.<domain>` wat na die **IP-adres** van die VPS wys en 'n **DNS MX** record wat na `mail.<domain>` wys

Kom ons toets nou om 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

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

Om die gophish-diens te skep sodat dit outomaties begin en as 'n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` met die volgende inhoud skep:
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
Voltooi die konfigurering van die diens en kontroleer dit deur die volgende te doen:
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

### Wag en wees geloofwaardig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang word. Jy moet dus so lank as moontlik wag (ten minste 1 week) voordat die phishing-assessering. Boonop, as jy 'n bladsy oor 'n reputasiesektor plaas, sal die verkrygde reputasie beter wees.

Let wel: selfs al moet jy 'n week wag, kan jy nou reeds alles konfigureer.

### Konfigureer Reverse DNS (rDNS) rekord

Stel 'n rDNS (PTR)-rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Record

Jy moet **'n SPF record vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF record is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS)

![](<../../images/image (1037).png>)

Dit is die inhoud wat in 'n TXT-rekord in die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die hostname `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet beide B64-waardes wat die DKIM-sleutel genereer, saamkoppel:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets die telling van jou e-poskonfigurasie

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com/) te gebruik. Gaan net na die bladsy en stuur 'n e-pos na die adres wat hulle jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **kontroleer jou e-poskonfigurasie** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die reaksie te lees** (hiervoor sal jy **oopmaak** port **25** en die reaksie sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
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
Jy kan ook **'n boodskap na 'n Gmail wat jy beheer** stuur, en kontroleer die **e-pos se headers** in jou Gmail-inbox; `dkim=pass` moet in die `Authentication-Results` header field teenwoordig wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwydering vanaf Spamhouse Swartlys

Die blad [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek om jou domein/IP verwyder te kry by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering vanaf Microsoft Swartlys

​​Jy kan versoek om jou domein/IP verwyder te kry by [https://sender.office.com/](https://sender.office.com).

## Skep en Lanseer GoPhish-veldtog

### Stuurprofiel

- Stel 'n **naam om te identifiseer** vir die senderprofiel
- Bepaal van watter rekening jy die phishing-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker dat jy die Ignore Certificate Errors aanvink

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek beveel aan om **send the test emails to 10min mails addresses** te gebruik om te voorkom dat jy by toetse op 'n swartlys beland.

### E-pos Sjabloon

- Stel 'n **naam om te identifiseer** vir die sjabloon
- Skryf dan 'n **onderwerp** (niks vreemds nie, net iets wat jy in 'n gewone e-pos sou verwag om te lees)
- Maak seker dat jy die "**Add Tracking Image**" gevink het
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
Neem kennis dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om 'n handtekening van 'n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die reaksie enige handtekening bevat.
- Soek na **openbare e-posadresse** soos info@ex.com of press@ex.com of public@ex.com en stuur vir hulle 'n e-pos en wag vir die reaksie.
- Probeer om **'n geldige ontdekte** e-pos te kontak en wag vir die reaksie

![](<../../images/image (80).png>)

> [!TIP]
> Die E-pos Sjabloon laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-uitdagings wil steel deur sommige spesiaal gekapte lêers/dokumente te gebruik [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landingsbladsy

- Skryf 'n **naam**
- **Skryf die HTML-kode** van die webblad. Let wel dat jy webblaaie kan **importeer**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel 'n **omleiding**

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en plaaslike toetse doen (miskien met 'n Apache-bediener) **tot jy tevrede is met die uitslag.** Daarna, skryf daardie HTML-kode in die blokkie.\
> Let wel dat as jy sommige **statiese hulpbronne** vir die HTML nodig het (miskien sommige CSS en JS bladsye) kan jy dit stoor in _**/opt/gophish/static/endpoint**_ en dan toegang verkry vanaf _**/static/\<filename>**_

> [!TIP]
> Vir die omleiding kan jy die gebruikers na die regte hoofblad van die slagoffer omlei, of omlei na _/static/migration.html_ byvoorbeeld, sit 'n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.

### Gebruikers & Groepe

- Stel 'n naam in
- **Importeer die data** (let wel dat om die sjabloon vir die voorbeeld te gebruik jy die voornaam, van en e-posadres van elke gebruiker nodig het)

![](<../../images/image (163).png>)

### Velddtog

Laastens, skep 'n veldtog deur 'n naam te kies, die e-pos sjabloon, die landingsblad, die URL, die stuurprofiel en die groep. Let wel dat die URL die skakel sal wees wat na die slagoffers gestuur word

Let wel dat die **Stuurprofiel toelaat om 'n toets-e-pos te stuur om te sien hoe die finale phishing-e-pos sal lyk**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek sou aanbeveel om die toets-e-posse aan 10min mail-adresse te stuur om te vermy dat jy tydens toetse op 'n swartlys beland.

Sodra alles gereed is, begin net die veldtog!

## Webwerf-kloning

As jy om enige rede die webwerf wil kloon, sien die volgende bladsy:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumente & Lêers met Agterdeur

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) wil jy ook **lêers stuur wat 'n tipe agterdeur bevat** (miskien 'n C2 of iets wat 'n outentisering sal veroorsaak).\
Kyk na die volgende bladsy vir voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is nogal slim omdat jy 'n werklike webwerf naboots en die inligting wat deur die gebruiker ingevoer is versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevul het nie of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, sal **hierdie inligting jou nie toelaat om die gefopte gebruiker te imiteer nie**.

Dit is waar gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie gereedskap stel jou in staat om 'n MitM-agtige aanval te genereer. Basies werk die aanval soos volg:

1. Jy **doen voor as die aanmeldvorm** van die werklike webblad.
2. Die gebruiker **stuur** sy **credentials** na jou valse bladsy en die gereedskap stuur dit na die werklike webblad, en **kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra en sodra die **gebruiker dit ingevoer het** sal die gereedskap dit na die werklike webblad stuur.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die credentials, die 2FA, die cookie en enige inligting** van elke interaksie vasgelê hê terwyl die gereedskap 'n MitM uitvoer.

### Via VNC

Wat as jy, in plaas daarvan om die slagoffer na 'n **skadelike bladsy** met dieselfde voorkoms as die oorspronklike te stuur, hom na 'n **VNC-sessie met 'n blaaier verbind aan die werklike webblad** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Bepaal of jy ontdek is

Een van die beste maniere om te weet of jy gevang is, is natuurlik om jou domein in swartlyste te **soek**. As dit op 'n lys verskyn, is jou domein op een of ander wyse as verdag bespeur.\
'n Maklike manier om na te gaan of jou domein in enige swartlys verskyn is om [https://malwareworld.com/](https://malwareworld.com/) te gebruik.

Daar is egter ander maniere om te weet of die slagoffer **aktiwiteit uitvoer om na verdagte phishing-aktiwiteit te soek** soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein koop met 'n baie soortgelyke naam** aan die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat deur jou beheer word wat die **sleutelwoord** van die slagoffer se domein bevat. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** met hulle uitvoer, sal jy weet dat **hulle aktief na verdagte domeine soek** en sal jy baie stil en versigtig moet optree.

### Evalueer die phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam-lêergids gaan beland, geblokkeer gaan word of suksesvol sal wees.

## Hoë-kontak identiteitskompromie (Help-Desk MFA-herset)

Moderne indringingsgroepe slaan toenemend e-poslokmiddels heeltemal oor en mik **direk na die service-desk / identity-recovery-werkvloei** om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operateur oor geldige credentials beskik, skakel hulle na ingeboude admin-instrumente – geen malware is nodig nie.

### Aanvalvloei
1. Rekognosering van die slagoffer
* Versamel persoonlike & korporatiewe besonderhede vanaf LinkedIn, databreuke, openbare GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende beamptes, IT, finansies) en som die **presiese help-desk proses** vir wagwoord / MFA-herset op.
2. Real-time sosial ingenieurskap
* Bel, gebruik Teams of chat met die help-desk terwyl jy die teiken naboots (dikwels met **gespoofte caller-ID** of **gekloneerde stem**).
* Verskaf die voorheen versamelde PII om kennisgebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA secret te reset** of 'n **SIM-swap** op 'n geregistreerde selfoonnommer uit te voer.
3. Onmiddellike poste-toegang aksies (≤60 min in werklike gevalle)
* Vestig 'n voet aan wal deur enige web SSO-portaal.
* Som AD / AzureAD op met ingeboude gereedskap (geen binaries word afgelaai nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec**, of wettige **RMM** agents wat reeds op 'n witlys in die omgewing is.

### Opsporing & Versagting
* Behandel help-desk identiteitsherstel as 'n **geprivilegieerde operasie** – vereis step-up auth & bestuurdergoedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku oor:
* MFA-metode verander + verifikasie vanaf nuwe toestel / geo.
* Onmiddellike opheffing van dieselfde prinsipal (user-→-admin).
* Neem help-desk oproepe op en dring aan op 'n **terugbel na 'n reeds geregistreerde nommer** voor enige herstel.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat pas-hersette rekeninge **nie** outomaties hoë-privilegie tokens erf nie.

---

## Grootskaalse Misleiding – SEO Poisoning & “ClickFix” Velddtogte
Commoditeitsgroepe kompenseer die koste van hoë-kontak operasies met massaanvalle wat **soekenjins & advertensienetwerke in die afleweringskanaal omskep**.

1. **SEO poisoning / malvertising** dryf 'n valse resultaat soos `chromium-update[.]site` bo-aan soekadvertensies.
2. Slagoffer laai 'n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde gesien deur Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltreer blaaierkoekies + credential DBs, en trek dan 'n **silent loader** wat realtime besluit of dit gaan ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Verhardingswenke
* Blokkeer onlangs- geregistreerde domeine & handhaaf **Advanced DNS / URL Filtering** op *search-ads* sowel as e-pos.
* Beperk sagteware-installasie tot gesigneerde MSI / Store-pakkette, weier `HTA`, `ISO`, `VBS` uitvoering per beleid.
* Monitor vir child processes van blaaiers wat installateurs open:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jag na LOLBins wat dikwels deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

---

## KI-/AI-Verbeterde Phishing Operasies
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokmiddels en realtime interaksie.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Genereer & stuur >100 k e-posse / SMS met gerandomiseerde bewoording & volgskakels.|
|Generative AI|Produseer *one-off* e-posse wat verwys na openbare M&A, binnetjied-grappe vanaf sosiale media; deep-fake CEO-stem in terugbelskema.|
|Agentic AI|Registreer outonoom domeine, skraap oopbron intel, vervaardig volgende-stap e-posse wanneer 'n slagoffer klik maar nie kredensiale indien nie.|

**Verdedigingsmaatreëls:**
• Voeg **dynamiese banners** by wat boodskappe uit onbetroubare outomatisering uitlig (via ARC/DKIM anomalieë).  
• Implementeer **voice-biometric challenge phrases** vir hoë-risiko telefoonversoeke.  
• Simuleer voortdurend KI-genereerde lokmiddels in bewusmakingsprogramme – statiese sjablone is verouderd.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Vermoeidheid / Push Bombing Variant – Gedwonge Herset
Benewens klassieke push-bombing, dwing operateurs eenvoudigweg **'n nuwe MFA-registrasie af** tydens die help-desk oproep, wat die gebruiker se bestaande token nietig maak. Enige daaropvolgende aanmeldprompt sal vir die slagoffer eg lyk.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Moniteer AzureAD/AWS/Okta gebeure waar **`deleteMFA` + `addMFA`** binne minute vanaf dieselfde IP plaasvind.



## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators plaas toenemend hul phishing-flows agter 'n eenvoudige toestelkontrole sodat desktop crawlers nooit die finale bladsye bereik nie. 'n Algemene patroon is 'n klein script wat toets of die DOM touch‑capable is en die resultaat na 'n server endpoint stuur; nie‑mobile kliënte ontvang HTTP 500 (of 'n leë bladsy), terwyl mobile gebruikers die volledige flow bedien kry.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (vereenvoudigde):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Bedienergedrag wat gereeld waargeneem word:
- Stel 'n sessie-cookie tydens die eerste laai.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of 'n plaasvervanger) terug vir opvolg GETs wanneer `is_mobile=false`; bedien phishing slegs as `true`.

Opsporing en deteksie-heuristieke:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie-mobiele; regte mobiele slagoffer-paaie lewer 200 met opvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik op `ontouchstart` of soortgelyke toestelkontroles kondisioneer.

Verdedigingswenke:
- Voer crawlers uit met mobiele-agtige vingerafdrukke en JS aangeskakel om toegangsbeperkte inhoud te openbaar.
- Waarskuw by verdagte 500-reaksies wat volg op `POST /detect` op onlangs geregistreerde domeine.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
