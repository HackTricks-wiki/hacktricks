# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon the victim
1. Izaberi **victim domain**.
2. Uradi osnovnu web enumeraciju **searching for login portals** koje koristi žrtva i **decide** koji ćeš **impersonate**.
3. Koristi **OSINT** da **find emails**.
2. Pripremi okruženje
1. **Buy the domain** koji ćeš koristiti za phishing procenu
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Konfiguriši VPS sa **gophish**
3. Pripremi kampanju
1. Pripremi **email template**
2. Pripremi **web page** za krađu credentials
4. Pokreni kampanju!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi** u skladištenju ili komunikaciji automatski promene zbog raznih faktora kao što su solarne oluje, kosmički zraci ili hardverske greške.

Kada se ovaj koncept primeni na DNS zahteve, moguće je da **domain koji DNS server zaprimi** nije isti kao domain koji je inicijalno zahtevan.

Na primer, promena jednog bita u domain-u "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo tako što registruju više bit-flipping domain-a** koji su slični domain-u žrtve. Njihova namera je da preusmere legitimne korisnike na svoju infrastrukturu.

Za više informacija pogledaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Možeš pretražiti [https://www.expireddomains.net/](https://www.expireddomains.net) za expired domain koji bi mogao da iskoristiš.\
Da bi bio siguran da expired domain koji planiraš da kupiš **već ima dobar SEO**, možeš proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da bi **otkrio više** validnih email adresa ili **verifikovao one** koje si već pronašao, možeš proveriti da li možeš brute-force-ovati smtp servere žrtve. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravi da ako korisnici koriste **bilo koji web portal za pristup mail-ovima**, možeš proveriti da li je ranjiv na **username brute force**, i iskoristiti tu ranjivost ako je moguće.

## Configuring GoPhish

### Instalacija

Možeš ga download-ovati sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download-uj i dekompresuj unutar `/opt/gophish` i pokreni `/opt/gophish/gophish`\
U output-u će ti biti dat password za admin user-a na portu 3333. Dakle, pristupi tom portu i iskoristi te credentials da promeniš admin password. Možda ćeš trebati da tuneluješ taj port ka lokalnom:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora da bude **usmeren** na **IP adresu VPS-a** gde konfigurišete **gophish**.
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
**Konfiguracija pošte**

Počnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe promenite vrednosti sledećih promenljivih u /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže vaš domen i **restartujte vaš VPS.**

Sada kreirajte **DNS A record** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada ćemo testirati slanje emaila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Zaustavite izvršavanje gophish i hajde da ga konfigurišemo.\
Izmenite `/opt/gophish/config.json` na sledeće (obratite pažnju na upotrebu https):
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
**Konfigurišite gophish servis**

Da biste kreirali gophish servis tako da se može automatski pokretati i upravljati kao servis, možete kreirati fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfiguraciju servisa i proveru tako što ćete uraditi:
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
## Konfigurisanje mail servera i domena

### Sačekaj i budi legitiman

Što je domen stariji, manja je verovatnoća da će biti označen kao spam. Zato treba da sačekaš što je moguće duže (najmanje 1 nedelju) pre phishing procene. Takođe, ako postaviš stranicu povezanu sa reputacionim sektorom, dobijena reputacija će biti bolja.

Imaj na umu da iako treba da sačekaš nedelju dana, možeš sada završiti svu konfiguraciju.

### Konfiguriši Reverse DNS (rDNS) zapis

Postavi rDNS (PTR) zapis koji rešava IP adresu VPS-a na ime domena.

### Sender Policy Framework (SPF) Record

Moraš **konfigurisati SPF zapis za novi domen**. Ako ne znaš šta je SPF zapis [**pročitaj ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možeš koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišeš svoju SPF politiku (koristi IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji treba postaviti u TXT record unutar domena:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT zapis usmeren na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je da spojite obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Samo pristupite stranici i pošaljite email na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Takođe možete **proveriti konfiguraciju e-pošte** slanjem e-poruke na `check-auth@verifier.port25.com` i **čitajući odgovor** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u fajlu _/var/mail/root_ ako pošaljete poruku kao root).\
Proverite da li ste prošli sve testove:
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
Takođe možete poslati **poruku na Gmail koji kontrolišete**, i proveriti **zaglavlja emaila** u svom Gmail inboxu, `dkim=pass` treba da bude prisutan u polju `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam pokaže da li je vaš domen blokiran od strane Spamhouse. Možete zatražiti uklanjanje vašeg domena/IP-a na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Možete zatražiti uklanjanje vašeg domena/IP-a na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil pošiljaoca

- Postavite neko **ime za identifikaciju** profila pošiljaoca
- Odlučite sa kog naloga ćete slati phishing mejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možete ostaviti korisničko ime i lozinku praznim, ali obavezno označite Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se da koristite funkciju "**Send Test Email**" da testirate da li sve radi.\
> Preporučujem da **pošaljete test mejlove na 10min mails adrese** kako biste izbegli stavljanje na crnu listu tokom testiranja.

### Šablon mejla

- Postavite neko **ime za identifikaciju** šablona
- Zatim napišite **subject** (ništa čudno, samo nešto što biste očekivali da pročitate u običnom mejlu)
- Obavezno označite "**Add Tracking Image**"
- Napišite **šablon mejla** (možete koristiti promenljive kao u sledećem primeru):
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
Napomena: **da biste povećali kredibilitet mejla**, preporučuje se korišćenje neke potpisa iz mejla klijenta. Predlozi:

- Pošaljite mejl na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne mejlove** kao info@ex.com ili press@ex.com ili public@ex.com i pošaljite im mejl i sačekajte odgovor.
- Pokušajte da kontaktirate **neki validan otkriven** mejl i sačekajte odgovor

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template takođe omogućava **prilaženje fajlova za slanje**. Ako želite i da ukradete NTLM challenges koristeći posebno kreirane fajlove/dokumente [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Unesite **ime**
- **Napišite HTML kod** web stranice. Imajte u vidu da možete **importovati** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Podesite **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Obično će biti potrebno modifikovati HTML kod stranice i raditi testove lokalno (možda koristeći neki Apache server) **dok ne dobijete željene rezultate.** Zatim taj HTML kod upišite u polje.\
> Napomena: ako trebate **koristiti statičke resurse** za HTML (npr. neke CSS i JS fajlove) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i potom im pristupati preko _**/static/\<filename>**_

> [!TIP]
> Za redirection možete **preusmeriti korisnike na legitimnu glavnu stranicu** žrtve, ili ih redirektovati na _/static/migration.html_ na primer, prikazati neki **spinning wheel** ([**https://loading.io/**](https://loading.io)) 5 sekundi i onda naznačiti da je proces uspešan.

### Users & Groups

- Podesite ime
- **Importujte podatke** (imajte u vidu da za korišćenje template-a u primeru trebate firstname, last name i email address svakog korisnika)

![](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte kampanju birajući ime, email template, landing page, URL, Sending Profile i grupu. Napomena: URL će biti link poslat žrtvama.

Imajte u vidu da **Sending Profile omogućava slanje test mejla da vidite kako će finalni phishing mejl izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučujem da **test mejlove šaljete na 10min mail adrese** kako biste izbegli da budete blacklisted tokom testiranja.

Kada je sve spremno, samo pokrenite kampanju!

## Website Cloning

Ako iz bilo kog razloga želite da klonirate vebsajt, proverite sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) ćete želeti i da **pošaljete fajlove koji sadrže neku vrstu backdoora** (možda C2 ili nešto što će samo pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično pametan jer falsifikujete stvarni sajt i prikupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako aplikacija koju ste falsifikovali koristi 2FA, **ove informacije vam neće omogućiti da se imitujete kao kompromitovani korisnik**.

Ovde alati poput [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena) postaju korisni. Ovaj alat vam omogućava da generišete MitM tip napada. U suštini, napad funkcioniše na sledeći način:

1. Vi **imitirate login** formu prave web stranice.
2. Korisnik **pošalje** svoje **credentials** na vašu lažnu stranicu i alat ih prosleđuje pravoj stranici, **proveravajući da li credentials rade**.
3. Ako nalog koristi **2FA**, MitM stranica će tražiti kod i kada **korisnik unese** kod, alat će ga poslati pravoj web stranici.
4. Kada je korisnik autentifikovan, vi (kao napadač) ćete imati **uhvaćene credentials, 2FA, cookie i sve informacije** o svakoj interakciji dok alat radi MitM.

### Via VNC

Šta ako umesto da **preusmerite žrtvu na malicioznu stranicu** koja izgleda kao originalna, pošaljete je u **VNC sesiju sa browserom koji je povezan na pravu web stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji se koristi, cookies...\
Možete ovo postići pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Očigledno, jedan od najboljih načina da saznate da li ste otkriveni je da **pretražite svoj domen u crnim listama**. Ako se pojavi na listi, na neki način je vaš domen detektovan kao sumnjiv.\
Jedan lak način da proverite da li se vaš domen nalazi u nekoj crnoj listi je korišćenje [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing domene u prirodi**, kao što je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** domenu žrtve **i/ili generisati sertifikat** za **subdomen** domena koji vi kontrolišete **koji sadrži** **ključnu reč** žrtvinog domena. Ako žrtva izvrši bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i bićete prinuđeni da budete veoma stealth.

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious) da procenite da li će vaš mejl završiti u spam folderu, biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderni intrusion setovi sve više preskaču email mamce i **direktno ciljaju service-desk / identity-recovery workflow** kako bi zaobišli MFA. Napad je potpuno "living-off-the-land": kada operator poseduje validne kredencijale, on pivotira sa ugrađenim admin alatima – nije potreban malware.

### Attack flow
1. Recon žrtve
* Sakupite lične i korporativne podatke sa LinkedIn, curenja podataka, javnog GitHub-a, itd.
* Identifikujte visokovredne identitete (izvršni, IT, finansije) i izbrojite **tačan help-desk proces** za reset lozinke / MFA.
2. Real-time social engineering
* Telefon, Teams ili chat sa help-deskom dok se predstavljate kao cilj (često sa **spoofed caller-ID** ili **cloned voice**).
* Pružite prethodno prikupljene PII podatke da prođete verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovanom broju mobilnog.
3. Immediate post-access actions (≤60 min u realnim slučajevima)
* Uspostavite foothold preko bilo kog web SSO porta.
* Enumerišite AD / AzureAD koristeći ugrađene alate (bez postavljanja binarnih fajlova):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateralno kretanje koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već na whitelisti u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privileged operation** – zahtevajte step-up auth i odobrenje menadžera.
* Rasporedite **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja alarmiraju na:
* Promena MFA metode + autentikacija sa novog uređaja / geolokacije.
* Momentalno eleviranje istog principala (user → admin).
* Snimajte help-desk pozive i zahtevajte **call-back na već registrovan broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novo resetovani nalozi **ne nasleđuju automatski** visokopriovilegovane tokene.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity timovi kompenzuju troškove high-touch operacija masovnim napadima koji pretvaraju **search engines & ad networks u kanal isporuke**.

1. **SEO poisoning / malvertising** gura lažni rezultat poput `chromium-update[.]site` na vrh pretrage i oglasa.
2. Žrtva skida mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrira cookies iz browsera + credential DBs, potom povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deploy-uje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence komponentu (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novo registrovane domene i primenite **Advanced DNS / URL Filtering** na *search-ads* kao i na email.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Monitorišite child procese browsera koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tražite LOLBins često zloupotrebljavane od strane first-stage loadera (npr. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Napadači sada povezuju **LLM & voice-clone APIs** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Layer | Primer upotrebe od strane threat actor-a |
|-------|------------------------------------------|
|Automation|Generisanje i slanje >100k mejlova / SMS sa nasumično variranim tekstom i tracking linkovima.|
|Generative AI|Kreiranje *jedinstvenih* mejlova koji referenciraju javne M&A događaje, interne šale sa društvenih mreža; deep-fake CEO glas u callback prevari.|
|Agentic AI|Autonomno registruje domene, scrape-uje open-source intel, kreira sledeće mejlove kada žrtva klikne ali ne pošalje kredencijale.|

**Defence:**
• Dodajte **dinamične banere** koji ističu poruke poslate iz nepouzdanih automatizacija (na osnovu ARC/DKIM anomalija).  
• Implementirajte **voice-biometric challenge phrases** za high-risk telefonske zahteve.  
• Kontinuirano simulirajte AI-generisane mamce u programima svesti – statički templatei su zastareli.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Pored klasičnog push-bombinga, operatori jednostavno **prisile novu MFA registraciju** tokom help-desk poziva, poništavajući korisnikov postojeći token. Bilo koji naredni login prompt izgleda legitimno žrtvi.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratite AzureAD/AWS/Okta događaje gde **`deleteMFA` + `addMFA`** dogode **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu tiho kopirati zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice, a zatim prevariti korisnika da ih nalepi u **Win + R**, **Win + X** ili terminal prozor, izvršavajući arbitrarni kod bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatori sve češće stavljaju svoje phishing flows iza jednostavne provere uređaja tako da desktop crawleri nikada ne dođu do krajnjih stranica. Uobičajen obrazac je mali skript koji testira touch-capable DOM i šalje rezultat na server endpoint; non‑mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok mobile korisnici dobijaju ceo flow.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (pojednostavljeno):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Često zapaženo ponašanje servera:
- Postavlja session cookie tokom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) na naredne GET zahteve kada je `is_mobile=false`; prikazuje phishing samo ako je `true`.

Heuristike za otkrivanje i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za ne-mobilne uređaje; legitimne putanje mobilnih žrtava vraćaju 200 sa narednim HTML/JS.
- Blokirajte ili detaljno proverite stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili sličnim proverama uređaja.

Saveti za odbranu:
- Pokrenite crawlers sa mobile-like fingerprints i omogućite JS da otkrijete gated content.
- Postavite alarm za sumnjive 500 odgovore koji slede nakon `POST /detect` na novoregistrovanim domenima.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
