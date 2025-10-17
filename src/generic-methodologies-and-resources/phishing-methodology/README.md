# Phishing Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon the victim
1. Select the **domen žrtve**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Pripremite okruženje
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Pripremite kampanju
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

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

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora da **pokazuje** na **IP VPS-a** na kojem konfigurišete **gophish**.
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
**Konfiguracija mejla**

Počnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Promenite takođe vrednosti sledećih varijabli u /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže vaš domen i **restartujte vaš VPS.**

Sada napravite **DNS A record** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada hajde da testiramo slanje e-pošte:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Zaustavite izvršavanje gophish i konfigurišimo ga.\
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

Da biste kreirali gophish servis tako da može da se pokreće automatski i da se upravlja kao servis, možete kreirati fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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
Dovršite konfigurisanje servisa i proverite ga tako što ćete:
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

### Sačekajte i budite legitimni

Što je domen stariji, to je manje verovatno da će biti označen kao spam. Zato treba da sačekate što je duže moguće (najmanje 1 nedelju) pre phishing assessment-a. Pored toga, ako postavite stranicu vezanu za reputacioni sektor, reputacija koja se dobije biće bolja.

Napomena: čak i ako morate da čekate nedelju dana, možete odmah završiti svu konfiguraciju.

### Configure Reverse DNS (rDNS) record

Postavite rDNS (PTR) zapis koji povezuje IP adresu VPS-a sa imenom domena.

### Sender Policy Framework (SPF) Record

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete vašu SPF politiku (koristite IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji treba postaviti u TXT zapis za domen:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Autentifikacija poruka zasnovana na domenu, izveštavanje i usklađenost (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT record za hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj tutorijal se zasniva na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je konkatenirati oba B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

To možete uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Jednostavno pristupite stranici i pošaljite e-mail na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe **proveriti svoju email konfiguraciju** tako što ćete poslati email na `check-auth@verifier.port25.com` i **pročitati odgovor** (za ovo ćete morati da **otvorite** port **25** i da vidite odgovor u fajlu _/var/mail/root_ ako pošaljete email kao root).\\ Proverite da li prolazite sve testove:
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
Takođe možete poslati **poruku na Gmail koji kontrolišete**, i proveriti **zaglavlja e-pošte** u svojoj Gmail pristigloj pošti; `dkim=pass` bi trebalo da bude prisutno u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse crne liste

The page [www.mail-tester.com](https://www.mail-tester.com) može da ti pokaže da li je tvoj domen blokiran na Spamhouse. Uklanjanje domena/IP-a možeš zatražiti na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Uklanjanje domena/IP-a možeš zatražiti na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil pošiljaoca

- Postavi neko **ime za identifikaciju** profila pošiljaoca
- Odredi sa kog naloga ćeš poslati phishing mejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možeš ostaviti polja username i password prazna, ali obavezno označi Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se da iskoristiš funkcionalnost "**Send Test Email**" da proveriš da li sve radi.\
> Preporučujem da **pošalješ test mejlove na 10min mails adrese** kako bi izbegao stavljanje na crnu listu tokom testiranja.

### Email šablon

- Postavi neko **ime za identifikaciju** šablona
- Zatim napiši **subject** (ništa čudno — nešto što bi mogao očekivati u običnom mejlu)
- Uveri se da si označio "**Add Tracking Image**"
- Napiši **email template** (možeš koristiti varijable kao u sledećem primeru):
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
Imajte na umu da je, **kako biste povećali kredibilitet e‑pošte**, preporučljivo upotrebiti potpis iz nekog mejla od klijenta. Predlozi:

- Pošaljite e‑poruku na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javno dostupne mejlove** kao što su info@ex.com ili press@ex.com ili public@ex.com, pošaljite im mejl i sačekajte odgovor.
- Pokušajte kontaktirati **neki validan otkriveni** mejl i sačekajte odgovor

![](<../../images/image (80).png>)

> [!TIP]
> Šablon e‑pošte takođe omogućava da se **prilože fajlovi za slanje**. Ako takođe želite da ukradete NTLM izazove koristeći posebno kreirane fajlove/dokumente [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Unesite **ime**
- **Napišite HTML kod** web stranice. Napomena: možete **importovati** web stranice.
- Označite opcije **Capture Submitted Data** i **Capture Passwords**
- Podesite **preusmeravanje**

![](<../../images/image (826).png>)

> [!TIP]
> Uobičajeno je da ćete morati izmeniti HTML kod stranice i napraviti neke testove lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim upišite taj HTML kod u polje.\
> Napomena: ako treba da **koristite statične resurse** za HTML (npr. neke CSS i JS fajlove) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i zatim im pristupiti iz _**/static/\<filename>**_

> [!TIP]
> Za preusmeravanje možete **preusmeriti korisnike na legitimnu glavnu stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, prikazati **spinning wheel** ([https://loading.io/](https://loading.io)) na 5 sekundi, pa zatim naznačiti da je proces uspešan.

### Users & Groups

- Unesite ime
- **Importujte podatke** (napomena: da biste koristili šablon za primer potrebno je ime, prezime i email adresa svakog korisnika)

![](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte kampanju tako što ćete izabrati ime, email template, landing page, URL, sending profile i grupu. Napomena: URL će biti link koji se šalje žrtvama

Imajte na umu da **Sending Profile omogućava slanje test e‑poruke da vidite kako će konačna phishing poruka izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučujem da **test mejlove šaljete na 10min mail adrese** kako biste izbegli da vas testovi uvrste na crnu listu.

Kada je sve spremno, samo pokrenite kampanju!

## Website Cloning

Ako iz bilo kog razloga želite da klonirate veb‑sajt pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) takođe ćete želeti da **pošaljete fajlove koji sadrže neku vrstu backdoor‑a** (možda C2 ili samo nešto što će pokrenuti autentikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično lukav jer falsifikujete pravu veb‑stranicu i prikupljate informacije koje je korisnik uneo. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako aplikacija koju ste falsifikovali ima podešen 2FA, **ove informacije vam neće omogućiti da se lažno predstavite kao prevareni korisnik**.

Tu su alati poput [**evilginx2**](https://github.com/kgretzky/evilginx2), [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena) korisni. Ovi alati omogućavaju da napravite MitM napad. U suštini, napad radi na sledeći način:

1. Vi **imitirate login** formu prave veb‑stranice.
2. Korisnik **pošalje** svoje **kredencijale** na vašu lažnu stranicu i alat ih zatim prosleđuje pravoj stranici, **proveravajući da li kredencijali funkcionišu**.
3. Ako je nalog konfigurisan sa **2FA**, MitM stranica će tražiti taj kod i kada **korisnik unese** kod, alat će ga proslediti pravoj stranici.
4. Kada je korisnik autentifikovan vi (kao napadač) ćete imati **uhvaćene kredencijale, 2FA, cookie i sve informacije** o svakoj interakciji dok alat radi MitM.

### Via VNC

Šta ako umesto da **pošaljete žrtvu na malicioznu stranicu** koja izgleda kao original, pošaljete je u **VNC sesiju sa browserom povezanom na pravu stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji koristi, cookies...\
Ovo možete izvesti uz pomoć [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Očigledno je jedan od najboljih načina da znate da li ste otkriveni da **pretražite vaš domen u crnim listama**. Ako se pojavi, vaš domen je na neki način detektovan kao sumnjiv.\
Jedan jednostavan način da proverite da li se vaš domen pojavljuje u nekoj crnoj listi je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing domene u divljini**, kao što je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa vrlo sličnim imenom** kao domen žrtve **i/ili generisati sertifikat** za **subdomen** domena koji kontrolišete, a koji sadrži **ključnu reč** žrtvinog domena. Ako žrtva preduzme bilo kakvu DNS ili HTTP interakciju sa njima, znaćete da **ona aktivno traži** sumnjive domene i moraćete da budete veoma stealt.

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious) da procenite da li će vaš mejl završiti u spam folderu, biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderni intrusion setovi sve češće preskaču email mamce i **direktno ciljaju service‑desk / identity‑recovery workflow** da bi zaobišli MFA. Napad je potpuno "living‑off‑the‑land": kad operater poseduje validne kredencijale, pivotira pomoću ugrađenih administrativnih alata – bez potrebe za malverom.

### Attack flow
1. Recon the victim
* Skupljanje ličnih i korporativnih podataka sa LinkedIn, data breaches, javnog GitHub‑a itd.
* Identifikujte visokovredne identitete (executives, IT, finance) i mapirajte **tačan proces help‑deska** za reset lozinke / MFA.
2. Real-time social engineering
* Telefonom, Teams‑om ili chat‑om kontaktirajte help‑desk dok se lažno predstavljate kao meta (često uz **spoofed caller‑ID** ili **cloned voice**).
* Pružite prethodno prikupljene PII da biste prošli verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili da izvrši **SIM‑swap** na registrovani mobilni broj.
3. Immediate post-access actions (≤60 min in real cases)
* Uspostavite foothold preko bilo kog web SSO portala.
* Enumerišite AD / AzureAD koristeći ugrađene alate (bez dropovanja binarija):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateralno kretanje koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već na whitelist‑u u okruženju.

### Detection & Mitigation
* Tretirajte identity recovery putem help‑deska kao **privileged operation** – zahtevajte step‑up auth i odobrenje menadžera.
* Implementirajte **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja alertuju na:
  * Promenu MFA metode + autentikacija sa novog uređaja / geolokacije.
  * Momentalno povećanje privilegija iste prinicpale (user → admin).
* Snimajte help‑desk pozive i zahtevajte **call‑back na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just‑In‑Time (JIT) / Privileged Access** tako da nalog koji je upravo resetovan ne nasleđuje automatski visokoprivilegovane tokene.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Operacije velike skale nadoknađuju troškove high‑touch operacija masovnim napadima koji pretvaraju **pretraživače & reklamne mreže u kanal isporuke**.

1. **SEO poisoning / malvertising** gura lažni rezultat kao `chromium-update[.]site` na vrh pretraga i oglasa.
2. Žrtva preuzme mali **first‑stage loader** (često JS/HTA/ISO). Primeri zabeleženi od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrira browser cookies + credential DBs, zatim povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deploy‑uje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* komponentu za persistenciju (registry Run key + scheduled task)

### Hardening tips
* Block newly‑registered domains & enforce **Advanced DNS / URL Filtering** na *search‑ads* kao i na e‑mail.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Pratite za child procese browsera koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins koji se često zloupotrebljavaju od strane first‑stage loadera (npr. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Napadači sada povezuju **LLM & voice‑clone API‑je** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Dodajte **dinamične banere** koji ističu poruke poslate iz nepouzdanih automatizacija (na osnovu ARC/DKIM anomalija).  
• Implementirajte **voice‑biometric challenge phrases** za visokorizične telefonske zahteve.  
• Kontinuirano simulirajte AI‑generisane mamce u programima podizanja svesti – statični šabloni su zastareli.

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
Pored klasičnog push‑bombinga, operatori jednostavno **forsiraju novu MFA registraciju** tokom help‑desk poziva, poništavajući postojeći token korisnika. Bilo koji naknadni prompt za prijavu izgleda legitimno za žrtvu.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratite AzureAD/AWS/Okta događaje gde se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu tiho kopirati zlonamerne komande u žrtvin clipboard sa kompromitovane ili typosquatted web stranice i potom prevariti korisnika da ih zalepi u **Win + R**, **Win + X** ili u terminal window, izvršavajući proizvoljan kod bez ikakvog download-a ili attachment-a.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatori sve češće zatvaraju svoje phishing tokove iza jednostavne provere uređaja tako da desktop crawlers nikada ne stignu do krajnjih stranica. Uobičajen obrazac je mali script koji proverava da li je DOM touch-capable i pošalje rezultat na server endpoint; non‑mobile clients dobijaju HTTP 500 (ili praznu stranicu), dok mobile users dobijaju ceo flow.

Minimal client snippet (tipična logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (pojednostavljeno):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Ponašanje servera često primećeno:
- Postavlja session cookie tokom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) na narednim GET zahtevima kada je `is_mobile=false`; prikazuje phishing samo ako je `true`.

Heuristike za lov i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non‑mobile; legitimne mobilne putanje korisnika vraćaju 200 sa naknadnim HTML/JS.
- Blokirajte ili detaljno proverite stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili slične provere uređaja.

Saveti za odbranu:
- Pokrenite crawlere koji imitiraju mobilni fingerprint i imaju uključen JS kako biste otkrili ograničeni sadržaj.
- Generišite alarm na sumnjive odgovore 500 nakon `POST /detect` na novoregistrovanim domenima.

## Reference

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
