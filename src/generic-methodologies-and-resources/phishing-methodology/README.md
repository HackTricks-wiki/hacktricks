# Phishing Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon the victim
1. Izaberite **victim domain**.
2. Izvršite osnovnu web enumeraciju **tražeći login portals** koje koristi žrtva i **odlučite** koji ćete **impersonate**.
3. Koristite **OSINT** da **pronađete email-ove**.
2. Pripremite okruženje
1. **Buy the domain** koji ćete koristiti za phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite **VPS** sa **gophish**
3. Pripremite kampanju
1. Pripremite **email template**
2. Pripremite **web page** za krađu podataka za prijavu
4. Pokrenite kampanju!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Ime domena **sadrži** važnu **keyword** originalnog domena (npr., zelster.com-management.com).
- **hypened subdomain**: Zamenite **dot sa crticom** u poddomeni (npr., www-zelster.com).
- **New TLD**: Isti domen koristeći **new TLD** (npr., zelster.org)
- **Homoglyph**: Zamenjuje slovo u imenu domena sa **slovima koja izgledaju slično** (npr., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zamenjuje dve ćelije u okviru imena domena (npr., zelsetr.com).
- **Singularization/Pluralization**: Dodaje ili uklanja "s" na kraju imena domena (npr., zeltsers.com).
- **Omission**: Uklanja jedno od slova iz imena domena (npr., zelser.com).
- **Repetition:** Ponavlja jedno od slova u imenu domena (npr., zeltsser.com).
- **Replacement**: Kao homoglyph ali manje prikriveno. Menja jedno od slova u imenu domena, možda slovom koje je blizu na tastaturi originalnog slova (npr., zektser.com).
- **Subdomained**: Uvodi tačku unutar imena domena (npr., ze.lster.com).
- **Insertion**: Umeće slovo u ime domena (npr., zerltser.com).
- **Missing dot**: Dodaje TLD na kraj imena domena. (npr., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji mogućnost da se neki bitovi čuvani ili u komunikaciji automatski promene zbog raznih faktora kao što su solarne oluje, kosmičke zrake ili hardverske greške.

Kada se ovaj koncept primeni na DNS zahteve, moguće je da domen koji DNS server primi nije isti kao domen koji je inicijalno zatražen.

Na primer, jedna promena bita u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu iskoristiti ovo registrujući više bit-flipping domena koji su slični domenu žrtve. Njihova namera je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Možete pretražiti [https://www.expireddomains.net/](https://www.expireddomains.net) za expired domain koji biste mogli koristiti.\
Da biste bili sigurni da expired domain koji planirate da kupite već ima dobar SEO, možete proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste otkrili više validnih email adresa ili verifikovali one koje ste već otkrili, možete proveriti da li možete brute-force-ovati SMTP servere žrtve. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravite da ako korisnici koriste **any web portal to access their mails**, možete proveriti da li je ranjiv na **username brute force**, i iskoristiti tu ranjivost ako je moguće.

## Configuring GoPhish

### Installation

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite i raspakujte unutar `/opt/gophish` i pokrenite `/opt/gophish/gophish`\
U izlazu će vam biti dat password za admin korisnika na portu 3333. Dakle, pristupite tom portu i iskoristite te akreditive da promenite admin lozinku. Možda će biti potrebno da tunelujete taj port na lokalni:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora biti **usmeren** na **IP VPS-a** gde konfigurišete **gophish**.
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
**Mail configuration**

Počnite sa instalacijom: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe promenite vrednosti sledećih promenljivih u fajlu /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** da sadrže ime vašeg domena i **restartujte vaš VPS.**

Sada napravite **DNS A record** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada ćemo testirati slanje e-maila:
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

Da biste kreirali gophish servis tako da se može automatski pokretati i upravljati kao servis, možete kreirati datoteku `/etc/init.d/gophish` sa sledećim sadržajem:
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

Što je domen stariji, manja je verovatnoća da će biti označen kao spam. Zbog toga treba da sačekate što duže (najmanje 1 nedelju) pre phishing procene. Pored toga, ako postavite stranicu vezanu za reputacioni sektor, dobijena reputacija će biti bolja.

Imajte na umu da, čak i ako morate da čekate nedelju dana, možete sada završiti konfiguraciju svega.

### Konfigurišite Reverse DNS (rDNS) zapis

Postavite rDNS (PTR) zapis koji rešava IP adresu VPS-a na ime domena.

### Sender Policy Framework (SPF) zapis

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete vašu SPF politiku (koristite IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen unutar TXT zapisa u domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT record koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj tutorijal se zasniva na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je da konkatenirate obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Možete to uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Samo pristupite stranici i pošaljite e‑poruku na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe da **proverite konfiguraciju e-pošte** slanjem mejla na `check-auth@verifier.port25.com` i **čitajući odgovor** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u fajlu _/var/mail/root_ ako pošaljete mejl kao root).\
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
Takođe možete poslati **poruku na Gmail pod vašom kontrolom** i proveriti **zaglavlja e-pošte** u svom Gmail inboxu — `dkim=pass` bi trebalo da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse Blacklist

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da pokaže da li je vaš domen blokiran od strane spamhouse. Zahtev za uklanjanje domena/IP-a možete poslati na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft Blacklist

​​Zahtev za uklanjanje domena/IP-a možete poslati na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil za slanje

- Postavite neko **ime za identifikaciju** profila pošiljaoca
- Odlučite sa kog naloga ćete slati phishing mejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Korisničko ime i lozinku možete ostaviti praznim, ali obavezno označite opciju Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcije "**Send Test Email**" da biste testirali da li sve radi.\
> Preporučio bih da **pošaljete test mejlove na 10min mails adrese** kako biste izbegli da tokom testiranja dospete na blacklist.

### Predložak emaila

- Postavite neko **ime za identifikaciju** predloška
- Zatim napišite **subject** (ništa čudno, samo nešto što biste očekivali da pročitate u običnom mejlu)
- Proverite da li je označena opcija "**Add Tracking Image**"
- Napišite **email template** (možete koristiti varijable kao u sledećem primeru):
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
Imajte na umu da je, kako biste povećali kredibilitet emaila, preporučljivo koristiti neki potpis iz emaila klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne emailove** kao što su info@ex.com ili press@ex.com ili public@ex.com i pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate **neki validan otkriveni** email i sačekajte odgovor

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Napišite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete **importovati** web stranice.
- Obeležite **Capture Submitted Data** i **Capture Passwords**
- Postavite **redirekciju**

![](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati izmeniti HTML kod stranice i napraviti neke testove lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim unesite taj HTML kod u polje.\
> Imajte u vidu da ako trebate **koristiti statičke resurse** za HTML (npr. neke CSS i JS stranice) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i potom im pristupati iz _**/static/\<filename>**_

> [!TIP]
> Za redirekciju možete **preusmeriti korisnike na legitimnu glavnu web stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, staviti **spinning wheel (**[**https://loading.io/**](https://loading.io)**) na 5 sekundi i zatim naznačiti da je proces uspešan**.

### Users & Groups

- Postavite ime
- **Importujte podatke** (imajte na umu da da biste koristili template za primer potrebni su firstname, last name i email address svakog korisnika)

![](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte kampanju birajući ime, email template, landing page, URL, sending profile i grupu. Imajte na umu da će URL biti link poslat žrtvama

Imajte u vidu da **Sending Profile omogućava slanje test emaila da vidite kako će konačni phishing email izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučio bih da **pošaljete test emailove na 10min mail adrese** kako biste izbegli da budete stavjeni na crnu listu prilikom testiranja.

Kada je sve spremno, samo pokrenite kampanju!

## Website Cloning

Ako iz nekog razloga želite da klonirate web sajt, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing ocenama (pre svega za Red Teams) takođe ćete želeti da pošaljete fajlove koji sadrže neku vrstu backdoora (možda C2 ili nešto što će pokrenuti autentikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično pametan jer falsifikujete pravu web stranicu i prikupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako aplikacija koju ste falsifikovali koristi 2FA, **ove informacije vam neće omogućiti da se predstavljate kao prevarena osoba**.

Tu dolaze alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovi alati omogućavaju izvođenje MitM napada. U suštini, napad funkcioniše na sledeći način:

1. Vi **lažno predstavljate login** formu prave web stranice.
2. Korisnik **pošalje** svoje **credentials** na vašu lažnu stranicu i alat ih prosleđuje pravoj web stranici, **proveravajući da li kredencijali funkcionišu**.
3. Ako je nalog konfigurisan sa **2FA**, MitM stranica će tražiti taj kod i kada ga **korisnik unese**, alat će ga proslediti pravoj web stranici.
4. Kada se korisnik autentifikuje, vi (kao napadač) ćete imati **uhvaćene credentials, 2FA, cookie i sve informacije** o svakoj interakciji dok alat izvodi MitM.

### Via VNC

Šta ako umesto da **preusmerite žrtvu na malicioznu stranicu** koja izgleda kao originalna, pošaljete je u **VNC sesiju sa browserom povezanom na pravu web stranicu**? Bićete u mogućnosti da vidite šta radi, ukradete lozinku, MFA koji koristi, kolačiće...\
Ovo možete uraditi sa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Očigledno, jedan od najboljih načina da znate da li ste otkriveni je da **pretražite svoj domen unutar crnih lista**. Ako se pojavi na listi, na neki način je vaš domen detektovan kao sumnjiv.\
Jedan lak način da proverite da li se vaš domen nalazi na nekoj crnoj listi je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti na mreži**, kako je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa vrlo sličnim imenom** domenu žrtve **i/ili generisati sertifikat** za **subdomen** domena koji kontrolišete koji sadrži **ključnu reč** domena žrtve. Ako **žrtva** izvrši bilo koju vrstu **DNS ili HTTP interakcije** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete biti veoma prikriveni.

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious) da procenite da li će vaš email završiti u spam folderu ili će biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderni intrusion setovi sve češće potpuno preskaču email mamce i **direktno ciljaju service-desk / identity-recovery workflow** kako bi zaobišli MFA. Napad je u potpunosti "living-off-the-land": jednom kada operator ima validne credentiale, pivotuje pomoću ugrađenih admin alata – malware nije potreban.

### Attack flow
1. Recon the victim
* Skupljanje ličnih i korporativnih detalja sa LinkedIn, data breaches, javnog GitHub-a itd.
* Identifikacija visokovrednih identiteta (izvršni, IT, finansije) i mapiranje **tačnog help-desk procesa** za reset lozinke / MFA.
2. Real-time social engineering
* Telefon, Teams ili chat sa help-deskom dok se predstavljate kao ciljna osoba (često sa **spoofed caller-ID** ili **cloned voice**).
* Dostavite prethodno prikupljene PII da prođete verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovani mobilni broj.
3. Immediate post-access actions (≤60 min in real cases)
* Uspostavite foothold kroz bilo koji web SSO portal.
* Enumerišite AD / AzureAD koristeći ugrađene alate (bez postavljanja binarija):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već na whitelisti u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privileged operation** – zahtevajte step-up auth i odobrenje menadžera.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja alarmiraju na:
* Promena MFA metode + autentikacija sa novog uređaja / geolokacije.
* Trenutna elevacija istog principala (user → admin).
* Snimajte help-desk pozive i primenite **call-back na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novopodešeni nalozi ne nasleđuju automatski tokene visokih privilegija.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity ekipe kompenzuju trošak high-touch operacija masovnim napadima koji pretvaraju **search engines & ad networks u kanal isporuke**.

1. **SEO poisoning / malvertising** gura lažni rezultat kao što je `chromium-update[.]site` na vrh pretrage i oglasa.
2. Žrtva preuzme mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader iznosi browser cookies + credential DBs, zatim povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deployuje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* komponentu za persistenciju (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novoregistrovane domene i primenite **Advanced DNS / URL Filtering** na *search-ads* kao i na email.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Monitorišite za child procese browsera koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt-ujte za LOLBins koje često zloupotrebljavaju first-stage loaderi (npr. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Napadači sada povezuju **LLM & voice-clone APIs** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generisanje i slanje >100k emailova / SMS sa randomizovanim formulacijama i tracking linkovima.|
|Generative AI|Kreiranje *jednokratnih* emailova referencirajući javna M&A, interne šale sa društvenih mreža; deep-fake CEO glas u callback prevari.|
|Agentic AI|Autonomno registruje domene, skreperuje open-source intel, kreira sledeće mejlove kada žrtva klikne ali ne unese kredencijale.|

**Defence:**
• Dodajte **dynamic banners** koji ističu poruke poslate iz nepouzdanih automatizacija (na osnovu ARC/DKIM anomalija).
• Primena **voice-biometric challenge phrases** za visokorizične telefonske zahteve.
• Kontinuirano simulirajte AI-generisane mamce u programima podizanja svesti – statični templateovi su zastareli.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Pored klasičnog push-bombinga, operateri jednostavno **forsiraju novu MFA registraciju** tokom help-desk poziva, poništavajući postojeći token korisnika. Bilo koji naknadni login prompt deluje legitimno korisniku.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratite AzureAD/AWS/Okta događaje gde se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu tiho kopirati zlonamerne komande u žrtvin clipboard sa kompromitovane ili typosquatted web stranice, a zatim prevariti korisnika da ih nalepi u **Win + R**, **Win + X** ili terminal prozor, pri čemu se izvršava proizvoljan kod bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateri sve češće zatvaraju svoje phishing tokove iza jednostavne provere uređaja, tako da desktop crawlers nikad ne dođu do krajnjih stranica. Uobičajen obrazac je mali skript koji testira touch-capable DOM i šalje rezultat na server endpoint; non‑mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok mobile korisnici dobijaju potpuni tok.

Minimalni klijentski isječak (tipična logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (pojednostavljeno):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Često primećeno ponašanje servera:
- Postavlja session cookie tokom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) na naredne GET zahteve kada je `is_mobile=false`; prikazuje phishing samo ako je `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non‑mobile; legitimne mobilne putanje žrtava vraćaju 200 sa pratećim HTML/JS.
- Blokirajte ili detaljno proverite stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili slične device provere.

Defence tips:
- Pokrenite crawlers sa mobile‑like fingerprints i uključenim JS-om da otkrijete gated content.
- Generišite alert na sumnjive 500 odgovore nakon `POST /detect` na novoregistrovanim domenima.

## Reference

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
