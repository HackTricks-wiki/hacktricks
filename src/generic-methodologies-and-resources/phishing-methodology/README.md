# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon žrtve
1. Selektujte **domen žrtve**.
2. Obavite osnovnu web enumeraciju **tražeći login portale** koje žrtva koristi i **odlučite** koji ćete **impostovati**.
3. Koristite **OSINT** da **pronađete email-ove**.
2. Pripremite okruženje
1. **Kupite domen** koji ćete koristiti za phishing procenu
2. **Konfigurišite zapise** vezane za email servis (SPF, DMARC, DKIM, rDNS)
3. Podesite VPS sa **gophish**
3. Pripremite kampanju
1. Pripremite **email template**
2. Pripremite **web stranicu** za krađu kredencijala
4. Pokrenite kampanju!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Ime domena **sadrži** važnu **ključnu reč** originalnog domena (npr., zelster.com-management.com).
- **hypened subdomain**: Zamenite **tačku crticom** u poddomeni (npr., www-zelster.com).
- **New TLD**: Isti domen koristeći **novi TLD** (npr., zelster.org)
- **Homoglyph**: **Zameni** slovo u imenu domena sa **slovima koja liče** (npr., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zameni dve strane** unutar imena domena (npr., zelsetr.com).
- **Singularization/Pluralization**: Doda ili ukloni “s” na kraju imena domena (npr., zeltsers.com).
- **Omission**: **Ukloni jedno** od slova iz imena domena (npr., zelser.com).
- **Repetition:** **Ponavlja jedno** od slova u imenu domena (npr., zeltsser.com).
- **Replacement**: Slično homoglyph, ali manje prikriveno. Zamenjuje jedno od slova u imenu domena, možda slovom u blizini originalnog na tastaturi (npr., zektser.com).
- **Subdomained**: Uvedite **tačku** unutar imena domena (npr., ze.lster.com).
- **Insertion**: **Umetne slovo** u ime domena (npr., zerltser.com).
- **Missing dot**: Pripoji TLD direktno imenu domena. (npr., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se pojedini bitovi** u skladištenju ili komunikaciji automatski preokrenu zbog različitih faktora kao što su solarne oluje, kosmičko zračenje ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da domen koji DNS server zaprimi **nije isti** kao domen koji je inicijalno zatražen.

Na primer, jedna promena bita u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo registrujući više bit-flipping domena** sličnih domenu žrtve. Njihova namera je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Možete pretražiti na [https://www.expireddomains.net/](https://www.expireddomains.net) za istekao domen koji biste mogli koristiti.\
Da biste bili sigurni da istakao domen koji planirate da kupite **već ima dobar SEO**, možete proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **otkrili više** validnih email adresa ili **verifikovali one** koje ste već pronašli, možete proveriti da li možete brute-forceovati SMTP servere žrtve. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravite da ako korisnici koriste **bilo koji web portal za pristup svojim mejlovima**, možete proveriti da li je ranjiv na **username brute force**, i iskoristiti ranjivost ako je moguće.

## Configuring GoPhish

### Installation

Možete ga download-ovati sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite i raspakujte ga u `/opt/gophish` i izvršite `/opt/gophish/gophish`\
U izlazu će vam biti dat password za admin korisnika na portu 3333. Stoga, pristupite tom portu i koristite te kredencijale da promenite admin password. Možda ćete morati da tunelujete taj port lokalno:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre nego što sprovedete ovaj korak, trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora biti **usmeren** na **IP VPS-a** na kojem konfigurišete **gophish**.
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

**Takođe promenite vrednosti sledećih varijabli unutar /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** na vaše ime domena i **restartujte vaš VPS.**

Sada kreirajte **DNS A record** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada da testiramo slanje emaila:
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
Završi konfigurisanje servisa i proveru njegovog rada:
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

Što je domen stariji, to je manje verovatno da će biti označen kao spam. Zbog toga treba da sačekate što duže (najmanje 1 nedelju) pre phishing procene. Pored toga, ako postavite stranicu u vezi sa sektorom koji utiče na reputaciju, dobijena reputacija će biti bolja.

Imajte na umu da, iako treba da sačekate nedelju dana, možete sada završiti svu konfiguraciju.

### Configure Reverse DNS (rDNS) record

Podesite rDNS (PTR) zapis koji rezolvuje IP adresu VPS-a na ime domena.

### Sender Policy Framework (SPF) Record

You must **configure a SPF record for the new domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen u TXT zapisu na domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) zapis

Morate konfigurisati DMARC zapis za novi domen. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj tutorijal je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je konkatenirati obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testirajte ocenu konfiguracije e-pošte

Možete to uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Jednostavno otvorite stranicu i pošaljite e-poštu na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Takođe možete da **proverite podešavanje email-a** slanjem poruke na `check-auth@verifier.port25.com` i **čitajući odgovor** (za ovo ćete morati da **otvorite** port **25** i pogledate odgovor u fajlu _/var/mail/root_ ako pošaljete poruku kao root).\
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
Možete takođe poslati **poruku na Gmail nalog pod vašom kontrolom**, i proveriti **zaglavlja e-pošte** u prijemnom sandučetu vašeg Gmail naloga; `dkim=pass` bi trebalo da bude prisutno u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam pokaže da li je vaš domen blokiran na Spamhouse. Možete zatražiti uklanjanje vašeg domena/IP adrese na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Možete zatražiti uklanjanje vašeg domena/IP adrese na [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Postavite neko **ime za identifikaciju** profila pošiljaoca
- Odlučite sa kog naloga ćete slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možete ostaviti prazno polje za korisničko ime i lozinku, ali obavezno štiklirajte opciju Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcionalnosti "**Send Test Email**" da biste testirali da li sve radi.\
> Preporučujem da **pošaljete test emailove na 10min mails adrese** kako biste izbegli da budete stavljeni na crnu listu tokom testiranja.

### Šablon emaila

- Postavite neko **ime za identifikaciju** šablona
- Zatim napišite **subject** (ništa čudno, samo nešto što biste očekivali da pročitate u običnom emailu)
- Uverite se da ste označili opciju "**Add Tracking Image**"
- Napišite **šablon emaila** (možete koristiti promenljive kao u sledećem primeru):
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
Imajte na umu da je, **kako biste povećali kredibilitet email-a**, preporučljivo upotrebiti neki potpis iz poruke stvarnog klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne email-ove** poput info@ex.com ili press@ex.com ili public@ex.com i pošaljite im poruku, pa sačekajte odgovor.
- Pokušajte kontaktirati **neki validan otkriven** email i sačekajte odgovor.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe dozvoljava **prilaženje fajlova za slanje**. Ako želite i da ukradete NTLM challenge-ove koristeći specijalno oblikovane fajlove/dokumente, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Napišite **ime**
- **Napišite HTML kod** web stranice. Imajte u vidu da možete **importovati** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Postavite **redirekciju**

![](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati izmeniti HTML kod stranice i napraviti neka lokalna testiranja (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatom.** Nakon toga, unesite taj HTML kod u polje.\
> Imajte na umu da, ako vam trebaju **staticki resursi** za HTML (npr. neki CSS ili JS fajlovi), možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i potom im pristupiti preko _**/static/\<filename>**_

> [!TIP]
> Za redirekciju možete **preusmeriti korisnike na legitimnu glavnu stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, prikazati neku **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 sekundi i potom obavestiti da je proces uspešno završen**.

### Users & Groups

- Postavite ime
- **Uvezite podatke** (napomena: da biste koristili šablon za primer treba vam firstname, last name i email address svakog korisnika)

![](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte campaign birajući ime, email template, landing page, URL, sending profile i grupu. Imajte na umu da će URL biti link koji se šalje žrtvama

Imajte na umu da **Sending Profile omogućava slanje test email-a da vidite kako će konačni phishing email izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučio bih da **test email-ove šaljete na 10min mails adrese** kako biste izbegli da vas testiranja stave na crnu listu.

Kada je sve spremno, samo pokrenite campaign!

## Website Cloning

Ako iz bilo kog razloga želite da clone-ujete web sajt, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) ćete želeti da takođe **pošaljete fajlove koji sadrže neku vrstu backdoora** (možda C2 ili nešto što će pokrenuti autentikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično pametan jer lažirate stvarnu veb-stranicu i prikupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako aplikacija koju ste falsifikovali koristi 2FA, **ove informacije vam neće omogućiti da se lažno predstavite prevarenoj osobi**.

Tu dolaze alati poput [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ti alati omogućavaju izvođenje MitM tipa napada. U suštini, napad funkcioniše na sledeći način:

1. Vi **lažirate login** formu prave veb-stranice.
2. Korisnik **pošalje** svoje **credentials** vašoj lažnoj strani i alat ih prosleđuje pravoj stranici, **proveravajući da li kredencijali rade**.
3. Ako je nalog podešen sa **2FA**, MitM stranica će tražiti taj kod i kada ga **korisnik unese**, alat će ga proslediti pravoj stranici.
4. Kada se korisnik autentifikuje, vi (kao napadač) ćete biti u mogućnosti da **zabeležite kredencijale, 2FA, cookie i sve informacije** iz svake interakcije dok alat izvodi MitM.

### Via VNC

Šta ako umesto da **preusmeravate žrtvu na malicioznu stranicu** koja izgleda kao original, pošaljete je u **VNC sesiju sa browser-om povezanom na pravu stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji je upotrebljen, cookie-e...\
Ovo možete izvesti uz pomoć [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Očigledno, jedan od najboljih načina da saznate da li ste otkriveni je da **proverite vaš domen u crnim listama**. Ako se pojavi na listi, na neki način vaš domen je detektovan kao sumnjiv.\
Jedan jednostavan način da proverite da li se vaš domen nalazi u nekoj crnoj listi je upotreba [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti u divljini**, kao što je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** domenu žrtve **i/ili generisati sertifikat** za **subdomen** domena koji kontrolišete koji sadrži **ključnu reč** žrtvinog domena. Ako **žrtva** izvrši bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma prikriveni.

### Evaluate the phishing

Koristite [**Phishious**](https://github.com/Rices/Phishious) da procenite da li će vaš email završiti u spam folderu, da li će biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderni intruzioni timovi sve češće preskaču email mamce u potpunosti i **direktno ciljaju service-desk / identity-recovery workflow** da bi zaobišli MFA. Napad je potpuno "living-off-the-land": kada operater dobije validne kredencijale, pivotuje koristeći ugrađene admin alate – nije potreban malware.

### Attack flow
1. Recon žrtve
* Sakupite lične i korporativne podatke sa LinkedIn-a, iz data breach-eva, javnog GitHub-a itd.
* Identifikujte visokovredne identitete (izvršni, IT, finansije) i izbrojite **tačan help-desk proces** za reset lozinke / MFA.
2. Real-time social engineering
* Telefon, Teams ili chat sa help‑deskom dok se predstavljate kao meta (često sa **spoofed caller‑ID** ili **kloniranim glasom**).
* Pružite prethodno prikupljene PII podatke da biste prošli verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovani mobilni broj.
3. Neposredne post‑access akcije (≤60 min u realnim slučajevima)
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
* Lateralno kretanje koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već na whitelisti u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privilegovan operaciju** – zahtevajte step-up autentikaciju i odobrenje menadžera.
* Deploy-ujte **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja alarmiraju na:
* Promenu MFA metode + autentikaciju sa novog uređaja / geolokacije.
* Neposrednu elevaciju iste principe (user → admin).
* Snimajte pozive help-desk-a i namećite **call-back na već registrovani broj** pre bilo kog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novo resetovani nalozi **ne** dobiju automatski visoko-privilegovane tokene.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity timovi nadoknađuju cenu high-touch operacija masovnim napadima koji pretvaraju **search engines & ad networks u kanal isporuke**.

1. **SEO poisoning / malvertising** gura lažni rezultat poput `chromium-update[.]site` na vrh pretraga i oglasa.
2. Žrtva preuzme mali **first-stage loader** (često JS/HTA/ISO). Primeri zabeleženi od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrira browser cookie-e + credential DB-e, zatim povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deploy-uje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* komponentu za persistenciju (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novo registrovane domene i namećite **Advanced DNS / URL Filtering** na *search-ads* kao i u email-u.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Monitorišite child procese browser-a koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tražite LOLBins često zloupotrebljavane od strane first-stage loader-a (npr. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Napadači sada povezuju **LLM & voice-clone API-je** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automatizacija|Generisanje i slanje >100k email-ova / SMS-ova sa nasumično promenjenim formulacijama i tracking linkovima.|
|Generativni AI|Proizvodnja *jednokratnih* email-ova koji referenciraju javne M&A, interne šale sa društvenih mreža; deep‑fake glas CEO-a u callback prevari.|
|Agentic AI|Autonomno registrovanje domena, scrapovanje open-source intel-a, kreiranje narednih mailova kada žrtva klikne ali ne unese kredencijale.|

**Odbrana:**
• Dodajte **dinamičke banere** koji ističu poruke poslate iz nepouzdanih automatizacija (preko ARC/DKIM anomalija).  
• Implementirajte **voice-biometric challenge phrases** za zahteve sa telefona visokog rizika.  
• Kontinuirano simulirajte AI-generisane mamce u programima za podizanje svesti – statični šabloni su zastareli.

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
Pored klasičnog push-bombinga, operateri jednostavno **forsiraju novu MFA registraciju** tokom help-desk poziva, što poništava korisnikov postojeći token. Bilo koji naredni prompt za prijavu izgleda legitimno žrtvi.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratiti događaje u AzureAD/AWS/Okta gde se **`deleteMFA` + `addMFA`** događaju **u roku od nekoliko minuta sa iste IP adrese**.



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
Operatori sve češće ograničavaju svoje phishing tokove iza jednostavne provere uređaja kako desktop crawleri nikada ne bi došli do krajnjih stranica. Uobičajen obrazac je mali skript koji testira da li je DOM touch‑capable i šalje rezultat na server endpoint; desktop klijenti dobijaju HTTP 500 (ili praznu stranicu), dok mobilnim korisnicima služi ceo tok.

Minimalni klijentski snippet (tipična logika):
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
- Vraća 500 (ili placeholder) na naredne GET zahteve kada je `is_mobile=false`; servira phishing samo ako je `true`.

Heuristike za otkrivanje:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za ne‑mobilne; legitimne putanje mobilnih žrtava vraćaju 200 sa pratećim HTML/JS.
- Blokirajte ili detaljno proverite stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili slične provere uređaja.

Saveti za odbranu:
- Pokrenite crawlers sa mobilnim fingerprint-ima i uključenim JS-om da otkrijete gated sadržaj.
- Upozorite na sumnjive 500 odgovore koji slede posle `POST /detect` na tek registrovanim domenima.

## Reference

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
