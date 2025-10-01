# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon žrtve
1. Izaberi **domen žrtve**.
2. Izvrši osnovnu web enumeraciju **pretražujući portale za prijavu** koje koristi žrtva i **odluči** koji ćete **imitirati**.
3. Koristi malo **OSINT** da **pronađeš e-mail adrese**.
2. Pripremi okruženje
1. **Kupi domen** koji ćeš koristiti za phishing procenu
2. **Konfiguriši zapise** vezane za email servis (SPF, DMARC, DKIM, rDNS)
3. Konfiguriši VPS sa **gophish**
3. Pripremi kampanju
1. Pripremi **email šablon**
2. Pripremi **web stranicu** za krađu kredencijala
4. Pokreni kampanju!

## Generisanje sličnih naziva domena ili kupovina pouzdanog domena

### Tehnike varijacija naziva domena

- **Keyword**: Naziv domena **sadrži** važnu **ključnu reč** originalnog domena (npr. zelster.com-management.com).
- **hypened subdomain**: Zameni **tačku crticom** u poddomeni (npr. www-zelster.com).
- **New TLD**: Isti domen koristeći **novi TLD** (npr. zelster.org)
- **Homoglyph**: **Zameni** slovo u nazivu domena sa **slovima koja izgledaju slično** (npr. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zameni mesta** dvema slovima unutar naziva domena (npr. zelsetr.com).
- **Singularization/Pluralization**: Dodaje ili uklanja “s” na kraju naziva domena (npr. zeltsers.com).
- **Omission**: **Ukloni jedno** od slova iz naziva domena (npr. zelser.com).
- **Repetition:** **Ponovi jedno** od slova u nazivu domena (npr. zeltsser.com).
- **Replacement**: Kao homoglyph ali manje prikriveno. Zamenjuje jedno od slova u nazivu domena, možda slovom bliskim na tastaturi (npr. zektser.com).
- **Subdomained**: Uvedi **tačku** unutar naziva domena (npr. ze.lster.com).
- **Insertion**: **Ubaci slovo** u naziv domena (npr. zerltser.com).
- **Missing dot**: Pripoji TLD uz naziv domena. (npr. zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi, koji su sačuvani ili u komunikaciji, automatski preokrenu** zbog različitih faktora kao što su solarne erupcije, kosmičko zračenje ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji DNS server primi** nije isti kao domen koji je prvobitno zatražen.

Na primer, jedna izmena bita u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo registrujući više bit-flipping domena** koji su slični domenu žrtve. Njihova namera je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kupovina pouzdanog domena

Možete pretražiti [https://www.expireddomains.net/](https://www.expireddomains.net) za istekao domen koji biste mogli koristiti.\
Da biste bili sigurni da domen koji planirate da kupite **već ima dobar SEO**, možete proveriti kako je kategorizovan u:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Otkrivanje e-mail adresa

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **otkrili više** validnih e-mail adresa ili **verifikovali one** koje ste već otkrili, možete proveriti da li ih možete brute-force-ovati na SMTP serverima žrtve. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pored toga, ne zaboravite da ako korisnici koriste **bilo koji web portal za pristup svojim mejlovima**, možete proveriti da li je ranjiv na **username brute force**, i iskoristiti ranjivost ako je moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite i raspakujte ga u `/opt/gophish` i pokrenite `/opt/gophish/gophish`\
U izlazu će vam biti dodeljena lozinka za admin korisnika na portu 3333. Dakle, pristupite tom portu i koristite te akreditive da promenite admin lozinku. Možda ćete morati da tunelišete taj port lokalno:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora biti **usmeren** na **IP VPS-a** na kojem konfigurišete **gophish**.
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

Počnite sa instalacijom: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe promenite vrednosti sledećih promenljivih u fajlu /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže vaš domen i **restartujte vaš VPS.**

Sada kreirajte **DNS A record** za `mail.<domain>` koji pokazuje na **ip address** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada ćemo testirati slanje e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Zaustavite izvršavanje gophish-a i hajde da ga konfigurišemo.\
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

Da biste kreirali gophish servis tako da može biti automatski pokrenut i upravljan kao servis, možete kreirati fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfigurisanje servisa i proverite ga tako što ćete uraditi:
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

Što je domen stariji, to je manja verovatnoća da će biti označen kao spam. Zato biste trebali čekati što duže (najmanje 1 nedelju) pre phishing procene. Pored toga, ako postavite stranicu vezanu za sektor sa boljom reputacijom, reputacija koja se stekne biće bolja.

Imajte na umu da, čak i ako morate čekati nedelju dana, možete sada završiti svu konfiguraciju.

### Configure Reverse DNS (rDNS) record

Postavite rDNS (PTR) zapis koji rezoluje IP adresu VPS-a na ime domena.

### Sender Policy Framework (SPF) Record

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete vašu SPF politiku (koristite IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen unutar TXT zapisa na domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je da konkatenirate obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

To možete uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Samo pristupite stranici i pošaljite e-mail na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe **proveriti konfiguraciju e-pošte** slanjem poruke na `check-auth@verifier.port25.com` i **čitajući odgovor** (za ovo ćete morati da **otvorite** port **25** i pogledate odgovor u fajlu _/var/mail/root_ ako pošaljete poruku kao root).\
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
Možete takođe poslati **poruku na Gmail nalog pod vašom kontrolom**, i proveriti **zaglavlja e-pošte** u svom Gmail inboxu, `dkim=pass` bi trebalo da bude prisutno u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam pokaže da li je vaš domen blokiran od strane Spamhouse-a. Možete zatražiti uklanjanje domena/IP-a na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Možete zatražiti uklanjanje domena/IP-a na [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Postavite neko **ime za identifikaciju** profila pošiljaoca
- Odlučite sa kojeg naloga ćete slati phishing mejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možete ostaviti prazno korisničko ime i lozinku, ali obavezno označite opciju Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcionalnosti "**Send Test Email**" da biste testirali da li sve radi.\
> Preporučio bih da **pošaljete test mejlove na 10min mails adrese** kako biste izbegli da prilikom testiranja budete stavljeni na crnu listu.

### Email Template

- Postavite neko **ime za identifikaciju** šablona
- Zatim napišite **subject** (ništa čudno, samo nešto što biste očekivali da pročitate u običnom emailu)
- Uverite se da ste označili "**Add Tracking Image**"
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
Imajte na umu da, **kako biste povećali kredibilitet e‑pošte**, preporučuje se korišćenje nekog potpisa iz e‑maila klijenta. Predlozi:

- Pošaljite poruku na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne adrese** kao što su info@ex.com, press@ex.com ili public@ex.com i pošaljite im e‑mail i sačekajte odgovor.
- Pokušajte da kontaktirate **neku validnu otkrivenu** adresu i sačekajte odgovor.

![](<../../images/image (80).png>)

> [!TIP]
> Šablon e‑pošte takođe omogućava **prilaženje fajlova za slanje**. Ako želite i da ukradete NTLM izazove korišćenjem posebno izrađenih fajlova/dokumenata, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Navedite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete **importovati** veb stranice.
- Obeležite **Capture Submitted Data** i **Capture Passwords**
- Podesite **preusmeravanje**

![](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i izvršite testove lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim unesite taj HTML kod u polje.\
> Imajte u vidu da ako treba da **koristite neke statične resurse** za HTML (npr. CSS i JS fajlove) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i potom im pristupati preko _**/static/\<filename>**_

> [!TIP]
> Za preusmeravanje možete **preusmeriti korisnike na legitimnu glavnu stranicu** žrtve, ili preusmeriti ih na _/static/migration.html_ na primer, prikazati **spinning wheel** ([https://loading.io/](https://loading.io)) 5 sekundi i potom naznačiti da je proces uspešan.

### Korisnici i grupe

- Postavite naziv
- **Importujte podatke** (imajte u vidu da da biste koristili šablon za primer trebate firstname, last name i email address svakog korisnika)

![](<../../images/image (163).png>)

### Kampanja

Na kraju, kreirajte kampanju birajući ime, šablon e‑pošte, landing page, URL, sending profile i grupu. Imajte na umu da će URL biti link poslat žrtvama.

Napomena: **Sending Profile omogućava slanje testne poruke da vidite kako će konačna phishing poruka izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučio bih da **testne poruke šaljete na 10min mail adrese** kako biste izbegli da vas stave na blacklist prilikom testiranja.

Kada je sve spremno, jednostavno pokrenite kampanju!

## Kloniranje vebsajta

Ako iz bilo kog razloga želite da klonirate vebsajt, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenti i fajlovi sa backdoorom

U nekim phishing procenama (uglavnom za Red Team-ove) možda ćete želeti da pošaljete i **fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili nešto što će samo pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Preko Proxy MitM

Prethodna metoda je prilično pametna jer falsifikujete pravu veb stranicu i prikupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako aplikacija koju ste falsifikovali koristi 2FA, **ove informacije vam neće omogućiti da se predstavljate kao prevareni korisnik**.

Tu dolaze alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovi alati vam omogućavaju da generišete MitM napad. U osnovi, napad funkcioniše na sledeći način:

1. Lažirate login formu prave veb stranice.
2. Korisnik pošalje svoje **credentials** na vašu lažnu stranicu i alat ih prosleđuje pravoj stranici, **proveravajući da li credentiali rade**.
3. Ako nalog koristi **2FA**, MitM stranica će tražiti kod i kada **korisnik unese** kod alat će ga proslediti pravoj veb stranici.
4. Kada je korisnik autentifikovan, vi (kao napadač) ste **zabeležili kredencijale, 2FA kod, cookie i sve informacije** svake interakcije dok alat radi MitM.

### Preko VNC

Šta ako umesto da **preusmerite žrtvu na zlonamernu stranicu** koja izgleda kao original, pošaljete žrtvu u **VNC sesiju sa browser-om povezanom na pravu veb stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji koristi, cookie-je...\
To možete uraditi koristeći [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Kako otkriti da ste otkriveni

Očigledno je da je jedan od najboljih načina da znate da li ste “pali” da **pretražite svoj domen u crnim listama**. Ako se pojavi na listi, vaš domen je na neki način detektovan kao sumnjiv.\
Jedan lak način da proverite da li se vaš domen nalazi u nekoj crnoj listi je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da znate da li žrtva **aktivno traži sumnjive phishing domene** kako je objašnjeno u:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen vrlo sličnog imena** žrtvinom domenu **i/ili generisati sertifikat** za **subdomen** domena koji kontrolišete, a koji sadrži **ključnu reč** iz domena žrtve. Ako **žrtva** izvrši bilo koju vrstu **DNS ili HTTP interakcije** sa njima, znaćete da **aktivno traži** sumnjive domene i bićete primorani da budete veoma stealth.

### Procena phishing kampanje

Koristite [**Phishious**](https://github.com/Rices/Phishious) da procenite da li će vaša poruka završiti u spam folderu, biti blokirana ili uspešna.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Savremeni intrusion setovi sve češće uopšte preskaču e‑mail mamce i **direktno ciljaju service-desk / workflow za identity-recovery** kako bi zaobišli MFA. Napad je u potpunosti “living-off-the-land”: jednom kada operator posede validne kredencijale pivot-uje koristeći ugrađene admin alate – nije potreban malware.

### Tok napada
1. Recon na metu
* Prikupljanje ličnih i korporativnih podataka sa LinkedIn-a, iz data breach-eva, javnog GitHub-a itd.
* Identifikujte visokovredne identitete (izvršni, IT, finansije) i izbrojte tačan help-desk proces za reset lozinke / MFA.
2. Socijalni inženjering u realnom vremenu
* Poziv, Teams ili chat help-deska dok se predstavljate kao meta (često sa **lažiranim caller-ID** ili **kloniranim glasom**).
* Dajte ranije prikupljene PII podatke da prođete verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovani mobilni broj.
3. Odmah nakon pristupa (≤60 min u realnim slučajevima)
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
* Lateralan pokret koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već na whitelist-i u okruženju.

### Detekcija i mitigacija
* Tretirajte help-desk identity recovery kao **privilegovan proces** – zahtevajte step-up auth i odobrenje menadžera.
* Implementirajte **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja alertuju na:
* Promenu MFA metode + autentikaciju sa novog uređaja / geolokacije.
* Odmahšnja elevacija istog principala (user → admin).
* Snimajte help-desk pozive i primenite **call-back na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novo resetovani nalozi **ne dobijaju automatski** visoke privilegovane tokene.

---

## Decepcija u velikom obimu – SEO Poisoning & “ClickFix” kampanje
Commodity ekipe pokrivaju troškove high-touch operacija masovnim napadima koji pretvaraju **pretraživače i ad network-e u kanal isporuke**.

1. **SEO poisoning / malvertising** ističe lažni rezultat poput `chromium-update[.]site` u vrhu search oglasa.
2. Žrtva preuzme mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrira cookie-je pretraživača + baze kredencijala, zatim povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deploy-uje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* komponentu za persistenciju (registry Run ključ + scheduled task)

### Saveti za hardening
* Blokirajte novo registrovane domene i primenite **Advanced DNS / URL Filtering** na *search-ads* kao i na e‑mail.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Monitorišite child procese browser-a koji otvaraju instalere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Lovite na LOLBins često zloupotrebljavane od strane first-stage loadera (npr. `regsvr32`, `curl`, `mshta`).

---

## AI‑poboljšane phishing operacije
Napadači sada povezuju **LLM & voice-clone API-je** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Sloj | Primer upotrebe od strane threat aktora |
|------|----------------------------------------|
| Automatizacija | Generisanje i slanje >100k e‑mailova / SMS-ova sa randomizovanim porukama i tracking linkovima. |
| Generativni AI | Proizvodnja jedinstvenih e‑mailova koji referenciraju javne M&A, interne šale sa društvenih mreža; deep-fake glas CEO-a u callback prevari. |
| Agentic AI | Autonomna registracija domena, scrape open-source intel-a, kreiranje sledećih mejlova kada žrtva klikne ali ne pošalje kredencijale. |

**Odbrana:**
• Dodajte **dinamičke banere** koji ističu poruke poslate iz nepouzdanih automatizovanih izvora (preko ARC/DKIM anomalija).  
• Implementirajte **voice-biometric challenge phrases** za visokorizične telefonske zahteve.  
• Kontinuirano simulirajte AI‑generisane mamce u programima svesti – statični šabloni su zastareli.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing varijanta – Forsirani reset
Pored klasičnog push-bombinga, operateri jednostavno **forsiraju novu MFA registraciju** tokom poziva help-deska, poništavajući korisnikov postojeći token. Bilo koji naredni prompt za prijavu izgleda legitimno za žrtvu.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno kopirati zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice i zatim prevariti korisnika da ih zalepi u **Win + R**, **Win + X** ili u prozor terminala, čime se izvršava proizvoljni kod bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
