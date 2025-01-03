# Phishing Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Metodologija

1. Istraži žrtvu
1. Izaberi **domen žrtve**.
2. Izvrši osnovnu web enumeraciju **tražeći login portale** koje koristi žrtva i **odluči** koji ćeš **imitirati**.
3. Koristi neki **OSINT** da **pronađeš emailove**.
2. Pripremi okruženje
1. **Kupite domen** koji ćete koristiti za phishing procenu
2. **Konfigurišite email servis** povezane zapise (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite VPS sa **gophish**
3. Pripremi kampanju
1. Pripremi **email šablon**
2. Pripremi **web stranicu** za krađu kredencijala
4. Pokreni kampanju!

## Generišite slične nazive domena ili kupite pouzdan domen

### Tehnike varijacije naziva domena

- **Ključna reč**: Naziv domena **sadrži** važnu **ključnu reč** originalnog domena (npr., zelster.com-management.com).
- **poddomen sa crticom**: Promenite **tačku u crtu** poddomena (npr., www-zelster.com).
- **Nova TLD**: Isti domen koristeći **novu TLD** (npr., zelster.org)
- **Homoglif**: **Zamenjuje** jedno slovo u nazivu domena sa **sličnim slovima** (npr., zelfser.com).
- **Transpozicija:** **Menja dva slova** unutar naziva domena (npr., zelsetr.com).
- **Singularizacija/Pluralizacija**: Dodaje ili uklanja “s” na kraju naziva domena (npr., zeltsers.com).
- **Odbacivanje**: **Uklanja jedno** od slova iz naziva domena (npr., zelser.com).
- **Ponavljanje:** **Ponavlja jedno** od slova u nazivu domena (npr., zeltsser.com).
- **Zamena**: Kao homoglif, ali manje suptilan. Zamenjuje jedno od slova u nazivu domena, možda sa slovom u blizini originalnog slova na tastaturi (npr, zektser.com).
- **Poddomen**: Uvedite **tačku** unutar naziva domena (npr., ze.lster.com).
- **Umetanje**: **Umeće slovo** u naziv domena (npr., zerltser.com).
- **Nedostajuća tačka**: Dodajte TLD nazivu domena. (npr., zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da jedan od nekih bitova koji su pohranjeni ili u komunikaciji može automatski da se preokrene** zbog raznih faktora kao što su solarne erupcije, kosmičke zrake ili greške u hardveru.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji je primljen od DNS servera** nije isti kao domen koji je prvobitno zatražen.

Na primer, jedna bit modifikacija u domenu "windows.com" može ga promeniti u "windnws.com."

Napadači mogu **iskoristiti ovo registrujući više domena sa preokrenutim bitovima** koji su slični domenu žrtve. Njihova namera je da preusmere legitimne korisnike na svoju infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kupite pouzdan domen

Možete pretraživati na [https://www.expireddomains.net/](https://www.expireddomains.net) za istekao domen koji biste mogli koristiti.\
Da biste se uverili da je istekao domen koji planirate da kupite **već ima dobar SEO**, možete proveriti kako je kategorizovan u:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Otkriće Emailova

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **otkrili više** validnih email adresa ili **verifikovali one** koje ste već otkrili, možete proveriti da li možete da brute-force-ujete smtp servere žrtve. [Saznajte kako da verifikujete/otkrijete email adresu ovde](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Pored toga, ne zaboravite da ako korisnici koriste **bilo koji web portal za pristup svojim mailovima**, možete proveriti da li je ranjiv na **brute force korisničkog imena**, i iskoristiti ranjivost ako je moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite i raspakujte ga unutar `/opt/gophish` i izvršite `/opt/gophish/gophish`\
Biće vam dat password za admin korisnika na portu 3333 u izlazu. Stoga, pristupite tom portu i koristite te kredencijale da promenite admin lozinku. Možda ćete morati da tunelujete taj port na lokalno:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre ovog koraka, trebali biste **već kupiti domen** koji ćete koristiti i on mora **biti usmeren** na **IP VPS-a** gde konfigurišete **gophish**.
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

Počnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće fajlove:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Promenite takođe vrednosti sledećih varijabli unutar /etc/postfix/main.cf**

`myhostname = <domena>`\
`mydestination = $myhostname, <domena>, localhost.com, localhost`

Na kraju, izmenite fajlove **`/etc/hostname`** i **`/etc/mailname`** na ime vaše domene i **ponovo pokrenite vaš VPS.**

Sada, kreirajte **DNS A zapis** za `mail.<domena>` koji pokazuje na **ip adresu** VPS-a i **DNS MX** zapis koji pokazuje na `mail.<domena>`

Sada hajde da testiramo slanje email-a:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfiguracija**

Prekinite izvršavanje gophisha i hajde da ga konfigurišemo.\
Izmenite `/opt/gophish/config.json` na sledeće (obratite pažnju na korišćenje https):
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

Da biste kreirali gophish servis koji može da se pokrene automatski i upravlja kao servis, možete kreirati datoteku `/etc/init.d/gophish` sa sledećim sadržajem:
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
Završite konfiguraciju usluge i proverite je tako što ćete:
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

### Čekajte i budite legitimni

Što je domen stariji, to je manje verovatno da će biti uhvaćen kao spam. Zato treba da čekate što je duže moguće (barem 1 nedelju) pre phishing procene. Štaviše, ako postavite stranicu o reputacionom sektoru, stečena reputacija će biti bolja.

Imajte na umu da čak i ako morate da čekate nedelju dana, možete završiti konfiguraciju svega sada.

### Konfigurišite Reverse DNS (rDNS) zapis

Postavite rDNS (PTR) zapis koji rešava IP adresu VPS-a na naziv domena.

### Sender Policy Framework (SPF) Zapis

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) za generisanje vaše SPF politike (koristite IP VPS mašine)

![](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen unutar TXT zapisa unutar domena:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Morate **konfigurisati DMARC zapis za novu domenu**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Morate kreirati novi DNS TXT zapis koji pokazuje na ime hosta `_dmarc.<domain>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novu domenu**. Ako ne znate šta je DMARC zapis [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/#dkim).

Ovaj tutorijal se zasniva na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> Morate spojiti oba B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testirajte svoj rezultat konfiguracije e-pošte

To možete uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com)\
Samo pristupite stranici i pošaljite e-poštu na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe **proveriti vašu email konfiguraciju** slanjem emaila na `check-auth@verifier.port25.com` i **čitajući odgovor** (za ovo ćete morati da **otvorite** port **25** i vidite odgovor u fajlu _/var/mail/root_ ako pošaljete email kao root).\
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
Možete takođe poslati **poruku na Gmail koji kontrolišete** i proveriti **zaglavlja e-pošte** u vašem Gmail inboxu, `dkim=pass` treba da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može vam pokazati da li je vaša domena blokirana od strane spamhouse-a. Možete zatražiti uklanjanje vaše domene/IP na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Možete zatražiti uklanjanje vaše domene/IP na [https://sender.office.com/](https://sender.office.com).

## Kreirajte i pokrenite GoPhish kampanju

### Profil pošiljaoca

- Postavite **ime za identifikaciju** profila pošiljaoca
- Odlučite sa kojeg naloga ćete slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Možete ostaviti prazne korisničko ime i lozinku, ali obavezno proverite opciju Ignoriši greške sertifikata

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> Preporučuje se korišćenje funkcionalnosti "**Pošalji test email**" da biste proverili da li sve funkcioniše.\
> Preporučujem da **pošaljete test emailove na 10min mail adrese** kako biste izbegli stavljanje na crnu listu tokom testiranja.

### Email šablon

- Postavite **ime za identifikaciju** šablona
- Zatim napišite **predmet** (ništa čudno, samo nešto što biste mogli očekivati da pročitate u redovnom emailu)
- Uverite se da ste označili "**Dodaj sliku za praćenje**"
- Napišite **email šablon** (možete koristiti varijable kao u sledećem primeru):
```markup
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
Napomena da je **preporučljivo koristiti neku potpisanu poruku iz emaila klijenta** kako bi se povećala kredibilnost emaila. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži neki potpis.
- Potražite **javne email adrese** kao što su info@ex.com ili press@ex.com ili public@ex.com i pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate **neku validnu otkrivenu** email adresu i sačekajte odgovor.

![](<../../images/image (80).png>)

> [!NOTE]
> Email šablon takođe omogućava **priključivanje datoteka za slanje**. Ako želite da ukradete NTLM izazove koristeći neke posebno kreirane datoteke/dokumente [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Odredišna stranica

- Napišite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete **importovati** web stranice.
- Označite **Zabeleži poslata podataka** i **Zabeleži lozinke**
- Postavite **preusmeravanje**

![](<../../images/image (826).png>)

> [!NOTE]
> Obično ćete morati da modifikujete HTML kod stranice i napravite neke testove lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima.** Zatim, napišite taj HTML kod u kutiju.\
> Imajte na umu da ako trebate da **koristite neke statične resurse** za HTML (možda neke CSS i JS stranice) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i zatim im pristupiti iz _**/static/\<filename>**_

> [!NOTE]
> Za preusmeravanje možete **preusmeriti korisnike na legitimnu glavnu web stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_, na primer, staviti neku **spinning wheel (**[**https://loading.io/**](https://loading.io)**) na 5 sekundi i zatim naznačiti da je proces bio uspešan**.

### Korisnici i grupe

- Postavite ime
- **Uvezite podatke** (imajte na umu da da biste koristili šablon za primer, trebate ime, prezime i email adresu svakog korisnika)

![](<../../images/image (163).png>)

### Kampanja

Na kraju, kreirajte kampanju birajući ime, email šablon, odredišnu stranicu, URL, profil slanja i grupu. Imajte na umu da će URL biti link poslat žrtvama.

Imajte na umu da **Profil slanja omogućava slanje testnog emaila da vidite kako će izgledati konačni phishing email**:

![](<../../images/image (192).png>)

> [!NOTE]
> Preporučio bih da **šaljete testne emailove na 10min mail adrese** kako biste izbegli stavljanje na crnu listu tokom testiranja.

Kada je sve spremno, jednostavno pokrenite kampanju!

## Kloniranje web stranica

Ako iz bilo kog razloga želite da klonirate web stranicu, proverite sledeću stranicu:

{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenti i datoteke sa backdoor-om

U nekim phishing procenama (pretežno za Red Teams) takođe ćete želeti da **šaljete datoteke koje sadrže neku vrstu backdoor-a** (možda C2 ili možda samo nešto što će pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Putem Proxy MitM

Prethodni napad je prilično pametan jer lažete pravu web stranicu i prikupljate informacije koje je postavio korisnik. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako je aplikacija koju ste lažirali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da se pretvarate da ste prevareni korisnik**.

Ovde su alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena) korisni. Ovaj alat će vam omogućiti da generišete MitM napad. U suštini, napadi funkcionišu na sledeći način:

1. **Pretvarate se da ste login** forma prave web stranice.
2. Korisnik **šalje** svoje **akreditive** na vašu lažnu stranicu, a alat šalje te podatke na pravu web stranicu, **proveravajući da li akreditivi rade**.
3. Ako je nalog konfiguran sa **2FA**, MitM stranica će tražiti to, a kada **korisnik unese** to, alat će to poslati na pravu web stranicu.
4. Kada je korisnik autentifikovan, vi (kao napadač) ćete imati **uhvaćene akreditive, 2FA, kolačiće i sve informacije** svake interakcije dok alat obavlja MitM.

### Putem VNC

Šta ako umesto da **šaljete žrtvu na zloćudnu stranicu** koja izgleda kao originalna, pošaljete ga na **VNC sesiju sa pretraživačem povezanom na pravu web stranicu**? Moći ćete da vidite šta radi, ukradete lozinku, korišćeni MFA, kolačiće...\
To možete uraditi sa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Otkrivanje detekcije

Očigledno je jedan od najboljih načina da saznate da li ste otkriveni da **pretražujete svoju domenu unutar crnih lista**. Ako se pojavi na listi, na neki način je vaša domena otkrivena kao sumnjiva.\
Jedan jednostavan način da proverite da li se vaša domena pojavljuje na bilo kojoj crnoj listi je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjivu phishing aktivnost u prirodi** kao što je objašnjeno u:

{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domenu sa veoma sličnim imenom** kao domena žrtve **i/ili generisati sertifikat** za **poddomen** domene koju kontrolišete **sadržeći** **ključnu reč** domena žrtve. Ako **žrtva** izvrši bilo kakvu vrstu **DNS ili HTTP interakcije** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma diskretni.

### Procena phishing-a

Koristite [**Phishious** ](https://github.com/Rices/Phishious) da procenite da li će vaš email završiti u spam folderu ili će biti blokiran ili uspešan.

## Reference

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
