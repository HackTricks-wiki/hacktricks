# Metodologia Phishingu

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Rozpoznanie ofiary
1. Wybierz **domenę ofiary**.
2. Wykonaj podstawową enumerację sieci **szukając portali logowania** używanych przez ofiarę i **zdecyduj**, który z nich będziesz **podrabiać**.
3. Użyj **OSINT**, aby **znaleźć e-maile**.
2. Przygotowanie środowiska
1. **Kup domenę**, którą zamierzasz użyć do oceny phishingowej.
2. **Skonfiguruj usługi e-mail** związane z rekordami (SPF, DMARC, DKIM, rDNS).
3. Skonfiguruj VPS z **gophish**.
3. Przygotowanie kampanii
1. Przygotuj **szablon e-maila**.
2. Przygotuj **stronę internetową** do kradzieży danych logowania.
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki wariacji nazw domen

- **Słowo kluczowe**: Nazwa domeny **zawiera** ważne **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).
- **poddomena z myślnikiem**: Zmień **kropkę na myślnik** w poddomenie (np. www-zelster.com).
- **Nowe TLD**: Ta sama domena używająca **nowego TLD** (np. zelster.org).
- **Homoglif**: **Zastępuje** literę w nazwie domeny **literami, które wyglądają podobnie** (np. zelfser.com).
- **Transpozycja:** **Zamienia dwie litery** w nazwie domeny (np. zelsetr.com).
- **Liczba pojedyncza/mnoga**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Ominięcie**: **Usuwa jedną** z liter z nazwy domeny (np. zelser.com).
- **Powtórzenie:** **Powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).
- **Zamiana**: Jak homoglif, ale mniej dyskretny. Zastępuje jedną z liter w nazwie domeny, być może literą bliską oryginalnej literze na klawiaturze (np. zektser.com).
- **Poddomenowana**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Wstawienie**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Brakująca kropka**: Dołącz TLD do nazwy domeny. (np. zelstercom.com)

**Narzędzia automatyczne**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony internetowe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że jeden z bitów przechowywanych lub w komunikacji może zostać automatycznie zmieniony** z powodu różnych czynników, takich jak wybuchy słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy ten koncept jest **stosowany do zapytań DNS**, możliwe jest, że **domena odebrana przez serwer DNS** nie jest taka sama jak domena pierwotnie żądana.

Na przykład, pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele domen z bit-flipping**, które są podobne do domeny ofiary. Ich intencją jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Aby uzyskać więcej informacji, przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kup zaufaną domenę

Możesz poszukać na [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłej domeny, którą mógłbyś wykorzystać.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą SEO**, możesz sprawdzić, jak jest sklasyfikowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Odkrywanie e-maili

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% darmowe)
- [https://phonebook.cz/](https://phonebook.cz) (100% darmowe)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** ważnych adresów e-mail lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy możesz przeprowadzić brute-force na serwerach smtp ofiary. [Dowiedz się, jak zweryfikować/odkryć adres e-mail tutaj](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto nie zapomnij, że jeśli użytkownicy korzystają z **jakiegokolwiek portalu internetowego do dostępu do swoich e-maili**, możesz sprawdzić, czy jest on podatny na **brute force nazwy użytkownika** i wykorzystać tę podatność, jeśli to możliwe.

## Konfigurowanie GoPhish

### Instalacja

Możesz go pobrać z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj go w `/opt/gophish` i uruchom `/opt/gophish/gophish`\
Otrzymasz hasło dla użytkownika admin na porcie 3333 w wyjściu. Dlatego uzyskaj dostęp do tego portu i użyj tych danych logowania, aby zmienić hasło administratora. Może być konieczne tunelowanie tego portu do lokalnego:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś **już kupić domenę**, którą zamierzasz użyć, i musi ona **wskazywać** na **IP VPS**, na którym konfigurujesz **gophish**.
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

Zacznij od instalacji: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Zmień także wartości następujących zmiennych w /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na swoją nazwę domeny i **zrestartuj swój VPS.**

Teraz stwórz **rekord A DNS** dla `mail.<domain>` wskazujący na **adres IP** VPS oraz **rekord MX DNS** wskazujący na `mail.<domain>`

Teraz przetestuj wysyłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj wykonywanie gophish i skonfiguruj go.\
Zmień `/opt/gophish/config.json` na następujące (zwróć uwagę na użycie https):
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
Zakończ konfigurowanie usługi i sprawdź to, wykonując:
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

### Czekaj i bądź legitny

Im starsza domena, tym mniej prawdopodobne, że zostanie uznana za spam. Dlatego powinieneś czekać jak najdłużej (przynajmniej 1 tydzień) przed oceną phishingu. Co więcej, jeśli umieścisz stronę o reputacyjnym sektorze, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz czekać tydzień, możesz teraz zakończyć konfigurację wszystkiego.

### Skonfiguruj rekord odwrotnego DNS (rDNS)

Ustaw rekord rDNS (PTR), który rozwiązuje adres IP VPS na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej polityki SPF (użyj adresu IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, która musi być ustawiona wewnątrz rekordu TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord uwierzytelniania wiadomości opartego na domenie, raportowania i zgodności (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący na nazwę hosta `_dmarc.<domain>` z następującą treścią:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, co to jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten samouczek oparty jest na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Musisz połączyć oba wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testuj wynik konfiguracji swojego e-maila

Możesz to zrobić, korzystając z [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu wejdź na stronę i wyślij e-mail na adres, który ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz również **sprawdzić swoją konfigurację e-mail** wysyłając wiadomość e-mail na `check-auth@verifier.port25.com` i **czytając odpowiedź** (w tym celu musisz **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_, jeśli wysyłasz e-mail jako root).\
Sprawdź, czy przeszedłeś wszystkie testy:
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
Możesz również wysłać **wiadomość do Gmaila, nad którym masz kontrolę**, i sprawdzić **nagłówki e-maila** w swojej skrzynce odbiorczej Gmail, `dkim=pass` powinno być obecne w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Usuwanie z Czarnej Listy Spamhouse

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z Czarnej Listy Microsoft

​​Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Utwórz i Uruchom Kampanię GoPhish

### Profil Wysyłania

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać e-maile phishingowe. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić puste pole na nazwę użytkownika i hasło, ale upewnij się, że zaznaczyłeś Ignoruj błędy certyfikatu

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się korzystanie z funkcji "**Wyślij e-mail testowy**", aby sprawdzić, czy wszystko działa.\
> Rekomenduję **wysyłanie e-maili testowych na adresy 10min mail**, aby uniknąć dodania do czarnej listy podczas testów.

### Szablon E-mail

- Ustaw **nazwę identyfikującą** szablon
- Następnie napisz **temat** (nic dziwnego, po prostu coś, co można by się spodziewać w zwykłym e-mailu)
- Upewnij się, że zaznaczyłeś "**Dodaj obrazek śledzący**"
- Napisz **szablon e-maila** (możesz używać zmiennych, jak w poniższym przykładzie):
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
Zauważ, że **aby zwiększyć wiarygodność e-maila**, zaleca się użycie jakiegoś podpisu z e-maila klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Szukaj **publicznych e-maili** takich jak info@ex.com lub press@ex.com lub public@ex.com i wyślij im e-mail, a następnie czekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś ważnym odkrytym** e-mailem i czekaj na odpowiedź.

![](<../../images/image (80).png>)

> [!TIP]
> Szablon e-maila pozwala również na **załączanie plików do wysłania**. Jeśli chcesz również ukraść wyzwania NTLM za pomocą specjalnie przygotowanych plików/dokumentów [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Napisz **nazwę**
- **Napisz kod HTML** strony internetowej. Zauważ, że możesz **importować** strony internetowe.
- Zaznacz **Zbieranie przesłanych danych** i **Zbieranie haseł**
- Ustaw **przekierowanie**

![](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj będziesz musiał zmodyfikować kod HTML strony i przeprowadzić kilka testów lokalnie (może używając jakiegoś serwera Apache) **aż do uzyskania zadowalających wyników.** Następnie wpisz ten kod HTML w polu.\
> Zauważ, że jeśli musisz **użyć jakichś statycznych zasobów** dla HTML (może jakieś strony CSS i JS), możesz je zapisać w _**/opt/gophish/static/endpoint**_ i następnie uzyskać do nich dostęp z _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników na legalną główną stronę** ofiary lub przekierować ich na _/static/migration.html_, na przykład, umieścić jakiś **kręcący się kółko (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a następnie wskazać, że proces zakończył się sukcesem**.

### Użytkownicy i grupy

- Ustaw nazwę
- **Importuj dane** (zauważ, że aby użyć szablonu w przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![](<../../images/image (163).png>)

### Kampania

Na koniec stwórz kampanię, wybierając nazwę, szablon e-maila, stronę docelową, URL, profil wysyłania i grupę. Zauważ, że URL będzie linkiem wysłanym do ofiar.

Zauważ, że **Profil wysyłania pozwala na wysłanie testowego e-maila, aby zobaczyć, jak będzie wyglądał końcowy e-mail phishingowy**:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecałbym **wysyłanie testowych e-maili na adresy 10min mail**, aby uniknąć dodania do czarnej listy podczas testów.

Gdy wszystko będzie gotowe, po prostu uruchom kampanię!

## Klonowanie stron internetowych

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:

{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W niektórych ocenach phishingowych (głównie dla Red Teams) będziesz chciał również **wysłać pliki zawierające jakiś rodzaj backdoora** (może C2 lub po prostu coś, co wywoła autoryzację).\
Sprawdź następującą stronę w celu uzyskania przykładów:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Poprzez Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę internetową i zbierasz informacje podane przez użytkownika. Niestety, jeśli użytkownik nie wpisał poprawnego hasła lub jeśli aplikacja, którą podrobiłeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci na podszywanie się pod oszukanego użytkownika**.

Tutaj przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). To narzędzie pozwoli ci wygenerować atak typu MitM. Zasadniczo atak działa w następujący sposób:

1. **Podszywasz się pod formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane logowania** na twoją fałszywą stronę, a narzędzie wysyła je na prawdziwą stronę internetową, **sprawdzając, czy dane logowania działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o to, a gdy **użytkownik wprowadzi** to, narzędzie wyśle to na prawdziwą stronę internetową.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) będziesz miał **przechwycone dane logowania, 2FA, ciasteczka i wszelkie informacje** z każdej interakcji, podczas gdy narzędzie wykonuje atak MitM.

### Poprzez VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** o takim samym wyglądzie jak oryginalna, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną internetową**? Będziesz mógł zobaczyć, co robi, ukraść hasło, używane MFA, ciasteczka...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów, aby dowiedzieć się, czy zostałeś wykryty, jest **sprawdzenie swojej domeny w czarnych listach**. Jeśli pojawi się na liście, w jakiś sposób twoja domena została wykryta jako podejrzana.\
Jednym z łatwych sposobów, aby sprawdzić, czy twoja domena pojawia się w jakiejkolwiek czarnej liście, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Jednak istnieją inne sposoby, aby dowiedzieć się, czy ofiara **aktywnie poszukuje podejrzanej aktywności phishingowej w sieci**, jak wyjaśniono w:

{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez ciebie **zawierającej** **słowo kluczowe** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek **interakcję DNS lub HTTP** z nimi, będziesz wiedział, że **aktywnie poszukuje** podejrzanych domen i będziesz musiał być bardzo ostrożny.

### Oceń phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twój e-mail trafi do folderu spam lub czy zostanie zablokowany lub odniesie sukces.

## Przechwytywanie schowka / Pastejacking

Atakujący mogą cicho kopiować złośliwe polecenia do schowka ofiary z kompromitowanej lub źle napisanej strony internetowej, a następnie oszukać użytkownika, aby wkleił je w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania lub załączania.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Odniesienia

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
