# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Rozpoznanie ofiary
1. Select the **victim domain**.
2. Wykonaj podstawową enumerację webową **wyszukując portale logowania** używane przez ofiarę i **zdecyduj**, który z nich będziesz **podszywać się**.
3. Użyj trochę **OSINT**, aby **znaleźć adresy email**.
2. Przygotuj środowisko
1. **Kup domenę**, której użyjesz do oceny phishingowej
2. **Skonfiguruj rekordy** związane z usługą email (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj **VPS** z **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon email**
2. Przygotuj **stronę webową**, aby wyłudzić poświadczenia
4. Uruchom kampanię!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Nazwa domeny **zawiera** ważne **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).
- **hypened subdomain**: Zmień **kropkę na myślnik** w subdomenie (np. www-zelster.com).
- **New TLD**: Ta sama domena z **innym TLD** (np. zelster.org)
- **Homoglyph**: Zastępuje literę w nazwie domeny literami, które **wyglądają podobnie** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zamienia miejscami dwie litery w nazwie domeny (np. zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Omission**: Usuwa jedną z liter w nazwie domeny (np. zelser.com).
- **Repetition:** Powtarza jedną z liter w nazwie domeny (np. zeltsser.com).
- **Replacement**: Podobne do homoglyph, ale mniej ukryte. Zastępuje jedną z liter w nazwie domeny, być może literą znajdującą się blisko oryginalnej na klawiaturze (np. zektser.com).
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Insertion**: Wstawia literę do nazwy domeny (np. zerltser.com).
- **Missing dot**: Dołącza TLD do nazwy domeny. (np. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre bity przechowywane lub przesyłane mogą się automatycznie odwrócić** z powodu różnych czynników, takich jak wybuchy słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Kiedy ten koncept jest **zastosowany do zapytań DNS**, możliwe jest, że **domena odebrana przez serwer DNS** nie jest taka sama, jak domena początkowo żądana.

Na przykład pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele domen podatnych na bit-flipping**, które są podobne do domeny ofiary. Ich intencją jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Po więcej informacji przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Możesz przeszukać [https://www.expireddomains.net/](https://www.expireddomains.net) pod kątem wygasłej domeny, której mógłbyś użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów email lub **zweryfikować te**, które już znalazłeś, możesz sprawdzić, czy możesz bruteforce'ować serwery smtp ofiary. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Dodatkowo, nie zapomnij, że jeśli użytkownicy korzystają z **dowolnego portalu webowego do dostępu do swoich maili**, możesz sprawdzić, czy jest on podatny na **brute force nazwy użytkownika**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Installation

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj go do `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W wyjściu zostanie podane hasło dla użytkownika admin na porcie 3333. Dlatego uzyskaj dostęp do tego portu i użyj tych poświadczeń, aby zmienić hasło admina. Może być konieczne przetunelowanie tego portu lokalnie.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś **już mieć kupioną domenę**, której zamierzasz użyć, i musi ona **wskazywać** na **adres IP VPS-a**, na którym konfigurujesz **gophish**.
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

Na końcu zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na nazwę swojej domeny i **zrestartuj swój VPS.**

Teraz utwórz **rekord DNS A** dla `mail.<domain>` wskazujący na **adres IP** VPS oraz **rekord DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysyłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie Gophish i skonfigurujmy go.\
Zmodyfikuj `/opt/gophish/config.json` następująco (zwróć uwagę na użycie https):
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
Dokończ konfigurację usługi i sprawdź jej działanie, wykonując:
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

### Poczekaj i bądź wiarygodny

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego powinieneś odczekać jak najdłużej (co najmniej 1 tydzień) przed phishing assessment. Ponadto, jeśli umieścisz stronę związaną z branżą o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz czekać tydzień, możesz teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj Reverse DNS (rDNS) record

Ustaw rDNS (PTR) record, który mapuje adres IP VPS na nazwę domeny.

### Sender Policy Framework (SPF) Record

Musisz **skonfigurować SPF record dla nowej domeny**. Jeśli nie wiesz, czym jest SPF record [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej SPF policy (użyj IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, która musi być ustawiona w TXT record w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord DMARC (Domain-based Message Authentication, Reporting & Conformance)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący nazwę hosta `_dmarc.<domain>` o następującej treści:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> You need to concatenate both B64 values that the DKIM key generates:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Przetestuj wynik konfiguracji e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Wystarczy wejść na stronę i wysłać e-mail na adres, który Ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz także **sprawdzić konfigurację poczty** wysyłając e-mail na `check-auth@verifier.port25.com` i **odczytać odpowiedź** (w tym celu musisz **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_ jeśli wyślesz e-mail jako root).\
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
Możesz też wysłać **wiadomość na Gmaila, którym zarządzasz**, i sprawdzić **nagłówki wiadomości** w swojej skrzynce Gmail; `dkim=pass` powinien być obecny w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Usuwanie z czarnej listy Spamhouse

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez Spamhouse. Możesz poprosić o usunięcie domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z czarnej listy Microsoft

​​Możesz poprosić o usunięcie domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Profil nadawcy

- Ustaw jakąś **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta zamierzasz wysyłać phishingowe e-maile. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić puste pola nazwy użytkownika i hasła, ale upewnij się, że zaznaczyłeś Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Zalecam **wysyłanie testowych e-maili na adresy 10min mails**, aby uniknąć trafienia na czarną listę podczas testów.

### Szablon e-mail

- Nadaj **nazwę identyfikującą** szablonowi
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, czego można się spodziewać w zwykłym e-mailu)
- Upewnij się, że zaznaczyłeś "**Add Tracking Image**"
- Napisz **szablon e-maila** (możesz użyć zmiennych jak w poniższym przykładzie):
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
Zauważ, że aby **zwiększyć wiarygodność e-maila**, zaleca się użycie jakiegoś podpisu z e-maila od klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Wyszukaj **publiczne e-maile** typu info@ex.com lub press@ex.com lub public@ex.com i wyślij im wiadomość, a następnie poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś prawidłowo odnalezionym** adresem e-mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> Szablon e-maila pozwala również **załączać pliki do wysłania**. Jeśli chcesz też przechwycić wyzwania NTLM używając specjalnie spreparowanych plików/dokumentów [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**
- **Wpisz kod HTML** strony. Zauważ, że możesz **importować** strony web.
- Zaznacz **Capture Submitted Data** oraz **Capture Passwords**
- Ustaw **przekierowanie**

![](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj będziesz musiał modyfikować kod HTML strony i robić testy lokalnie (może używając jakiegoś serwera Apache), **aż będziesz zadowolony z efektów.** Potem wklej ten kod HTML w pole.\
> Uwaga: jeśli potrzebujesz **użyć jakichś zasobów statycznych** dla HTML (np. plików CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_ i potem odwoływać się do nich z _**/static/\<filename>**_

> [!TIP]
> Dla przekierowania możesz **przekierować użytkowników na legit główną stronę** ofiary, lub przekierować ich do _/static/migration.html_ na przykład, pokazać **wirujące kółko (**) [**https://loading.io/**](https://loading.io)**) przez 5 sekund, a potem wskazać, że proces zakończył się pomyślnie**.

### Użytkownicy i grupy

- Ustaw nazwę
- **Importuj dane** (zauważ, że aby użyć szablonu w przykładzie potrzebujesz firstname, last name i email address każdego użytkownika)

![](<../../images/image (163).png>)

### Kampania

Na koniec stwórz kampanię wybierając nazwę, szablon e-maila, stronę docelową, URL, sending profile i grupę. Zauważ, że URL będzie linkiem wysyłanym do ofiar

Zauważ, że **Sending Profile pozwala wysłać testowy e-mail, aby zobaczyć jak będzie wyglądał finalny phishing**:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecałbym **wysyłać testowe e-maile na adresy 10min mails**, aby uniknąć wpisania się na czarne listy podczas testów.

Gdy wszystko jest gotowe, po prostu uruchom kampanię!

## Klonowanie strony

Jeśli z jakiegoś powodu chcesz sklonować stronę, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Podstawione dokumenty i pliki (Backdoored Documents & Files)

W niektórych ocenach phishingowych (głównie dla Red Teams) będziesz chciał także **wysyłać pliki zawierające jakiś rodzaj backdoora** (może C2 lub coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę dla przykładów:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing a MFA

### Przez Proxy MitM

Poprzedni atak jest całkiem sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz informacje wpisane przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła lub jeśli aplikacja, którą podrobiłeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci się podszyć pod oszukanego użytkownika**.

Tutaj przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) oraz [**muraena**](https://github.com/muraenateam/muraena). Narzędzie to pozwala wygenerować atak MitM. W zasadzie atak działa w następujący sposób:

1. Podszywasz się pod formularz logowania prawdziwej strony.
2. Użytkownik **wysyła** swoje **poświadczenia** do twojej fałszywej strony, a narzędzie przesyła je do prawdziwej strony, **sprawdzając czy poświadczenia działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o nią i gdy **użytkownik ją wprowadzi**, narzędzie przekaże ją do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) będziesz miał **przechwycone poświadczenia, 2FA, ciasteczko i wszelkie informacje** z każdej interakcji podczas gdy narzędzie wykonuje MitM.

### Przez VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** wyglądającą jak oryginał, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną**? Będziesz mógł zobaczyć, co robi, ukraść hasło, MFA, ciasteczka...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów, by wiedzieć, czy zostałeś złapany, jest **wyszukanie swojej domeny na czarnych listach**. Jeśli pojawi się na liście, w jakiś sposób twoja domena została uznana za podejrzaną.\
Łatwy sposób, by sprawdzić, czy twoja domena pojawia się na jakiejś czarnej liście, to użyć [https://malwareworld.com/](https://malwareworld.com)

Są jednak inne sposoby, by dowiedzieć się, czy ofiara **aktywnie szuka podejrzanych aktywności phishingowych w sieci**, jak wyjaśniono w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez ciebie **zawierającej** **słowo-klucz** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek interakcję DNS lub HTTP z nimi, dowiesz się, że **aktywnie szuka** podejrzanych domen i będziesz musiał być bardzo dyskretny.

### Oceń phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious) aby ocenić, czy twój e-mail trafi do folderu spam lub czy zostanie zablokowany albo okaże się skuteczny.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Nowoczesne zestawy intruzyjne coraz częściej pomijają w ogóle wabiki e-mailowe i **bezpośrednio atakują workflow service-desk / identity-recovery**, aby pokonać MFA. Atak jest w pełni „living-off-the-land”: gdy operator zdobędzie prawidłowe poświadczenia, porusza się przy użyciu wbudowanych narzędzi administracyjnych – malware nie jest wymagane.

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbieraj dane osobowe i korporacyjne z LinkedIn, wycieków danych, publicznego GitHub itp.
* Zidentyfikuj wysokowartościowe tożsamości (kadra kierownicza, IT, finanse) i wyewidencjonuj **dokładny proces help-desk** dla resetu hasła / MFA.
2. Socjotechnika w czasie rzeczywistym
* Dzwonienie, Teams lub czat do help-desku udając cel (często ze **sfałszowanym caller-ID** lub **sklonowanym głosem**).
* Podaj wcześniej zebrane PII, aby przejść weryfikację wiedzy.
* Przekonaj agenta do **zresetowania sekretu MFA** lub wykonania **SIM-swapu** na zarejestrowany numer telefonu.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
* Ustanów punkt zaczepienia przez dowolne web SSO portal.
* Enumeruj AD / AzureAD wbudowanymi narzędziami (bez umieszczania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch lateralny z użyciem **WMI**, **PsExec**, lub legalnych agentów **RMM** już białej listy w środowisku.

### Wykrywanie i łagodzenie
* Traktuj operacje odzyskiwania tożsamości przez help-desk jako **operację uprzywilejowaną** – wymagaj podniesienia uwierzytelnienia i zatwierdzenia przez managera.
* Wdroż **Identity Threat Detection & Response (ITDR)** / reguły **UEBA**, które alarmują przy:
* Zmiana metody MFA + logowanie z nowego urządzenia / lokalizacji.
* Natychmiastowe podniesienie uprawnień tego samego podmiotu (user → admin).
* Nagrywaj rozmowy help-desk i wymuszaj **oddzwonienie na już zarejestrowany numer** przed jakimkolwiek resetem.
* Wdroż **Just-In-Time (JIT) / Privileged Access**, aby nowo zresetowane konta **nie** odziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## Dezinformacja na dużą skalę – SEO Poisoning & kampanie „ClickFix”
Zespoły korzystające z masowej skali równoważą koszty operacji high-touch masowymi atakami, które zamieniają **search engines & ad networks w kanał dostawy**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam wyszukiwania.
2. Ofiara pobiera mały **first-stage loader** (często JS/HTA/ISO). Przykłady obserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrowuje ciasteczka przeglądarki + credential DBs, potem pobiera **cichy loader**, który decyduje – *w czasie rzeczywistym* – czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent utrzymania (klucz Run w rejestrze + zadanie zaplanowane)

### Wskazówki dotyczące hardeningu
* Blokuj nowo zarejestrowane domeny i egzekwuj **Advanced DNS / URL Filtering** na *search-ads* oraz w e-mailach.
* Ogranicz instalację oprogramowania do podpisanych MSI / pakietów ze Store, zabroń wykonywania `HTA`, `ISO`, `VBS` przez politykę.
* Monitoruj procesy potomne przeglądarek uruchamiające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Poluj na LOLBins często nadużywane przez first-stage loadery (np. `regsvr32`, `curl`, `mshta`).

---

## Operacje phishingowe wspomagane AI
Atakujący teraz łączą **LLM & voice-clone APIs** dla w pełni spersonalizowanych wabików i interakcji w czasie rzeczywistym.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Obrona:**
• Dodaj **dynamiczne bannery** podkreślające wiadomości wysyłane z nieufnej automatyzacji (na podstawie anomalii ARC/DKIM).  
• Wdroż **voice-biometric challenge phrases** dla wysokiego ryzyka żądań telefonicznych.  
• Ciągle symuluj lury generowane przez AI w programach podnoszących świadomość – statyczne szablony są przestarzałe.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Wymuszony reset
Poza klasycznym push-bombingiem, operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-deskiem, unieważniając istniejący token użytkownika. Każde kolejne okno logowania wydaje się wtedy ofierze prawidłowe.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego adresu IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą w sposób niewidoczny skopiować złośliwe polecenia do schowka ofiary ze skompromitowanej lub typosquatted strony i następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania czy załączników.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej umieszczają swoje phishing flows za prostą kontrolą urządzenia, tak aby desktop crawlers nigdy nie docierały do stron końcowych. Typowym wzorcem jest mały skrypt, który testuje, czy DOM obsługuje dotyk i wysyła wynik do endpointu serwera; klienci nie‑mobilni otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobilni otrzymują pełny flow.

Minimal client snippet (typical logic):
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
- Ustawia session cookie podczas pierwszego ładowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) na kolejnych GET, gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki poszukiwań i wykrywania:
- zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla urządzeń nie‑mobilnych; legalne ścieżki ofiary na mobile zwracają 200 z dalszym HTML/JS.
- Blokuj lub wnikliwie analizuj strony, które uzależniają treść wyłącznie od `ontouchstart` lub podobnych device checks.

Wskazówki obronne:
- Uruchamiaj crawlers z mobile‑like fingerprintami i włączonym JS, żeby ujawnić ukrytą treść.
- Generuj alerty na podejrzane odpowiedzi 500 po `POST /detect` dla nowo zarejestrowanych domen.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
