# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Rozpoznanie ofiary
1. Wybierz **victim domain**.
2. Wykonaj podstawową enumerację webową **wyszukując portale logowania** używane przez ofiarę i **zdecyduj**, który z nich będziesz **podszywać się**.
3. Użyj OSINT, aby **znaleźć adresy email**.
2. Przygotuj środowisko
1. **Kup domenę**, której zamierzasz użyć do oceny phishingowej
2. **Skonfiguruj rekordy** związane z usługą email (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon email**
2. Przygotuj **stronę WWW** do wykradania poświadczeń
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Domain Name Variation Techniques

- **Keyword**: Nazwa domeny **zawiera** istotne **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).
- **hypened subdomain**: Zmień **kropkę na myślnik** w subdomenie (np. www-zelster.com).
- **New TLD**: Ta sama domena z **innym TLD** (np. zelster.org)
- **Homoglyph**: **Zastępuje** literę w nazwie domeny literami o **podobnym wyglądzie** (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Omission**: **Usuwa jedną** z liter z nazwy domeny (np. zelser.com).
- **Repetition:** **Powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).
- **Replacement**: Podobne do homoglyph, ale mniej ukryte. Zastępuje jedną z liter w nazwie domeny, np. literą znajdującą się blisko na klawiaturze (np. zektser.com).
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Insertion**: **Wstawia literę** do nazwy domeny (np. zerltser.com).
- **Missing dot**: Dołącza TLD do nazwy domeny. (np. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre bity** przechowywane lub przesyłane mogą **zostać automatycznie odwrócone** z powodu różnych czynników, takich jak burze słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy ta koncepcja jest **stosowana do zapytań DNS**, możliwe jest, że **domena odebrana przez serwer DNS** nie jest taka sama jak domena początkowo żądana.

Na przykład, pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele domen powstałych przez bit-flipping**, które są podobne do domeny ofiary. Ich celem jest przekierowanie legalnych użytkowników do własnej infrastruktury.

Aby dowiedzieć się więcej przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Możesz wyszukać na [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłą domenę, której mógłbyś użyć.\
Aby upewnić się, że wygasła domena, którą chcesz kupić, **ma już dobrą pozycję SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Odkrywanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które już znalazłeś, możesz sprawdzić, czy możesz je brute-force'ować na serwerach smtp ofiary. [Dowiedz się jak weryfikować/odkrywać adresy email tutaj](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Dodatkowo, nie zapomnij, że jeśli użytkownicy używają **dowolnego portalu webowego do dostępu do swoich maili**, możesz sprawdzić, czy jest podatny na **brute force nazw użytkowników**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Instalacja

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj wewnątrz `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W wyjściu zostanie podane hasło dla użytkownika admin na porcie 3333. Uzyskaj dostęp do tego portu i użyj tych poświadczeń, aby zmienić hasło admina. Może być konieczne przetunelowanie tego portu na lokalny:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś mieć już zakupioną domenę, której będziesz używać, i musi ona wskazywać na adres IP VPS, na którym konfigurujesz gophish.
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

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`**, wpisując swoją nazwę domeny, i **zrestartuj VPS.**

Teraz utwórz **DNS A record** dla `mail.<domain>`, wskazujący na **ip address** VPS, oraz **DNS MX** record wskazujący na `mail.<domain>`

Teraz przetestuj wysłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie Gophish i skonfigurujmy go.\
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
**Skonfiguruj usługę gophish**

Aby utworzyć usługę gophish, tak aby była uruchamiana automatycznie i zarządzana jako usługa, utwórz plik `/etc/init.d/gophish` o następującej zawartości:
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
Dokończ konfigurowanie usługi i sprawdź jej działanie, wykonując:
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
## Konfiguracja serwera poczty i domeny

### Poczekaj i bądź wiarygodny

Im starsza domena, tym mniejsze jest prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego powinieneś poczekać jak najdłużej (co najmniej 1 tydzień) przed oceną phishingową. Ponadto, jeśli umieścisz stronę dotyczącą branży o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zwróć uwagę, że nawet jeśli musisz poczekać tydzień, możesz już teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który rozwiązuje adres IP VPS do nazwy domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) aby wygenerować swoją politykę SPF (użyj adresu IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, która musi zostać ustawiona w rekordzie TXT dla domeny:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Uwierzytelnianie wiadomości oparte na domenie, raportowanie i zgodność (DMARC) — rekord

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący nazwę hosta `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Musisz połączyć obie wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Możesz to zrobić, używając [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Po prostu wejdź na stronę i wyślij e-mail na adres, który Ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz także **sprawdzić konfigurację e-mail** wysyłając e-mail na `check-auth@verifier.port25.com` i **odczytać odpowiedź** (w tym celu musisz **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wysyłasz e-mail jako root).\
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
Możesz także wysłać **wiadomość na konto Gmail, którym zarządzasz**, i sprawdzić **email’s headers** w swojej skrzynce Gmail, `dkim=pass` powinno być obecne w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Usuwanie z czarnej listy Spamhouse

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez Spamhouse. Możesz poprosić o usunięcie domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z czarnej listy Microsoft

​​Możesz poprosić o usunięcie domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Utwórz i uruchom kampanię GoPhish

### Profil wysyłania

- Ustaw jakąś **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z jakiego konta będziesz wysyłać phishingowe maile. Propozycje: _noreply, support, servicedesk, salesforce..._
- Możesz zostawić puste pola username i password, ale upewnij się, że zaznaczyłeś opcję Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użyć funkcji "**Send Test Email**", aby przetestować, czy wszystko działa.\
> Polecam **wysyłać testowe maile na adresy 10min mail**, aby uniknąć wpisania na czarną listę podczas testów.

### Szablon e-mail

- Ustaw jakąś **nazwę identyfikującą** szablon
- Następnie wpisz **temat** (nic podejrzanego, po prostu coś, czego można się spodziewać w zwykłej wiadomości)
- Upewnij się, że zaznaczyłeś opcję "**Add Tracking Image**"
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
Zauważ, że **w celu zwiększenia wiarygodności wiadomości e-mail** zaleca się użycie jakiegoś podpisu z wiadomości od klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Wyszukaj **publiczne adresy e-mail** typu info@ex.com, press@ex.com lub public@ex.com i wyślij im wiadomość, a następnie poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś prawidłowym odkrytym** adresem e-mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**
- **Wpisz kod HTML** strony. Zauważ, że możesz **importować** strony WWW.
- Zaznacz **Capture Submitted Data** oraz **Capture Passwords**
- Ustaw **przekierowanie**

![](<../../images/image (826).png>)

> [!TIP]
> Zwykle będziesz musiał modyfikować kod HTML strony i robić testy lokalnie (może przy użyciu serwera Apache), **aż będziesz zadowolony z efektów.** Następnie wklej ten kod HTML do pola.\
> Zauważ, że jeśli potrzebujesz **użyć zasobów statycznych** dla HTML (np. plików CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_ a następnie uzyskać do nich dostęp przez _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników na legalną stronę główną** ofiary, albo przekierować ich np. na _/static/migration.html_, pokazać **kręcące się kółko ładowania (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a następnie poinformować, że proces zakończył się pomyślnie**.

### Użytkownicy i grupy

- Ustaw nazwę
- **Importuj dane** (zauważ, że aby użyć szablonu w przykładzie potrzebujesz firstname, last name oraz email address każdego użytkownika)

![](<../../images/image (163).png>)

### Kampania

Na koniec utwórz kampanię, wybierając nazwę, szablon e-mail, stronę docelową, URL, profil wysyłki oraz grupę. Zauważ, że URL będzie linkiem wysyłanym ofiarom.

Zauważ, że **Sending Profile pozwala wysłać testowy e-mail, aby zobaczyć, jak finalny phishingowy e-mail będzie wyglądać**:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecam **wysyłać testowe e-maile na adresy 10min mail**, aby uniknąć wpisania się na blackliste podczas testów.

Gdy wszystko jest gotowe, uruchom kampanię!

## Klonowanie strony internetowej

Jeśli z jakiegoś powodu chcesz sklonować stronę, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W niektórych ocenach phishingowych (głównie dla Red Teamów) zechcesz również **wysyłać pliki zawierające jakiś rodzaj backdoora** (może C2 lub coś, co wywoła uwierzytelnienie).\
Sprawdź poniższą stronę dla przykładów:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing i MFA

### Przez Proxy MitM

Poprzedni atak jest całkiem sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz informacje wpisane przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła lub jeśli aplikacja, którą sfałszowałeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci się podszyć pod oszukanego użytkownika**.

Tutaj przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Narzędzie to pozwala wygenerować atak typu MitM. Zasadniczo atak działa w następujący sposób:

1. Podszywasz się pod formularz logowania prawdziwej strony.
2. Użytkownik **wysyła** swoje **poświadczenia** do twojej fałszywej strony, a narzędzie przekazuje je do prawdziwej strony, **sprawdzając, czy poświadczenia działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o nią i gdy **użytkownik ją wprowadzi**, narzędzie przekaże ją do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) będziesz mieć **złapane poświadczenia, 2FA, cookie oraz wszelkie informacje** z każdej interakcji podczas działania MitM.

### Przez VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** wyglądem identyczną z oryginałem, wyślesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną**? Będziesz w stanie obserwować, co robi, ukraść hasło, MFA, ciasteczka...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie, że zostałeś wykryty

Oczywiście jednym z najlepszych sposobów, aby wiedzieć, czy zostałeś przyłapany, jest **wyszukanie swojej domeny na czarnych listach**. Jeśli pojawi się na liście, w jakiś sposób twoja domena została uznana za podejrzaną.\
Jednym z prostych sposobów sprawdzenia, czy twoja domena figuruje na którejś czarnej liście jest użycie [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby, aby wiedzieć, czy ofiara **aktywne poszukuje podejrzanej aktywności phishingowej w sieci**, jak wyjaśniono w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez ciebie **zawierającej** **słowo kluczowe** z domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek interakcję DNS lub HTTP z nimi, będziesz wiedzieć, że **aktywnie poszukuje** podejrzanych domen i będziesz musiał być bardzo stealth.

### Oceń phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious) aby ocenić, czy twój e-mail trafi do folderu spam, czy zostanie zablokowany, lub okaże się skuteczny.

## High-Touch Identity Compromise (Reset MFA przez help-desk)

Nowoczesne kampanie intruzji coraz częściej pomijają wabiki e-mailowe całkowicie i **bezpośrednio atakują workflow help-desk / identity-recovery**, aby obejść MFA. Atak jest w pełni „living-off-the-land”: gdy operator posiada prawidłowe poświadczenia, porusza się za pomocą wbudowanych narzędzi administracyjnych – malware nie jest wymagany.

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbieraj dane osobowe i korporacyjne z LinkedIn, wycieków danych, publicznego GitHub itp.
* Zidentyfikuj wysokowartościowe tożsamości (kadra zarządzająca, IT, finanse) i wypisz **dokładny proces help-desk** dla resetu hasła / MFA.
2. Socjotechnika w czasie rzeczywistym
* Telefon, Teams lub chat do help-desku podszywając się pod cel (często z **sfałszowanym caller-ID** lub **sklonowanym głosem**).
* Podaj wcześniej zebrane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj agenta, aby **zresetował sekret MFA** lub wykonał **SIM-swap** na zarejestrowanym numerze telefonu.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w realnych przypadkach)
* Ustanów punkt zaczepienia poprzez dowolny portal web SSO.
* Wypisz AD / AzureAD za pomocą wbudowanych narzędzi (bez upuszczania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Przemieszczanie boczne za pomocą **WMI**, **PsExec**, lub legalnych agentów **RMM** już wpisanych na białą listę w środowisku.

### Wykrywanie i przeciwdziałanie
* Traktuj odzyskiwanie tożsamości przez help-desk jako **operację uprzywilejowaną** – wymagaj step-up auth i zatwierdzenia przez managera.
* Wdroż **Identity Threat Detection & Response (ITDR)** / **UEBA** oraz reguły alarmujące o:
* zmianie metody MFA + logowaniu z nowego urządzenia / lokalizacji.
* natychmiastowym podwyższeniu uprawnień tej samej tożsamości (user → admin).
* Nagrywaj rozmowy do help-desku i wymuszaj **oddzwonienie na już zarejestrowany numer** przed jakimkolwiek resetem.
* Wdróż **Just-In-Time (JIT) / Privileged Access**, aby świeżo zresetowane konta **nie** dziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## Decepcja na dużą skalę – SEO Poisoning & kampanie “ClickFix”
Zespoły commodity równoważą koszty operacji high-touch masowymi atakami, które zamieniają **silniki wyszukiwania i sieci reklamowe w kanał dostarczania**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam wyszukiwania.
2. Ofiara pobiera mały **first-stage loader** (często JS/HTA/ISO). Przykłady widziane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrowuje ciasteczka przeglądarki + bazy poświadczeń, a następnie pobiera **cichy loader**, który w czasie rzeczywistym decyduje, czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent trwałego utrwalenia (klucz Run w rejestrze + zaplanowane zadanie)

### Wskazówki zabezpieczające
* Blokuj nowo zarejestrowane domeny i egzekwuj **Advanced DNS / URL Filtering** dla *search-ads* oraz e-maili.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / Store, zablokuj wykonywanie `HTA`, `ISO`, `VBS` polityką.
* Monitoruj procesy potomne przeglądarek otwierające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Poluj na LOLBins często nadużywane przez first-stage loadery (np. `regsvr32`, `curl`, `mshta`).

---

## Operacje phishingowe wspomagane AI
Atakujący teraz łączą **LLM & voice-clone APIs** w celu tworzenia w pełni spersonalizowanych wabików oraz interakcji w czasie rzeczywistym.

| Warstwa | Przykładowe użycie przez operatora zagrożenia |
|-------|-----------------------------|
|Automation|Generowanie i wysyłka >100k e-maili / SMS z losowo zmienianymi sformułowaniami i linkami śledzącymi.|
|Generative AI|Tworzenie *jednorazowych* e-maili odwołujących się do publicznych M&A, żartów z mediów społecznościowych; deepfake-owy głos CEO w oszustwie telefonicznym.|
|Agentic AI|Autonomiczne rejestrowanie domen, zbieranie OSINT, komponowanie kolejnych maili, gdy ofiara kliknie, ale nie poda poświadczeń.|

**Obrona:**
• Dodaj **dynamiczne banery** informujące o wiadomościach wysłanych z niezaufanej automatyzacji (na podstawie anomalii ARC/DKIM).  
• Wdróż **frazy weryfikujące biometrycznie głos** dla żądań telefonicznych o wysokim ryzyku.  
• Ciągle symuluj wabiki generowane przez AI w programach podnoszących świadomość – statyczne szablony są przestarzałe.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing – wariant: wymuszony reset
Poza klasycznym push-bombingiem operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-deskiem, unieważniając istniejący token użytkownika. Każde kolejne okno logowania wygląda dla ofiary jak prawidłowe.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego adresu IP**.



## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej umieszczają swoje phishing flows za prostym sprawdzeniem urządzenia, aby desktop crawlers nigdy nie docierały do końcowych stron. Typowy wzorzec to mały skrypt, który testuje, czy DOM obsługuje dotyk, i wysyła wynik do endpointu serwera; klienci niebędący mobilnymi otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobilni są obsługiwani pełnym flow.

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
- Zwraca 500 (lub placeholder) dla kolejnych GETów gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki wykrywania i poszukiwania:
- zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla non‑mobile; prawidłowe ścieżki ofiary na urządzeniu mobilnym zwracają 200 z następnym HTML/JS.
- Blokuj lub uważnie sprawdzaj strony, które uzależniają zawartość wyłącznie od `ontouchstart` lub podobnych sprawdzeń urządzenia.

Wskazówki obronne:
- Uruchamiaj crawlery z fingerprintami przypominającymi urządzenie mobilne i z włączonym JS, aby ujawnić ukrytą zawartość.
- Wywołuj alarm przy podejrzanych odpowiedziach 500 po `POST /detect` na świeżo zarejestrowanych domenach.

## Źródła

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
