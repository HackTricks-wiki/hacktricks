# Metodologia Phishingu

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon the victim
1. Wybierz **domena ofiary**.
2. Wykonaj podstawową enumerację webową **szukając portali logowania** używanych przez ofiarę i **zdecyduj**, za który z nich się **podszyjesz**.
3. Użyj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
1. **Kup domenę**, której zamierzasz użyć w ramach testu phishingowego
2. **Skonfiguruj rekordy związane z usługą e-mail** (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon e-mail**
2. Przygotuj **stronę internetową**, aby wyłudzić dane uwierzytelniające
4. Uruchom kampanię!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Słowo kluczowe**: Nazwa domeny **zawiera** ważne **słowo kluczowe** oryginalnej domeny (np., zelster.com-management.com).
- **hypened subdomain**: Zmień **kropkę na myślnik** w subdomenie (np., www-zelster.com).
- **New TLD**: Ta sama domena używając **nowego TLD** (np., zelster.org)
- **Homoglyph**: Zastępuje literę w nazwie domeny **literami, które wyglądają podobnie** (np., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Zamienia dwie litery w nazwie domeny (np., zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np., zeltsers.com).
- **Omission**: Usuwa jedną z liter z nazwy domeny (np., zelser.com).
- **Repetition:** Powtarza jedną z liter w nazwie domeny (np., zeltsser.com).
- **Replacement**: Podobne do homoglyph, ale mniej ukryte. Zastępuje jedną z liter w nazwie domeny, być może literą znajdującą się blisko oryginalnej na klawiaturze (np., zektser.com).
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np., ze.lster.com).
- **Insertion**: Wstawia literę do nazwy domeny (np., zerltser.com).
- **Missing dot**: Dodaje TLD bez kropki do nazwy domeny. (np., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje możliwość, że jeden z bitów zapisanych lub przesyłanych może zostać automatycznie odwrócony z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy ta koncepcja zostanie zastosowana do żądań DNS, możliwe jest, że domena otrzymana przez serwer DNS nie będzie taka sama jak domena początkowo żądana.

Na przykład pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą wykorzystać to, rejestrując wiele domen podatnych na bitflipping, które są podobne do domeny ofiary. Ich celem jest przekierowanie prawdziwych użytkowników na własną infrastrukturę.

Aby dowiedzieć się więcej, przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Możesz wyszukać na [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłą domenę, którą mógłbyś użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą pozycję SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Odkrywanie adresów e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy możesz przeprowadzić brute-force na serwerach smtp ofiary. [Dowiedz się, jak weryfikować/odkrywać adresy e-mail tutaj](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto nie zapomnij, że jeśli użytkownicy korzystają z jakiegoś portalu webowego do dostępu do swoich wiadomości, możesz sprawdzić, czy portal jest podatny na username brute force i wykorzystać tę podatność, jeśli to możliwe.

## Configuring GoPhish

### Installation

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj to do `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W wyjściu zostanie podane hasło dla użytkownika admin na porcie 3333. Dlatego uzyskaj dostęp do tego portu i użyj tych poświadczeń, aby zmienić hasło admina. Może być konieczne przetunnelowanie tego portu na lokalny:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś **już kupić domenę**, której zamierzasz użyć i musi ona **wskazywać** na **adres IP VPS**, na którym konfigurujesz **gophish**.
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
**Mail configuration**

Zainstaluj: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Zmień także wartości następujących zmiennych w pliku /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na swoją nazwę domeny i **zrestartuj swój VPS.**

Teraz utwórz **rekord DNS A** `mail.<domain>` wskazujący na **adres IP** VPS oraz **rekord DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysłanie wiadomości e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

Zatrzymaj działanie gophish i skonfigurujmy go.\
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
**Skonfiguruj usługę gophish**

Aby utworzyć usługę gophish, dzięki której będzie mogła być uruchamiana automatycznie i zarządzana, utwórz plik `/etc/init.d/gophish` z następującą zawartością:
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

### Poczekaj i bądź wiarygodny

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Powinieneś więc odczekać jak najdłużej (przynajmniej 1 tydzień) przed oceną phishingową. Ponadto, jeśli umieścisz stronę związaną z sektorem o dobrej reputacji, reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz czekać tydzień, możesz już teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj Reverse DNS (rDNS) record

Ustaw rDNS (PTR) record, który rozwiązuje adres IP VPS na nazwę domeny.

### Sender Policy Framework (SPF) Record

Musisz **skonfigurować SPF record dla nowej domeny**. Jeśli nie wiesz, czym jest SPF record [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) aby wygenerować swoją politykę SPF (użyj adresu IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, która musi zostać ustawiona wewnątrz TXT record w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord DMARC (Domain-based Message Authentication, Reporting & Conformance)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący nazwę hosta `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Musisz połączyć obie wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Możesz to zrobić przy użyciu [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu wejdź na stronę i wyślij e-mail na adres, który podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz także **sprawdzić konfigurację poczty** wysyłając e-mail na `check-auth@verifier.port25.com` i **odczytać odpowiedź** (do tego będziesz musiał **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_, jeśli wyślesz e-mail jako root).\
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
Możesz też wysłać **wiadomość na Gmaila, którym zarządzasz**, i sprawdzić **nagłówki e-maila** w swojej skrzynce Gmail, `dkim=pass` powinien być obecny w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Set some **name to identify** the sender profile
- Decide from which account are you going to send the phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- You can leave blank the username and password, but make sure to check the Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Set some **name to identify** the template
- Then write a **subject** (nothing estrange, just something you could expect to read in a regular email)
- Make sure you have checked "**Add Tracking Image**"
- Write the **email template** (you can use variables like in the following example):
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
Zauważ, że **aby zwiększyć wiarygodność e-maila**, zaleca się użycie jakiegoś podpisu z wiadomości e-mail od klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Wyszukaj **publiczne adresy e-mail** jak info@ex.com, press@ex.com lub public@ex.com, wyślij do nich wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś znalezionym ważnym** adresem e-mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> Szablon e-maila pozwala również **dołączać pliki do wysłania**. Jeśli chcesz też pozyskiwać NTLM challenges używając specjalnie spreparowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**
- **Wpisz kod HTML** strony. Zauważ, że możesz **importować** strony.
- Zaznacz opcje **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj będziesz musiał zmodyfikować kod HTML strony i testować lokalnie (np. używając serwera Apache) **dopóki nie będziesz zadowolony z rezultatu.** Następnie wklej ten kod HTML w pole.\
> Zauważ, że jeśli potrzebujesz **użyć zasobów statycznych** dla HTML (np. plików CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_ i potem uzyskać do nich dostęp z _**/static/\<filename>**_

> [!TIP]
> W przypadku przekierowania możesz **przekierować użytkowników na prawdziwą główną stronę** ofiary, albo przekierować ich np. do _/static/migration.html_, umieścić **spinning wheel (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a następnie wskazać, że proces zakończył się sukcesem**.

### Użytkownicy i grupy

- Ustaw nazwę
- **Importuj dane** (zauważ, że aby użyć szablonu dla przykładu potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![](<../../images/image (163).png>)

### Kampania

Na koniec utwórz kampanię, wybierając nazwę, szablon e-maila, stronę docelową, URL, sending profile i grupę. Zauważ, że URL będzie linkiem wysyłanym do ofiar.

Zauważ, że **Sending Profile pozwala wysłać testowy e-mail, aby zobaczyć jak będzie wyglądać końcowy phishingowy e-mail**:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecam **wysyłać testowe e-maile na adresy 10min mails** aby uniknąć wpisania na listy blokujące podczas testów.

Gdy wszystko jest gotowe, po prostu uruchom kampanię!

## Klonowanie strony internetowej

Jeśli z jakiegokolwiek powodu chcesz sklonować stronę, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W niektórych ocenach phishingowych (głównie dla Red Teams) będziesz chciał również **wysyłać pliki zawierające jakiś backdoor** (może C2, a może coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę po przykłady:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła lub jeśli aplikacja, którą podrobiłeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci na podszycie się pod oszukanego użytkownika**.

W tym miejscu przydają się narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2), [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Te narzędzia pozwalają wygenerować atak MitM. Zasadniczo atak działa w następujący sposób:

1. **Podszywasz się pod formularz logowania** prawdziwej strony.
2. Użytkownik **wysyła** swoje **credentials** do twojej fałszywej strony, a narzędzie przesyła je do prawdziwej strony, **sprawdzając, czy credentials działają**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o nie, a kiedy **użytkownik je wprowadzi**, narzędzie wyśle je do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) będziesz miał **przechwycone credentials, 2FA, cookie i wszelkie informacje** z każdej interakcji, podczas gdy narzędzie wykonuje MitM.

### Przez VNC

Co jeśli zamiast **przekierowywać ofiarę na złośliwą stronę** o podobnym wyglądzie, skierujesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną**? Będziesz mógł zobaczyć, co robi, ukraść hasło, użyte MFA, cookie...\
Można to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie, że zostałeś wykryty

Oczywiście jednym z najlepszych sposobów, aby dowiedzieć się, czy zostałeś przyłapany, jest **wyszukanie swojej domeny na listach blokujących**. Jeśli pojawi się na liście, w jakiś sposób twoja domena została wykryta jako podejrzana.\
Jednym prostym sposobem, aby sprawdzić, czy twoja domena znajduje się na jakiejś liście blokującej, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Istnieją jednak inne sposoby, aby dowiedzieć się, czy ofiara **aktywnie poszukuje podejrzanej aktywności phishingowej w sieci**, jak wyjaśniono w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny, którą kontrolujesz, **zawierającej** **słowo kluczowe** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek interakcję **DNS lub HTTP** z nimi, dowiesz się, że **aktywnie poszukuje** podejrzanych domen i będziesz musiał być bardzo ukryty.

### Ocena phishingu

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twój e-mail trafi do folderu spam, zostanie zablokowany, czy będzie skuteczny.

## High-Touch Identity Compromise (Reset MFA przez help-desk)

Nowoczesne grupy atakujące coraz częściej pomijają w ogóle wabiki e-mailowe i **bezpośrednio atakują workflow serwisu help-desk / odzyskiwania tożsamości**, aby obejść MFA. Atak jest w pełni "living-off-the-land": gdy operator zdobędzie ważne credentials, pivotuje za pomocą wbudowanych narzędzi administracyjnych – żadne malware nie jest wymagane.

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbieranie danych osobowych i korporacyjnych z LinkedIn, wycieków danych, publicznego GitHub itd.
* Identyfikacja wartościowych tożsamości (kadra zarządzająca, IT, finanse) i wypisanie **dokładnego procesu help-desk** dotyczącego resetu hasła / MFA.
2. Inżynieria społeczna w czasie rzeczywistym
* Telefon, Teams lub chat z help-desk, podszywając się pod cel (często z **spoofed caller-ID** lub **cloned voice**).
* Przekaż wcześniej zebrane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj agenta, aby **zresetował sekret MFA** lub wykonał **SIM-swap** na zarejestrowanym numerze mobilnym.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
* Ustanów przyczółek przez dowolny web SSO portal.
* Enumeruj AD / AzureAD za pomocą wbudowanych narzędzi (bez wrzucania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch boczny za pomocą **WMI**, **PsExec**, lub legalnych agentów **RMM** już białych list w środowisku.

### Wykrywanie i łagodzenie
* Traktuj odzyskiwanie tożsamości przez help-desk jako **operację uprzywilejowaną** – wymagaj step-up auth i zatwierdzenia przez menedżera.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które alarmują przy:
* Zmiana metody MFA + uwierzytelnienie z nowego urządzenia / geo.
* Natychmiastowe podniesienie uprawnień tego samego podmiotu (user-→-admin).
* Nagrywaj rozmowy help-desk i wymuszaj **oddzwonienie na już zarejestrowany numer** przed jakimkolwiek resetem.
* Wdroż **Just-In-Time (JIT) / Privileged Access**, aby nowo zresetowane konta **nie** dziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## Decepcja na dużą skalę – SEO Poisoning & “ClickFix” Campaigns
Zespoły commodity kompensują koszty operacji high-touch masowymi atakami, które zamieniają **wyszukiwarki i sieci reklamowe w kanał dostawy**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam w wyszukiwarce.
2. Ofiara pobiera mały **first-stage loader** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Wskazówki zabezpieczające
* Blokuj świeżo zarejestrowane domeny i egzekwuj **Advanced DNS / URL Filtering** dla *search-ads* oraz e-maili.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / Store, zabroń wykonywania `HTA`, `ISO`, `VBS` poprzez politykę.
* Monitoruj uruchamianie procesów potomnych przeglądarek otwierających instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Wyszukuj LOLBins często nadużywane przez first-stage loadery (np. `regsvr32`, `curl`, `mshta`).

---

## Operacje phishingowe z użyciem AI
Atakujący teraz łączą **LLM & voice-clone APIs** do w pełni spersonalizowanych wabików i interakcji w czasie rzeczywistym.

| Warstwa | Przykładowe użycie przez aktora zagrożenia |
|-------|-----------------------------|
|Automation|Generuje i wysyła >100 k e-maili / SMS z losowo zmienionymi sformułowaniami i linkami śledzącymi.|
|Generative AI|Tworzy *jednorazowe* e-maile odnoszące się do publicznych M&A, wewnętrznych żartów z social media; deep-fake głosu CEO w callback scam.|
|Agentic AI|Autonomicznie rejestruje domeny, skrobuje open-source intel, tworzy kolejne e-maile, gdy ofiara kliknie, ale nie poda credentials.|

**Obrona:**
• Dodaj **dynamiczne bannery** podkreślające wiadomości wysłane z niezaufanej automatyzacji (przez anomalie ARC/DKIM).  
• Wdroż **voice-biometric challenge phrases** dla wysoce ryzykownych żądań telefonicznych.  
• Ciągle symuluj AI-generowane wabiki w programach świadomości – statyczne szablony są przestarzałe.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Poza klasycznym push-bombingiem, operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-desk, unieważniając istniejący token użytkownika. Każdy kolejny monit o logowanie wydaje się ofierze prawidłowy.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu skopiować złośliwe polecenia do schowka ofiary z kompromitowanej lub typosquatted strony i następnie skłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez potrzeby pobierania czy załączników.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej umieszczają swoje phishing flows za prostym sprawdzeniem urządzenia, tak aby desktop crawlers nigdy nie docierały do końcowych stron. Typowym wzorcem jest mały script, który testuje, czy DOM obsługuje touch, i wysyła wynik do server endpoint; klienci nie‑mobile otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobile otrzymują pełny flow.

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
- Ustawia session cookie podczas pierwszego ładowania.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub placeholder) dla kolejnych żądań GET gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki wyszukiwania i wykrywania:
- zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria sieciowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla nie‑mobilnych; legalne ścieżki ofiary mobilnej zwracają 200 z następczym HTML/JS.
- Blokuj lub dokładnie analizuj strony, które warunkują zawartość wyłącznie na `ontouchstart` lub podobnych testach urządzenia.

Wskazówki obronne:
- Uruchamiaj crawlers z fingerprintami przypominającymi urządzenia mobilne i z włączonym JS, aby ujawnić gated content.
- Generuj alerty na podejrzane odpowiedzi 500 następujące po `POST /detect` na nowo zarejestrowanych domenach.

## Źródła

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
