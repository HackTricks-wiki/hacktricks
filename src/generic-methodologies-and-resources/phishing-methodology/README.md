# Phishing Metodologia

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś mieć **już zakupioną domenę**, której zamierzasz użyć, i musi ona **wskazywać** na **adres IP VPS**, na którym konfigurujesz **gophish**.
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

**Zmień także wartości następujących zmiennych w /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na swoją nazwę domeny i **zrestartuj swój VPS.**

Teraz utwórz **rekord A DNS** dla `mail.<domain>` wskazujący na **adres IP** VPS oraz **rekord MX DNS** wskazujący na `mail.<domain>`

Teraz przetestujmy wysyłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj wykonywanie gophish i skonfigurujmy go.\
Zmodyfikuj `/opt/gophish/config.json` tak, aby wyglądał następująco (zwróć uwagę na użycie https):
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

Aby utworzyć usługę gophish tak, aby mogła być uruchamiana automatycznie i zarządzana, możesz utworzyć plik `/etc/init.d/gophish` z następującą zawartością:
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
## Konfiguracja serwera poczty i domeny

### Poczekaj i bądź wiarygodny

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego powinieneś poczekać jak najdłużej (co najmniej 1 tydzień) przed testem phishingowym. Ponadto, jeśli umieścisz stronę związaną z sektorem o dobrej reputacji, uzyskana reputacja będzie lepsza.

Pamiętaj, że nawet jeśli musisz poczekać tydzień, możesz już teraz dokończyć konfigurację wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który mapuje adres IP VPS na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej polityki SPF (użyj adresu IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, którą należy ustawić w rekordzie TXT domeny:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord DMARC (Domain-based Message Authentication, Reporting & Conformance)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

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

Możesz to sprawdzić używając [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Po prostu wejdź na stronę i wyślij e-mail na adres, który Ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz też **sprawdzić konfigurację poczty** wysyłając e-mail na `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu będziesz musiał **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wyślesz wiadomość jako root).\
Sprawdź, czy zdasz wszystkie testy:
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
### Usuwanie z Spamhouse Blacklist

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie domeny/IP na: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z Microsoft Blacklist

Możesz zgłosić prośbę o usunięcie domeny/IP na [https://sender.office.com/](https://sender.office.com).

## Utwórz i uruchom GoPhish Campaign

### Sending Profile

- Ustaw jakąś **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishingowe maile. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz zostawić puste username i password, ale upewnij się, że zaznaczyłeś opcję "Ignore Certificate Errors"

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zalecane jest użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Polecam wysyłać testowe maile na adresy 10min mails, aby uniknąć zablokowania podczas testów.

### Email Template

- Ustaw jakąś **nazwę identyfikującą** szablon
- Następnie wpisz **subject** (nic dziwnego, po prostu coś, co można by oczekiwać w zwykłym mailu)
- Upewnij się, że zaznaczyłeś "**Add Tracking Image**"
- Napisz **email template** (możesz użyć zmiennych, jak w poniższym przykładzie):
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
Należy pamiętać, że **w celu zwiększenia wiarygodności e-maila** zaleca się użycie jakiegoś podpisu z wiadomości od klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Wyszukaj **publiczne adresy e‑mail** takie jak info@ex.com, press@ex.com lub public@ex.com, wyślij do nich wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś odnalezionym, prawidłowym** adresem e‑mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Strona docelowa

- Wpisz **nazwę**
- **Wpisz kod HTML** strony. Zwróć uwagę, że możesz **importować** strony.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![](<../../images/image (826).png>)

> [!TIP]
> Zazwyczaj będziesz musiał zmodyfikować kod HTML strony i przeprowadzić testy lokalnie (np. używając serwera Apache) **aż osiągniesz zadowalający efekt.** Następnie wklej ten kod HTML w pole.\
> Zwróć uwagę, że jeśli potrzebujesz **użyć zasobów statycznych** dla HTML (np. CSS i JS) możesz zapisać je w _**/opt/gophish/static/endpoint**_ i potem uzyskać do nich dostęp z _**/static/\<filename>**_

> [!TIP]
> Dla przekierowania możesz **przekierować użytkowników na prawdziwą główną stronę** ofiary, lub przekierować ich np. na _/static/migration.html_, dodać **kręcące się kółko (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a potem wskazać, że proces się powiódł**.

### Użytkownicy & grupy

- Ustaw nazwę
- **Zaimportuj dane** (zwróć uwagę, że aby użyć szablonu w przykładzie potrzebujesz imienia, nazwiska i adresu e‑mail każdego użytkownika)

![](<../../images/image (163).png>)

### Kampania

Na koniec stwórz kampanię, wybierając nazwę, szablon wiadomości, stronę docelową, URL, profil wysyłkowy i grupę. Pamiętaj, że URL będzie linkiem wysyłanym ofiarom

Zwróć uwagę, że **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> Zalecam **wysyłać testowe e-maile na adresy 10min mail**, aby uniknąć zablokowania podczas testów.

Gdy wszystko jest gotowe, po prostu uruchom kampanię!

## Klonowanie strony

Jeśli z jakiegokolwiek powodu chcesz sklonować stronę, sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Dokumenty i pliki z backdoorem

W niektórych ocenach phishingowych (głównie dla Red Teams) będziesz też chciał **wysyłać pliki zawierające jakiś rodzaj backdoora** (może C2 lub coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę, aby zobaczyć przykłady:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Przez Proxy MitM

Poprzedni atak jest całkiem sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła lub jeśli aplikacja, którą sfałszowałeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podszyć się pod oszukanego użytkownika**.

W tym miejscu przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Narzędzie to pozwala wygenerować atak typu MitM. Zasadniczo atak działa w następujący sposób:

1. Podszywasz się pod **formularz logowania** prawdziwej strony.
2. Użytkownik wysyła swoje **credentials** do twojej fałszywej strony, a narzędzie przekazuje je do prawdziwej strony, **sprawdzając, czy dane działają**.
3. Jeśli konto ma skonfigurowane **2FA**, strona MitM poprosi o nie, a gdy **użytkownik je wprowadzi** narzędzie prześle je do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) będziesz miał **przechwycone credentials, 2FA, cookie i wszystkie informacje** z każdej interakcji podczas działania MitM.

### Przez VNC

Co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** o wyglądzie identycznym z oryginałem, przekierujesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną**? Będziesz mógł obserwować jej działania, ukraść hasło, używane MFA, cookies...\
Można to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie, że zostałeś wykryty

Oczywiście jednym z najlepszych sposobów, aby wiedzieć, czy zostałeś złapany, jest **sprawdzenie swojej domeny na czarnych listach**. Jeśli pojawi się na liście, w jakiś sposób twoja domena została wykryta jako podejrzana.\
Jednym z prostych sposobów sprawdzenia, czy twoja domena pojawia się na jakiejkolwiek czarnej liście, jest użycie [https://malwareworld.com/](https://malwareworld.com)

Jednak istnieją inne sposoby, aby dowiedzieć się, czy ofiara **aktywnie szuka podejrzanej aktywności phishingowej w sieci**, jak opisano w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez Ciebie **zawierającej** **słowo kluczowe** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek interakcję **DNS lub HTTP** z nimi, dowiesz się, że **aktywnie szuka** podejrzanych domen i będziesz musiał być bardzo dyskretny.

### Oceń phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious) aby ocenić, czy Twój e-mail trafi do folderu spamu, zostanie zablokowany, czy będzie skuteczny.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Nowoczesne zestawy intruzyjne coraz częściej pomijają w ogóle wabiki e‑mailowe i **bezpośrednio celują w workflow service-desk / identity-recovery**, aby obejść MFA. Atak jest w pełni "living-off-the-land": gdy operator uzyska prawidłowe credentials, porusza się używając wbudowanych narzędzi administratorskich – żadne malware nie jest potrzebne.

### Przebieg ataku
1. Rozpoznanie ofiary
* Zbieraj dane osobowe i korporacyjne z LinkedIn, wycieków danych, publicznego GitHub itp.
* Zidentyfikuj wartościowe tożsamości (kadra zarządzająca, IT, finanse) i wypisz **dokładny proces help-desk** dotyczący resetu hasła / MFA.
2. Inżynieria społeczna w czasie rzeczywistym
* Zadzwoń, użyj Teams lub czatu do help-desk podszywając się pod cel (często z **sfałszowanym caller-ID** lub **sklonowanym głosem**).
* Podaj wcześniej zebrane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj agenta, aby **zresetował MFA secret** lub przeprowadził **SIM-swap** na zarejestrowanym numerze.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w realnych przypadkach)
* Ustanów przyczółek przez dowolny portal web SSO.
* Enumeruj AD / AzureAD za pomocą wbudowanych narzędzi (bez zapisywania binariów):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ruch lateralny za pomocą **WMI**, **PsExec**, lub legalnych agentów **RMM** już białolistowanych w środowisku.

### Wykrywanie i łagodzenie
* Traktuj odzyskiwanie tożsamości przez help-desk jako **operację uprzywilejowaną** – wymagaj step-up auth i zatwierdzenia przez menedżera.
* Wdróż reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które alarmują gdy:
* Zmiana metody MFA + uwierzytelnienie z nowego urządzenia / regionu.
* Natychmiastowe podniesienie uprawnień tego samego podmiotu (user → admin).
* Nagrywaj połączenia do help-desk i wymuszaj **oddzwonienie na już zarejestrowany numer** przed jakimkolwiek resetem.
* Wdroż **Just-In-Time (JIT) / Privileged Access**, aby świeżo zresetowane konta **nie** dziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## Dezinformacja na dużą skalę – SEO Poisoning & “ClickFix” Campaigns
Zespoły commoditowe równoważą koszty operacji high-touch masowymi atakami, które zamieniają **wyszukiwarki i sieci reklamowe w kanał dostarczenia**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik taki jak `chromium-update[.]site` na szczyt reklam w wynikach wyszukiwania.
2. Ofiara pobiera niewielki **first-stage loader** (często JS/HTA/ISO). Przykłady obserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltruje cookies przeglądarki + bazy credential DB, potem pobiera **silent loader**, który decyduje – *w czasie rzeczywistym* – czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent utrwalający (klucz Run w rejestrze + zadanie harmonogramu)

### Wskazówki dotyczące utwardzania
* Blokuj świeżo zarejestrowane domeny i egzekwuj **Advanced DNS / URL Filtering** na *search-ads* oraz w poczcie.
* Ogranicz instalację oprogramowania do podpisanych paczek MSI / Store, zablokuj uruchamianie `HTA`, `ISO`, `VBS` polityką.
* Monitoruj procesy potomne przeglądarek uruchamiające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Poluj na LOLBins często nadużywane przez first-stage loadery (np. `regsvr32`, `curl`, `mshta`).

---

## Operacje phishingowe wspomagane AI
Atakujący teraz łączą **LLM & voice-clone APIs** dla w pełni spersonalizowanych wabików i interakcji w czasie rzeczywistym.

| Warstwa | Przykładowe użycie przez aktora zagrożenia |
|-------|-----------------------------|
|Automatyzacja|Generuj i wysyłaj >100k e‑maili / SMS z losowo zmienianą treścią i linkami śledzącymi.|
|Generative AI|Twórz *jednorazowe* e‑maile odnoszące się do publicznych M&A, wewnętrznych żartów z social media; deep-fake głos CEO w oszustwie callback.|
|Agentic AI|Autonomicznie rejestruj domeny, zeskrobuj open-source intel, twórz kolejne maile, gdy ofiara kliknie, ale nie poda creds.|

**Obrona:**
• Dodaj **dynamiczne banery** podkreślające wiadomości wysyłane z niezaufanej automatyzacji (na podstawie anomalii ARC/DKIM).  
• Wdróż **głosowe frazy biometryczne** dla ryzykownych żądań telefonicznych.  
• Ciągle symuluj wabiki generowane przez AI w programach świadomościowych – statyczne szablony są przestarzałe.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Poza klasycznym push-bombing, operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-deskiem, unieważniając istniejący token użytkownika. Każdy kolejny monit logowania wygląda dla ofiary jak prawidłowy.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego adresu IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą potajemnie skopiować złośliwe polecenia do schowka ofiary z skompromitowanej lub typosquatted strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub w oknie terminala, co skutkuje wykonaniem dowolnego kodu bez pobierania lub załączników.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Źródła

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
