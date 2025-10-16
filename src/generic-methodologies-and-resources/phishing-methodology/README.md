# Phishing Methodology

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

Przed tym krokiem powinieneś mieć już **kupioną domenę**, której zamierzasz użyć, i musi ona **wskazywać** na **IP of the VPS**, na którym konfigurujesz **gophish**.
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

Zacznij instalację: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Zmień także wartości następujących zmiennych w pliku /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`**, ustawiając swoją nazwę domeny i **zrestartuj VPS.**

Teraz utwórz **DNS A record** dla `mail.<domain>` wskazujący na **adres IP** VPS i rekord **DNS MX** wskazujący na `mail.<domain>`

Teraz przetestujmy wysyłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj działanie gophish i skonfiguruj go.\
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
**Skonfiguruj gophish service**

Aby utworzyć gophish service, tak aby mógł być uruchamiany automatycznie i zarządzany jako service, możesz utworzyć plik `/etc/init.d/gophish` z następującą zawartością:
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
## Konfigurowanie mail server and domain

### Poczekaj i wyglądaj wiarygodnie

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie oznaczona jako spam. Dlatego powinieneś poczekać jak najdłużej (co najmniej 1 tydzień) przed phishing assessment. Ponadto, jeśli umieścisz stronę dotyczącą sektora o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz poczekać tydzień, możesz teraz skończyć konfigurację wszystkiego.

### Skonfiguruj Reverse DNS (rDNS) record

Ustaw rekord rDNS (PTR), który rozwiązuje adres IP VPS na nazwę domeny.

### Rekord Sender Policy Framework (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej polityki SPF (użyj adresu IP maszyny VPS)

![](<../../images/image (1037).png>)

To jest zawartość, którą należy ustawić w rekordzie TXT domeny:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord DMARC (Domain-based Message Authentication, Reporting & Conformance)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący na nazwę hosta `_dmarc.<domain>` z następującą zawartością:
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

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Po prostu wejdź na stronę i wyślij e-mail na adres, który Ci podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz też **sprawdzić konfigurację poczty** wysyłając e-mail na `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu będziesz musiał **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_, jeśli wyślesz e-mail jako root).\
Upewnij się, że przechodzisz wszystkie testy:
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
Możesz też wysłać **wiadomość na Gmaila, którym zarządzasz**, i sprawdzić **nagłówki emaila** w swojej skrzynce Gmail, `dkim=pass` powinien być obecny w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez Spamhouse. Możesz poprosić o usunięcie domeny/IP na: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Możesz poprosić o usunięcie domeny/IP na [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishingowe e-maile. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz pozostawić puste pola nazwę użytkownika i hasło, ale upewnij się, że zaznaczyłeś Ignoruj błędy certyfikatu

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Wyślij e-mail testowy**" aby sprawdzić, czy wszystko działa.\
> Zalecam **wysyłać e-maile testowe na adresy 10min mails** aby uniknąć zablokowania podczas testów.

### Email Template

- Nadaj **nazwę identyfikującą** szablonowi
- Następnie wpisz **temat** (nic dziwnego, po prostu coś, co mógłbyś spodziewać się przeczytać w zwykłym e-mailu)
- Upewnij się, że zaznaczyłeś "**Dodaj obraz śledzący**"
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
Zauważ, że **aby zwiększyć wiarygodność e-maila**, zaleca się użyć podpisu z wiadomości od klienta. Sugestie:

- Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
- Poszukaj **publicznych adresów e-mail** jak info@ex.com, press@ex.com lub public@ex.com, wyślij im wiadomość i poczekaj na odpowiedź.
- Spróbuj skontaktować się z **jakimś odnalezionym prawidłowym** adresem e-mail i poczekaj na odpowiedź

![](<../../images/image (80).png>)

> [!TIP]
> Szablon wiadomości e-mail pozwala także **dołączać pliki do wysłania**. Jeśli chcesz także wykraść wyzwania NTLM przy użyciu specjalnie spreparowanych plików/dokumentów [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Wpisz **nazwę**
- **Wpisz kod HTML** strony. Zauważ, że możesz **importować** strony.
- Zaznacz **Capture Submitted Data** i **Capture Passwords**
- Ustaw **przekierowanie**

![](<../../images/image (826).png>)

> [!TIP]
> Zwykle będziesz musiał zmodyfikować kod HTML strony i przeprowadzić testy lokalnie (np. używając serwera Apache) **aż będziesz zadowolony z efektów.** Następnie wpisz ten kod HTML w pole.\
> Zauważ, że jeśli potrzebujesz **użyć statycznych zasobów** dla HTML (np. plików CSS i JS) możesz zapisać je w _**/opt/gophish/static/endpoint**_ i następnie uzyskać do nich dostęp z _**/static/\<filename>**_

> [!TIP]
> Dla przekierowania możesz **przekierować użytkowników na prawdziwą główną stronę** ofiary, lub przekierować ich na _/static/migration.html_ na przykład, wyświetlić **spinning wheel (**[**https://loading.io/**](https://loading.io)**) przez 5 sekund, a następnie wskazać, że proces zakończył się sukcesem**.

### Users & Groups

- Ustaw nazwę
- **Importuj dane** (zauważ, że aby użyć szablonu w przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![](<../../images/image (163).png>)

### Campaign

Na koniec utwórz kampanię, wybierając nazwę, szablon e-mail, landing page, URL, sending profile i grupę. Zwróć uwagę, że URL będzie linkiem wysyłanym do ofiar

Zauważ, że **Sending Profile pozwala wysłać e-mail testowy, aby zobaczyć, jak będzie wyglądał finalny phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Polecam **wysyłać e-maile testowe na adresy 10min mails**, aby uniknąć wpisania na blacklistę podczas testów.

Gdy wszystko jest gotowe, uruchom kampanię!

## Website Cloning

Jeśli z jakiegoś powodu chcesz sklonować stronę sprawdź następującą stronę:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

W niektórych ocenach phishingowych (głównie dla Red Teams) możesz chcieć również **wysyłać pliki zawierające jakiś rodzaj backdoora** (np. C2 lub coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę, aby zobaczyć przykłady:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę i zbierasz dane wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła lub jeśli aplikacja, którą sfałszowałeś, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podszyć się pod oszukanego użytkownika**.

Tutaj przydają się narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Narzędzie to pozwala wygenerować atak typu MitM. Zasadniczo atak działa w następujący sposób:

1. Podszywasz się pod formularz logowania prawdziwej strony.
2. Użytkownik **wysyła** swoje **credentials** do twojej fałszywej strony, a narzędzie przesyła je do prawdziwej strony, **sprawdzając, czy credentials działają**.
3. Jeśli konto ma skonfigurowane **2FA**, strona MitM poprosi o nią i gdy **użytkownik ją poda**, narzędzie przekaże ją do prawdziwej strony.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) przechwycisz **credentials, 2FA, cookie oraz wszelkie informacje** z każdej interakcji, podczas gdy narzędzie wykonuje MitM.

### Via VNC

A co jeśli zamiast **wysyłać ofiarę na złośliwą stronę** o wyglądzie oryginału, skierujesz ją do **sesji VNC z przeglądarką połączoną z prawdziwą stroną**? Będziesz mógł zobaczyć, co robi, ukraść hasło, użyte MFA, cookies...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Oczywiście jednym z najlepszych sposobów, by sprawdzić, czy zostałeś zdemaskowany, jest **wyszukanie swojej domeny na listach blokujących**. Jeśli pojawi się na liście, w jakiś sposób twoja domena została wykryta jako podejrzana.\
Łatwym sposobem sprawdzenia, czy twoja domena występuje na jakiejkolwiek czarnej liście jest użycie [https://malwareworld.com/](https://malwareworld.com)

Są jednak inne sposoby, by dowiedzieć się, czy ofiara **aktywnie poszukuje podejrzanej aktywności phishingowej**, jak wyjaśniono w:


{{#ref}}
detecting-phising.md
{{#endref}}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **subdomeny** domeny kontrolowanej przez ciebie **zawierającej** **słowo kluczowe** domeny ofiary. Jeśli **ofiara** wykona jakąkolwiek **interakcję DNS lub HTTP** z nimi, dowiesz się, że **aktywnie poszukuje** podejrzanych domen i będziesz musiał być bardzo ukryty.

### Evaluate the phishing

Użyj [**Phishious** ](https://github.com/Rices/Phishious) aby ocenić, czy twój e-mail skończy w folderze spam, czy zostanie zablokowany, czy odniesie sukces.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Współczesne grupy włamujące się coraz częściej pomijają wędkowanie e-mailowe i **bezpośrednio celują w workflow service-desk / identity-recovery**, aby obejść MFA. Atak jest w pełni „living-off-the-land”: gdy operator zdobędzie ważne credentials, pivotuje za pomocą wbudowanych narzędzi administracyjnych – nie jest wymagane żadne malware.

### Attack flow
1. Rozpoznanie ofiary
* Zbieraj dane osobowe i korporacyjne z LinkedIn, wycieków danych, publicznego GitHub itp.
* Zidentyfikuj wysokowartościowe tożsamości (kadra zarządzająca, IT, finanse) i wyenumeruj **dokładny proces help-desk** dla resetu hasła / MFA.
2. Socjotechnika w czasie rzeczywistym
* Dzwoń, użyj Teams lub czatu do help-desk, podszywając się pod cel (często z **sfałszowanym caller-ID** lub **sklonowanym głosem**).
* Podaj wcześniej zebrane PII, aby przejść weryfikację opartą na wiedzy.
* Przekonaj agenta, aby **zresetował sekret MFA** lub wykonał **SIM-swap** na zarejestrowany numer telefonu.
3. Natychmiastowe działania po uzyskaniu dostępu (≤60 min w rzeczywistych przypadkach)
* Utrzymaj punkt zaczepienia przez dowolne web SSO portal.
* Wylistuj AD / AzureAD przy użyciu wbudowanych narzędzi (bez upuszczania binarek):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Poruszanie boczne z użyciem **WMI**, **PsExec** lub legalnych agentów **RMM** już białych list w środowisku.

### Detection & Mitigation
* Traktuj help-desk identity recovery jako **operację uprzywilejowaną** – wymagaj step-up auth i zatwierdzenia menedżera.
* Wdrażaj reguły **Identity Threat Detection & Response (ITDR)** / **UEBA**, które alarmują o:
* zmiana metody MFA + logowanie z nowego urządzenia / lokalizacji.
* natychmiastowe podniesienie uprawnień tego samego podmiotu (user → admin).
* Nagrywaj rozmowy z help-desk i wymuszaj **oddzwonienie na wcześniej zarejestrowany numer** przed jakimkolwiek resetem.
* Wdroż Just-In-Time (JIT) / Privileged Access, tak aby nowo zresetowane konta **nie** dziedziczyły automatycznie tokenów o wysokich uprawnieniach.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Masowe grupy atakujące równoważą koszty operacji high-touch kampaniami masowymi, które zamieniają **wyszukiwarki i sieci reklamowe w kanał dostawy**.

1. **SEO poisoning / malvertising** wypycha fałszywy wynik, taki jak `chromium-update[.]site`, na szczyt reklam w wyszukiwarce.
2. Ofiara pobiera mały **first-stage loader** (często JS/HTA/ISO). Przykłady zaobserwowane przez Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader eksfiltrowuje cookies przeglądarki + bazy credentials, a następnie pobiera **silent loader**, który decyduje – *w czasie rzeczywistym* – czy wdrożyć:
* RAT (np. AsyncRAT, RustDesk)
* ransomware / wiper
* komponent persistence (klucz Run w rejestrze + zadanie zaplanowane)

### Hardening tips
* Blokuj nowo zarejestrowane domeny i egzekwuj **Advanced DNS / URL Filtering** zarówno dla reklam w wyszukiwarce, jak i e-maili.
* Ogranicz instalację oprogramowania do podpisanych pakietów MSI / Store, zabroń wykonywania `HTA`, `ISO`, `VBS` przez politykę.
* Monitoruj procesy potomne przeglądarek uruchamiające instalatory:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Łów LOLBins często nadużywane przez first-stage loadery (np. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Atakujący łańcuchowo wykorzystują teraz **LLM & voice-clone APIs** do w pełni spersonalizowanych przynęt i interakcji w czasie rzeczywistym.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

Obrona:
• Dodaj **dynamiczne banery** podkreślające wiadomości wysyłane z niezaufanej automatyzacji (przez anomalie ARC/DKIM).  
• Wdrażaj **zwroty wyzwań biometrycznych głosu** dla żądań telefonicznych o wysokim ryzyku.  
• Ciągle symuluj przynęty generowane przez AI w programach świadomości – statyczne szablony są przestarzałe.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Poza klasycznym push-bombingiem, operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-deskiem, unieważniając istniejący token użytkownika. Każde kolejne wywołanie logowania będzie wyglądać dla ofiary jak prawidłowe.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, w których **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą w tle kopiować złośliwe polecenia do schowka ofiary ze zhakowanej lub typosquatowanej strony i następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez żadnego pobierania lub załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej ograniczają swoje phishingowe przepływy za prostą kontrolą urządzenia, tak aby desktopowe crawlery nigdy nie docierały do stron końcowych. Typowy wzorzec to mały skrypt sprawdzający, czy DOM obsługuje dotyk, i wysyłający wynik do endpointu serwera; klienci niemobilni otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobilni widzą pełny przepływ.

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
- Zwraca 500 (lub placeholder) do kolejnych GETów gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki wyszukiwania i wykrywania:
- zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria webowa: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla non‑mobile; prawidłowe ścieżki mobilnej ofiary zwracają 200 z kolejnym HTML/JS.
- Blokuj lub szczegółowo sprawdzaj strony, które uzależniają zawartość wyłącznie od `ontouchstart` lub podobnych sprawdzeń urządzenia.

Wskazówki obronne:
- Uruchamiaj crawlers z mobile‑like fingerprints i włączonym JS, aby ujawnić gated content.
- Generuj alerty dla podejrzanych odpowiedzi 500 pojawiających się po `POST /detect` na nowo zarejestrowanych domenach.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
