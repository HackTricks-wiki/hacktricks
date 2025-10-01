# Mbinu za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Fanya recon kwa victim
1. Chagua the **victim domain**.
2. Fanya web enumeration ya msingi ukitafuta **login portals** zinazotumika na victim na **amua** ni ipi utakayo **impersonate**.
3. Tumia **OSINT** ili **find emails**.
2. Andaa mazingira
1. **Buy the domain** utakaotumia kwa phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS na **gophish**
3. Andaa campaign
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Mbinu za mabadiliko ya domain

- **Keyword**: Jina la domain linajumuisha keyword muhimu la domain ya asili (mfano, zelster.com-management.com).
- **hypened subdomain**: Badilisha dot kwa hyphen ya subdomain (mfano, www-zelster.com).
- **New TLD**: Ipi domain ile ile ukitumia New TLD (mfano, zelster.org)
- **Homoglyph**: Inabadilisha herufi katika jina la domain kwa herufi zinazofanana kwa muonekano (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Inabadilisha nafasi za herufi mbili ndani ya jina la domain (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa "s" mwishoni mwa jina la domain (mfano, zeltsers.com).
- **Omission**: Inaondoa moja ya herufi kutoka jina la domain (mfano, zelser.com).
- **Repetition:** Inarudia moja ya herufi ndani ya jina la domain (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini isiyo na stealth nyingi. Inabadilisha moja ya herufi katika jina la domain, labda kwa herufi ambayo iko karibu kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Ingiza dot ndani ya jina la domain (mfano, ze.lster.com).
- **Insertion**: Inaingiza herufi katika jina la domain (mfano, zerltser.com).
- **Missing dot**: Ambatanisha TLD kwa jina la domain. (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna uwezekano kwamba moja ya bits zilizohifadhiwa au zinazotumwa inaweza kupinduliwa kiotomatiki kutokana na sababu mbalimbali kama solar flares, cosmic rays, au makosa ya hardware.

Wakati dhana hii inapotumika kwa maombi ya DNS, inawezekana kwamba domain iliyopokelewa na DNS server si ile ile iliyokuwa imeombwa awali.

Kwa mfano, mabadiliko ya bit moja kwenye domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Attackers wanaweza kuchukua faida ya hili kwa kusajili domains nyingi za bit-flipping zinazofanana na domain ya victim. Kusudio lao ni kupeleka watumiaji halali kwenye infrastructure yao.

Kwa taarifa zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Nunua domain yenye kuaminika

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyokwisha muda ambayo unaweza kutumia.\
Ili kuhakikisha kwamba expired domain unayopanga kununua tayari ina SEO nzuri unaweza kuangalia jinsi ilivyokatagoriwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili kugundua zaidi anwani za email halali au kuthibitisha zile ulizogundua tayari unaweza kuangalia kama unaweza ku-brute-force smtp servers za victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia any web portal kufikia mails zao, unaweza kuangalia kama ni vunja kwa username brute force, na kutumia udhaifu huo ikiwa inawezekana.

## Configuring GoPhish

### Installation

Unaweza kupakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download na decompress ndani ya `/opt/gophish` na uendeshe `/opt/gophish/gophish`\
Utapewa password kwa admin user kwenye port 3333 katika output. Kwa hiyo, ingia kwenye port hiyo na tumia yale credentials kubadilisha admin password. Unaweza kuhitaji ku-tunnel port hiyo hadi local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti la TLS**

Kabla ya hatua hii unapaswa kuwa tayari umenunua kikoa utakayotumia, na lazima kiwe kimeelekezwa kwenye IP ya VPS ambapo unasanidi gophish.
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

**Pia badilisha thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwisho, badilisha mafaili **`/etc/hostname`** na **`/etc/mailname`** kwa jina lako la domain na **anzisha upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwa **ip address** ya VPS na rekodi ya **DNS MX** inayoelekeza kwa `mail.<domain>`

Sasa tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha gophish na tufanye usanidi wake.\
Badilisha `/opt/gophish/config.json` kuwa ifuatayo (kumbuka matumizi ya https):
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

Ili kuunda huduma ya gophish ili iweze kuanzishwa kiotomatiki na kusimamiwa kama huduma, unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:
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
Maliza kusanidi huduma na kuangalia inavyofanya:
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

### Subiri & kuwa halali

Kadri domain inavyokuwa ya zamani, ndivyo uwezekano wa kugunduliwa kama spam unavyopungua. Kwa hivyo unapaswa kusubiri muda mrefu iwezekanavyo (angalau 1week) kabla ya phishing assessment. Zaidi ya hayo, ukiongeza ukurasa kuhusu sekta yenye sifa, sifa utakayopata itakuwa bora.

Kumbuka kwamba hata ukilazimika kusubiri wiki unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi Reverse DNS (rDNS) record

Weka rekodi ya rDNS (PTR) inayotatua IP address ya VPS kwa jina la domain.

### Rekodi ya Sender Policy Framework (SPF)

Unapaswa **kusanidi SPF record kwa domain mpya**. Ikiwa haujui SPF record ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuunda SPF policy yako (tumia IP ya mashine ya VPS)

![](<../../images/image (1037).png>)

Hili ndilo maudhui yanayopaswa kuwekwa ndani ya TXT record ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Uthibitishaji wa Ujumbe Unaotegemea Domain, Ripoti & Utii (DMARC) Rekodi

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa haujui ni rekodi ya DMARC ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unahitaji kuunda rekodi mpya ya DNS TXT ikielekeza hostname `_dmarc.<domain>` na yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Unapaswa **kusanidi DKIM kwa domain mpya**. Ikiwa haujui ni rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo ufunguo wa DKIM unazozalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Fungua ukurasa huo na tuma barua pepe kwa anwani watakayo kutoa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kukagua usanidi wako wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma majibu** (kwa hili utahitaji **kufungua** port **25** na kuona majibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe a kama root).\
Angalia kwamba unapitisha vipimo vyote:
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
Unaweza pia kutuma **ujumbe kwa akaunti ya Gmail unayodhibiti**, na ukague **vichwa vya barua pepe** katika inbox yako ya Gmail, `dkim=pass` inapaswa kuwepo katika uwanja wa kichwa `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondolewa kwenye Orodha Nyeusi ya Spamhouse

Ukurasa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha kama domain yako inazuiliwa na spamhouse. Unaweza kuomba domain/IP yako iondolewe kwa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kwenye Orodha Nyeusi ya Microsoft

​​Unaweza kuomba domain/IP yako iondolewe kwa [https://sender.office.com/](https://sender.office.com).

## Unda & Anzisha Kampeni ya GoPhish

### Profaili ya Kutuma

- Weka **jina la utambuzi** la profaili ya mtumaji
- Amua kutoka kwa akaunti ipi utakayotumia kutuma phishing emails. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inashauriwa kutumia kipengele cha "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Ninapendekeza **kutuma barua za jaribio kwa anwani za 10min mails** ili kuepuka kuwekwa kwenye orodha nyeusi wakati wa majaribio.

### Kiolezo cha Barua Pepe

- Weka **jina la utambuzi** la kiolezo
- Kisha andika **subject** (hakuna kitu cha kigeni, tu kile unachoweza kutarajia kusoma katika barua pepe ya kawaida)
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
Kumbuka kwamba **ili kuongeza uhalali wa email**, inashauriwa kutumia baadhi ya saini kutoka kwenye email ya mteja. Mapendekezo:

- Tuma email kwa **anwani isiyokuwepo** na angalia kama jibu lina saini yoyote.
- Tafuta **emails za umma** kama info@ex.com au press@ex.com au public@ex.com na utume email kwao na usubiri jibu.
- Jaribu kuwasiliana na **email sahihi iliyogunduliwa** na subiri jibu

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika the HTML code** ya ukurasa wa wavuti. Kumbuka kwamba unaweza **ku-import** web pages.
- Mark **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kubadilisha code ya HTML ya ukurasa na kufanya majaribio kwa local (labda ukitumia Apache server) **mpaka utakapopendeza matokeo.** Kisha, andika hiyo HTML code kwenye box.
> Kumbuka kwamba ikiwa unahitaji **kutumia static resources** kwa HTML (labda baadhi ya CSS na JS pages) unaweza kuziweka katika _**/opt/gophish/static/endpoint**_ na kisha kuzipata kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **ku-redirect watumiaji kwenye ukurasa halali wa mwanzo** wa mwathiriwa, au ku-redirect kwa _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha onyesha kuwa mchakato umefanikiwa**.

### Users & Groups

- Weka jina
- **Import the data** (kumbuka kwamba ili kutumia template kwa mfano unahitaji jina la kwanza, jina la mwisho na email address ya kila mtumiaji)

![](<../../images/image (163).png>)

### Campaign

Hatimaye, unda kampeni ukichagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa waathiriwa

Kumbuka pia kwamba **Sending Profile inaruhusu kutuma test email ili kuona jinsi email ya hatima itakavyoonekana**:

![](<../../images/image (192).png>)

> [!TIP]
> Napendekeza **kutuma test emails kwa anwani za 10min mails** ili kuepuka kuorodheshwa kwenye blacklist wakati wa kufanya majaribio.

Mara kila kitu kikiwa tayari, anza kampeni tu!

## Website Cloning

Ikiwa kwa sababu yoyote ungependa kukopa tovuti angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma files zenye aina fulani ya backdoor** (labda C2 au labda kitu ambacho kitachochea authentication).\
Angalia ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni changamto kwani unafanana na tovuti halisi na kukusanya taarifa zilizowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuweka password sahihi au ikiwa application uliyofanya clone imewekwa na 2FA, **taarifa hizi hazitatumika kukufanya uende kama mtumiaji aliyefumwa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapoweza kusaidia. Zana hizi zitakuwezesha kuzalisha shambulio la MitM. Kwa msingi, shambulio hufanya kazi kwa njia ifuatayo:

1. Unachanganya fomu ya **login** ya ukurasa halisi.
2. Mtumiaji **anatuma** credential zake kwenye ukurasa wako wa fake na zana inazituma kwenye ukurasa halisi, **ikikagua kama credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba 2FA na mara mtumiaji **akitolea** itaambatishwa kwenye ukurasa halisi.
4. Mara mtumiaji anapothibitishwa wewe (kama mshambulizi) utakuwa ume **kamata credentials, 2FA, cookie na taarifa zote** za kila mwingiliano wakati zana ikifanya MitM.

### Via VNC

Je, badala ya **kumtamisha mwathiriwa kwenye ukurasa wa uhalifu** unaoonekana kama wa awali, ungeweza kumpeleka kwenye **kikao cha VNC chenye browser iliyounganishwa kwenye ukurasa halisi**? Utaweza kuona anachofanya, kuiba password, MFA iliyotumika, cookies...\
Unaweza kufanya hivi kwa kutumia [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obvious moja ya njia bora za kujua kama umeuawa ni **kutafuta domain yako ndani ya blacklists**. Ikiwa inaonekana imeorodheshwa, kwa namna fulani domain yako iligunduliwa kama shaka.\
Njia moja rahisi ya kukagua kama domain yako inaonekana kwenye blacklist ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mwathiriwa anatafuta kwa uangalifu shughuli za phishing zenye shaka kama ilivyoelezwa kwenye:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathiriwa **na/au kuzalisha certificate** kwa **subdomain** ya domain unayodhibiti **lenye** **keyword** ya domain ya mwathiriwa. Ikiwa **mwathiriwa** atafanya aina yoyote ya mwingiliano wa **DNS au HTTP** nao, utajua kuwa **yeye anatafuta kwa ufanisi** domains zenye shaka na utahitaji kuwa mwiba sana.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious) kutathmini kama email yako itaishia kwenye spam folder au itazuiliwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Sets za uvamizi wa kisasa mara nyingi hupuuza malengo ya email kabisa na **hufokusisha moja kwa moja mchakato wa service-desk / identity-recovery** ili kuondoa MFA. Shambulio hilo ni kamili "living-off-the-land": mara operator anapomiliki credentials halali wanapitia na zana za admin zilizojengwa – hakuna malware inayohitajika.

### Attack flow
1. Recon ya mwathiriwa
* Pata maelezo ya binafsi & ya kampuni kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua identities zenye thamani kubwa (maafisa wakuu, IT, fedha) na weka orodha ya **hasa ya mchakato wa help-desk** kwa reset ya password / MFA.
2. Social engineering kwa wakati halisi
* Piga simu, tumia Teams au chat kwa help-desk ukijinakili kuwa ni eneo lengwa (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa ili kupita uthibitishaji wa maarifa.
* Mshawishi afanye **reset ya MFA secret** au kufanya **SIM-swap** kwenye namba ya simu iliyosajiliwa.
3. Hatua za mara moja baada ya kupata (≤60 min katika kesi halisi)
* Anzisha foothold kupitia portal yoyote ya web SSO.
* Ordoza AD / AzureAD kwa kutumia built-ins (bila kupeleka binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Kuhamia upande wa ndani kwa kutumia **WMI**, **PsExec**, au agents halali za **RMM** ambazo tayari zimewekwa kwenye whitelist ndani ya mazingira.

### Detection & Mitigation
* Tibu help-desk identity recovery kama **operesheni ya kipaumbele** – hitaji step-up auth & idhini ya manager.
* Tumia **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazotia alarm juu ya:
* MFA method changed + authentication kutoka kwenye device / geo mpya.
* Kuongezeka mara moja kwa ruhusa kwa mfano huo huo (user-→-admin).
* Rekodi simu za help-desk na lipa utekelezaji wa **call-back kwa namba iliyosajiliwa tayari** kabla ya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizorekebishwa hivi karibuni **zisipate** token za uenyekiti wa juu moja kwa moja.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Mataifa ya kawaida hupunguza gharama za operesheni za high-touch kwa shambulio la wingi linalotumia **search engines & ad networks kama njia ya utoaji**.

1. **SEO poisoning / malvertising** inasukuma matokeo ya uongo kama `chromium-update[.]site` kwenye matangazo ya juu ya search ads.
2. Mwathiriwa anapakua loader ndogo ya hatua ya kwanza (mara nyingi JS/HTA/ISO). Mifano iliyoshuhudiwa na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader inatoa exfiltrate browser cookies + credential DBs, kisha inachukua **silent loader** ambayo inaamua – kwa wakati halisi – ikiwa itaweka:
* RAT (mfano AsyncRAT, RustDesk)
* ransomware / wiper
* sehemu ya persistence (Run key ya registry + scheduled task)

### Hardening tips
* Zuia domains zilizosajiliwa hivi karibuni & tekeleza **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na e-mail.
* Zuia ufungaji wa software isipokuwa MSI / Store packages zilizosainiwa, kata utekelezaji wa `HTA`, `ISO`, `VBS` kwa sera.
* Simamia kwa ajili ya child processes za browsers zinazoanisha installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Kagua LOLBins zinazotumika mara kwa mara na first-stage loaders (mfano `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Wavamizi sasa wanachanganya **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kikamilifu na mwingiliano wa wakati halisi.

| Layer | Mfano wa matumizi na mtoo wa vitisho |
|-------|--------------------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

Ulinzi:
• Ongeza **dynamic banners** zinazobainisha ujumbe ulioletwa na automation isiyotumika kwa kuaminika (kupitia ARC/DKIM anomalies).
• Tekeleza **voice-biometric challenge phrases** kwa maombi ya hatari kwenye simu.
• Endelea kutekeleza majaribio ya lures zilizotengenezwa na AI katika programu za uhamasishaji – templates imara zimepitwa na wakati.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya kawaida, operator wanaweza tu **lazimisha usajili mpya wa MFA** wakati wa simu ya help-desk, wakifuta token ya mtumiaji iliyokuwepo. Kumbukumbu yoyote inayofuata ya login itaonekana halali kwa mwathiriwa.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** yanatokea **katika dakika chache kutoka IP ile ile**.



## Clipboard Hijacking / Pastejacking

Wavamizi wanaweza kwa utulivu kunakili amri zenye madhara kwenye clipboard ya mwathiriwa kutoka kwenye ukurasa wa wavuti uliovamiwa au typosquatted, kisha kumdanganya mtumiaji kubandika ndani ya **Win + R**, **Win + X** au dirisha la terminal, wakitekeleza arbitrary code bila kupakua au kiambatisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
