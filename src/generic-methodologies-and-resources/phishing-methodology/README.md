# Phishing Mbinu

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Recon waathiriwa
1. Chagua **domain ya waathiriwa**.
2. Fanya uchunguzi wa wavuti wa msingi **kutafuta login portals** zinazotumika na waathiriwa na **amua** ni ipi utakayoweza **kuiga**.
3. Tumia OSINT kupata anwani za barua pepe.
2. Andaa mazingira
1. **Nunua domain** utakayotumia kwa tathmini ya phishing
2. **Sanidi rekodi za huduma ya email** zinazohusiana (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS kwa gophish
3. Tayarisha kampeni
1. Tayarisha **kiolezo cha email**
2. Tayarisha **ukurasa wa wavuti** wa kuiba vigezo vya kuingia
4. Zindua kampeni!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Neno muhimu**: Jina la domain linajumuisha neno muhimu muhimu la domain ya asili (mfano, zelster.com-management.com).
- **hypened subdomain**: Badilisha **dot kwa hyphen** ya subdomain (mfano, www-zelster.com).
- **New TLD**: Domain ile ile ikitumia **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: Inabadilisha herufi kwenye jina la domain kwa **herufi zinazofanana kwa muonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Inabadili nafasi za herufi mbili ndani ya jina la domain (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa jina la domain (mfano, zeltsers.com).
- **Omission**: Inaondoa moja ya herufi kwenye jina la domain (mfano, zelser.com).
- **Repetition:** Inarudia moja ya herufi kwenye jina la domain (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini si ya kimfichiko sana. Inabadilisha moja ya herufi kwenye jina la domain, labda kwa herufi inayokaribu kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Taa **dot** ndani ya jina la domain (mfano, ze.lster.com).
- **Insertion**: Inachomeka herufi kwenye jina la domain (mfano, zerltser.com).
- **Missing dot**: Ambatanisha TLD kwa jina la domain. (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinaposafirishwa zinaweza kubadilika moja kwa moja kwa sababu mbalimbali kama vile solar flares, cosmic rays, au hitilafu za hardware.

Wakati dhana hii inapotumika kwa maombi ya DNS, inawezekana kwamba domain iliyopokelewa na DNS server sio ile ile iliyokuwa imetakiwa awali.

Kwa mfano, mabadiliko ya bit moja kwenye domain "windows.com" yanaweza kuiweka kuwa "windnws.com."

Wavamizi wanaweza kuchukua faida ya hili kwa kusajili domains nyingi zilizofanyiwa bit-flipping ambazo zinafanana na domain ya mhusika. Nia yao ni kuelekeza watumiaji halali kwenye miundombinu yao wenyewe.

Kwa taarifa zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyokwisha kuisha ambayo unaweza kutumia.\
Ili kuhakikisha kwamba domain iliyokwisha kuisha unayokusudia kununua **inamiliki SEO nzuri**, unaweza kuangalia jinsi inavyoranganywa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (bure kabisa)
- [https://phonebook.cz/](https://phonebook.cz) (bure kabisa)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili kugundua anwani zaidi za barua pepe zinazofanya kazi au kuthibitisha zile ulizozigundua tayari unaweza kujaribu ku-brute-force server za smtp za waathiriwa. [Jifunze jinsi ya kuthibitisha/kugundua anwani za barua pepe hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia portal yoyote ya wavuti kufikia barua pepe zao, unaweza kuangalia kama iko hatarini kwa username brute force, na kutekeleza udhaifu huo ikiwa inawezekana.

## Configuring GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download na decompress ndani ya `/opt/gophish` kisha endesha `/opt/gophish/gophish`\
Utapewa password kwa mtumiaji admin kwenye port 3333 katika output. Kwa hivyo, fikia port hiyo na tumia credentials hizo kubadilisha password ya admin. Huenda ukahitaji kutunnel port hiyo kwa local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii unapaswa tayari kuwa umenunua domain utakaoitumia na lazima iwe imeelekezwa kwa IP ya VPS ambapo unasanidi **gophish**.
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

Mwishowe badilisha faili **`/etc/hostname`** na **`/etc/mailname`** kwa jina la domain yako na **anzisha upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwa **ip address** ya VPS na **DNS MX** record inayoelekeza kwa `mail.<domain>`

Sasa tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

Simamisha utekelezaji wa gophish na tufanye usanidi.\
Badilisha `/opt/gophish/config.json` kuwa ifuatayo (kumbuka kutumia https):
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
Maliza kusanidi huduma na ukague jinsi inavyofanya:
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
## Kusanidi seva ya barua na domain

### Subiri & uwe halali

Kadiri domain inavyo kuwa ya zamani ndivyo inavyokuwa na uwezekano mdogo wa kugunduliwa kama spam. Kwa hivyo unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, ikiwa utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa itakayopatikana itakuwa bora.

Kumbuka kwamba hata kama unapaswa kusubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Configure Reverse DNS (rDNS) record

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kuwa jina la domain.

### Sender Policy Framework (SPF) Record

Lazima **usakinishe rekodi ya SPF kwa domain mpya**. Ikiwa hujui SPF record ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza sera yako ya SPF (tumia anwani ya IP ya mashine ya VPS)

![](<../../images/image (1037).png>)

Huu ndio yaliyomo ambayo yanapaswa kuwekwa ndani ya rekodi ya TXT ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya DMARC (Domain-based Message Authentication, Reporting & Conformance)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa haujui ni rekodi ya DMARC ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unahitaji kuunda rekodi mpya ya DNS TXT kwa hostname `_dmarc.<domain>` na yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa haujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mafunzo haya yanatokana na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo ufunguo wa DKIM unazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Pima alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua tu ukurasa na utume barua pepe kwa anuani watakayopewa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Pia unaweza **kuangalia usanidi wa barua pepe yako** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **fungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe ukiwa root).\
Hakikisha unapita mitihani yote:
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
Unaweza pia kutuma **ujumbe kwa akaunti ya Gmail unayodhibiti**, na kagua **vichwa vya barua pepe** katika kikasha chako cha Gmail; `dkim=pass` inapaswa kuwepo katika uwanja wa kichwa `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondolewa kutoka Spamhouse Blacklist

Tovuti [www.mail-tester.com](https://www.mail-tester.com) inaweza kukuonyesha kama domain yako inazuiliwa na Spamhouse. Unaweza kuomba domain/IP yako iondolewe kwa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kutoka Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kwa [https://sender.office.com/](https://sender.office.com).

## Tengeneza na Anzisha Kampeni ya GoPhish

### Profaili ya Kutuma

- Weka **jina la kutambulisha** la profaili ya mtumaji
- Amua kutoka akaunti gani utakayotumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password tupu, lakini hakikisha umechagua Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia kifaa cha "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Napendekeza **kutuma barua za mtihani kwa anwani za 10min mails** ili kuepuka kuorodheshwa kwenye blacklist wakati wa kufanya majaribio.

### Kiolezo la Barua Pepe

- Weka **jina la kutambulisha** la kiolezo
- Kisha andika **subject** (usichague kitu cha kushangaza, kitu ambacho ungeweza kutarajia kusoma katika barua pepe ya kawaida)
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
Kumbuka kwamba **ili kuongeza uhalali wa barua pepe**, inashauriwa kutumia saini kutoka kwa barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyokuwepo** na angalia ikiwa jibu lina saini yoyote.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com na watumie barua pepe kisha subiri jibu.
- Jaribu kuwasiliana na **barua pepe halali uliyoibua** na subiri jibu

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template pia inaruhusu **kuambatisha faili za kutuma**. Ikiwa ungependa pia kunyanga changamoto za NTLM kwa kutumia baadhi ya faili/nyaraka zilizotengenezwa mahsusi [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika code ya HTML** ya ukurasa wa wavuti. Kumbuka kwamba unaweza **ku-import** kurasa za wavuti.
- Chagua **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kawaida utahitaji kuhariri code ya HTML ya ukurasa na kufanya majaribio kwa local (labda ukitumia Apache server) **hadi utakapopenda matokeo.** Kisha, andika code ya HTML hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji kutumia **static resources** kwa HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuzihifadhi katika _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kupeleka watumiaji kwenye ukurasa halali mkuu** wa mtumiaji, au kuwaleta kwenye _/static/migration.html_ kwa mfano, weka **spinning wheel** (**[https://loading.io/](https://loading.io/)**) kwa sekunde 5 na kishaonyesha kwamba mchakato umefanikiwa.

### Users & Groups

- Weka jina
- **Import data** (kumbuka kwamba ili kutumia template kwa mfano unahitaji firstname, last name na email address ya kila mtumiaji)

![](<../../images/image (163).png>)

### Campaign

Mwisho, unda campaign ukichagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa waathiriwa

Kumbuka kwamba **Sending Profile inaruhusu kutuma email ya mtihani kuona jinsi barua pepe ya phishing itakavyotokea**:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma barua za mtihani kwa anwani za 10min mail** ili kuepuka kunyakuwa kwenye blacklists wakati wa majaribio.

Mara kila kitu kiko tayari, washa tu campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka clone tovuti angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma faili zenye aina fulani ya backdoor** (labda C2 au labda kitu kitakachochochea uthibitisho).\
Tazama ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni mnyoofu kwa kuwa unatengeneza tovuti ya uongo na kukusanya taarifa zilizowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuweka password sahihi au kama application uliyofake imewekwa na 2FA, **taarifa hizi hazitakuwezesha kumfanyia mtu kujifanya mtumiaji aliyedanganywa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zilivyo za manufaa. Zana hizi zitakuwezesha kuzalisha shambulio la MitM. Kimsingi, shambulio hufanya kazi kwa njia ifuatayo:

1. Unafikia fomu ya **login** ya ukurasa halisi.
2. Mtumiaji **anatuma** **credentials** zake kwenye ukurasa wako wa uongo na zana inazituma kwenye ukurasa halisi, ikithibitisha ikiwa **credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba 2FA na mara mtumiaji **akitolea** itatumwa kwenye ukurasa halisi.
4. Mara mtumiaji anapothibitishwa wewe (kama mwizi) utakuwa umeshapata **credentials, 2FA, cookie na taarifa zote** za kila mwingiliano wakati zana inavyoendesha MitM.

### Via VNC

Je, badala ya **kumpa mwathiri ukurasa wenye madhara** unaonekana kama asili, umpe vikao vya **VNC na browser iliyounganishwa kwenye ukurasa halisi**? Utaweza kuona anachofanya, kunyanga password, MFA iliyotumika, cookies...\
Unaweza kufanya hivi kwa kutumia [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Bila shaka mojawapo ya njia bora za kujua kama umegunduliwa ni **kutafuta domain yako ndani ya blacklists**. Ikiwa inaonekana imeorodheshwa, kwa namna fulani domain yako ilitambuliwa kama shaka.\
Njia rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mwathiriwa anaangalia kwa ufasaha shughuli za phishing zisizo za kawaida kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain lenye jina linalofanana sana** na domain ya mwathiriwa **na/au kutengeneza cheti** kwa **subdomain** ya domain unayodhibiti **iliyokuwa na** **neno muhimu** la domain ya mwathiriwa. Ikiwa **mwathiriwa** atafanya aina yoyote ya mwingiliano wa **DNS au HTTP** nao, utajua kwamba **anatafuta kwa uangalifu** kwa ajili ya domain zenye shaka na utahitaji kuwa sana mwangalifu.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious) kutathmini kama barua pepe yako itamalizika kwenye folda ya spam au itakomeshwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Sets za kuvamia za kisasa mara nyingi zinapuuza kabisa vishawishi kwa barua pepe na **hulenga moja kwa moja mchakato wa help-desk / identity-recovery** ili kushinda MFA. Shambulio ni "living-off-the-land" kabisa: mara operator akishapata credentials halali wanageuza kutumia zana za admin zilizojengwa ndani – hakuna malware inahitajika.

### Attack flow
1. Rekebisha mwathiriwa (Recon)
* Kukusanya maelezo ya kibinafsi & ya kibiashara kutoka LinkedIn, data breaches, GitHub ya umma, n.k.
* Tambua vitambulisho vya thamani kubwa (maafisa wakuu, IT, fedha) na elezea **mchakato halisi wa help-desk** kwa reset ya password / MFA.
2. Social engineering ya wakati-halisi
* Piga simu, tumia Teams au chat kwa help-desk huku ukijihusisha kama mhusika (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Wasilisha PII uliokusanya hapo awali ili kupitisha ukaguzi wa maarifa.
* Kushawishi agent kurekebisha **MFA secret** au kufanya **SIM-swap** kwa namba ya simu iliyosajiliwa.
3. Hatua za mara moja baada ya kupata ufikiaji (≤60 min kwa matukio halisi)
* Kuweka foothold kupitia portal yoyote ya web SSO.
* Orodhesha AD / AzureAD kwa kutumia zana zilizojengwa (hakuna binaries zinazopangwa):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Kusogea upande kwa upande kwa kutumia **WMI**, **PsExec**, au wakala halali wa **RMM** tayari waliowekwa kwenye whitelist ya mazingira.

### Detection & Mitigation
* Tibu urejeshaji wa utambulisho wa help-desk kama **operesheni iliyo na vigezo vya juu** – hitaji step-up auth & idhini ya meneja.
* Wezesha **Identity Threat Detection & Response (ITDR)** / **UEBA** rules zinazoangaza kuhusu:
* Mbinu ya MFA imebadilika + uthibitisho kutoka kifaa/geo kipya.
* Kuongezeka mara moja kwa nafasi ya mtumiaji huyo (user-→-admin).
* Rekodi simu za help-desk na lipa umuhimu wa **kamiliya kurudi kwa namba iliyosajiliwa** kabla ya kureset.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizorejeshwa hivi karibuni zisipokee moja kwa moja token za mamlaka ya juu.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Vikundi vya kawaida vinaondoa gharama za operesheni za high-touch kwa mashambulio makubwa yanayotumia **search engines & ad networks kama chaneli ya kusambaza**.

1. **SEO poisoning / malvertising** husukuma matokeo ya uongo kama `chromium-update[.]site` juu ya matangazo ya utafutaji.
2. Mwathiriwa hushusha kidogo **first-stage loader** (mara nyingi JS/HTA/ISO). Mifano iliyoshuhudiwa na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader huondoa cookies za browser + DB za credentials, kisha huvuta **silent loader** ambayo inaamua – *kwa muda halisi* – iwape au la:
* RAT (mfano AsyncRAT, RustDesk)
* ransomware / wiper
* sehemu ya persistence (Run key ya registry + scheduled task)

### Hardening tips
* Zuia domain zinazosajiliwa hivi karibuni & tekereza **Advanced DNS / URL Filtering** kwa *search-ads* pamoja na barua pepe.
* Zuia ufungaji wa programu isipokuwa MSI zilizotiwa saini / packages za Store, kataa utekelezaji wa `HTA`, `ISO`, `VBS` kwa sera.
* Wazimwe kwa kufuatilia mchakato wa mtoto unaofungua installers kutoka kwa browsers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chunguza LOLBins zinazotumiwa mara kwa mara na first-stage loaders (mfano `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Watendaji sasa wanachain LLM & voice-clone APIs kwa vishawishi vilivyobinafsishwa kabisa na mwingiliano wa wakati-halisi.

| Layer | Mfano wa matumizi na mtendaji wa tishio |
|-------|------------------------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoonyesha ujumbe uliotumwa na automation isiyokubalika (kwa ARC/DKIM anomalies).  
• Tekeleza **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.  
• Endelea kuiga vishawishi vilivyotengenezwa na AI katika programu za uelewa – templates za static zimetoweka.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya kawaida, operator wanaweza tu **kulazimisha usajili mpya wa MFA** wakati wa simu ya help-desk, ikifuta token iliyokuwapo ya mtumiaji. Kumbukumbu yoyote ya kuingia inayofuata inaonekana halali kwa mwathiriwa.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** yanatokea **ndani ya dakika kutoka kwa IP ile ile**.



## Clipboard Hijacking / Pastejacking

Wavamizi wanaweza kunakili kimya kimya amri zenye madhara kwenye clipboard ya mhanga kutoka kwenye ukurasa wa wavuti uliovamiwa au typosquatted na kisha kumdanganya mtumiaji kubandika ndani ya **Win + R**, **Win + X** au dirisha la terminal, na kutekeleza msimbo yoyote bila kupakua au kiambatisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji wanazuia zaidi phishing flows zao nyuma ya ukaguzi rahisi wa kifaa ili crawlers za desktop zisifike kwenye kurasa za mwisho. Mfano wa kawaida ni script ndogo inayojaribu touch-capable DOM na kutuma matokeo kwa server endpoint; wateja wasiokuwa mobile wanapokea HTTP 500 (au ukurasa tupu), wakati watumiaji wa mobile wanatumikishwa flow kamili.

Kipande kifupi cha client (mantiki ya kawaida):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantiki (iliyorahisishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- Huweka session cookie during the first load.
- Inakubali `POST /detect {"is_mobile":true|false}`.
- Inarudisha 500 (au placeholder) kwa subsequent GETs wakati `is_mobile=false`; hutoa phishing tu ikiwa `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mlolongo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non‑mobile; legitimate mobile waathiriwa paths hurudisha 200 na follow‑on HTML/JS.
- Zuia au chunguza kwa undani kurasa zinazotegemea maudhui kwa ujumla kwenye `ontouchstart` au device checks zinazofanana.

Defence tips:
- Endesha crawlers zenye mobile‑like fingerprints na JS imewezeshwa ili kufichua gated content.
- Toa tahadhari juu ya majibu ya 500 yenye shaka yanayotokea baada ya `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## Marejeo

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
