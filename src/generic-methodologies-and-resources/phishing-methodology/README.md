# Mbinu za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Fanya Recon kwa mwathirika
1. Chagua the **victim domain**.
2. Fanya uchambuzi wa msingi wa wavuti **searching for login portals** zinazotumika na mwathirika na **decide** ni ipi utakayoi **impersonate**.
3. Tumia **OSINT** kutafuta **emails**.
2. Andaa mazingira
1. **Buy the domain** utakao tumia kwa tathmini ya phishing
2. **Configure the email service** rekodi zinazohusiana (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS na **gophish**
3. Andaa kampeni
1. Andaa **email template**
2. Andaa **web page** ili kuiba credentials
4. Anzisha kampeni!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Jina la domain **linajumuisha** keyword muhimu la domain asili (e.g., zelster.com-management.com).
- **hypened subdomain**: Badilisha **dot kwa hyphen** kwenye subdomain (e.g., www-zelster.com).
- **New TLD**: Domain ile ile ikitumia **TLD mpya** (e.g., zelster.org)
- **Homoglyph**: Inabadilisha herufi kwenye jina la domain kwa herufi ambazo zinaonekana sawa (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Inabadilisha herufi mbili ndani ya jina la domain (e.g., zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa "s" mwishoni mwa jina la domain (e.g., zeltsers.com).
- **Omission**: Inafuta moja ya herufi kwenye jina la domain (e.g., zelser.com).
- **Repetition:** Inarudia moja ya herufi kwenye jina la domain (e.g., zeltsser.com).
- **Replacement**: Kama homoglyph lakini si stealthy sana. Inabadilisha moja ya herufi, labda kwa herufi iliyo karibu kwenye keyboard (e.g., zektser.com).
- **Subdomained**: Ingiza **dot** ndani ya jina la domain (e.g., ze.lster.com).
- **Insertion**: Inaingiza herufi ndani ya jina la domain (e.g., zerltser.com).
- **Missing dot**: Ambatanisha TLD kwenye jina la domain. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazosafirishwa zinaweza kubadilika moja kwa moja (kukafurika) kutokana na mambo mbalimbali kama solar flares, cosmic rays, au hitilafu za hardware.

Unapoleta dhana hii kwenye maombi ya DNS, inawezekana kwamba domain iliyopewa kwa server ya DNS sio ile ile iliyokuwa imetakiwa awali.

Kwa mfano, mabadiliko ya bit moja katika domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Wavamizi wanaweza kutumia hili kwa kujiandikisha kwa multiple bit-flipping domains zinazofanana na domain ya mwathirika. Nia yao ni kupanua trafiki halali kwa miundombinu yao wenyewe.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyokwisha kuisha ambayo unaweza kununua.\
Ili kuhakikisha kwamba domain iliyokwisha kuisha unayonyakua **ina SEO nzuri** tayari unaweza kuangalia jinsi ilivyoainishwa kwenye:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **gundua zaidi** anwani halali za barua pepe au **thibitisha zile** ulizogundua tayari unaweza kujaribu ku-brute-force kwenye smtp servers za mwathirika. [Soma jinsi ya kuverify/gundua anwani za barua pepe hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia **web portal yoyote kufikia mail zao**, unaweza kuangalia kama iko hatarini kwa **username brute force**, na kuitumia ikiwa inawezekana.

## Kusanidi GoPhish

### Usakinishaji

Unaweza kui-download kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na ifungua (decompress) ndani ya `/opt/gophish` na endesha `/opt/gophish/gophish`\
Utapewa password kwa user wa admin kwenye port 3333 katika output. Kwa hivyo, ingia kwenye port hiyo na tumia credentials hizo kubadilisha password ya admin. Inawezekana utahitaji kutunnel port hiyo kwa local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii unapaswa kuwa **tayari umenunua domain** utakayotumia, na inapaswa kuwa **imeelekezwa** kwa **IP ya VPS** ambapo unasanidi **gophish**.
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

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwisho fanya mabadiliko kwenye faili **`/etc/hostname`** na **`/etc/mailname`** kwenda jina la domain yako na **anzisha upya VPS yako.**

Sasa, tengeneza **rekodi ya DNS A** ya `mail.<domain>` ikielekeza kwa **anwani ya IP** ya VPS na **rekodi ya DNS MX** ikielekeza kwa `mail.<domain>`

Sasa tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tufanye usanidi wake.\
Badilisha `/opt/gophish/config.json` kwa ifuatayo (zingatia matumizi ya https):
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

Ili kuunda huduma ya gophish ili iweze kuanzishwa kiotomatiki na kusimamiwa kama huduma, unaweza kuunda faili `/etc/init.d/gophish` yenye yaliyomo yafuatayo:
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
Maliza kusanidi service na kuangalia inafanya:
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

Kadri domain inavyokuwa ya zamani zaidi, ndivyo ina uwezekano mdogo zaidi kuonekana kama spam. Kwa hivyo unapaswa kusubiri muda mwingi iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, ikiwa utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa utakazopata zitakuwa bora.

Kumbuka kwamba hata kama unapaswa kusubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi Reverse DNS (rDNS) record

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kwa jina la domain.

### Sender Policy Framework (SPF) Record

Lazima **usanidi rekodi ya SPF kwa domain mpya**. Ikiwa hujui rekodi ya SPF ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuendeleza sera yako ya SPF (tumia IP ya mashine ya VPS)

![](<../../images/image (1037).png>)

Hii ni yaliyomo yanayopaswa kuwekwa ndani ya rekodi ya TXT ndani ya domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Uthibitishaji wa Ujumbe Unaotegemea Domain, Ripoti & Ulinganifu (DMARC)

Unapaswa **kusanidi rekodi ya DMARC kwa domain mpya**. Ikiwa haujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unapaswa kuunda rekodi mpya ya DNS ya aina TXT inayolenga hostname `_dmarc.<domain>` yenye yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui ni rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo DKIM key inazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fungua ukurasa na utume barua pepe kwenda anwani wanayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kukagua usanidi wako wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
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
Unaweza pia kutuma **ujumbe kwa Gmail unayodhibiti**, na kukagua **vichwa vya barua pepe** kwenye kikasha chako cha Gmail; `dkim=pass` inapaswa kuwepo katika uwanja wa kichwa wa `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Kuondolewa kutoka Orodha Nyeusi ya Spamhouse

The page [www.mail-tester.com](https://www.mail-tester.com) inaweza kukuonyesha kama domain yako inazuizwa na spamhouse. Unaweza kuomba domain/IP yako iondolewe kwenye: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kutoka Orodha Nyeusi ya Microsoft

​​Unaweza kuomba domain/IP yako iondolewe kwenye [https://sender.office.com/](https://sender.office.com).

## Unda na Anzisha Kampeni ya GoPhish

### Profaili ya Kutuma

- Weka **jina la utambulisho** kwa profaili ya mtumaji
- Amua kutoka kwa akaunti gani utakayotumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password bila kujaza, lakini hakikisha umechagua Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inashauriwa kutumia utendaji wa "**Send Test Email**" ili kujaribu kuwa kila kitu kinafanya kazi.\
> Napendekeza **kutuma barua pepe za mtihani kwa anwani za 10min mails** ili kuepuka kuwekewa orodha nyeusi wakati wa majaribio.

### Kiolezo cha Barua Pepe

- Weka **jina la utambulisho** kwa kiolezo
- Kisha andika **subject** (hakuna kitu cha kushangaza, tu kitu unachoweza kutarajia kusoma katika barua pepe ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **kiolezo cha barua pepe** (unaweza kutumia vigezo kama katika mfano ufuatao):
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
Kumbuka kwamba **ili kuongeza uhalisia wa barua pepe**, inapendekezwa kutumia baadhi ya signature kutoka kwa barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anuani isiyokuwepo** na angalia kama majibu yana signature yoyote.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com na utumie barua pepe; subiri jibu.
- Jaribu kuwasiliana na **barua pepe halali uliyoibua** na usubiri jibu

![](<../../images/image (80).png>)

> [!TIP]
> Template ya Email pia inaruhusu **kuambatisha faili za kutuma**. Ikiwa ungependa pia kuiba challengi za NTLM kwa kutumia baadhi ya faili/nyaraka zilizotengenezwa mahsusi [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika msimbo wa HTML** wa ukurasa wa wavuti. Kumbuka unaweza **kuingiza** (import) kurasa za wavuti.
- Chekmark **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kawaida utahitaji kurekebisha msimbo wa HTML wa ukurasa na kufanya majaribio kwa kawaida (labda kwa kutumia Apache server) **mpaka utakapopendezwa na matokeo.** Kisha, andika msimbo huo wa HTML kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia rasilimali za static** kwa HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuzihifadhi katika _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa redirection unaweza **kupeleka watumiaji kwenye ukurasa halali wa mtendaji** wa mwathirika, au kuwaelekeza kwenye _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha onyesha kuwa mchakato ulifanikiwa**.

### Users & Groups

- Weka jina
- **Import data** (kumbuka ili kutumia template kwa mfano unahitaji firstname, last name na anwani ya barua pepe ya kila mtumiaji)

![](<../../images/image (163).png>)

### Campaign

Hatimaye, unda campaign kwa kuchagua jina, email template, landing page, URL, sending profile na group. Kumbuka URL itakuwa link itakayotumwa kwa wahanga

Kumbuka kwamba **Sending Profile inaruhusu kutuma email ya majaribio ili kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana**:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutumia anwani za 10min mail** kwa ajili ya kutuma majaribio ili kuepuka kuorodheshwa kama blacklisted wakati wa majaribio.

Mara kila kitu kitakapokuwa tayari, anzisha campaign!

## Website Cloning

Kama kwa sababu yoyote ungependa ku-clone tovuti angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma faili zenye aina fulani ya backdoor** (labda C2 au labda kitu kitakachochochea uthibitishaji).\
Angalia ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni la werevu kwani unadanganya kuwa ni tovuti halisi na kukusanya taarifa zilizowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuweka nywila sahihi au ikiwa programu uliyodanganya imewekwa na 2FA, **taarifa hizi hazitaturuhusu kujionyesha kama mtumiaji aliyepangiwa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapokuwa muhimu. Zana hizi zinawezesha shambulio la MitM. Kwa jumla, shambulio hufanya kazi kwa njia ifuatayo:

1. Unadanganya fomu ya **login** ya ukurasa halisi.
2. Mtumiaji **hutuma** **credentials** zake kwenye ukurasa wako bandia na zana inazituma kwa ukurasa halisi, **kukagua kama credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba hiyo na mara mtumiaji **ataingiza** itatumwa kwa ukurasa halisi.
4. Mara mtumiaji anapothibitishwa wewe (kama mshambulizi) utakuwa **umeshakamata credentials, 2FA, cookie na taarifa yoyote** ya kila mwingiliano wakati zana inafanya MitM.

### Via VNC

Je, badala ya **kumpeleka mwathirika kwenye ukurasa mbaya** uliofanana na ule wa asili, ukampeleke kwenye **vikao vya VNC na browser iliyounganishwa na ukurasa halisi**? Utakuwa na uwezo wa kuona anachofanya, kuiba nywila, MFA iliyotumika, cookies...\
Hii inaweza kufanywa kwa kutumia [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Bila shaka mojawapo ya njia bora za kujua kama umevamiwa ni **kutafuta domain yako ndani ya blacklists**. Ikiwa inaonekana imeorodheshwa, kwa namna fulani domain yako ilitambuliwa kuwa yenye shaka.\
Njia rahisi ya kuchunguza kama domain yako iko kwenye blacklist ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mwathirika **anatafuta kwa makusudi shughuli za phishing zenye shaka** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathirika **na/au kuunda cheti** kwa **subdomain** ya domain unayodhibiti **ikiwa na** **keyword** ya domain ya mwathirika. Ikiwa **mwathirika** atafanya aina yoyote ya mwingiliano wa **DNS au HTTP** nao, utajua kuwa **anatafuta kwa uangalifu** domain zenye shaka na utahitaji kuwa wa siri sana.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kuyaangalia ikiwa email yako itafikia folda ya spam au itakuwa imezuiwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Sets za uvamizi wa kisasa mara nyingi zinaacha kabisa vilaghai vya barua pepe na **kusonga moja kwa moja kwa mchakato wa service-desk / identity-recovery** ili kuondoa MFA. Shambulio linategemea rasilimali za mazingira pekee: mara operator anapopata credentials halali wanatumia zana za admin zilizopo – hakuna malware inahitajika.

### Attack flow
1. Recon kwa mwathirika
* Kunasa taarifa za kibinafsi & za kampuni kutoka LinkedIn, data breaches, GitHub ya umma, n.k.
* Tambua vitambulisho vya thamani (wakuu, IT, fedha) na orodha ya **mchakato kamili wa help-desk** kwa reset ya password / MFA.
2. Social engineering ya wakati-halisi
* Piga simu, tumia Teams au chat kwa help-desk ukijinakshi kama lengo (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita uthibitisho wa maarifa.
* Kumshawishi agent **kupanga upya siri ya MFA** au kufanya **SIM-swap** kwenye nambari ya simu iliyosajiliwa.
3. Vitendo vya mara moja baada ya kupata ufikiaji (≤60 min kwa matukio halisi)
* Weka mtego kupitia portal yoyote ya web SSO.
* Orodhesha AD / AzureAD ukitumia zana zilizopo (hakuna binaries zinazoangushwa):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Kusogea kwa ndani kwa kutumia **WMI**, **PsExec**, au ma-ajenti halali ya **RMM** tayari yaliyoorodheshwa kwenye mazingira.

### Detection & Mitigation
* Tibu identity recovery ya help-desk kama **operesheni yenye ruhusa za juu** – weka step-up auth & approval ya meneja.
* Tumia **Identity Threat Detection & Response (ITDR)** / **UEBA** sheria zinazoangazia:
* Mbadala wa njia ya MFA + uthibitisho kutoka kifaa kipya / geo.
* Kuongezeka mara moja kwa nafsi hiyo hiyo kwa hadhi (user-→-admin).
* Rekodi simu za help-desk na utekeleze **call-back kwa nambari tayari iliyosajiliwa** kabla ya kureset.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizoreset zisiweze kupata token zenye ruhusa za juu moja kwa moja.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Mafundi wa kawaida wanapunguza gharama za operesheni za high-touch kwa mashambulio ya umati yanayofanya **search engines & ad networks kuwa chaneli ya utoaji**.

1. **SEO poisoning / malvertising** inasukuma matokeo bandia kama `chromium-update[.]site` hadi sehemu ya juu ya matangazo ya utafutaji.
2. Mwathiri hupakua loader ndogo ya **first-stage** (mara nyingi JS/HTA/ISO). Mifano iliyoshuhudiwa:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader huondoa cookies za browser + credential DBs, kisha hupakua **silent loader** ambayo inaamua – *kwa wakati halisi* – kama itaweka:
* RAT (mfano AsyncRAT, RustDesk)
* ransomware / wiper
* kipengele cha persistence (registry Run key + scheduled task)

### Hardening tips
* Zuia domain mpya zilizojisajili na zuia kwa kutumia **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na barua pepe.
* Zuia ufungaji wa programu isipokuwa MSI / Store packages zilizosainiwa, kata utekelezaji wa `HTA`, `ISO`, `VBS` kwa sera.
* Endelea kufuatilia kwa ajili ya michakato tanzu za browsers zinazofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumika mara kwa mara na loaders wa first-stage (mfano `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Wadukuzi sasa wanachanganya **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kikamilifu na mwingiliano wa wakati-halisi.

| Layer | Mfano wa matumizi kwa mhalifu |
|-------|-----------------------------|
| Automation | Tengenea & tuma >100 k emails / SMS zenye maneno yaliyobadilishwa & links za tracking. |
| Generative AI | Tengenea barua pepe za *mojawapo* zikirejea M&A za umma, vicheko vya ndani kutoka social media; sauti ya deep-fake ya CEO katika udanganyifu wa callback. |
| Agentic AI | Sajili domaines, chuma intel ya chanzo wazi, tengenea barua za hatua inayofuata wakati mwathirika atabofya lakini hatetumi credentials kwa njia ya kujitegemea. |

**Defence:**
• Ongeza **banners zinazobadilika** zinazoonyesha ujumbe ulioletwa na automation isiyotegemewa (kutokana na anomalies za ARC/DKIM).
• Tekeleza **voice-biometric challenge phrases** kwa maombi ya hatari kubwa ya simu.
• Endelea kuiga lures zilizotengenezwa na AI katika mipango ya uelewa – templates za jadi hazitatosha.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya jadi, waendeshaji kwa urahisi **huwalazimisha usanidi mpya wa MFA** wakati wa simu ya help-desk, kuharibu token iliyokuwepo ya mtumiaji. Utaulizi unaofuata wa kuingia unaonekana halali kwa mwathirika.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

Wavamizi wanaweza kimya kimya kunakili amri hatarishi ndani ya clipboard ya mwathirika kutoka kwenye ukurasa wa wavuti uliovamiwa au typosquatted, kisha kumdanganya mtumiaji kuzipaste ndani ya **Win + R**, **Win + X** au dirisha la terminal, na kutekeleza arbitrary code bila kupakua au kiambatisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators mara nyingi huzuia phishing flows zao nyuma ya ukaguzi rahisi wa kifaa ili desktop crawlers wasifike kwenye kurasa za mwisho. Mfano wa kawaida ni script ndogo inayotest DOM inayoweza kugusa na kutuma matokeo kwa server endpoint; non‑mobile clients hupokea HTTP 500 (au ukurasa tupu), wakati mobile users wanatumiwa flow kamili.

Client snippet mfupi (mantiki ya kawaida):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantiki (imefupishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- Huiweka session cookie wakati wa mara ya kwanza.
- Accepts `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GETs zinazofuata wakati `is_mobile=false`; huwasilisha phishing tu ikiwa `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: mfululizo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non‑mobile; njia halali za waathiriwa wa mobile hurudisha 200 na HTML/JS inayofuata.
- Zuia au chunguza kwa undani kurasa zinazoweka maudhui kwa kipekee kwenye `ontouchstart` au ukaguzi wa kifaa kama huo.

Defence tips:
- Endesha crawlers zenye fingerprints zinazofanana na za mobile na JS imewezeshwa ili kufichua gated content.
- Tuma tahadhari juu ya majibu ya 500 yenye shaka kufuatia `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## Marejeo

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
