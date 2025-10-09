# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

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

- **Keyword**: Jina la domain linajumuisha neno muhimu la domain ya asili (mfano, zelster.com-management.com).
- **hypened subdomain**: Badilisha **dot kwa hyphen** katika subdomain (mfano, www-zelster.com).
- **New TLD**: Tumia domain ile ile lakini na **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: Inabadilisha herufi katika jina la domain kwa **herufi zinazofanana kwa muonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Inabadilisha **nchi mbili za herufi** ndani ya jina la domain (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa jina la domain (mfano, zeltsers.com).
- **Omission**: Inaondoa moja ya herufi kutoka jina la domain (mfano, zelser.com).
- **Repetition:** Inarudia moja ya herufi kwenye jina la domain (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini isiyo ya kimkakati. Inabadilisha moja ya herufi kwenye jina la domain, labda kwa herufi iliyo karibu kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Weka **dot** ndani ya jina la domain (mfano, ze.lster.com).
- **Insertion**: Inaingiza herufi ndani ya jina la domain (mfano, zerltser.com).
- **Missing dot**: Ambatisha TLD kwenye jina la domain. (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazosafirishwa zinaweza kugeuka moja kwa moja kutokana na sababu mbalimbali kama solar flares, cosmic rays, au hitilafu za hardware.

Wakati dhana hii inatumika kwa maombi ya DNS, inawezekana kwamba domain iliyopokelewa na server ya DNS sio ile ile iliyombwa awali.

Kwa mfano, mabadiliko ya bit moja katika domain "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Attackers wanaweza **kuitumia hali hii kwa kusajili multiple bit-flipping domains** zinazofanana na domain ya mjeruhi. Kusudi lao ni kupitisha watumiaji halali kwa infrastructure yao.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyokwisha kuisha ambayo unaweza kununua.\
Ili kuhakikisha kuwa expired domain utakayenunua **inamiliki SEO nzuri** tayari unaweza kuangalia jinsi ilivyoainishwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **discover more** valid email addresses au **verify the ones** tayari umevumbua unaweza kuangalia kama unaweza brute-force smtp servers za mjeruhi. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia **any web portal to access their mails**, unaweza kuangalia kama iko vulnerable kwa **username brute force**, na kufungua mdudu huo ikiwa inawezekana.

## Configuring GoPhish

### Ufungaji

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Utapewa password ya user admin kwenye port 3333 kwenye output. Kwa hiyo, pata access kwenye port hiyo na tumia credentials hizo kubadilisha password ya admin. Huenda ukahitaji ku-tunnel port hiyo kwa local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii unapaswa kuwa **tayari umenunua kikoa** utakachotumia na lazima **kimeelekezwa** kwa **IP ya VPS** ambapo unasanidi **gophish**.
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

Anza kusakinisha: `apt-get install postfix`

Kisha ongeza jina la kikoa kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwisho badilisha faili **`/etc/hostname`** na **`/etc/mailname`** kwa jina la kikoa chako na anzisha upya VPS yako.

Sasa, tengeneza rekodi ya **DNS A record** ya `mail.<domain>` ikielekeza kwa **anwani ya IP** ya VPS na rekodi ya **DNS MX** ikielekeza `mail.<domain>`

Sasa tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa Gophish na tufanye usanidi wake.\
Badilisha `/opt/gophish/config.json` kuwa ifuatayo (tazama matumizi ya https):
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
**Sanidi gophish service**

Ili kuunda gophish service ili iweze kuanzishwa kiotomatiki na kusimamiwa kama service, unaweza kuunda faili `/etc/init.d/gophish` yenye yaliyomo yafuatayo:
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
## Kusanidi server ya barua na domain

### Subiri & kuwa halali

Kadiri domain inavyozeeka, ndivyo uwezekano wake wa kushikiliwa kama spam unavyopungua. Kwa hivyo unapaswa kusubiri muda mwingi iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, ikiwa utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa utakazopata itakuwa bora.

Kumbuka kwamba hata kama unapaswa kusubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kwa jina la domain.

### Rekodi ya Sender Policy Framework (SPF)

Unapaswa **kusanidi rekodi ya SPF kwa domain mpya**. Ikiwa haujui SPF ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza sera yako ya SPF (tumia anwani ya IP ya mashine ya VPS)

![](<../../images/image (1037).png>)

Hii ndiyo yaliyomo yanayotakiwa kuwekwa ndani ya rekodi ya TXT katika domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Uthibitishaji wa Ujumbe Unaotegemea Domain, Kuripoti & Utii (DMARC)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa hujui rekodi ya DMARC ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unapaswa kuunda rekodi mpya ya DNS TXT inayolenga jina la mwenyeji `_dmarc.<domain>` na maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa haujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo DKIM key inazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Pima alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Ingia tu kwenye ukurasa na utume barua pepe kwa anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kagua usanidi wa barua pepe yako** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakikisha kwamba unapitisha mitihani yote:
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
Unaweza pia kutuma **ujumbe kwa Gmail unayodhibiti**, na kuangalia **email’s headers** kwenye inbox yako ya Gmail, `dkim=pass` inapaswa kuwepo katika `Authentication-Results` header field.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondoa kutoka Spamhouse Blacklist

Tovuti [www.mail-tester.com](https://www.mail-tester.com) inaweza kukuonyesha ikiwa domain yako inazuiawa na Spamhouse. Unaweza kuomba domain/IP yako iondolewe kwenye: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kutoka Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kwenye [https://sender.office.com/](https://sender.office.com).

## Unda & Anzisha Kampeni ya GoPhish

### Profaili ya Kutuma

- Weka baadhi ya **jina la kutambua** profaili ya mtumaji
- Amua kutoka akaunti gani utatumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha jina la mtumiaji na nenosiri tupu, lakini hakikisha umeweka alama kwenye Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inashauriwa kutumia kipengee cha "**Send Test Email**" kujaribu kwamba kila kitu kinafanya kazi.\
> Ningependekeza **kutuma barua za mtihani kwa anwani za 10min mails** ili kuepuka kuingia kwenye blacklist wakati wa kufanya majaribio.

### Templeti ya Barua Pepe

- Weka baadhi ya **jina la kutambua** templeti
- Kisha andika **subject** (si kitu cha kushangaza, tu kitu ungetarajia kusoma katika barua pepe ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **email template** (unaweza kutumia vigezo kama katika mfano ufuatao):
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
Kumbuka kwamba **ili kuongeza uhalali wa barua pepe**, inapendekezwa kutumia baadhi ya sahihi (signature) kutoka kwa barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyopo** na angalia kama jibu lina sahihi yoyote.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com na utumie barua pepe na subiri jibu.
- Jaribu kuwasiliana na **barua pepe halali ulizogundua** na subiri jibu

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika HTML code** ya ukurasa wa wavuti. Kumbuka unaweza **kuingiza** kurasa za wavuti.
- Chagua **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kubadilisha HTML ya ukurasa na kufanya majaribio pale kwa mtaa (labda ukitumia server ya Apache) **hadi utakapofurahia matokeo.** Kisha, andika HTML hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia rasilimali zisizo za mabadiliko** kwa HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuzihifadhi katika _**/opt/gophish/static/endpoint**_ kisha uzifikishe kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa ajili ya redirection unaweza **kupeleka watumiaji kwenye ukurasa mkuu halali** wa mwathiri, au kuwarudisha kwa _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kishaonyesha kwamba mchakato ulifanikiwa**.

### Users & Groups

- Weka jina
- **Import the data** (kumbuka kwamba ili kutumia template kwa mfano utahitaji firstname, last name na email address ya kila mtumiaji)

![](<../../images/image (163).png>)

### Campaign

Mwishowe, unda campaign ukichagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa link itakayotumwa kwa waathiriwa

Kumbuka kwamba **Sending Profile** inaruhusu kutuma barua pepe ya mtihani kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma barua pepe za mtihani kwa anwani za 10min mails** ili kuepuka kusukwa kwenye blacklist wakati wa kufanya majaribio.

Mara kila kitu kiko tayari, anzisha tu campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka kunakili tovuti angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma faili zenye aina fulani ya backdoor** (labda C2 au labda kitu ambacho kitachochea uthibitisho).\
Tazama ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni janja kwa kuwa unalifanya kuwa tovuti halisi na kukusanya taarifa zilizopakiwa na mtumiaji. Kwa bahati mbaya, kama mtumiaji hakuweka nenosiri sahihi au ikiwa application uliyofanyia fake imewekwa na 2FA, **taarifa hizi hazitatumika kukufanya ujifikirie kama mtumiaji aliyepigwa wizi**.

Hapa ndio ambapo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinakuwa muhimu. Zana hizi zitakuwezesha kuanzisha shambulio la MitM. Kwa msingi, shambulio linafanya hivi:

1. Unafanya **impersonate** fomu ya login ya ukurasa halisi.
2. Mtumiaji **anatuma** **credentials** zake kwenye ukurasa wako bandia na zana inazituma kwa ukurasa halisi, **kukagua kama credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba hiyo na mara **mtumiaji anapoiingiza** zana itaipeleka kwenye ukurasa halisi.
4. Mara mtumiaji akithibitishwa wewe (kama mshambuliaji) utakuwa umekamata **credentials, 2FA, cookie na taarifa yoyote** ya kila mwingiliano wakati zana inafanya MitM.

### Via VNC

Je, vipi ikiwa badala ya **kumpeleka mhusika kwenye ukurasa wa ulaghai** unaoonekana kama asili, unampeleka kwenye **vituo vya VNC na browser iliyounganika kwenye ukurasa halisi**? Utaweza kuona anachofanya, kuiba nenosiri, MFA iliyotumika, cookies...\
Unaweza kufanya hili na [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Kwa wazi mojawapo ya njia bora za kujua kama umegunduliwa ni **kutafuta domain yako ndani ya blacklists**. Ikiwa inaonekana kwenye orodha, kwa namna fulani domain yako ilitambuliwa kama ya kutiliwa shaka.\
Njia rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mhusika **anatafuta kwa umakini shughuli za phishing zinazoshukiwa** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathiri **na/au kuunda certificate** kwa **subdomain** ya domain inayodhibitiwa na wewe **inayoambatanisha** **keyword** ya domain ya mwathiri. Ikiwa **mwathiri** atafanya aina yoyote ya **DNS au HTTP interaction** nayo, utajua kwamba **yeye anaangalia kwa makini** kwa ajili ya domains zinazoshukiwa na utahitaji kuwa sana mnyonge.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kuangalia kama barua pepe yako itamalizika katikati ya folda ya spam au ikiwa itazuiliwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Seti za uvamizi za kisasa mara nyingi zinapita uhamasishaji wa barua pepe kabisa na **kuwakwabua moja kwa moja utaratibu wa service-desk / identity-recovery** ili kuvunja MFA. Shambulio hutegemea kabisa "living-off-the-land": mara operator anapokuwa na credentials halali wanabadilisha kwa zana za admin zilizo ndani – hakuna malware inayohitajika.

### Attack flow
1. Recon kwa mhusika
* Kukusanya maelezo binafsi & ya kampuni kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua vitambulisho vyenye thamani kubwa (wakuu, IT, fedha) na orodhesha **mchakato wa help-desk** kwa usahihi kwa ajili ya reset ya password / MFA.
2. Social engineering ya wakati-halisi
* Simu, Teams au chat help-desk huku ukijifanya kuwa mhusika (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupita ukaguzi wa maarifa.
* Mshawishi agent afanye **reset ya MFA secret** au kufanya **SIM-swap** kwa namba ya simu iliyosajiliwa.
3. Hatua za mara moja baada ya kupata ufikiaji (≤60 min kwa matukio halisi)
* Tumia njia ya msingi kupitia web SSO portal yoyote kuanzisha foothold.
* Ordo AD / AzureAD kwa zana zilizojengwa (bila kupeleka binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mwendo wa pande (lateral movement) kwa **WMI**, **PsExec**, au wakala halali wa **RMM** tayari waliowekwa kwenye whitelist ya mazingira.

### Detection & Mitigation
* Tibu identity recovery ya help-desk kama **operesheni yenye vibali** – hitaji step-up auth & approval ya manager.
* Tengeneza kanuni za **Identity Threat Detection & Response (ITDR)** / **UEBA** ambazo zinaonya juu ya:
* Mbinu ya MFA imebadilishwa + uthibitisho kutoka kifaa kipya / geo.
* Kuinuka mara moja kwa mcheleweshaji uleule (user-→-admin).
* Rekodi simu za help-desk na uweke kanuni ya **call-back kwenye namba iliyosajiliwa kabla** ya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizorejeshwa hivi karibuni **zisizopata** moja kwa moja token za hali ya juu.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Mafungu ya kawaida yanagharamia gharama za operesheni za high-touch kwa mashambulizi ya wingi yanayofanya **search engines & ad networks kuwa chaneli ya utoaji**.

1. **SEO poisoning / malvertising** inasukuma matokeo bandia kama `chromium-update[.]site` juu ya matangazo ya utafutaji.
2. Mwathiriwa anapakua loader ndogo ya **first-stage** (mara nyingi JS/HTA/ISO). Mifano iliyoshuhudiwa na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader huondoa cookies za browser + credential DBs, kisha huvuta **silent loader** ambayo inaamua – *kwa wakati-halisi* – kama itapeleka:
* RAT (mf. AsyncRAT, RustDesk)
* ransomware / wiper
* sehemu ya persistence (registry Run key + scheduled task)

### Hardening tips
* Zuia domains zilizosajiliwa hivi karibuni & fanya utekelezaji wa **Advanced DNS / URL Filtering** kwa *search-ads* pamoja na barua pepe.
* Zuia usakinishaji wa software isipokuwa MSI / Store zilizosainiwa, ukatae utekelezaji wa `HTA`, `ISO`, `VBS` kwa sera.
* Sibiti kwa mfuatiliaji mchakato watoto wa browsers waliopenisha installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumika mara kwa mara na first-stage loaders (mf. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Wavamizi sasa wanachanganua **LLM & voice-clone APIs** kwa lures zilizobinafsishwa kabisa na mwingiliano wa wakati-halisi.

| Layer | Mfano wa matumizi na mtendaji wa tishio |
|-------|-----------------------------|
|Automation|Tengeneza & tuma >100k emails / SMS zenye maneno yaliyobadilishwa & viungo vya tracking.|
|Generative AI|Zalisha barua pepe za *one-off* zikirejea M&A za umma, vichekesho vya ndani kutoka social media; sauti bandia ya CEO kwenye simu ya udanganyifu.|
|Agentic AI|Jisajili mwenyewe domains, scrape intel ya open-source, unda barua za hatua inayofuata wakati mwathiriwa anabonyeza lakini hakutuma creds.|

**Defence:**
• Ongeza **bango zinazoibuka** zinazoonyesha ujumbe ulioletwa na automation isiyo ya kuaminika (kutokana na ARC/DKIM anomalies).  
• Tumia **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.  
• Endelea kufanya majaribio ya lures zilizotengenezwa na AI katika programu za uelimishaji – templates za static hazifai tena.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya jadi, operator kwa urahisi **wanafanya rejista mpya ya MFA** wakati wa simu ya help-desk, kuharibu token iliyokuwepo ya mtumiaji. Kila ombi la kuingia linalofuata linaonekana halali kwa mhusika.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** yanatokea **ndani ya dakika chache kutoka kwenye IP ileile**.



## Clipboard Hijacking / Pastejacking

Wavamizi wanaweza kunakili kimya kimya maagizo ya kukera kwenye clipboard ya mwathirika kutoka kwenye ukurasa wa wavuti uliobambikiwa au typosquatted, kisha kumdanganya mtumiaji kuyabandika ndani ya **Win + R**, **Win + X** au terminal window, na hivyo kuendesha code yoyote bila kupakua au kutumia attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji wanaziba mtiririko wao wa phishing nyuma ya ukaguzi rahisi wa kifaa ili crawlers za desktop zisifike kwenye kurasa za mwisho. Mfano wa kawaida ni script ndogo inayotesta ikiwa DOM ina uwezo wa touch na kutuma matokeo kwa server endpoint; clients zisizo za mobile hupokea HTTP 500 (au ukurasa tupu), wakati watumiaji wa mobile wanapewa mtiririko kamili.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantiki (imefupishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Mienendo ya server inayoshuhudiwa mara nyingi:
- Huweka session cookie wakati wa mzigo wa kwanza.
- Accepts `POST /detect {"is_mobile":true|false}`.
- Inarudisha 500 (au placeholder) kwa GETs zinazofuata wakati `is_mobile=false`; inahudumia phishing tu ikiwa `true`.

Uwindaji na kanuni za utambuzi:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Telemetry ya Web: mfululizo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non‑mobile; njia halali za mobile victim hurudisha 200 pamoja na HTML/JS za kuendelea.
- Zuia au chunguza kwa makini kurasa zinazotegemea yaliyomo pekee kwa `ontouchstart` au ukaguzi wa kifaa kama hicho.

Vidokezo vya ulinzi:
- Endesha crawlers zenye mobile‑like fingerprints na JS imewezeshwa ili kufichua gated content.
- Toa tahadhari juu ya majibu 500 yenye shaka yanayotokea baada ya `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
