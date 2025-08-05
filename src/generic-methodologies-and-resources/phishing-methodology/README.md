# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Fanya utafiti kuhusu mwathirika
1. Chagua **domeni la mwathirika**.
2. Fanya utafiti wa msingi wa wavuti **ukitafuta milango ya kuingia** inayotumiwa na mwathirika na **amua** ni ipi utayejifanya kuwa.
3. Tumia **OSINT** ili **kupata barua pepe**.
2. Andaa mazingira
1. **Nunua domeni** ambayo utatumia kwa tathmini ya phishing
2. **Sanidi huduma ya barua pepe** inayohusiana na rekodi (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS na **gophish**
3. Andaa kampeni
1. Andaa **kigezo cha barua pepe**
2. Andaa **ukurasa wa wavuti** wa kuiba taarifa za kuingia
4. Anzisha kampeni!

## Tengeneza majina ya domeni yanayofanana au nunua domeni inayotegemewa

### Mbinu za Mabadiliko ya Jina la Domeni

- **Neno muhimu**: Jina la domeni **linajumuisha** neno muhimu la **domeni la asili** (mfano, zelster.com-management.com).
- **subdomain yenye hyphen**: Badilisha **nukta kuwa hyphen** ya subdomain (mfano, www-zelster.com).
- **TLD Mpya**: Domeni sawa ikitumia **TLD mpya** (mfano, zelster.org)
- **Homoglyph**: In **badilisha** herufi katika jina la domeni kwa **herufi zinazofanana** (mfano, zelfser.com).

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Mabadiliko:** In **badilisha herufi mbili** ndani ya jina la domeni (mfano, zelsetr.com).
- **Kuweka umoja/mingi**: Ongeza au ondolea “s” mwishoni mwa jina la domeni (mfano, zeltsers.com).
- **Kuondoa**: In **ondoa moja** ya herufi kutoka jina la domeni (mfano, zelser.com).
- **Kurudia:** In **rudia moja** ya herufi katika jina la domeni (mfano, zeltsser.com).
- **Kubadilisha**: Kama homoglyph lakini si wa siri sana. Inabadilisha moja ya herufi katika jina la domeni, labda kwa herufi iliyo karibu na herufi ya asili kwenye kibodi (mfano, zektser.com).
- **Subdomained**: Ingiza **nukta** ndani ya jina la domeni (mfano, ze.lster.com).
- **Kuingiza**: In **ingiza herufi** ndani ya jina la domeni (mfano, zerltser.com).
- **Nukta iliyokosekana**: Ongeza TLD kwenye jina la domeni. (mfano, zelstercom.com)

**Zana za Kiotomatiki**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Tovuti**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba moja ya baadhi ya bits zilizohifadhiwa au katika mawasiliano inaweza kubadilishwa kiotomatiki** kutokana na sababu mbalimbali kama vile miale ya jua, mionzi ya anga, au makosa ya vifaa.

Wakati dhana hii inatumika kwa maombi ya DNS, inawezekana kwamba **domeni iliyopokelewa na seva ya DNS** si sawa na domeni iliyotakiwa awali.

Kwa mfano, mabadiliko ya bit moja katika domeni "windows.com" yanaweza kuibadilisha kuwa "windnws.com."

Washambuliaji wanaweza **kunufaika na hili kwa kujiandikisha kwa domeni nyingi za bit-flipping** ambazo zinafanana na domeni ya mwathirika. Nia yao ni kuelekeza watumiaji halali kwenye miundombinu yao.

Kwa maelezo zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Nunua domeni inayotegemewa

Unaweza kutafuta katika [https://www.expireddomains.net/](https://www.expireddomains.net) kwa domeni iliyokwisha ambayo unaweza kutumia.\
Ili kuhakikisha kwamba domeni iliyokwisha unayokusudia kununua **ina SEO nzuri tayari** unaweza kutafuta jinsi inavyopangwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Barua Pepe

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% bure)
- [https://phonebook.cz/](https://phonebook.cz) (100% bure)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **gundua zaidi** anwani halali za barua pepe au **kuhakiki zile** ulizozigundua tayari unaweza kuangalia kama unaweza kujaribu nguvu kwenye seva za smtp za mwathirika. [Jifunze jinsi ya kuangalia/kugundua anwani ya barua pepe hapa](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia **milango yoyote ya wavuti kuingia kwenye barua zao**, unaweza kuangalia kama inahatarishwa kwa **kujaribu nguvu jina la mtumiaji**, na kutumia udhaifu huo ikiwa inawezekana.

## Sanidi GoPhish

### Usakinishaji

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na uondoe ndani ya `/opt/gophish` na uendeshe `/opt/gophish/gophish`\
Utapewa nenosiri kwa mtumiaji wa admin kwenye bandari 3333 katika matokeo. Hivyo, fikia bandari hiyo na tumia hizo taarifa kuhamasisha nenosiri la admin. Unaweza kuhitaji kupitisha bandari hiyo kwa eneo la ndani:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS certificate configuration**

Kabla ya hatua hii unapaswa kuwa **umeshanunua jina la kikoa** unalotaka kutumia na lazima liwe **linaanika** kwenye **IP ya VPS** ambapo unafanya usanidi wa **gophish**.
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

Anza kufunga: `apt-get install postfix`

Kisha ongeza kikoa kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Hatimaye, badilisha faili **`/etc/hostname`** na **`/etc/mailname`** kuwa jina la kikoa chako na **anzisha upya VPS yako.**

Sasa, tengeneza **rekodi ya DNS A** ya `mail.<domain>` ikielekeza kwenye **anwani ya ip** ya VPS na rekodi ya **DNS MX** ikielekeza kwa `mail.<domain>`

Sasa hebu jaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Mipangilio ya Gophish**

Acha utekelezaji wa gophish na hebu tuipange.\
Badilisha `/opt/gophish/config.json` kuwa ifuatayo (zingatia matumizi ya https):
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
Maliza kusanifisha huduma na kuangalia inavyofanya:
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
## Kuunda seva ya barua na kikoa

### Subiri & kuwa halali

Kadiri kikoa kilivyo na umri mrefu ndivyo inavyokuwa na uwezekano mdogo wa kukamatwa kama spam. Hivyo unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Aidha, ikiwa utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa iliyopatikana itakuwa bora.

Kumbuka kwamba hata kama unapaswa kusubiri wiki moja unaweza kumaliza kuunda kila kitu sasa.

### Sanidi Rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) inayotatua anwani ya IP ya VPS kwa jina la kikoa.

### Rekodi ya Sender Policy Framework (SPF)

Lazima **uunde rekodi ya SPF kwa kikoa kipya**. Ikiwa hujui ni nini rekodi ya SPF [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuunda sera yako ya SPF (tumia IP ya mashine ya VPS)

![](<../../images/image (1037).png>)

Hii ni maudhui ambayo yanapaswa kuwekwa ndani ya rekodi ya TXT ndani ya kikoa:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Lazima **uweke rekodi ya DMARC kwa jina jipya la kikoa**. Ikiwa hujui ni nini rekodi ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Lazima uunde rekodi mpya ya DNS TXT ikielekeza jina la mwenyeji `_dmarc.<domain>` yenye maudhui yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **uweke DKIM kwa jina jipya la kikoa**. Ikiwa hujui ni rekodi gani ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mafunzo haya yanategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo funguo za DKIM zinazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Fikia tu ukurasa huo na tuma barua pepe kwa anwani wanayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wako wa barua pepe** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **kufungua** bandari **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Angalia kwamba unapitisha majaribio yote:
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
Unaweza pia kutuma **ujumbe kwa Gmail chini ya udhibiti wako**, na kuangalia **vichwa vya barua pepe** katika kikasha chako cha Gmail, `dkim=pass` inapaswa kuwepo katika uwanja wa kichwa cha `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Kuondoa kutoka kwenye Orodha ya Spamhouse

Ukurasa [www.mail-tester.com](https://www.mail-tester.com) unaweza kuonyesha ikiwa jina lako la kikoa linazuiwa na spamhouse. Unaweza kuomba jina lako la kikoa/IP kuondolewa kwenye: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kutoka kwenye Orodha ya Microsoft

​​Unaweza kuomba jina lako la kikoa/IP kuondolewa kwenye [https://sender.office.com/](https://sender.office.com).

## Unda & Anzisha Kampeni ya GoPhish

### Profaili ya Kutuma

- Weka **jina la kutambulisha** profaili ya mtumaji
- Amua kutoka kwenye akaunti gani utaenda kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha jina la mtumiaji na nenosiri kuwa tupu, lakini hakikisha umeangalia Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inapendekezwa kutumia kazi ya "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Ningependekeza **kutuma barua pepe za majaribio kwa anwani za 10min mails** ili kuepuka kuorodheshwa kwenye orodha ya watu wasiotakikana wakati wa majaribio.

### Kiolezo cha Barua Pepe

- Weka **jina la kutambulisha** kiolezo
- Kisha andika **kichwa** (hakuna kitu cha ajabu, ni kitu ambacho unaweza kutarajia kusoma katika barua pepe ya kawaida)
- Hakikisha umeangalia "**Add Tracking Image**"
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
Kumbuka kwamba **ili kuongeza uaminifu wa barua pepe**, inashauriwa kutumia saini kutoka kwa barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyo na ukweli** na angalia ikiwa jibu lina saini yoyote.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com na uwatume barua pepe na subiri jibu.
- Jaribu kuwasiliana na **barua pepe halali zilizogunduliwa** na subiri jibu.

![](<../../images/image (80).png>)

> [!TIP]
> Template ya Barua Pepe pia inaruhusu **kuambatisha faili za kutuma**. Ikiwa ungependa pia kuiba changamoto za NTLM kwa kutumia faili/hati zilizoundwa kwa njia maalum [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Ukurasa wa Kutua

- Andika **jina**
- **Andika msimbo wa HTML** wa ukurasa wa wavuti. Kumbuka kwamba unaweza **kuagiza** kurasa za wavuti.
- Mark **Kamata Data Iliyowasilishwa** na **Kamata Nywila**
- Weka **mwelekeo**

![](<../../images/image (826).png>)

> [!TIP]
> Kawaida utahitaji kubadilisha msimbo wa HTML wa ukurasa na kufanya majaribio katika eneo la ndani (labda kwa kutumia seva ya Apache) **hadi upate matokeo unayopenda.** Kisha, andika msimbo huo wa HTML katika kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia rasilimali za kudumu** kwa HTML (labda kurasa za CSS na JS) unaweza kuziokoa katika _**/opt/gophish/static/endpoint**_ na kisha uzifikie kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa mwelekeo unaweza **kuwapeleka watumiaji kwenye ukurasa halali wa wavuti** wa mwathirika, au kuwapeleka kwenye _/static/migration.html_ kwa mfano, weka **wheel inayozunguka** ([**https://loading.io/**](https://loading.io)**) kwa sekunde 5 na kisha onyesha kwamba mchakato ulikuwa na mafanikio**.

### Watumiaji na Makundi

- Weka jina
- **Agiza data** (kumbuka kwamba ili kutumia template kwa mfano unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)

![](<../../images/image (163).png>)

### Kampeni

Hatimaye, tengeneza kampeni ukichagua jina, template ya barua pepe, ukurasa wa kutua, URL, wasifu wa kutuma na kundi. Kumbuka kwamba URL itakuwa kiungo kitakachotumwa kwa wahanga.

Kumbuka kwamba **Wasifu wa Kutuma unaruhusu kutuma barua pepe ya majaribio kuona jinsi barua pepe ya udukuzi itakavyokuwa**:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma barua pepe za majaribio kwa anwani za barua pepe za 10min** ili kuepuka kuorodheshwa kwenye orodha ya mblacklisted wakati wa majaribio.

Mara kila kitu kiko tayari, uzindue kampeni!

## K cloning wa Tovuti

Ikiwa kwa sababu yoyote unataka kunakili tovuti angalia ukurasa ufuatao:

{{#ref}}
clone-a-website.md
{{#endref}}

## Hati na Faili Zenye Backdoor

Katika tathmini za udukuzi (hasa kwa Timu za Red) utataka pia **kutuma faili zinazokuwa na aina fulani ya backdoor** (labda C2 au labda kitu ambacho kitachochea uthibitisho).\
Angalia ukurasa ufuatao kwa mifano:

{{#ref}}
phishing-documents.md
{{#endref}}

## Udukuzi wa MFA

### Kupitia Proxy MitM

Shambulio la awali ni la busara kwani unafanyia kazi tovuti halisi na kukusanya taarifa zilizowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuweka nywila sahihi au ikiwa programu uliyofanya kazi nayo imewekwa na 2FA, **habari hii haitakuruhusu kujifanya kuwa mtumiaji aliyejipatia hila**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinakuwa na manufaa. Zana hii itakuruhusu kuunda shambulio kama la MitM. Kimsingi, shambulio linafanya kazi kwa njia ifuatayo:

1. Unajifanya kuwa fomu ya kuingia ya ukurasa halisi wa wavuti.
2. Mtumiaji **anatumia** **taarifa zake** kwenye ukurasa wako wa uongo na zana hiyo inapeleka hizo kwenye ukurasa halisi wa wavuti, **ikikagua ikiwa taarifa hizo zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utauliza kwa hiyo na mara mtumiaji **anapoweka** hiyo zana itapeleka kwenye ukurasa halisi wa wavuti.
4. Mara mtumiaji anapothibitishwa wewe (kama mshambuliaji) utakuwa **umechukua taarifa, 2FA, cookie na taarifa yoyote** ya kila mwingiliano wako wakati zana hiyo inafanya MitM.

### Kupitia VNC

Je, ni vipi badala ya **kumpeleka mwathirika kwenye ukurasa mbaya** wenye muonekano sawa na wa asili, unampeleka kwenye **kikao cha VNC chenye kivinjari kilichounganishwa na ukurasa halisi wa wavuti**? Utaweza kuona anachofanya, kuiba nywila, MFA iliyotumika, cookies...\
Unaweza kufanya hivi na [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Kugundua kugundua

Kwa wazi moja ya njia bora za kujua ikiwa umekamatwa ni **kutafuta domain yako ndani ya orodha za mblacklisted**. Ikiwa inaonekana imeorodheshwa, kwa namna fulani domain yako iligunduliwa kama ya mashaka.\
Njia rahisi ya kuangalia ikiwa domain yako inaonekana katika orodha yoyote ya mblacklisted ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua ikiwa mwathirika **anatafuta kwa nguvu shughuli za udukuzi za mashaka katika mazingira** kama ilivyoelezwa katika:

{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathirika **na/au kuunda cheti** kwa **subdomain** ya domain inayodhibitiwa na wewe **ikiwemo** **neno muhimu** la domain ya mwathirika. Ikiwa **mwathirika** atafanya aina yoyote ya **DNS au mwingiliano wa HTTP** nao, utajua kwamba **anatafuta kwa nguvu** domain za mashaka na utahitaji kuwa na uangalifu mkubwa.

### Kadiria udukuzi

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kadiria ikiwa barua pepe yako itamalizika kwenye folda ya spam au ikiwa itazuiwa au kufanikiwa.

## Kuathiri Utambulisho wa Juu (Kusaidia-Desk MFA Reset)

Seti za uvamizi za kisasa zinaendelea kupuuza mtego wa barua pepe kabisa na **kuwalenga moja kwa moja huduma za desk / mchakato wa urejeleaji wa utambulisho** ili kushinda MFA. Shambulio hili linaishi "katika ardhi": mara tu opereta anapokuwa na taarifa halali anageuka na zana za usimamizi zilizojengwa - hakuna malware inahitajika.

### Mchakato wa Shambulio
1. Fanya utafiti wa mwathirika
* Kusanya maelezo ya kibinafsi na ya kampuni kutoka LinkedIn, uvujaji wa data, GitHub ya umma, nk.
* Tambua utambulisho wa thamani kubwa (wakurugenzi, IT, fedha) na orodhesha **mchakato halisi wa desk** wa kurekebisha nywila / MFA.
2. Uhandisi wa kijamii wa wakati halisi
* Simu, Teams au chat desk ya msaada huku ukijifanya kuwa lengo (mara nyingi kwa **ID ya mpiga simu iliyopotoshwa** au **sauti iliyokopwa**).
* Toa PII iliyokusanywa awali ili kupita uthibitisho wa maarifa.
* Mshawishi wakala kubadilisha **siri ya MFA** au kufanya **SIM-swap** kwenye nambari ya simu iliyosajiliwa.
3. Vitendo vya papo hapo baada ya ufikiaji (≤60 min katika kesi halisi)
* Kuanzisha mguu kupitia yoyote ya lango la SSO la wavuti.
* Orodhesha AD / AzureAD kwa kutumia zana zilizojengwa (hakuna binaries zilizotolewa):
```powershell
# orodhesha makundi ya saraka & majukumu yenye mamlaka
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – orodhesha majukumu ya saraka
Get-MgDirectoryRole | ft DisplayName,Id

# Orodhesha vifaa ambavyo akaunti inaweza kuingia
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Harakati za upande kwa kutumia **WMI**, **PsExec**, au wakala halali wa **RMM** ambao tayari umeorodheshwa katika mazingira.

### Kugundua na Kupunguza
* Treat desk ya msaada ya urejeleaji wa utambulisho kama **operesheni yenye mamlaka** – hitaji uthibitisho wa hatua na idhini ya meneja.
* Weka **Utambuzi wa Hatari ya Utambulisho na Majibu (ITDR)** / **UEBA** sheria zinazotoa taarifa juu ya:
* Njia ya MFA iliyobadilishwa + uthibitisho kutoka kwa kifaa kipya / geo.
* Kuinua mara moja kwa kanuni ile ile (mtumiaji-→-admin).
* Rekodi simu za desk ya msaada na kulazimisha **kurudi kwa nambari iliyosajiliwa tayari** kabla ya kurekebisha.
* Tekeleza **Just-In-Time (JIT) / Ufikiaji wa Mamlaka** ili akaunti mpya zilizorekebishwa **zisirithi** token za mamlaka ya juu moja kwa moja.

---

## Udanganyifu kwa Wingi – SEO Poisoning & Kampeni za “ClickFix”
Vikundi vya kawaida vinapunguza gharama za operesheni zenye uhusiano wa karibu kwa mashambulizi ya wingi yanayobadilisha **mashine za utafutaji na mitandao ya matangazo kuwa njia ya usambazaji**.

1. **SEO poisoning / malvertising** inasukuma matokeo ya uongo kama `chromium-update[.]site` hadi kwenye matangazo ya utafutaji ya juu.
2. Mwathirika anapakua **loader ya hatua ya kwanza** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyoonwa na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader inatoa cookies za kivinjari + DB za taarifa za kuingia, kisha inavuta **loader ya kimya** ambayo inamua – *katika wakati halisi* – ikiwa itapeleka:
* RAT (mfano AsyncRAT, RustDesk)
* ransomware / wiper
* kipengele cha kudumu (funguo za Run za rejista + kazi iliyopangwa)

### Vidokezo vya Kuimarisha
* Zuia majina mapya ya usajili na kulazimisha **Advanced DNS / URL Filtering** kwenye *matangazo ya utafutaji* pamoja na barua pepe.
* Punguza usakinishaji wa programu kwa pakiti za MSI / Duka zilizotiwa saini, kataza `HTA`, `ISO`, `VBS` kutekelezwa kwa sera.
* Fuata mchakato wa watoto wa kivinjari kufungua waandikaji:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumiwa mara kwa mara na loaders za hatua ya kwanza (mfano `regsvr32`, `curl`, `mshta`).

---

## Operesheni za Udukuzi Zenye AI
Wavamizi sasa wanashirikisha **LLM & voice-clone APIs** kwa mtego wa kibinafsi kabisa na mwingiliano wa wakati halisi.

| Tabaka | Matumizi ya mfano na mhusika wa tishio |
|-------|-----------------------------|
|Automatisering|Tengeneza na tuma >100 k barua pepe / SMS zikiwa na maneno yaliyobadilishwa na viungo vya kufuatilia.|
|Generative AI|Tengeneza *barua pepe za kipekee* zinazorejelea M&A za umma, vichekesho vya ndani kutoka mitandao ya kijamii; sauti ya CEO ya deep-fake katika udanganyifu wa kurudi.|
|Agentic AI|Kujiandikisha kwa uhuru majina ya domain, kuchora intel ya chanzo wazi, kuunda barua za hatua inayofuata wakati mwathirika anabonyeza lakini hajawasilisha taarifa.|

**Ulinzi:**
• Ongeza **banners za dynamic** zinazosisitiza ujumbe uliopelekwa kutoka kwa automatisering isiyoaminika (kupitia ARC/DKIM anomalies).
• Weka **maneno ya changamoto ya sauti-biometric** kwa maombi ya simu ya hatari.
• Endelea kuiga mtego wa AI ulioandaliwa katika programu za uelewa – templates za kudumu hazifai tena.

---

## Uchovu wa MFA / Push Bombing Variant – Reset ya Lazima
Mbali na push-bombing ya kawaida, waendeshaji kwa urahisi **wanalazimisha usajili mpya wa MFA** wakati wa simu ya desk ya msaada, wakifuta token ya mtumiaji iliyopo. Kila ombi la kuingia linalofuata linaonekana kuwa halali kwa mwathirika.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor kwa matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** zinatokea **ndani ya dakika kutoka kwa IP ile ile**.

## Clipboard Hijacking / Pastejacking

Wavamizi wanaweza kimya kimya kunakili amri mbaya kwenye clipboard ya mwathirika kutoka kwenye ukurasa wa wavuti ulioathiriwa au ulioandikwa vibaya na kisha kumdanganya mtumiaji kuziweka ndani ya **Win + R**, **Win + X** au dirisha la terminal, wakitekeleza msimbo wa kiholela bila kupakua au kiambatisho.

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
