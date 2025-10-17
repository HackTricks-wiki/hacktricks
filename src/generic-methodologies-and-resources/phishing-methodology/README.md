# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Mbinu

1. Recon the victim
1. Chagua the **victim domain**.
2. Fanya baadhi ya basic **web enumeration** kwa **searching for login portals** zinazotumiwa na victim na **decide** ni ipi utakayo **impersonate**.
3. Tumia baadhi ya **OSINT** ili **find emails**.
2. Tayarisha mazingira
1. **Buy the domain** utakayotumia kwa phishing assessment
2. **Configure the email service** rekodi zinazohusiana (SPF, DMARC, DKIM, rDNS)
3. Sanidi the VPS na **gophish**
3. Tayarisha campaign
1. Tayarisha the **email template**
2. Tayarisha the **web page** ili kuiba credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Badilisha the **dot for a hyphen** ya subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: Inabadilisha herufi ndani ya domain name na **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Inabadili nafasi za herufi mbili ndani ya domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Inaongeza au kuondoa “s” mwishoni mwa domain name (e.g., zeltsers.com).
- **Omission**: Inafuta moja ya herufi kutoka kwenye domain name (e.g., zelser.com).
- **Repetition:** Inarudia moja ya herufi kwenye domain name (e.g., zeltsser.com).
- **Replacement**: Kama homoglyph lakini si stealthy sana. Inabadilisha moja ya herufi kwenye domain name, labda kwa herufi inayokaribu kwenye keyboard (e.g, zektser.com).
- **Subdomained**: Ingiza **dot** ndani ya domain name (e.g., ze.lster.com).
- **Insertion**: Inaiingiza herufi ndani ya domain name (e.g., zerltser.com).
- **Missing dot**: Ambatisha TLD kwenye domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna uwezekano kwamba baadhi ya bits zilizohifadhiwa au zinazotumika katika mawasiliano zinaweza kugeuzwa kiotomatiki kutokana na vigezo mbalimbali kama solar flares, cosmic rays, au hardware errors.

Wakati wazo hili linapotumika kwa DNS requests, inawezekana kwamba domain iliyopokelewa na DNS server si ile ile iliyokuwa imetRequested awali.

Kwa mfano, urekebishaji wa single bit katika domain "windows.com" unaweza kuibadilisha kuwa "windnws.com."

Wavamizi wanaweza kuchukua faida ya hili kwa kujiandikisha multiple bit-flipping domains zinazofanana na domain ya victim. Kusudio lao ni kurekebisha watumiaji halali kwa infrastructure yao.

Kwa taarifa zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Unaweza kutafuta katika [https://www.expireddomains.net/](https://www.expireddomains.net) kwa expired domain ambayo unaweza kutumia.\
Ili kuhakikisha kwamba expired domain unayopanga kununua **has already a good SEO** unaweza angalia jinsi ilivyoainishwa katika:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Ili **discover more** anwani halali za email au **verify the ones** ulizogundua tayari unaweza angalia kama unaweza kuwabrute-force smtp servers za victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia **any web portal to access their mails**, unaweza kuangalia kama iko vulnerable kwa **username brute force**, na kutekeleza exploit ikiwa inawezekana.

## Configuring GoPhish

### Installation

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Utapewa password kwa admin user kwenye port 3333 kwenye output. Kwa hivyo, ingia kwenye port hiyo na tumia credentials hizo kubadili admin password. Huenda ukahitaji kutunnel port hiyo hadi local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii, unapaswa kuwa **tayari umenunua domain** utakayotumia, na lazima iwe **ikielekeza** kwa **IP ya VPS** ambako unasanidi **gophish**.
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
**Usanidi wa Barua**

Anza kusakinisha: `apt-get install postfix`

Kisha ongeza domain kwenye faili zifuatazo:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Badilisha pia thamani za vigezo vifuatavyo ndani ya /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Mwisho badilisha faili **`/etc/hostname`** na **`/etc/mailname`** kuwa jina la domain yako na **anzisha upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<domain>` ikielekeza kwa **IP address** ya VPS na rekodi ya **DNS MX** ikielekeza `mail.<domain>`

Sasa, tujaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish usanidi**

Simamisha utekelezaji wa gophish na tufanye usanidi wake.\
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
## Kusanidi seva ya barua na domain

### Subiri & kuwa halali

Kadri domain ilivyo na umri zaidi, ndivyo inavyokuwa na uwezekano mdogo zaidi wa kugunduliwa kama spam. Hivyo unapaswa kusubiri muda mrefu kadiri uwezavyo (angalau wiki 1) kabla ya tathmini ya phishing. Zaidi ya hayo, kama utaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa utakazopata itakuwa bora.

Kumbuka hata ukihitaji kusubiri wiki moja unaweza kumalizia kusanidi kila kitu sasa.

### Configure Reverse DNS (rDNS) record

Set a rDNS (PTR) record that resolves the IP address of the VPS to the domain name.

### Sender Policy Framework (SPF) Record

You must **configure a SPF record for the new domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Unapaswa **kusanidi rekodi ya DMARC kwa domain mpya**. Ikiwa haufahamu ni rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Unahitaji kuunda rekodi mpya ya DNS TXT ikielekeza hostname `_dmarc.<domain>` na yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Lazima **usanidi DKIM kwa domain mpya**. Ikiwa haujui rekodi ya DMARC ni nini [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Mwongozo huu unategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Unahitaji kuunganisha thamani zote mbili za B64 ambazo DKIM key inazalisha:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Pima alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Ingiza ukurasa na utume barua pepe kwa anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **angalia usanidi wa barua pepe yako** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma jibu** (kwa hili utahitaji **fungua** port **25** na kuona jibu katika faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakikisha unapitisha majaribio yote:
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
Unaweza pia kutuma **ujumbe kwa Gmail unayodhibiti**, na angalia **vichwa vya barua pepe** kwenye kisanduku chako cha Gmail, `dkim=pass` inapaswa kuwepo katika uwanja wa kichwa `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Kuondolewa kutoka Spamhouse Blacklist

Ukurasa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukuonyesha ikiwa domain yako inawekewa block na Spamhouse. Unaweza kuomba domain/IP yako iondolewe kwa: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondolewa kutoka Microsoft Blacklist

​​Unaweza kuomba domain/IP yako iondolewe kwa [https://sender.office.com/](https://sender.office.com).

## Unda & Washa Kampeni ya GoPhish

### Profaili ya Kutuma

- Weka **jina la kutambulisha** profaili ya mtumaji
- Amua kutoka kwenye akaunti ipi utaweka barua za phishing. Mapendekezo: _noreply, support, servicedesk, salesforce..._
- Unaweza kuacha username na password wazi, lakini hakikisha umechagua Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Inashauriwa kutumia functionality ya "**Send Test Email**" ili kujaribu kwamba kila kitu kinafanya kazi.\
> Napendekeza **kutuma barua za mtihani kwa anwani za 10min mails** ili kuepuka kuingia kwenye blacklist wakati wa kufanya majaribio.

### Email Template

- Weka **jina la kutambulisha** kiolezo
- Kisha andika **subject** (usilete kitu cha kushangaza, tu kitu unachoweza kutegemea kusoma katika barua pepe ya kawaida)
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
Kumbuka kwamba **ili kuongeza uaminifu wa barua pepe**, inashauriwa kutumia saini kutoka kwenye barua pepe ya mteja. Mapendekezo:

- Tuma barua pepe kwa **anwani isiyokuwepo** na angalia ikiwa jibu lina saini yoyote.
- Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com na uwatume barua pepe uka subiri jibu.
- Jaribu kuwasiliana na **anwani halali zilizobainika** na usubiri jibu

![](<../../images/image (80).png>)

> [!TIP]
> Kiolezo cha Barua Pepe pia kinakuwezesha **kuambatanisha mafaili ya kutumwa**. Ikiwa ungependa pia kuiba NTLM challenges kwa kutumia baadhi ya mafaili/nyaraka maalum [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Andika **jina**
- **Andika msimbo wa HTML** wa ukurasa wa wavuti. Kumbuka unaweza **kuingiza** kurasa za wavuti.
- Weka alama **Capture Submitted Data** na **Capture Passwords**
- Weka **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Kawaida utahitaji kubadilisha msimbo wa HTML wa ukurasa na kufanya majaribio kwa ndani (labda kwa kutumia Apache server) **mpaka utakapofurahia matokeo.** Kisha, andika msimbo huo wa HTML kwenye kisanduku.\
> Kumbuka kwamba ikiwa unahitaji **kutumia baadhi ya rasilimali za static** kwa ajili ya HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuziweka katika _**/opt/gophish/static/endpoint**_ kisha kuzifikia kutoka _**/static/\<filename>**_

> [!TIP]
> Kwa muelekezo unaweza **kupeleka watumiaji kwenye ukurasa mkuu halali** wa mwathirika, au kuwaelekeza kwa _/static/migration.html_ kwa mfano, uweke **spinning wheel (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha uonyeshe kuwa mchakato ulifanikiwa**.

### Users & Groups

- Weka jina
- **Import the data** (kumbuka kwamba ili kutumia kiolezo kwa mfano unahitaji firstname, last name na email address ya kila mtumiaji)

![](<../../images/image (163).png>)

### Campaign

Mwishowe, tengeneza kampeni kwa kuchagua jina, kiolezo cha barua pepe, ukurasa wa kutua, URL, sending profile na kundi. Kumbuka kuwa URL itakuwa linki inayotumwa kwa wahasiriwa

Kumbuka kwamba **Sending Profile inaruhusu kutuma barua pepe ya mtihani kuona jinsi barua pepe ya mwisho ya phishing itakavyoonekana**:

![](<../../images/image (192).png>)

> [!TIP]
> Ningependekeza **kutuma barua pepe za majaribio kwa anwani za 10min mails** ili kuepuka kuorodheshwa kama blacklisted wakati wa kufanya majaribio.

Mara kila kitu tayari, anzisha kampeni!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Katika tathmini za phishing (hasa kwa Red Teams) utataka pia **kutuma mafaili yenye aina fulani ya backdoor** (labda C2 au kitu kitakachochochea uthibitishaji).\
Angalia ukurasa unaofuata kwa mifano:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Shambulio lililotangulia ni werevu kwani unafanana na tovuti halisi na kukusanya taarifa zilizotumwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakutia nywila sahihi au ikiwa programu uliyodanganya imewekwa na 2FA, **taarifa hizi hazitakuwezesha kujifanya mtumiaji aliyechezwa**.

Hapa ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinapofaa. Zana hizi zitakuwezesha kuzalisha shambulio la MitM. Kwa msingi, shambulio linafanya kazi kwa njia ifuatayo:

1. Unajifanya kuwa fomu ya kuingia ya ukurasa halisi.
2. Mtumiaji **anatuma** **credentials** zake kwenye ukurasa wako bandia na zana huwa inazituma kwenye ukurasa halisi, **kuangalia kama credentials zinafanya kazi**.
3. Ikiwa akaunti imewekwa na **2FA**, ukurasa wa MitM utaomba hiyo na mara **mtumiaji anapoingiza** itazitumwa na zana kwenye ukurasa halisi.
4. Mara mtumiaji anapotambuliwa, wewe (kama mshambuliaji) utakuwa umepata **credentials, 2FA, cookie na taarifa yoyote** ya kila mwingiliano wakati zana inafanya MitM.

### Via VNC

Je, badala ya **kumutuma mwathirika kwenye ukurasa hatari** unaofanana na ule wa kweli, ukamtuma kwenye **VNC session with a browser connected to the real web page**? Utaweza kuona anachofanya, kuiba nywila, MFA iliyotumika, cookies...\
Unaweza kufanya hivi na [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Bila shaka, moja ya njia bora za kujua kama umegunduliwa ni **kutafuta domain yako kwenye blacklists**. Ikiwa inaonekana imeorodheshwa, kwa namna fulani domain yako ilitambuliwa kama shaka.\
Njia rahisi ya kuangalia kama domain yako inaonekana kwenye blacklist yoyote ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua ikiwa mwathirika **anatafuta kwa bidii shughuli za phishing zenye shaka** kama ilivyoelezwa katika:


{{#ref}}
detecting-phising.md
{{#endref}}

Unaweza **kununua domain yenye jina linalofanana sana** na domain ya mwathirika **na/au kuzalisha certificate** kwa **subdomain** ya domain unaodhibiti **ikiwa na** **keyword** ya domain ya mwathirika. Ikiwa **mwathirika** atafanya aina yoyote ya **DNS au HTTP interaction** nao, utajua kuwa **anatafuta kwa bidii** domain zenye shaka na utahitaji kuwa kimya sana.

### Evaluate the phishing

Tumia [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Vifurushi vya uvamizi vya kisasa mara nyingi hupuuza vilio vya barua pepe kabisa na **kulenga moja kwa moja mchakato wa service-desk / identity-recovery** ili kuzuia MFA. Shambulio ni "living-off-the-land" kabisa: mara operator anapomiliki credentials halali wanapindua kwa zana za admin zilizojengwa ndani – hakuna malware inayohitajika.

### Attack flow
1. Recon mwathirika
* Kusanya taarifa za kibinafsi & za kampuni kutoka LinkedIn, data breaches, public GitHub, n.k.
* Tambua vitambulisho vya thamani ya juu (executives, IT, finance) na orodha ya **exact help-desk process** kwa ajili ya password / MFA reset.
2. Real-time social engineering
* Piga simu, tumia Teams au chat kwa help-desk huku ukijifanya mtumiaji (mara nyingi kwa **spoofed caller-ID** au **cloned voice**).
* Toa PII iliyokusanywa awali ili kupitisha uthibitisho wa msingi wa maarifa.
* Shinikiza wakala **kufanya reset ya MFA secret** au kutekeleza **SIM-swap** kwenye namba ya simu iliyosajiliwa.
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
* Tibu help-desk identity recovery kama **operesheni ya hadhi maalum (privileged operation)** – hitaji step-up auth & idhini ya meneja.
* Tekeleza sheria za **Identity Threat Detection & Response (ITDR)** / **UEBA** ambazo zinaonya kuhusu:
* Mbadala wa njia ya MFA + uthibitisho kutoka kifaa kipya / eneo jipya.
* Kupandishwa mara moja kwa hadhi ya mhusika mmoja (user-→-admin).
* Rekodi simu za help-desk na utekeleze **call-back to an already-registered number** kabla ya reset yoyote.
* Tekeleza **Just-In-Time (JIT) / Privileged Access** ili akaunti zilizorekebishwa hivi karibuni **zisirithi** moja kwa moja tokeni za cheo cha juu.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Mafungu ya kawaida huzipatia gharama za operesheni za high-touch kwa mashambulizi ya wingi yanayogeuza **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** hupandisha matokeo bandia kama `chromium-update[.]site` kwenye matangazo ya juu ya utafutaji.
2. Mhasiriwa anapakua **first-stage loader** ndogo (mara nyingi JS/HTA/ISO). Mifano iliyotazamwa na Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader huondoa (exfiltrates) browser cookies + credential DBs, kisha huvuta **silent loader** ambayo inaamua – *kwa wakati halisi* – ikiwa itaweka:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Zuia domains zilizojisajiliwa hivi karibuni & tekekeza **Advanced DNS / URL Filtering** kwenye *search-ads* pamoja na barua pepe.
* Weka ukomo wa ufungaji wa programu kwa signed MSI / Store packages, kata utekelezaji wa `HTA`, `ISO`, `VBS` kwa sera.
* Fuatilia mchakato wa watoto wa vivinjari wanaofungua installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Tafuta LOLBins zinazotumiwa mara kwa mara na first-stage loaders (mfano `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Washambuliaji sasa wanachaina **LLM & voice-clone APIs** kwa lures zilizo kibinafsi kabisa na mwingiliano wa wakati halisi.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Zalisha & tuma >100 k barua pepe / SMS zenye maneno yaliyobadilishwa nasibu & viungo vya tracking.|
|Generative AI|Tengeneza barua pepe *mojawapo* zikirejea M&A za umma, vichekesho vya ndani kutoka mitandao ya kijamii; deep-fake CEO voice katika udanganyifu wa callback.|
|Agentic AI|Jisajili kwa uhuru domains, scrape open-source intel, tengeneza barua za hatua inayofuata wakati mhasiriwa anakibonyeza lakini hajawasilisha creds.|

**Defence:**
• Ongeza **dynamic banners** zinazoangazia ujumbe ulioletwa na automation isiyotambulika (kupitia anomalies za ARC/DKIM).  
• Tekeleza **voice-biometric challenge phrases** kwa maombi ya simu yenye hatari kubwa.  
• Endelea kuiga lures zilizotengenezwa na AI katika programu za uhamasishaji – templates za static hazitumiki tena.

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
Mbali na push-bombing ya jadi, operator hurudia **kulazimisha usajili mpya wa MFA** wakati wa simu ya help-desk, kuibatilisha tokeni ya mtumiaji iliyopo. Mwaliko wowote wa kuingia unaofuata unaonekana halali kwa mwathirika.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Fuatilia matukio ya AzureAD/AWS/Okta ambapo **`deleteMFA` + `addMFA`** zitokee **kwa ndani ya dakika chache kutoka IP ile ile**.



## Clipboard Hijacking / Pastejacking

Washambuliaji wanaweza kimya kimya kunakili amri hatari kwenye clipboard ya mwathirika kutoka ukurasa wa wavuti uliovamiwa au typosquatted, kisha kumdanganya mtumiaji kuziweka (paste) ndani ya **Win + R**, **Win + X** au dirisha la terminal, na hivyo kutekeleza msimbo wowote bila kupakua au kiambatanisho.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Waendeshaji mara nyingi wanaweka mtiririko wao wa phishing nyuma ya ukaguzi rahisi wa kifaa ili desktop crawlers wasiweze kufikia kurasa za mwisho. Mfano wa kawaida ni script ndogo inayotest DOM yenye uwezo wa touch na kutuma matokeo kwa server endpoint; non‑mobile clients wanarudishiwa HTTP 500 (au ukurasa tupu), wakati watumiaji wa mobile wanahudumiwa mtiririko kamili.

Kifupi cha client (mantiki ya kawaida):
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
- Inaweka session cookie wakati wa upakiaji wa kwanza.
- Inakubali `POST /detect {"is_mobile":true|false}`.
- Inarudisha 500 (au placeholder) kwa GETs zinazofuata wakati `is_mobile=false`; inaonyesha phishing tu ikiwa `true`.

Mbinu za utafutaji na heuristics za utambuzi:
- Utafutaji wa urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetry ya wavuti: mfululizo wa `GET /static/detect_device.js` → `POST /detect` → HTTP 500 kwa non‑mobile; njia halali za waathiriwa wa mobile hurudisha 200 na HTML/JS inayofuata.
- Zuia au chunguza kwa ukaribu kurasa zinazoonyesha maudhui kwa kigezo cha `ontouchstart` pekee au ukaguzi mwingine wa kifaa.

Vidokezo vya ulinzi:
- Endesha crawlers zenye fingerprints zinazofanana na mobile na JS imewezeshwa ili kufichua maudhui yaliyozuiliwa.
- Weka tahadhari kwa majibu ya 500 yenye shaka yanayotokea baada ya `POST /detect` kwenye domain zilizosajiliwa hivi karibuni.

## Marejeo

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
