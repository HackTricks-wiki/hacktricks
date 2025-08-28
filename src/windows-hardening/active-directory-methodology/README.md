# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवलोकन

**Active Directory** एक बुनियादी तकनीक के रूप में कार्य करता है, जो **नेटवर्क प्रशासकों** को नेटवर्क के भीतर **domains**, **users**, और **objects** को कुशलतापूर्वक बनाने और प्रबंधित करने में सक्षम बनाता है। यह स्केलेबल तरीके से डिज़ाइन किया गया है, जिससे बड़ी संख्या में users को प्रबंधनीय **groups** और **subgroups** में व्यवस्थित किया जा सकता है, साथ ही विभिन्न स्तरों पर **access rights** को नियंत्रित किया जा सकता है।

**Active Directory** की संरचना तीन प्राथमिक परतों से मिलकर बनी होती है: **domains**, **trees**, और **forests**। एक **domain** उन वस्तुओं का संग्रह होता है, जैसे **users** या **devices**, जो एक सामान्य डेटाबेस साझा करते हैं। **Trees** उन domains का समूह होते हैं जो एक साझा संरचना द्वारा जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो **trust relationships** के माध्यम से इंटरकनेक्टेड होते हैं, और संगठनात्मक संरचना की शीर्ष परत बनाते हैं। विशिष्ट **access** और **communication rights** इनमे से प्रत्येक स्तर पर निर्दिष्ट किए जा सकते हैं।

Active Directory के प्रमुख अवधारणाएँ शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी जानकारी रखता है।
2. **Object** – डायरेक्टरी के भीतर की संस्थाएँ, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – डायरेक्टरी objects का कंटेनर होता है; एक **forest** के भीतर कई domains सह-अस्तित्व में रह सकते हैं, प्रत्येक का अपना object संग्रह होता है।
4. **Tree** – domains का एक समूह जो एक सामान्य root domain साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना का शीर्ष स्तर, कई trees से मिलकर और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** उन सेवाओं का एक सेट है जो नेटवर्क के केंद्रीकृत प्रबंधन और संचार के लिए महत्वपूर्ण हैं। ये सेवाएँ शामिल हैं:

1. **Domain Services** – डेटा स्टोरेज को केंद्रीकृत करता है और **users** तथा **domains** के बीच इंटरैक्शन को manages करता है, जिसमें **authentication** और **search** कार्यक्षमताएँ शामिल हैं।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से directory-enabled applications का समर्थन करता है।
4. **Directory Federation Services** – एकल सत्र में कई web applications पर उपयोगकर्ताओं को authenticate करने के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – कॉपीराइट सामग्री की अनधिकृत वितरण और उपयोग को नियंत्रित करके उसकी सुरक्षा में मदद करता है।
6. **DNS Service** – **domain names** के रिज़ॉल्यूशन के लिए महत्वपूर्ण है।

अधिक विवरण के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

अगर आप किसी AD पर हमला करना सीखना चाहते हैं तो आपको **Kerberos authentication process** को बहुत अच्छी तरह समझना होगा।\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

आप तेजी से देखने के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) का उपयोग कर सकते हैं कि किन commands को आप प्रयोग करके किसी AD को enumerate/exploit कर सकते हैं।

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

यदि आपके पास किसी AD environment तक पहुँच है लेकिन आपके पास कोई credentials/sessions नहीं हैं तो आप:

- **Pentest the network:**
- नेटवर्क को scan करें, machines और open ports खोजें और कोशिश करें कि उनपर मौजूद कमजोरियों को **exploit vulnerabilities** या उनसे **extract credentials** करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS को enumerate करने से domain के भीतर key servers जैसे web, printers, shares, vpn, media इत्यादि के बारे में जानकारी मिल सकती है।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- इस बारे में और जानकारी पाने के लिए सामान्य [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह modern Windows versions पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server को enumerate करने की अधिक विस्तृत गाइड यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP enumerate करने के बारे में अधिक विस्तृत गाइड यहाँ मिलती है (anonymous access पर **विशेष ध्यान** दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder का उपयोग करके सेवाओं का impersonate करके credentials इकट्ठा करें ([**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) के जरिए host तक पहुँच प्राप्त करें
- दुष्ट UPnP सेवाएँ expose करके credentials इकट्ठा करें [**exposing fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents, social media, services (मुख्यतः web) में और publicly available स्रोतों से usernames/names निकालें।
- अगर आपको कंपनी कर्मचारियों के पूरे नाम मिल जाते हैं, तो आप विभिन्न AD **username conventions** आज़मा सकते हैं ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). सबसे सामान्य conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक का 3 अक्षर), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पृष्ठ देखें।
- **Kerbrute enum**: जब कोई **invalid username is requested** होगा तो server **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ प्रतिक्रिया देगा, जिससे हमें पता चल जाता है कि username अमान्य था। **Valid usernames** या तो **TGT in a AS-REP** response में मिलेंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_ देंगे, जो संकेत करता है कि user को pre-authentication करना आवश्यक है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) interface के खिलाफ auth-level = 1 (No authentication) का उपयोग करके। यह method MS-NRPC interface को bind करने के बाद `DsrGetDcNameEx2` function को कॉल करके बिना किसी credentials के यह जांचता है कि user या computer मौजूद है या नहीं। इस प्रकार की enumeration को लागू करने वाला टूल [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) है। शोध यहाँ पाया जा सकता है [यहाँ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आप नेटवर्क में इन सर्वरों में से किसी को पाते हैं तो आप इसके खिलाफ **user enumeration against it** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

ठीक है, तो आपके पास पहले से ही एक वैध username तो है पर कोई password नहीं... तब कोशिश करें:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास attribute _DONT_REQ_PREAUTH_ नहीं है तो आप उस user के लिए एक AS_REP message request कर सकते हैं जिसमें कुछ data होगा जो user के password के derivation से एन्क्रिप्टेड होगा।
- [**Password Spraying**](password-spraying.md): खोजे गए प्रत्येक users के साथ सबसे सामान्य passwords आज़माएँ; शायद कोई user कमजोर password का उपयोग कर रहा हो (password policy का ध्यान रखें!)।
- ध्यान दें कि आप users के mail servers तक access पाने की कोशिश के लिए OWA servers पर भी spray कर सकते हैं।

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप कुछ challenge hashes प्राप्त कर सकते हैं जिन्हें crack करने के लिए नेटवर्क के कुछ protocols को poisoning किया जा सकता है:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आप Active Directory का enumeration करने में सफल रहे हैं तो आपके पास और भी emails होंगे और network की बेहतर समझ होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को force कर के AD env तक access प्राप्त कर सकते हैं।

### Steal NTLM Creds

यदि आप null या guest user के साथ अन्य PCs या shares तक access कर सकते हैं तो आप फाइलें (जैसे SCF file) रख सकते हैं जो किसी तरह access होने पर आपके खिलाफ NTLM authentication trigger कर देंगी, जिससे आप NTLM challenge चुरा कर उसे crack कर सकेंगे:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

इस चरण के लिए आपके पास किसी वैध domain account के credentials या session का compromise होना आवश्यक है। अगर आपके पास कुछ वैध credentials हैं या domain user के रूप में shell है, तो याद रखें कि पहले दिए गए विकल्प अभी भी अन्य users को compromise करने के लिए उपलब्ध हैं।

Authenticated enumeration शुरू करने से पहले आपको यह जानना चाहिए कि Kerberos double hop problem क्या है।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account का compromise करना पूरे domain को compromise करने की शुरुआत के लिए एक बड़ा कदम है, क्योंकि इससे आप Active Directory Enumeration शुरू कर पाएंगे:

जहाँ तक [**ASREPRoast**](asreproast.md) की बात है, अब आप हर संभावित vulnerable user ढूंढ सकते हैं, और जहाँ तक [**Password Spraying**](password-spraying.md) की बात है आप सभी usernames की सूची बनाकर compromised account का password, empty passwords और नए promising passwords आज़मा सकते हैं।

- आप [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**powershell for recon**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं, जो अधिक stealthier होगा
- आप और विस्तृत जानकारी निकालने के लिए [**use powerview**](../basic-powershell-for-pentesters/powerview.md) का उपयोग कर सकते हैं
- Active Directory में recon के लिए एक और शानदार टूल [**BloodHound**](bloodhound.md) है। यह (आपके collection methods पर निर्भर करते हुए) बहुत stealthy नहीं है, लेकिन अगर आपको इसकी परवाह नहीं है तो इसे जरूर आज़माएँ। पता लगाएँ कि users कहाँ RDP कर सकते हैं, अन्य groups तक किस तरह का path है, आदि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) देखें क्योंकि इनमें उपयोगी जानकारी हो सकती है।
- एक GUI वाला tool जो आप directory enumerate करने के लिए इस्तेमाल कर सकते हैं वह **AdExplorer.exe** है, जो **SysInternal** Suite का हिस्सा है।
- आप LDAP database में **ldapsearch** से भी खोज कर सकते हैं ताकि _userPassword_ & _unixUserPassword_ फील्ड्स में credentials देखें, या यहाँ तक कि _Description_ में भी। अन्य तरीकों के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)।
- यदि आप **Linux** उपयोग कर रहे हैं, तो आप domain enumerate करने के लिए [**pywerview**](https://github.com/the-useless-one/pywerview) का भी उपयोग कर सकते हैं।
- आप निम्न automated tools भी आज़मा सकते हैं:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration सेक्शन छोटा दिखे, यह सबसे महत्वपूर्ण हिस्सा है। दिए गए links (मुख्यतः cmd, powershell, powerview और BloodHound) को खोलकर सीखें कि domain को कैसे enumerate करें और तब तक अभ्यास करें जब तक आप सहज महसूस न करें। एक assessment के दौरान यही वह मुख्य क्षण होगा जब आप DA तक पहुंचने का रास्ता ढूँढेंगे या यह तय करेंगे कि कुछ भी किया नहीं जा सकता।

### Kerberoast

Kerberoasting में उन TGS tickets को प्राप्त करना शामिल है जो services द्वारा उपयोग होते हैं जो user accounts से जुड़े होते हैं, और उनकी encryption — जो user passwords पर आधारित होती है — को offline crack करना शामिल है।

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आपके पास कुछ credentials हों, तो आप जाँच सकते हैं कि क्या किसी machine तक आपकी पहुँच है। इसके लिए आप CrackMapExec का उपयोग कर कई servers पर विभिन्न protocols के साथ connect करने की कोशिश कर सकते हैं, अपने port scans के अनुसार।

### Local Privilege Escalation

यदि आपने एक सामान्य domain user के रूप में credentials या session compromise किया है और इस user से domain की किसी भी machine तक आपकी access है, तो आपको local privilege escalate करने और credentials loot करने की कोशिश करनी चाहिए। क्योंकि केवल local administrator privileges के साथ ही आप अन्य users के hashes को memory (LSASS) और लोकल रूप से (SAM) dump कर पाएँगे।

इस किताब में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) पर एक पूरी page है और एक [**checklist**](../checklist-windows-privilege-escalation.md) भी है। साथ ही, WinPEAS का उपयोग करना न भूलें: [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

यह बहुत ही unlikely है कि आप current user में ऐसे tickets पाएँ जो आपको unexpected resources तक access देने की permission दें, लेकिन आप जाँच कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Computer Shares में Creds खोजें | SMB Shares

अब जब आपके पास कुछ बेसिक credentials हैं, तो आपको यह चेक करना चाहिए कि क्या आप AD के भीतर शेयर की जा रही किसी भी दिलचस्प फाइल को **खोज** सकते हैं। आप यह मैन्युअली कर सकते हैं पर यह बहुत उबाऊ और दोहराव वाला काम है (और भी ज्यादा अगर आपको सैकड़ों docs मिलते हैं जिन्हें आपको चेक करना होगा)।

[**इस लिंक को फॉलो करें ताकि आप उपयोग कर सकने वाले tools के बारे में जान सकें।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप अन्य PCs या shares तक **access** कर सकते हैं तो आप ऐसी फाइलें (जैसे एक SCF file) रख सकते हैं कि यदि किसी तरह वे एक्सेस हों तो वे आपके विरुद्ध NTLM authentication को **trigger** कर दें, ताकि आप NTLM challenge को **चुरा** सकें और उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

यह vulnerability किसी भी authenticated user को **domain controller को compromise** करने की अनुमति देती थी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**निम्नलिखित techniques के लिए एक सामान्य domain user पर्याप्त नहीं है, इन attacks को करने के लिए आपको कुछ विशेष privileges/credentials चाहिए।**

### Hash extraction

आशा है कि आप [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) सहित relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके कुछ local admin account को **compromise** करने में सफल हुए होंगे।\
फिर, यह समय है कि memory और local दोनों जगह से सभी hashes को dump करने का।\
[**हैश प्राप्त करने के विभिन्न तरीकों के बारे में इस पेज को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो जाता है**, आप इसका उपयोग करके उसे **impersonate** कर सकते हैं।\
आपको ऐसा कोई **tool** उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication** को अंजाम दे, **या** आप नया **sessionlogon** बना सकते हैं और उस **hash** को **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication** हो, वह **hash** उपयोग किया जाए। अंतिम विकल्प वही है जो mimikatz करता है।\
[**और जानकारी के लिए इस पेज को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह attack इस बात का लक्ष्य रखता है कि उपयोगकर्ता के NTLM hash का उपयोग करके Kerberos tickets request किए जाएँ, जो सामान्य Pass The Hash over NTLM protocol का एक विकल्प है। इसलिए, यह उन नेटवर्क्स में विशेष रूप से उपयोगी हो सकता है जहाँ NTLM protocol disabled है और केवल Kerberos ही authentication protocol के रूप में allowed है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) attack method में, attackers उपयोगकर्ता का authentication ticket उसके password या hash values की बजाय **चुराते** हैं। यह चुराया गया ticket फिर उपयोगकर्ता को **impersonate** करने के लिए उपयोग किया जाता है, जिससे network के भीतर resources और services तक unauthorized access मिल जाती है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी local administrator का **hash** या **password** है, तो आपको इसके साथ अन्य **PCs** पर **local login** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **noisy** है और **LAPS** इसे **mitigate** करेगा।

### MSSQL Abuse & Trusted Links

यदि किसी उपयोगकर्ता के पास **access MSSQL instances** की privileges हैं, तो वह इसे MSSQL host में **execute commands** करने के लिए उपयोग कर सकता है (यदि यह SA के रूप में चल रहा हो), NetNTLM **hash** को **steal** कर सकता है या यहाँ तक कि एक **relay** **attack** भी कर सकता है।\
इसके अलावा, यदि कोई MSSQL instance किसी अलग MSSQL instance द्वारा trusted (database link) है और उपयोगकर्ता के पास trusted database पर privileges हैं, तो वह **use the trust relationship to execute queries also in the other instance** कर सकेगा। ये trusts chained हो सकते हैं और किसी बिंदु पर उपयोगकर्ता किसी misconfigured database को ढूँढ सकता है जहाँ वह commands execute कर सके।\
**डेटाबेस के बीच के लिंक forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution के लिए powerful रास्ते उजागर करते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आपको कोई Computer object attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) के साथ मिलता है और आपके पास उस कंप्यूटर पर domain privileges हैं, तो आप उस कंप्यूटर पर login करने वाले हर उपयोगकर्ता की memory से TGTs dump कर पाएंगे।\
इसलिए, यदि कोई **Domain Admin उस कंप्यूटर पर login** करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग कर उसे impersonate कर पाएंगे।\
constrained delegation के कारण आप यहाँ तक कि **automatically compromise a Print Server** भी कर सकते हैं (आशा है कि वह DC होगा)。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" के लिए अनुमति दी गई है तो वह किसी computer में कुछ सेवाओं तक पहुँचने के लिए **किसी भी user का impersonate** कर सकेगा।\
फिर, यदि आप इस user/computer के hash को **compromise** कर लेते हैं तो आप **किसी भी user** (यहाँ तक कि domain admins भी) का impersonate कर कुछ सेवाओं तक पहुँच सकते हैं।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से आप **बढ़ी हुई privileges** के साथ code execution हासिल कर सकते हैं:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर ऐसे **interesting privileges** हो सकते हैं जो आपको बाद में lateral **move** करने या **escalate** privileges करने की अनुमति दे सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

डोमेन के भीतर किसी **Spool service listening** को खोजकर उसे **abuse** करके नए credentials प्राप्त करने और privileges **escalate** करने के लिए उपयोग किया जा सकता है।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य users** compromised मशीन तक **access** करते हैं, तो उनसे memory से credentials **gather** करना और यहाँ तक कि उनके processes में beacons **inject** करके उनका impersonation करना संभव है।\
अधिकतर उपयोगकर्ता सिस्टम तक RDP के माध्यम से पहुँचते हैं, इसलिए यहां third party RDP sessions पर कुछ attacks करने के तरीके दिए गए हैं:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined कंप्यूटर्स पर **local Administrator password** को manage करने के लिए एक प्रणाली प्रदान करता है, सुनिश्चित करता है कि वह पासवर्ड **randomized**, unique और अक्सर **changed** हो। ये पासवर्ड Active Directory में store होते हैं और ACLs के माध्यम से केवल authorized users के लिए access नियंत्रित होता है। यदि इन पासवर्ड्स तक पहुंचने के लिए पर्याप्त permissions हों, तो अन्य कंप्यूटर्स पर pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised machine से **certificates को gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configured हैं तो उनका दुरुपयोग करके privileges escalate किया जा सकता है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आप **Domain Admin** या उससे भी बेहतर **Enterprise Admin** privileges प्राप्त कर लेते हैं, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ तकनीकों को persistence के लिए भी उपयोग किया जा सकता है।\
उदाहरण के लिए आप कर सकते हैं:

- उपयोगकर्ताओं को [**Kerberoast**](kerberoast.md) के लिए vulnerable बनाना

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- उपयोगकर्ताओं को [**ASREPRoast**](asreproast.md) के लिए vulnerable बनाना

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- किसी user को [**DCSync**](#dcsync) privileges प्रदान करना

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** किसी विशेष service के लिए एक वैध Ticket Granting Service (TGS) ticket बनाता है, जिसका उपयोग **NTLM hash** (उदाहरण के लिए, PC account के hash) से किया जाता है। इस विधि का उपयोग service privileges तक पहुँचने के लिए किया जाता है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account** के NTLM hash तक पहुँच प्राप्त करता है। यह account विशेष है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** पर साइन करने के लिए उपयोग होता है, जो AD नेटवर्क के भीतर authentication के लिए आवश्यक होते हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, वह किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack जैसी)।


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets की तरह होते हैं लेकिन इन्हें इस तरह से forge किया जाता है कि ये **common golden tickets detection mechanisms** को bypass कर दें।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates होना** या उन्हें request करने में सक्षम होना users के account में persist करने का एक बहुत अच्छा तरीका है (यहाँ तक कि यदि उसने password बदल भी दिया हो): 


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के अंदर high privileges के साथ persist करने के लिए भी संभव है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करने के लिए एक standard **Access Control List (ACL)** apply करता है ताकि unauthorized परिवर्तन रोके जा सकें। हालाँकि, इस फीचर का दुरुपयोग किया जा सकता है; यदि attacker AdminSDHolder के ACL में संशोधन करके किसी regular user को full access दे देता है, तो वह user सभी privileged groups पर व्यापक नियंत्रण प्राप्त कर लेगा। यह सुरक्षा उपाय, जो सुरक्षा के लिए है, तब उल्टा प्रभाव डाल सकता है और अनुचित access की अनुमति दे सकता है जब तक कि इसे कड़ी निगरानी में न रखा जाए।

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक local administrator account मौजूद होता है। ऐसी किसी मशीन पर admin rights प्राप्त करके, local Administrator hash को **mimikatz** का उपयोग करके extract किया जा सकता है। इसके बाद इस password के उपयोग को सक्षम करने के लिए registry modification की आवश्यकता होती है, जिससे local Administrator account तक remote access संभव हो जाता है।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी विशेष domain objects पर किसी **user** को कुछ विशेष permissions **दे** सकते हैं जो उस user को भविष्य में privileges escalate करने की अनुमति देंगे।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** का उपयोग किसी object के ऊपर मौजूद permissions को **store** करने के लिए किया जाता है। यदि आप किसी object के security descriptor में थोड़ा सा भी परिवर्तन कर देते हैं, तो आप उस object पर बहुत ही रोचक privileges हासिल कर सकते हैं बिना किसी privileged group का सदस्य होने की आवश्यकता के।


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS में memory को बदलकर एक **universal password** स्थापित करें, जो सभी domain accounts तक पहुंच की अनुमति देता है।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **own SSP** बना सकते हैं ताकि मशीन तक पहुँचने में उपयोग किए जाने वाले **credentials** को **clear text** में capture किया जा सके।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नई Domain Controller** register करता है और उसे specified objects पर attributes (SIDHistory, SPNs...) **push** करने के लिए उपयोग करता है **बिना** उन **modifications** के बारे में बहुत सारे logs छोड़े। आपको DA privileges की आवश्यकता है और आपको **root domain** के अंदर होना चाहिए।\
ध्यान दें कि यदि आप गलत data का उपयोग करते हैं, तो काफी बुरे logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords पढ़ने** की पर्याप्त permission है तो कैसे privileges escalate किए जा सकते हैं। हालाँकि, इन पासवर्ड्स का उपयोग persistence बनाए रखने के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary के रूप में देखता है। इसका मतलब है कि **एक single domain के compromise से संभावित रूप से पूरे Forest का compromise हो सकता है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain के resources तक पहुँचने की अनुमति देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications आसानी से flow कर सकें। जब domains trust स्थापित करते हैं, तो वे अपने Domain Controllers (DCs) में कुछ विशेष **keys** exchange और retain करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

सामान्य परिदृश्य में, यदि कोई user किसी **trusted domain** में किसी service तक पहुँचने का इरादा रखता है, तो उसे पहले अपने domain के DC से एक विशेष ticket जिसे **inter-realm TGT** कहा जाता है, request करना होगा। यह TGT उस shared **key** के साथ encrypt होता है जो दोनों domains के बीच सहमति से मौजूद होता है। फिर user इस TGT को **trusted domain** के DC को प्रस्तुत करता है ताकि उसे service के लिए एक service ticket (**TGS**) मिल सके। यदि trusted domain का DC inter-realm TGT को सफलतापूर्वक validate कर लेता है, तो वह TGS जारी करता है, जिससे user को service तक पहुँचने की अनुमति मिलती है।

**Steps**:

1. एक **client computer** Domain 1 में अपनी **NTLM hash** का उपयोग करते हुए अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करना शुरू करता है।
2. यदि client authenticated है तो DC1 एक नया TGT जारी करता है।
3. फिर client को **Domain 2** के resources तक पहुँचने के लिए DC1 से एक **inter-realm TGT** request करना होता है।
4. inter-realm TGT उस **trust key** के साथ encrypt होता है जो DC1 और DC2 के बीच दो-तरफ़ा domain trust के हिस्से के रूप में साझा किया गया है।
5. client inter-realm TGT लेकर **Domain 2 के Domain Controller (DC2)** के पास जाता है।
6. DC2 अपने shared trust key का उपयोग करके inter-realm TGT को verify करता है और यदि मान्य है, तो वह Domain 2 में उस server के लिए **Ticket Granting Service (TGS)** जारी करता है जिसे client access करना चाहता है।
7. अंत में, client यह TGS server को प्रस्तुत करता है, जिसे server के account hash के साथ encrypt किया गया है, ताकि Domain 2 में service तक पहुँच मिल सके।

### Different trusts

यह ध्यान रखना महत्वपूर्ण है कि **एक trust 1 way या 2 ways** हो सकता है। 2 way विकल्प में दोनों domains एक-दूसरे पर trust करेंगे, लेकिन **1 way** trust संबंध में एक domain **trusted** होगा और दूसरा **trusting** domain होगा। अंतिम मामले में, **trusted domain से केवल trusting domain के अंदर के resources तक ही आप पहुंच सकेंगे**।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted domain है। इसके अलावा, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह आमतौर पर उसी forest के भीतर सेटअप होता है, जहाँ एक child domain अपने parent domain के साथ स्वचालित रूप से two-way transitive trust रखता है। इसका अर्थ है कि authentication requests parent और child के बीच आसानी से बह सकते हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" कहा जाता है, ये child domains के बीच स्थापित किए जाते हैं ताकि referral प्रक्रियाएँ तेज़ हो सकें। जटिल forests में, authentication referrals को अक्सर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाकर यह यात्रा छोटी हो जाती है, जो भौगोलिक रूप से फैले हुए वातावरण में विशेष रूप से उपयोगी है।
- **External Trusts**: ये अलग, unrelated domains के बीच सेटअप होते हैं और स्वभाव से non-transitive होते हैं। [Microsoft के documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उन domains के resources तक पहुंचने के लिए उपयोगी हैं जो current forest से बाहर हैं और forest trust द्वारा जुड़े नहीं हैं। सुरक्षा को external trusts के साथ SID filtering के माध्यम से मजबूत किया जाता है।
- **Tree-root Trusts**: ये trust forest root domain और किसी newly added tree root के बीच स्वचालित रूप से स्थापित होते हैं। हालांकि ये आमतौर पर सामने नहीं आते, tree-root trusts नए domain trees को forest में जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे उन्हें एक unique domain name बनाए रखने और two-way transitivity सुनिश्चित करने में मदद मिलती है। अधिक जानकारी के लिए [Microsoft के गाइड](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) देखें।
- **Forest Trusts**: यह प्रकार दो forest root domains के बीच two-way transitive trust है, जो सुरक्षा उपायों को बढ़ाने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts थोड़ा अधिक specialized होते हैं और उन वातावरणों के लिए होते हैं जिन्हें Windows पारिस्थितिकी तंत्र के बाहर Kerberos-based systems के साथ एकीकरण की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** भी हो सकती है (A trust B, B trust C, तो A trust C) या **non-transitive** भी।
- एक trust relationship **bidirectional trust** के रूप में सेटअप की जा सकती है (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** के रूप में (केवल एक ही दूसरे पर trust करता है)।

### Attack Path

1. **Enumerate** करें trusting relationships को
2. चेक करें कि क्या कोई **security principal** (user/group/computer) के पास **other domain** के resources तक **access** है, शायद ACE entries द्वारा या दूसरे domain के groups में होने के कारण। **relationships across domains** के लिए देखें (शायद trust इसी के लिए बनाया गया था)।
1. इस मामले में kerberoast एक अन्य विकल्प भी हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के बीच **pivot** कर सकते हैं।

Attackers के पास तीन प्रमुख mechanisms के माध्यम से दूसरे domain में resources तक पहुँचने की क्षमता हो सकती है:

- **Local Group Membership**: Principals को machines के local groups में जोड़ा जा सकता है, जैसे कि किसी server पर “Administrators” group, जो उन्हें उस मशीन पर महत्वपूर्ण नियंत्रण देता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के सदस्य भी हो सकते हैं। हालांकि, इस तरीके की प्रभावशीलता trust के प्रकार और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals किसी **ACL** में specify किए जा सकते हैं, विशेष रूप से **ACEs** के रूप में एक **DACL** के अंदर, जो उन्हें specific resources तक पहुँच प्रदान करता है। ACLs, DACLs और ACEs की mechanics में गहराई में जाने वालों के लिए, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” अमूल्य संसाधन है।

### Find external users/groups with permissions

आप **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** चेक कर सकते हैं ताकि domain में foreign security principals पाए जा सकें। ये बाहरी domain/forest के user/group होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके चेक कर सकते हैं:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
डोमेन ट्रस्ट्स को सूचीबद्ध करने के अन्य तरीके:
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
> वर्तमान में **2 trusted keys** मौजूद हैं, एक _Child --> Parent_ के लिए और दूसरा _Parent_ --> _Child_ के लिए।\
> आप वर्तमान डोमेन द्वारा उपयोग की जा रही कुंजी को इस तरह देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग करके SID-History injection के जरिए child/parent domain में Enterprise admin के रूप में अधिकार बढ़ाएँ:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) को कैसे exploit किया जा सकता है यह समझना महत्वपूर्ण है। Configuration NC Active Directory (AD) वातावरण में एक forest भर में configuration डेटा के लिए केंद्रीय रिपॉज़िटरी के रूप में काम करता है। यह डेटा forest के हर Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable copy बनाए रखते हैं। इसे exploit करने के लिए, किसी DC पर **SYSTEM privileges on a DC** होना आवश्यक है, बेहतर है कि वह child DC हो।

**GPO को root DC site से लिंक करें**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined कंप्यूटरों की साइट्स की जानकारी शामिल होती है। किसी भी DC पर SYSTEM privileges के साथ काम करके, attackers GPOs को root DC sites से लिंक कर सकते हैं। इस क्रिया से उन साइट्स पर लागू नीतियों को बदलकर root domain संभावित रूप से compromise हो सकता है।

गहराई से जानकारी के लिए निम्न रिसर्च देखी जा सकती है: [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Forest में किसी भी gMSA को compromise करें**

एक attack vector domain के भीतर privileged gMSAs को निशाना बनाता है। gMSAs के passwords की गणना के लिए आवश्यक KDS Root key Configuration NC में स्टोर रहती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key तक पहुँच कर पूरे forest के किसी भी gMSA का password compute करना संभव है।

विस्तृत विश्लेषण और step-by-step मार्गदर्शन यहाँ उपलब्ध है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

पूरक delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

अतिरिक्त बाहरी रिसर्च: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

यह विधि धैर्य मांगती है — नए privileged AD objects के बनने का इंतजार करना होता है। SYSTEM privileges के साथ, एक attacker AD Schema में बदलाव करके किसी भी user को सभी classes पर complete control दे सकता है। इससे नए बनाए गए AD objects तक unauthorized access और control हो सकता है।

अधिक पढ़ने के लिए देखें: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का उद्देश्य Public Key Infrastructure (PKI) objects पर नियंत्रण हासिल करके ऐसा certificate template बनाना है जो forest में किसी भी user के रूप में authentication सक्षम करे। चूँकि PKI objects Configuration NC में रहते हैं, इसलिए एक writable child DC को compromise करके ESC5 attacks को निष्पादित किया जा सकता है।

इस पर और जानकारी के लिए पढ़ें: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). यदि ADCS मौजूद नहीं है, तो attacker आवश्यक components खुद सेटअप करने में सक्षम होता है, जैसा कि इस लेख में चर्चा की गई है: [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
इस परिदृश्य में **आपके डोमेन को एक बाह्य डोमेन द्वारा ट्रस्ट किया गया है**, जो आपको उस पर **अनिर्धारित अनुमतियाँ** देता है। आपको पता लगाना होगा कि **आपके डोमेन के कौन से सिक्योरिटी प्रिंसिपल्स बाह्य डोमेन पर किस प्रकार की पहुँच रखते हैं** और फिर उनका शोषण करने की कोशिश करनी होगी:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फ़ॉरेस्ट डोमेन - एक-तरफ़ा (आउटबाउंड)
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
In this परिदृश्य **your domain** किसी **different domains** के प्रिंसिपल को कुछ **privileges** सौंप रहा होता है।

हालाँकि, जब एक **domain is trusted** होता है trusting domain द्वारा, तो trusted domain एक **user** बनाता है जिसका नाम प्रेडिक्टेबल होता है और जिसका **password the trusted password** होता है। इसका मतलब यह है कि यह संभव है कि **access a user from the trusting domain to get inside the trusted one** ताकि उसे enumerate किया जा सके और अधिक privileges हासिल करने की कोशिश की जा सके:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

एक और तरीका trusted domain को compromise करने का यह है कि उस दिशा में बने हुए [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) को ढूँढा जाए जो domain trust के विपरीत दिशा में बनाया गया हो (जो कि बहुत आम नहीं है)।

एक और तरीका trusted domain को compromise करने का है कि attacker उस मशीन पर इंतज़ार करे जहाँ **user from the trusted domain can access** कर सकता है और RDP के माध्यम से login कर सकता है। फिर attacker RDP session process में code inject कर सकता है और वहाँ से **access the origin domain of the victim** कर सकता है.\
इसके अलावा, अगर **victim mounted his hard drive** कर चुका है, तो **RDP session** process से attacker हार्ड ड्राइव के **startup folder** में **backdoors** स्टोर कर सकता है। इस तकनीक को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID Filtering के सक्रिय होने से inter-forest trusts में SID history attribute के जरिए होने वाले हमलों का खतरा कम होता है; यह सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय होता है। यह इस धारणा पर आधारित है कि intra-forest trusts सुरक्षित हैं, क्योंकि Microsoft के दृष्टिकोण के अनुसार सुरक्षा सीमा forest है, न कि domain।
- हालांकि, एक समस्या यह है कि SID filtering कुछ applications और user access को बाधित कर सकता है, जिसकी वजह से इसे कभी-कभी deactivate किया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users स्वतः authenticated न हों। इसके बजाय, users को trusting domain या forest के अंदर domains और servers तक पहुँचने के लिए स्पष्ट permissions की आवश्यकता होती है।
- यह महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर हमलों से सुरक्षा प्रदान नहीं करते हैं।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: सुझाया जाता है कि Domain Admins केवल Domain Controllers पर ही login करने की अनुमति रखें और अन्य hosts पर उनका उपयोग टालें।
- **Service Account Privileges**: सेवाएँ Domain Admin (DA) privileges के साथ नहीं चलानी चाहिए ताकि सुरक्षा बनी रहे।
- **Temporal Privilege Limitation**: जिन कार्यों में DA privileges की आवश्यकता होती है, उनके समय को सीमित रखा जाना चाहिए। इसे इस तरह से लागू किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Deception लागू करने में traps सेट करना शामिल है, जैसे decoy users या computers, जिनमें ऐसे फ़ीचर हो सकते हैं जैसे passwords that do not expire या Trusted for Delegation के रूप में चिह्नित। विस्तृत तरीका specific rights वाले users बनाने या उन्हें high privilege groups में जोड़ने जैसी चीज़ें शामिल करता है।
- एक व्यावहारिक उदाहरण में tools का उपयोग किया जाता है जैसे: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques के deployment के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिलती है।

### **Identifying Deception**

- **For User Objects**: संदिग्ध संकेतों में असामान्य ObjectSID, कम logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की तुलना असली objects के साथ करने से inconsistencies पता चल सकती हैं। ایسے tools जैसे [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) deception की पहचान में मदद कर सकते हैं।

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: टिकट बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है क्योंकि यह NTLM पर downgrade नहीं करता।
- **DCSync Attacks**: DCSync को non-Domain Controller से execute करने की सलाह दी जाती है ताकि ATA detection से बचा जा सके, क्योंकि Domain Controller पर सीधे execution alerts ट्रिगर करेगा।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
